//! Linux/x86_64 Firecracker lifecycle supervisor.
//!
//! This module owns the VMM process and the host-side identity binding. It
//! deliberately refuses to issue C1 evidence when the guest-side filesystem
//! and process observer is absent: a guest report is not host-owned evidence.

#![cfg(target_os = "linux")]

use crate::capsule::{
    BackendKind, CapsuleFacts, CapsuleFailure, CapsuleObservation, CheckResult,
    evidence_binding_root,
};
use crate::filesystem_world::{FilesystemWorld, delta, scan_directory};
use crate::jailer_plan::{NetworkPolicy, ProductionJailerPlan};
use crate::measured_launch::{
    CaptureContext, ConsumableInputBinding, DirectMeasuredLaunch, FileIdentity,
    JailedResourcePaths, LaunchEvidence, LaunchProfile, LaunchedInputResources,
    LaunchedJailerInputBinding, MeasuredLaunchSession, ObservedContainedLaunch, PolicyIdentity,
    PreparedExecutionInputs, UnixEndpointIdentity, VmmIncarnation,
};
use crate::profile::SyncTrace as _;
use crate::{
    execute::{C1BackendInputPaths, ProductionJailerConfig},
    mediation::{CheckedMediationClaim, MediationFailure},
    task_envelope::TaskEnvelope,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    os::unix::io::AsRawFd,
    os::unix::net::{UnixListener, UnixStream},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const API_SOCKET_NAME: &str = "firecracker.api";
const TASK_SOCKET_NAME: &str = "realm.task";
const MAX_MESSAGE: usize = 64 * 1024;

#[derive(Serialize)]
struct ApiRequestEvidence {
    status_line: String,
    response_headers_blake3: String,
}

pub(crate) fn scan_detached_workspace(
    image: &Path,
    _state: &Path,
    label: &str,
) -> Result<FilesystemWorld, SupervisorError> {
    let _profile = crate::profile::Span::new("detached_world_observation");
    // libguestfs creates Unix sockets below the mountpoint, so nesting this
    // under the full run/execution state path can exceed SUN_LEN. Keep the
    // mountpoint short and process-unique; create_dir still refuses a stale
    // path instead of reusing it.
    let mountpoint = std::env::temp_dir().join(format!("r6-scan-{}-{label}", std::process::id()));
    fs::create_dir(&mountpoint)?;
    let image_file = File::open(image)?;
    let image_fd = unsafe { libc::fcntl(image_file.as_raw_fd(), libc::F_DUPFD, 64) };
    if image_fd < 0 {
        let _ = fs::remove_dir(&mountpoint);
        return Err(SupervisorError::Protocol(
            "workspace image descriptor duplication refused".into(),
        ));
    }
    let mounted = Command::new("guestmount")
        .args(["--ro", "--format=raw", "-a"])
        .arg(format!("/proc/self/fd/{image_fd}"))
        .args(["-m", "/dev/sda"])
        .arg(&mountpoint)
        .status();
    unsafe {
        libc::close(image_fd);
    }
    let mounted = mounted?.success();
    if !mounted {
        let _ = fs::remove_dir(&mountpoint);
        return Err(SupervisorError::UnsupportedHost(
            "guestmount could not create an offline workspace view".into(),
        ));
    }
    let world = scan_directory(&mountpoint)
        .map_err(|_| SupervisorError::Protocol("offline workspace scan refused".into()));
    let unmounted = Command::new("guestunmount")
        .arg(&mountpoint)
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    let _ = fs::remove_dir(&mountpoint);
    if !unmounted {
        return Err(SupervisorError::Protocol(
            "offline workspace view could not be unmounted".into(),
        ));
    }
    world
}

#[derive(Clone, Debug)]
pub struct FirecrackerSupervisor {
    pub backend: C1BackendInputPaths,
    pub starting_workspace_image: PathBuf,
    pub working_workspace_image: PathBuf,
    pub timeout: Duration,
}

struct JailedLaunchContext {
    jail_id: String,
    jail_root: PathBuf,
    resources: JailedResourcePaths,
    jailer_path: PathBuf,
    jailer_sha256: String,
    firecracker_sha256: String,
    config: ProductionJailerConfig,
    input_binding: Option<ConsumableInputBinding>,
    jailer_pid: u32,
    jailer_process: VmmIncarnation,
    firecracker_pid: u32,
    firecracker_pid_namespace: u32,
}

enum PendingLaunchEvidence {
    Direct(Box<DirectMeasuredLaunch>),
    Contained(Box<ObservedContainedLaunch>),
}

impl std::ops::Deref for PendingLaunchEvidence {
    type Target = MeasuredLaunchSession;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Direct(launch) => launch,
            Self::Contained(launch) => launch,
        }
    }
}

struct JailDirectoryGuard {
    path: PathBuf,
    armed: bool,
}

impl JailDirectoryGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for JailDirectoryGuard {
    fn drop(&mut self) {
        if self.armed && self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

enum SupervisorLaunchInputs {
    Direct(Box<LaunchedInputResources>),
    Jailed(Box<JailedLaunchContext>),
}

struct LaunchedExecution {
    child: Child,
    api_socket: PathBuf,
    task_socket_host: PathBuf,
    task_socket_guest: PathBuf,
    firecracker_pid: u32,
    inputs: SupervisorLaunchInputs,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskReply {
    protocol: u16,
    run_id: String,
    execution_id: String,
    capsule_id: String,
    challenge: String,
    task_envelope_identity: String,
    tool_call_id: String,
    tool_id: String,
    capability_ref: String,
    effect_contract_identity: String,
    input_workspace_identity: String,
    workspace_identity: String,
    exited: bool,
    exit_code: Option<i32>,
    crashed: bool,
    completion_sequence: u64,
    supervisor_identity: String,
    state: String,
}

impl TaskReply {
    fn matches_challenge(&self, envelope: &TaskEnvelope) -> bool {
        self.protocol == envelope.protocol
            && self.run_id == envelope.run_id
            && self.execution_id == envelope.execution_id
            && self.capsule_id == envelope.capsule_id
            && self.challenge == envelope.challenge
            && self.task_envelope_identity == envelope.identity().unwrap_or_default()
            && self.tool_call_id == envelope.tool_call_id
            && self.tool_id == envelope.tool_id
            && self.capability_ref == envelope.capability_ref
            && self.effect_contract_identity == envelope.effect_contract_identity
            && self.input_workspace_identity == envelope.input_workspace_identity
            && self.workspace_identity == envelope.workspace_identity
            && self.completion_sequence == 1
            && self.state == "FINALIZED"
    }
}

#[derive(Debug)]
pub enum SupervisorError {
    UnsupportedHost(String),
    Invalid(String),
    Io(io::Error),
    Protocol(String),
    Capsule(CapsuleFailure),
    Claim(MediationFailure),
}

impl std::fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedHost(reason) => write!(f, "unsupported host: {reason}"),
            Self::Invalid(reason) => write!(f, "invalid supervisor input: {reason}"),
            Self::Io(error) => write!(f, "supervisor I/O: {error}"),
            Self::Protocol(reason) => write!(f, "supervisor protocol: {reason}"),
            Self::Capsule(_) => write!(f, "capsule evidence construction failed"),
            Self::Claim(_) => write!(f, "C1 claim issuance refused"),
        }
    }
}

impl std::error::Error for SupervisorError {}

impl From<io::Error> for SupervisorError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<CapsuleFailure> for SupervisorError {
    fn from(value: CapsuleFailure) -> Self {
        Self::Capsule(value)
    }
}

pub(crate) struct MeasuredExecutionRequest<'a> {
    pub(crate) run_id: &'a str,
    pub(crate) execution_id: &'a str,
    pub(crate) argv: &'a [String],
    pub(crate) cwd: &'a str,
    pub(crate) safe_environment: &'a [String],
    pub(crate) effect_contract: &'a [String],
    pub(crate) policy: PolicyIdentity,
}

type LaunchHook<'a> = dyn FnMut(&MeasuredLaunchSession) -> Result<(), SupervisorError> + 'a;
type GuestRpcHook<'a> =
    dyn FnMut(&mut UnixStream, &TaskEnvelope) -> Result<(), SupervisorError> + 'a;

struct GuestRunRequest<'a, 'hook> {
    child: &'a mut Child,
    api: &'a Path,
    task_path: &'a Path,
    task_guest_path: &'a Path,
    firecracker_pid: u32,
    state: &'a Path,
    envelope: TaskEnvelope,
    starting_world_root: String,
    policy: PolicyIdentity,
    launched_inputs: SupervisorLaunchInputs,
    launch_hook: Option<&'hook mut LaunchHook<'hook>>,
    guest_rpc_hook: Option<&'hook mut GuestRpcHook<'hook>>,
}

impl FirecrackerSupervisor {
    pub fn preflight(&self) -> Result<(), SupervisorError> {
        if std::env::consts::ARCH != "x86_64" {
            return Err(SupervisorError::UnsupportedHost(
                "C1 requires Linux x86_64".into(),
            ));
        }
        if File::options()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_err()
        {
            return Err(SupervisorError::UnsupportedHost(
                "/dev/kvm is unavailable or not usable by this process".into(),
            ));
        }
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
            return Err(SupervisorError::UnsupportedHost(
                "cgroup v2 is unavailable".into(),
            ));
        }
        if !Command::new("debugfs")
            .arg("-V")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return Err(SupervisorError::UnsupportedHost(
                "debugfs is required to verify the supervisor embedded in rootfs".into(),
            ));
        }
        for (name, path) in [
            ("firecracker", &self.backend.firecracker),
            ("kernel", &self.backend.kernel),
            ("immutable rootfs", &self.backend.rootfs),
            ("workspace base", &self.backend.workspace_device),
            ("guest supervisor", &self.backend.guest_supervisor),
            ("starting workspace image", &self.starting_workspace_image),
            ("working workspace image", &self.working_workspace_image),
        ] {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(SupervisorError::UnsupportedHost(format!(
                    "{name} is not a private regular file"
                )));
            }
        }
        if !self.backend.state_dir.is_absolute() {
            return Err(SupervisorError::Invalid(
                "state directory must be absolute".into(),
            ));
        }
        Ok(())
    }

    pub fn run(
        &self,
        run_id: &str,
        execution_id: &str,
        argv: &[String],
        cwd: &str,
    ) -> Result<CapsuleObservation, SupervisorError> {
        let unbound_policy = PolicyIdentity::new(
            "unbound-diagnostic".into(),
            "0".into(),
            b"no-effective-policy-supplied",
            b"",
        );
        self.run_core(
            MeasuredExecutionRequest {
                run_id,
                execution_id,
                argv,
                cwd,
                safe_environment: &[],
                effect_contract: &[],
                policy: unbound_policy,
            },
            None,
            None,
            None,
        )
        .map(|(observation, _)| observation)
    }

    pub(crate) fn run_measured(
        &self,
        request: MeasuredExecutionRequest<'_>,
    ) -> Result<(CapsuleObservation, LaunchEvidence), SupervisorError> {
        self.run_core(request, None, None, None)
    }

    /// Join the runtime-owned BrokerRpc envelope to the canonical graded
    /// launch producer. The callback runs after launch measurement and input
    /// revalidation, immediately before Firecracker InstanceStart.
    pub(crate) fn run_measured_brokered<F>(
        &self,
        envelope: &TaskEnvelope,
        policy: PolicyIdentity,
        launch_hook: &mut F,
    ) -> Result<(CapsuleObservation, LaunchEvidence), SupervisorError>
    where
        F: FnMut(&MeasuredLaunchSession) -> Result<(), SupervisorError>,
    {
        self.run_core(
            MeasuredExecutionRequest {
                run_id: &envelope.run_id,
                execution_id: &envelope.execution_id,
                argv: &envelope.argv,
                cwd: &envelope.cwd,
                safe_environment: &envelope.safe_environment,
                effect_contract: &envelope.effect_contract,
                policy,
            },
            Some(launch_hook),
            Some(envelope.clone()),
            None,
        )
    }

    /// Run a measured task whose guest performs its effect through the
    /// canonical BrokerRpc stream on the already peer-bound VMM connection.
    pub(crate) fn run_measured_brokered_with_rpc<F, G>(
        &self,
        envelope: &TaskEnvelope,
        policy: PolicyIdentity,
        launch_hook: &mut F,
        guest_rpc_hook: &mut G,
    ) -> Result<(CapsuleObservation, LaunchEvidence), SupervisorError>
    where
        F: FnMut(&MeasuredLaunchSession) -> Result<(), SupervisorError>,
        G: FnMut(&mut UnixStream, &TaskEnvelope) -> Result<(), SupervisorError>,
    {
        self.run_core(
            MeasuredExecutionRequest {
                run_id: &envelope.run_id,
                execution_id: &envelope.execution_id,
                argv: &envelope.argv,
                cwd: &envelope.cwd,
                safe_environment: &envelope.safe_environment,
                effect_contract: &envelope.effect_contract,
                policy,
            },
            Some(launch_hook),
            Some(envelope.clone()),
            Some(guest_rpc_hook),
        )
    }

    fn run_core<'hook>(
        &self,
        request: MeasuredExecutionRequest<'_>,
        launch_hook: Option<&'hook mut LaunchHook<'hook>>,
        provided_envelope: Option<TaskEnvelope>,
        guest_rpc_hook: Option<&'hook mut GuestRpcHook<'hook>>,
    ) -> Result<(CapsuleObservation, LaunchEvidence), SupervisorError> {
        let MeasuredExecutionRequest {
            run_id,
            execution_id,
            argv,
            cwd,
            safe_environment,
            effect_contract,
            policy,
        } = request;
        self.preflight()?;
        if run_id.is_empty() || execution_id.is_empty() || argv.is_empty() {
            return Err(SupervisorError::Invalid(
                "empty execution identity or command".into(),
            ));
        }
        fs::create_dir_all(&self.backend.state_dir)?;
        let state_root = fs::symlink_metadata(&self.backend.state_dir)?;
        let effective_uid = unsafe { libc::geteuid() };
        if !state_root.is_dir() || state_root.uid() != effective_uid {
            return Err(SupervisorError::Invalid(
                "state directory is not host-owned".into(),
            ));
        }
        // Unix-domain sockets have a bounded pathname; keep the full execution ID in
        // the envelope/evidence while bounding only this ephemeral directory name.
        let socket_execution_id = digest_text(&format!("{run_id}:{execution_id}"));
        let state = self
            .backend
            .state_dir
            .join(format!("r-{}", &socket_execution_id[..20]));
        fs::create_dir(&state)?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
        let api = state.join(API_SOCKET_NAME);
        let task = state.join(TASK_SOCKET_NAME);
        let capsule_id = digest_text(&format!("{run_id}:{execution_id}:capsule"));
        let challenge = match provided_envelope.as_ref() {
            Some(envelope)
                if envelope.challenge.len() == 64
                    && envelope
                        .challenge
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit()) =>
            {
                envelope.challenge.clone()
            }
            Some(_) => return Err(SupervisorError::Invalid("invalid runtime challenge".into())),
            None => fresh_challenge()?,
        };
        let prepared = PreparedExecutionInputs::prepare(
            &self.backend,
            &self.starting_workspace_image,
            &self.working_workspace_image,
            &state,
        )
        .map_err(|_| SupervisorError::Protocol("C1 input preparation refused".into()))?;
        let starting_world =
            scan_detached_workspace(&prepared.starting_workspace_path(), &state, "start")?;
        let binding = prepared
            .bind(
                run_id.into(),
                execution_id.into(),
                challenge.clone(),
                starting_world.root.clone(),
                policy.clone(),
            )
            .map_err(|_| SupervisorError::Protocol("C1 input binding refused".into()))?;

        let envelope = if let Some(envelope) = provided_envelope {
            if envelope.protocol != 1
                || envelope.run_id != run_id
                || envelope.execution_id != execution_id
                || envelope.argv != argv
                || envelope.cwd != cwd
                || envelope.safe_environment != safe_environment
                || envelope.effect_contract != effect_contract
                || envelope.timeout_ms == 0
                || envelope.timeout_ms > self.timeout.as_millis().min(u64::MAX as u128) as u64
                || envelope.workspace_identity != starting_world.root
                || envelope.tool_call_id.is_empty()
                || envelope.tool_id.is_empty()
                || envelope.capability_ref.is_empty()
                || envelope.effect_contract_identity.is_empty()
            {
                return Err(SupervisorError::Invalid(
                    "BrokerRpc TaskEnvelope differs from measured launch inputs".into(),
                ));
            }
            envelope
        } else {
            TaskEnvelope {
                protocol: 1,
                run_id: run_id.into(),
                tool_call_id: "diagnostic-call".into(),
                tool_id: "diagnostic.exec".into(),
                capability_ref: "diagnostic-only".into(),
                effect_contract_identity: digest_text("diagnostic-no-effect-contract"),
                input_workspace_identity: starting_world.root.clone(),
                execution_id: execution_id.into(),
                capsule_id: capsule_id.clone(),
                challenge: challenge.clone(),
                argv: argv.to_vec(),
                cwd: cwd.into(),
                safe_environment: safe_environment.to_vec(),
                timeout_ms: self.timeout.as_millis().min(u64::MAX as u128) as u64,
                workspace_identity: starting_world.root.clone(),
                effect_contract: effect_contract.to_vec(),
            }
        };
        let mut launched = self.launch(
            binding,
            &api,
            &task,
            &state,
            run_id,
            execution_id,
            &challenge,
        )?;
        let jail_cleanup = match &launched.inputs {
            SupervisorLaunchInputs::Direct(_) => None,
            SupervisorLaunchInputs::Jailed(context) => Some((
                context.jail_root.clone(),
                Path::new("/sys/fs/cgroup")
                    .join(&context.config.cgroup_parent)
                    .join(&context.jail_id),
            )),
        };
        let result = self.run_guest(GuestRunRequest {
            child: &mut launched.child,
            api: &launched.api_socket,
            task_path: &launched.task_socket_host,
            task_guest_path: &launched.task_socket_guest,
            firecracker_pid: launched.firecracker_pid,
            state: &state,
            envelope,
            starting_world_root: starting_world.root.clone(),
            policy,
            launched_inputs: launched.inputs,
            launch_hook,
            guest_rpc_hook,
        });
        let (reply, pending_launch) = match result {
            Ok(result) => result,
            Err(error) => {
                let _ = cleanup_failed_jailer(
                    &mut launched.child,
                    jail_cleanup.as_ref().map(|(root, cgroup)| (root, cgroup)),
                );
                return Err(error);
            }
        };
        if !reply.exited {
            let _ = cleanup_failed_jailer(
                &mut launched.child,
                jail_cleanup.as_ref().map(|(root, cgroup)| (root, cgroup)),
            );
            return Err(SupervisorError::Protocol(
                "guest did not report a terminal task state".into(),
            ));
        }
        // The production guest may shut down Firecracker as part of its finalized
        // task path. At this point the challenge-matched terminal reply and
        // post-guest API configuration have already been observed. Do not require
        // a new API operation after that closure; the direct diagnostic path still
        // takes its existing snapshot.
        if jail_cleanup.is_none()
            && let Err(error) = pause_and_snapshot(&api, &state, None)
        {
            let _ = cleanup_failed_jailer(&mut launched.child, None);
            return Err(error);
        }
        let launch = match pending_launch {
            PendingLaunchEvidence::Direct(launch) => LaunchEvidence::Direct(launch),
            PendingLaunchEvidence::Contained(observed) => {
                // Request the supported guest reboot path and reap our adopted
                // VMM. A forced kill or an unobserved exit cannot mint authority.
                write_json_record(
                    &state.join("production-containment-observed.json"),
                    &serde_json::json!({
                        "assurance_grade": "OBSERVED_CONTAINMENT_PENDING_EXIT",
                        "containment": observed.observation_record(),
                        "production_authority_minted": false,
                    }),
                )?;
                let retirement = retire_jailed_vmm(&launched.api_socket, observed.vmm(), &state);
                let status = match retirement {
                    Ok(status) => status,
                    Err(error) => {
                        let _ = cleanup_failed_jailer(
                            &mut launched.child,
                            jail_cleanup.as_ref().map(|(root, cgroup)| (root, cgroup)),
                        );
                        return Err(error);
                    }
                };
                let production = match observed.finish_after_exit(launched.firecracker_pid, status)
                {
                    Ok(production) => production,
                    Err(error) => {
                        let _ = cleanup_failed_jailer(
                            &mut launched.child,
                            jail_cleanup.as_ref().map(|(root, cgroup)| (root, cgroup)),
                        );
                        return Err(SupervisorError::Protocol(format!(
                            "contained VMM closure refused: {error:?}"
                        )));
                    }
                };
                write_json_record(
                    &state.join("production-contained-launch.json"),
                    &serde_json::json!({
                        "schema_version": 2,
                        "run_id": production.run_id(), "execution_id": production.execution_id(),
                        "production_launch_root": production.production_launch_root(),
                        "assurance_grade": "PRODUCTION_CONTAINED",
                        "containment": production.containment_record(),
                        "cgroup_controllers": production.cgroup_controllers_record(),
                        "admission": "REFUSE(UNVERIFIED_BOUNDARY)", "task_success": false,
                    }),
                )?;
                LaunchEvidence::Production(Box::new(production))
            }
        };
        let final_workspace = launch
            .workspace_resource_path()
            .ok_or_else(|| SupervisorError::Protocol("missing consumed workspace pin".into()))?;
        let final_world = match scan_detached_workspace(&final_workspace, &state, "final") {
            Ok(world) => world,
            Err(error) => {
                let _ = cleanup_failed_jailer(
                    &mut launched.child,
                    jail_cleanup.as_ref().map(|(root, cgroup)| (root, cgroup)),
                );
                return Err(error);
            }
        };
        if jail_cleanup.is_some() {
            let copy_result =
                copy_isolated_workspace(&final_workspace, &self.working_workspace_image);
            if let Err(error) = copy_result {
                let _ = cleanup_failed_jailer(
                    &mut launched.child,
                    jail_cleanup.as_ref().map(|(root, cgroup)| (root, cgroup)),
                );
                return Err(error.into());
            }
        }
        cleanup_failed_jailer(
            &mut launched.child,
            jail_cleanup.as_ref().map(|(root, cgroup)| (root, cgroup)),
        )?;
        let changes = delta(&starting_world, &final_world);
        let observed_effects = changes
            .iter()
            .map(|change| match change {
                crate::filesystem_world::FilesystemChange::Create { path, .. }
                | crate::filesystem_world::FilesystemChange::Modify { path, .. }
                | crate::filesystem_world::FilesystemChange::Delete { path, .. } => path.clone(),
            })
            .collect();
        let delta_root = blake3::hash(
            &serde_json::to_vec(&changes)
                .map_err(|_| SupervisorError::Protocol("delta encoding failed".into()))?,
        )
        .to_hex()
        .to_string();
        // A guest terminal reply is a report, not an authenticated host witness.
        let completion_evidence = String::new();
        let finalization_evidence = String::new();
        let pause_snapshot_evidence = String::new();
        let unsupported_effects = vec![
            "UNCLASSIFIED_EFFECT_HISTORY".into(),
            "DESCENDANT_CLOSURE_UNAVAILABLE".into(),
            "GUEST_TERMINAL_REPORT_UNAUTHENTICATED".into(),
            "NETWORK_EFFECT_CLOSURE_UNAVAILABLE".into(),
        ];
        let process_identity = blake3::hash(
            &serde_json::to_vec(launch.vmm())
                .map_err(|_| SupervisorError::Protocol("VMM identity encoding failed".into()))?,
        )
        .to_hex()
        .to_string();
        let mut facts = CapsuleFacts {
            run_id: run_id.into(),
            execution_id: execution_id.into(),
            backend: BackendKind::DiagnosticOnly,
            workspace_identity: starting_world.root.clone(),
            capsule_id,
            custody_process_identity: Some(process_identity),
            descendants: vec!["UNMEASURED_DESCENDANTS".into()],
            starting_world: starting_world.root,
            final_world: Some(final_world.root),
            observed_effects,
            exit_code: reply.exit_code,
            crashed: reply.crashed,
            quiescence: CheckResult::Unavailable,
            monitor_loss: CheckResult::Unavailable,
            network: CheckResult::Unavailable,
            filesystem: CheckResult::Verified,
            frozen: CheckResult::Unavailable,
            evidence_root: None,
            sequence_start: 0,
            sequence_end: None,
            unsupported_effects,
            runtime_identity: launch.runtime_identity().into(),
            network_policy_identity: launch.network_policy_blake3(),
            completion_evidence,
            finalization_evidence,
            pause_snapshot_evidence,
            vmm_terminal_observation_root: None,
            delta_root,
        };
        facts.evidence_root = Some(evidence_binding_root(&facts));
        let observation = CapsuleObservation::from_supervisor_facts(
            facts,
            "diagnostic-only:measured-launch-topology".into(),
        )?;
        Ok((observation, launch))
    }

    /// Diagnostic helper retained for protocol compatibility. The current
    /// supervisor emits unavailable closure/freeze facts, so claim issuance
    /// must refuse this result.
    pub fn run_and_issue_c1(
        &self,
        manifest_bytes: &[u8],
        comparison_root: &str,
        run_id: &str,
        execution_id: &str,
        argv: &[String],
        cwd: &str,
    ) -> Result<(CapsuleObservation, CheckedMediationClaim), SupervisorError> {
        let observation = self.run(run_id, execution_id, argv, cwd)?;
        let claim = crate::mediation::issue_c1_claim(manifest_bytes, comparison_root, &observation)
            .map_err(SupervisorError::Claim)?;
        Ok((observation, claim))
    }

    #[allow(clippy::too_many_arguments)]
    fn launch(
        &self,
        binding: ConsumableInputBinding,
        api: &Path,
        task: &Path,
        state: &Path,
        run_id: &str,
        execution_id: &str,
        challenge: &str,
    ) -> Result<LaunchedExecution, SupervisorError> {
        if let Some(config) = self.backend.production_jailer.as_ref() {
            return self.launch_with_jailer(
                binding,
                config,
                state,
                run_id,
                execution_id,
                challenge,
            );
        }
        let stdout = File::create(state.join("firecracker.stdout"))?;
        let stderr = File::create(state.join("firecracker.stderr"))?;
        let duplicated = binding.duplicate_vmm_inputs().map_err(|_| {
            SupervisorError::Protocol("C1 input descriptor duplication refused".into())
        })?;
        let child = Command::new(duplicated.bindings_executable_path())
            .arg("--api-sock")
            .arg(api)
            .current_dir(state)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?;
        let pid = child.id();
        let configured = (|| {
            wait_for_socket(api, self.timeout)?;
            let paths = duplicated.bindings_paths(pid);
            configure_firecracker(api, &paths[1], &paths[2], &paths[3], task)
        })();
        if let Err(error) = configured {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        Ok(LaunchedExecution {
            child,
            api_socket: api.to_path_buf(),
            task_socket_host: task.to_path_buf(),
            task_socket_guest: task.to_path_buf(),
            firecracker_pid: pid,
            inputs: SupervisorLaunchInputs::Direct(Box::new(
                LaunchedInputResources::from_consumed_binding(binding, duplicated.bindings()),
            )),
        })
    }

    fn launch_with_jailer(
        &self,
        binding: ConsumableInputBinding,
        config: &ProductionJailerConfig,
        state: &Path,
        run_id: &str,
        execution_id: &str,
        challenge: &str,
    ) -> Result<LaunchedExecution, SupervisorError> {
        self.launch_with_jailer_profile(
            binding,
            config,
            state,
            run_id,
            execution_id,
            challenge,
            LaunchProfile::Workspace,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn launch_with_jailer_profile(
        &self,
        binding: ConsumableInputBinding,
        config: &ProductionJailerConfig,
        state: &Path,
        run_id: &str,
        execution_id: &str,
        challenge: &str,
        profile: LaunchProfile,
    ) -> Result<LaunchedExecution, SupervisorError> {
        let _profile = crate::profile::Span::new("firecracker_startup");
        const JAILER_SHA256: &str =
            "65ef226e96f0ceda55ba643f445801ef2cc0ea667ef67cad8ac4f406c9c8434f";
        const FIRECRACKER_SHA256: &str =
            "99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5";
        if unsafe { libc::geteuid() } != 0
            || config.uid == 0
            || config.gid == 0
            || config.cgroup_parent.is_absolute()
            || config.cgroup_parent.as_os_str().is_empty()
        {
            return Err(SupervisorError::UnsupportedHost(
                "production jailer requires root and a non-root uid/gid with relative cgroup parent".into(),
            ));
        }
        crate::measured_launch::require_realm_fc_identity(config.uid, config.gid).map_err(|_| {
            SupervisorError::UnsupportedHost(
                "configured jailer uid/gid must identify the unique dedicated realm-fc account and group".into(),
            )
        })?;
        self.preflight_cgroup_v2(&config.cgroup_parent)?;
        ensure_root_trusted_directory(&config.chroot_base_dir)?;
        if !directory_is_trusted(state)? {
            return Err(SupervisorError::Invalid(
                "jailer executable and input state has an untrusted or writable parent".into(),
            ));
        }

        let id_material = format!("{run_id}:{execution_id}:{challenge}");
        let jail_id = format!("realm-{}", &digest_text(&id_material)[..32]);
        let vm_parent = config.chroot_base_dir.join("firecracker");
        fs::create_dir_all(&vm_parent)?;
        if !directory_is_trusted(&vm_parent)? {
            return Err(SupervisorError::Invalid(
                "jailer executable-name directory is writable by an untrusted principal".into(),
            ));
        }
        let vm_dir = vm_parent.join(&jail_id);
        fs::create_dir(&vm_dir).map_err(|error| {
            SupervisorError::Invalid(format!(
                "fresh jail identity already exists or cannot be created: {error}"
            ))
        })?;
        let mut jail_guard = JailDirectoryGuard::new(vm_dir.clone());
        let jail_root = vm_dir.join("root");
        fs::create_dir(&jail_root)?;
        fs::set_permissions(&jail_root, fs::Permissions::from_mode(0o755))?;
        let run_dir = jail_root.join("run");
        fs::create_dir(&run_dir)?;
        chown_path(&run_dir, config.uid, config.gid)?;
        fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700))?;

        let jailer_source_identity = FileIdentity::measure(&config.jailer).map_err(|_| {
            SupervisorError::Invalid("jailer binary identity is unavailable".into())
        })?;
        let source_jailer_sha = sha256_file(Path::new(jailer_source_identity.path()))?;
        if source_jailer_sha != JAILER_SHA256 {
            return Err(SupervisorError::Invalid(
                "jailer SHA256 does not match locked v1.17.0".into(),
            ));
        }
        let jailer_path = state.join("jailer-v1.17.0");
        copy_locked_executable(
            Path::new(jailer_source_identity.path()),
            &jailer_path,
            JAILER_SHA256,
        )?;
        let jailer_sha256 = sha256_file(&jailer_path)?;
        if jailer_sha256 != JAILER_SHA256 {
            return Err(SupervisorError::Invalid(
                "materialized jailer SHA256 mismatch".into(),
            ));
        }

        let resources = binding
            .materialize_for_jailer(&jail_root, state, config.uid, config.gid)
            .map_err(|error| {
                SupervisorError::Protocol(format!(
                    "bound jail resource materialization refused: {error:?}"
                ))
            })?;
        resources
            .verify_before_instance_start()
            .map_err(|_| SupervisorError::Invalid("jailer input materialization refused".into()))?;
        let firecracker_sha256 = sha256_file(&resources.firecracker_exec_source)?;
        if firecracker_sha256 != FIRECRACKER_SHA256 {
            return Err(SupervisorError::Invalid(
                "materialized Firecracker SHA256 does not match locked v1.17.0".into(),
            ));
        }

        let api_guest = PathBuf::from("/run/firecracker.socket");
        let task_guest = PathBuf::from(format!("/run/{TASK_SOCKET_NAME}"));
        let api_host = jail_root.join(api_guest.strip_prefix("/").unwrap());
        let task_host = jail_root.join(task_guest.strip_prefix("/").unwrap());
        let plan = ProductionJailerPlan::new(
            jailer_path.clone(),
            "v1.17.0",
            resources.firecracker_exec_source.clone(),
            "v1.17.0",
            jail_id.clone(),
            config.uid,
            config.gid,
            config.chroot_base_dir.clone(),
            config.cgroup_parent.clone(),
            config.memory_max_bytes,
            config.pids_max,
            api_guest,
            NetworkPolicy::NoGuestInterfaces,
        )
        .map_err(|error| {
            SupervisorError::Invalid(format!("production jailer plan refused: {error:?}"))
        })?;

        let stdout = File::create(state.join("jailer.stdout"))?;
        let stderr = File::create(state.join("jailer.stderr"))?;
        let mut command = Command::new(&jailer_path);
        command
            .args(plan.arguments())
            .current_dir(state)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let (mut child, jailer_process) = spawn_observed_jailer(&mut command)?;
        let jailer_pid = child.id();
        let startup = (|| {
            let (firecracker_pid, firecracker_pid_namespace) =
                wait_for_jailer_child(jailer_pid, &jail_root, self.timeout)?;
            wait_for_socket(&api_host, self.timeout)?;
            // The official jailer initially owns / and its executable as the
            // VMM account. Protect their identities before configuring devices.
            protect_jailer_inputs(&jail_root)?;
            resources.verify_before_instance_start().map_err(|error| {
                SupervisorError::Protocol(format!("jailer changed protected inputs: {error:?}"))
            })?;
            let status = child.wait()?;
            if !status.success() {
                return Err(SupervisorError::Protocol(format!(
                    "official jailer exited unsuccessfully: {status}"
                )));
            }
            if profile == LaunchProfile::RootfsBroker {
                configure_broker_firecracker(&api_host, &task_guest)?;
            } else {
                configure_firecracker(
                    &api_host,
                    &PathBuf::from("/kernel"),
                    &PathBuf::from("/rootfs.ext4"),
                    &PathBuf::from("/workspace.ext4"),
                    &task_guest,
                )?;
            }
            Ok::<_, SupervisorError>((firecracker_pid, firecracker_pid_namespace))
        })();
        let (firecracker_pid, firecracker_pid_namespace) = match startup {
            Ok(pids) => pids,
            Err(error) => {
                // A failed launch must not orphan Firecracker after jailer
                // exec has detached the child from the supervisor lifecycle.
                let cgroup = Path::new("/sys/fs/cgroup")
                    .join(&config.cgroup_parent)
                    .join(&jail_id);
                let _ = cleanup_failed_jailer(&mut child, Some((&jail_root, &cgroup)));
                return Err(error);
            }
        };
        jail_guard.disarm();
        Ok(LaunchedExecution {
            child,
            api_socket: api_host,
            task_socket_host: task_host,
            task_socket_guest: task_guest,
            firecracker_pid,
            inputs: SupervisorLaunchInputs::Jailed(Box::new(JailedLaunchContext {
                jail_id,
                jail_root,
                resources,
                jailer_path,
                jailer_sha256,
                firecracker_sha256,
                config: config.clone(),
                input_binding: Some(binding),
                jailer_pid,
                jailer_process,
                firecracker_pid,
                firecracker_pid_namespace,
            })),
        })
    }

    fn preflight_cgroup_v2(&self, parent: &Path) -> Result<(), SupervisorError> {
        if parent.is_absolute()
            || parent.as_os_str().is_empty()
            || parent
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(SupervisorError::Invalid(
                "cgroup parent must be a clean relative path".into(),
            ));
        }
        let root = Path::new("/sys/fs/cgroup");
        if fs::read_to_string(root.join("cgroup.controllers")).is_err() {
            return Err(SupervisorError::UnsupportedHost(
                "unified cgroup v2 controllers unavailable".into(),
            ));
        }
        let parent_path = root.join(parent);
        let metadata = fs::symlink_metadata(&parent_path).map_err(|_| {
            SupervisorError::UnsupportedHost(
                "configured cgroup parent does not already exist".into(),
            )
        })?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(SupervisorError::UnsupportedHost(
                "configured cgroup parent is not root-owned and protected".into(),
            ));
        }
        let enabled_text =
            fs::read_to_string(parent_path.join("cgroup.subtree_control")).map_err(|_| {
                SupervisorError::UnsupportedHost("cgroup delegation unavailable".into())
            })?;
        let enabled = enabled_text
            .split_whitespace()
            .map(|controller| controller.trim_start_matches('+'))
            .collect::<std::collections::BTreeSet<_>>();
        if !["cpu", "memory", "pids"]
            .into_iter()
            .all(|controller| enabled.contains(controller))
        {
            return Err(SupervisorError::UnsupportedHost(
                "cgroup parent lacks delegated cpu, memory, and pids controllers".into(),
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn run_guest(
        &self,
        request: GuestRunRequest<'_, '_>,
    ) -> Result<(TaskReply, PendingLaunchEvidence), SupervisorError> {
        let GuestRunRequest {
            child,
            api,
            task_path,
            task_guest_path,
            firecracker_pid,
            state,
            envelope,
            starting_world_root,
            policy,
            launched_inputs,
            launch_hook,
            mut guest_rpc_hook,
        } = request;
        let task_endpoint = task_path.with_file_name(format!("{TASK_SOCKET_NAME}_7000"));
        let _ = fs::remove_file(&task_endpoint);
        let listener = UnixListener::bind(&task_endpoint)?;
        fs::set_permissions(&task_endpoint, fs::Permissions::from_mode(0o600))?;
        let (expected_socket_uid, expected_socket_gid) = match &launched_inputs {
            SupervisorLaunchInputs::Direct(_) => {
                (unsafe { libc::geteuid() }, Some(unsafe { libc::getegid() }))
            }
            SupervisorLaunchInputs::Jailed(context) => {
                chown_path(&task_endpoint, context.config.uid, context.config.gid)?;
                (context.config.uid, Some(context.config.gid))
            }
        };
        listener.set_nonblocking(true)?;

        // Measure the actual Firecracker API state before starting the VM.
        let endpoint = UnixEndpointIdentity::capture_with_owner(
            &listener,
            &task_endpoint,
            expected_socket_uid,
            expected_socket_gid,
        )
        .map_err(|_| SupervisorError::Protocol("host vsock UDS identity refused".into()))?;
        let full_config = api_get(api, "/vm/config")?;
        let version_bytes = api_get(api, "/version")?;
        let version_json: serde_json::Value =
            serde_json::from_slice(&version_bytes).map_err(|_| {
                SupervisorError::Protocol("Firecracker version response malformed".into())
            })?;
        let firecracker_version = version_json
            .get("firecracker_version")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                SupervisorError::Protocol("Firecracker version response lacks identity".into())
            })?
            .to_owned();
        let vmm = VmmIncarnation::capture_linux(firecracker_pid)
            .map_err(|_| SupervisorError::Protocol("VMM incarnation measurement refused".into()))?;
        let (
            vmm_input_fds,
            firecracker_path,
            kernel_path,
            rootfs_path,
            workspace_path,
            guest_supervisor_path,
            jail_root_host,
            input_binding,
            jailer_input_binding,
            production_context,
        ) = match launched_inputs {
            SupervisorLaunchInputs::Direct(inputs) => {
                let vmm_fds = inputs.vmm_input_fds();
                let paths = (
                    inputs.firecracker_path(firecracker_pid),
                    inputs.kernel_path(firecracker_pid),
                    inputs.rootfs_path(firecracker_pid),
                    inputs.workspace_path(firecracker_pid),
                    inputs.guest_supervisor_path(),
                );
                (
                    Some(vmm_fds),
                    paths.0,
                    paths.1,
                    paths.2,
                    paths.3,
                    paths.4,
                    None,
                    Some(*inputs),
                    None,
                    None,
                )
            }
            SupervisorLaunchInputs::Jailed(mut context) => {
                let jailed = context.resources.clone();
                let jailer_input_binding = context
                    .input_binding
                    .take()
                    .map(|binding| LaunchedJailerInputBinding::new(binding, jailed.clone()))
                    .ok_or_else(|| {
                        SupervisorError::Protocol(
                            "jailer input binding was already consumed or missing".into(),
                        )
                    })?;
                (
                    None,
                    context.jail_root.join("firecracker"),
                    jailed.kernel_host_path,
                    jailed.rootfs_host_path,
                    jailed.workspace_host_path,
                    self.backend.guest_supervisor.clone(),
                    Some(context.jail_root.clone()),
                    None,
                    Some(jailer_input_binding),
                    Some(context),
                )
            }
        };
        let launch = MeasuredLaunchSession::capture(
            &full_config,
            CaptureContext {
                profile: LaunchProfile::Workspace,
                vmm_birth_identity_root: None,
                run_id: envelope.run_id.clone(),
                execution_id: envelope.execution_id.clone(),
                challenge: envelope.challenge.clone(),
                s0_root: starting_world_root,
                firecracker_version,
                firecracker_path,
                kernel_path,
                rootfs_path,
                workspace_path,
                guest_policy_path: guest_supervisor_path,
                uds_path: task_guest_path.to_path_buf(),
                jail_root_host,
                broker_endpoint: endpoint,
                policy,
                vmm,
                vmm_input_fds,
                input_binding,
                jailer_input_binding,
            },
        )
        .map_err(|error| {
            SupervisorError::Protocol(format!("measured launch topology refused: {error:?}"))
        })?;
        let prestart_api_configuration = api_get(api, "/vm/config")?;
        launch
            .verify_same_config(&prestart_api_configuration)
            .and_then(|()| launch.revalidate_inputs())
            .map_err(|_| {
                SupervisorError::Protocol("launch inputs changed after measurement".into())
            })?;
        if let Some(context) = production_context.as_ref() {
            context
                .resources
                .verify_before_instance_start()
                .map_err(|_| {
                    SupervisorError::Protocol(
                        "jail resources changed or have an untrusted parent before InstanceStart"
                            .into(),
                    )
                })?;
            write_json_record(
                &state.join("production-launch-prestart.json"),
                &serde_json::json!({
                    "schema_version": 1,
                    "assurance_grade": "PRE_PRODUCTION_VERIFICATION",
                    "run_id": &envelope.run_id,
                    "execution_id": &envelope.execution_id,
                    "challenge": &envelope.challenge,
                    "jail_id": &context.jail_id,
                    "jailer_pid": context.jailer_pid,
                    "firecracker_pid_host_namespace": context.firecracker_pid,
                    "firecracker_pid_in_namespace": context.firecracker_pid_namespace,
                    "input_binding_root": &context.resources.input_binding_root,
                    "materialized_resources": [
                        FileIdentity::measure(&context.resources.kernel_host_path).map_err(|_| SupervisorError::Protocol("jail kernel identity changed".into()))?,
                        FileIdentity::measure(&context.resources.rootfs_host_path).map_err(|_| SupervisorError::Protocol("jail rootfs identity changed".into()))?,
                        FileIdentity::measure(&context.resources.workspace_host_path).map_err(|_| SupervisorError::Protocol("jail workspace identity changed".into()))?,
                    ],
                    "jailer_sha256": &context.jailer_sha256,
                    "firecracker_sha256": &context.firecracker_sha256,
                    "api_configuration": serde_json::from_slice::<serde_json::Value>(&prestart_api_configuration).map_err(|_| SupervisorError::Protocol("prestart API configuration malformed".into()))?,
                    "api_configuration_blake3": blake3::hash(&prestart_api_configuration).to_hex().to_string(),
                }),
            )?;
        } else {
            launch
                .write_direct_prestart_evidence(
                    &prestart_api_configuration,
                    &state.join("direct-launch-prestart.json"),
                )
                .map_err(|_| {
                    SupervisorError::Protocol("durable prestart launch evidence refused".into())
                })?;
        }
        launch.revalidate_inputs().map_err(|_| {
            SupervisorError::Protocol(
                "launch inputs changed between prestart evidence and InstanceStart".into(),
            )
        })?;
        let instance_start_api_configuration = api_get(api, "/vm/config")?;
        launch
            .verify_same_config(&instance_start_api_configuration)
            .map_err(|_| {
                SupervisorError::Protocol(
                    "Firecracker API configuration changed before InstanceStart".into(),
                )
            })?;
        launch.revalidate_inputs().map_err(|_| {
            SupervisorError::Protocol(
                "launch inputs changed immediately before InstanceStart".into(),
            )
        })?;
        if let Some(context) = production_context.as_ref() {
            context
                .resources
                .verify_before_instance_start()
                .map_err(|_| {
                    SupervisorError::Protocol(
                        "jail resources changed immediately before InstanceStart".into(),
                    )
                })?;
        }
        let instance_start_api_value: serde_json::Value =
            serde_json::from_slice(&instance_start_api_configuration).map_err(|_| {
                SupervisorError::Protocol(
                    "pre-InstanceStart Firecracker API configuration was malformed".into(),
                )
            })?;

        if let Some(hook) = launch_hook {
            hook(&launch)?;
        }

        let instance_start_response = api_request_with_evidence(
            api,
            "PUT",
            "/actions",
            br#"{"action_type":"InstanceStart"}"#,
        )?;
        write_json_record(
            &state.join(if production_context.is_some() {
                "production-launch-instance-start.json"
            } else {
                "direct-launch-instance-start.json"
            }),
            &serde_json::json!({
                "schema_version": 1,
                "run_id": &envelope.run_id,
                "execution_id": &envelope.execution_id,
                "challenge": &envelope.challenge,
                "action": "InstanceStart",
                "response": instance_start_response,
                "api_configuration_immediately_before_instance_start": instance_start_api_value,
                "api_configuration_bytes_blake3": blake3::hash(&instance_start_api_configuration).to_hex().to_string(),
            }),
        )?;
        let deadline = Instant::now() + self.timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(SupervisorError::Protocol(
                    "guest task transport timeout".into(),
                ));
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    launch.broker_endpoint().revalidate().map_err(|_| {
                        SupervisorError::Protocol("host vsock UDS identity changed".into())
                    })?;
                    let peer = unix_peer_credentials(&stream)?;
                    let observed_vmm = VmmIncarnation::capture_linux(peer.0).map_err(|_| {
                        SupervisorError::Protocol("vsock peer incarnation refused".into())
                    })?;
                    if peer.0 != launch.vmm().pid()
                        || peer.1 != launch.vmm().owner().0
                        || peer.2 != launch.vmm().owner().1
                        || !observed_vmm.same_process(launch.vmm())
                    {
                        return Err(SupervisorError::Protocol(
                            "vsock peer is not the measured Firecracker process".into(),
                        ));
                    }
                    send_json(&mut stream, &envelope)?;
                    let task_envelope_identity = envelope.identity().map_err(|_| {
                        SupervisorError::Protocol("TaskEnvelope identity failed".into())
                    })?;
                    send_json(
                        &mut stream,
                        &serde_json::json!({
                            "task_envelope_identity": task_envelope_identity,
                        }),
                    )?;
                    if let Some(hook) = guest_rpc_hook.as_deref_mut() {
                        hook(&mut stream, &envelope)?;
                    }
                    let reply: TaskReply = receive_json(&mut stream)?;
                    // `supervisor_identity` is guest supplied and is not used as
                    // host identity or terminal-closure evidence.
                    if !reply.matches_challenge(&envelope) {
                        return Err(SupervisorError::Protocol(
                            "guest reply does not match this diagnostic challenge".into(),
                        ));
                    }
                    launch.broker_endpoint().revalidate().map_err(|_| {
                        SupervisorError::Protocol("host vsock UDS identity changed".into())
                    })?;
                    let observed_vmm =
                        VmmIncarnation::capture_linux(firecracker_pid).map_err(|_| {
                            SupervisorError::Protocol("VMM exited before reply closure".into())
                        })?;
                    if !observed_vmm.same_process(launch.vmm()) {
                        return Err(SupervisorError::Protocol(
                            "VMM process incarnation changed during guest reply".into(),
                        ));
                    }
                    let postguest_api_configuration = api_get(api, "/vm/config")?;
                    let postguest_api_value: serde_json::Value =
                        serde_json::from_slice(&postguest_api_configuration).map_err(|_| {
                            SupervisorError::Protocol(
                                "post-guest Firecracker API configuration was malformed".into(),
                            )
                        })?;
                    write_json_record(
                        &state.join(if production_context.is_some() {
                            "production-launch-postguest-config.json"
                        } else {
                            "direct-launch-postguest-config.json"
                        }),
                        &serde_json::json!({
                            "schema_version": 1,
                            "run_id": &envelope.run_id,
                            "execution_id": &envelope.execution_id,
                            "challenge": &envelope.challenge,
                            "configuration": postguest_api_value,
                            "configuration_bytes_blake3": blake3::hash(&postguest_api_configuration).to_hex().to_string(),
                            "observation_point": "after_challenge_matched_guest_reply"
                        }),
                    )?;
                    launch
                        .verify_same_config(&postguest_api_configuration)
                        .map_err(|_| {
                            SupervisorError::Protocol(
                                "Firecracker API configuration changed during guest execution"
                                    .into(),
                            )
                        })?;
                    launch.revalidate_inputs_after_guest().map_err(|error| {
                        SupervisorError::Protocol(format!(
                            "launch input revalidation after guest execution refused: {error:?}"
                        ))
                    })?;
                    write_json_record(
                        &state.join(if production_context.is_some() {
                            "production-launch-guest-start.json"
                        } else {
                            "direct-launch-guest-start.json"
                        }),
                        &serde_json::json!({
                            "schema_version": 1,
                            "run_id": &envelope.run_id,
                            "execution_id": &envelope.execution_id,
                            "challenge": &envelope.challenge,
                            "host_observed_vsock_peer": {
                                "pid": peer.0,
                                "uid": peer.1,
                                "gid": peer.2,
                            },
                            "measured_vmm_incarnation": launch.vmm(),
                            "guest_task_reply": &reply,
                            "observation": "fresh_challenge_matched_reply_received_over_measured_vmm_channel"
                        }),
                    )?;
                    let evidence = if let Some(context) = production_context {
                        let observed = ObservedContainedLaunch::from_verified_jailer(
                            launch,
                            &context.jail_id,
                            context.jailer_pid,
                            context.jailer_process,
                            context.firecracker_pid,
                            context.firecracker_pid_namespace,
                            &context.jailer_path,
                            &context.jailer_sha256,
                            &context.firecracker_sha256,
                            context.config.uid,
                            context.config.gid,
                            &context.jail_root,
                            &context.config.cgroup_parent,
                            context.config.memory_max_bytes,
                            context.config.pids_max,
                            &context.resources,
                        )
                        .map_err(|error| {
                            SupervisorError::Protocol(format!(
                                "production containment observation refused: {error:?}"
                            ))
                        })?;
                        PendingLaunchEvidence::Contained(Box::new(observed))
                    } else {
                        PendingLaunchEvidence::Direct(Box::new(
                            DirectMeasuredLaunch::from_direct_session(launch, state.to_path_buf()),
                        ))
                    };
                    return Ok((reply, evidence));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            if !Path::new(&format!("/proc/{firecracker_pid}")).exists() {
                return Err(SupervisorError::Protocol(
                    "Firecracker VMM exited before task transport".into(),
                ));
            }
            if production_context.is_none()
                && let Some(status) = child.try_wait()?
            {
                return Err(SupervisorError::Protocol(format!(
                    "firecracker exited before task transport: {status}"
                )));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn wait_for_socket(path: &Path, timeout: Duration) -> Result<(), SupervisorError> {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if Instant::now() >= deadline {
            return Err(SupervisorError::Protocol(
                "Firecracker API socket timeout".into(),
            ));
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    Ok(())
}

fn directory_is_trusted(path: &Path) -> Result<bool, SupervisorError> {
    if !path.is_absolute() {
        return Ok(false);
    }
    let canonical = path.canonicalize().map_err(|error| {
        SupervisorError::Invalid(format!("directory path unavailable: {error}"))
    })?;
    if canonical != path {
        return Ok(false);
    }
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn ensure_root_trusted_directory(path: &Path) -> Result<(), SupervisorError> {
    if !path.is_absolute() {
        return Err(SupervisorError::Invalid(
            "jailer chroot base must be absolute".into(),
        ));
    }
    fs::create_dir_all(path)?;
    if !directory_is_trusted(path)? {
        return Err(SupervisorError::Invalid(
            "jailer chroot base has an untrusted or writable parent".into(),
        ));
    }
    Ok(())
}

pub(crate) fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<(), SupervisorError> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| SupervisorError::Invalid("path contains NUL".into()))?;
    if unsafe { libc::chown(path.as_ptr(), uid, gid) } != 0 {
        return Err(SupervisorError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, SupervisorError> {
    let _profile = crate::profile::Span::new("resource_sha256_verification");
    let output = Command::new("/usr/bin/sha256sum")
        .arg("--")
        .arg(path)
        .env_clear()
        .output()?;
    if !output.status.success() {
        return Err(SupervisorError::Invalid(format!(
            "sha256sum failed for {}",
            path.display()
        )));
    }
    let digest = std::str::from_utf8(&output.stdout)
        .ok()
        .and_then(|line| line.split_whitespace().next())
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| SupervisorError::Invalid("sha256sum output was malformed".into()))?;
    Ok(digest.to_owned())
}

fn copy_locked_executable(
    source: &Path,
    destination: &Path,
    expected_sha256: &str,
) -> Result<(), SupervisorError> {
    if sha256_file(source)? != expected_sha256 {
        return Err(SupervisorError::Invalid(
            "executable source hash mismatch".into(),
        ));
    }
    let before = FileIdentity::measure(source)
        .map_err(|_| SupervisorError::Invalid("executable source identity unavailable".into()))?;
    let mut input = File::open(source)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(destination)?;
    let copied = io::copy(&mut input, &mut output)?;
    crate::profile::bytes("jail_resource_materialization", "copied_logical", copied);
    output.sync_all_traced()?;
    if unsafe { libc::fchown(output.as_raw_fd(), 0, 0) } != 0
        || unsafe { libc::fchmod(output.as_raw_fd(), 0o500) } != 0
    {
        return Err(SupervisorError::Io(io::Error::last_os_error()));
    }
    output.sync_all_traced()?;
    let after = FileIdentity::measure(source)
        .map_err(|_| SupervisorError::Invalid("executable source changed while copying".into()))?;
    let staged = FileIdentity::measure(destination)
        .map_err(|_| SupervisorError::Invalid("staged executable identity unavailable".into()))?;
    if before.blake3() != after.blake3()
        || before.device_inode() != after.device_inode()
        || before.blake3() != staged.blake3()
        || sha256_file(destination)? != expected_sha256
    {
        return Err(SupervisorError::Invalid(
            "staged executable identity mismatch".into(),
        ));
    }
    Ok(())
}

fn copy_isolated_workspace(source: &Path, destination: &Path) -> io::Result<()> {
    let source_meta = fs::metadata(source)?;
    let destination_meta = fs::metadata(destination)?;
    if source_meta.dev() == destination_meta.dev() && source_meta.ino() == destination_meta.ino() {
        return Err(io::Error::other(
            "refusing workspace copy onto its own consumed inode",
        ));
    }
    let copied = fs::copy(source, destination)?;
    crate::profile::bytes("mutable_state_materialization", "copied_logical", copied);
    File::open(destination)?.sync_all_traced()
}

fn protect_jailer_inputs(jail_root: &Path) -> Result<(), SupervisorError> {
    if fs::symlink_metadata(jail_root)?.file_type().is_symlink()
        || fs::symlink_metadata(jail_root.join("firecracker"))?
            .file_type()
            .is_symlink()
    {
        return Err(SupervisorError::Invalid(
            "jailer resource root or executable is a symlink".into(),
        ));
    }
    chown_path(jail_root, 0, 0)?;
    fs::set_permissions(jail_root, fs::Permissions::from_mode(0o755))?;
    let executable = jail_root.join("firecracker");
    chown_path(&executable, 0, 0)?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o555))?;
    if !directory_is_trusted(jail_root)? {
        return Err(SupervisorError::Invalid(
            "jailer input parent chain remains untrusted".into(),
        ));
    }
    Ok(())
}

fn spawn_observed_jailer(
    command: &mut Command,
) -> Result<(Child, VmmIncarnation), SupervisorError> {
    // Adopt the official jailer's CLONE_NEWPID child after the short-lived
    // jailer exits. Keep a kernel-observed executable/birth record by tracing
    // only the exec stop; detach before the official jailer performs its setup.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    unsafe {
        command.pre_exec(|| {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let pid = child.id();
    let observation = (|| {
        let mut status = 0;
        if unsafe { libc::waitpid(pid as i32, &mut status, 0) } != pid as i32
            || !libc::WIFSTOPPED(status)
            || libc::WSTOPSIG(status) != libc::SIGTRAP
        {
            return Err(SupervisorError::Protocol(
                "jailer exec observation stop unavailable".into(),
            ));
        }
        let incarnation = VmmIncarnation::capture_linux(pid)
            .map_err(|_| SupervisorError::Protocol("jailer exec incarnation unavailable".into()))?;
        if unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) } == -1 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(incarnation)
    })();
    match observation {
        Ok(incarnation) => Ok((child, incarnation)),
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(error)
        }
    }
}

fn configure_broker_firecracker(api: &Path, task: &Path) -> Result<(), SupervisorError> {
    let encode = |value: serde_json::Value| {
        serde_json::to_vec(&value).map_err(|e| SupervisorError::Protocol(e.to_string()))
    };
    api_request(
        api,
        "PUT",
        "/boot-source",
        &encode(serde_json::json!({
            "kernel_image_path":"/kernel", "boot_args":crate::measured_launch::BROKER_BOOT_ARGS
        }))?,
    )?;
    api_request(api,"PUT","/drives/rootfs",br#"{"drive_id":"rootfs","path_on_host":"/rootfs.ext4","is_root_device":true,"is_read_only":true,"io_engine":"Sync"}"#)?;
    api_request(
        api,
        "PUT",
        "/machine-config",
        br#"{"vcpu_count":1,"mem_size_mib":256,"smt":false}"#,
    )?;
    api_request(
        api,
        "PUT",
        "/vsock",
        &encode(serde_json::json!({"guest_cid":3,"uds_path":task}))?,
    )
}

fn retire_jailed_vmm(
    api: &Path,
    incarnation: &VmmIncarnation,
    state: &Path,
) -> Result<i32, SupervisorError> {
    let pid = incarnation.pid();
    let current = VmmIncarnation::capture_linux(pid)
        .map_err(|_| SupervisorError::Protocol("VMM missing before shutdown".into()))?;
    if !current.same_process(incarnation) {
        return Err(SupervisorError::Protocol(
            "VMM substituted before shutdown".into(),
        ));
    }
    let response = api_request_with_evidence(
        api,
        "PUT",
        "/actions",
        br#"{"action_type":"SendCtrlAltDel"}"#,
    )?;
    write_json_record(
        &state.join("production-launch-shutdown.json"),
        &serde_json::json!({
            "action": "SendCtrlAltDel", "vmm": incarnation, "response": response,
            "production_authority_minted": false,
        }),
    )?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut status = 0;
        let waited =
            unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG | libc::__WALL) };
        if waited == pid as i32 {
            write_json_record(
                &state.join("production-launch-vmm-exit.json"),
                &serde_json::json!({
                    "pid": pid, "raw_wait_status": status,
                    "exited": libc::WIFEXITED(status),
                    "exit_code": if libc::WIFEXITED(status) { Some(libc::WEXITSTATUS(status)) } else { None },
                    "production_authority_minted": false,
                }),
            )?;
            return Ok(status);
        }
        if waited < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if Instant::now() >= deadline {
            return Err(SupervisorError::Protocol("VMM did not exit cleanly after SendCtrlAltDel; forced cleanup cannot mint production authority".into()));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_jailer_child(
    _jailer_pid: u32,
    jail_root: &Path,
    timeout: Duration,
) -> Result<(u32, u32), SupervisorError> {
    let pid_file = jail_root.join("firecracker.pid");
    let expected_path = jail_root.join("firecracker");
    let jail_root_identity = fs::metadata(jail_root)?;
    let deadline = Instant::now() + timeout;
    let mut expected_identity = None;
    loop {
        // The official jailer creates/chowns its chroot tree asynchronously
        // after spawn. Do not turn that normal startup race into an error.
        if expected_identity.is_none() {
            expected_identity = FileIdentity::measure(&expected_path).ok();
        }
        let expected = expected_identity.as_ref();
        let pid_value = fs::read_to_string(&pid_file)
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok());
        if let (Some(expected), Some(pid_value)) = (expected, pid_value)
            && pid_value != 0
            && let Ok(entries) = fs::read_dir("/proc")
        {
            for entry in entries.flatten() {
                let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
                    continue;
                };
                let process_root = fs::metadata(format!("/proc/{pid}/root"));
                let process_exe = fs::metadata(format!("/proc/{pid}/exe"));
                if !process_root.is_ok_and(|identity| {
                    identity.dev() == jail_root_identity.dev()
                        && identity.ino() == jail_root_identity.ino()
                }) || !process_exe.is_ok_and(|identity| {
                    identity.dev() == expected.device_inode().0
                        && identity.ino() == expected.device_inode().1
                }) {
                    continue;
                }
                let actual = VmmIncarnation::capture_linux(pid).map_err(|_| {
                    SupervisorError::Protocol("jailed Firecracker incarnation unavailable".into())
                })?;
                if actual.owner().0 == 0 {
                    continue;
                }
                let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
                let namespace_pids = status
                    .lines()
                    .find_map(|line| line.strip_prefix("NSpid:"))
                    .map(|value| {
                        value
                            .split_whitespace()
                            .filter_map(|item| item.parse::<u32>().ok())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if namespace_pids.first() == Some(&pid_value)
                    && let Some(namespace_pid) = namespace_pids.last().copied()
                {
                    return Ok((pid, namespace_pid));
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(SupervisorError::Protocol(
                "jailed Firecracker child identity timeout".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn terminate_firecracker_in_jail(jail_root: &Path) {
    let (Ok(root), Ok(executable)) = (
        fs::metadata(jail_root),
        fs::metadata(jail_root.join("firecracker")),
    ) else {
        return;
    };
    let Ok(entries) = fs::read_dir("/proc") else {
        return;
    };
    let pids = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok())
        .filter(|pid| {
            let process_root = fs::metadata(format!("/proc/{pid}/root"));
            let process_exe = fs::metadata(format!("/proc/{pid}/exe"));
            process_root
                .is_ok_and(|metadata| metadata.dev() == root.dev() && metadata.ino() == root.ino())
                && process_exe.is_ok_and(|metadata| {
                    metadata.dev() == executable.dev() && metadata.ino() == executable.ino()
                })
        })
        .collect::<Vec<_>>();
    for pid in &pids {
        unsafe { libc::kill(*pid, libc::SIGTERM) };
    }
    for _ in 0..50 {
        for pid in &pids {
            let mut status = 0;
            unsafe {
                libc::waitpid(*pid, &mut status, libc::WNOHANG | libc::__WALL);
            }
        }
        if pids
            .iter()
            .all(|pid| !Path::new(&format!("/proc/{pid}")).exists())
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    for pid in &pids {
        if Path::new(&format!("/proc/{pid}")).exists() {
            unsafe { libc::kill(*pid, libc::SIGKILL) };
        }
    }
    for _ in 0..50 {
        for pid in &pids {
            let mut status = 0;
            unsafe {
                libc::waitpid(*pid, &mut status, libc::WNOHANG | libc::__WALL);
            }
        }
        if pids
            .iter()
            .all(|pid| !Path::new(&format!("/proc/{pid}")).exists())
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn cleanup_failed_jailer(child: &mut Child, paths: Option<(&PathBuf, &PathBuf)>) -> io::Result<()> {
    if let Some((jail_root, _)) = paths {
        terminate_firecracker_in_jail(jail_root);
    }
    let _ = child.kill();
    let _ = child.wait();
    if let Some((jail_root, cgroup)) = paths {
        if let Some(jail_dir) = jail_root.parent()
            && jail_dir.exists()
        {
            fs::remove_dir_all(jail_dir)?;
        }
        if cgroup.exists() {
            let _ = fs::write(cgroup.join("cgroup.kill"), b"1");
            for _ in 0..50 {
                let empty = fs::read_to_string(cgroup.join("cgroup.procs"))
                    .is_ok_and(|processes| processes.trim().is_empty());
                if empty && fs::remove_dir(cgroup).is_ok() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            if cgroup.exists() {
                return Err(io::Error::other(
                    "jailer cgroup remained populated after bounded cleanup",
                ));
            }
        }
    }
    Ok(())
}

fn pause_and_snapshot(
    api: &Path,
    state: &Path,
    jail_root: Option<&Path>,
) -> Result<(), SupervisorError> {
    api_request(api, "PATCH", "/vm", br#"{"state":"Paused"}"#)?;
    let (snapshot_path, mem_file_path) = match jail_root {
        Some(root) => (root.join("run/final.snapshot"), root.join("run/final.mem")),
        None => (state.join("final.snapshot"), state.join("final.mem")),
    };
    let (api_snapshot_path, api_mem_path) = if jail_root.is_some() {
        (
            PathBuf::from("/run/final.snapshot"),
            PathBuf::from("/run/final.mem"),
        )
    } else {
        (snapshot_path, mem_file_path)
    };
    let snapshot = serde_json::to_vec(&serde_json::json!({
        "snapshot_type": "Full",
        "snapshot_path": api_snapshot_path,
        "mem_file_path": api_mem_path
    }))
    .map_err(|e| SupervisorError::Invalid(e.to_string()))?;
    api_request(api, "PUT", "/snapshot/create", &snapshot)?;
    Ok(())
}

fn configure_firecracker(
    api: &Path,
    kernel: &Path,
    rootfs: &Path,
    workspace: &Path,
    task_socket_guest: &Path,
) -> Result<(), SupervisorError> {
    let boot = serde_json::to_vec(&serde_json::json!({
        "kernel_image_path": kernel,
        "boot_args": "console=ttyS0 root=/dev/vda rw init=/sbin/realm-guest-supervisor"
    }))
    .map_err(|e| SupervisorError::Invalid(e.to_string()))?;
    api_request(api, "PUT", "/boot-source", &boot)?;
    let drive = serde_json::to_vec(&serde_json::json!({
        "drive_id": "rootfs",         "path_on_host": rootfs,
        "is_root_device": true, "is_read_only": true, "io_engine": "Sync"
    }))
    .map_err(|e| SupervisorError::Invalid(e.to_string()))?;
    api_request(api, "PUT", "/drives/rootfs", &drive)?;
    let workspace_drive = serde_json::to_vec(&serde_json::json!({
        "drive_id": "workspace", "path_on_host": workspace,
        "is_root_device": false, "is_read_only": false, "io_engine": "Sync"
    }))
    .map_err(|e| SupervisorError::Invalid(e.to_string()))?;
    api_request(api, "PUT", "/drives/workspace", &workspace_drive)?;
    api_request(
        api,
        "PUT",
        "/machine-config",
        br#"{"vcpu_count":1,"mem_size_mib":256,"smt":false}"#,
    )?;
    let vsock = serde_json::to_vec(&serde_json::json!({
        "vsock_id": "realm-task", "guest_cid": 3, "uds_path": task_socket_guest
    }))
    .map_err(|e| SupervisorError::Invalid(e.to_string()))?;
    api_request(api, "PUT", "/vsock", &vsock)?;
    Ok(())
}

fn api_request(
    socket: &Path,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(), SupervisorError> {
    api_request_with_evidence(socket, method, path, body).map(|_| ())
}

fn api_request_with_evidence(
    socket: &Path,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<ApiRequestEvidence, SupervisorError> {
    let mut stream = UnixStream::connect(socket)?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !response.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        if response.len() > MAX_MESSAGE {
            return Err(SupervisorError::Protocol(
                "Firecracker API response too large".into(),
            ));
        }
    }
    if !response.starts_with(b"HTTP/1.1 2") {
        return Err(SupervisorError::Protocol(format!(
            "Firecracker API rejected {method} {path}"
        )));
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| SupervisorError::Protocol("malformed Firecracker API response".into()))?;
    let header_text = std::str::from_utf8(&response[..header_end]).map_err(|_| {
        SupervisorError::Protocol("invalid Firecracker API response headers".into())
    })?;
    let status_line = header_text
        .lines()
        .next()
        .ok_or_else(|| SupervisorError::Protocol("missing Firecracker API status".into()))?
        .to_owned();
    Ok(ApiRequestEvidence {
        status_line,
        response_headers_blake3: blake3::hash(&response[..header_end]).to_hex().to_string(),
    })
}

fn write_json_record(path: &Path, value: &serde_json::Value) -> Result<(), SupervisorError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| SupervisorError::Protocol(error.to_string()))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all_traced()?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all_traced()?;
    }
    Ok(())
}

fn api_get(socket: &Path, path: &str) -> Result<Vec<u8>, SupervisorError> {
    let mut stream = UnixStream::connect(socket)?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    )?;
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut header_end = None;
    let mut expected_response_len = None;
    while expected_response_len.is_none_or(|expected| response.len() < expected) {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        if response.len() > MAX_MESSAGE {
            return Err(SupervisorError::Protocol(
                "Firecracker GET response too large".into(),
            ));
        }
        if header_end.is_none() {
            let Some(end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let headers = std::str::from_utf8(&response[..end]).map_err(|_| {
                SupervisorError::Protocol("invalid Firecracker HTTP headers".into())
            })?;
            let mut lines = headers.split("\r\n");
            if !lines
                .next()
                .is_some_and(|status| status.starts_with("HTTP/1.1 200 "))
            {
                return Err(SupervisorError::Protocol(format!(
                    "Firecracker rejected GET {path}"
                )));
            }
            let content_length = lines
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                .ok_or_else(|| {
                    SupervisorError::Protocol("Firecracker GET omitted Content-Length".into())
                })?;
            if content_length > MAX_MESSAGE {
                return Err(SupervisorError::Protocol(
                    "Firecracker GET response too large".into(),
                ));
            }
            expected_response_len = Some(end + 4 + content_length);
            header_end = Some(end);
        }
    }
    let header_end = header_end
        .ok_or_else(|| SupervisorError::Protocol("malformed Firecracker GET response".into()))?;
    if Some(response.len()) != expected_response_len {
        return Err(SupervisorError::Protocol(
            "Firecracker GET body length mismatch".into(),
        ));
    }
    Ok(response[header_end + 4..].to_vec())
}

pub(crate) fn unix_peer_credentials(
    stream: &UnixStream,
) -> Result<(u32, u32, u32), SupervisorError> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(SupervisorError::Protocol(
            "host UDS peer credentials unavailable".into(),
        ));
    }
    let credentials = unsafe { credentials.assume_init() };
    if credentials.pid <= 0 {
        return Err(SupervisorError::Protocol(
            "host UDS peer PID invalid".into(),
        ));
    }
    Ok((credentials.pid as u32, credentials.uid, credentials.gid))
}

fn send_json<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), SupervisorError> {
    let bytes = serde_json::to_vec(value).map_err(|e| SupervisorError::Protocol(e.to_string()))?;
    if bytes.len() > MAX_MESSAGE {
        return Err(SupervisorError::Protocol("task message too large".into()));
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    Ok(())
}

fn receive_json<T: for<'de> Deserialize<'de>>(
    stream: &mut UnixStream,
) -> Result<T, SupervisorError> {
    let mut size = [0; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_MESSAGE {
        return Err(SupervisorError::Protocol(
            "invalid task message size".into(),
        ));
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|e| SupervisorError::Protocol(e.to_string()))
}

fn fresh_challenge() -> Result<String, SupervisorError> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn digest_text(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

/// The canonical official-jailer launch retained across broker service.
/// No serialized evidence can construct this live owner.
pub(crate) struct RootfsBrokerLaunch {
    child: Child,
    state: PathBuf,
    api: PathBuf,
    listener: Option<UnixListener>,
    pending: Option<ObservedContainedLaunch>,
    prepared: Option<MeasuredLaunchSession>,
    containment_context: Option<JailedLaunchContext>,
    cgroup: crate::run_closure::linux::CgroupV2Run,
    pinned_vmm: crate::run_closure::linux::PinnedVmm,
    jail_root: PathBuf,
    cgroup_path: PathBuf,
    timeout: Duration,
    started: bool,
}

impl FirecrackerSupervisor {
    pub(crate) fn prepare_rootfs_broker(
        &self,
        run: &str,
        execution: &str,
        challenge: &crate::mediation::MediationChallenge,
        s0: &str,
        policy: PolicyIdentity,
    ) -> Result<RootfsBrokerLaunch, SupervisorError> {
        let _profile = crate::profile::Span::new("host_run_jail_preparation");
        self.preflight()?;
        let config = self.backend.production_jailer.as_ref().ok_or_else(|| {
            SupervisorError::Invalid("rootfs broker publication requires official jailer".into())
        })?;
        let state = self
            .backend
            .state_dir
            .join(format!("{run}-{}", &execution[..16]));
        fs::create_dir(&state)?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
        let prepared = PreparedExecutionInputs::prepare_profile(
            &self.backend,
            &self.starting_workspace_image,
            &self.working_workspace_image,
            &state,
            LaunchProfile::RootfsBroker,
        )
        .map_err(|e| SupervisorError::Protocol(format!("broker inputs refused: {e:?}")))?;
        let binding = prepared
            .bind(
                run.into(),
                execution.into(),
                challenge.root().into(),
                s0.into(),
                policy.clone(),
            )
            .map_err(|e| {
                SupervisorError::Protocol(format!("broker input binding refused: {e:?}"))
            })?;
        let mut launched = self.launch_with_jailer_profile(
            binding,
            config,
            &state,
            run,
            execution,
            challenge.root(),
            LaunchProfile::RootfsBroker,
        )?;
        let mut ctx = match launched.inputs {
            SupervisorLaunchInputs::Jailed(ctx) => *ctx,
            SupervisorLaunchInputs::Direct(_) => {
                return Err(SupervisorError::Protocol(
                    "direct launch cannot enter production broker".into(),
                ));
            }
        };
        let cgroup_path = Path::new("/sys/fs/cgroup")
            .join(&config.cgroup_parent)
            .join(&ctx.jail_id);
        let setup = (|| {
            let endpoint_path =
                PathBuf::from(format!("{}_7000", launched.task_socket_host.display()));
            let listener = UnixListener::bind(&endpoint_path)?;
            chown_path(&endpoint_path, config.uid, config.gid)?;
            fs::set_permissions(&endpoint_path, fs::Permissions::from_mode(0o600))?;
            listener.set_nonblocking(true)?;
            let endpoint = UnixEndpointIdentity::capture_with_owner(
                &listener,
                &endpoint_path,
                config.uid,
                Some(config.gid),
            )
            .map_err(|e| SupervisorError::Protocol(format!("broker endpoint refused: {e:?}")))?;
            let vmm = VmmIncarnation::capture_linux(launched.firecracker_pid)
                .map_err(|e| SupervisorError::Protocol(format!("broker VMM refused: {e:?}")))?;
            let cgroup = crate::run_closure::linux::CgroupV2Run::open(&cgroup_path)
                .map_err(|e| SupervisorError::Protocol(e.to_string()))?;
            let (pinned_vmm, birth) = cgroup
                .pin_idle_adopted_vmm(&vmm)
                .map_err(|e| SupervisorError::Protocol(e.to_string()))?;
            let full_config = api_get(&launched.api_socket, "/vm/config")?;
            let version: serde_json::Value =
                serde_json::from_slice(&api_get(&launched.api_socket, "/version")?)
                    .map_err(|e| SupervisorError::Protocol(e.to_string()))?;
            let firecracker_version = version["firecracker_version"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| SupervisorError::Protocol("Firecracker version missing".into()))?
                .to_owned();
            let launch = MeasuredLaunchSession::capture(
                &full_config,
                CaptureContext {
                    profile: LaunchProfile::RootfsBroker,
                    vmm_birth_identity_root: Some(birth.root().to_owned()),
                    run_id: run.into(),
                    execution_id: execution.into(),
                    challenge: challenge.root().into(),
                    s0_root: s0.into(),
                    firecracker_version,
                    firecracker_path: ctx.jail_root.join("firecracker"),
                    kernel_path: ctx.resources.kernel_host_path.clone(),
                    rootfs_path: ctx.resources.rootfs_host_path.clone(),
                    workspace_path: ctx.resources.workspace_host_path.clone(),
                    guest_policy_path: self.backend.guest_supervisor.clone(),
                    uds_path: launched.task_socket_guest.clone(),
                    jail_root_host: Some(ctx.jail_root.clone()),
                    broker_endpoint: endpoint,
                    policy,
                    vmm,
                    vmm_input_fds: None,
                    input_binding: None,
                    jailer_input_binding: Some(LaunchedJailerInputBinding::new(
                        ctx.input_binding.take().ok_or_else(|| {
                            SupervisorError::Protocol("consumed binding missing".into())
                        })?,
                        ctx.resources.clone(),
                    )),
                },
            )
            .map_err(|e| {
                SupervisorError::Protocol(format!(
                    "rootfs broker launch measurement refused: {e:?}"
                ))
            })?;
            write_json_record(
                &state.join("production-launch-prestart.json"),
                &serde_json::json!({
                    "run_id":run,"execution_id":execution,"challenge":challenge.root(),
                    "profile":"rootfs-only-broker-v1","api_configuration":serde_json::from_slice::<serde_json::Value>(&full_config).map_err(|e|SupervisorError::Protocol(e.to_string()))?,
                    "measurement_root":launch.canonical_hash_blake3(),"vmm_birth_identity":birth,
                    "raw_vmm_status":fs::read_to_string(format!("/proc/{}/status",launch.vmm().pid()))?,"authority_minted":false,
                }),
            )?;
            Ok::<_, SupervisorError>((listener, cgroup, pinned_vmm, launch))
        })();
        match setup {
            Ok((listener, cgroup, pinned_vmm, launch)) => Ok(RootfsBrokerLaunch {
                child: launched.child,
                state,
                api: launched.api_socket,
                listener: Some(listener),
                pending: None,
                prepared: Some(launch),
                jail_root: ctx.jail_root.clone(),
                containment_context: Some(ctx),
                cgroup,
                pinned_vmm,
                cgroup_path,
                timeout: self.timeout,
                started: false,
            }),
            Err(e) => {
                let _ = cleanup_failed_jailer(
                    &mut launched.child,
                    Some((&ctx.jail_root, &cgroup_path)),
                );
                Err(e)
            }
        }
    }
}

impl RootfsBrokerLaunch {
    pub(crate) fn measurement(&self) -> &MeasuredLaunchSession {
        if let Some(pending) = self.pending.as_ref() {
            pending
        } else {
            self.prepared
                .as_ref()
                .expect("live session retains measured launch")
        }
    }
    pub(crate) fn state(&self) -> &Path {
        &self.state
    }
    pub(crate) fn cgroup(&self) -> &crate::run_closure::linux::CgroupV2Run {
        &self.cgroup
    }
    pub(crate) fn pinned_vmm(&self) -> &crate::run_closure::linux::PinnedVmm {
        &self.pinned_vmm
    }
    pub(crate) fn start(&mut self) -> Result<(), SupervisorError> {
        let _profile = crate::profile::Span::new("instance_start_containment");
        if self.started {
            return Err(SupervisorError::Protocol(
                "InstanceStart already consumed".into(),
            ));
        }
        let bytes = api_get(&self.api, "/vm/config")?;
        self.measurement()
            .verify_same_config(&bytes)
            .and_then(|()| self.measurement().revalidate_inputs())
            .map_err(|e| {
                SupervisorError::Protocol(format!("pre-InstanceStart consistency refused: {e:?}"))
            })?;
        let response = api_request_with_evidence(
            &self.api,
            "PUT",
            "/actions",
            br#"{"action_type":"InstanceStart"}"#,
        )?;
        write_json_record(
            &self.state.join("production-launch-instance-start.json"),
            &serde_json::json!({
                "action":"InstanceStart","response":response,
                "api_configuration_immediately_before_instance_start":serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|e|SupervisorError::Protocol(e.to_string()))?,
            }),
        )?;
        // Firecracker installs the VMM thread seccomp filter during InstanceStart.
        // Require canonical containment before any bootstrap or effect response.
        let ctx = self
            .containment_context
            .take()
            .ok_or_else(|| SupervisorError::Protocol("containment context consumed".into()))?;
        let launch = self
            .prepared
            .take()
            .ok_or_else(|| SupervisorError::Protocol("prepared launch consumed".into()))?;
        write_json_record(
            &self.state.join("production-launch-running-status.json"),
            &serde_json::json!({"phase":"RUNNING","raw_vmm_status":fs::read_to_string(format!("/proc/{}/status",launch.vmm().pid()))?}),
        )?;
        let pending = ObservedContainedLaunch::from_verified_jailer(
            launch,
            &ctx.jail_id,
            ctx.jailer_pid,
            ctx.jailer_process.clone(),
            ctx.firecracker_pid,
            ctx.firecracker_pid_namespace,
            &ctx.jailer_path,
            &ctx.jailer_sha256,
            &ctx.firecracker_sha256,
            ctx.config.uid,
            ctx.config.gid,
            &ctx.jail_root,
            &ctx.config.cgroup_parent,
            ctx.config.memory_max_bytes,
            ctx.config.pids_max,
            &ctx.resources,
        )
        .map_err(|e| {
            SupervisorError::Protocol(format!("rootfs broker containment refused: {e:?}"))
        })?;
        self.pending = Some(pending);
        self.started = true;
        Ok(())
    }
    pub(crate) fn accept(&self) -> Result<UnixStream, SupervisorError> {
        let _profile = crate::profile::Span::new("guest_boot_connection");
        if !self.started {
            return Err(SupervisorError::Protocol(
                "guest connection before InstanceStart".into(),
            ));
        }
        let deadline = Instant::now() + self.timeout;
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| SupervisorError::Protocol("effect transport already closed".into()))?;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    let peer = unix_peer_credentials(&stream)?;
                    let observed = VmmIncarnation::capture_linux(peer.0).map_err(|e| {
                        SupervisorError::Protocol(format!("broker peer refused: {e:?}"))
                    })?;
                    if peer.0 != self.measurement().vmm().pid()
                        || (peer.1, peer.2) != self.measurement().vmm().owner()
                        || !observed.same_process(self.measurement().vmm())
                    {
                        return Err(SupervisorError::Protocol(
                            "broker peer differs from measured VMM".into(),
                        ));
                    }
                    stream.set_nonblocking(false)?;
                    stream.set_read_timeout(Some(self.timeout))?;
                    stream.set_write_timeout(Some(self.timeout))?;
                    return Ok(stream);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    pub(crate) fn check_live_configuration(&self) -> Result<(), SupervisorError> {
        let current = VmmIncarnation::capture_linux(self.measurement().vmm().pid())
            .map_err(|e| SupervisorError::Protocol(format!("live VMM unavailable: {e:?}")))?;
        if !current.same_process(self.measurement().vmm()) {
            return Err(SupervisorError::Protocol("VMM incarnation changed".into()));
        }
        let bytes = api_get(&self.api, "/vm/config")?;
        self.measurement()
            .verify_same_config(&bytes)
            .and_then(|()| self.measurement().revalidate_inputs())
            .map_err(|e| {
                SupervisorError::Protocol(format!("live broker configuration refused: {e:?}"))
            })
    }
    pub(crate) fn close_transport(
        &mut self,
        stream: UnixStream,
        challenge: &crate::mediation::MediationChallenge,
    ) -> Result<crate::broker_rpc::ClosedMeasuredEffectChannel, SupervisorError> {
        self.check_live_configuration()?;
        let bytes = api_get(&self.api, "/vm/config")?;
        write_json_record(
            &self.state.join("production-launch-postguest-config.json"),
            &serde_json::json!({
                "configuration":serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|e|SupervisorError::Protocol(e.to_string()))?,
                "phase":"QUIESCING","broker_requests_completed":6,
            }),
        )?;
        let listener = self
            .listener
            .take()
            .ok_or_else(|| SupervisorError::Protocol("broker listener already consumed".into()))?;
        crate::broker_rpc::ClosedMeasuredEffectChannel::close_owned_transport(
            self.measurement(),
            challenge,
            listener,
            stream,
        )
        .map_err(|e| SupervisorError::Protocol(format!("effect-channel closure refused: {e:?}")))
    }
    pub(crate) fn retire(
        &mut self,
        completion: &crate::mediation::MeasuredBrokerCompletion,
    ) -> Result<crate::measured_launch::ProductionContainedLaunch, SupervisorError> {
        let _profile = crate::profile::Span::new("process_capability_closure");
        if self.listener.is_some()
            || completion.run_id() != self.measurement().run_id()
            || completion.execution_id() != self.measurement().execution_id()
            || self.measurement().bound_challenge() != Some(completion.challenge_root())
        {
            return Err(SupervisorError::Protocol(
                "broker not frozen for this live run".into(),
            ));
        }
        let pending = self.pending.take().ok_or_else(|| {
            SupervisorError::Protocol("contained capability already consumed".into())
        })?;
        let status = retire_jailed_vmm(&self.api, pending.vmm(), &self.state)?;
        let production = pending
            .finish_after_exit(pending_pid(&self.pinned_vmm), status)
            .map_err(|e| {
                SupervisorError::Protocol(format!("production capability refused: {e:?}"))
            })?;
        write_json_record(
            &self.state.join("production-contained-launch.json"),
            &serde_json::json!({
                "run_id":production.run_id(),"execution_id":production.execution_id(),
                "production_launch_root":production.production_launch_root(),"containment":production.containment_record(),
                "admission":"REFUSE(UNVERIFIED_BOUNDARY)","profile":"rootfs-only-broker-v1",
            }),
        )?;
        Ok(production)
    }
}

fn pending_pid(pinned: &crate::run_closure::linux::PinnedVmm) -> u32 {
    pinned.measured_pid()
}

impl Drop for RootfsBrokerLaunch {
    fn drop(&mut self) {
        let _profile = crate::profile::Span::new("run_cleanup");
        let _ = cleanup_failed_jailer(&mut self.child, Some((&self.jail_root, &self.cgroup_path)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_self_copy_is_refused_without_truncation() {
        let path = std::env::temp_dir().join(format!("r6-self-copy-{}", std::process::id()));
        fs::write(&path, b"preserve-consumed-workspace").unwrap();
        assert!(copy_isolated_workspace(&path, &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"preserve-consumed-workspace");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn official_jailer_exec_stop_records_birth_before_short_lived_parent_exits() {
        let mut command = Command::new("/bin/true");
        let (mut child, birth) = spawn_observed_jailer(&mut command).unwrap();
        assert_eq!(birth.pid(), child.id());
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn jailer_owned_input_root_is_protected_before_configuration() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let root = PathBuf::from(format!(
            "/root/realm-v6-jail-protect-{}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let exe = root.join("firecracker");
        fs::write(&exe, b"fixture-executable").unwrap();
        chown_path(&root, 1001, 1001).unwrap();
        chown_path(&exe, 1001, 1001).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!directory_is_trusted(&root).unwrap());
        protect_jailer_inputs(&root).unwrap();
        assert!(directory_is_trusted(&root).unwrap());
        let actual = fs::metadata(&exe).unwrap();
        assert_eq!(
            (actual.uid(), actual.gid(), actual.mode() & 0o777),
            (0, 0, 0o555)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn trusted_directory_check_rejects_symlink_aliases() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let root = PathBuf::from(format!("/root/realm-v6-trusted-dir-{}", std::process::id()));
        let safe = root.join("safe");
        let alias = root.join("alias");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&safe).unwrap();
        std::os::unix::fs::symlink(&safe, &alias).unwrap();
        assert!(!directory_is_trusted(&alias).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn task_envelope_binds_all_runtime_identities() {
        let envelope = TaskEnvelope {
            protocol: 1,
            run_id: "run".into(),
            tool_call_id: "call".into(),
            tool_id: "shell.exec".into(),
            capability_ref: "cap:shell.exec".into(),
            effect_contract_identity: "effect-contract".into(),
            input_workspace_identity: "input-workspace".into(),
            execution_id: "execution".into(),
            capsule_id: "capsule".into(),
            challenge: "challenge".into(),
            argv: vec!["/bin/true".into()],
            cwd: "/".into(),
            safe_environment: vec![],
            timeout_ms: 1000,
            workspace_identity: "workspace".into(),
            effect_contract: vec![],
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(
            serde_json::from_slice::<TaskEnvelope>(&bytes).unwrap(),
            envelope
        );
    }

    #[test]
    fn guest_asserted_supervisor_identity_is_not_a_host_identity() {
        let envelope = TaskEnvelope {
            protocol: 1,
            run_id: "run".into(),
            tool_call_id: "call".into(),
            tool_id: "shell.exec".into(),
            capability_ref: "cap:shell.exec".into(),
            effect_contract_identity: "effect-contract".into(),
            input_workspace_identity: "input-workspace".into(),
            execution_id: "execution".into(),
            capsule_id: "capsule".into(),
            challenge: "challenge".into(),
            argv: vec!["/bin/true".into()],
            cwd: "/".into(),
            safe_environment: vec![],
            timeout_ms: 1000,
            workspace_identity: "workspace".into(),
            effect_contract: vec![],
        };
        let reply = TaskReply {
            protocol: envelope.protocol,
            run_id: envelope.run_id.clone(),
            execution_id: envelope.execution_id.clone(),
            capsule_id: envelope.capsule_id.clone(),
            challenge: envelope.challenge.clone(),
            task_envelope_identity: envelope.identity().unwrap(),
            tool_call_id: envelope.tool_call_id.clone(),
            tool_id: envelope.tool_id.clone(),
            capability_ref: envelope.capability_ref.clone(),
            effect_contract_identity: envelope.effect_contract_identity.clone(),
            input_workspace_identity: envelope.input_workspace_identity.clone(),
            workspace_identity: envelope.workspace_identity.clone(),
            exited: true,
            exit_code: Some(0),
            crashed: false,
            completion_sequence: 1,
            supervisor_identity: "guest-self-asserted-fake".into(),
            state: "FINALIZED".into(),
        };
        assert!(reply.matches_challenge(&envelope));
        assert_eq!(reply.supervisor_identity, "guest-self-asserted-fake");
        let mut foreign_run = reply.clone();
        foreign_run.run_id = "foreign-run".into();
        let mut foreign_challenge = reply.clone();
        foreign_challenge.challenge = "foreign-challenge".into();
        let mut foreign_envelope = reply.clone();
        foreign_envelope.task_envelope_identity = "f".repeat(64);
        let mut foreign_call = reply.clone();
        foreign_call.tool_call_id = "foreign-call".into();
        for forged in [
            foreign_run,
            foreign_challenge,
            foreign_envelope,
            foreign_call,
        ] {
            assert!(!forged.matches_challenge(&envelope));
        }
        // Matching the diagnostic challenge still creates no terminal claim.
    }
}
