//! One contained, non-authorizing broker file-create/write family.
//! The real guest sends Identify, WriteRange(ABC), and Close through BrokerRpc.
//! PR12 produces containment; the runtime preserves typed launch/frontier
//! products for the independent Kepler closure and publication join.

use crate::{
    broker_rpc::{DiagnosticBinding, DiagnosticBrokerRpc, RuntimeToolCall},
    c1::{FsKind, scan_ext4_image},
    execute::{C1BackendInputPaths, prepare_workspace_images},
    execution_backend::{
        BackendError, BackendLaunchContext, BackendLaunchEvidence, BackendTask,
        ExecutionBackendCapabilities, FirecrackerBackend,
    },
    frontier::EffectFrontier,
    measured_launch::{LaunchAssuranceGrade, PolicyIdentity},
    runtime_effects::{
        BrokerCompletion, CallerState, EffectObservation, EffectOperation, FailurePoint,
        RecoveryReport, RuntimeEffectBroker, RuntimeSessionIdentity, TaskFamily,
    },
    supervisor::FirecrackerSupervisor,
};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
    time::Duration,
};

const BROKER_ID: &str = "realm-broker-rpc-diagnostic-v1";
const MAX_INPUT_BYTES: u64 = 1024 * 1024 - 10;
const MAX_TIMEOUT_MS: u64 = 300_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecRuntimePaths {
    pub workspace_root: PathBuf,
    pub input_path: PathBuf,
    pub workspace_device: PathBuf,
    pub rootfs: PathBuf,
    pub guest_supervisor: PathBuf,
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    pub state_dir: PathBuf,
    #[serde(default)]
    pub production_jailer: Option<crate::execute::ProductionJailerConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerExecRequest {
    pub tool_call: RuntimeToolCall,
    /// Fresh opaque identity assigned by the runtime to the input workspace.
    pub input_workspace_identity: String,
    pub runtime: ExecRuntimePaths,
    #[serde(default)]
    pub fault: Option<RuntimeFault>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFault {
    pub point: Option<FailurePoint>,
    #[serde(default)]
    pub guest_budget_probe: bool,
    pub caller_stop: Option<CallerState>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RuntimeTaskResult {
    Executed(Box<BrokerExecResult>),
    Recovered {
        recovery: Box<RecoveryReport>,
        prior_tool_result: Option<Box<BrokerExecResult>>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerExecResult {
    pub schema_version: u16,
    pub backend_id: String,
    pub backend_capabilities: ExecutionBackendCapabilities,
    pub run_id: String,
    pub call_id: String,
    pub tool_id: String,
    pub capability_ref: String,
    pub effect_contract_identity: String,
    pub task_envelope_identity: String,
    pub challenge: String,
    pub vmm_process_identity: String,
    pub launch_assurance_grade: LaunchAssuranceGrade,
    pub measured_launch_identity: String,
    pub launch_evidence_path: Option<PathBuf>,
    pub input_workspace_identity: String,
    pub execution_id: Option<String>,
    pub vmm_pid: Option<u32>,
    pub vmm_start_time_ticks: Option<u64>,
    pub task_launched: bool,
    pub guest_exit_code: Option<i32>,
    pub guest_task_terminal_reported: bool,
    pub vmm_process_waited: bool,
    pub observed_effects: Vec<String>,
    pub starting_world_root: String,
    pub final_world_root: Option<String>,
    pub final_result_blake3: Option<String>,
    pub final_result_bytes: Option<u64>,
    pub stdout_bytes: u64,
    pub stdout_blake3: String,
    pub stdout_truncated: bool,
    pub stderr_bytes: u64,
    pub stderr_blake3: String,
    pub stderr_truncated: bool,
    pub frontier_journal: Option<PathBuf>,
    pub frontier_head: Option<String>,
    pub frontier_blake3: Option<String>,
    pub frontier_evidence_sequence: u64,
    pub committed_file_effect: Option<CommittedFileEffect>,
    pub broker_rpc_operations: Vec<String>,
    pub unsupported_effects: Vec<String>,
    pub authority: String,
    pub decision: String,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_effects: Option<RecoveryReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_launch_reference: Option<RuntimeLaunchReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedFileEffect {
    pub path: String,
    pub bytes: u64,
    pub content_blake3: String,
    pub object_device: u64,
    pub object_inode: u64,
    pub run_id: String,
    pub call_id: String,
    pub execution_id: String,
    pub challenge: String,
    pub task_envelope_identity: String,
    pub effect_contract_identity: String,
    pub measured_launch_identity: String,
    pub vmm_process_identity: String,
    pub broker_operation_prefix: String,
    pub frontier_head: String,
    pub frontier_sequence: u64,
    pub frontier_journal_blake3: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLaunchReference {
    pub production_launch_root: String,
    pub prestart_launch_identity: String,
    pub policy_identity: String,
    pub vmm_process_identity: String,
    pub task_envelope_identity: String,
}

/// Actual in-process products from this execution. JSON result fields cannot
/// construct this handoff or a production launch. No ACCEPT authority is issued.
/// ```compile_fail
/// use realm_v6::broker_exec::RuntimeTaskExecution;
/// let _forged: RuntimeTaskExecution = serde_json::from_str("{}").unwrap();
/// ```
pub struct RuntimeTaskExecution {
    result: RuntimeTaskResult,
    launch: Option<crate::measured_launch::ProductionContainedLaunch>,
    frontier: RuntimeExecutionFrontier,
    envelope: Option<crate::task_envelope::TaskEnvelope>,
    observation: Option<crate::capsule::CapsuleObservation>,
    tool_call: RuntimeToolCall,
    caller: RuntimeCallerEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeCallerEvidence {
    pub result_state: CallerState,
    pub last_recorded_delivery: CallerState,
}

pub enum RuntimeExecutionFrontier {
    Live(Box<EffectFrontier>),
    Recovered(Box<BrokerCompletion>),
}
/// Ordinary result data and actual optional capabilities. Recovery returns a
/// broker completion capability, never reconstructs a production launch from JSON.
pub struct RuntimeExecutionParts {
    pub result: RuntimeTaskResult,
    pub launch: Option<crate::measured_launch::ProductionContainedLaunch>,
    pub frontier: RuntimeExecutionFrontier,
    pub envelope: Option<crate::task_envelope::TaskEnvelope>,
    pub observation: Option<crate::capsule::CapsuleObservation>,
    pub tool_call: RuntimeToolCall,
    pub caller: RuntimeCallerEvidence,
}
impl RuntimeTaskExecution {
    pub fn result(&self) -> &RuntimeTaskResult {
        &self.result
    }
    pub fn caller(&self) -> &RuntimeCallerEvidence {
        &self.caller
    }
    pub fn tool_call(&self) -> &RuntimeToolCall {
        &self.tool_call
    }
    pub fn into_parts(self) -> RuntimeExecutionParts {
        RuntimeExecutionParts {
            result: self.result,
            launch: self.launch,
            frontier: self.frontier,
            envelope: self.envelope,
            observation: self.observation,
            tool_call: self.tool_call,
            caller: self.caller,
        }
    }
}

#[derive(Debug)]
pub enum BrokerExecError {
    Invalid(&'static str),
    Io(std::io::Error),
    Rpc(String),
    Supervisor(String),
}

impl std::fmt::Display for BrokerExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid BrokerRpc tool call: {reason}"),
            Self::Io(error) => write!(f, "broker task I/O: {error}"),
            Self::Rpc(reason) => write!(f, "BrokerRpc refused: {reason}"),
            Self::Supervisor(reason) => write!(f, "contained supervisor refused: {reason}"),
        }
    }
}

impl std::error::Error for BrokerExecError {}

impl From<std::io::Error> for BrokerExecError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn file_entry<'a>(
    world: &'a crate::c1::FilesystemWorld,
    path: &str,
) -> Option<&'a crate::c1::CanonicalEntry> {
    world.entries.iter().find(|entry| entry.path == path)
}

fn fresh_execution_id(run_id: &str, call_id: &str) -> Result<String, BrokerExecError> {
    let mut nonce = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    Ok(digest(
        &[run_id.as_bytes(), b":", call_id.as_bytes(), b":", &nonce].concat(),
    ))
}

fn fresh_task_challenge() -> Result<String, BrokerExecError> {
    let mut nonce = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    Ok(digest(&nonce))
}

fn setup_brokered_file_output(
    workspace_root: &Path,
    execution_id: &str,
) -> Result<(PendingOutput, File), BrokerExecError> {
    let root = fs::symlink_metadata(workspace_root)?;
    if !root.is_dir()
        || root.file_type().is_symlink()
        || root.uid() != unsafe { libc::geteuid() }
        || root.mode() & 0o022 != 0
    {
        return Err(BrokerExecError::Invalid(
            "workspace root is not a private host-owned directory",
        ));
    }
    let destination = workspace_root.join("output.txt");
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(BrokerExecError::Invalid(
            "workspace write destination already exists",
        ));
    }
    let staged = workspace_root.join(format!(".realm-pending-{execution_id}"));
    let file = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&staged)?;
    Ok((PendingOutput::new(staged), file))
}

struct PendingOutput {
    path: PathBuf,
    published: bool,
}

impl PendingOutput {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            published: false,
        }
    }
}

impl Drop for PendingOutput {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn publish_brokered_file_output(
    workspace_root: &Path,
    staged: &Path,
    output: &File,
) -> Result<(), BrokerExecError> {
    let staged_name = staged
        .file_name()
        .ok_or(BrokerExecError::Invalid("staged result has no basename"))?;
    let root = File::open(workspace_root)?;
    let output_identity = output.metadata()?;
    if !output_identity.is_file() || output_identity.nlink() != 1 {
        return Err(BrokerExecError::Invalid(
            "staged result identity is unsupported",
        ));
    }
    let staged_metadata = fs::symlink_metadata(staged)?;
    if staged_metadata.dev() != output_identity.dev()
        || staged_metadata.ino() != output_identity.ino()
        || staged_metadata.nlink() != 1
    {
        return Err(BrokerExecError::Invalid(
            "staged result pathname differs from the brokered object",
        ));
    }
    let staged_name = std::ffi::CString::new(staged_name.as_encoded_bytes())
        .map_err(|_| BrokerExecError::Invalid("staged result basename is invalid"))?;
    let output_name = std::ffi::CString::new("output.txt")
        .map_err(|_| BrokerExecError::Invalid("output basename is invalid"))?;
    // SAFETY: both C strings are NUL-terminated, `root` is an open directory,
    // and RENAME_NOREPLACE makes publication fail if another path appeared.
    let status = unsafe {
        libc::renameat2(
            root.as_raw_fd(),
            staged_name.as_ptr(),
            root.as_raw_fd(),
            output_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status != 0 {
        return Err(BrokerExecError::Io(std::io::Error::last_os_error()));
    }
    root.sync_all()?;
    let published = fs::symlink_metadata(workspace_root.join("output.txt"))?;
    if published.dev() != output_identity.dev()
        || published.ino() != output_identity.ino()
        || published.nlink() != 1
    {
        return Err(BrokerExecError::Invalid(
            "published result identity differs from the brokered object",
        ));
    }
    Ok(())
}

/// Persist an at-most-once claim before guest work. Interrupted calls consume
/// their pair; retries must use a fresh call id rather than risk duplicate effects.
fn claim_call_id(state_dir: &Path, run_id: &str, call_id: &str) -> Result<(), BrokerExecError> {
    fs::create_dir_all(state_dir)?;
    let metadata = fs::symlink_metadata(state_dir)?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(BrokerExecError::Invalid(
            "broker state directory is not host-owned",
        ));
    }
    fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700))?;
    let path = state_dir.join("broker-call-ids.tsv");
    let mut ledger = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = ledger.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(BrokerExecError::Invalid(
            "call identity ledger is not a private host-owned file",
        ));
    }
    if unsafe { libc::flock(ledger.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(BrokerExecError::Io(std::io::Error::last_os_error()));
    }
    ledger.seek(SeekFrom::Start(0))?;
    let mut content = String::new();
    ledger.read_to_string(&mut content)?;
    let key = format!("{run_id}\t{call_id}");
    if content.lines().any(|line| line == key) {
        return Err(BrokerExecError::Invalid(
            "duplicate BrokerRpc run and call identity",
        ));
    }
    ledger.seek(SeekFrom::End(0))?;
    ledger.write_all(key.as_bytes())?;
    ledger.write_all(b"\n")?;
    ledger.sync_all()?;
    Ok(())
}

/// Execute one BrokerRpc-validated tool call through the optimizer-owned launch seam.
/// Every outcome stays diagnostic-only and non-authorizing.
impl crate::broker_rpc::BrokerRpc {
    pub fn execute_task(request: BrokerExecRequest) -> Result<RuntimeTaskResult, BrokerExecError> {
        Self::execute_typed_task(request).map(|execution| execution.result)
    }

    pub fn execute_typed_task(
        request: BrokerExecRequest,
    ) -> Result<RuntimeTaskExecution, BrokerExecError> {
        if let Some(recovered) = recover_existing(&request)? {
            return Ok(recovered);
        }
        let tool_call = request.tool_call.clone();
        let normalized_call = digest(
            &serde_json::to_vec(&request.tool_call)
                .map_err(|_| BrokerExecError::Invalid("normalized call encoding"))?,
        );
        let request_binding = request_identity(&request)?;
        let fault = request.fault.clone();
        let task = Self::validate_tool_call(&request.tool_call, &request.input_workspace_identity)
            .map_err(|_| BrokerExecError::Invalid("tool call or effect contract is unsupported"))?;
        if task.brokered_file_write.is_none() && task.runtime_family.is_none() {
            return Err(BrokerExecError::Invalid(
                "only brokered output.txt=ABC is supported",
            ));
        }
        if task.timeout_ms == 0 || task.timeout_ms > MAX_TIMEOUT_MS {
            return Err(BrokerExecError::Invalid(
                "tool timeout is outside the fixed profile",
            ));
        }
        if !cfg!(target_os = "linux") {
            return Err(BrokerExecError::Invalid(
                "Firecracker execution requires Linux x86_64",
            ));
        }
        let paths = request.runtime;
        if paths.production_jailer.is_none() {
            return Err(BrokerExecError::Invalid(
                "workspace.write requires the canonical production jailer; no direct fallback",
            ));
        }
        let root = paths
            .workspace_root
            .canonicalize()
            .map_err(|_| BrokerExecError::Invalid("workspace root is unavailable"))?;
        if task
            .brokered_file_write
            .as_ref()
            .is_some_and(|effect| effect.path != "output.txt" || effect.bytes != b"ABC")
        {
            return Err(BrokerExecError::Invalid(
                "brokered file effect differs from the fixed profile",
            ));
        }
        let raw_input_metadata = fs::symlink_metadata(&paths.input_path)?;
        if !raw_input_metadata.is_file() || raw_input_metadata.nlink() != 1 {
            return Err(BrokerExecError::Invalid(
                "input is not a private regular file",
            ));
        }
        let input_path = paths
            .input_path
            .canonicalize()
            .map_err(|_| BrokerExecError::Invalid("input file is unavailable"))?;
        if input_path.parent() != Some(root.as_path())
            || input_path.file_name() != Some(std::ffi::OsStr::new("input.txt"))
        {
            return Err(BrokerExecError::Invalid(
                "input must be workspace_root/input.txt",
            ));
        }
        let input_metadata = fs::symlink_metadata(&input_path)?;
        if !input_metadata.is_file()
            || input_metadata.nlink() != 1
            || input_metadata.len() > MAX_INPUT_BYTES
        {
            return Err(BrokerExecError::Invalid(
                "input is not a bounded private regular file",
            ));
        }
        let input_bytes = fs::read(&input_path)?;
        claim_call_id(&paths.state_dir, &task.run_id, &task.call_id)?;
        let call_state = paths.state_dir.join(format!(
            "c-{}",
            &digest(format!("{}:{}", task.run_id, task.call_id).as_bytes())[..16]
        ));
        fs::create_dir(&call_state)?;
        fs::set_permissions(&call_state, fs::Permissions::from_mode(0o700))?;
        crate::runtime_effects::write_new(
            &call_state.join("runtime-request-identity"),
            request_binding.as_bytes(),
        )
        .map_err(|e| BrokerExecError::Rpc(e.to_string()))?;

        let base_world = scan_ext4_image(&paths.workspace_device).map_err(|_| {
            BrokerExecError::Invalid("workspace image failed initial offline ext4 scan")
        })?;
        let base_input = file_entry(&base_world, "input.txt").ok_or(BrokerExecError::Invalid(
            "workspace image is missing input.txt",
        ))?;
        if base_input.kind != FsKind::File
            || base_input.size != input_bytes.len() as u64
            || base_input.content_blake3.as_deref() != Some(digest(&input_bytes).as_str())
        {
            return Err(BrokerExecError::Invalid(
                "workspace image input differs from runtime input",
            ));
        }
        let execution_id = fresh_execution_id(&task.run_id, &task.call_id)?;
        let images = prepare_workspace_images(
            &paths.workspace_device,
            &call_state,
            &task.run_id,
            &execution_id,
        )
        .map_err(|_| BrokerExecError::Invalid("per-execution workspace images refused"))?;
        let initial_world = scan_ext4_image(&images.starting)
            .map_err(|_| BrokerExecError::Invalid("starting workspace copy failed offline scan"))?;
        if initial_world.root != base_world.root {
            return Err(BrokerExecError::Invalid(
                "starting workspace copy differs from input image",
            ));
        }
        // Use the canonical PR12 world commitment in the TaskEnvelope and
        // launch binding; the C1 byte scanner above has a different schema.
        let canonical_initial =
            crate::supervisor::scan_detached_workspace(&images.starting, &call_state, "envelope")
                .map_err(|error| BrokerExecError::Supervisor(error.to_string()))?;
        let (mut pending_output, mut brokered_output_file) = setup_brokered_file_output(
            if task.runtime_family.is_some() {
                &call_state
            } else {
                &root
            },
            &execution_id,
        )?;
        if task.runtime_family.is_some() {
            pending_output.published = true;
        }
        let output_path = pending_output.path.clone();
        let frontier = EffectFrontier::create(
            &call_state,
            &task.run_id,
            BROKER_ID,
            &input_path,
            &output_path,
        )
        .map_err(|error| BrokerExecError::Rpc(format!("frontier initialization: {error:?}")))?;

        let capsule_id = digest(format!("{}:{execution_id}:capsule", task.run_id).as_bytes());
        let challenge = fresh_task_challenge()?;
        let envelope = Self::build_task_envelope(
            &task,
            &execution_id,
            &capsule_id,
            &challenge,
            &canonical_initial.root,
        )
        .map_err(|_| BrokerExecError::Invalid("BrokerRpc refused TaskEnvelope construction"))?;
        let task_envelope_identity = envelope
            .identity()
            .map_err(|_| BrokerExecError::Invalid("TaskEnvelope identity encoding failed"))?;
        let operation_prefix = format!(
            "{}:{}",
            if task.runtime_family.is_some() {
                "rt"
            } else {
                "fw"
            },
            digest(
                format!(
                    "{}:{}:{}",
                    task.run_id, task.call_id, task_envelope_identity
                )
                .as_bytes()
            )
        );
        let policy_bytes = serde_json::to_vec(&serde_json::json!({
            "profile": "realm-v6-brokered-file-write-tool-v1",
            "tool_id": &task.tool_id,
            "tool_call_id": &task.call_id,
            "capability_ref": &task.capability_ref,
            "effect_contract_identity": &task.effect_contract_identity,
            "input_workspace_identity": &task.input_workspace_identity,
            "effect_contract": &task.effect_contract,
            "task_envelope_identity": &task_envelope_identity,
        }))
        .map_err(|_| BrokerExecError::Invalid("tool policy encoding failed"))?;
        let envelope_bytes = serde_json::to_vec(&envelope)
            .map_err(|_| BrokerExecError::Invalid("TaskEnvelope encoding failed"))?;
        let policy = PolicyIdentity::new(
            "realm-v6-brokered-file-write-tool".into(),
            "1".into(),
            &policy_bytes,
            &envelope_bytes,
        );
        let policy_identity = policy.blake3().to_owned();
        let backend = FirecrackerBackend::new(FirecrackerSupervisor {
            backend: C1BackendInputPaths {
                firecracker: paths.firecracker,
                kernel: paths.kernel,
                rootfs: paths.rootfs,
                workspace_device: paths.workspace_device,
                guest_supervisor: paths.guest_supervisor,
                state_dir: call_state.clone(),
                production_jailer: paths.production_jailer,
            },
            starting_workspace_image: images.starting,
            working_workspace_image: images.working,
            timeout: Duration::from_millis(task.timeout_ms),
        });

        let mut frontier = Some(frontier);
        let broker: RefCell<Option<DiagnosticBrokerRpc>> = RefCell::new(None);
        let mut launch_hook = |launch: &BackendLaunchContext| -> Result<(), BackendError> {
            let frontier = frontier
                .take()
                .ok_or_else(|| BackendError::new("broker_rpc", "already initialized"))?;
            let binding = DiagnosticBinding {
                run_id: task.run_id.clone(),
                broker_identity: BROKER_ID.into(),
                launch_identity: launch.execution_id.clone(),
                semantic_launch_identity: launch.execution_id.clone(),
                challenge_root: challenge.clone(),
                starting_generation: canonical_initial.root.clone(),
                topology_root: launch.topology_root.clone(),
                vmm_start_ticks: launch.process_start_ticks,
            };
            let mut diagnostic = DiagnosticBrokerRpc::new(frontier, binding)
                .map_err(|error| BackendError::new("broker_rpc", format!("{error:?}")))?;
            if let Some(family) = task.runtime_family {
                let session = RuntimeSessionIdentity {
                    run_id: task.run_id.clone(),
                    call_id: task.call_id.clone(),
                    execution_id: execution_id.clone(),
                    challenge: challenge.clone(),
                    normalized_call_blake3: normalized_call.clone(),
                    task_envelope_identity: task_envelope_identity.clone(),
                    contract_identity: task.effect_contract_identity.clone(),
                    policy_identity: policy_identity.clone(),
                    prestart_launch_identity: launch.measured_launch_identity.clone().ok_or_else(
                        || BackendError::new("runtime_effects", "prestart launch identity absent"),
                    )?,
                    vmm_process_identity: launch.vmm_process_identity.clone().ok_or_else(|| {
                        BackendError::new("runtime_effects", "VMM identity absent")
                    })?,
                    broker_session_identity: digest(
                        format!(
                            "{}:{}:{}:{}",
                            task.run_id, execution_id, challenge, launch.process_start_ticks
                        )
                        .as_bytes(),
                    ),
                    family,
                };
                let runtime = RuntimeEffectBroker::create(&call_state, &root, session)
                    .map_err(|e| BackendError::new("runtime_effects", e.to_string()))?;
                diagnostic
                    .attach_runtime(
                        runtime,
                        &operation_prefix,
                        fault
                            .as_ref()
                            .and_then(|f| f.point)
                            .filter(|p| *p != FailurePoint::AfterToolResult),
                        fault.as_ref().is_some_and(|f| f.guest_budget_probe),
                    )
                    .map_err(|e| BackendError::new("runtime_effects", format!("{e:?}")))?;
                *broker.borrow_mut() = Some(diagnostic);
                return Ok(());
            }
            let effect = task
                .brokered_file_write
                .as_ref()
                .ok_or_else(|| BackendError::new("broker_rpc", "unsupported effect"))?;
            diagnostic
                .restrict_to_file_write(&operation_prefix, &effect.path, &effect.bytes)
                .map_err(|error| BackendError::new("broker_rpc", format!("{error:?}")))?;
            *broker.borrow_mut() = Some(diagnostic);
            Ok(())
        };
        let mut guest_rpc_hook = |stream: &mut std::os::unix::net::UnixStream,
                                  _envelope: &crate::task_envelope::TaskEnvelope|
         -> Result<(), crate::supervisor::SupervisorError> {
            stream
                .set_read_timeout(Some(Duration::from_millis(task.timeout_ms)))
                .map_err(crate::supervisor::SupervisorError::Io)?;
            stream
                .set_write_timeout(Some(Duration::from_millis(task.timeout_ms)))
                .map_err(crate::supervisor::SupervisorError::Io)?;
            let session_identity = broker
                .borrow()
                .as_ref()
                .and_then(|d| d.runtime_report().ok())
                .map(|r| r.frontier.session_identity);
            crate::broker_rpc::write_frame(
                stream,
                &serde_json::json!({"broker_operation_prefix": operation_prefix,"runtime_session_identity":session_identity,
                    "guest_budget_probe":fault.as_ref().is_some_and(|f|f.guest_budget_probe)}),
            )
            .map_err(|error| {
                crate::supervisor::SupervisorError::Protocol(format!(
                    "broker operation prefix frame failed: {error:?}"
                ))
            })?;
            let mut slot = broker.borrow_mut();
            let diagnostic = slot.as_mut().ok_or_else(|| {
                crate::supervisor::SupervisorError::Protocol(
                    "BrokerRpc launch hook did not initialize the diagnostic session".into(),
                )
            })?;
            diagnostic.send_bootstrap(stream).map_err(|error| {
                crate::supervisor::SupervisorError::Protocol(format!(
                    "BrokerRpc bootstrap failed: {error:?}"
                ))
            })?;
            let count = task.runtime_family.map_or(3, |f| f.operations().len());
            for _ in 0..count {
                diagnostic.serve_one(stream).map_err(|error| {
                    crate::supervisor::SupervisorError::Protocol(format!(
                        "guest BrokerRpc operation failed: {error:?}"
                    ))
                })?;
            }
            if task.runtime_family.is_some() && fault.as_ref().is_some_and(|f| f.guest_budget_probe)
            {
                diagnostic.serve_one(stream).map_err(|_| {
                    crate::supervisor::SupervisorError::Protocol("third effect refused".into())
                })?;
                return Err(crate::supervisor::SupervisorError::Protocol(
                    "undeclared extra effect refused".into(),
                ));
            }
            if !diagnostic.expected_file_write_complete() || diagnostic.is_poisoned() {
                return Err(crate::supervisor::SupervisorError::Protocol(
                    "guest BrokerRpc file-write sequence did not complete".into(),
                ));
            }
            Ok(())
        };
        let backend_execution = backend
            .execute_with_guest_rpc(
                BackendTask {
                    envelope: &envelope,
                    policy,
                },
                &mut launch_hook,
                &mut guest_rpc_hook,
            )
            .map_err(|error| BrokerExecError::Supervisor(error.to_string()))?;
        if !envelope.matches_identity(&task_envelope_identity) {
            return Err(BrokerExecError::Invalid(
                "TaskEnvelope changed after BrokerRpc validation",
            ));
        }

        let launch = &backend_execution.launch;
        let facts = backend_execution.observation.facts();
        let (
            launch_assurance_grade,
            measured_launch_identity,
            typed_vmm_identity,
            typed_run_id,
            typed_execution_id,
            typed_task_identity,
            direct_workspace_path,
        ) = match backend_execution.launch_evidence.as_ref() {
            Some(BackendLaunchEvidence::Direct(direct)) => (
                LaunchAssuranceGrade::DirectFunctional,
                direct.canonical_hash_blake3().to_owned(),
                Some(digest(&serde_json::to_vec(direct.vmm()).map_err(|_| {
                    BrokerExecError::Invalid("measured VMM identity encoding failed")
                })?)),
                direct.run_id().to_owned(),
                direct.execution_id().to_owned(),
                Some(direct.policy_identity().task_blake3().to_owned()),
                Some(backend_execution.detached_workspace.clone()),
            ),
            Some(BackendLaunchEvidence::Production(production)) => (
                LaunchAssuranceGrade::ProductionContained,
                production.production_launch_root(),
                Some(digest(&serde_json::to_vec(production.vmm()).map_err(
                    |_| BrokerExecError::Invalid("production VMM identity encoding failed"),
                )?)),
                production.run_id().to_owned(),
                production.execution_id().to_owned(),
                Some(production.policy_identity().task_blake3().to_owned()),
                Some(backend_execution.detached_workspace.clone()),
            ),
            None => {
                return Err(BrokerExecError::Invalid(
                    "backend returned no typed launch product",
                ));
            }
        };
        let launch_vmm_identity =
            launch
                .vmm_process_identity
                .as_deref()
                .ok_or(BrokerExecError::Invalid(
                    "backend launch omitted VMM process identity",
                ))?;
        // In the legacy C1 diagnostic capsule schema, the observed VMM root
        // occupies custody_process_identity. This route has no terminal
        // publication authority; C0 external-custodian capsules are excluded.
        let observed_vmm_identity = facts
            .custody_process_identity()
            .as_deref()
            .filter(|_| facts.vmm_terminal_observation_root().is_none())
            .ok_or(BrokerExecError::Invalid("diagnostic VMM identity absent"))?;
        if launch.run_id != task.run_id
            || launch.execution_id != envelope.execution_id
            || launch.task_envelope_identity != task_envelope_identity
            || launch.assurance_grade != Some(launch_assurance_grade)
            || launch.measured_launch_identity.as_deref() != Some(measured_launch_identity.as_str())
            || launch_vmm_identity != observed_vmm_identity
            || typed_vmm_identity.as_deref() != Some(observed_vmm_identity)
            || typed_run_id != task.run_id
            || typed_execution_id != envelope.execution_id
            || typed_task_identity.as_deref() != Some(task_envelope_identity.as_str())
            || facts.run_id() != task.run_id.as_str()
            || facts.execution_id() != envelope.execution_id.as_str()
            || measured_launch_identity.len() != 64
            || !measured_launch_identity
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(BrokerExecError::Invalid(
                "typed backend launch does not match validated TaskEnvelope",
            ));
        }
        if launch_assurance_grade == LaunchAssuranceGrade::DirectFunctional
            && launch
                .launch_evidence_path
                .as_ref()
                .is_none_or(|path| !path.is_absolute() || !path.is_dir())
        {
            return Err(BrokerExecError::Invalid(
                "DirectMeasuredLaunch evidence directory is unavailable",
            ));
        }
        let workspace_path = direct_workspace_path.ok_or(BrokerExecError::Invalid(
            "backend did not expose a detached result workspace",
        ))?;
        let final_world = scan_ext4_image(&workspace_path).map_err(|_| {
            BrokerExecError::Invalid("final workspace failed detached offline scan")
        })?;
        let diagnostic = broker.into_inner().ok_or(BrokerExecError::Invalid(
            "BrokerRpc prestart hook did not run",
        ))?;
        let input_hash = digest(&input_bytes);
        let final_input = file_entry(&final_world, "input.txt");
        if final_input.is_none_or(|entry| {
            entry.kind != FsKind::File
                || entry.size != input_bytes.len() as u64
                || entry.content_blake3.as_deref() != Some(input_hash.as_str())
        }) {
            return Err(BrokerExecError::Invalid("final workspace input changed"));
        }

        let operations = vec![
            "Identify(output)".into(),
            "WriteRange(output)".into(),
            "Close(output)".into(),
        ];
        let task_exit = *facts.exit_code();
        let crashed = *facts.crashed();
        // CapsuleFacts does not expose captured streams. The fixed successful
        // transform redirects output to result.txt; do not present an
        // unobserved stream as a measured empty stream.
        let stdout = Vec::new();
        let stderr = Vec::new();
        let stdout_truncated = false;
        let stderr_truncated = false;
        if let Some(family) = task.runtime_family {
            if launch_assurance_grade != LaunchAssuranceGrade::ProductionContained
                || task_exit != Some(0)
                || crashed
                || final_world.root != initial_world.root
                || !facts.observed_effects().is_empty()
                || diagnostic.is_poisoned()
                || !diagnostic.expected_file_write_complete()
            {
                return Err(BrokerExecError::Invalid(
                    "typed effect execution/escape reconciliation incomplete",
                ));
            }
            let report = diagnostic
                .runtime_report()
                .map_err(|_| BrokerExecError::Invalid("runtime world reconciliation failed"))?;
            if !report.complete
                || report.session.task_envelope_identity != task_envelope_identity
                || report.session.vmm_process_identity != launch_vmm_identity
                || report.session.prestart_launch_identity
                    != match backend_execution.launch_evidence.as_ref() {
                        Some(BackendLaunchEvidence::Production(p)) => {
                            p.prestart_measurement_identity()
                        }
                        _ => "",
                    }
            {
                return Err(BrokerExecError::Invalid(
                    "runtime session is not joined to actual launch",
                ));
            }
            let committed =
                report
                    .operations
                    .iter()
                    .find_map(|r| match (&r.request.operation, &r.after) {
                        (
                            EffectOperation::FileCreate { path, .. },
                            Some(EffectObservation::File { object }),
                        ) => Some(CommittedFileEffect {
                            path: path.clone(),
                            bytes: object.bytes,
                            content_blake3: object.content_blake3.clone(),
                            object_device: object.device,
                            object_inode: object.inode,
                            run_id: task.run_id.clone(),
                            call_id: task.call_id.clone(),
                            execution_id: execution_id.clone(),
                            challenge: challenge.clone(),
                            task_envelope_identity: task_envelope_identity.clone(),
                            effect_contract_identity: task.effect_contract_identity.clone(),
                            measured_launch_identity: measured_launch_identity.clone(),
                            vmm_process_identity: launch_vmm_identity.into(),
                            broker_operation_prefix: operation_prefix.clone(),
                            frontier_head: report.frontier.head.clone(),
                            frontier_sequence: report.frontier.records,
                            frontier_journal_blake3: report.frontier.journal_blake3.clone(),
                        }),
                        _ => None,
                    });
            let result = BrokerExecResult {
                schema_version: 3,
                backend_id: backend_execution.backend_id.clone(),
                backend_capabilities: backend_execution.capabilities.clone(),
                run_id: task.run_id.clone(),
                call_id: task.call_id.clone(),
                tool_id: task.tool_id.clone(),
                capability_ref: task.capability_ref.clone(),
                effect_contract_identity: task.effect_contract_identity.clone(),
                task_envelope_identity: task_envelope_identity.clone(),
                challenge: challenge.clone(),
                vmm_process_identity: launch_vmm_identity.into(),
                launch_assurance_grade,
                measured_launch_identity: measured_launch_identity.clone(),
                launch_evidence_path: launch.launch_evidence_path.clone(),
                input_workspace_identity: task.input_workspace_identity.clone(),
                execution_id: Some(execution_id.clone()),
                vmm_pid: Some(launch.vmm_pid),
                vmm_start_time_ticks: Some(launch.process_start_ticks),
                task_launched: true,
                guest_exit_code: task_exit,
                guest_task_terminal_reported: true,
                vmm_process_waited: true,
                observed_effects: match family {
                    TaskFamily::File => vec!["output.txt".into()],
                    TaskFamily::Sqlite => vec!["counter.sqlite".into()],
                    TaskFamily::Combined => vec!["output.txt".into(), "counter.sqlite".into()],
                },
                starting_world_root: canonical_initial.root.clone(),
                final_world_root: facts.final_world().clone(),
                final_result_blake3: committed.as_ref().map(|c| c.content_blake3.clone()),
                final_result_bytes: committed.as_ref().map(|c| c.bytes),
                stdout_bytes: 0,
                stdout_blake3: digest(b""),
                stdout_truncated: false,
                stderr_bytes: 0,
                stderr_blake3: digest(b""),
                stderr_truncated: false,
                frontier_journal: Some(report.frontier.journal.clone()),
                frontier_head: Some(report.frontier.head.clone()),
                frontier_blake3: Some(report.frontier.journal_blake3.clone()),
                frontier_evidence_sequence: report.frontier.records,
                committed_file_effect: committed,
                broker_rpc_operations: family
                    .operations()
                    .iter()
                    .map(|op| serde_json::to_string(op).unwrap())
                    .collect(),
                unsupported_effects: facts.unsupported_effects().clone(),
                authority: "NON_AUTHORIZING".into(),
                decision: "REFUSE".into(),
                reason_code: "UNVERIFIED_BOUNDARY".into(),
                runtime_launch_reference: Some(RuntimeLaunchReference {
                    production_launch_root: measured_launch_identity.clone(),
                    prestart_launch_identity: report.session.prestart_launch_identity.clone(),
                    policy_identity: report.session.policy_identity.clone(),
                    vmm_process_identity: report.session.vmm_process_identity.clone(),
                    task_envelope_identity: report.session.task_envelope_identity.clone(),
                }),
                runtime_effects: Some(report),
            };
            persist_result(&call_state, &result)?;
            let production = match backend_execution.launch_evidence {
                Some(BackendLaunchEvidence::Production(p)) => *p,
                _ => return Err(BrokerExecError::Invalid("production capability missing")),
            };
            let frontier = diagnostic.into_frontier();
            if frontier.runtime_completion().is_none() {
                return Err(BrokerExecError::Invalid(
                    "broker completion capability missing",
                ));
            }
            let delivery = RuntimeEffectBroker::reopen(&call_state)
                .map_err(|e| BrokerExecError::Rpc(e.to_string()))?;
            delivery
                .delivery(CallerState::ResultAvailable)
                .map_err(|e| BrokerExecError::Rpc(e.to_string()))?;
            if let Some(stop) = fault.as_ref().and_then(|f| f.caller_stop) {
                if !matches!(stop, CallerState::TimedOut | CallerState::Cancelled) {
                    return Err(BrokerExecError::Invalid(
                        "unsupported caller stop injection",
                    ));
                }
                delivery
                    .delivery(stop)
                    .map_err(|e| BrokerExecError::Rpc(e.to_string()))?;
                // The caller can kill this waiting control process; guest/VMM already exited.
                std::thread::sleep(Duration::from_secs(300));
            }
            if fault.as_ref().and_then(|f| f.point) == Some(FailurePoint::AfterToolResult) {
                delivery
                    .delivery(CallerState::Unknown)
                    .map_err(|e| BrokerExecError::Rpc(e.to_string()))?;
                unsafe { libc::_exit(86) };
            }
            return Ok(RuntimeTaskExecution {
                result: RuntimeTaskResult::Executed(Box::new(result)),
                launch: Some(production),
                frontier: RuntimeExecutionFrontier::Live(Box::new(frontier)),
                envelope: Some(envelope),
                observation: Some(backend_execution.observation),
                tool_call,
                caller: RuntimeCallerEvidence {
                    result_state: CallerState::ResultAvailable,
                    last_recorded_delivery: CallerState::ResultAvailable,
                },
            });
        }
        if let Some(effect) = &task.brokered_file_write {
            if launch_assurance_grade != LaunchAssuranceGrade::ProductionContained {
                return Err(BrokerExecError::Invalid(
                    "file write lacks typed production containment",
                ));
            }
            let staged_file = &mut brokered_output_file;
            if final_world.root != initial_world.root || !facts.observed_effects().is_empty() {
                return Err(BrokerExecError::Invalid(
                    "undeclared guest workspace effect",
                ));
            }
            if task_exit != Some(0)
                || crashed
                || !diagnostic.expected_file_write_complete()
                || diagnostic.is_poisoned()
                || diagnostic.evidence_sequence() != 4
                || diagnostic.output_content_digest() != digest(&effect.bytes)
            {
                return Err(BrokerExecError::Invalid(
                    "guest terminal state or BrokerRpc file-write evidence is incomplete",
                ));
            }
            staged_file.seek(SeekFrom::Start(0))?;
            let mut staged_bytes = Vec::new();
            staged_file.read_to_end(&mut staged_bytes)?;
            if staged_bytes != effect.bytes {
                return Err(BrokerExecError::Invalid(
                    "brokered output bytes differ from the validated ToolCall",
                ));
            }
            staged_file.sync_all()?;
            publish_brokered_file_output(&root, &output_path, staged_file)?;
            pending_output.published = true;
            let object = staged_file.metadata()?;
            let journal_path = diagnostic.journal_path().to_path_buf();
            let journal = fs::read(&journal_path)?;
            let frontier_head = diagnostic.frontier_head().to_owned();
            let frontier_sequence = diagnostic.evidence_sequence();
            let frontier_journal_blake3 = digest(&journal);
            let committed_file_effect = CommittedFileEffect {
                path: effect.path.clone(),
                bytes: staged_bytes.len() as u64,
                content_blake3: digest(&staged_bytes),
                object_device: object.dev(),
                object_inode: object.ino(),
                run_id: task.run_id.clone(),
                call_id: task.call_id.clone(),
                execution_id: launch.execution_id.clone(),
                challenge: challenge.clone(),
                task_envelope_identity: task_envelope_identity.clone(),
                effect_contract_identity: task.effect_contract_identity.clone(),
                measured_launch_identity: measured_launch_identity.clone(),
                vmm_process_identity: launch_vmm_identity.to_owned(),
                broker_operation_prefix: operation_prefix.clone(),
                frontier_head: frontier_head.clone(),
                frontier_sequence,
                frontier_journal_blake3: frontier_journal_blake3.clone(),
            };
            let result = BrokerExecResult {
                schema_version: 2,
                backend_id: backend_execution.backend_id.clone(),
                backend_capabilities: backend_execution.capabilities.clone(),
                run_id: task.run_id.clone(),
                call_id: task.call_id.clone(),
                tool_id: task.tool_id.clone(),
                capability_ref: task.capability_ref.clone(),
                effect_contract_identity: task.effect_contract_identity.clone(),
                task_envelope_identity: task_envelope_identity.clone(),
                challenge: challenge.clone(),
                vmm_process_identity: launch_vmm_identity.to_owned(),
                launch_assurance_grade,
                measured_launch_identity: measured_launch_identity.clone(),
                launch_evidence_path: launch.launch_evidence_path.clone(),
                input_workspace_identity: task.input_workspace_identity.clone(),
                execution_id: Some(launch.execution_id.clone()),
                vmm_pid: Some(launch.vmm_pid),
                vmm_start_time_ticks: Some(launch.process_start_ticks),
                task_launched: true,
                guest_exit_code: task_exit,
                guest_task_terminal_reported: true,
                vmm_process_waited: true,
                observed_effects: vec![effect.path.clone()],
                starting_world_root: canonical_initial.root.clone(),
                final_world_root: facts.final_world().clone(),
                final_result_blake3: Some(committed_file_effect.content_blake3.clone()),
                final_result_bytes: Some(committed_file_effect.bytes),
                stdout_bytes: stdout.len() as u64,
                stdout_blake3: digest(&stdout),
                stdout_truncated,
                stderr_bytes: stderr.len() as u64,
                stderr_blake3: digest(&stderr),
                stderr_truncated,
                frontier_journal: Some(journal_path),
                frontier_head: Some(frontier_head),
                frontier_blake3: Some(frontier_journal_blake3),
                frontier_evidence_sequence: frontier_sequence,
                committed_file_effect: Some(committed_file_effect),
                broker_rpc_operations: operations,
                unsupported_effects: facts
                    .unsupported_effects()
                    .iter()
                    .filter(|limitation| limitation.as_str() != "UNCLASSIFIED_EFFECT_HISTORY")
                    .cloned()
                    .chain(std::iter::once(
                        "stdout/stderr bytes are not captured by CapsuleFacts".into(),
                    ))
                    .collect(),
                authority: "NON_AUTHORIZING".into(),
                decision: "REFUSE".into(),
                reason_code: "UNVERIFIED_BOUNDARY".into(),
                runtime_effects: None,
                runtime_launch_reference: None,
            };
            let evidence = serde_json::to_vec(&result)
                .map_err(|_| BrokerExecError::Invalid("effect result encoding failed"))?;
            let mut durable = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(call_state.join("committed-file-effect.json"))?;
            durable.write_all(&evidence)?;
            durable.write_all(b"\n")?;
            durable.sync_all()?;
            File::open(&call_state)?.sync_all()?;
            let production = match backend_execution.launch_evidence {
                Some(BackendLaunchEvidence::Production(product)) => *product,
                _ => return Err(BrokerExecError::Invalid("typed production handoff absent")),
            };
            return Ok(RuntimeTaskExecution {
                result: RuntimeTaskResult::Executed(Box::new(result)),
                launch: Some(production),
                frontier: RuntimeExecutionFrontier::Live(Box::new(diagnostic.into_frontier())),
                envelope: Some(envelope),
                observation: Some(backend_execution.observation),
                tool_call,
                caller: RuntimeCallerEvidence {
                    result_state: CallerState::ResultAvailable,
                    last_recorded_delivery: CallerState::Pending,
                },
            });
        }
        Err(BrokerExecError::Invalid("unsupported effect family"))
    }
}

fn request_identity(request: &BrokerExecRequest) -> Result<String, BrokerExecError> {
    Ok(digest(
        &serde_json::to_vec(&(
            &request.tool_call,
            &request.input_workspace_identity,
            &request.runtime,
        ))
        .map_err(|_| BrokerExecError::Invalid("request identity encoding"))?,
    ))
}
fn persist_result(state: &Path, result: &BrokerExecResult) -> Result<(), BrokerExecError> {
    crate::runtime_effects::write_new(
        &state.join("runtime-tool-result.json"),
        &serde_json::to_vec(result)
            .map_err(|_| BrokerExecError::Invalid("result serialization"))?,
    )
    .map_err(|e| BrokerExecError::Rpc(e.to_string()))
}
fn recover_existing(
    request: &BrokerExecRequest,
) -> Result<Option<RuntimeTaskExecution>, BrokerExecError> {
    let state = request.runtime.state_dir.join(format!(
        "c-{}",
        &digest(format!("{}:{}", request.tool_call.run_id, request.tool_call.call_id).as_bytes())
            [..16]
    ));
    if !state.exists() {
        return Ok(None);
    }
    if !state.join("runtime-session.json").exists() {
        // Preserved legacy profile keeps its refusal-only replay semantics.
        return Err(BrokerExecError::Invalid(
            "duplicate BrokerRpc run and call identity",
        ));
    }
    if fs::read(state.join("runtime-request-identity"))? != request_identity(request)?.as_bytes() {
        return Err(BrokerExecError::Invalid(
            "same call ID has different semantics or runtime binding",
        ));
    }
    let mut broker =
        RuntimeEffectBroker::reopen(&state).map_err(|e| BrokerExecError::Rpc(e.to_string()))?;
    let report = broker
        .retry_all()
        .map_err(|e| BrokerExecError::Rpc(e.to_string()))?;
    if !report.complete {
        return Err(BrokerExecError::Invalid(
            "partial contract; unknown/unrequested effects are not executed by recovery",
        ));
    }
    let prior_tool_result = match fs::read(state.join("runtime-tool-result.json")) {
        Ok(b) => Some(Box::new(
            serde_json::from_slice::<BrokerExecResult>(&b)
                .map_err(|_| BrokerExecError::Invalid("stored result malformed"))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    if let Some(prior) = &prior_tool_result {
        let r = prior
            .runtime_effects
            .as_ref()
            .ok_or(BrokerExecError::Invalid(
                "stored result missing typed effects",
            ))?;
        if r.session != report.session
            || r.frontier != report.frontier
            || prior.run_id != request.tool_call.run_id
            || prior.call_id != request.tool_call.call_id
        {
            return Err(BrokerExecError::Invalid(
                "stored result/session/frontier mismatch",
            ));
        }
    }
    let completion = broker
        .completion()
        .map_err(|e| BrokerExecError::Rpc(e.to_string()))?;
    let caller = RuntimeCallerEvidence {
        result_state: CallerState::ResultAvailable,
        last_recorded_delivery: report.caller_state,
    };
    Ok(Some(RuntimeTaskExecution {
        result: RuntimeTaskResult::Recovered {
            recovery: Box::new(report),
            prior_tool_result,
        },
        launch: None,
        frontier: RuntimeExecutionFrontier::Recovered(Box::new(completion)),
        envelope: None,
        observation: None,
        tool_call: request.tool_call.clone(),
        caller,
    }))
}
