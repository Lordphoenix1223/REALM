//! Run adapter for the existing native coding launch and diagnostic custody.
//! No semantic/publication issuer. Root operator and host relay remain trusted.
use crate::{
    broker_rpc::{DiagnosticBinding, DiagnosticBrokerRpc},
    coding_submission::SubmissionContract,
    custody::CustodyClient,
    execute::C1BackendInputPaths,
    frontier::EffectFrontier,
    mediation::MediationChallenge,
    supervisor::FirecrackerSupervisor,
};
use serde::Deserialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Read, Write},
    os::{
        fd::FromRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixDatagram, UnixStream},
        },
    },
    path::{Path, PathBuf},
    time::Duration,
};
pub mod attempt_history;
#[path = "bin/coding_submission_probe/auxiliary_fds.rs"]
mod auxiliary_fds;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configure {
    phase: String,
    binding: SubmissionContract,
    backend: C1BackendInputPaths,
    starting_workspace: PathBuf,
    working_workspace: PathBuf,
    s0_root: String,
    timeout_seconds: u64,
    #[serde(default)]
    coding_scope: Option<crate::coding_submission::CodingExecutionScope>,
    #[serde(default)]
    native_relay: Option<crate::coding_relay::RelayConfig>,
}
fn line(input: &mut impl BufRead) -> Result<serde_json::Value> {
    let mut bytes = Vec::new();
    input.take(65537).read_until(b'\n', &mut bytes)?;
    if bytes.len() > 65536 || !bytes.ends_with(b"\n") {
        return Err("bounded native control line required".into());
    }
    Ok(crate::strict_json::parse(&bytes).map_err(|_| "strict native control JSON required")?)
}
fn emit(value: serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string(&value)?);
    io::stdout().flush()?;
    Ok(())
}
fn record(path: &Path, value: &serde_json::Value) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    f.write_all(&serde_json::to_vec(value)?)?;
    f.sync_all()?;
    File::open(path.parent().ok_or("record parent missing")?)?.sync_all()?;
    Ok(())
}
fn expect(input: &mut impl BufRead, phase: &str, binding: &SubmissionContract) -> Result<()> {
    let expected = serde_json::json!({"phase":phase,"binding":binding});
    if line(input)? != expected {
        return Err("native control phase/run/challenge differs".into());
    }
    Ok(())
}

fn auxiliary_channel(auxiliary_fd: i32) -> Result<UnixDatagram> {
    if auxiliary_fd <= 2 {
        return Err("private auxiliary descriptor required".into());
    }
    let flags = unsafe { libc::fcntl(auxiliary_fd, libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(auxiliary_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let auxiliary = unsafe { UnixDatagram::from_raw_fd(auxiliary_fd) };
    auxiliary.set_read_timeout(Some(Duration::from_secs(30)))?;
    // Socketpair credentials are fixed by the kernel at creation. Do not
    // accept a foreign handoff endpoint supplied as an ordinary FD number.
    use std::os::fd::AsRawFd;
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            auxiliary.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
        || size as usize != std::mem::size_of::<libc::ucred>()
        || peer.pid != unsafe { libc::getppid() }
        || peer.uid != 0
        || peer.gid != 0
    {
        return Err("auxiliary handoff must originate in the root parent".into());
    }

    Ok(auxiliary)
}

pub fn run(args: &[String]) -> Result<()> {
    if args.len() != 8 || unsafe { libc::geteuid() } != 0 || std::env::consts::ARCH != "x86_64" {
        return Err("--owned-launch STATE TASK_SHA256 WORKER_SHA256 OUTPUT_RO_FD CUSTODY_SOCKET_FD AUXILIARY_HANDOFF_FD requires root Linux x86_64".into());
    }
    let state = PathBuf::from(&args[2]);
    let meta = fs::symlink_metadata(&state)?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o7777 != 0o700 {
        return Err("fresh private native state required".into());
    }
    let output_fd: i32 = args[5].parse()?;
    let custody_fd: i32 = args[6].parse()?;
    let auxiliary_fd: i32 = args[7].parse()?;
    if output_fd <= 2
        || custody_fd <= 2
        || auxiliary_fd <= 2
        || output_fd == custody_fd
        || auxiliary_fd == output_fd
        || auxiliary_fd == custody_fd
    {
        return Err("unique transferred descriptors required".into());
    }
    // Python pass_fds clears CLOEXEC for this exec. Restore it before any
    // native launcher can exec jailer/VMM; neither may inherit custody access.
    for fd in [output_fd, custody_fd, auxiliary_fd] {
        let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if descriptor_flags < 0
            || unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
    }
    let flags = unsafe { libc::fcntl(output_fd, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err("broker must receive read-only custody output".into());
    }
    // SAFETY: exact unique descriptors are transferred by the trusted owned launcher.
    let output = unsafe { File::from_raw_fd(output_fd) };
    let mut custody = unsafe { UnixStream::from_raw_fd(custody_fd) };
    let auxiliary = auxiliary_channel(auxiliary_fd)?;
    custody.set_nonblocking(false)?;
    custody.set_read_timeout(Some(Duration::from_secs(30)))?;
    custody.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut output_snapshot = output.try_clone()?;
    let output_object = output.metadata()?;
    if !output_object.is_file()
        || output_object.nlink() != 1
        || output_object.mode() & 0o7777 != 0o600
    {
        return Err("private single-link custody output required".into());
    }
    let empty_world_path = state.join("empty-output-world");
    fs::create_dir(&empty_world_path)?;
    let before = crate::filesystem_world::scan_directory(&empty_world_path)
        .map_err(|e| format!("initial output world refused: {e:?}"))?;
    let challenge = MediationChallenge::fresh()?;
    let binding = SubmissionContract {
        run_id: MediationChallenge::fresh()?.root().into(),
        execution_id: MediationChallenge::fresh()?.root().into(),
        challenge_root: challenge.root().into(),
        task_sha256: args[3].clone(),
        worker_sha256: args[4].clone(),
    };
    binding.validate()?;
    record(
        &state.join("binding.json"),
        &serde_json::to_value(&binding)?,
    )?;
    emit(
        serde_json::json!({"phase":"BINDING","binding":binding,"s0_root":before.root,"authority":"NONE"}),
    )?;
    let mut input = io::BufReader::new(io::stdin());
    let config: Configure = serde_json::from_value(line(&mut input)?)?;
    if config.phase != "CONFIGURE"
        || config.binding != binding
        || !(1..=120).contains(&config.timeout_seconds)
        || config.s0_root != before.root
    {
        return Err("native configuration binding/deadline differs".into());
    }
    let mut ready = [0u8; b"REALM-C0-CUSTODIAN-READY-V1\n".len()];
    custody.read_exact(&mut ready)?;
    if &ready != b"REALM-C0-CUSTODIAN-READY-V1\n" {
        return Err("custody launch READY differs".into());
    }
    custody.write_all(b"REALM-C0-CUSTODIAN-START-V1\n")?;
    custody.flush()?;
    let supervisor = FirecrackerSupervisor {
        backend: config.backend,
        starting_workspace_image: config.starting_workspace,
        working_workspace_image: config.working_workspace,
        timeout: Duration::from_secs(config.timeout_seconds),
    };
    if config.coding_scope.is_some() {
        return Err("legacy diagnostic entry cannot consume a measured coding scope".into());
    }
    let mut live = supervisor.prepare_coding_tools(&binding, &challenge, &config.s0_root)?;
    let m = live.measurement();
    let ready = serde_json::json!({"phase":"PREPARED","authority":"NONE","binding":binding,
        "vmm_pid":m.vmm().pid(),"vmm_start_ticks":m.vmm().start_time_ticks(),"vmm_owner":m.vmm().owner(),
        "measurement_root":m.canonical_hash_blake3(),"endpoint_root":m.broker_endpoint_blake3(),
        "control_endpoint":live.auxiliary_endpoint(9001)?,"raw_endpoint":live.auxiliary_endpoint(9000)?,
        "launch_state":live.state()});
    record(&state.join("native-prepared.json"), &ready)?;
    emit(ready)?;
    expect(&mut input, "START", &binding)?;
    live.start()?;
    let m = live.measurement();
    let empty = state.join("input");
    let f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&empty)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    f.sync_all()?;
    drop(f);
    let frontier = EffectFrontier::create_custodied(
        &state,
        &binding.run_id,
        "coding-native-development",
        &empty,
        output,
        CustodyClient::new(custody, binding.run_id.clone()),
    )
    .map_err(|e| format!("native frontier refused: {e:?}"))?;
    let service = DiagnosticBinding {
        run_id: binding.run_id.clone(),
        broker_identity: "coding-native-development".into(),
        launch_identity: binding.execution_id.clone(),
        semantic_launch_identity: binding.execution_id.clone(),
        starting_generation: config.s0_root,
        topology_root: m.canonical_hash_blake3().into(),
        vmm_start_ticks: m.vmm().start_time_ticks(),
        challenge_root: challenge.root().into(),
    };
    let mut broker = DiagnosticBrokerRpc::new(frontier, service)
        .map_err(|e| format!("native broker refused: {e:?}"))?;
    broker
        .restrict_to_coding_submission(binding.clone())
        .map_err(|e| format!("submission profile refused: {e:?}"))?;
    emit(serde_json::json!({"phase":"RUNNING","binding":binding,"authority":"NONE"}))?;
    let mut wire = live.accept_submission()?;
    broker
        .send_bootstrap(&mut wire)
        .map_err(|e| format!("bootstrap refused: {e:?}"))?;
    for _ in 0..2 {
        live.check_live_configuration()?;
        broker
            .serve_one(&mut wire)
            .map_err(|e| format!("native request refused: {e:?}"))?;
        if broker.is_poisoned() {
            return Err("native broker poisoned".into());
        }
    }
    let closed = live.close_submission(wire, &challenge)?;
    emit(serde_json::json!({"phase":"SUBMISSION_CLOSED","binding":binding,"authority":"NONE"}))?;
    // The host must transfer actual sockets after durable raw ACK. Ordinary
    // JSON only sequences the handoff; it cannot create closure authority.
    expect(&mut input, "RETIRE_AFTER_AUX_HANDOFF", &binding)?;
    let (control_listener, control_stream, raw_listener, raw_stream) =
        auxiliary_fds::receive(auxiliary)?;
    let retired = closed.close_auxiliary_and_retire(
        control_listener,
        control_stream,
        raw_listener,
        raw_stream,
    )?;
    let barrier = blake3::hash(&serde_json::to_vec(&retired.record())?)
        .to_hex()
        .to_string();
    let custody_head = broker
        .seal_custodian_after_barrier(&barrier)
        .map_err(|e| format!("custody seal refused: {e:?}"))?;
    let frontier_head = broker
        .seal_frontier_for_diagnostic_audit(&barrier)
        .map_err(|e| format!("frontier seal refused: {e:?}"))?;
    let mut packet = Vec::new();
    (&mut output_snapshot)
        .take(crate::coding_submission::MAX_SUBMISSION as u64 + 1)
        .read_to_end(&mut packet)?;
    let submitted = binding.decode(&packet)?;
    let packet_blake3 = blake3::hash(&packet).to_hex().to_string();
    if packet_blake3 != broker.output_content_digest() {
        return Err("sealed output differs from broker version".into());
    }
    let after_object = output_snapshot.metadata()?;
    if (
        after_object.dev(),
        after_object.ino(),
        after_object.mode(),
        after_object.nlink(),
    ) != (
        output_object.dev(),
        output_object.ino(),
        output_object.mode(),
        output_object.nlink(),
    ) {
        return Err("held custody output object changed".into());
    }
    let result = serde_json::json!({"phase":"RETIRED_SEALED_DIAGNOSTIC","authority":"NONE","realm_artifact":null,
        "binding":binding,"retirement":retired.record(),"custody_head":custody_head,"frontier_head":frontier_head,
        "barrier":barrier,"packet_blake3":packet_blake3,"transcript_head":submitted.transcript_head,
        "output_object":{"device":output_object.dev(),"inode":output_object.ino()},"publication_authority":false,"control_raw_closure":"NATIVE_EOF_REVOKED"});
    record(&state.join("native-session-result.json"), &result)?;
    emit(result)?;
    Ok(())
}

/// Native child/custody ownership successor. The existing run021 archive and
/// legacy entry point are unchanged historical inputs; this is not approved to run.
pub fn run_native_retirement(args: &[String]) -> Result<NativeCodingRetirement> {
    run_native_retirement_inner(args, None)
}
/// Retain opaque setup admission before native preparation and through closure.
pub fn run_native_retirement_with_admission(
    args: &[String],
    admission: crate::runtime_admission::ReviewedRuntimeAdmission,
) -> Result<NativeCodingRetirement> {
    run_native_retirement_inner(args, Some(admission))
}
fn run_native_retirement_inner(
    args: &[String],
    admission: Option<crate::runtime_admission::ReviewedRuntimeAdmission>,
) -> Result<NativeCodingRetirement> {
    match run_native_attempt_inner(args, admission)? {
        NativeCodingAttempt::Retired(run) => Ok(*run),
        NativeCodingAttempt::ApiRetired(_) => Err("API-only owner cannot finalize a whole task".into()),
        NativeCodingAttempt::Refused(_) => Err("native owned referee refused; actual retired attempt retained, no success or retry authority".into()),
    }
}

/// Same original launch path, retaining an actual retired semantic refusal.
/// No serialized history/diagnostic record can enter this API as an owner.
pub fn run_native_attempt(args: &[String]) -> Result<NativeCodingAttempt> {
    run_native_attempt_inner(args, None)
}
pub fn run_native_attempt_with_admission(
    args: &[String],
    admission: crate::runtime_admission::ReviewedRuntimeAdmission,
) -> Result<NativeCodingAttempt> {
    run_native_attempt_inner(args, Some(admission))
}
fn run_native_attempt_inner(
    args: &[String],
    admission: Option<crate::runtime_admission::ReviewedRuntimeAdmission>,
) -> Result<NativeCodingAttempt> {
    let mut input = io::BufReader::new(io::stdin());
    run_native_attempt_stream(args, admission, &mut input, None, None, None)
}

// The persistent owner supplies ONE reader for its entire lifetime. Creating a
// new BufReader per attempt can lose an already-buffered next control frame.
fn run_native_attempt_stream(
    args: &[String],
    admission: Option<crate::runtime_admission::ReviewedRuntimeAdmission>,
    input: &mut impl BufRead,
    auxiliary_override: Option<File>,
    expected_task: Option<&attempt_history::FrozenNativeTask>,
    expected_subtask: Option<&crate::native_workflow::NativeSubtask>,
) -> Result<NativeCodingAttempt> {
    use crate::coding_custody::CodingCustody;
    let mut admission = admission;
    let with_referee = args.get(1).is_some_and(|a| a == "--native-referee-launch");
    if args.len() != if with_referee { 10 } else { 9 }
        || unsafe { libc::geteuid() } != 0
        || std::env::consts::ARCH != "x86_64"
    {
        return Err("--native-custody-launch STATE TASK_SHA WORKER_SHA CUSTODIAN UID GID AUX_FD; --native-referee-launch adds PYTHON. Requires root Linux x86_64".into());
    }
    if with_referee {
        crate::coding_provenance::inspect_kernel_access()?;
    }
    let state = PathBuf::from(&args[2]);
    let metadata = fs::symlink_metadata(&state)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
        return Err("fresh private native state required".into());
    }
    // The retained descriptor is only audit transport until the SAME kernel
    // root-parent check as the single-run path succeeds. No trusted-channel
    // bypass is introduced by the persistent owner.
    let auxiliary = auxiliary_channel(match auxiliary_override {
        Some(channel) => std::os::fd::IntoRawFd::into_raw_fd(channel),
        None => args[8].parse()?,
    })?;
    let empty = state.join("empty-output-world");
    fs::create_dir(&empty)?;
    let s0_output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(empty.join("output"))?;
    s0_output.set_permissions(fs::Permissions::from_mode(0o600))?;
    s0_output.sync_all()?;
    drop(s0_output);
    let before = crate::filesystem_world::scan_directory(&empty)
        .map_err(|e| format!("S0 refused: {e:?}"))?;
    let challenge = MediationChallenge::fresh()?;
    let binding = SubmissionContract {
        run_id: MediationChallenge::fresh()?.root().into(),
        execution_id: MediationChallenge::fresh()?.root().into(),
        challenge_root: challenge.root().into(),
        task_sha256: args[3].clone(),
        worker_sha256: args[4].clone(),
    };
    binding.validate()?;
    record(
        &state.join("binding.json"),
        &serde_json::to_value(&binding)?,
    )?;
    let mut task_inputs = if expected_task.is_some_and(|t| t.installed_admission)
        && admission.is_none()
    {
        let step = expected_subtask.ok_or("native input profile requires keeper-selected role")?;
        Some(
            crate::runtime_admission::installed::prepare_workflow_inputs(
                step.role, &binding, step,
            )?,
        )
    } else {
        None
    };
    let mut binding_notice = serde_json::json!({"phase":"BINDING","binding":binding,"s0_root":before.root,"authority":"NONE"});
    if let Some(admitted) = &admission {
        record(
            &state.join("runtime-admission.json"),
            &serde_json::to_value(admitted.envelope())?,
        )?;
        // The trusted parent must commit this exact identity into the scope
        // returned in CONFIGURE; validate_prelaunch rejects any substitution.
        binding_notice["runtime_admission_id"] = admitted.identity().into();
    }
    if let Some(step) = expected_subtask {
        binding_notice["native_subtask"] = serde_json::to_value(step)?;
    }
    if let Some(inputs) = &task_inputs {
        binding_notice["task_inputs"] = serde_json::to_value(inputs.data())?;
        binding_notice["task_inputs_blake3"] = inputs.root().into();
    }
    emit(binding_notice)?;
    let config: Configure = serde_json::from_value(line(input)?)?;
    if config.phase != "CONFIGURE"
        || config.binding != binding
        || config.s0_root != before.root
        || !(1..=120).contains(&config.timeout_seconds)
    {
        return Err("native configuration binding differs".into());
    }
    let mut scope = config
        .coding_scope
        .ok_or("precommitted coding source/checker scope required")?;
    scope.validate()?;
    if scope.submission != binding {
        return Err("coding scope binds another run".into());
    }
    if scope.native_subtask.as_ref() != expected_subtask {
        return Err("native role/predecessor/history was not issued by the original keeper".into());
    }
    if expected_task.is_some_and(|task| !task.permits(&scope)) {
        return Err(
            "retained workflow source/checker/task commitments differ before launch".into(),
        );
    }
    if let Some(inputs) = &mut task_inputs {
        if scope.runtime_admission_id.is_some() || !inputs.data().matches_scope(&scope) {
            return Err("configured task inputs were not issued by original keeper".into());
        }
        let role = expected_subtask.ok_or("original role missing")?.role;
        // Independently measure the protected immutable image BEFORE signing.
        let data = inputs.data();
        let expected = crate::runtime_admission::installed::input_rootfs_digest(role, data)?;
        inputs.hold_rootfs(&config.backend.rootfs, &expected)?;
        let statement = crate::runtime_admission::installed::issue_for_inputs(role, inputs)?;
        admission = Some(crate::coding_provenance::preflight_with_admission(
            &statement,
        )?);
        let admitted = admission.as_ref().ok_or("original admission missing")?;
        scope.runtime_admission_id = Some(admitted.identity().into());
        record(
            &state.join("runtime-admission.json"),
            &serde_json::to_value(&statement)?,
        )?;
        emit(
            serde_json::json!({"phase":"ADMITTED","authority":"NONE","binding":binding,
            "runtime_admission_id":admitted.identity(),"task_inputs_blake3":inputs.root()}),
        )?;
    } else if scope.task_inputs_blake3.is_some() {
        return Err("task inputs lack original sealed owner".into());
    }
    if let Some(admitted) = &admission {
        if !with_referee || config.native_relay.is_none() {
            return Err("admitted execution requires native relay and owned referee".into());
        }
        crate::coding_provenance::validate_prelaunch(
            admitted,
            &scope,
            &config.backend,
            Path::new(&args[9]),
        )?;
    } else if scope.runtime_admission_id.is_some() {
        return Err("diagnostic execution cannot claim a runtime admission".into());
    }
    let supervisor = FirecrackerSupervisor {
        backend: config.backend,
        starting_workspace_image: config.starting_workspace,
        working_workspace_image: config.working_workspace,
        timeout: Duration::from_secs(config.timeout_seconds),
    };
    record(
        &state.join("coding-prelaunch-scope.json"),
        &serde_json::to_value(&scope)?,
    )?;
    if with_referee && config.native_relay.is_none() {
        return Err(
            "REFUSE_UNVERIFIED_BOUNDARY: production referee path requires actual native relay"
                .into(),
        );
    }
    if let Some(inputs) = &task_inputs {
        inputs.revalidate()?;
    }
    let mut live = supervisor.prepare_measured_coding_tools(&scope, &challenge, &config.s0_root)?;
    let mut custody = CodingCustody::start(
        &live,
        &scope,
        &challenge,
        &config.s0_root,
        Path::new(&args[5]),
        args[6].parse()?,
        args[7].parse()?,
    )?;
    let mut resources = if config.native_relay.is_some() {
        Some(live.capture_coding_resources()?)
    } else {
        None
    };
    let relay = config
        .native_relay
        .map(|c| {
            let m = live.measurement();
            crate::coding_relay::NativeRelay::prepare(
                c,
                &scope,
                &live.auxiliary_endpoint(9001)?,
                &state,
                m,
                Duration::from_secs(config.timeout_seconds),
            )
            .and_then(|relay| relay.with_task_inputs(task_inputs.take()))
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })
        })
        .transpose()?;
    let m = live.measurement();
    let prepared = serde_json::json!({"phase":"PREPARED","authority":"NONE","binding":binding,
        "vmm_pid":m.vmm().pid(),"vmm_start_ticks":m.vmm().start_time_ticks(),"vmm_owner":m.vmm().owner(),
        "measurement_root":m.canonical_hash_blake3(),"endpoint_root":m.broker_endpoint_blake3(),
        "control_endpoint":live.auxiliary_endpoint(9001)?,"raw_endpoint":live.auxiliary_endpoint(9000)?,
        "launch_state":live.state(),"owned_custody":custody.birth_record()});
    record(&state.join("native-prepared.json"), &prepared)?;
    emit(prepared)?;
    expect(input, "START", &binding)?;
    if let Some(admitted) = &admission {
        crate::coding_provenance::validate_instance_start(admitted, &scope, live.measurement())?;
    }
    live.start()?;
    if let Some(resources) = &mut resources {
        resources.initialized(live.measurement())?;
    }

    let relay = relay.map(|r| std::thread::spawn(move || r.run()));

    emit(serde_json::json!({"phase":"RUNNING","binding":binding,"authority":"NONE"}))?;
    let mut wire = live.accept_submission()?;
    custody
        .broker()
        .send_bootstrap(&mut wire)
        .map_err(|e| format!("bootstrap refused: {e:?}"))?;
    for _ in 0..2 {
        live.check_live_configuration()?;
        custody
            .broker()
            .serve_one(&mut wire)
            .map_err(|e| format!("broker request refused: {e:?}"))?;
        if custody.broker().is_poisoned() {
            return Err("native broker poisoned".into());
        }
    }
    if let Some(resources) = &mut resources {
        resources.observe_before_close(live.measurement())?;
    }
    let closed = live.close_submission(wire, &challenge)?;
    emit(serde_json::json!({"phase":"SUBMISSION_CLOSED","binding":binding,"authority":"NONE"}))?;
    expect(input, "RETIRE_AFTER_AUX_HANDOFF", &binding)?;
    let (a, b, c, d, capture) = if let Some(thread) = relay {
        let captured = thread.join().map_err(|_| "native relay panicked")??;
        let (raw_listener, raw_stream) = auxiliary_fds::receive_raw(auxiliary)?;
        (
            captured.listener,
            captured.stream,
            raw_listener,
            raw_stream,
            Some(captured.capture),
        )
    } else {
        let (a, b, c, d) = auxiliary_fds::receive(auxiliary)?;
        (a, b, c, d, None)
    };
    let closed = closed.close_auxiliary_channels(a, b, c, d)?;
    let custody = custody.seal_and_wait(&closed)?;
    let observation = if with_referee {
        Some(custody.observe_finite_task(&closed, Path::new(&args[9]))?)
    } else {
        None
    };
    let (referee, api_referee, refused) = match observation {
        Some(crate::coding_referee::OwnedCodingTaskOutcome::Passed(v)) => (Some(v), None, None),
        Some(crate::coding_referee::OwnedCodingTaskOutcome::ApiPassed(v)) => (None, Some(v), None),
        Some(crate::coding_referee::OwnedCodingTaskOutcome::Refused(v)) => (None, None, Some(v)),
        None => (None, None, None),
    };
    if let Some(check) = &referee {
        record(
            &state.join("owned-referee.json"),
            &serde_json::json!({
            "root":check.root(),"identity_record":check.identity_record(),"check":check.diagnostic(),"authority":"NONE",
            "same_run_admission":"REFUSE: controller/runtime scope and coding measured mediation remain required"}),
        )?;
    }
    let custody_record = custody.record();
    let mut retired = closed.retire_with_custody(custody)?;
    let resources = resources
        .map(|resources| resources.finish_after_retirement(&retired))
        .transpose()?;
    if let Some(resources) = &resources {
        record(
            &state.join("native-vmm-resources.json"),
            &resources.diagnostic(),
        )?;
    }
    if let Some(refused) = refused {
        let capture = capture.ok_or("refused attempt lacks original relay capture")?;
        let resources =
            resources.ok_or("refused attempt lacks original retired resource observations")?;
        let failure =
            NativeCodingRefusalRetirement::seal(retired, refused, capture, resources, admission)?;
        record(
            &state.join("native-attempt-refusal.json"),
            &failure.diagnostic(),
        )?;
        return Ok(NativeCodingAttempt::Refused(Box::new(failure)));
    }
    if let Some(api_referee) = api_referee {
        let provenance = crate::coding_provenance::OwnedCodingProvenance::seal(
            &mut retired,
            api_referee.view(),
            capture.ok_or("API capture absent")?,
            resources.ok_or("API resources absent")?,
            admission,
        )?;
        let root = provenance.root().to_owned();
        retired.owned_provenance = Some(provenance);
        return Ok(NativeCodingAttempt::ApiRetired(Box::new(
            NativeCodingApiRetirement {
                retired,
                referee: api_referee,
                state,
                binding,
                custody_record,
                capture_root: root,
            },
        )));
    }
    let relay_capture_root = if let (Some(capture), Some(resources), Some(referee)) =
        (capture, resources, referee.as_ref())
    {
        let provenance = crate::coding_provenance::OwnedCodingProvenance::seal(
            &mut retired,
            referee,
            capture,
            resources,
            admission,
        )?;
        record(
            &state.join("native-provenance-identity.json"),
            provenance.identity_record(),
        )?;
        let root = provenance.root().to_owned();
        retired.owned_provenance = Some(provenance);
        Some(root)
    } else {
        None
    };
    Ok(NativeCodingAttempt::Retired(Box::new(
        NativeCodingRetirement {
            retired,
            referee,
            state,
            binding,
            custody_record,
            relay_capture_root,
        },
    )))
}

/// Original actual run owners survive both semantic outcomes. Retired without
/// an owned referee remains diagnostic; it is not semantic success. Refused
/// has no conversion into a successful retirement or publication capability.
pub enum NativeCodingAttempt {
    Retired(Box<NativeCodingRetirement>),
    ApiRetired(Box<NativeCodingApiRetirement>),
    Refused(Box<NativeCodingRefusalRetirement>),
}
/// Actual API retirement; cannot convert to NativeCodingRetirement/whole task.
pub struct NativeCodingApiRetirement {
    retired: crate::supervisor::RetiredCodingVmm,
    referee: crate::coding_referee::OwnedNativeApiCheck,
    state: PathBuf,
    binding: SubmissionContract,
    custody_record: serde_json::Value,
    capture_root: String,
}
/// No constructor, Clone, deserializer or publication conversion. This owner
/// preserves the real rejected run, child exit, custody, action capture and
/// kernel retirement for a future long-lived supervisor's attempt ledger.
/// ```compile_fail
/// fn promote(x: realm_v6::coding_runtime::NativeCodingRefusalRetirement)
///     -> realm_v6::supervisor::RetiredCodingVmm { x.retired }
/// ```
pub struct NativeCodingRefusalRetirement {
    retired: crate::supervisor::RetiredCodingVmm,
    referee: crate::coding_referee::OwnedCodingTaskRefusal,
    admission: Option<crate::runtime_admission::ReviewedRuntimeAdmission>,
    capture_root: String,
}
impl NativeCodingRefusalRetirement {
    fn seal(
        mut retired: crate::supervisor::RetiredCodingVmm,
        referee: crate::coding_referee::OwnedCodingTaskRefusal,
        capture: crate::coding_relay::RelayCapture,
        resources: crate::vmm_resources::ObservedVmmResources,
        admission: Option<crate::runtime_admission::ReviewedRuntimeAdmission>,
    ) -> Result<Self> {
        let capture_root = Self::validate_owners(&retired, &referee, &capture, &resources)?;
        let registered = retired
            .owned_custody
            .as_ref()
            .ok_or("missing refused custody")?
            .publication_inputs()
            .0
            .native_subtask
            .is_some();
        let mut admission = admission;
        let qualified = if registered { admission.take() } else { None };
        let provenance = crate::coding_provenance::OwnedCodingProvenance::seal(
            &mut retired,
            &referee,
            capture,
            resources,
            qualified,
        )?;
        retired.owned_provenance = Some(provenance);
        Ok(Self {
            retired,
            referee,
            admission,
            capture_root,
        })
    }
    fn validate_owners(
        retired: &crate::supervisor::RetiredCodingVmm,
        referee: &crate::coding_referee::OwnedCodingTaskRefusal,
        capture: &crate::coding_relay::RelayCapture,
        resources: &crate::vmm_resources::ObservedVmmResources,
    ) -> Result<String> {
        let custody = retired
            .owned_custody
            .as_ref()
            .ok_or("missing original refused custody")?;
        custody.validate_retired(&retired.production)?;
        let (scope, packet, native, frozen, _) = custody.publication_inputs();
        if !retired.has_closed_coding_channels()
            || !referee.native_binding(scope, packet, &native.root, frozen.completion.root())
            || !capture.matches_native(&retired.production)
            || !resources.matches(&retired.production)
        {
            return Err(
                "refused attempt owners belong to different runs or incomplete closure".into(),
            );
        }
        let fence = retired
            .coding_fence
            .as_ref()
            .ok_or("refused attempt lacks original execution fence")?;
        fence.revalidate_objects()?;
        if !fence.matches_terminal(&retired.production) {
            return Err("refused attempt fence belongs to another run".into());
        }
        Ok(capture.verify_refusal(scope, packet, referee)?)
    }
    /// Recheck the original same-run objects before any future owner join. This
    /// does not authorize a retry, qualify a workflow or recreate an owner.
    pub fn revalidate(&self) -> Result<()> {
        let custody = self
            .retired
            .owned_custody
            .as_ref()
            .ok_or("missing refused custody")?;
        custody.validate_retired(&self.retired.production)?;
        let (scope, packet, native, frozen, _) = custody.publication_inputs();
        let provenance = self
            .retired
            .owned_provenance
            .as_ref()
            .ok_or("missing refused provenance")?;
        if !self
            .referee
            .native_binding(scope, packet, &native.root, frozen.completion.root())
            || provenance.identity_record()["capture_root"] != self.capture_root
            || !provenance.matches_native(
                &self.retired.production,
                scope,
                frozen.completion.frontier_root(),
                &frozen.barrier,
            )
        {
            return Err("refused attempt original owners/capture changed".into());
        }
        Ok(())
    }
    /// Read-only data, never a replacement for these original owners.
    pub fn diagnostic(&self) -> serde_json::Value {
        serde_json::json!({"schema":"realm.native-semantic-refusal-retirement.v1",
            "retirement":self.retired.record(), "referee_identity":self.referee.identity_record(),
            "custody":self.retired.owned_custody.as_ref().map(|c|c.record()),
            "referee":self.referee.diagnostic(), "capture_root":self.capture_root,
            "owner_revalidation":if self.revalidate().is_ok() { "UNCHANGED" } else { "REFUSE_CHANGED" },
            "runtime_observations":self.retired.owned_provenance.as_ref().map(|p|p.identity_record()),
            "admission_identity":self.admission.as_ref().map(|a|a.identity()),
            "authority":"NONE","qualification":"NOT_ESTABLISHED","retry_authorization":"NONE"})
    }
}

/// Native owners survive the runtime boundary; diagnostics cannot reconstruct them.
pub struct NativeCodingRetirement {
    pub retired: crate::supervisor::RetiredCodingVmm,
    pub referee: Option<crate::coding_referee::OwnedCodingTaskCheck>,
    state: PathBuf,
    binding: SubmissionContract,
    custody_record: serde_json::Value,
    relay_capture_root: Option<String>,
}

/// Historical diagnostic mode shares execution and retains its NONE classification.
pub fn run_native_custody(args: &[String]) -> Result<()> {
    let run = run_native_retirement(args)?;
    emit_native_retirement(&run)
}

fn emit_native_retirement(run: &NativeCodingRetirement) -> Result<()> {
    let NativeCodingRetirement {
        retired,
        referee,
        state,
        binding,
        custody_record,
        relay_capture_root,
    } = run;
    let result = serde_json::json!({"phase":"RETIRED_SEALED_DIAGNOSTIC","binding":binding,"authority":"NONE",
        "retirement":retired.record(),"owned_custody":custody_record,"native_relay_capture_root":relay_capture_root,
        "owned_referee":referee.as_ref().map(|r|serde_json::json!({"root":r.root(),"check":r.diagnostic()})),
        "output_object":custody_record["output_object"],"custody_head":custody_record["custody_head"],
        "frontier_head":custody_record["frontier_head"],"packet_blake3":custody_record["packet_blake3"],
        "transcript_head":custody_record["transcript_head"],"publication_authority":false,"realm_artifact":null});
    record(&state.join("native-session-result.json"), &result)?;
    emit(result)?;
    Ok(())
}
