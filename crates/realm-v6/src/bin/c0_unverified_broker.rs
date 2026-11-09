//! One real C0 transport probe through the Rust durable broker. This binary
//! cannot create a checked mediation claim or an admission decision.
#[cfg(target_os = "linux")]
use realm_v6::broker_rpc::BrokerRpc;
#[cfg(target_os = "linux")]
use realm_v6::custody::CustodyClient;
#[cfg(target_os = "linux")]
use realm_v6::frontier::{self, EffectFrontier, ObjectIdentity};
#[cfg(target_os = "linux")]
use realm_v6::integration::{self, JoinContext};
#[cfg(target_os = "linux")]
use realm_v6::measured_launch::{
    C0DiagnosticCaptureContext, MeasuredLaunchSession, UnixEndpointIdentity,
};
#[cfg(target_os = "linux")]
use realm_v6::mediation::{MediationChallenge, MediationSessionBinding};
#[cfg(target_os = "linux")]
use realm_v6::semantic_v2::{self as v2, Access, Action, ReadEnd};
#[cfg(target_os = "linux")]
use serde_json::json;
#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
fn proc_start_ticks(pid: i32) -> Result<u64, Box<dyn std::error::Error>> {
    if pid <= 1 {
        return Err("invalid process identity".into());
    }
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // The comm field is parenthesized and may itself contain spaces or ')'.
    // After the final ") ", index 19 is the kernel's starttime field 22.
    let fields = stat
        .rsplit_once(") ")
        .ok_or("malformed process stat")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    if fields.len() <= 19 {
        return Err("short process stat".into());
    }
    Ok(fields[19].parse()?)
}

#[cfg(target_os = "linux")]
fn check_live_binding(
    pidfd: i32,
    listener: &UnixListener,
    listener_path: &Path,
    listener_identity: (u64, u64),
    peer_pid: i32,
    expected_start_ticks: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{pidfd}"))?;
    let pid_lines: Vec<_> = info
        .lines()
        .filter_map(|line| line.strip_prefix("Pid:"))
        .collect();
    if pid_lines.len() != 1 || pid_lines[0].trim().parse::<i32>()? != peer_pid {
        return Err("pidfd does not pin the AF_UNIX peer process".into());
    }
    if expected_start_ticks == 0 || proc_start_ticks(peer_pid)? != expected_start_ticks {
        return Err("AF_UNIX peer start identity differs from the VMM incarnation".into());
    }
    let mut poll_fd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll_fd is a valid single-element poll buffer.
    if unsafe { libc::poll(&mut poll_fd, 1, 0) } != 0 || poll_fd.revents != 0 {
        return Err("VMM pidfd exited or became ambiguous during RPC".into());
    }
    // A socket FD's sockfs inode is distinct from the pathname inode. Check
    // the held socket's bound name and the path's observed identity separately.
    if listener.local_addr()?.as_pathname() != Some(listener_path) {
        return Err("held AF_UNIX listener is bound to another path".into());
    }
    let path_stat = fs::symlink_metadata(listener_path)?;
    if !path_stat.file_type().is_socket() || (path_stat.dev(), path_stat.ino()) != listener_identity
    {
        return Err("host AF_UNIX listener pathname changed from the held socket".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wait_vmm_exit_before_challenge(
    pidfd: i32,
    control: &UnixStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut ready = [
        libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: control.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // SAFETY: ready is a valid two-element poll buffer. A premature response
    // or closed control socket is never treated as terminal authorization.
    if unsafe { libc::poll(ready.as_mut_ptr(), ready.len() as libc::nfds_t, 20_000) } < 1
        || ready[1].revents != 0
        || ready[0].revents & libc::POLLIN == 0
        || ready[0].revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("VMM exit or prechallenge control state ambiguous".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn challenge_runner(control: &mut UnixStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut premature = libc::pollfd {
        fd: control.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: premature is a valid single-element poll buffer.
    if unsafe { libc::poll(&mut premature, 1, 0) } != 0 || premature.revents != 0 {
        return Err("control response arrived before broker challenge".into());
    }
    let mut nonce = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let mut challenge = [0u8; 33];
    challenge[0] = b'C';
    challenge[1..].copy_from_slice(&nonce);
    control.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    control.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
    control.write_all(&challenge)?;
    let mut response = [0u8; 33];
    control.read_exact(&mut response)?;
    if response[0] != b'R' || response[1..] != nonce {
        return Err("terminal challenge response mismatch".into());
    }
    let mut extra = [0u8; 1];
    if control.read(&mut extra)? != 0 {
        return Err("terminal challenge response had extra bytes".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_terminal_binding(
    pidfd: i32,
    listener: &UnixListener,
    listener_path: &Path,
    listener_identity: (u64, u64),
    stream: &mut UnixStream,
) -> Result<(), Box<dyn std::error::Error>> {
    // This is the same held pidfd checked against peer PID/start while live.
    // After reaping, /proc/<pid>/stat may vanish; numeric PID lookup here
    // would be a weaker (and possibly reused) identity.
    let mut exited = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: exited is a valid single-element poll buffer.
    if unsafe { libc::poll(&mut exited, 1, 0) } != 1
        || exited.revents & libc::POLLIN == 0
        || exited.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("held VMM pidfd has no unambiguous exit observation".into());
    }
    if listener.local_addr()?.as_pathname() != Some(listener_path) {
        return Err("held AF_UNIX listener is bound to another path".into());
    }
    let path_stat = fs::symlink_metadata(listener_path)?;
    if !path_stat.file_type().is_socket() || (path_stat.dev(), path_stat.ino()) != listener_identity
    {
        return Err("host AF_UNIX listener pathname changed before terminal observation".into());
    }
    let mut pending_connection = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pending_connection is a valid single-element poll buffer.
    if unsafe { libc::poll(&mut pending_connection, 1, 0) } != 0 || pending_connection.revents != 0
    {
        return Err("host AF_UNIX listener has pending or ambiguous connections".into());
    }
    stream.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    let mut pending = [0u8; 1];
    if stream.read(&mut pending)? != 0 {
        return Err("unexpected RPC bytes remained after C0 Close".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn revalidate_measured_launch(
    measured: &MeasuredLaunchSession,
    config_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    measured
        .revalidate_c0_diagnostic(&fs::read(config_path)?)
        .map_err(|error| format!("measured VMM/config revalidation refused: {error:?}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

#[cfg(target_os = "linux")]
fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 20 {
        return Err(
            "usage: c0_unverified_broker CONNECTION_FD LISTENER_FD VMM_PIDFD STATE RUN START VMM_BIRTH VMM_UID VMM_GID CONFIG LISTENER_PATH CONTROL_SOCKET_FD READONLY_OUTPUT_FD CUSTODY_SOCKET_FD MANIFEST FIRECRACKER KERNEL ROOTFS GUEST_POLICY".into(),
        );
    }
    let fd: i32 = args[1].parse()?;
    let listener_fd: i32 = args[2].parse()?;
    let pidfd: i32 = args[3].parse()?;
    let control_fd: i32 = args[12].parse()?;
    let output_fd: i32 = args[13].parse()?;
    let custody_fd: i32 = args[14].parse()?;
    let vmm_start_ticks: u64 = args[7].parse()?;
    let vmm_uid: u32 = args[8].parse()?;
    let vmm_gid: u32 = args[9].parse()?;
    if fd < 3
        || listener_fd < 3
        || pidfd < 3
        || control_fd < 3
        || output_fd < 3
        || custody_fd < 3
        || fd == listener_fd
        || fd == pidfd
        || fd == control_fd
        || listener_fd == pidfd
        || listener_fd == control_fd
        || pidfd == control_fd
        || [fd, listener_fd, pidfd, control_fd].contains(&output_fd)
        || [fd, listener_fd, pidfd, control_fd, output_fd].contains(&custody_fd)
        || vmm_start_ticks == 0
    {
        return Err("invalid inherited connection or VMM label".into());
    }
    // SAFETY: the launcher explicitly passes this owned connection descriptor
    // to this child process. The binary constructs exactly one owning stream.
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
    // SAFETY: the launcher explicitly passes this bound listener descriptor.
    let listener = unsafe { UnixListener::from_raw_fd(listener_fd) };
    // SAFETY: the launcher passes one owned end of an AF_UNIX socketpair.
    let mut control = unsafe { UnixStream::from_raw_fd(control_fd) };
    // SAFETY: the launcher passes only its pre-opened read-only output handle
    // and the broker end of an AF_UNIX socketpair to the custodian.
    let output = unsafe { File::from_raw_fd(output_fd) };
    let custody_stream = unsafe { UnixStream::from_raw_fd(custody_fd) };
    let output_metadata = output.metadata()?;
    let output_identity = ObjectIdentity {
        device: output_metadata.dev(),
        inode: output_metadata.ino(),
    };
    let output_snapshot = output.try_clone()?;
    if control.local_addr()?.as_pathname().is_some() {
        return Err("terminal control socket is unexpectedly named".into());
    }
    // Python's timeout mode sets O_NONBLOCK on the shared open-file description.
    // Rust's read_exact/write_all need blocking mode plus explicit timeouts.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(20)))?;
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` and `length` are valid writable buffers and the
    // descriptor is an inherited AF_UNIX stream checked by the caller.
    let status = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if status != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::last_os_error().into());
    }
    if credentials.uid != vmm_uid || credentials.gid != vmm_gid {
        return Err("AF_UNIX peer credentials differ from dedicated VMM identity".into());
    }
    let listener_path = Path::new(&args[11]);
    let path_stat = fs::symlink_metadata(listener_path)?;
    if !path_stat.file_type().is_socket() {
        return Err("host AF_UNIX listener path is not a socket".into());
    }
    let listener_identity = (path_stat.dev(), path_stat.ino());
    check_live_binding(
        pidfd,
        &listener,
        listener_path,
        listener_identity,
        credentials.pid,
        vmm_start_ticks,
    )?;
    let state = Path::new(&args[4]);
    let manifest_bytes = fs::read(&args[15])?;
    if manifest_bytes.is_empty() || manifest_bytes.len() > 65536 {
        return Err("diagnostic topology bytes missing or too large".into());
    }
    let config_path = Path::new(&args[10]);
    let config_bytes = fs::read(config_path)?;
    let config: serde_json::Value = serde_json::from_slice(&config_bytes)?;
    let uds_path = config
        .get("vsock")
        .and_then(|value| value.get("uds_path"))
        .and_then(serde_json::Value::as_str)
        .ok_or("measured C0 config lacks a vsock UDS path")?;
    let firecracker_path = Path::new(&args[16]);
    let firecracker_version_output = Command::new(firecracker_path).arg("--version").output()?;
    if !firecracker_version_output.status.success() {
        return Err("Firecracker version query failed".into());
    }
    let firecracker_version = String::from_utf8(firecracker_version_output.stdout)?
        .trim()
        .to_owned();
    if firecracker_version.is_empty() {
        return Err("Firecracker version query returned an empty identity".into());
    }
    let task_bytes = fs::read(&args[19])?;
    // This binary is diagnostic-only, but it must still measure the exact
    // challenge later used by its broker session rather than inventing one in
    // the launch record.
    let rpc_challenge = MediationChallenge::fresh()?;
    let broker_endpoint =
        UnixEndpointIdentity::capture_for_vmm_group(&listener, listener_path, vmm_gid)
            .map_err(|error| format!("measured C0 broker endpoint refused: {error:?}"))?;
    let measured_launch = MeasuredLaunchSession::capture_c0_diagnostic(
        &config_bytes,
        C0DiagnosticCaptureContext {
            run_id: args[5].clone(),
            execution_id: args[5].clone(),
            challenge: rpc_challenge.value().to_owned(),
            s0_root: args[6].clone(),
            expected_vmm_start_ticks: vmm_start_ticks,
            expected_vmm_gid: vmm_gid,
            firecracker_version,
            firecracker_path: firecracker_path.to_path_buf(),
            kernel_path: Path::new(&args[17]).to_path_buf(),
            rootfs_path: Path::new(&args[18]).to_path_buf(),
            guest_policy_path: Path::new(&args[19]).to_path_buf(),
            uds_path: Path::new(uds_path).to_path_buf(),
            broker_endpoint,
            policy_identifier: "c0-diagnostic-policy".into(),
            policy_version: "1".into(),
            policy_bytes: manifest_bytes.clone(),
            task_bytes: task_bytes.clone(),
            vmm_pid: credentials.pid as u32,
        },
    )
    .map_err(|error| format!("measured C0 launch refused: {error:?}"))?;
    if !measured_launch.network_is_explicitly_empty() || measured_launch.consumable_input_binding()
    {
        return Err("measured C0 launch identity contradicted its live binding".into());
    }
    revalidate_measured_launch(&measured_launch, config_path)?;
    let semantic_launch = v2::Launch {
        task: digest(&task_bytes),
        executable: measured_launch.rootfs_identity().blake3().to_owned(),
        interpreter: None,
        libraries: Vec::new(),
        argv: vec!["c0".into()],
        environment: std::collections::BTreeMap::new(),
        cwd: "/work".into(),
        policy: digest(&manifest_bytes),
        generation: 0,
        allowed_inputs: vec!["input".into()],
        allowed_outputs: vec!["output".into()],
        time_rng_policy: digest(b"REALM-C0-FIXED-TIME-RNG-V1"),
    };
    let semantic_launch_identity = digest(&serde_json::to_vec(&semantic_launch)?);
    let session_binding = MediationSessionBinding::from_measured_launch(
        &measured_launch,
        &semantic_launch_identity,
        &args[6],
        &rpc_challenge,
    )
    .map_err(|error| format!("measured broker session binding refused: {error:?}"))?;
    let broker_binding_root = session_binding.root().to_owned();
    let broker_identity = measured_launch.firecracker_identity().blake3().to_owned();
    let frontier = EffectFrontier::create_custodied(
        state,
        &args[5],
        &broker_identity,
        &state.join("input"),
        output,
        CustodyClient::new(custody_stream, args[5].clone()),
    )
    .map_err(|e| format!("frontier creation failed: {e:?}"))?;
    let mut broker = BrokerRpc::new_for_measured_session(frontier, session_binding)
        .map_err(|e| format!("measured broker startup refused: {e:?}"))?;
    check_live_binding(
        pidfd,
        &listener,
        listener_path,
        listener_identity,
        credentials.pid,
        vmm_start_ticks,
    )?;
    revalidate_measured_launch(&measured_launch, config_path)?;
    broker
        .send_bootstrap(&mut stream)
        .map_err(|e| format!("bootstrap failed: {e:?}"))?;
    for request_index in 1..=6 {
        check_live_binding(
            pidfd,
            &listener,
            listener_path,
            listener_identity,
            credentials.pid,
            vmm_start_ticks,
        )?;
        revalidate_measured_launch(&measured_launch, config_path)?;
        broker.serve_one(&mut stream).map_err(|e| {
            format!(
                "RPC {request_index} transport failed after {} durable records: {e:?}",
                broker.evidence_sequence()
            )
        })?;
        if broker.is_poisoned() {
            return Err("Rust broker refused a C0 request".into());
        }
        if request_index < 6 {
            check_live_binding(
                pidfd,
                &listener,
                listener_path,
                listener_identity,
                credentials.pid,
                vmm_start_ticks,
            )?;
            revalidate_measured_launch(&measured_launch, config_path)?;
        }
    }
    if broker.evidence_sequence() != 8 {
        return Err("unexpected C0 durable record count".into());
    }
    wait_vmm_exit_before_challenge(pidfd, &control)?;
    check_terminal_binding(
        pidfd,
        &listener,
        listener_path,
        listener_identity,
        &mut stream,
    )?;
    challenge_runner(&mut control)?;
    check_terminal_binding(
        pidfd,
        &listener,
        listener_path,
        listener_identity,
        &mut stream,
    )?;
    let custody_head = broker
        .seal_custodian_after_barrier("c0-terminal")
        .map_err(|e| format!("custodian terminal seal failed: {e:?}"))?;
    let journal_path = broker.journal_path().to_path_buf();
    let output_blake3 = broker.output_content_digest().to_owned();
    let completion = broker
        .finish_measured_session("c0-terminal")
        .map_err(|e| format!("measured broker completion refused: {e:?}"))?;
    let journal = fs::read(&journal_path)?;
    let audit = frontier::audit_journal(&journal_path, &args[5], &broker_identity)
        .map_err(|e| format!("diagnostic frontier audit refused: {e:?}"))?;
    if audit.head != completion.frontier_root() {
        return Err("frontier head changed between seal and audit".into());
    }
    let input_path = state.join("input");
    let input_bytes = fs::read(&input_path)?;
    if input_bytes != b"abc" {
        return Err("C0 input changed from the pinned initial bytes".into());
    }
    let input_metadata = fs::metadata(&input_path)?;
    let input_identity = ObjectIdentity {
        device: input_metadata.dev(),
        inode: input_metadata.ino(),
    };
    // This duplicate was acquired before the original output descriptor moved
    // into the frontier, so it observes the same custodian-owned inode safely.
    let output_metadata = output_snapshot.metadata()?;
    let output_reader = output_snapshot;
    if output_metadata.len() > 1024 * 1024 {
        return Err("C0 output exceeded the semantic model limit".into());
    }
    let mut output_bytes = vec![0; output_metadata.len() as usize];
    let read_count = output_reader.read_at(&mut output_bytes, 0)?;
    output_bytes.truncate(read_count);
    if output_bytes != b"ABC" || read_count as u64 != output_metadata.len() {
        return Err("C0 output bytes or length differ from the declared task".into());
    }
    if output_metadata.dev() != output_identity.device
        || output_metadata.ino() != output_identity.inode
    {
        return Err("output descriptor identity changed after broker binding".into());
    }
    let input_incarnation = format!("input-{}-{}", input_identity.device, input_identity.inode);
    let output_incarnation = format!(
        "output-{}-{}",
        output_identity.device, output_identity.inode
    );
    let input_mode = input_metadata.mode() & 0o777;
    let output_mode = output_metadata.mode() & 0o777;
    let initial = std::collections::BTreeMap::from([
        (
            "input".to_owned(),
            v2::Object {
                incarnation: input_incarnation.clone(),
                version: 0,
                bytes: input_bytes,
                mode: input_mode,
            },
        ),
        (
            "output".to_owned(),
            v2::Object {
                incarnation: output_incarnation.clone(),
                version: 0,
                bytes: Vec::new(),
                mode: output_mode,
            },
        ),
    ]);
    let process = format!("vmm-{}-{}", credentials.pid, vmm_start_ticks);
    let epoch = "c0-terminal".to_owned();
    let events = vec![
        Action::Start { parent: None },
        Action::Open {
            fd: 0,
            handle: "input".into(),
            path: "input".into(),
            incarnation: input_incarnation.clone(),
            access: Access::Read,
        },
        Action::Read {
            fd: 0,
            handle: "input".into(),
            incarnation: input_incarnation.clone(),
            version: 0,
            offset: 0,
            requested: 128,
            returned: b"abc".to_vec(),
            returned_length: 3,
            end: ReadEnd::Eof,
        },
        Action::Close {
            fd: 0,
            handle: "input".into(),
        },
        Action::Open {
            fd: 1,
            handle: "output".into(),
            path: "output".into(),
            incarnation: output_incarnation.clone(),
            access: Access::Write,
        },
        Action::Write {
            fd: 1,
            handle: "output".into(),
            incarnation: output_incarnation.clone(),
            before_version: 0,
            after_version: 1,
            offset: 0,
            requested: b"ABC".to_vec(),
            returned_length: 3,
        },
        Action::Close {
            fd: 1,
            handle: "output".into(),
        },
        Action::Exit { code: 0 },
        Action::Terminal,
    ]
    .into_iter()
    .enumerate()
    .map(|(sequence, action)| v2::Event {
        sequence: sequence as u64,
        run: args[5].clone(),
        process: process.clone(),
        epoch: epoch.clone(),
        action,
    })
    .collect::<Vec<_>>();
    let mut final_world = initial.clone();
    final_world.insert(
        "output".into(),
        v2::Object {
            incarnation: output_incarnation,
            version: 1,
            bytes: output_bytes,
            mode: output_mode,
        },
    );
    let mut receipt = v2::Receipt {
        format: 2,
        run: args[5].clone(),
        authority_parent: args[6].clone(),
        launch: semantic_launch.clone(),
        directories: Default::default(),
        initial: initial.clone(),
        events,
        dependencies: Vec::new(),
        final_world,
        health: v2::Health {
            epoch: epoch.clone(),
            source_count: 9,
            gaps: 0,
            duplicates: 0,
            reorder: 0,
            overflow: 0,
            restart: 0,
            partial: 0,
            delayed: 0,
            pending: 0,
            logger_died: false,
        },
        evidence_root: String::new(),
    };
    receipt.dependencies =
        v2::derive(&receipt).map_err(|e| format!("semantic receipt derivation refused: {e:?}"))?;
    v2::seal(&mut receipt).map_err(|e| format!("semantic receipt seal refused: {e:?}"))?;
    let expected = v2::ExpectedContext {
        run: args[5].clone(),
        process,
        epoch: epoch.clone(),
        authority_parent: args[6].clone(),
        launch: semantic_launch,
        directories: Default::default(),
        initial,
        source_count: 9,
        source_root: receipt.evidence_root.clone(),
    };
    let context = JoinContext {
        head: audit.head.clone(),
        monitor_id: broker_identity.clone(),
        manifest_root: broker_binding_root.clone(),
        launch_identity: semantic_launch_identity.clone(),
        starting_generation: args[6].clone(),
        freeze_epoch: epoch,
        input: input_identity,
        output: output_identity.clone(),
    };
    let joined = integration::join(
        &audit,
        &v2::Input {
            receipt: receipt.clone(),
            expected,
        },
        &context,
    )
    .map_err(|e| format!("same-run semantic/frontier join refused: {e:?}"))?;
    if joined.admission() != realm_v6::Admission::Refuse(realm_v6::Refusal::UnverifiedBoundary) {
        return Err("diagnostic semantic join produced an unexpected admission".into());
    }
    fs::write(
        state.join("semantic-v2-receipt.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    let measured_vmm_root = blake3::hash(&serde_json::to_vec(measured_launch.vmm())?)
        .to_hex()
        .to_string();
    let summary = json!({
        "report_schema": "realm.c0-measured-broker-report",
        "report_schema_version": 1,
        "classification": "MEASURED_BROKER_COMPLETION_SEMANTIC_JOIN_NON_AUTHORIZING",
        "accept": false,
        "checked_mediation_claim": false,
        "journal_sealed": true,
        "semantic_verification": "VALID_NON_AUTHORIZING",
        "semantic_receipt_root": receipt.evidence_root,
        "semantic_dependency_count": receipt.dependencies.len(),
        "semantic_launch_identity": semantic_launch_identity,
        "frontier_join_head": audit.head,
        "freeze_epoch": false,
        "terminal_observation": "HELD_PIDFD_EXIT_RPC_EOF_CHALLENGE_NON_AUTHORIZING",
        "vmm_pid": credentials.pid,
        "vmm_start_ticks": vmm_start_ticks,
        "execution_id": measured_launch.execution_id(),
        "measured_launch_domain": measured_launch.canonical_hash_domain(),
        "measured_launch_version": measured_launch.canonical_hash_version(),
        "measured_launch_root": measured_launch.canonical_hash_blake3(),
        "measured_launch_consumable_inputs": measured_launch.consumable_input_binding(),
        "measured_vm_config_root": measured_launch.vm_config_blake3(),
        "measured_firecracker_version": measured_launch.firecracker_version(),
        "measured_kernel_blake3": measured_launch.kernel_identity().blake3(),
        "measured_rootfs_blake3": measured_launch.rootfs_identity().blake3(),
        "measured_vmm_root": measured_vmm_root,
        "measured_broker_endpoint_root": measured_launch.broker_endpoint_blake3(),
        "broker_rpc_challenge_root": rpc_challenge.root(),
        "broker_session_binding_root": broker_binding_root,
        "broker_completion_root": completion.root(),
        "measured_network_empty": measured_launch.network_is_explicitly_empty(),
        "listener_device": listener_identity.0,
        "listener_inode": listener_identity.1,
        "rpc_requests": 6,
        "journal_records": audit.records().len(),
        "journal_blake3": blake3::hash(&journal).to_hex().to_string(),
        "output_blake3": output_blake3,
        "output_device": output_identity.device,
        "output_inode": output_identity.inode,
        "custody_terminal_head": custody_head,
    });
    fs::write(
        state.join("rust-broker-result.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_frontier_file(
    path: &Path,
    expected_blake3: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    const MAX_FRONTIER_BYTES: u64 = 64 * 1024 * 1024;
    if expected_blake3.len() != 64
        || !expected_blake3
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("expected frontier digest is malformed".into());
    }
    let path_before = fs::symlink_metadata(path)?;
    if !path_before.is_file() {
        return Err("frontier is not a regular file".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > MAX_FRONTIER_BYTES {
        return Err("frontier file exceeds the bounded regular-file profile".into());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(MAX_FRONTIER_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let identity = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    if bytes.len() as u64 > MAX_FRONTIER_BYTES
        || bytes.len() as u64 != before.len()
        || identity(&before) != identity(&after)
    {
        return Err("frontier changed or exceeded its bound while being read".into());
    }
    let path_after = fs::symlink_metadata(path)?;
    if path_after.dev() != after.dev() || path_after.ino() != after.ino() {
        return Err("frontier path no longer names the verified file".into());
    }
    let actual = blake3::hash(&bytes).to_hex().to_string();
    if actual != expected_blake3 {
        return Err("frontier bytes differ from the sealed broker digest".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = env::args().collect();
    let outcome = if args.len() == 4 && args[1] == "--verify-frontier-blake3" {
        verify_frontier_file(Path::new(&args[2]), &args[3])
    } else {
        run(&args)
    };
    if let Err(err) = outcome {
        eprintln!("C0 unverified broker refused: {err}");
        std::process::exit(2);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("C0 broker diagnostic requires Linux AF_UNIX peer credentials");
    std::process::exit(2);
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::{AsRawFd, OwnedFd};

    #[test]
    fn frontier_rehash_requires_the_exact_bounded_regular_file() {
        let dir = env::temp_dir().join(format!("realm-c0-frontier-rehash-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let path = dir.join("frontier.jsonl");
        let bytes = b"sealed frontier\n";
        fs::write(&path, bytes).unwrap();
        let digest = blake3::hash(bytes).to_hex().to_string();
        assert!(verify_frontier_file(&path, &digest).is_ok());
        assert!(verify_frontier_file(&path, &"0".repeat(64)).is_err());
        assert!(verify_frontier_file(&path, &"A".repeat(64)).is_err());
        let oversized = dir.join("oversized.jsonl");
        let oversized_file = File::create(&oversized).unwrap();
        oversized_file.set_len(64 * 1024 * 1024 + 1).unwrap();
        drop(oversized_file);
        assert!(verify_frontier_file(&oversized, &digest).is_err());
        fs::remove_file(&path).unwrap();
        let target = dir.join("target.jsonl");
        fs::write(&target, bytes).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(verify_frontier_file(&path, &digest).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn challenge_requires_fresh_echo_and_rejects_premature_bytes() {
        let (mut broker, mut runner) = UnixStream::pair().unwrap();
        let responder = std::thread::spawn(move || {
            let mut challenge = [0u8; 33];
            runner.read_exact(&mut challenge).unwrap();
            assert_eq!(challenge[0], b'C');
            challenge[0] = b'R';
            runner.write_all(&challenge).unwrap();
            runner.shutdown(std::net::Shutdown::Write).unwrap();
        });
        challenge_runner(&mut broker).unwrap();
        responder.join().unwrap();

        let (mut broker, mut runner) = UnixStream::pair().unwrap();
        runner.write_all(b"premature").unwrap();
        assert!(challenge_runner(&mut broker).is_err());

        let (mut broker, mut runner) = UnixStream::pair().unwrap();
        let responder = std::thread::spawn(move || {
            let mut challenge = [0u8; 33];
            runner.read_exact(&mut challenge).unwrap();
            challenge[0] = b'R';
            challenge[1] ^= 1;
            runner.write_all(&challenge).unwrap();
            runner.shutdown(std::net::Shutdown::Write).unwrap();
        });
        assert!(challenge_runner(&mut broker).is_err());
        responder.join().unwrap();
    }

    #[test]
    fn terminal_binding_requires_exited_pidfd_and_original_listener() {
        let dir = env::temp_dir().join(format!("realm-c0-terminal-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let path = dir.join("listener");
        let moved = dir.join("moved-listener");
        let listener = UnixListener::bind(&path).unwrap();
        let stat = fs::symlink_metadata(&path).unwrap();
        let identity = (stat.dev(), stat.ino());
        let (mut stream, peer) = UnixStream::pair().unwrap();
        drop(peer);
        // SAFETY: pidfd_open returns a new descriptor for this live process.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as i32;
        assert!(raw >= 0);
        // SAFETY: raw is an owned pidfd.
        let live = unsafe { OwnedFd::from_raw_fd(raw) };
        assert!(
            check_terminal_binding(live.as_raw_fd(), &listener, &path, identity, &mut stream)
                .is_err()
        );

        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
        // SAFETY: child has been spawned and is still waitable.
        let raw =
            unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) } as i32;
        assert!(raw >= 0);
        // SAFETY: raw is an owned pidfd pinned before the child exits/reaps.
        let exited = unsafe { OwnedFd::from_raw_fd(raw) };
        child.wait().unwrap();
        let (control, mut premature) = UnixStream::pair().unwrap();
        premature.write_all(b"early").unwrap();
        assert!(wait_vmm_exit_before_challenge(exited.as_raw_fd(), &control).is_err());
        drop(premature);
        let (control, _runner) = UnixStream::pair().unwrap();
        wait_vmm_exit_before_challenge(exited.as_raw_fd(), &control).unwrap();
        check_terminal_binding(exited.as_raw_fd(), &listener, &path, identity, &mut stream)
            .unwrap();

        let pending = UnixStream::connect(&path).unwrap();
        assert!(
            check_terminal_binding(exited.as_raw_fd(), &listener, &path, identity, &mut stream)
                .is_err()
        );
        drop(pending);

        fs::rename(&path, &moved).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        assert!(
            check_terminal_binding(exited.as_raw_fd(), &listener, &path, identity, &mut stream)
                .is_err()
        );
        drop(replacement);
        drop(listener);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn live_pidfd_and_listener_path_replacement() {
        let dir = env::temp_dir().join(format!("realm-c0-binding-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let path = dir.join("listener");
        let moved = dir.join("moved-listener");
        let listener = UnixListener::bind(&path).unwrap();
        let stat = fs::symlink_metadata(&path).unwrap();
        let identity = (stat.dev(), stat.ino());
        // SAFETY: pidfd_open returns a new owned descriptor for this process.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as i32;
        assert!(raw >= 0);
        // SAFETY: raw was returned by pidfd_open and is owned exactly once.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        let peer_pid = std::process::id() as i32;
        let start = proc_start_ticks(peer_pid).unwrap();
        check_live_binding(
            pidfd.as_raw_fd(),
            &listener,
            &path,
            identity,
            peer_pid,
            start,
        )
        .unwrap();
        assert!(
            check_live_binding(
                pidfd.as_raw_fd(),
                &listener,
                &path,
                identity,
                peer_pid + 1,
                start
            )
            .is_err()
        );
        assert!(
            check_live_binding(
                pidfd.as_raw_fd(),
                &listener,
                &path,
                identity,
                peer_pid,
                start + 1
            )
            .is_err()
        );
        fs::rename(&path, &moved).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        assert!(
            check_live_binding(
                pidfd.as_raw_fd(),
                &listener,
                &path,
                identity,
                peer_pid,
                start
            )
            .is_err()
        );
        drop(replacement);
        drop(listener);
        fs::remove_dir_all(dir).unwrap();
    }
}
