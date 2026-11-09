#[cfg(test)]
#[path = "coding_submission_probe/auxiliary_fds.rs"]
mod auxiliary_fds;
#[cfg(target_os = "linux")]
#[path = "coding_submission_probe/owned.rs"]
mod owned;
// Existing native broker/custodian transport for a coding DEVELOPMENT probe.
// No semantic capability, canonical publisher or apply.
#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use realm_v6::{
        broker_rpc::{DiagnosticBinding, DiagnosticBrokerRpc},
        coding_submission::SubmissionContract,
        custody::CustodyClient,
        frontier::EffectFrontier,
    };
    use std::{
        fs::{self, File},
        io::Write,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                fs::{MetadataExt, OpenOptionsExt},
                net::UnixStream,
            },
        },
        path::PathBuf,
    };
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 10 || unsafe { libc::geteuid() } != 0 {
        return Err("root diagnostic launcher required: STATE CONTRACT PID START UID GID OUTPUT_FD CUSTODY_FD PIDFD".into());
    }
    let state = PathBuf::from(&args[1]);
    let m = fs::symlink_metadata(&state)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o7777 != 0o700 {
        return Err("private fresh diagnostic state required".into());
    }
    let contract: SubmissionContract = serde_json::from_slice(&fs::read(&args[2])?)?;
    contract.validate()?;
    let pid: i32 = args[3].parse()?;
    let start: u64 = args[4].parse()?;
    let uid: u32 = args[5].parse()?;
    let gid: u32 = args[6].parse()?;
    let output_fd: i32 = args[7].parse()?;
    let custody_fd: i32 = args[8].parse()?;
    let pidfd: i32 = args[9].parse()?;
    if pid <= 1
        || start == 0
        || uid == 0
        || gid == 0
        || output_fd <= 2
        || custody_fd <= 2
        || pidfd <= 2
        || output_fd == custody_fd
        || output_fd == pidfd
        || custody_fd == pidfd
    {
        return Err("diagnostic process/descriptor identity differs".into());
    }
    // SAFETY: each descriptor is uniquely transferred by the owned launcher.
    let mut wire = unsafe { UnixStream::from_raw_fd(0) };
    let output = unsafe { File::from_raw_fd(output_fd) };
    let custody = unsafe { UnixStream::from_raw_fd(custody_fd) };
    let held_pidfd = unsafe { File::from_raw_fd(pidfd) };
    wire.set_nonblocking(false)?;
    custody.set_nonblocking(false)?;
    custody.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    custody.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    wire.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    wire.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: writable ucred buffer and socklen address are valid.
    if unsafe {
        libc::getsockopt(
            wire.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
        || size as usize != std::mem::size_of::<libc::ucred>()
        || (peer.pid, peer.uid, peer.gid) != (pid, uid, gid)
    {
        return Err("native connection is not the owned VMM peer".into());
    }
    let live = || -> Result<(), Box<dyn std::error::Error>> {
        let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", held_pidfd.as_raw_fd()))?;
        if !info.lines().any(|line| {
            line.strip_prefix("Pid:")
                .is_some_and(|v| v.trim() == pid.to_string())
        }) {
            return Err("pidfd incarnation differs".into());
        }
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let actual: u64 = stat
            .rsplit_once(") ")
            .ok_or("malformed process stat")?
            .1
            .split_whitespace()
            .nth(19)
            .ok_or("missing process start")?
            .parse()?;
        let m = fs::metadata(format!("/proc/{pid}"))?;
        let mut poll = libc::pollfd {
            fd: held_pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid writable pollfd; nonblocking observation.
        if actual != start
            || (m.uid(), m.gid()) != (uid, gid)
            || unsafe { libc::poll(&mut poll, 1, 0) } != 0
            || poll.revents != 0
        {
            return Err("owned native peer is no longer live".into());
        }
        Ok(())
    };
    live()?;
    let input = state.join("input");
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&input)?;
    file.sync_all()?;
    drop(file);
    let frontier = EffectFrontier::create_custodied(
        &state,
        &contract.run_id,
        "coding-native-development",
        &input,
        output,
        CustodyClient::new(custody, contract.run_id.clone()),
    )
    .map_err(|e| format!("frontier refused: {e:?}"))?;
    let binding = DiagnosticBinding {
        run_id: contract.run_id.clone(),
        broker_identity: "coding-native-development".into(),
        launch_identity: contract.execution_id.clone(),
        semantic_launch_identity: contract.execution_id.clone(),
        starting_generation: blake3::hash(b"").to_hex().to_string(),
        topology_root: blake3::hash(&serde_json::to_vec(&contract)?)
            .to_hex()
            .to_string(),
        vmm_start_ticks: start,
        challenge_root: contract.challenge_root.clone(),
    };
    let mut broker = DiagnosticBrokerRpc::new(frontier, binding)
        .map_err(|e| format!("broker refused: {e:?}"))?;
    broker
        .restrict_to_coding_submission(contract)
        .map_err(|e| format!("profile refused: {e:?}"))?;
    broker
        .send_bootstrap(&mut wire)
        .map_err(|e| format!("bootstrap refused: {e:?}"))?;
    for _ in 0..2 {
        live()?;
        broker
            .serve_one(&mut wire)
            .map_err(|e| format!("native request refused: {e:?}"))?;
        if broker.is_poisoned() {
            return Err("native request poisoned the diagnostic session".into());
        }
    }
    drop(wire);
    println!("NATIVE_WRITE_CLOSE_ACKNOWLEDGED; AUTHORITY=NONE");
    std::io::stdout().flush()?;
    // Transport EOF is not a terminal barrier. The parent's exact held pidfd
    // must actually report exit before diagnostic journal sealing.
    let mut poll = libc::pollfd {
        fd: held_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one writable pollfd retained for this exact incarnation.
    if unsafe { libc::poll(&mut poll, 1, 60_000) } != 1
        || poll.revents & libc::POLLIN == 0
        || poll.revents & !(libc::POLLIN | libc::POLLHUP) != 0
    {
        return Err("owned VMM terminal observation unavailable; history remains unsealed".into());
    }
    broker
        .seal_custodian_after_barrier("diagnostic-owned-vmm-exited")
        .map_err(|e| format!("custody seal refused: {e:?}"))?;
    broker
        .seal_frontier_for_diagnostic_audit("diagnostic-owned-vmm-exited")
        .map_err(|e| format!("frontier seal refused: {e:?}"))?;
    println!("DIAGNOSTIC_NATIVE_HISTORY_SEALED; AUTHORITY=NONE");
    Ok(())
}
// Read-only adapter to the existing independent auditors. Produces no token.
fn audit(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        fs::OpenOptions,
        io::{Read, Seek, SeekFrom},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::Path,
    };
    let measured = args[1] == "--audit-measured-owned";
    if args.len() != if measured { 10 } else { 8 } {
        return Err("audit: --audit-diagnostic STATE EXPECTED_CONTRACT OBJECT_DEVICE OBJECT_INODE PACKET_BLAKE3 EXPECTED_HEAD".into());
    }
    fn bytes(path: &Path, limit: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let before = file.metadata()?;
        if !before.is_file()
            || before.nlink() != 1
            || before.len() > limit as u64
            || before.mode() & 0o7777 != 0o600
        {
            return Err("diagnostic input identity/mode/bound refused".into());
        }
        let mut value = Vec::new();
        (&file).take(limit as u64 + 1).read_to_end(&mut value)?;
        if value.len() > limit || value.len() as u64 != before.len() {
            return Err("diagnostic read bound differs".into());
        }
        file.seek(SeekFrom::Start(0))?;
        let mut second = Vec::new();
        (&file).take(limit as u64 + 1).read_to_end(&mut second)?;
        if second != value {
            return Err("diagnostic bytes changed during second pass".into());
        }
        let held_after = file.metadata()?;
        if (
            before.dev(),
            before.ino(),
            before.len(),
            before.mode(),
            before.uid(),
            before.gid(),
            before.nlink(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            held_after.dev(),
            held_after.ino(),
            held_after.len(),
            held_after.mode(),
            held_after.uid(),
            held_after.gid(),
            held_after.nlink(),
            held_after.mtime(),
            held_after.mtime_nsec(),
            held_after.ctime(),
            held_after.ctime_nsec(),
        ) {
            return Err("held diagnostic input changed".into());
        }
        let after = std::fs::symlink_metadata(path)?;
        if (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) {
            return Err("diagnostic input changed during read".into());
        }
        Ok(value)
    }
    let state = Path::new(&args[2]);
    let contract: realm_v6::coding_submission::SubmissionContract =
        serde_json::from_slice(&bytes(Path::new(&args[3]), 4096)?)?;
    contract.validate()?;
    let output = bytes(
        &state.join("custody/output"),
        realm_v6::coding_submission::MAX_SUBMISSION,
    )?;
    let packet = contract.decode(&output)?;
    let digest = blake3::hash(&output).to_hex().to_string();
    if digest != args[6] || packet.transcript_head != args[7] {
        return Err("external packet/head pins differ".into());
    }
    let object = realm_v6::frontier::ObjectIdentity {
        device: args[4].parse()?,
        inode: args[5].parse()?,
    };
    let frontier = realm_v6::frontier::audit_bytes(
        &bytes(
            &state.join(format!("{}.frontier.jsonl", contract.run_id)),
            64 * 1024 * 1024,
        )?,
        &contract.run_id,
        if measured {
            &args[8]
        } else if args[1] == "--audit-native-owned" {
            "coding-native-owned"
        } else {
            "coding-native-development"
        },
    )
    .map_err(|e| format!("frontier audit refused: {e:?}"))?;
    if measured
        && (args[8].len() != 64
            || args[9].len() != 64
            || frontier.records().iter().any(|r| {
                r.mediation_manifest_root != args[9] || r.launch_identity != contract.execution_id
            }))
    {
        return Err("externally expected measured broker/session differs".into());
    }
    let custody = realm_v6::custody::audit_custody_against_frontier(
        &bytes(&state.join("custody/custody.jsonl"), 64 * 1024 * 1024)?,
        &frontier,
        &object,
    )
    .map_err(|e| format!("custody audit refused: {e:?}"))?;
    if custody.committed_write_count != 1 || custody.final_output_digest != digest {
        return Err("native output/custody agreement differs".into());
    }
    println!(
        "{}",
        serde_json::json!({"schema":"realm.coding-native-development-audit.v1","authority":"NONE",
        "realm_artifact":null,"object_identity_scope":"expected retained journal identity; copied output inode is not authenticated","run_id":contract.run_id,"transcript_head":packet.transcript_head,
        "packet_blake3":digest,"committed_write_count":custody.committed_write_count,
        "custody_head":custody.head,"frontier_head":frontier.head})
    );
    Ok(())
}

fn main() {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    if let Some(result) = realm_v6::controller_relay::dispatch_internal() {
        if let Err(error) = result {
            eprintln!("REFUSE_INTERNAL_RELAY; AUTHORITY=NONE: {error}");
            std::process::exit(2);
        }
        return;
    }

    let args: Vec<_> = std::env::args().collect();
    #[cfg(target_os = "linux")]
    if args.get(1).is_some_and(|s| s == "--retain-native-attempts") {
        if let Err(error) = realm_v6::coding_runtime::attempt_history::run_retained(&args) {
            eprintln!("NATIVE_ATTEMPT_HISTORY_INCOMPLETE; AUTHORITY=NONE: {error}");
            std::process::exit(2);
        }
        return;
    }
    #[cfg(target_os = "linux")]
    if args.len() == 2 && args[1] == "--resource-inspection-preflight" {
        let result = realm_v6::coding_provenance::inspect_kernel_access();
        println!(
            "{}",
            serde_json::json!({"authority":"NONE","architecture":std::env::consts::ARCH,
            "inspection_api_available":result.is_ok(),"vmm_qualification":"NOT_RUN",
            "error":result.as_ref().err().map(ToString::to_string)})
        );
        if result.is_err() {
            std::process::exit(2);
        }
        return;
    }
    if args.get(1).is_some_and(|s| {
        matches!(
            s.as_str(),
            "--audit-diagnostic" | "--audit-native-owned" | "--audit-measured-owned"
        )
    }) {
        if let Err(error) = audit(&args) {
            eprintln!("DIAGNOSTIC_AUDIT_REFUSED; AUTHORITY=NONE: {error}");
            std::process::exit(2);
        }
        return;
    }
    #[cfg(target_os = "linux")]
    if args.get(1).is_some_and(|s| {
        matches!(
            s.as_str(),
            "--native-custody-launch" | "--native-referee-launch"
        )
    }) {
        if let Err(error) = owned::run_native_custody(&args) {
            eprintln!("NATIVE_CODING_CUSTODY_REFUSED; AUTHORITY=NONE: {error}");
            std::process::exit(2);
        }
        return;
    }
    #[cfg(target_os = "linux")]
    if args.get(1).is_some_and(|s| s == "--owned-launch") {
        if let Err(error) = owned::run(&args) {
            eprintln!("OWNED_CODING_NATIVE_REFUSED; AUTHORITY=NONE: {error}");
            std::process::exit(2);
        }
        return;
    }
    #[cfg(target_os = "linux")]
    if let Err(error) = run() {
        eprintln!("DEVELOPMENT_NATIVE_INCOMPLETE; AUTHORITY=NONE: {error}");
        std::process::exit(2);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("REFUSE: actual Linux required; AUTHORITY=NONE");
        std::process::exit(2);
    }
}
