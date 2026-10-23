//! One supported live production profile. All authority remains process-local.
#![cfg(target_os = "linux")]
use crate::profile::SyncTrace as _;
use crate::{
    broker_rpc::{BrokerRpc, FrozenMeasuredBroker},
    capsule::{BackendKind, CapsuleFacts, CapsuleObservation, CheckResult, evidence_binding_root},
    custody::{CustodyClient, audit_custody_against_frontier},
    execute::{ExecuteError, ExecuteRequest},
    filesystem_world::{self, FilesystemChange, FilesystemObject, FilesystemWorld},
    frontier::{self, EffectFrontier, ObjectIdentity},
    integration::{self, JoinContext, JoinedEvidence},
    measured_launch::{FileIdentity, PolicyIdentity, ProductionContainedLaunch},
    mediation::{MediationChallenge, MediationSessionBinding},
    run_closure::{
        self, RunClosureProofV3,
        linux::{ChildLaunch, RunOwnedChild, RunOwnedProcessIdentity},
    },
    semantic_v2::{self as v2, Access, Action, ReadEnd},
    supervisor::FirecrackerSupervisor,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::OwnedFd,
        unix::{
            fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    time::Duration,
};

pub(crate) struct ClosedCustodian {
    pub(crate) run_id: String,
    pub(crate) process: RunOwnedProcessIdentity,
    pub(crate) frontier_root: String,
    pub(crate) journal_root: String,
    pub(crate) root: String,
}

pub(crate) struct ProductionRun {
    pub(crate) production: ProductionContainedLaunch,
    pub(crate) session: MediationSessionBinding,
    pub(crate) frozen: FrozenMeasuredBroker,
    pub(crate) semantic: JoinedEvidence,
    pub(crate) closure: RunClosureProofV3,
    pub(crate) observation: CapsuleObservation,
    pub(crate) before: FilesystemWorld,
    pub(crate) after: FilesystemWorld,
    pub(crate) final_image: PathBuf,
    pub(crate) state: PathBuf,
}
fn bad(s: impl ToString) -> ExecuteError {
    ExecuteError::Supervisor(s.to_string())
}
fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
fn object(file: &File) -> Result<ObjectIdentity, ExecuteError> {
    let m = file.metadata()?;
    Ok(ObjectIdentity {
        device: m.dev(),
        inode: m.ino(),
    })
}
fn record(state: &Path, name: &str, value: &impl serde::Serialize) -> Result<(), ExecuteError> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(state.join(name))?;
    f.write_all(&serde_json::to_vec_pretty(value).map_err(bad)?)?;
    f.sync_all_traced()?;
    File::open(state)?.sync_all_traced()?;
    Ok(())
}
fn debugfs(image: &Path, command: &str) -> Result<Vec<u8>, ExecuteError> {
    let mut tool = std::process::Command::new("debugfs");
    if !command.starts_with("cat ") {
        tool.arg("-w");
    }
    let o = tool.args(["-R", command]).arg(image).output()?;
    if !o.status.success() {
        return Err(bad(String::from_utf8_lossy(&o.stderr)));
    }
    Ok(o.stdout)
}
fn open_custodian(
    live: &crate::supervisor::RootfsBrokerLaunch,
    binary: &Path,
    uid: u32,
    gid: u32,
    run: &str,
    timeout_ms: u64,
) -> Result<(RunOwnedChild, UnixStream, File, PathBuf, FileIdentity), ExecuteError> {
    let _profile = crate::profile::Span::new("custodian_start");
    if uid == 0 || gid == 0 {
        return Err(bad("custodian requires dedicated non-root credentials"));
    }
    let binary_id = FileIdentity::measure(binary)
        .map_err(|e| bad(format!("custodian input refused: {e:?}")))?;
    if binary_id.owner() != (0, 0)
        || !binary_id.trusted_parent_chain()
        || binary_id.mode() & 0o022 != 0
    {
        return Err(bad("custodian executable is not protected by the host"));
    }
    let dir = live.state().join("custody");
    fs::create_dir(&dir)?;
    crate::supervisor::chown_path(&dir, uid, gid).map_err(bad)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let output = dir.join("output");
    let journal = dir.join("custody.jsonl");
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&output)?;
    f.sync_all_traced()?;
    crate::supervisor::chown_path(&output, uid, gid).map_err(bad)?;
    drop(f);
    let ro = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&output)?;
    let (mut broker, child_stream) = UnixStream::pair()?;
    broker.set_read_timeout(Some(Duration::from_secs(20)))?;
    broker.set_write_timeout(Some(Duration::from_secs(20)))?;
    let owned: OwnedFd = child_stream.into();
    let stdin = File::from(owned);
    let stdout = File::create(live.state().join("custodian.stdout"))?;
    let stderr = File::create(live.state().join("custodian.stderr"))?;
    let uid_arg = uid.to_string();
    let gid_arg = gid.to_string();
    let args = vec![
        "--reuid",
        &uid_arg,
        "--regid",
        &gid_arg,
        "--clear-groups",
        "--inh-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
    ];
    let mut os_args = args
        .into_iter()
        .map(std::ffi::OsStr::new)
        .collect::<Vec<_>>();
    let timeout_arg = timeout_ms.to_string();
    os_args.extend([
        binary.as_os_str(),
        std::ffi::OsStr::new("output"),
        std::ffi::OsStr::new("custody.jsonl"),
        std::ffi::OsStr::new(run),
        std::ffi::OsStr::new(&timeout_arg),
    ]);
    let child = live
        .cgroup()
        .spawn_owned_with_fds(
            ChildLaunch {
                program: Path::new("/usr/bin/setpriv"),
                arguments: &os_args,
                working_directory: &dir,
                stdin: &stdin,
                stdout: &stdout,
                stderr: &stderr,
            },
            &[],
        )
        .map_err(bad)?;
    drop(stdin);
    drop(stdout);
    drop(stderr);
    let mut ready = [0u8; b"REALM-C0-CUSTODIAN-READY-V1\n".len()];
    broker.read_exact(&mut ready)?;
    if ready != *b"REALM-C0-CUSTODIAN-READY-V1\n" {
        return Err(bad("custodian ready gate differs"));
    }
    let current = crate::measured_launch::VmmIncarnation::capture_linux(child.pid() as u32)
        .map_err(|e| bad(format!("custodian incarnation refused: {e:?}")))?;
    if current.start_time_ticks() != child.identity().start_ticks()
        || current.owner() != (uid, gid)
        || current.executable_identity().blake3() != binary_id.blake3()
    {
        return Err(bad("custodian birth/credentials/executable differs"));
    }
    broker.write_all(b"REALM-C0-CUSTODIAN-START-V1\n")?;
    Ok((child, broker, ro, journal, binary_id))
}

pub(crate) fn run(
    supervisor: &FirecrackerSupervisor,
    request: &ExecuteRequest,
    execution: &str,
    policy: PolicyIdentity,
    custodian: &Path,
    uid: u32,
    gid: u32,
) -> Result<ProductionRun, ExecuteError> {
    run_contract(
        supervisor,
        request,
        &crate::c0_contract::C0FileContract::frozen(),
        execution,
        policy,
        custodian,
        uid,
        gid,
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_contract(
    supervisor: &FirecrackerSupervisor,
    request: &ExecuteRequest,
    contract: &crate::c0_contract::C0FileContract,
    execution: &str,
    policy: PolicyIdentity,
    custodian: &Path,
    uid: u32,
    gid: u32,
) -> Result<ProductionRun, ExecuteError> {
    contract.validate().map_err(bad)?;
    let _profile = crate::profile::Span::new("contained_task_pipeline");
    let initial_world_profile = crate::profile::Span::new("initial_world_observation");
    let before = crate::supervisor::scan_detached_workspace(
        &supervisor.starting_workspace_image,
        Path::new("/tmp"),
        "broker-start",
    )
    .map_err(bad)?;
    if before.entries.len() != 1
        || before.entries.get("input.txt")
            != Some(&FilesystemObject::File {
                content_blake3: digest(&contract.input_bytes),
                mode: contract.input_mode,
            })
        || filesystem_world::scan_directory(&request.root)
            .map_err(|e| bad(format!("S0 directory scan: {e:?}")))?
            .root
            != before.root
    {
        return Err(bad(
            "S0 differs from the frozen C0 input bytes/mode or has extra entries",
        ));
    }
    drop(initial_world_profile);
    let challenge = MediationChallenge::fresh()?;
    let mut live = supervisor
        .prepare_rootfs_broker(&request.run_id, execution, &challenge, &before.root, policy)
        .map_err(bad)?;
    let state = live.state().to_path_buf();
    let input_path = state.join("input");
    let actual_input = debugfs(&supervisor.starting_workspace_image, "cat input.txt")?;
    if actual_input != contract.input_bytes {
        return Err(bad("pinned S0 input bytes differ"));
    }
    let mut input = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&input_path)?;
    input.write_all(&actual_input)?;
    input.sync_all_traced()?;
    drop(input);
    let input_file = File::open(&input_path)?;
    let input_identity = object(&input_file)?;
    let (child, custody_stream, output, journal, custodian_binary) = open_custodian(
        &live,
        custodian,
        uid,
        gid,
        &request.run_id,
        request.timeout_ms,
    )?;
    if std::env::var_os("REALM_V6_QUALIFY_CONTAINMENT_CONTROLS").is_some() {
        match live.cgroup().remove_empty() {
            Err(run_closure::linux::CgroupOpenError::Refused("run cgroup is not empty")) => {}
            other => {
                return Err(bad(format!(
                    "live process survivor did not refuse empty-cgroup removal: {other:?}"
                )));
            }
        }
        record(
            &state,
            "qualification-live-survivor.json",
            &serde_json::json!({"case":"live_process_survivor_nonempty_cgroup","classification":"INVALID_REFUSED","scope":"actual VMM and custodian are live; remove_empty refuses; no closure capability exists yet"}),
        )?;
    }
    let output_identity = object(&output)?;
    let output_snapshot = output.try_clone()?;
    let launch = v2::Launch {
        task: live.measurement().policy_identity().task_blake3().into(),
        executable: live.measurement().guest_policy_identity().blake3().into(),
        interpreter: None,
        libraries: vec![],
        argv: request.command.clone(),
        environment: Default::default(),
        cwd: "/work".into(),
        policy: live.measurement().policy_identity().blake3().into(),
        generation: 0,
        allowed_inputs: vec!["input".into()],
        allowed_outputs: vec!["output".into()],
        time_rng_policy: digest(b"REALM-C0-FIXED-TIME-RNG-V1"),
    };
    let semantic_launch_root = digest(&serde_json::to_vec(&launch).map_err(bad)?);
    let session = MediationSessionBinding::from_measured_launch(
        live.measurement(),
        &semantic_launch_root,
        &before.root,
        &challenge,
    )
    .map_err(|e| bad(format!("broker binding refused: {e:?}")))?;
    let service_binding = MediationSessionBinding::from_measured_launch(
        live.measurement(),
        &semantic_launch_root,
        &before.root,
        &challenge,
    )
    .map_err(|e| bad(format!("broker service binding refused: {e:?}")))?;
    let broker_identity = live
        .measurement()
        .firecracker_identity()
        .blake3()
        .to_owned();
    let frontier = EffectFrontier::create_custodied(
        &state,
        &request.run_id,
        &broker_identity,
        &input_path,
        output,
        CustodyClient::new(custody_stream, request.run_id.clone()),
    )
    .map_err(|e| bad(format!("frontier refused: {e:?}")))?;
    let mut broker = BrokerRpc::new_for_measured_session(frontier, service_binding)
        .map_err(|e| bad(format!("broker refused: {e:?}")))?;
    if let Some(delay) = std::env::var_os("REALM_V6_QUALIFY_CUSTODIAN_IDLE_MS") {
        let delay = delay
            .to_str()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|d| *d < request.timeout_ms)
            .ok_or_else(|| bad("invalid bounded custodian idle qualification delay"))?;
        std::thread::sleep(Duration::from_millis(delay));
    }
    live.start().map_err(bad)?;
    let mut stream = live.accept().map_err(bad)?;
    broker
        .send_bootstrap(&mut stream)
        .map_err(|e| bad(format!("bootstrap refused: {e:?}")))?;
    let task_profile = crate::profile::Span::new("task_broker_rpc_execution");
    for n in 1..=6 {
        live.check_live_configuration().map_err(bad)?;
        broker
            .serve_one(&mut stream)
            .map_err(|e| bad(format!("RPC {n} refused: {e:?}")))?;
        if broker.is_poisoned() {
            return Err(bad("broker poisoned by guest operation"));
        }
    }
    if broker.evidence_sequence() != 8 || !broker.task_effects_closed() {
        return Err(bad("broker did not revoke all task authority"));
    }
    drop(task_profile);
    let freeze_profile = crate::profile::Span::new("effect_freeze_frontier_seal");
    let closed = live.close_transport(stream, &challenge).map_err(bad)?;
    let custody_head = broker
        .seal_custodian_after_barrier("effects-frozen-v1")
        .map_err(|e| bad(format!("custody seal refused: {e:?}")))?;
    let frontier_path = broker.journal_path().to_path_buf();
    let frozen = broker
        .freeze_measured_effects(closed, "effects-frozen-v1")
        .map_err(|e| bad(format!("effect freeze refused: {e:?}")))?;
    drop(freeze_profile);
    if std::env::var_os("REALM_V6_QUALIFY_CONTAINMENT_CONTROLS").is_some() {
        record(
            &state,
            "qualification-post-freeze.json",
            &serde_json::json!({"case":"attempted_write_after_actual_custodied_freeze","classification":"INVALID_REFUSED","unchanged_journal_and_output_version":true,"subsequent_output_snapshot_and_custody_audit_required":true}),
        )?;
    }
    let audit_profile = crate::profile::Span::new("frozen_evidence_consistency");
    let raw_frontier = fs::read(&frontier_path)?;
    let audit = frontier::audit_bytes(&raw_frontier, &request.run_id, &broker_identity)
        .map_err(|e| bad(format!("frozen frontier refused: {e:?}")))?;
    if audit.head != frozen.frontier_root()
        || audit.records().len() != 9
        || audit.committed_write_count != 1
    {
        return Err(bad("frozen frontier differs from completion"));
    }
    let raw_custody = fs::read(&journal)?;
    let custody_audit = audit_custody_against_frontier(&raw_custody, &audit, &output_identity)
        .map_err(|e| bad(format!("custody history refused: {e:?}")))?;
    if custody_audit.head != custody_head
        || custody_audit.final_output_digest != digest(&contract.output_bytes)
        || custody_audit.committed_write_count != 1
    {
        return Err(bad("custody seal/history/output differs"));
    }
    let mut bytes = vec![0u8; output_snapshot.metadata()?.len() as usize];
    if bytes.len() != contract.output_bytes.len()
        || output_snapshot.read_at(&mut bytes, 0)? != bytes.len()
        || bytes != contract.output_bytes
        || object(&output_snapshot)? != output_identity
    {
        return Err(bad("frozen read-only output differs from contract"));
    }
    drop(audit_profile);
    record(
        &state,
        "effects-frozen.json",
        &serde_json::json!({"phase":"EFFECTS_FROZEN","challenge":challenge.root(),
        "session_root":session.root(),"completion_root":frozen.root(),"channel_root":frozen.channel_root(),
        "frontier_root":audit.head,"custody_head":custody_head,"journal_digest":digest(&raw_frontier)}),
    )?;
    // The custody backing inode is private staging, never a member of S0.
    // Materialize only its already-sealed bytes into the detached S1 image.
    let final_world_profile = crate::profile::Span::new("final_world_materialization_observation");
    let final_image = state.join("broker-final.ext4");
    let copied = fs::copy(&supervisor.starting_workspace_image, &final_image)?;
    crate::profile::bytes(
        "final_world_materialization_observation",
        "copied_logical",
        copied,
    );
    let sealed_output = state.join("sealed-output");
    fs::write(&sealed_output, &bytes)?;
    fs::set_permissions(&sealed_output, fs::Permissions::from_mode(0o400))?;
    File::open(&sealed_output)?.sync_all_traced()?;
    if sealed_output.to_string_lossy().contains(['"', '\n', '\r']) {
        return Err(bad(
            "unsupported state path for detached image materialization",
        ));
    }
    debugfs(
        &final_image,
        &format!(
            "write \"{}\" {}",
            sealed_output.display(),
            contract.output_path
        ),
    )?;
    debugfs(
        &final_image,
        &format!("set_inode_field {} mode 0x8180", contract.output_path),
    )?;
    fs::set_permissions(&final_image, fs::Permissions::from_mode(0o400))?;
    File::open(&final_image)?.sync_all_traced()?;
    let after = crate::supervisor::scan_detached_workspace(&final_image, &state, "broker-final")
        .map_err(bad)?;
    let changes = filesystem_world::delta(&before, &after);
    if changes
        != vec![FilesystemChange::Create {
            path: contract.output_path.clone(),
            object: FilesystemObject::File {
                content_blake3: digest(&contract.output_bytes),
                mode: 0o600,
            },
        }]
        || after.entries.len() != 2
    {
        return Err(bad("S1/delta exceeds the frozen create-output contract"));
    }
    drop(final_world_profile);
    let closure_profile = crate::profile::Span::new("production_closure");
    let process = child.wait_clean(Duration::from_secs(10)).map_err(bad)?;
    let custody_root = digest(
        &serde_json::to_vec(&(
            "realm.closed-custody/v1",
            &request.run_id,
            &process,
            &custodian_binary,
            &custody_audit.head,
            digest(&raw_custody),
            &audit.head,
            &output_identity,
            digest(&bytes),
        ))
        .map_err(bad)?,
    );
    let closed_custody = ClosedCustodian {
        run_id: request.run_id.clone(),
        process,
        frontier_root: audit.head.clone(),
        journal_root: custody_audit.head,
        root: custody_root,
    };
    let production = live.retire(&frozen).map_err(bad)?;
    let kernel = live
        .cgroup()
        .kill_and_observe(live.pinned_vmm(), 1, 0, Duration::from_secs(5))
        .map_err(bad)?;
    let (receipt, semantic) = semantic_join(
        &request.run_id,
        production.vmm().pid(),
        production.vmm().start_time_ticks(),
        &before.root,
        launch,
        &session,
        &audit,
        &input_identity,
        &output_identity,
        actual_input,
        bytes.clone(),
        contract.input_mode,
        kernel.raw_evidence_root(),
    )?;
    record(&state, "semantic-v2-receipt.json", &receipt)?;
    let capsule_id = digest(format!("{}:{execution}:capsule", request.run_id).as_bytes());
    let closure = run_closure::issue_production(
        &production,
        &frozen,
        &semantic,
        &closed_custody,
        &capsule_id,
        kernel,
    )
    .map_err(bad)?;
    let closure_root = digest(&serde_json::to_vec(&closure).map_err(bad)?);
    drop(closure_profile);
    let snapshot_root = digest(
        &serde_json::to_vec(&(
            "realm.frozen-effect-world/v1",
            frozen.root(),
            FileIdentity::measure(&supervisor.starting_workspace_image)
                .map_err(|e| bad(format!("S0 pin refused: {e:?}")))?,
            FileIdentity::measure(&final_image)
                .map_err(|e| bad(format!("S1 pin refused: {e:?}")))?,
            &before.root,
            &after.root,
        ))
        .map_err(bad)?,
    );
    let delta_root = digest(&serde_json::to_vec(&changes).map_err(bad)?);
    let mut facts = CapsuleFacts {
        run_id: request.run_id.clone(),
        execution_id: execution.into(),
        backend: BackendKind::FirecrackerMeasured,
        workspace_identity: before.root.clone(),
        capsule_id,
        custody_process_identity: Some(closed_custody.process.root().into()),
        descendants: vec![],
        starting_world: before.root.clone(),
        final_world: Some(after.root.clone()),
        observed_effects: vec![contract.output_path.clone()],
        // The guest protocol closed and the host observed VMM shutdown.
        // No guest process exit code was observed.
        exit_code: None,
        crashed: false,
        quiescence: CheckResult::Verified,
        monitor_loss: CheckResult::Verified,
        network: CheckResult::Verified,
        filesystem: CheckResult::Verified,
        frozen: CheckResult::Verified,
        evidence_root: None,
        sequence_start: 0,
        sequence_end: Some(1),
        unsupported_effects: vec![],
        runtime_identity: production.runtime_identity().into(),
        network_policy_identity: production.network_policy_blake3(),
        completion_evidence: challenge.root().into(),
        finalization_evidence: closure_root.clone(),
        pause_snapshot_evidence: snapshot_root,
        vmm_terminal_observation_root: Some(closure_root),
        delta_root,
    };
    facts.evidence_root = Some(evidence_binding_root(&facts));
    let observation =
        CapsuleObservation::from_host_facts(facts, production.production_launch_root())
            .map_err(|e| bad(format!("host facts refused: {e:?}")))?;
    record(&state, "closure-proof.json", &closure)?;
    record(&state, "capsule-facts.json", observation.facts())?;
    record(
        &state,
        "worlds.json",
        &serde_json::json!({"contract":contract,
        "before":before,"after":after,"delta":changes,"custody_process":closed_custody.process,"custody_root":closed_custody.root}),
    )?;
    Ok(ProductionRun {
        production,
        session,
        frozen,
        semantic,
        closure,
        observation,
        before,
        after,
        final_image,
        state,
    })
}

#[allow(clippy::too_many_arguments)]
fn semantic_join(
    run: &str,
    pid: u32,
    birth: u64,
    parent: &str,
    launch: v2::Launch,
    session: &MediationSessionBinding,
    audit: &frontier::FrontierAudit,
    input: &ObjectIdentity,
    output: &ObjectIdentity,
    input_bytes: Vec<u8>,
    output_bytes: Vec<u8>,
    input_mode: u32,
    shutdown_observation_root: &str,
) -> Result<(v2::Receipt, JoinedEvidence), ExecuteError> {
    let _profile = crate::profile::Span::new("semantic_verification");
    let i = format!("input-{}-{}", input.device, input.inode);
    let o = format!("output-{}-{}", output.device, output.inode);
    let initial = std::collections::BTreeMap::from([
        (
            "input".into(),
            v2::Object {
                incarnation: i.clone(),
                version: 0,
                bytes: input_bytes.clone(),
                mode: input_mode,
            },
        ),
        (
            "output".into(),
            v2::Object {
                incarnation: o.clone(),
                version: 0,
                bytes: vec![],
                mode: 0o600,
            },
        ),
    ]);
    let process = format!("vmm-{pid}-{birth}");
    let epoch = "effects-frozen-v1".to_owned();
    let input_length = input_bytes.len() as u64;
    let output_length = output_bytes.len() as u64;
    let actions = vec![
        Action::Start { parent: None },
        Action::Open {
            fd: 0,
            handle: "input".into(),
            path: "input".into(),
            incarnation: i.clone(),
            access: Access::Read,
        },
        Action::Read {
            fd: 0,
            handle: "input".into(),
            incarnation: i,
            version: 0,
            offset: 0,
            requested: 128,
            returned: input_bytes,
            returned_length: input_length,
            end: if input_length == 128 {
                ReadEnd::Complete
            } else {
                ReadEnd::Eof
            },
        },
        Action::Close {
            fd: 0,
            handle: "input".into(),
        },
        Action::Open {
            fd: 1,
            handle: "output".into(),
            path: "output".into(),
            incarnation: o.clone(),
            access: Access::Write,
        },
        Action::Write {
            fd: 1,
            handle: "output".into(),
            incarnation: o.clone(),
            before_version: 0,
            after_version: u64::from(output_length > 0),
            offset: 0,
            requested: output_bytes.clone(),
            returned_length: output_length,
        },
        Action::Close {
            fd: 1,
            handle: "output".into(),
        },
        Action::Poweroff {
            observation_root: shutdown_observation_root.into(),
        },
        Action::Terminal,
    ];
    let events = actions
        .into_iter()
        .enumerate()
        .map(|(n, action)| v2::Event {
            sequence: n as u64,
            run: run.into(),
            process: process.clone(),
            epoch: epoch.clone(),
            action,
        })
        .collect();
    let mut final_world = initial.clone();
    final_world.insert(
        "output".into(),
        v2::Object {
            incarnation: o,
            version: u64::from(output_length > 0),
            bytes: output_bytes,
            mode: 0o600,
        },
    );
    let mut receipt = v2::Receipt {
        format: 2,
        run: run.into(),
        authority_parent: parent.into(),
        launch: launch.clone(),
        directories: Default::default(),
        initial: initial.clone(),
        events,
        dependencies: vec![],
        final_world,
        health: v2::Health {
            epoch: epoch.clone(),
            source_count: audit.records().len() as u64,
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
        v2::derive(&receipt).map_err(|e| bad(format!("semantic derivation refused: {e:?}")))?;
    v2::seal(&mut receipt).map_err(|e| bad(format!("semantic seal refused: {e:?}")))?;
    let expected = v2::ExpectedContext {
        run: run.into(),
        process,
        epoch: epoch.clone(),
        authority_parent: parent.into(),
        launch: launch.clone(),
        directories: Default::default(),
        initial,
        source_count: audit.records().len() as u64,
        source_root: receipt.evidence_root.clone(),
    };
    let context = JoinContext {
        head: audit.head.clone(),
        monitor_id: session.broker_identity().into(),
        manifest_root: session.root().into(),
        launch_identity: digest(&serde_json::to_vec(&launch).map_err(bad)?),
        starting_generation: parent.into(),
        freeze_epoch: epoch,
        input: input.clone(),
        output: output.clone(),
    };
    let joined = integration::join(
        audit,
        &v2::Input {
            receipt: receipt.clone(),
            expected,
        },
        &context,
    )
    .map_err(|e| bad(format!("semantic/frontier verification refused: {e:?}")))?;
    Ok((receipt, joined))
}

pub(crate) fn audit_real_foreign_joins(
    a: &ProductionRun,
    b: &ProductionRun,
) -> Result<serde_json::Value, ExecuteError> {
    fn claim(r: &ProductionRun) -> Result<crate::mediation::CheckedMediationClaim, ExecuteError> {
        let facts = r.observation.facts();
        let manifest = crate::execute::c1_manifest(
            r.production.run_id(),
            &r.before.root,
            &r.after.root,
            facts.delta_root(),
            &r.production,
        )?;
        crate::mediation::CheckedMediationClaim::issue_for_production_session(
            &manifest,
            &digest(&manifest),
            &r.observation,
            &r.session,
            &r.frozen,
            &r.production,
        )
        .map_err(|e| bad(format!("positive production claim refused: {e:?}")))
    }
    let ca = claim(a)?;
    let cb = claim(b)?;
    a.semantic
        .checked_same_run(&ca, &a.observation, &a.production, &a.closure)
        .map_err(|e| bad(format!("positive A join refused: {e:?}")))?;
    b.semantic
        .checked_same_run(&cb, &b.observation, &b.production, &b.closure)
        .map_err(|e| bad(format!("positive B join refused: {e:?}")))?;
    let mut cases = Vec::new();
    macro_rules! refused {($name:literal,$expression:expr)=>{{
        let result=$expression;
        if result.is_ok(){return Err(bad(concat!("FALSE_ACCEPT qualification: ",$name)));}
        cases.push(serde_json::json!({"case":$name,"classification":"INVALID_REFUSED","diagnostic":format!("{:?}",result.err().unwrap()),"boundary":"live typed production join"}));
    }}}
    let fa = a.observation.facts();
    let manifest = crate::execute::c1_manifest(
        a.production.run_id(),
        &a.before.root,
        &a.after.root,
        fa.delta_root(),
        &a.production,
    )?;
    let mr = digest(&manifest);
    refused!(
        "foreign_production_launch",
        crate::mediation::CheckedMediationClaim::issue_for_production_session(
            &manifest,
            &mr,
            &a.observation,
            &a.session,
            &a.frozen,
            &b.production
        )
    );
    refused!(
        "foreign_broker_completion_frontier",
        crate::mediation::CheckedMediationClaim::issue_for_production_session(
            &manifest,
            &mr,
            &a.observation,
            &a.session,
            &b.frozen,
            &a.production
        )
    );
    refused!(
        "foreign_broker_session",
        crate::mediation::CheckedMediationClaim::issue_for_production_session(
            &manifest,
            &mr,
            &a.observation,
            &b.session,
            &a.frozen,
            &a.production
        )
    );
    refused!(
        "foreign_observation",
        crate::mediation::CheckedMediationClaim::issue_for_production_session(
            &manifest,
            &mr,
            &b.observation,
            &a.session,
            &a.frozen,
            &a.production
        )
    );
    refused!(
        "foreign_semantic_result",
        b.semantic
            .checked_same_run(&ca, &a.observation, &a.production, &a.closure)
    );
    refused!(
        "foreign_closure",
        a.semantic
            .checked_same_run(&ca, &a.observation, &a.production, &b.closure)
    );
    refused!(
        "foreign_checked_claim",
        a.semantic
            .checked_same_run(&cb, &a.observation, &a.production, &a.closure)
    );
    refused!(
        "foreign_launch_at_same_run_join",
        a.semantic
            .checked_same_run(&ca, &a.observation, &b.production, &a.closure)
    );
    let raw = fs::read(
        a.state
            .join(format!("{}.frontier.jsonl", a.production.run_id())),
    )?;
    let monitor = a.production.firecracker_identity().blake3();
    frontier::audit_bytes(&raw, a.production.run_id(), monitor)
        .map_err(|e| bad(format!("positive raw frontier refused: {e:?}")))?;
    let lines = raw.split_inclusive(|b| *b == b'\n').collect::<Vec<_>>();
    let mut missing = lines.clone();
    missing.remove(4);
    let mut duplicated = lines.clone();
    duplicated.insert(5, lines[4]);
    let mut reordered = lines.clone();
    reordered.swap(4, 5);
    for (name, data) in [
        ("missing_required_effect", missing.concat()),
        ("duplicated_effect", duplicated.concat()),
        ("reordered_effect", reordered.concat()),
        ("frontier_truncated", raw[..raw.len() - 1].to_vec()),
    ] {
        let result = frontier::audit_bytes(&data, a.production.run_id(), monitor);
        if result.is_ok() {
            return Err(bad(format!("FALSE_ACCEPT qualification: {name}")));
        }
        cases.push(serde_json::json!({"case":name,"classification":"INVALID_REFUSED","diagnostic":format!("{:?}",result.err().unwrap()),"boundary":"real positive frontier audit"}));
    }
    Ok(
        serde_json::json!({"schema":"realm.v6.real-production-join-qualification/v1","public_accept":false,"positive_live_joins":2,"cases":cases,"first_run":a.production.run_id(),"second_run":b.production.run_id(),"first_state":a.state,"second_state":b.state}),
    )
}
