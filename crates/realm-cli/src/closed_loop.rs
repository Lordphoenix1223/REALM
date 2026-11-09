//! Human-facing closed loop over the canonical V6 production APIs. No host
//! agent tools and no VM fallback are started by this client.
use realm_artifact::{
    ArtifactBundle,
    host_apply::{self, ArtifactPermit, TransferProof},
    lifecycle,
};
use realm_v6::c0_contract::C0FileContract;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskDraft {
    schema_version: u16,
    description: String,
    semantics: String,
    contract: C0FileContract,
    forbidden: Vec<String>,
}
impl TaskDraft {
    fn identity(&self) -> Result<String> {
        Ok(realm_artifact::hash("realm.task-draft.v1", &serde_json::to_vec(self)?).value)
    }
    fn validate(&self) -> Result<()> {
        self.contract.validate()?;
        if self.schema_version != 1
            || self.description.is_empty()
            || self.description.len() > 4096
            || self.semantics != "c0-xor-0x20-one-fresh-file-v1"
            || self.forbidden
                != [
                    "overwrite",
                    "delete",
                    "shell",
                    "network",
                    "additional-files",
                ]
        {
            return Err("REFUSE: unsupported task contract".into());
        }
        Ok(())
    }
}
fn input_path(p: &str) -> Result<std::path::PathBuf> {
    let p = Path::new(p);
    Ok(if p.is_absolute() {
        p.to_owned()
    } else {
        std::env::current_dir()?.join(p)
    })
}
fn read(p: &str) -> Result<Vec<u8>> {
    Ok(host_apply::read_transfer_file(&input_path(p)?)?)
}
fn json<T: serde::de::DeserializeOwned>(p: &str) -> Result<T> {
    Ok(host_apply::coding_transfer::strict_json(&read(p)?)?)
}
fn write_once(p: &Path, b: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)?;
    f.write_all(b)?;
    f.sync_all()?;
    fs::File::open(p.parent().ok_or("missing output parent")?)?.sync_all()?;
    Ok(())
}
fn checked(a: &str, p: &str, t: &str) -> Result<host_apply::VerifiedDelta> {
    let proof: TransferProof = json(p)?;
    let permit: ArtifactPermit = json(t)?;
    Ok(host_apply::verify_transfer(&read(a)?, &proof, &permit)?)
}
const HELP: &str = "REALM closed loop (production C0; coding native join currently refuses)\n\
  realm task preflight\n\
  realm task run-coding-native WORKER_WORLD EVIDENCE TRUST.json --native-referee-launch STATE TASK_SHA WORKER_SHA CUSTODIAN UID GID AUX_FD PYTHON\n\
  realm task draft INPUT OUTPUT_NAME DRAFT.json DESCRIPTION\n\
  realm task inspect DRAFT.json\n\
  realm task run DRAFT BACKEND CUSTODIAN UID GID WORKER_WORLD EVIDENCE --approve TASK_ID\n\
  realm artifact pack-development-coding PAYLOAD.json EXPECTATIONS.json PAYLOAD_BLAKE3 EXPECTATIONS_BLAKE3 FRESH.realm\n\
  realm artifact inspect-development-realm|extract-development-coding FILE.realm ARTIFACT_BLAKE3 EXPECTATIONS.json EXPECTATIONS_BLAKE3\n\
  realm transfer receive-installed HANDLE ARTIFACT ARTIFACT_BLAKE3 EXPECTED_RUN\n\
  realm artifact provision-coding-policy PUBLICATION_HANDLE\n\
  realm artifact preflight-installed-coding GENESIS ADMISSION_JSON ADMISSION_BLAKE3\n\
  realm artifact inspect-development-coding PAYLOAD.json EXPECTATIONS.json PAYLOAD_BLAKE3 EXPECTATIONS_BLAKE3\n\
  realm artifact coding-admission NATIVE_CHECKED_EVIDENCE.json\n\
  realm artifact inspect FILE.realm\n\
  realm artifact inspect-coding FILE.realm EXTERNAL_CODING_POLICY.json\n\
  realm artifact verify-coding FILE.realm PROOF.json EXTERNAL_CODING_POLICY.json\n\
  realm transfer preflight-bound|run-bound OPERATOR_BINDING.json INDEPENDENT_BINDING_BLAKE3\n\
  realm transfer preflight FILE.realm PROOF.json EXTERNAL_CODING_POLICY.json DEST STATE\n\
  realm transfer run|resume FILE.realm PROOF.json EXTERNAL_CODING_POLICY.json DEST STATE --approve APPROVAL_ID\n\
  realm apply progress-coding|verify-coding FILE.realm PROOF.json EXTERNAL_CODING_POLICY.json DEST STATE\n\
  realm artifact export WORKER_WORLD GENESIS_ROOT EXACT_HEAD_ROOT PROOF.json\n\
  realm artifact verify FILE.realm PROOF.json EXTERNAL_PERMIT.json\n\
  realm apply preflight FILE.realm PROOF.json EXTERNAL_PERMIT.json DESTINATION\n\
  realm apply run|resume FILE.realm PROOF.json EXTERNAL_PERMIT.json DESTINATION STATE --approve APPROVAL_ID\n\
  realm apply verify|receipt FILE.realm PROOF.json EXTERNAL_PERMIT.json DESTINATION STATE\n\n\
Trust pins must arrive independently from the authenticated worker/operator.\n\
DESTINATION and STATE must be existing private 0700 directories on one filesystem.\n\
Draft text is context; only the displayed exact byte/mode predicate is verified.\n\
Universal contained coding agents are unavailable; no host-command fallback.";
pub fn run(group: &str, args: &[String]) -> Result<()> {
    match (group, args) {
        (_, []) => println!("{HELP}"),
        (_, [h]) if h == "--help" || h == "help" => println!("{HELP}"),
        #[cfg(feature = "development-executor")]
        (
            "transfer",
            [
                command,
                artifact,
                pin,
                expectations,
                epin,
                procedure_pin,
                destination,
                tail @ ..,
            ],
        ) if command == "plan-development-procedure"
            || command == "apply-development-procedure"
            || command == "verify-development-procedure" =>
        {
            let batch = host_apply::ordered_create::fixtures::verify_development_procedure(
                &read(artifact)?,
                pin,
                &read(expectations)?,
                epin,
                procedure_pin,
            )?;
            let destination = input_path(destination)?;
            let result = match (command.as_str(), tail) {
                ("plan-development-procedure", []) => {
                    let plan = batch.prepare(&destination)?.result;
                    let approval = plan.approval_id()?;
                    let mut value = serde_json::to_value(plan)?;
                    value["approval_id"] = approval.into();
                    value
                }
                ("apply-development-procedure", [state, approval]) => serde_json::to_value(
                    batch
                        .apply(&destination, &input_path(state)?, approval)?
                        .result,
                )?,
                ("verify-development-procedure", [state]) => serde_json::to_value(
                    batch
                        .final_verify(&destination, &input_path(state)?)?
                        .result,
                )?,
                _ => return Err("REFUSE: exact development procedure arguments required".into()),
            };
            println!(
                "{}",
                serde_json::json!({"authority":"NONE", "execution_qualification":"INCOMPLETE",
                "scope":"EXPLICIT_DISPOSABLE_MECHANICS_ONLY", "result":result})
            );
        }
        ("artifact", [c, run]) if c == "provision-coding-policy" => {
            let report = host_apply::installed_coding_policy::provision_installed(run)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ("artifact", [c, payload, expectations, payload_pin, expectations_pin])
            if c == "inspect-development-coding" =>
        {
            let report = host_apply::coding_development::inspect(
                &read(payload)?,
                payload_pin,
                &read(expectations)?,
                expectations_pin,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Err("INCOMPLETE: development evidence has no native execution/publication/application authority".into());
        }
        (
            "artifact",
            [
                c,
                payload,
                expectations,
                payload_pin,
                expectations_pin,
                output,
            ],
        ) if c == "pack-development-coding" => {
            let bytes = host_apply::coding_development::pack_capture(
                &read(payload)?,
                payload_pin,
                &read(expectations)?,
                expectations_pin,
            )?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(output)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            println!(
                "{}",
                serde_json::json!({"authority":"NONE","status":"UNQUALIFIED_DEVELOPMENT_CAPTURE","artifact_blake3":blake3::hash(&bytes).to_hex().to_string()})
            );
        }
        ("artifact", [c, artifact, artifact_pin, expectations, expectations_pin])
            if c == "inspect-development-realm" =>
        {
            let report = host_apply::coding_development::inspect_capture(
                &read(artifact)?,
                artifact_pin,
                &read(expectations)?,
                expectations_pin,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Err("INCOMPLETE: development capture grants no execution/publication/application authority".into());
        }
        ("artifact", [c, artifact, artifact_pin, expectations, expectations_pin])
            if c == "extract-development-coding" =>
        {
            let payload = host_apply::coding_development::capture_payload(
                &read(artifact)?,
                artifact_pin,
                &read(expectations)?,
                expectations_pin,
            )?;
            std::io::stdout().write_all(&payload)?;
        }
        ("task", [c, world, evidence, trust, native @ ..]) if c == "run-coding-native-workflow" => {
            coding_workflow_run(world, evidence, trust, native)?;
        }
        ("task", [c, mode, world, evidence, trust, native @ ..])
            if c == "run-coding-native" && mode == "--publication-only" =>
        {
            coding_worker_run(world, evidence, trust, native, true)?;
        }
        ("task", [c, world, evidence, trust, native @ ..]) if c == "run-coding-native" => {
            coding_worker_run(world, evidence, trust, native, false)?;
        }
        ("task", [c]) if c == "preflight" => {
            println!(
                "Client: {} / {}\nSupported task: C0 XOR-0x20, one input <=128 bytes, one fresh output.\nHost application: create-only, external trust + destination approval required.",
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            #[cfg(not(target_os = "linux"))]
            println!(
                "Worker: REFUSE (Linux/x86_64 KVM required; configure an independently qualified worker).\nNo VM or paid resource was started."
            );
            #[cfg(target_os = "linux")]
            {
                let kvm = OpenOptions::new().read(true).write(true).open("/dev/kvm");
                println!(
                    "Worker KVM device accessible: {}. This is preflight, not containment qualification.",
                    kvm.is_ok()
                );
            }
        }
        ("task", [c, input, output, draft, description]) if c == "draft" => {
            let b = read(input)?;
            if b.len() > 128 {
                return Err("REFUSE: C0 input exceeds 128 bytes".into());
            }
            let m = fs::metadata(input)?.permissions().mode() & 0o7777;
            let spec = TaskDraft {
                schema_version: 1,
                description: description.clone(),
                semantics: "c0-xor-0x20-one-fresh-file-v1".into(),
                contract: C0FileContract {
                    input_bytes: b.clone(),
                    input_mode: m,
                    output_path: output.clone(),
                    output_bytes: b.iter().map(|x| x ^ 0x20).collect(),
                    output_mode: 0o600,
                },
                forbidden: [
                    "overwrite",
                    "delete",
                    "shell",
                    "network",
                    "additional-files",
                ]
                .map(str::to_owned)
                .to_vec(),
            };
            spec.validate()?;
            write_once(Path::new(draft), &serde_json::to_vec_pretty(&spec)?)?;
            describe(&spec)?;
            println!(
                "Draft only. Approve this task ID explicitly on the qualified worker: {}",
                spec.identity()?
            );
        }
        ("task", [c, draft]) if c == "inspect" => {
            let d: TaskDraft = json(draft)?;
            d.validate()?;
            describe(&d)?;
            println!("Task ID: {}", d.identity()?);
        }
        (
            "task",
            [
                c,
                draft,
                backend,
                custodian,
                uid,
                gid,
                world,
                evidence,
                flag,
                approval,
            ],
        ) if c == "run" && flag == "--approve" => {
            let d: TaskDraft = json(draft)?;
            d.validate()?;
            if d.identity()? != *approval {
                return Err("REFUSE: task approval differs from this draft".into());
            }
            worker_run(&d, backend, custodian, uid, gid, world, evidence)?;
        }
        ("artifact", [c, input]) if c == "coding-admission" => {
            let raw = read(input)?;
            let report = match host_apply::coding_transfer::strict_json::<
                realm_v6::execute::CheckedC1Evidence,
            >(&raw)
            {
                Ok(evidence) => realm_v6::integration::coding::inspect_coding_admission(
                    &evidence,
                    &Default::default(),
                ),
                Err(_) => realm_v6::integration::coding::invalid_coding_admission(),
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Err("REFUSE: serialized evidence cannot reconstruct missing native capabilities; inspect admission checks".into());
        }
        ("artifact", [c, a, policy]) if c == "inspect-coding" => {
            let policy = json(policy)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&host_apply::coding_transfer::inspect_content(
                    &read(a)?,
                    &policy,
                    host_apply::coding_transfer::now_unix()?
                )?)?
            );
        }
        ("artifact", [c, a, proof, policy]) if c == "verify-coding" => {
            host_apply::coding_transfer::verify_transfer(&read(a)?, &json(proof)?, &json(policy)?)?;
            println!(
                "Qualified native coding transfer verified; destination approval still required."
            );
        }
        ("artifact", [c, genesis, statement, pin]) if c == "preflight-installed-coding" => {
            let raw = read(statement)?;
            if raw.len() > 256 * 1024 || blake3::hash(&raw).to_hex().as_str() != pin {
                return Err("REFUSE: admission byte bound or raw pin differs".into());
            }
            let value = realm_v6::strict_json::parse(&raw)
                .map_err(|_| "REFUSE: strict runtime admission JSON required")?;
            let envelope: realm_v6::runtime_admission::SignedRuntimeAdmission =
                serde_json::from_value(value)?;
            let report =
                host_apply::installed_coding_policy::preflight_installed(genesis, &envelope)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ("transfer", [c, handle, artifact, pin, run]) if c == "receive-installed" => {
            let report = host_apply::installed_coding_policy::receive_installed(
                handle,
                &read(artifact)?,
                pin,
                run,
            );
            let complete = report.status == "APPLIED_AND_FINAL_VERIFIED";
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !complete {
                return Err(
                    "Installed handoff INCOMPLETE; preserve evidence and dispatch history".into(),
                );
            }
        }
        ("transfer", [c, binding, pin]) if c == "preflight-bound" || c == "run-bound" => {
            let bound =
                host_apply::coding_lifecycle::load_bound_transfer(&input_path(binding)?, pin)?;
            let report = host_apply::coding_lifecycle::receive(
                &bound.artifact,
                &bound.proof,
                &bound.policy,
                &bound.binding.destination,
                &bound.binding.state,
                if c == "run-bound" {
                    Some(&bound.binding.approval_id)
                } else {
                    None
                },
            );
            let expected = if c == "run-bound" {
                "APPLIED_AND_FINAL_VERIFIED"
            } else {
                "PREPARED_REQUIRES_SEPARATE_APPROVAL"
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report.status != expected {
                return Err("Bound transfer incomplete; inspect stage report; preserve original inputs and durable state".into());
            }
        }
        ("transfer", [c, a, proof, policy, dest, state]) if c == "preflight" => {
            let report = host_apply::coding_lifecycle::receive(
                &read(a)?,
                &json(proof)?,
                &json(policy)?,
                Path::new(dest),
                Path::new(state),
                None,
            );
            let prepared = report.status == "PREPARED_REQUIRES_SEPARATE_APPROVAL";
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !prepared {
                return Err(
                    "Transfer not prepared; inspect first non-PASS stage; no fallback".into(),
                );
            }
        }
        ("transfer", [c, a, proof, policy, dest, state, flag, approval])
            if (c == "run" || c == "resume") && flag == "--approve" =>
        {
            let report = host_apply::coding_lifecycle::receive(
                &read(a)?,
                &json(proof)?,
                &json(policy)?,
                Path::new(dest),
                Path::new(state),
                Some(approval),
            );
            let complete = report.status == "APPLIED_AND_FINAL_VERIFIED";
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !complete {
                return Err(
                    "Transfer incomplete; inspect report and durable state before retry".into(),
                );
            }
        }
        ("apply", [c, a, proof, policy, dest, state])
            if c == "progress-coding" || c == "verify-coding" =>
        {
            let v = host_apply::coding_transfer::verify_for_observation(
                &read(a)?,
                &json(proof)?,
                &json(policy)?,
            )?;
            if c == "progress-coding" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&host_apply::ordered_create::progress(
                        &v,
                        Path::new(dest),
                        Path::new(state)
                    )?)?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&host_apply::ordered_create::verify_host(
                        &v,
                        Path::new(dest),
                        Path::new(state)
                    )?)?
                );
            }
        }
        ("artifact", [c, a]) if c == "inspect" => {
            println!("{}", ArtifactBundle::unpack(&read(a)?)?.inspect()?)
        }
        ("artifact", [c, world, genesis, head, out]) if c == "export" => {
            let layout = realm_v6::generation::GenerationLayout::inspect(world)?;
            let trust = lifecycle::LifecycleTrust {
                genesis_root: genesis.clone(),
                previously_trusted_head_root: head.clone(),
            };
            let (genesis, snapshot) = lifecycle::export_verified_lifecycle(&layout, &trust)?;
            let proof = TransferProof {
                schema_version: 1,
                genesis,
                snapshot,
            };
            write_once(Path::new(out), &serde_json::to_vec(&proof)?)?;
            println!(
                "Exported verified lifecycle evidence. This sidecar does not authenticate its worker; preserve the external pins."
            );
        }
        ("artifact", [c, a, p, t]) if c == "verify" => {
            let v = checked(a, p, t)?;
            println!(
                "Verified pinned C0 publication for run {}.\nAuthorized effect: create {} ({} bytes, mode {:04o}).\nNo destination has been changed.",
                v.run_id(),
                v.contract().output_path,
                v.contract().output_bytes.len(),
                v.contract().output_mode
            );
        }
        ("apply", [c, a, p, t, dest]) if c == "preflight" => {
            let v = checked(a, p, t)?;
            let plan = host_apply::preflight(&v, Path::new(dest))?;
            println!(
                "Dry run: create {} ({} bytes, mode {:04o}) in {}.\nInput matches verified baseline; output must remain absent.\nApprove this exact destination-bound ID: {}",
                plan.create_path,
                plan.create_bytes,
                plan.create_mode,
                dest,
                plan.approval_id()?
            );
        }
        ("apply", [c, a, p, t, dest, state, flag, approval])
            if (c == "run" || c == "resume") && flag == "--approve" =>
        {
            let v = checked(a, p, t)?;
            let receipt = host_apply::apply(&v, Path::new(dest), Path::new(state), approval)?;
            println!(
                "HOST FINAL STATE VERIFIED: {}.\nDurable receipt: {state}/receipt.json\nSame journal resumes without repeating the effect; guest acceptance and this host result are separate claims.",
                receipt.operation
            );
        }
        ("apply", [c, a, p, t, dest, state]) if c == "verify" || c == "receipt" => {
            let v = checked(a, p, t)?;
            let receipt = host_apply::verify_host(&v, Path::new(dest), Path::new(state))?;
            println!(
                "HOST FINAL STATE VERIFIED: {}\nArtifact {}\nBoundary: {}",
                receipt.operation, receipt.artifact_blake3, receipt.scope
            );
        }
        _ => return Err(HELP.into()),
    }
    Ok(())
}
fn describe(d: &TaskDraft) -> Result<()> {
    println!(
        "Requested: {}\nVerified predicate: XOR every input byte with 0x20; create {} with exact resulting bytes, mode 0600.\nInput length: {} bytes; mode {:04o}.\nForbidden: overwrite, delete, shell, network, extra files.\nNatural-language intent beyond this predicate is unverified.",
        d.description,
        d.contract.output_path,
        d.contract.input_bytes.len(),
        d.contract.input_mode
    );
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn worker_run(_: &TaskDraft, _: &str, _: &str, _: &str, _: &str, _: &str, _: &str) -> Result<()> {
    Err("REFUSE: production execution requires a qualified Linux/x86_64 KVM worker; no host-command substitute started".into())
}
#[cfg(target_os = "linux")]
fn worker_run(
    d: &TaskDraft,
    backend: &str,
    custodian: &str,
    uid: &str,
    gid: &str,
    world: &str,
    evidence: &str,
) -> Result<()> {
    use realm_v6::{execute, generation};
    let backend: execute::C1BackendInputPaths = json(backend)?;
    let evidence = Path::new(evidence);
    if evidence.starts_with(Path::new(world)) {
        return Err("REFUSE: evidence must be outside task world".into());
    }
    fs::create_dir(evidence)?;
    fs::set_permissions(evidence, fs::Permissions::from_mode(0o700))?;
    write_once(
        &evidence.join("approved-task.json"),
        &serde_json::to_vec_pretty(d)?,
    )?;
    let layout = generation::GenerationLayout::inspect(world)?;
    let before = realm_v6::filesystem_world::scan_directory(Path::new(world))
        .map_err(|e| format!("REFUSE: {e:?}"))?;
    if before.root != d.contract.commitments()?.0 {
        return Err("REFUSE: worker baseline differs from approved task".into());
    }
    let genesis = lifecycle::GenesisAnchor::new(
        layout.workspace_identity(),
        before.root,
        "operator-approved-c0-task",
    );
    let genesis_root = genesis.root()?;
    let head = lifecycle::initialize_lifecycle(&layout, &genesis, &genesis_root)?;
    let trust = lifecycle::LifecycleTrust {
        genesis_root: genesis_root.clone(),
        previously_trusted_head_root: head.authority_root,
    };
    let request = execute::ExecuteRequest {
        run_id: format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ),
        root: Path::new(world).to_owned(),
        command: vec!["c0".into()],
        timeout_ms: 120_000,
        allowed_effects: vec!["filesystem".into()],
        allowed_paths: vec![d.contract.output_path.clone()],
        rootfs: None,
        workspace_device: None,
        guest_supervisor: None,
        firecracker: None,
        kernel: None,
        state_dir: None,
    };
    let outcome = execute::execute_rootfs_brokered_contract(
        &request,
        &d.contract,
        &backend,
        Path::new(custodian),
        uid.parse()?,
        gid.parse()?,
    )?;
    write_once(
        &evidence.join("execution-report.json"),
        &serde_json::to_vec_pretty(&outcome.result)?,
    )?;
    let cap = outcome
        .publication_capability
        .ok_or("REFUSE: no checked publication capability; audit report retained")?;
    let prepared = generation::prepare_candidate(&cap, world)?;
    let published = lifecycle::publish_prepared_generation(prepared, cap, &trust)?;
    let bytes = published.bundle().pack()?;
    write_once(&evidence.join("accepted.realm"), &bytes)?;
    // The exact head is pinned on this trusted worker, never inferred on receipt.
    let result = lifecycle::verify_lifecycle_directory(&layout, &trust);
    if result.state != lifecycle::VerificationState::Valid {
        return Err("REFUSE: publication failed independent reconstruction".into());
    }
    let head_root = result
        .reconstructed_head_root
        .ok_or("missing reconstructed head")?;
    let exact = lifecycle::LifecycleTrust {
        genesis_root: genesis_root.clone(),
        previously_trusted_head_root: head_root.clone(),
    };
    let (genesis, snapshot) = lifecycle::export_verified_lifecycle(&layout, &exact)?;
    let proof = TransferProof {
        schema_version: 1,
        genesis,
        snapshot,
    };
    write_once(
        &evidence.join("transfer-proof.json"),
        &serde_json::to_vec(&proof)?,
    )?;
    let permit = ArtifactPermit {
        schema_version: 1,
        artifact_blake3: blake3::hash(&bytes).to_hex().to_string(),
        genesis_root,
        exact_head_root: head_root,
        contract: d.contract.clone(),
    };
    write_once(
        &evidence.join("worker-permit.json"),
        &serde_json::to_vec_pretty(&permit)?,
    )?;
    host_apply::verify_transfer(&bytes, &proof, &permit)?;
    println!(
        "C0 isolated task accepted and portable artifact reverified.\nArtifact: {}\nTransfer evidence: {}\nExternal trust pins: {} (deliver through an authenticated operator channel)\nDestination has not been changed.",
        evidence.join("accepted.realm").display(),
        evidence.join("transfer-proof.json").display(),
        evidence.join("worker-permit.json").display()
    );
    Ok(())
}

/// Transport consistency only, never an execution/publication capability.
#[cfg(any(target_os = "linux", test))]
fn verify_native_export_artifact(
    artifact: &[u8],
    retained: &std::collections::BTreeMap<String, Vec<u8>>,
    latest: Option<&realm_artifact::Digest>,
) -> Result<()> {
    let lifecycle_digest = realm_artifact::hash("realm.v6-lifecycle-artifact", artifact);
    if retained.get(&lifecycle_digest.value).map(Vec::as_slice) != Some(artifact)
        || latest != Some(&lifecycle_digest)
    {
        return Err("REFUSE: coding publication advanced or exported artifact differs".into());
    }
    Ok(())
}

/// Use the same native executor as the diagnostic probe; keep its owners in
/// this process through the existing issuer and canonical lifecycle publisher.
#[cfg(target_os = "linux")]
fn coding_worker_run(
    world: &str,
    evidence: &str,
    trust: &str,
    native: &[String],
    publication_only: bool,
) -> Result<()> {
    use realm_v6::{coding_runtime, generation};
    if native.first().map(String::as_str) != Some("--native-referee-launch") {
        return Err("REFUSE: native-owned referee launch required".into());
    }
    let native = &native[1..];
    let (admission, statement, native) = match native {
        [flag, rest @ ..] if flag == "--installed-runtime-admission" => {
            let envelope =
                realm_v6::runtime_admission::issue_installed_admission().map_err(|error| {
                    format!("INCOMPLETE: installed runtime admission unavailable: {error}")
                })?;
            (
                realm_v6::coding_provenance::preflight_with_admission(&envelope)?,
                envelope,
                rest,
            )
        }
        [flag, path, pin, rest @ ..] if flag == "--runtime-admission" => {
            let bytes = read(path)?;
            if bytes.len() > 256 * 1024 || blake3::hash(&bytes).to_hex().as_str() != pin {
                return Err("REFUSE: runtime admission raw pin or bound differs".into());
            }
            let value = realm_v6::strict_json::parse(&bytes)
                .map_err(|_| "REFUSE: strict runtime admission JSON required")?;
            let envelope: realm_v6::runtime_admission::SignedRuntimeAdmission =
                serde_json::from_value(value)?;
            (
                realm_v6::coding_provenance::preflight_with_admission(&envelope)?,
                envelope,
                rest,
            )
        }
        _ => {
            realm_v6::coding_provenance::preflight()?;
            return Err("REFUSE: setup-provisioned runtime admission required".into());
        }
    };
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TrustPins {
        genesis_root: String,
        previously_trusted_head_root: String,
    }
    let pins: TrustPins = json(trust)?;
    let trust = lifecycle::LifecycleTrust {
        genesis_root: pins.genesis_root,
        previously_trusted_head_root: pins.previously_trusted_head_root,
    };
    let evidence = input_path(evidence)?;
    let metadata = fs::symlink_metadata(&evidence)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err("REFUSE: existing private evidence directory required".into());
    }
    let setup =
        host_apply::installed_coding_policy::preflight_installed(&trust.genesis_root, &statement)?;
    write_once(
        &evidence.join("installed-setup-preflight.json"),
        &serde_json::to_vec_pretty(&setup)?,
    )?;
    let _layout = generation::GenerationLayout::inspect(world)?;
    let mut args = vec!["realm-native".into(), "--native-referee-launch".into()];
    args.extend_from_slice(native);
    let mut run = coding_runtime::run_native_retirement_with_admission(&args, admission)?;
    write_once(
        &evidence.join("native-retirement.json"),
        &serde_json::to_vec_pretty(&run.retired.record())?,
    )?;
    let referee = run.referee.ok_or("REFUSE: missing native-owned referee")?;
    write_once(
        &evidence.join("native-referee.json"),
        &serde_json::to_vec_pretty(referee.diagnostic())?,
    )?;
    let provenance = run.retired.require_coding_provenance()?;
    let cap = run.retired.finalize_coding(referee, provenance)?;
    let terminal = publish_native_capability(cap, world, &evidence, &trust, publication_only)?;
    println!("{}", serde_json::to_string(&terminal)?);
    Ok(())
}
#[cfg(target_os = "linux")]
fn publish_native_capability(
    cap: realm_v6::execute::CheckedExecutionForPublication,
    world: &str,
    evidence: &Path,
    trust: &lifecycle::LifecycleTrust,
    publication_only: bool,
) -> Result<serde_json::Value> {
    let layout = realm_v6::generation::GenerationLayout::inspect(world)?;
    let checked = cap.checked_c1_evidence();
    write_once(
        &evidence.join("checked-c1-evidence.json"),
        &serde_json::to_vec_pretty(&checked)?,
    )?;
    let prepared = realm_v6::generation::prepare_candidate(&cap, world)?;
    let published = lifecycle::publish_prepared_generation(prepared, cap, trust)?;
    let artifact = published.bundle().pack()?;
    write_once(&evidence.join("accepted.realm"), &artifact)?;
    let verified = lifecycle::verify_lifecycle_directory(&layout, trust);
    if verified.state != lifecycle::VerificationState::Valid {
        return Err("REFUSE: canonical publication reconstruction failed".into());
    }
    // Pin the reconstructed worker head before exporting. A retained parent
    // proves ancestry but cannot select the exact publication at the receiver.
    let exact = lifecycle::LifecycleTrust {
        genesis_root: trust.genesis_root.clone(),
        previously_trusted_head_root: verified
            .reconstructed_head_root
            .clone()
            .ok_or("REFUSE: canonical publication head missing")?,
    };
    let (genesis, snapshot) = lifecycle::export_verified_lifecycle(&layout, &exact)?;
    let artifact_pin = blake3::hash(&artifact).to_hex().to_string();
    verify_native_export_artifact(
        &artifact,
        &snapshot.artifacts,
        snapshot.transitions.last().map(|t| &t.artifact_digest),
    )?;
    let proof = TransferProof {
        schema_version: 1,
        genesis,
        snapshot,
    };
    let proof_bytes = serde_json::to_vec(&proof)?;
    write_once(&evidence.join("transfer-proof.json"), &proof_bytes)?;
    let coding = checked
        .coding
        .as_ref()
        .ok_or("REFUSE: coding publication data missing")?;
    let receipt = coding
        .semantic_evidence
        .as_ref()
        .ok_or("REFUSE: coding semantic receipt missing")?;
    let qualification = receipt
        .runtime_qualification
        .as_ref()
        .ok_or("REFUSE: coding runtime qualification missing")?;
    // This transport record is not a destination policy or an approval. A
    // receiver must obtain its trust pins and admission through protected setup.
    let mut handoff = serde_json::json!({
        "schema": "realm.native-coding-publication-handoff.v1",
        "authority": "NONE: transport record; independent receiver trust required",
        "run_id": checked.run_id,
        "execution_id": checked.execution_id,
        "artifact_blake3": artifact_pin,
        "transfer_proof_blake3": blake3::hash(&proof_bytes).to_hex().to_string(),
        "genesis_root": exact.genesis_root,
        "exact_head_root": exact.previously_trusted_head_root,
        "semantic_root": published.bundle().semantic_identity()?.value,
        "contract": coding.contract,
        "runtime_admission": qualification.admission,
        "runtime_admission_id": qualification.admission_identity,
        "destination_policy": null,
        "approval_id": null,
        "application_dispatched": false
    });
    if let Some(history) = &coding
        .semantic_evidence
        .as_ref()
        .ok_or("missing semantic receipt")?
        .workflow
    {
        let prior_admissions = history
            .prior
            .iter()
            .map(|r| {
                r.evidence
                    .runtime_qualification
                    .as_ref()
                    .map(|q| q.admission.clone())
                    .ok_or("original attempt qualification missing")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        handoff["workflow_trust"] =
            serde_json::to_value(host_apply::coding_qualification::NativeWorkflowTrust {
                workflow: history.workflow.clone(),
                prior_admissions,
            })?;
    }
    write_once(
        &evidence.join("publication-handoff.json"),
        &serde_json::to_vec_pretty(&handoff)?,
    )?;
    // Publish first, then independently authorize receiving under protected
    // setup. A VALID publication is never an application authorization.
    let handle = evidence
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("REFUSE: publication evidence needs a storage handle")?;
    let application = native_application_handoff(publication_only, || {
        Ok(serde_json::to_value(
            host_apply::installed_coding_policy::receive_installed(
                handle,
                &artifact,
                &artifact_pin,
                &checked.run_id,
            ),
        )?)
    })?;
    write_once(
        &evidence.join("application-handoff-result.json"),
        &serde_json::to_vec_pretty(&application)?,
    )?;
    let complete = publication_only || application["status"] == "APPLIED_AND_FINAL_VERIFIED";
    let mut terminal = serde_json::to_value(&verified)?;
    terminal["application_handoff"] = serde_json::to_value(&application)?;
    if !complete {
        return Err(
            "INCOMPLETE: publication retained; protected application did not complete".into(),
        );
    }
    Ok(terminal)
}
#[cfg(not(target_os = "linux"))]
fn coding_worker_run(_: &str, _: &str, _: &str, _: &[String], _: bool) -> Result<()> {
    Err("REFUSE_UNVERIFIED_BOUNDARY: qualified Linux/x86_64 native coding runtime required".into())
}

#[cfg(target_os = "linux")]
fn coding_workflow_run(world: &str, evidence: &str, trust: &str, native: &[String]) -> Result<()> {
    if native.first().map(String::as_str) != Some("--retain-native-attempts") {
        return Err("existing persistent native keeper required".into());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Pins {
        genesis_root: String,
        previously_trusted_head_root: String,
    }
    let pins: Pins = json(trust)?;
    let trust = lifecycle::LifecycleTrust {
        genesis_root: pins.genesis_root,
        previously_trusted_head_root: pins.previously_trusted_head_root,
    };
    let evidence = input_path(evidence)?;
    let m = fs::symlink_metadata(&evidence)?;
    if !m.is_dir() || m.permissions().mode() & 0o7777 != 0o700 {
        return Err("private original workflow evidence directory required".into());
    }
    let mut args = vec!["realm-native".to_owned()];
    args.extend_from_slice(native);
    realm_v6::coding_runtime::attempt_history::run_retained_with_publisher(&args, |cap| {
        publish_native_capability(cap, world, &evidence, &trust, true)
    })
}
#[cfg(not(target_os = "linux"))]
fn coding_workflow_run(_: &str, _: &str, _: &str, _: &[String]) -> Result<()> {
    Err("native keeper requires Linux; no development fallback".into())
}

// Only transport disposition: this value is neither a native receipt nor an
// application capability. The qualified issuer and publication run unchanged.
#[cfg(any(target_os = "linux", test))]
fn native_application_handoff(
    publication_only: bool,
    apply: impl FnOnce() -> Result<serde_json::Value>,
) -> Result<serde_json::Value> {
    if publication_only {
        return Ok(serde_json::json!({
            "status": "NOT_RUN",
            "application_authorization": "NONE",
            "application_dispatched": false,
            "receiver_profile": "realm.stage8.ordered-create.v1",
            "reason": "INDEPENDENT_STAGE8_AUTHORIZATION_REQUIRED"
        }));
    }
    apply()
}

#[cfg(test)]
mod native_export_tests {
    use super::*;

    #[test]
    fn publication_only_never_invokes_installed_application() {
        let report = native_application_handoff(true, || panic!("application dispatched")).unwrap();
        assert_eq!(report["status"], "NOT_RUN");
        assert_eq!(report["application_authorization"], "NONE");
        assert_eq!(report["application_dispatched"], false);
        assert_eq!(report["receiver_profile"], "realm.stage8.ordered-create.v1");
        assert!(
            native_application_handoff(false, || Err("actual receiver refusal".into())).is_err()
        );
        let actual = serde_json::json!({"status":"APPLIED_AND_FINAL_VERIFIED"});
        assert_eq!(
            native_application_handoff(false, || Ok(actual.clone())).unwrap(),
            actual
        );
    }

    #[test]
    fn lifecycle_export_digest_is_distinct_from_receiver_raw_pin() {
        let bytes = b"non-authorizing transport consistency test";
        let domain = realm_artifact::hash("realm.v6-lifecycle-artifact", bytes);
        let raw = realm_artifact::Digest {
            algorithm: domain.algorithm.clone(),
            domain: domain.domain.clone(),
            value: blake3::hash(bytes).to_hex().to_string(),
        };
        assert_ne!(domain.value, raw.value);
        let retained = std::collections::BTreeMap::from([(domain.value.clone(), bytes.to_vec())]);
        assert!(verify_native_export_artifact(bytes, &retained, Some(&domain)).is_ok());
        // The original bug used the raw receiver pin in this lifecycle index.
        let raw_index = std::collections::BTreeMap::from([(raw.value.clone(), bytes.to_vec())]);
        assert!(verify_native_export_artifact(bytes, &raw_index, Some(&raw)).is_err());
        assert!(verify_native_export_artifact(bytes, &retained, Some(&raw)).is_err());
        assert!(
            verify_native_export_artifact(b"substituted bytes", &retained, Some(&domain)).is_err()
        );
        assert!(verify_native_export_artifact(bytes, &retained, None).is_err());
    }
}
