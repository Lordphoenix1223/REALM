// Thin CLI for the canonical production execution and durable publisher.
// Test-support builds cannot emit a public ACCEPT.
#[cfg(all(target_os = "linux", not(feature = "test-support")))]
mod production {
    use realm_artifact::{ArtifactBundle, ValidationLevel, lifecycle};
    use realm_v6::profile::SyncTrace as _;
    use realm_v6::{
        execute::{C1BackendInputPaths, ExecuteRequest, execute_rootfs_brokered},
        filesystem_world,
        generation::{GenerationLayout, prepare_candidate},
    };
    use std::{
        fs::{self, File, OpenOptions},
        io::Write,
        os::unix::fs::OpenOptionsExt,
        path::Path,
    };
    fn save(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all_traced()?;
        File::open(path.parent().ok_or("missing parent")?)?.sync_all_traced()?;
        Ok(())
    }
    // Qualification-only scheduling barrier. It grants no authority and all
    // destination-lock, S0, durability and authority-head checks follow it.
    fn publication_barrier(
        evidence: &Path,
        destination: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(path) = std::env::var_os("REALM_V6_PUBLICATION_BARRIER") else {
            return Ok(());
        };
        let path = std::path::PathBuf::from(path);
        let parent = path
            .parent()
            .ok_or("barrier lacks parent")?
            .canonicalize()?;
        if parent.starts_with(destination.canonicalize()?) {
            return Err("barrier inside supported world".into());
        }
        save(
            &evidence.join("candidate-ready.json"),
            br#"{"phase":"CHECKED_FOR_PUBLICATION","authority":false}"#,
        )?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            match realm_v6::measured_launch::FileIdentity::measure(&path) {
                Ok(pin) => {
                    if !pin.trusted_parent_chain()
                        || pin.owner_uid() != 0
                        || pin.mode() != 0o600
                        || fs::read(&path)? != b"REALM-RELEASE-CHECKED-CANDIDATES-V1\n"
                    {
                        return Err("untrusted qualification barrier".into());
                    }
                    break;
                }
                Err(_) if !path.exists() && std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                Err(_) => return Err("qualification barrier failed or timed out".into()),
            }
        }
        Ok(())
    }
    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let a = std::env::args().collect::<Vec<_>>();
        if a.len() == 9 && a[1] == "qualify-joins" {
            let first: ExecuteRequest = serde_json::from_slice(&fs::read(&a[2])?)?;
            let second: ExecuteRequest = serde_json::from_slice(&fs::read(&a[3])?)?;
            let backend: C1BackendInputPaths = serde_json::from_slice(&fs::read(&a[4])?)?;
            let output_parent = Path::new(&a[8])
                .parent()
                .ok_or("qualification output lacks parent")?
                .canonicalize()?;
            if output_parent.starts_with(first.root.canonicalize()?)
                || output_parent.starts_with(second.root.canonicalize()?)
            {
                return Err("qualification output inside supported world".into());
            }
            let result = realm_v6::execute::qualify_real_production_joins(
                &first,
                &second,
                &backend,
                Path::new(&a[5]),
                a[6].parse()?,
                a[7].parse()?,
            )?;
            save(Path::new(&a[8]), &serde_json::to_vec_pretty(&result)?)?;
            println!("{}", serde_json::to_string(&result)?);
            return Ok(());
        }
        if a.len() == 4 && a[1] == "init" {
            let destination = Path::new(&a[2]);
            let evidence = Path::new(&a[3]).canonicalize()?;
            if evidence.starts_with(destination.canonicalize()?) {
                return Err("evidence is inside task world".into());
            }
            let layout = GenerationLayout::inspect(destination)?;
            let world = filesystem_world::scan_directory(destination)
                .map_err(|e| format!("genesis scan refused: {e:?}"))?;
            let anchor = lifecycle::GenesisAnchor::new(
                layout.workspace_identity(),
                world.root,
                "operator-selected-c0-genesis",
            );
            let root = anchor.root()?;
            let head = lifecycle::initialize_lifecycle(&layout, &anchor, &root)?;
            save(
                &evidence.join("genesis-anchor.json"),
                &serde_json::to_vec_pretty(&anchor)?,
            )?;
            save(
                &evidence.join("operator-pins.json"),
                &serde_json::to_vec_pretty(
                    &serde_json::json!({"genesis_root":root,"previously_trusted_head_root":head.authority_root}),
                )?,
            )?;
            return Ok(());
        }
        if !(a.len() == 11 && a[1] == "run" || a.len() == 12 && a[1] == "run-contract") {
            return Err("usage: init DEST EVIDENCE | run REQUEST BACKEND CUSTODIAN UID GID DEST EVIDENCE GENESIS_ROOT HEAD_ROOT".into());
        }
        let request: ExecuteRequest = serde_json::from_slice(&fs::read(&a[2])?)?;
        let backend: C1BackendInputPaths = serde_json::from_slice(&fs::read(&a[3])?)?;
        let destination = Path::new(&a[7]);
        let evidence = Path::new(&a[8]).canonicalize()?;
        if evidence.starts_with(destination.canonicalize()?) {
            return Err("evidence is inside task world".into());
        }
        if std::env::var_os("REALM_V6_PROFILE").is_some()
            && let Err(e) = realm_v6::profile::initialize(&evidence)
        {
            eprintln!("profile unavailable: {e}");
        }
        let _pipeline_profile = realm_v6::profile::Span::new("accept_end_to_end");
        let layout = GenerationLayout::inspect(destination)?;
        let trust = lifecycle::LifecycleTrust {
            genesis_root: a[9].clone(),
            previously_trusted_head_root: a[10].clone(),
        };
        let head = lifecycle::recover_lifecycle_head(&layout, &trust)?;
        if head.authority_root != trust.previously_trusted_head_root {
            return Err("recovered authority head differs from external pin".into());
        }
        let before = lifecycle::verify_lifecycle_directory(&layout, &trust);
        if before.state != lifecycle::VerificationState::Valid {
            return Err(format!("pre-execution lifecycle refused: {before:?}").into());
        }
        let contract = if a[1] == "run-contract" {
            Some(serde_json::from_slice::<
                realm_v6::c0_contract::C0FileContract,
            >(&fs::read(&a[11])?)?)
        } else {
            None
        };
        let outcome = if let Some(contract) = &contract {
            realm_v6::execute::execute_rootfs_brokered_contract(
                &request,
                contract,
                &backend,
                Path::new(&a[4]),
                a[5].parse()?,
                a[6].parse()?,
            )?
        } else {
            execute_rootfs_brokered(
                &request,
                &backend,
                Path::new(&a[4]),
                a[5].parse()?,
                a[6].parse()?,
            )?
        };
        save(
            &evidence.join("checked-execution-report.json"),
            &serde_json::to_vec_pretty(&outcome.result)?,
        )?;
        let capability = outcome
            .publication_capability
            .ok_or("no checked production publication capability")?;
        publication_barrier(&evidence, destination)?;
        let prepared = prepare_candidate(&capability, destination)?;
        let published = lifecycle::publish_prepared_generation(prepared, capability, &trust)?;
        let artifact = evidence.join("accepted.realm");
        save(&artifact, &published.bundle().pack()?)?;
        let reopen_profile = realm_v6::profile::Span::new("artifact_cold_reopen");
        let reopened = ArtifactBundle::open(&artifact)?;
        reopened.validate_at(ValidationLevel::AttestationShape)?;
        drop(reopen_profile);
        let verification = lifecycle::verify_lifecycle_directory(&layout, &trust);
        if verification.state != lifecycle::VerificationState::Valid {
            return Err(
                format!("post-publication full verification refused: {verification:?}").into(),
            );
        }
        save(
            &evidence.join("full-chain-verification.json"),
            &serde_json::to_vec_pretty(&verification)?,
        )?;
        let report = serde_json::json!({"artifact_path":artifact,"artifact_reopened_and_validated":true,"public_accept_report":published.report(),"full_from_genesis_verification":verification});
        save(
            &evidence.join("public-accept.json"),
            &serde_json::to_vec_pretty(&report)?,
        )?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        Ok(())
    }
}
fn main() {
    #[cfg(all(target_os = "linux", not(feature = "test-support")))]
    if let Err(e) = production::run() {
        eprintln!("production publication refused: {e}");
        std::process::exit(1);
    }
    #[cfg(any(not(target_os = "linux"), feature = "test-support"))]
    {
        eprintln!("production publication unavailable on this build");
        std::process::exit(1);
    }
}
