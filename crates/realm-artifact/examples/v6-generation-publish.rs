use realm_artifact::{ArtifactBundle, ValidationLevel, lifecycle};
use realm_v6::{
    execute::{ExecuteRequest, execute_with_authority},
    generation::{GenerationLayout, prepare_candidate},
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process,
};

#[cfg(not(feature = "test-support"))]
fn main() {
    if let Err(error) = run() {
        eprintln!("V6 artifact publication refused: {error}");
        process::exit(1);
    }
}

#[cfg(feature = "test-support")]
fn main() {
    eprintln!("production publisher unavailable in test-support build");
    process::exit(1);
}

#[cfg(not(feature = "test-support"))]
fn run() -> Result<(), String> {
    let args = std::env::args().collect::<Vec<_>>();
    let separator = args.iter().position(|arg| arg == "--").ok_or_else(usage)?;
    let mut root = None;
    let mut destination = None;
    let mut run_id = None;
    let mut artifact_output = None;
    let mut genesis_anchor_file = None;
    let mut trusted_genesis_root = None;
    let mut trusted_head_root = None;
    let mut timeout_ms = 30_000;
    let mut rootfs = None;
    let mut workspace_device = None;
    let mut guest_supervisor = None;
    let mut firecracker = None;
    let mut kernel = None;
    let mut state_dir = None;
    let mut allowed_paths = Vec::new();
    let mut index = 1;
    while index < separator {
        let option = args[index].as_str();
        if option == "--timeout-ms" {
            index += 1;
            timeout_ms = args
                .get(index)
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| "--timeout-ms requires an integer".to_string())?;
        } else {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| format!("{option} requires a value"))?;
            match option {
                "--root" => root = Some(PathBuf::from(value)),
                "--destination" => destination = Some(PathBuf::from(value)),
                "--run-id" => run_id = Some(value.clone()),
                "--artifact-output" => artifact_output = Some(PathBuf::from(value)),
                "--genesis-anchor" => genesis_anchor_file = Some(PathBuf::from(value)),
                "--trusted-genesis-root" => trusted_genesis_root = Some(value.clone()),
                "--trusted-head-root" => trusted_head_root = Some(value.clone()),
                "--rootfs" => rootfs = Some(PathBuf::from(value)),
                "--workspace-device" => workspace_device = Some(PathBuf::from(value)),
                "--guest-supervisor" => guest_supervisor = Some(PathBuf::from(value)),
                "--firecracker" => firecracker = Some(PathBuf::from(value)),
                "--kernel" => kernel = Some(PathBuf::from(value)),
                "--state-dir" => state_dir = Some(PathBuf::from(value)),
                "--allow-path" => allowed_paths.push(value.clone()),
                _ => return Err(format!("unknown option: {option}")),
            }
        }
        index += 1;
    }
    let root = required(root, "--root")?;
    let destination = required(destination, "--destination")?;
    let run_id = run_id.ok_or_else(|| "--run-id is required".to_string())?;
    let artifact_output = required(artifact_output, "--artifact-output")?;
    let genesis_anchor_file = required(genesis_anchor_file, "--genesis-anchor")?;
    let trusted_genesis_root =
        trusted_genesis_root.ok_or_else(|| "--trusted-genesis-root is required".to_string())?;
    let trusted_head_root =
        trusted_head_root.ok_or_else(|| "--trusted-head-root is required".to_string())?;
    ensure_artifact_output_location(&artifact_output, &destination)?;
    let layout = GenerationLayout::inspect(&destination).map_err(|error| error.to_string())?;
    let genesis: lifecycle::GenesisAnchor =
        serde_json::from_slice(&fs::read(&genesis_anchor_file).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    lifecycle::initialize_lifecycle(&layout, &genesis, &trusted_genesis_root)
        .map_err(|error| error.to_string())?;
    let trust = lifecycle::LifecycleTrust {
        genesis_root: trusted_genesis_root,
        previously_trusted_head_root: trusted_head_root.clone(),
    };
    let recovered_head =
        lifecycle::recover_lifecycle_head(&layout, &trust).map_err(|error| error.to_string())?;
    if recovered_head.authority_root != trust.previously_trusted_head_root {
        return Err(format!(
            "recovery advanced the authority head to {}; pin that root before new work",
            recovered_head.authority_root
        ));
    }
    let initial_verification = lifecycle::verify_lifecycle_directory(&layout, &trust);
    if initial_verification.state != lifecycle::VerificationState::Valid {
        return Err(format!(
            "durable lifecycle does not verify before execution: {} ({:?})",
            initial_verification.diagnostic, initial_verification.state
        ));
    }
    if allowed_paths.is_empty() {
        allowed_paths.push("target.txt".into());
    }
    let mut unique_allowed = std::collections::BTreeSet::new();
    if allowed_paths.iter().any(|path| {
        path.is_empty()
            || path.starts_with('/')
            || path.contains('\\')
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !unique_allowed.insert(path.clone())
    }) {
        return Err("allowed paths must be unique normalized workspace-relative paths".into());
    }

    let request = ExecuteRequest {
        run_id,
        root,
        command: args[separator + 1..].to_vec(),
        timeout_ms,
        allowed_effects: vec!["filesystem".into()],
        allowed_paths,
        rootfs: Some(required(rootfs, "--rootfs")?),
        workspace_device: Some(required(workspace_device, "--workspace-device")?),
        guest_supervisor: Some(required(guest_supervisor, "--guest-supervisor")?),
        firecracker: Some(required(firecracker, "--firecracker")?),
        kernel: Some(required(kernel, "--kernel")?),
        state_dir: Some(required(state_dir, "--state-dir")?),
    };
    let outcome = execute_with_authority(&request).map_err(|error| error.to_string())?;
    let Some(publication_capability) = outcome.publication_capability else {
        println!("{}", serde_json::to_string_pretty(&outcome.result).unwrap());
        process::exit(3);
    };

    // The lifecycle transaction owns the expected-head check through exchange,
    // receipt/journal binding, AuthorityHead CAS, and full-chain verification.
    // It returns a serializable ACCEPT report only after every step succeeds.
    let prepared = prepare_candidate(&publication_capability, &destination)
        .map_err(|error| error.to_string())?;
    let published =
        lifecycle::publish_prepared_generation(prepared, publication_capability, &trust)
            .map_err(|error| error.to_string())?;
    let bundle = published.bundle();
    write_new_artifact(bundle, &artifact_output).map_err(|error| error.to_string())?;

    let reopened = ArtifactBundle::open(&artifact_output).map_err(|error| error.to_string())?;
    reopened
        .validate_at(ValidationLevel::AttestationShape)
        .map_err(|error| error.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "artifact_path": artifact_output,
            "semantic_execution_identity": reopened.semantic_identity().map_err(|error| error.to_string())?,
            "generation_publication": reopened.envelope.publication.generation,
            "public_accept_report": published.report(),
            "artifact_reopened_and_validated": true,
        }))
        .map_err(|error| error.to_string())?
    );
    Ok(())
}

fn required(value: Option<PathBuf>, name: &str) -> Result<PathBuf, String> {
    value.ok_or_else(|| format!("{name} is required"))
}

fn ensure_artifact_output_location(output: &Path, destination: &Path) -> Result<(), String> {
    let workspace = destination
        .canonicalize()
        .map_err(|error| format!("cannot resolve destination: {error}"))?;
    let parent = output
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .map_err(|error| format!("cannot resolve artifact output directory: {error}"))?;
    let name = output
        .file_name()
        .ok_or_else(|| "artifact output must name a file".to_string())?;
    if parent.join(name).starts_with(workspace) {
        return Err("artifact output must be outside the published workspace".into());
    }
    Ok(())
}

fn write_new_artifact(
    bundle: &ArtifactBundle,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let parent = parent.canonicalize()?;
    let name = output
        .file_name()
        .ok_or("artifact output must name a file")?;
    let path = parent.join(name);
    let bytes = bundle.pack()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn usage() -> String {
    concat!(
        "usage: cargo run -p realm-artifact --example v6-generation-publish -- \\
",
        "     --root ROOT --destination ROOT --run-id ID --artifact-output FILE \\
",
        "     --genesis-anchor FILE --trusted-genesis-root ROOT --trusted-head-root ROOT \\
",
        "     --rootfs ROOTFS --workspace-device DEVICE --guest-supervisor SUPERVISOR \\
",
        "     --firecracker BIN --kernel KERNEL --state-dir DIR [--allow-path PATH]... \\
",
        "     -- COMMAND [ARGS...]"
    )
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_output_must_not_modify_the_published_workspace() {
        let root = std::env::temp_dir().join(format!(
            "realm-artifact-output-test-{}-{}",
            process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let workspace = root.join("workspace");
        let evidence = root.join("evidence");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(&evidence).unwrap();

        assert!(ensure_artifact_output_location(&workspace.join("run.realm"), &workspace).is_err());
        assert!(ensure_artifact_output_location(&evidence.join("run.realm"), &workspace).is_ok());
        fs::remove_dir_all(root).unwrap();
    }
}
