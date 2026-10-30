use realm_artifact::{ArtifactBundle, lifecycle, receipt};
use realm_v6::Receipt;
use std::{env, fs};

#[path = "../artifact_cli.rs"]
mod artifact_cli;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if let Some(code) = artifact_cli::dispatch(&args) {
        std::process::exit(code);
    }
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("realm-artifact: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    match args.as_slice() {
        [command, input] if command == "validate" => { let artifact = ArtifactBundle::open(input)?; artifact.validate()?; println!("valid {}", artifact.identity()?.value); }
        [command, input] if command == "identify" || command == "hash" => println!("{}", ArtifactBundle::open(input)?.identity()?.value),
        [command, live_root, genesis_root, trusted_head_root] if command == "verify-lifecycle" => {
            let layout = realm_v6::generation::GenerationLayout::inspect(live_root)?;
            let trust = lifecycle::LifecycleTrust {
                genesis_root: genesis_root.clone(),
                previously_trusted_head_root: trusted_head_root.clone(),
            };
            let result = lifecycle::verify_lifecycle_directory(&layout, &trust);
            println!("{}", serde_json::to_string(&result)?);
            if result.state != lifecycle::VerificationState::Valid {
                return Err(format!("{:?}: {}", result.state, result.diagnostic).into());
            }
        }
        [command, input, output] if command == "unpack" || command == "open" => { ArtifactBundle::open(input)?.write(output)?; }
        [command, receipt_path, output] if command == "create" || command == "build" => {
            let bytes = fs::read(receipt_path)?;
            let receipt: Receipt = serde_json::from_slice(&bytes)?;
            receipt::from_receipt(&receipt, &bytes)?.write(output)?;
            println!("wrote {output}");
        }
        [command, left, right] if command == "diff" => println!("{}", ArtifactBundle::open(left)?.diff(&ArtifactBundle::open(right)?)?),
        [command, input] if command == "seal" => { let mut a=ArtifactBundle::open(input)?; let root=a.seal()?; a.write(input)?; println!("{}", root.value); }
        _ => return Err("usage: realm-artifact verify-lifecycle <live-root> <externally-pinned-genesis-root> <externally-pinned-previous-head-root> | create|build <receipt.json> <out.realm> | inspect|validate|identify|hash|seal <file.realm> | unpack|open <file.realm> <out.realm> | diff <left.realm> <right.realm>".into()),
    }
    Ok(())
}
