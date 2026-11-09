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
    if args.first().map(String::as_str) == Some("fixture-receiver") {
        #[cfg(feature = "receiver-fixtures")]
        return fixture_receiver(&args[1..]);
        #[cfg(not(feature = "receiver-fixtures"))]
        return Err("REFUSE: fixture receiver absent; explicit receiver-fixtures build required; production authority unavailable".into());
    }
    match args.as_slice() {
        [command, input] if command == "inspect-coding" => println!("{}", serde_json::to_string_pretty(&realm_artifact::host_apply::ordered_create::candidate::inspect(&read_candidate(input)?)?)?),
        [command, input] if command == "verify-coding" => { realm_artifact::host_apply::ordered_create::candidate::verify(&read_candidate(input)?)?; },
        [command, input] if command == "inspect" => println!("{}", ArtifactBundle::open(input)?.inspect()?),
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
        _ => return Err("usage: realm-artifact inspect-coding|verify-coding FILE.realm | verify-lifecycle <live-root> <externally-pinned-genesis-root> <externally-pinned-previous-head-root> | create|build <receipt.json> <out.realm> | inspect|validate|identify|hash|seal <file.realm> | unpack|open <file.realm> <out.realm> | diff <left.realm> <right.realm>".into()),
    }
    Ok(())
}

fn read_candidate(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(path);
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    Ok(realm_artifact::host_apply::read_transfer_file(&absolute)?)
}

#[cfg(feature = "receiver-fixtures")]
fn fixture_receiver(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use realm_artifact::host_apply::ordered_create::fixtures;
    use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};
    match args {
        [c, artifact, pin, dest, state] if c == "receive" => {
            let v = fixtures::verify(&read_candidate(artifact)?, pin)?;
            let report = v.receive(Path::new(dest), Path::new(state), None);
            let ok = report.status == "PREPARED_REQUIRES_SEPARATE_APPROVAL";
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !ok { return Err("NON_AUTHORIZING fixture preparation refused".into()); }
        }
        [c, artifact, pin, dest, state, flag, approval] if c == "receive" && flag == "--approve" => {
            let v = fixtures::verify(&read_candidate(artifact)?, pin)?;
            let report = v.receive(Path::new(dest), Path::new(state), Some(approval));
            let ok = report.status == "NON_AUTHORIZING_FIXTURE_APPLIED";
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !ok { return Err("NON_AUTHORIZING fixture application incomplete; preserve state".into()); }
        }
        [c, output] if c == "make" => {
            let bytes = fixtures::artifact("disposable-receiver-run", [
                b"def summarize(values): return sum(values)\n".to_vec(),
                b"from totals import summarize\n".to_vec(),
                b"from totals import summarize\nassert summarize([1, 2]) == 3\n".to_vec(),
            ])?;
            let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(output)?;
            f.write_all(&bytes)?; f.sync_all()?;
            println!("{}", serde_json::json!({"authority":"NONE", "artifact_blake3": blake3::hash(&bytes).to_hex().to_string()}));
        }
        [c, artifact, pin, dest] if c == "prepare" => {
            let v = fixtures::verify(&read_candidate(artifact)?, pin)?;
            let p = v.prepare(Path::new(dest))?;
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({"authority":"NONE", "approval_id": p.result.approval_id()?, "plan": p}))?);
        }
        [c, artifact, pin, dest, state, flag, approval] if c == "apply" && flag == "--approve" => {
            let v = fixtures::verify(&read_candidate(artifact)?, pin)?;
            println!("{}", serde_json::to_string_pretty(&v.apply(Path::new(dest), Path::new(state), approval)?)?);
        }
        [c, artifact, pin, dest, state] if c == "progress" || c == "final-verify" => {
            let v = fixtures::verify(&read_candidate(artifact)?, pin)?;
            if c == "progress" { println!("{}", serde_json::to_string_pretty(&v.progress(Path::new(dest), Path::new(state))?)?); }
            else { println!("{}", serde_json::to_string_pretty(&v.final_verify(Path::new(dest), Path::new(state))?)?); }
        }
        _ => return Err("NON_AUTHORIZING ONLY: fixture-receiver receive FILE.realm EXTERNAL_BLAKE3 DEST STATE [--approve ID] | make FILE.realm | prepare FILE.realm EXTERNAL_BLAKE3 DEST | apply FILE.realm EXTERNAL_BLAKE3 DEST STATE --approve ID | progress|final-verify FILE.realm EXTERNAL_BLAKE3 DEST STATE".into()),
    }
    Ok(())
}
