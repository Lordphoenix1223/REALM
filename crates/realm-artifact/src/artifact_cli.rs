use realm_artifact::{ArtifactBundle, ContentMode, inspection, observations};
use serde_json::json;
use std::{fs, io::Write, path::Path};

const HELP: &str = "REALM portable artifact toolkit (research preview)

Usage:
  realm-artifact demo --output FRESH_DIR
  realm-artifact inspect FILE [--json]
  realm-artifact verify FILE [--json] [--require-execution]
  realm-artifact record RUN_ID BEFORE AFTER OBSERVER_LOG OUT.realm
  realm-artifact version [--json]
  realm-artifact --help

verify checks artifact integrity and referenced bytes with the existing engine.
It never authorizes execution or proves complete observation. --require-execution
returns INCOMPLETE even for intact bundles. record imports caller-supplied bytes
as non-authoritative observations; it does not run or mediate an agent.

Exit codes (new interface): 0 content checked; 1 invalid; 2 usage;
3 incomplete; 4 unsupported format/reader limit; 5 I/O failure.
Legacy: validate, identify/hash, diff, unpack/open, create/build, seal,
verify-lifecycle. These retain their existing interfaces and trust requirements.
Supported native targets: macOS/Linux. Windows requires dependency work; WSL2 is not tested here.
";

pub fn dispatch(args: &[String]) -> Option<i32> {
    let command = args.first().map(String::as_str).unwrap_or("--help");
    if matches!(command, "--help" | "-h" | "help") && args.len() <= 1 {
        print!("{HELP}");
        return Some(0);
    }
    if matches!(command, "version" | "--version" | "-V") {
        if args.len() == 1 {
            println!(
                "realm-artifact {} | portable format 3 | report {} | research preview",
                env!("CARGO_PKG_VERSION"),
                inspection::REPORT_SCHEMA
            );
            return Some(0);
        }
        if args.len() == 2 && args[1] == "--json" {
            println!(
                "{}",
                json!({"version":env!("CARGO_PKG_VERSION"), "artifact_schema":3,
                "report_schema":inspection::REPORT_SCHEMA, "execution_authorization":"NOT_CHECKED"})
            );
            return Some(0);
        }
        return Some(usage());
    }
    match command {
        "inspect" | "verify" => Some(check(args)),
        "demo" => Some(match args {
            [_, flag, output] if flag == "--output" => {
                demo(Path::new(output)).unwrap_or_else(io_error)
            }
            _ => usage(),
        }),
        "record" => Some(match args {
            [_, run, before, after, log, output] => {
                record(run, before, after, log, output).unwrap_or_else(io_error)
            }
            _ => usage(),
        }),
        "validate" | "identify" | "hash" | "diff" | "unpack" | "open" | "create" | "build"
        | "seal" | "verify-lifecycle" => None,
        _ => Some(usage()),
    }
}

fn usage() -> i32 {
    eprintln!("Invalid arguments. Run realm-artifact --help for commands and proof boundaries.");
    2
}

fn io_error(error: Box<dyn std::error::Error>) -> i32 {
    eprintln!("realm-artifact: I/O or input error: {error}");
    5
}

fn check(args: &[String]) -> i32 {
    let mut path = None;
    let mut json_output = false;
    let mut require_execution = false;
    for arg in &args[1..] {
        match arg.as_str() {
            "--json" if !json_output => json_output = true,
            "--require-execution" if args[0] == "verify" && !require_execution => {
                require_execution = true
            }
            value if !value.starts_with('-') && path.is_none() => path = Some(value),
            _ => return usage(),
        }
    }
    let Some(path) = path else {
        return usage();
    };
    let report = inspection::check_file(Path::new(path), require_execution);
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&report).expect("serializable report")
        );
    } else {
        println!(
            "Result: {:?}\n{}\nArtifact integrity: {}\nReferenced content: {}\nObservation completeness: {}\nExecution authorization: {}",
            report.status,
            report.diagnostic,
            report.checks.artifact_integrity,
            report.checks.referenced_content,
            report.checks.observation_completeness,
            report.checks.execution_authorization
        );
        if args[0] == "inspect"
            && let Some(metadata) = &report.metadata
        {
            println!(
                "{}",
                serde_json::to_string_pretty(metadata).expect("serializable metadata")
            );
        }
        println!("authority: external only");
    }
    report.exit_code()
}

fn record(
    run: &str,
    before: &str,
    after: &str,
    log: &str,
    output: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    if run.is_empty() || run.len() > 256 {
        return Ok(usage());
    }
    // Size-bound each import; these are observations supplied by the caller.
    let read = |path: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let bytes = inspection::read_regular_prefix(
            Path::new(path),
            inspection::MAX_ARTIFACT_BYTES / 4 + 1,
        )?;
        if bytes.len() as u64 > inspection::MAX_ARTIFACT_BYTES / 4 {
            return Err("each imported file is limited to 16 MiB".into());
        }
        Ok(bytes)
    };
    let bundle = observations::from_file_observation(run, read(before)?, read(after)?, read(log)?)?;
    let bytes = bundle.pack()?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(output)?.write_all(&bytes)?;
    println!(
        "Recorded caller-supplied observations. Execution authorization: NOT_CHECKED; verification: UNKNOWN."
    );
    Ok(0)
}

fn demo(output: &Path) -> Result<i32, Box<dyn std::error::Error>> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(output)?;
    let valid = include_bytes!("../examples/minimal.realm").to_vec();
    let mut corrupt = valid.clone();
    *corrupt.last_mut().expect("nonempty fixture") ^= 1;
    let mut thin = ArtifactBundle::unpack(&valid)?;
    thin.envelope.content = ContentMode::Thin;
    let key = thin.blobs.keys().next().expect("fixture blob").clone();
    thin.blobs.remove(&key);
    let cases = [
        ("valid", valid, inspection::Status::Valid),
        ("tampered", corrupt, inspection::Status::Invalid),
        ("incomplete", thin.pack()?, inspection::Status::Incomplete),
    ];
    let mut results = Vec::new();
    for (name, bytes, expected) in cases {
        let path = output.join(format!("{name}.realm"));
        fs::write(&path, &bytes)?;
        let report = inspection::check_file(&path, false);
        fs::write(
            output.join(format!("{name}.json")),
            serde_json::to_vec_pretty(&report)?,
        )?;
        if report.status != expected {
            return Err(format!("demo control {name} produced {:?}", report.status).into());
        }
        println!("{name}: {:?} (exit {})", report.status, report.exit_code());
        results.push(json!({"case":name, "status":report.status, "exit_code":report.exit_code()}));
    }
    fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(&json!({
        "scope":"synthetic fixture demonstration", "execution_authority":"NONE", "cases":results}))?,
    )?;
    println!(
        "Fixture only. Integrity is not execution authorization. Inspect the saved .realm and .json files."
    );
    Ok(0)
}
