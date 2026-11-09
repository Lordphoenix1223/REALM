//! Small real-process workload for the independent counterfactual harness.
//!
//! The parent mediates every benchmark input/output byte through EffectFrontier.
//! The child receives only the brokered input on stdin and CF_CONFIG, computes,
//! and returns bytes on stdout. This is a broker fixture, not a contained V6 run.

use realm_v6::frontier::{EffectFrontier, audit_journal};
use serde::Serialize;
use std::env;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

const READ_LEN: usize = 4096;
const WORK_UNITS: u64 = 25_000;

#[derive(Serialize)]
struct RunSummary {
    run_id: String,
    return_code: i32,
    output_blake3: String,
    output_hex: String,
    observed_reads: Vec<ReadSummary>,
    committed_writes: u64,
    journal_head: String,
    work_units: u64,
}

#[derive(Serialize)]
struct ReadSummary {
    object: realm_v6::frontier::ObjectIdentity,
    offset: u64,
    length: usize,
    bytes_blake3: String,
    whole_object_version: String,
}

fn blake3_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = blake3::hash(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest.as_bytes() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn worker() -> Result<(), String> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .map_err(|e| e.to_string())?;
    let config = env::var("CF_CONFIG").map_err(|e| e.to_string())?;
    let mut state = blake3::hash(&input).as_bytes().to_vec();
    for i in 0..WORK_UNITS {
        let mut h = blake3::Hasher::new();
        h.update(&state);
        h.update(config.as_bytes());
        h.update(&i.to_le_bytes());
        state = h.finalize().as_bytes().to_vec();
    }
    std::io::stdout()
        .write_all(&state)
        .map_err(|e| e.to_string())
}

fn run(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err("usage: cf_task <world-dir> <run-id>".into());
    }
    let dir = Path::new(&args[1]);
    let run_id = &args[2];
    let input_path = dir.join("input.bin");
    let output_path = dir.join("output.bin");
    let mut broker = EffectFrontier::create(
        dir,
        run_id,
        "counterfactual-host-broker-v1",
        &input_path,
        &output_path,
    )
    .map_err(|e| format!("frontier create: {e:?}"))?;

    let input = broker
        .read("benchmark-input-prefix", false, 0, READ_LEN)
        .map_err(|e| format!("frontier read: {e:?}"))?;
    let config = env::var("CF_CONFIG").map_err(|e| e.to_string())?;
    let mut child = Command::new(env::current_exe().map_err(|e| e.to_string())?)
        .arg("--worker")
        .env_clear()
        .env("CF_CONFIG", &config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn worker: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("worker stdin missing")?
        .write_all(&input)
        .map_err(|e| format!("write worker stdin: {e}"))?;
    let output = child
        .wait_with_output()
        .map_err(|e| format!("wait worker: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "worker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    broker
        .write("benchmark-output", 0, &output.stdout)
        .map_err(|e| format!("frontier write: {e:?}"))?;
    let journal_path = broker.journal_path().to_path_buf();
    let head = broker
        .seal("local-process-complete-v1")
        .map_err(|e| format!("seal: {e:?}"))?;
    let audit = audit_journal(&journal_path, run_id, "counterfactual-host-broker-v1")
        .map_err(|e| format!("audit: {e:?}"))?;
    let reads = audit
        .reads
        .iter()
        .map(|r| ReadSummary {
            object: r.object.clone(),
            offset: r.offset,
            length: r.returned_bytes.len(),
            bytes_blake3: blake3_hex(&r.returned_bytes),
            whole_object_version: r.object_version.clone(),
        })
        .collect();
    let summary = RunSummary {
        run_id: run_id.clone(),
        return_code: output.status.code().unwrap_or(-1),
        output_blake3: blake3_hex(&output.stdout),
        output_hex: output.stdout.iter().map(|b| format!("{b:02x}")).collect(),
        observed_reads: reads,
        committed_writes: audit.committed_write_count,
        journal_head: head,
        work_units: WORK_UNITS,
    };
    println!(
        "{}",
        serde_json::to_string(&summary).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = if args.get(1).is_some_and(|arg| arg == "--worker") {
        worker()
    } else {
        run(&args)
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
