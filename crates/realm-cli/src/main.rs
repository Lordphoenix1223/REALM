use realm_agent::{AgentAdapter, AgentRequest, DeterministicAgent, PlatformSandbox};
use realm_capture::{CaptureBackend, SyntheticCaptureBackend};
use realm_cas::PreimageStore;
use realm_core::{ObjectId, PathBytes, TransactionId};
use realm_history::{
    HistoryEdit, ReconstructionPlan, ReconstructionPolicy, ReconstructionResult, RecoveryEngine,
    RecoveryStrategy,
};
use realm_history_bench::{
    analyze_oracle_gap, run_benchmark, run_phase4_track0, run_realmbench_rewrite,
    sandbox_conformance, sandbox_conformance_v3,
};
use realm_lab::{
    benchmark_with_crash_evidence, create_fixture, create_test_root, destroy_test_root,
    generate_phase2_artifacts,
};
use realm_ledger::JournalStore;
use realm_verify::verify_history_reconstruction;
use realm_world::{TransactionLayerId, WorldHeadId, WorldStore};
use std::{
    collections::BTreeMap,
    env, fs,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod closed_loop;
mod research;
use uuid::Uuid;

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

    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("realm: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    match args.as_slice() {
        [command, rest @ ..] if command == "task" || command == "artifact" || command == "apply" || command == "transfer" => closed_loop::run(command, rest),
        [command] if command == "doctor" => doctor(),
        [command, rest @ ..] if command == "research" => research::run(rest),
        [command, subcommand] if command == "capture" && subcommand == "self-test" => capture_self_test(),
        [command, subcommand, action] if command == "lab" && subcommand == "fixture" && action == "create" => {
            let root = env::temp_dir().join(format!("realm-fixture-{}", unique_suffix()));
            let manifest = create_fixture(&root, 1000, 4)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
            Ok(())
        }
        [command, subcommand, action, path] if command == "lab" && subcommand == "fixture" && action == "create" => {
            let manifest = create_fixture(path, 1000, 4)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
            Ok(())
        }
        [command, action, journal, ready, failpoint] if command == "lab" && action == "crash-child" => crash_child(journal, ready, failpoint),
        [command, action, journal] if command == "lab" && action == "crash-recover" => crash_recover(journal),
        [command, output_flag, output] if command == "bench" && output_flag == "--output" => {
            let crash_matrix = synthetic_crash_matrix()?;
            let results = benchmark_with_crash_evidence(&PathBuf::from(output), Some(crash_matrix))?;
            println!("wrote {} ({} synthetic events)", output, results.payload.test_counts["synthetic_events"]);
            Ok(())
        }
        [command, subcommand, output] if command == "lab" && subcommand == "phase2-artifacts" => {
            let crash_matrix = synthetic_crash_matrix()?;
            generate_phase2_artifacts(&PathBuf::from(output), Some(crash_matrix))?;
            println!("wrote Phase-II artifacts to {output}; live capture remains BLOCKED_EXTERNAL");
            Ok(())
        }
        [command, subcommand, output] if command == "lab" && subcommand == "history-bench" => {
            let summary = run_benchmark(&PathBuf::from(output), 1)?;
            println!("wrote RealmBench-History artifacts to {output}; primary metric {}", summary.primary_metric);
            Ok(())
        }
        [command, subcommand, output, replicates] if command == "lab" && subcommand == "history-bench" => {
            let replicates = replicates.parse::<u32>()?;
            let summary = run_benchmark(&PathBuf::from(output), replicates)?;
            println!("wrote RealmBench-History artifacts to {output}; primary metric {}", summary.primary_metric);
            Ok(())
        }
        [command, subcommand, results, output]
            if command == "lab" && subcommand == "phase4-gap-analysis" =>
        {
            let analysis = analyze_oracle_gap(
                PathBuf::from(results).as_path(),
                PathBuf::from(output).as_path(),
            )?;
            println!(
                "wrote Phase-IV gap analysis to {output}; {} row gaps, {} unique programs, realistic Track-0 target {}/{}",
                analysis.oracle_gap_rows,
                analysis.unique_gap_programs,
                analysis.realistic_phase4_track0_target,
                analysis.phase3_oracle_valid
            );
            Ok(())
        }
        [command, subcommand, output, replicates]
            if command == "lab" && subcommand == "phase4-track0" =>
        {
            let replicates = replicates.parse::<u32>()?;
            let summary = run_phase4_track0(&PathBuf::from(output), replicates)?;
            println!(
                "wrote Phase-IV Track-0 rerun to {output}; valid {}/{}, safe conflicts {}, unsafe {}",
                summary.valid,
                summary.total,
                summary.safe_conflict,
                summary.unsafe_resolution
            );
            Ok(())
        }
        [command, subcommand, output, replicates]
            if command == "lab" && subcommand == "realmbench-rewrite" =>
        {
            let replicates = replicates.parse::<u32>()?;
            let summary = run_realmbench_rewrite(&PathBuf::from(output), replicates)?;
            println!(
                "wrote RealmBench-Rewrite to {output}; holdout valid {:.3}, unsafe {}, deterministic gate {}",
                summary.holdout_valid_rewrite.rate,
                summary.holdout_unsafe_resolution.count,
                summary.deterministic_gate_passed
            );
            Ok(())
        }
        [command, subcommand, output] if command == "lab" && subcommand == "sandbox-conformance" => {
            let report = sandbox_conformance(&PathBuf::from(output))?;
            println!("sandbox conformance: {:?}", report.status);
            Ok(())
        }
        [command, subcommand, output]
            if command == "lab" && subcommand == "sandbox-conformance-v3" =>
        {
            let report = sandbox_conformance_v3(&PathBuf::from(output))?;
            println!(
                "sandbox conformance v3: {:?}; attacks passed {}; child agent {}; real model admitted {}",
                report.conformance.status,
                report.conformance.all_attacks_passed,
                report.child_agent_smoke.is_some(),
                report.real_model_admitted
            );
            Ok(())
        }
        [command, action, fixture, store] if command == "world" && action == "import" => world_import(fixture, store),
        [command, action, store, head] if command == "world" && action == "show" => world_show(store, head),
        [command, action, store, head] if command == "world" && action == "fork" => world_fork(store, head),
        [command, action, store, head] if command == "world" && action == "history" => world_history(store, head),
        [command, action, store, head, workspace, script] if command == "world" && action == "run" => world_run(store, head, workspace, script),
        [command, subcommand, store, today, target, strategy, candidate] if command == "history" && subcommand == "rebuild-without" => history_rebuild(store, today, target, strategy, candidate),
        [command, subcommand, store, today, target, replacement, plan]
            if command == "history" && subcommand == "plan-replace" =>
        {
            history_plan_replace(store, today, target, replacement, plan)
        }
        [command, subcommand, plan]
            if command == "history" && subcommand == "explain-plan" =>
        {
            history_explain_plan(plan)
        }
        [command, subcommand, store, plan, candidate, result]
            if command == "history" && subcommand == "execute-plan" =>
        {
            history_execute_plan(store, plan, candidate, result)
        }
        [command, subcommand, store, plan, result, candidate, receipt]
            if command == "candidate" && subcommand == "verify" =>
        {
            candidate_verify(store, plan, result, candidate, receipt)
        }
        [command, rest @ ..] if command == "run" => {
            let _ = rest;
            Err("real `realm run -- <command>` is not exposed until an entitlement-backed macOS capture backend is proven; use `capture self-test` for synthetic evidence".into())
        }
        [command] if command == "--help" || command == "help" => closed_loop::run("task", &[]),
        [] => Err("usage: realm task|artifact|apply --help | doctor | capture self-test | research import/propose-claims/lint/lock/reproduce/attack/minimize/verify/pack ... | lab ... | world ... | history ... | candidate verify ...".into()),
        _ => Err("unknown command; run `realm` without arguments for the research CLI command summary".into()),
    }
}

fn parse_head(value: &str) -> Result<WorldHeadId, Box<dyn std::error::Error>> {
    Ok(WorldHeadId(Uuid::parse_str(value)?))
}

fn world_import(fixture: &str, store_root: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = WorldStore::open(store_root)?;
    let head = store.import(
        PathBuf::from(fixture)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("fixture"),
        PathBuf::from(fixture).as_path(),
    )?;
    let manifest = store.manifest(head.manifest)?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"world_id":head.world_id,"head":head.id,"base_generation":head.base_generation,"manifest_hash":manifest.root_hash,"object_count":manifest.object_count,"logical_bytes":manifest.logical_bytes})
        )?
    );
    Ok(())
}

fn world_show(store_root: &str, head_value: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = WorldStore::open(store_root)?;
    let head = store.head(parse_head(head_value)?)?;
    let manifest = store.manifest(head.manifest)?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"head":head,"manifest_hash":manifest.root_hash,"semantic_hash":manifest.semantic_hash,"object_count":manifest.object_count,"logical_bytes":manifest.logical_bytes})
        )?
    );
    Ok(())
}

fn world_fork(store_root: &str, head_value: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = WorldStore::open(store_root)?;
    let fork = store.fork(parse_head(head_value)?)?;
    println!("{}", serde_json::to_string_pretty(&fork)?);
    Ok(())
}

fn world_history(store_root: &str, head_value: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = WorldStore::open(store_root)?;
    let history = store.history(parse_head(head_value)?)?;
    println!("{}", serde_json::to_string_pretty(&history)?);
    Ok(())
}

fn world_run(
    store_root: &str,
    head_value: &str,
    workspace: &str,
    script_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = WorldStore::open(store_root)?;
    let parent = parse_head(head_value)?;
    let workspace_path = PathBuf::from(workspace);
    let materialized = store.materialize(parent, &workspace_path, "cli-world-run")?;
    let workspace_path = fs::canonicalize(&workspace_path)?;
    let protected_store = fs::canonicalize(store_root)?;
    let script: realm_agent::DeterministicScript = serde_json::from_slice(&fs::read(script_path)?)?;
    let request = AgentRequest {
        prompt: format!("deterministic script {}", script.script_id),
        workspace: workspace_path.clone(),
        state_root: workspace_path.join(".realm-agent-state"),
        scratch_root: workspace_path.join(".realm-scratch"),
        history_root: protected_store.clone(),
        cas_root: protected_store.clone(),
        ledger_root: protected_store.clone(),
        contracts_root: protected_store.clone(),
        oracle_root: protected_store.clone(),
        evaluator_root: protected_store.clone(),
        host_root: protected_store,
        timeout_ms: 30_000,
        model: None,
        deterministic_script: Some(script),
    };
    let run = DeterministicAgent.run(&request, &PlatformSandbox)?;
    let head = store.commit_workspace(
        parent,
        &workspace_path,
        "deterministic",
        &request.prompt,
        BTreeMap::new(),
    )?;
    store.destroy_materialized(&materialized.root)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({"run":run,"head":head}))?
    );
    Ok(())
}

fn history_rebuild(
    store_root: &str,
    today: &str,
    target: &str,
    strategy: &str,
    candidate: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let strategy = match strategy.to_ascii_lowercase().as_str() {
        "snapshot" | "snapshotrollback" => RecoveryStrategy::SnapshotRollback,
        "exact" | "exactsubtract" => RecoveryStrategy::ExactSubtract,
        "forward" | "forwardreplay" => RecoveryStrategy::ForwardReplay,
        "hybrid" | "hybridrepair" => RecoveryStrategy::HybridRepair,
        "semantic" | "semanticrepair" => RecoveryStrategy::SemanticRepair,
        _ => return Err(format!("unknown recovery strategy {strategy}").into()),
    };
    let store = WorldStore::open(store_root)?;
    let today = parse_head(today)?;
    let target = realm_world::TransactionLayerId(Uuid::parse_str(target)?);
    let result = RecoveryEngine::new(&store).recover_into(
        today,
        target,
        strategy,
        PathBuf::from(candidate).as_path(),
    )?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn parse_layer(value: &str) -> Result<TransactionLayerId, Box<dyn std::error::Error>> {
    Ok(TransactionLayerId(Uuid::parse_str(value)?))
}

fn history_plan_replace(
    store_root: &str,
    today: &str,
    target: &str,
    replacement: &str,
    plan_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = WorldStore::open(store_root)?;
    let plan = RecoveryEngine::new(&store).plan_history_rewrite(
        parse_head(today)?,
        HistoryEdit::Replace {
            target: parse_layer(target)?,
            replacement: parse_layer(replacement)?,
        },
        ReconstructionPolicy::phase4_safe(),
    )?;
    fs::write(plan_path, serde_json::to_vec_pretty(&plan)?)?;
    println!("{}", plan.history_view);
    Ok(())
}

fn history_explain_plan(plan_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let plan: ReconstructionPlan = serde_json::from_slice(&fs::read(plan_path)?)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "history_view": plan.history_view,
            "status": plan.status,
            "actions": plan.actions,
            "conflicts": plan.conflicts,
            "known_unknowns": plan.known_unknowns,
            "replay_frontier": plan.replay_frontier,
            "estimated_agent_calls": 0
        }))?
    );
    Ok(())
}

fn history_execute_plan(
    store_root: &str,
    plan_path: &str,
    candidate: &str,
    result_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = WorldStore::open(store_root)?;
    let plan: ReconstructionPlan = serde_json::from_slice(&fs::read(plan_path)?)?;
    let result = RecoveryEngine::new(&store)
        .execute_reconstruction_plan(&plan, PathBuf::from(candidate).as_path())?;
    fs::write(result_path, serde_json::to_vec_pretty(&result)?)?;
    println!("{}", result.candidate_world);
    Ok(())
}

fn candidate_verify(
    store_root: &str,
    plan_path: &str,
    result_path: &str,
    candidate: &str,
    receipt_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = WorldStore::open(store_root)?;
    let plan: ReconstructionPlan = serde_json::from_slice(&fs::read(plan_path)?)?;
    let result: ReconstructionResult = serde_json::from_slice(&fs::read(result_path)?)?;
    let receipt =
        verify_history_reconstruction(&store, PathBuf::from(candidate).as_path(), &plan, &result)?;
    fs::write(receipt_path, serde_json::to_vec_pretty(&receipt)?)?;
    println!("{:?}", receipt.outcome);
    Ok(())
}

fn doctor() -> Result<(), Box<dyn std::error::Error>> {
    let cwd = env::current_dir()?;
    println!("Realm Foundation doctor (inspection only)");
    println!(
        "OS                     {} {}",
        env::consts::OS,
        env::consts::ARCH
    );
    println!(
        "Kernel                 {}",
        command_output("uname", &["-sr"])
    );
    let mount = command_output("sh", &["-c", "mount | rg ' on / '"]);
    println!("Filesystem             {}", mount);
    println!(
        "Available disk         {}",
        command_output("df", &["-h", cwd.to_str().unwrap_or(".")])
    );
    println!(
        "SQLite                 {}",
        command_output("sqlite3", &["--version"])
    );
    let sdk = command_output("xcrun", &["--sdk", "macosx", "--show-sdk-path"]);
    println!("Apple SDK              {}", sdk);
    let header = command_output(
        "sh",
        &[
            "-c",
            "SDK=$(xcrun --sdk macosx --show-sdk-path 2>/dev/null); if rg -q 'es_new_descendants_client' \"$SDK/usr/include/EndpointSecurity\" 2>/dev/null; then echo AVAILABLE; else echo NOT_FOUND; fi",
        ],
    );
    println!("Descendant ES API      {}", header);
    println!("ES entitlement         MISSING / NOT PROVEN (this CLI is not entitlement-signed)");
    println!("macOS capture          BLOCKED BY ENTITLEMENT; no real capture claim");
    println!(
        "APFS clone             {}",
        if mount.contains("apfs") {
            "APFS mounted; clone capability not yet exercised"
        } else {
            "not confirmed"
        }
    );
    println!("Journal                READY (framed CRC32C + BLAKE3 hash chain)");
    println!("CAS                    READY (BLAKE3, atomic publication)");
    println!("Synthetic lab          READY (SYNTHETIC only)");
    Ok(())
}

fn capture_self_test() -> Result<(), Box<dyn std::error::Error>> {
    let root = env::temp_dir().join(format!("realm-self-test-{}", unique_suffix()));
    fs::create_dir_all(&root)?;
    let cas = PreimageStore::open(root.join("cas"))?;
    let blob = cas.put_bytes(b"historical bytes")?;
    let mut journal = JournalStore::open(root.join("journal"))?;
    let tx = TransactionId::new();
    let object = ObjectId::new();
    let mut backend = SyntheticCaptureBackend::with_actor("self-test");
    backend.start(tx)?;
    backend.object_write(object, PathBytes(b"fixture.txt".to_vec()), None, None)?;
    backend.object_delete(object, PathBytes(b"fixture.txt".to_vec()), None)?;
    let batch = backend.stop()?;
    for event in &batch.events {
        journal.append_json("EVENT", event)?;
    }
    let replayed = journal.scan()?.records.len();
    println!("SYNTHETIC capture self-test: PASS");
    println!("transaction: {tx}");
    println!("events: {}", batch.events.len());
    println!("journal records replayed: {replayed}");
    println!("CAS blob: {} ({} bytes)", blob.hash, blob.size);
    println!("real macOS capture: NOT TESTED");
    fs::remove_dir_all(root)?;
    Ok(())
}

fn crash_child(
    journal_path: &str,
    ready_path: &str,
    failpoint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut journal = JournalStore::open(journal_path)?;
    if failpoint == "auth_event_received" {
        pause_for_kill(ready_path)?;
    }
    if failpoint == "preimage_fsynced" {
        pause_for_kill(ready_path)?;
    }
    journal.append("PREPARED_MUTATION", br#"{"mutation":"fixture"}"#)?;
    if failpoint == "prepared_record_written" {
        pause_for_kill(ready_path)?;
    }
    journal.append("COMMITTED_MUTATION", br#"{"mutation":"fixture"}"#)?;
    Ok(())
}

fn crash_recover(journal_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let journal = JournalStore::open(journal_path)?;
    let scan = journal.scan()?;
    println!(
        "valid_records={} last_valid_offset={} tail_was_invalid={}",
        scan.records.len(),
        scan.last_valid_offset,
        scan.tail_was_invalid
    );
    Ok(())
}

fn synthetic_crash_matrix() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let root_path = env::temp_dir().join(format!("realm-crash-matrix-{}", unique_suffix()));
    let owned = create_test_root(&root_path)?;
    let executable = env::current_exe()?;
    let mut cases = Vec::new();
    for (failpoint, expected_records) in [
        ("auth_event_received", 0usize),
        ("preimage_fsynced", 0usize),
        ("prepared_record_written", 1usize),
    ] {
        let journal = owned.root.join(format!("{failpoint}.journal"));
        let ready = owned.root.join(format!("{failpoint}.ready"));
        let mut child = Command::new(&executable)
            .args([
                "lab",
                "crash-child",
                journal.to_str().unwrap_or_default(),
                ready.to_str().unwrap_or_default(),
                failpoint,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let wait_start = Instant::now();
        while !ready.exists() {
            if child.try_wait()?.is_some() {
                return Err(format!("crash child exited before failpoint {failpoint}").into());
            }
            if wait_start.elapsed() > Duration::from_secs(5) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("crash child timed out at failpoint {failpoint}").into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        child.kill()?;
        let _ = child.wait();
        let recovered = Command::new(&executable)
            .args(["lab", "crash-recover", journal.to_str().unwrap_or_default()])
            .output()?;
        if !recovered.status.success() {
            return Err(format!("crash recovery failed at {failpoint}").into());
        }
        let output = String::from_utf8_lossy(&recovered.stdout);
        let records = output
            .split_whitespace()
            .find_map(|part| part.strip_prefix("valid_records="))
            .ok_or_else(|| format!("recovery output had no record count: {output}"))?
            .parse::<usize>()?;
        cases.push(serde_json::json!({
            "failpoint":failpoint,
            "expected_valid_records":expected_records,
            "observed_valid_records":records,
            "status":if records == expected_records {"GREEN_PROVEN"} else {"FAILED_CONFORMANCE"}
        }));
    }
    destroy_test_root(&owned.root)?;
    Ok(serde_json::json!({
        "schema_version":1,
        "status":if cases.iter().all(|case| case["status"] == "GREEN_PROVEN") {"GREEN_PROVEN"} else {"FAILED_CONFORMANCE"},
        "mode":"synthetic_process_sigkill",
        "cases":cases
    }))
}

fn pause_for_kill(ready_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(ready_path, b"ready")?;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn command_output(command: &str, args: &[&str]) -> String {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .replace('\n', " | ")
        })
        .filter(|output| !output.is_empty())
        .unwrap_or_else(|| "unavailable".into())
}

fn unique_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}
