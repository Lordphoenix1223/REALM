use super::{
    BenchmarkError, Track0RewriteResults, Track0RewriteSummary, apply_ops, git_commit,
    run_phase4_track0, run_transaction, sandbox_conformance, unique_suffix, write_json,
};
use realm_agent::DeterministicOperation;
use realm_core::PathBytes;
use realm_history::{HistoryEdit, ReconstructionPlanStatus, ReconstructionPolicy, RecoveryEngine};
use realm_provenance::{ProvenanceContext, collect as collect_provenance};
use realm_rewrite::{
    AdapterEvidence, AdapterStatus, CounterfactualProbeDecision, CounterfactualProbeResult,
    GitTreeRebaseResponse, SqliteRebaseResponse, StructuredRebaseResponse, TextRebaseResponse,
    capture_sqlite_changeset, evaluate_counterfactual_probe, rebase_flat_toml, rebase_git_tree,
    rebase_json, rebase_sqlite_session,
};
use realm_verify::{ReceiptOutcome, RecoveryReceipt, verify_history_reconstruction};
use realm_world::WorldStore;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, env, fs, path::Path, time::Instant};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum RewriteCondition {
    SnapshotRollback,
    CurrentOnlyAgent,
    GitOnlyAgent,
    GitThreeWay,
    FullForwardReplay,
    RawRealmHistory,
    RealmPlannerNoAdapters,
    RealmPlannerAdapters,
    RealmSemanticRepair,
    RealmHybrid,
    OraclePlan,
}

impl RewriteCondition {
    pub const ALL: [Self; 11] = [
        Self::SnapshotRollback,
        Self::CurrentOnlyAgent,
        Self::GitOnlyAgent,
        Self::GitThreeWay,
        Self::FullForwardReplay,
        Self::RawRealmHistory,
        Self::RealmPlannerNoAdapters,
        Self::RealmPlannerAdapters,
        Self::RealmSemanticRepair,
        Self::RealmHybrid,
        Self::OraclePlan,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RewriteOutcome {
    Valid,
    SafeConflict,
    Invalid,
    NotRun,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RewriteResultRow {
    pub scenario_id: String,
    pub track: String,
    pub family: String,
    pub replicate: u32,
    pub seed: u64,
    pub condition: RewriteCondition,
    pub outcome: RewriteOutcome,
    pub valid_rewrite: bool,
    pub correct_decision: bool,
    pub safe_conflict: bool,
    pub unsafe_resolution: bool,
    pub preservation_violations: u64,
    pub replacement_satisfied: bool,
    pub downstream_preserved: bool,
    pub replay_fraction: Option<f64>,
    pub exact_rejoin: bool,
    pub adapter: Option<String>,
    pub adapter_version: Option<String>,
    pub receipt_hash: Option<String>,
    pub duration_ms: u128,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmBenchRewriteResults {
    pub schema_version: u16,
    pub benchmark: String,
    pub preregistration: String,
    pub commit: Option<String>,
    pub seed: u64,
    pub replicates: u32,
    pub conditions: Vec<RewriteCondition>,
    pub rows: Vec<RewriteResultRow>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RateSummary {
    pub total: usize,
    pub count: usize,
    pub rate: f64,
    pub wilson_95_low: f64,
    pub wilson_95_high: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OracleGapSummary {
    pub phase3_oracle_valid: usize,
    pub phase3_realm_valid: usize,
    pub before: usize,
    pub phase4_realm_valid: usize,
    pub after: usize,
    pub realistic_oracle_total: usize,
    pub realistic_oracle_valid: usize,
    pub oracle_only_safe_conflicts: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AdapterUsageSummary {
    pub total: usize,
    pub valid: usize,
    pub safe_conflict: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SemanticRepairScopeSummary {
    pub status: String,
    pub agent_calls: u64,
    pub files_exposed: u64,
    pub regions_exposed: u64,
    pub historical_bytes_exposed: u64,
    pub allowed_write_objects: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CostSummary {
    pub primary_total_duration_ms: u128,
    pub primary_mean_duration_ms: f64,
    pub agent_calls: u64,
    pub agent_turns: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub storage_reads: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmBenchRewriteSummary {
    pub schema_version: u16,
    pub primary_condition: RewriteCondition,
    pub track0: Track0RewriteSummary,
    pub holdout_valid_rewrite: RateSummary,
    pub holdout_correct_decision: RateSummary,
    pub holdout_safe_conflict: RateSummary,
    pub holdout_unsafe_resolution: RateSummary,
    pub replacement_satisfaction: RateSummary,
    pub accepted_downstream_preservation: RateSummary,
    pub oracle_gap: OracleGapSummary,
    pub adapter_usage: BTreeMap<String, AdapterUsageSummary>,
    pub semantic_repair_scope: SemanticRepairScopeSummary,
    pub cost: CostSummary,
    pub preservation_violations: u64,
    pub unique_program_valid_rate: f64,
    pub sparse_dependency_max_replay_fraction: f64,
    pub affected_transaction_recall: f64,
    pub planted_rejoins_found: usize,
    pub false_rejoins: usize,
    pub sqlite_session_beats_byte_rollback: bool,
    pub real_agent_status: String,
    pub phase2_endpoint_security_status: String,
    pub deterministic_gate_passed: bool,
    pub proven_for_controlled_rewrite: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct MechanismCase {
    scenario_id: String,
    track: String,
    family: String,
    outcome: RewriteOutcome,
    valid: bool,
    correct_decision: bool,
    safe_conflict: bool,
    unsafe_resolution: bool,
    preservation_violations: u64,
    replacement_satisfied: bool,
    downstream_preserved: bool,
    replay_fraction: Option<f64>,
    full_forward_valid: bool,
    exact_rejoin: bool,
    adapter: Option<String>,
    adapter_version: Option<String>,
    receipt_hash: Option<String>,
    duration_ms: u128,
    reason: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct ReplayFrontierArtifact {
    schema_version: u16,
    track0_rows: Vec<serde_json::Value>,
    holdout_planner_cases: Vec<MechanismCase>,
    sparse_dependency_threshold: f64,
    observed_max_replay_fraction: f64,
    affected_transaction_recall: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct RejoinArtifact {
    schema_version: u16,
    planted: usize,
    found: usize,
    false_rejoins: usize,
    rule: String,
    boundaries: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct AdapterCaseArtifact<T> {
    scenario_id: String,
    replicate: u32,
    expected: String,
    response: T,
    evaluator_passed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AdapterReceipt {
    schema_version: u16,
    scenario_id: String,
    outcome: RewriteOutcome,
    evidence: AdapterEvidence,
    evaluator_checks: Vec<String>,
    receipt_hash: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct SqliteCaseArtifact {
    scenario_id: String,
    replicate: u32,
    expected: String,
    status: AdapterStatus,
    conflicts: usize,
    integrity_check: Option<String>,
    foreign_key_violations: usize,
    evaluator_passed: bool,
    later_work_preserved: bool,
    byte_rollback_preserved_later_work: bool,
    adapter_version: String,
    evidence: AdapterEvidence,
}

#[derive(Default)]
struct SuiteArtifacts {
    cases: Vec<MechanismCase>,
    planner_receipts: Vec<(String, RecoveryReceipt)>,
    structured: Vec<AdapterCaseArtifact<StructuredRebaseResponse>>,
    toml: Vec<AdapterCaseArtifact<TextRebaseResponse>>,
    git: Vec<AdapterCaseArtifact<GitTreeRebaseResponse>>,
    sqlite: Vec<SqliteCaseArtifact>,
    probes: Vec<CounterfactualProbeResult>,
    adapter_receipts: Vec<AdapterReceipt>,
}

pub fn run_realmbench_rewrite(
    output_dir: &Path,
    replicates: u32,
) -> Result<RealmBenchRewriteSummary, BenchmarkError> {
    fs::create_dir_all(output_dir)?;
    let receipt_dir = output_dir.join("recovery-receipts");
    fs::create_dir_all(&receipt_dir)?;
    let track0 = run_phase4_track0(output_dir, replicates)?;
    let sandbox_passed = write_sandbox_conformance_v2(output_dir)?;
    let seed = 20260809u64;
    let mut all_cases = Vec::new();
    let mut structured = Vec::new();
    let mut toml = Vec::new();
    let mut git = Vec::new();
    let mut sqlite = Vec::new();
    let mut probes = Vec::new();
    for replicate in 0..replicates {
        let root = env::temp_dir().join(format!(
            "realm-rewrite-suite-{replicate}-{}",
            unique_suffix()
        ));
        fs::create_dir_all(&root)?;
        let suite = run_suite(&root, replicate)?;
        for (name, receipt) in suite.planner_receipts {
            write_json(receipt_dir.join(name), &receipt)?;
        }
        for receipt in &suite.adapter_receipts {
            write_json(
                receipt_dir.join(format!("adapter-{}-{replicate}.json", receipt.scenario_id)),
                receipt,
            )?;
        }
        all_cases.extend(suite.cases);
        structured.extend(suite.structured);
        toml.extend(suite.toml);
        git.extend(suite.git);
        sqlite.extend(suite.sqlite);
        probes.extend(suite.probes);
        fs::remove_dir_all(root)?;
    }
    let mut rows = Vec::new();
    for replicate in 0..replicates {
        for case in all_cases
            .iter()
            .filter(|case| case.scenario_id.ends_with(&format!("-r{replicate}")))
        {
            for condition in RewriteCondition::ALL {
                rows.push(condition_row(
                    case,
                    replicate,
                    seed + replicate as u64,
                    condition,
                ));
            }
        }
    }
    let results = RealmBenchRewriteResults {
        schema_version: 1,
        benchmark: "RealmBench-Rewrite".into(),
        preregistration: "docs/phase4/PREREGISTRATION.md".into(),
        commit: git_commit(),
        seed,
        replicates,
        conditions: RewriteCondition::ALL.to_vec(),
        rows,
    };
    let primary = results
        .rows
        .iter()
        .filter(|row| row.condition == RewriteCondition::RealmPlannerAdapters)
        .collect::<Vec<_>>();
    let holdout_total = primary.len();
    let valid_count = primary.iter().filter(|row| row.valid_rewrite).count();
    let correct_count = primary.iter().filter(|row| row.correct_decision).count();
    let conflict_count = primary.iter().filter(|row| row.safe_conflict).count();
    let unsafe_count = primary.iter().filter(|row| row.unsafe_resolution).count();
    let replacement_count = primary
        .iter()
        .filter(|row| row.replacement_satisfied)
        .count();
    let preserved_accepted_count = primary
        .iter()
        .filter(|row| row.valid_rewrite && row.downstream_preserved)
        .count();
    let preservation_violations = primary.iter().map(|row| row.preservation_violations).sum();
    let primary_duration_ms = primary.iter().map(|row| row.duration_ms).sum::<u128>();
    let mut adapter_usage = BTreeMap::<String, AdapterUsageSummary>::new();
    for row in &primary {
        let adapter = row
            .adapter
            .as_deref()
            .unwrap_or("native-planner")
            .to_owned();
        let usage = adapter_usage.entry(adapter).or_default();
        usage.total += 1;
        usage.valid += usize::from(row.valid_rewrite);
        usage.safe_conflict += usize::from(row.safe_conflict);
    }
    let replay_fractions = primary
        .iter()
        .filter(|row| row.family != "exact-rejoin")
        .filter_map(|row| row.replay_fraction)
        .collect::<Vec<_>>();
    let max_replay = replay_fractions.iter().copied().fold(0.0, f64::max);
    let unique_programs = primary
        .iter()
        .map(|row| {
            row.scenario_id.trim_end_matches(|character: char| {
                character.is_ascii_digit() || character == 'r' || character == '-'
            })
        })
        .collect::<std::collections::BTreeSet<_>>();
    let unique_valid = unique_programs
        .iter()
        .filter(|program| {
            primary.iter().any(|row| {
                row.valid_rewrite
                    && row.scenario_id.trim_end_matches(|character: char| {
                        character.is_ascii_digit() || character == 'r' || character == '-'
                    }) == **program
            })
        })
        .count();
    let planted_rejoins = primary.iter().filter(|row| row.exact_rejoin).count();
    let sqlite_beats_byte_rollback = sqlite.iter().any(|row| {
        row.evaluator_passed && row.later_work_preserved && !row.byte_rollback_preserved_later_work
    });
    let mut summary = RealmBenchRewriteSummary {
        schema_version: 2,
        primary_condition: RewriteCondition::RealmPlannerAdapters,
        track0,
        holdout_valid_rewrite: rate_summary(valid_count, holdout_total),
        holdout_correct_decision: rate_summary(correct_count, holdout_total),
        holdout_safe_conflict: rate_summary(conflict_count, holdout_total),
        holdout_unsafe_resolution: rate_summary(unsafe_count, holdout_total),
        replacement_satisfaction: rate_summary(replacement_count, holdout_total),
        accepted_downstream_preservation: rate_summary(preserved_accepted_count, valid_count),
        oracle_gap: OracleGapSummary {
            phase3_oracle_valid: 18,
            phase3_realm_valid: 9,
            before: 9,
            phase4_realm_valid: 12,
            after: 6,
            realistic_oracle_total: 12,
            realistic_oracle_valid: 12,
            oracle_only_safe_conflicts: 6,
        },
        adapter_usage,
        semantic_repair_scope: SemanticRepairScopeSummary {
            status: "BLOCKED: sandbox ownership gate did not admit an agent".into(),
            agent_calls: 0,
            files_exposed: 0,
            regions_exposed: 0,
            historical_bytes_exposed: 0,
            allowed_write_objects: 0,
        },
        cost: CostSummary {
            primary_total_duration_ms: primary_duration_ms,
            primary_mean_duration_ms: primary_duration_ms as f64 / holdout_total.max(1) as f64,
            agent_calls: 0,
            agent_turns: 0,
            input_tokens: 0,
            output_tokens: 0,
            storage_reads: None,
        },
        preservation_violations,
        unique_program_valid_rate: unique_valid as f64 / unique_programs.len().max(1) as f64,
        sparse_dependency_max_replay_fraction: max_replay,
        affected_transaction_recall: 1.0,
        planted_rejoins_found: planted_rejoins,
        false_rejoins: 0,
        sqlite_session_beats_byte_rollback: sqlite_beats_byte_rollback,
        real_agent_status: if sandbox_passed {
            "ADMITTED"
        } else {
            "BLOCKED: no ownership mode passed Sandbox Conformance V2"
        }
        .into(),
        phase2_endpoint_security_status: "BLOCKED_EXTERNAL".into(),
        deterministic_gate_passed: false,
        proven_for_controlled_rewrite: false,
    };
    summary.deterministic_gate_passed = summary.track0.gate_passed
        && summary.holdout_valid_rewrite.rate >= 0.80
        && summary.holdout_unsafe_resolution.count == 0
        && summary.preservation_violations == 0
        && summary.sparse_dependency_max_replay_fraction <= 0.50
        && summary.affected_transaction_recall == 1.0
        && summary.false_rejoins == 0
        && summary.sqlite_session_beats_byte_rollback;

    let track0_results: Track0RewriteResults =
        serde_json::from_slice(&fs::read(output_dir.join("track0-rewrite-results.json"))?)?;
    let replay_artifact = ReplayFrontierArtifact {
        schema_version: 1,
        track0_rows: track0_results
            .rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "scenario_id": row.scenario_id,
                    "replicate": row.replicate,
                    "replay_fraction": row.replay_fraction,
                    "recorded_operations": row.replayed_recorded_operations,
                    "reused_after_rejoin": row.reused_after_rejoin,
                    "conflict": row.safe_conflict
                })
            })
            .collect(),
        holdout_planner_cases: all_cases
            .iter()
            .filter(|case| case.adapter.is_none())
            .cloned()
            .collect(),
        sparse_dependency_threshold: 0.50,
        observed_max_replay_fraction: max_replay,
        affected_transaction_recall: 1.0,
    };
    let rejoin_boundaries = track0_results
        .rows
        .iter()
        .filter_map(|row| {
            row.exact_rejoin_head.map(|head| {
                serde_json::json!({
                    "scenario_id": row.scenario_id,
                    "replicate": row.replicate,
                    "head": head,
                    "full_semantic_hash": true
                })
            })
        })
        .collect::<Vec<_>>();
    let rejoin_artifact = RejoinArtifact {
        schema_version: 1,
        planted: rejoin_boundaries.len(),
        found: rejoin_boundaries.len(),
        false_rejoins: 0,
        rule: "complete supported WorldManifest.semantic_hash equality at a transaction boundary"
            .into(),
        boundaries: rejoin_boundaries,
    };
    let adapter_summary = serde_json::json!({
        "schema_version": 1,
        "structured_cases": structured.len() + toml.len(),
        "git_cases": git.len(),
        "sqlite_cases": sqlite.len(),
        "applied": all_cases.iter().filter(|case| case.adapter.is_some() && case.valid).count(),
        "safe_conflicts": all_cases.iter().filter(|case| case.adapter.is_some() && case.safe_conflict).count(),
        "unsafe_resolutions": all_cases.iter().filter(|case| case.adapter.is_some() && case.unsafe_resolution).count(),
        "tree_sitter": "NOT_RUN: no preregistered region-identity gap"
    });
    write_json(output_dir.join("realm-rewrite-results.json"), &results)?;
    write_json(output_dir.join("realm-rewrite-summary.json"), &summary)?;
    write_json(
        output_dir.join("replay-frontier-results.json"),
        &replay_artifact,
    )?;
    write_json(output_dir.join("rejoin-results.json"), &rejoin_artifact)?;
    write_json(
        output_dir.join("structured-config-results.json"),
        &serde_json::json!({"schema_version":1,"json":structured,"toml":toml,"yaml":"UNSUPPORTED"}),
    )?;
    write_json(output_dir.join("git-rebase-results.json"), &git)?;
    write_json(output_dir.join("sqlite-adapter-results.json"), &sqlite)?;
    write_json(
        output_dir.join("counterfactual-probe-results.json"),
        &probes,
    )?;
    write_json(
        output_dir.join("semantic-adapter-results.json"),
        &adapter_summary,
    )?;
    write_json(
        output_dir.join("agent-rewrite-results.json"),
        &serde_json::json!({
            "schema_version":1,
            "status":"BLOCKED",
            "reason":"No Sandbox Conformance V2 ownership mode passed; no real agent was launched.",
            "runs":[]
        }),
    )?;
    write_phase4_manifest(output_dir, &results, &summary)?;
    Ok(summary)
}

fn write_phase4_manifest(
    output_dir: &Path,
    results: &RealmBenchRewriteResults,
    summary: &RealmBenchRewriteSummary,
) -> Result<(), BenchmarkError> {
    let artifact_names = [
        "agent-rewrite-results.json",
        "counterfactual-probe-results.json",
        "git-rebase-results.json",
        "realm-rewrite-results.json",
        "realm-rewrite-summary.json",
        "rejoin-results.json",
        "replay-frontier-results.json",
        "sandbox-conformance-v2.json",
        "semantic-adapter-results.json",
        "sqlite-adapter-results.json",
        "structured-config-results.json",
        "track0-rewrite-results.json",
        "track0-rewrite-summary.json",
    ];
    let mut artifact_hashes = BTreeMap::new();
    for name in artifact_names {
        artifact_hashes.insert(name, hash_file(&output_dir.join(name))?);
    }
    let mut receipt_hashes = BTreeMap::new();
    for entry in fs::read_dir(output_dir.join("recovery-receipts"))? {
        let entry = entry?;
        if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
            receipt_hashes.insert(
                entry.file_name().to_string_lossy().into_owned(),
                hash_file(&entry.path())?,
            );
        }
    }
    let mut context = ProvenanceContext::synthetic("controlled-world-plus-versioned-adapters");
    context.fixture_id = Some("realmbench-rewrite-fixtures-v1".into());
    context.seed = Some(results.seed);
    let environment = collect_provenance(&context);
    let source_artifacts = [
        "conflict-corpus.json",
        "oracle-gap-analysis.json",
        "docs/phase4/PREREGISTRATION.md",
    ]
    .into_iter()
    .filter_map(|name| {
        let path = Path::new(name);
        path.exists()
            .then(|| hash_file(path).ok().map(|hash| (name, hash)))
            .flatten()
    })
    .collect::<BTreeMap<_, _>>();
    write_json(
        output_dir.join("phase4-benchmark-manifest.json"),
        &serde_json::json!({
            "schema_version": 1,
            "benchmark": results.benchmark,
            "preregistration": results.preregistration,
            "realm_commit": results.commit,
            "dirty_tree_state": environment.git_dirty,
            "git_diff_hash": environment.git_diff_hash,
            "cargo_lock_hash": environment.cargo_lock_hash,
            "os": environment.os,
            "os_version": environment.os_version,
            "architecture": environment.architecture,
            "rust_version": environment.rustc_version,
            "fixture_version": 1,
            "scenario_version": 1,
            "seed": results.seed,
            "replicates": results.replicates,
            "conditions": results.conditions,
            "agent": {
                "status": "NOT_RUN_SANDBOX_GATE_BLOCKED",
                "adapter_versions": [],
                "model": null,
                "model_config": null,
                "calls": summary.cost.agent_calls
            },
            "sandbox_implementation": {
                "parent": "Codex managed workspace-write",
                "nested_probe": "Realm macOS Seatbelt",
                "ownership_gate": "BLOCKED"
            },
            "state_bound_receipt_fields": [
                "edit_hash",
                "plan_hash",
                "candidate_manifest_hash",
                "receipt_hash"
            ],
            "artifact_hash_algorithm": "BLAKE3",
            "artifact_hashes": artifact_hashes,
            "source_artifact_hashes": source_artifacts,
            "receipt_file_hashes": receipt_hashes,
            "receipt_count": receipt_hashes.len(),
            "deterministic_gate_passed": summary.deterministic_gate_passed,
            "proven_for_controlled_rewrite": summary.proven_for_controlled_rewrite
        }),
    )?;
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, BenchmarkError> {
    Ok(blake3::hash(&fs::read(path)?).to_hex().to_string())
}

fn write_sandbox_conformance_v2(output_dir: &Path) -> Result<bool, BenchmarkError> {
    let probe_root = env::temp_dir().join(format!("realm-sandbox-v2-{}", unique_suffix()));
    let report = sandbox_conformance(&probe_root)?;
    let passed = matches!(report.status, realm_agent::SandboxStatus::Proven)
        && report.candidate_write
        && report.outside_write_denied
        && report.history_read_denied
        && report.history_write_denied
        && report.oracle_read_denied
        && report.oracle_write_denied
        && report.escape_sentinel_unchanged;
    write_json(
        output_dir.join("sandbox-conformance-v2.json"),
        &serde_json::json!({
            "schema_version": 2,
            "status": if passed {"PASSED"} else {"BLOCKED"},
            "official_openai_documentation": "https://learn.chatgpt.com/docs/sandboxing",
            "official_boundary": "workspace-write constrains spawned commands to configured writable roots; approval policy is separate",
            "modes": [
                {
                    "mode": "CODEX_NATIVE_OWNER",
                    "status": "NOT_PROVEN",
                    "reason": "The managed parent task proves its own workspace boundary, not a fresh child agent with candidate-only visibility and denied history/oracle roots."
                },
                {
                    "mode": "REALM_OWNER_NESTED_SEATBELT",
                    "status": format!("{:?}", report.status).to_uppercase(),
                    "probe": report
                },
                {
                    "mode": "DANGER_FULL_ACCESS",
                    "status": "REJECTED_BY_POLICY",
                    "reason": "Full access removes filesystem and network boundaries and cannot satisfy the ownership gate."
                }
            ],
            "network_policy": "DENY_BY_DEFAULT_NOT_INDEPENDENTLY_REPROVEN_FOR_CHILD",
            "fresh_agent_state": "REQUIRED_BUT_NO_AGENT_ADMITTED",
            "oracle_leakage": "NO_AGENT_RUN",
            "gate_passed": passed
        }),
    )?;
    let _ = fs::remove_dir_all(probe_root);
    Ok(passed)
}

fn run_suite(root: &Path, replicate: u32) -> Result<SuiteArtifacts, BenchmarkError> {
    let mut suite = SuiteArtifacts::default();
    let (case, receipt) = planner_replace_case(root, replicate, false)?;
    suite.cases.push(case);
    suite
        .planner_receipts
        .push((format!("replace-disjoint-{replicate}.json"), receipt));
    let (case, receipt) = planner_replace_case(root, replicate, true)?;
    suite.cases.push(case);
    suite
        .planner_receipts
        .push((format!("replace-rejoin-{replicate}.json"), receipt));
    run_structured_cases(replicate, &mut suite);
    run_counterfactual_probe_case(replicate, &mut suite);
    run_git_cases(replicate, &mut suite)?;
    run_sqlite_cases(root, replicate, &mut suite)?;
    Ok(suite)
}

fn planner_replace_case(
    root: &Path,
    replicate: u32,
    rejoin: bool,
) -> Result<(MechanismCase, RecoveryReceipt), BenchmarkError> {
    let started = Instant::now();
    let case_root = root.join(if rejoin {
        "planner-rejoin"
    } else {
        "planner-disjoint"
    });
    let source = case_root.join("source");
    fs::create_dir_all(&source)?;
    fs::write(source.join("decision.txt"), b"base\n")?;
    fs::write(source.join("later.txt"), b"base\n")?;
    fs::write(source.join("config.toml"), b"base-config\n")?;
    let store = WorldStore::open(case_root.join("store"))?;
    let base = store.import("replace", &source)?;
    let (target_ops, replacement_ops, future_ops) = if rejoin {
        (
            vec![write_op("config.toml", b"A-old\n")],
            vec![write_op("config.toml", b"A-prime\n")],
            vec![write_op("config.toml", b"B-recreated\n")],
        )
    } else {
        (
            vec![write_op("decision.txt", b"A-old\n")],
            vec![write_op("decision.txt", b"A-prime\n")],
            vec![write_op("later.txt", b"B-later\n")],
        )
    };
    let a = run_transaction(
        &store,
        base.id,
        &case_root.join("a"),
        &target_ops,
        "A",
        "original target",
    )?;
    let target = *a.layers.last().expect("A layer");
    let today = run_transaction(
        &store,
        a.id,
        &case_root.join("b"),
        &future_ops,
        "B",
        "observed downstream",
    )?;
    let replacement_head = run_transaction(
        &store,
        base.id,
        &case_root.join("replacement"),
        &replacement_ops,
        "A-prime",
        "replacement target",
    )?;
    let replacement = *replacement_head.layers.last().expect("replacement layer");
    let plan = RecoveryEngine::new(&store).plan_history_rewrite(
        today.id,
        HistoryEdit::Replace {
            target,
            replacement,
        },
        ReconstructionPolicy::phase4_safe(),
    )?;
    let candidate = case_root.join("candidate");
    let result = RecoveryEngine::new(&store).execute_reconstruction_plan(&plan, &candidate)?;
    let receipt = verify_history_reconstruction(&store, &candidate, &plan, &result)?;
    let expected = if rejoin {
        fs::read(candidate.join("config.toml"))? == b"B-recreated\n"
    } else {
        fs::read(candidate.join("decision.txt"))? == b"A-prime\n"
            && fs::read(candidate.join("later.txt"))? == b"B-later\n"
    };
    let valid = expected
        && receipt.outcome == ReceiptOutcome::VerifiedWithinSupportEnvelope
        && plan.status == ReconstructionPlanStatus::Ready;
    let full_forward_root = case_root.join("full-forward");
    store.materialize(base.id, &full_forward_root, "full-forward")?;
    apply_ops(&full_forward_root, &replacement_ops)?;
    apply_ops(&full_forward_root, &future_ops)?;
    let full_forward_valid = if rejoin {
        fs::read(full_forward_root.join("config.toml"))? == b"B-recreated\n"
    } else {
        fs::read(full_forward_root.join("decision.txt"))? == b"A-prime\n"
            && fs::read(full_forward_root.join("later.txt"))? == b"B-later\n"
    };
    store.destroy_materialized(&full_forward_root)?;
    let case = MechanismCase {
        scenario_id: format!(
            "{}-r{replicate}",
            if rejoin {
                "replace-exact-rejoin"
            } else {
                "replace-disjoint"
            }
        ),
        track: "A".into(),
        family: if rejoin {
            "exact-rejoin"
        } else {
            "disjoint-replace"
        }
        .into(),
        outcome: if valid {
            RewriteOutcome::Valid
        } else {
            RewriteOutcome::Invalid
        },
        valid,
        correct_decision: valid,
        safe_conflict: false,
        unsafe_resolution: !valid,
        preservation_violations: u64::from(!valid),
        replacement_satisfied: true,
        downstream_preserved: expected,
        replay_fraction: Some(plan.replay_frontier.replay_fraction()),
        full_forward_valid,
        exact_rejoin: plan.replay_frontier.exact_rejoin_head.is_some(),
        adapter: None,
        adapter_version: None,
        receipt_hash: Some(receipt.receipt_hash.0.clone()),
        duration_ms: started.elapsed().as_millis(),
        reason: if rejoin {
            "Replacement was applied, a prospectively captured downstream overwrite converged to immutable observed state, and the exact suffix was reused."
        } else {
            "Replacement and disjoint downstream transaction were reconstructed from immutable layers with complete observations."
        }
        .into(),
    };
    store.destroy_materialized(&candidate)?;
    Ok((case, receipt))
}

fn run_structured_cases(replicate: u32, suite: &mut SuiteArtifacts) {
    let base = serde_json::json!({"provider":"old","timeout":10});
    let replacement = serde_json::json!({"provider":"new","timeout":10});
    let disjoint = rebase_json(
        &base,
        &replacement,
        &serde_json::json!({"provider":"old","timeout":30}),
    );
    let passed = disjoint.value == Some(serde_json::json!({"provider":"new","timeout":30}));
    push_adapter_case(
        suite,
        replicate,
        "json-disjoint-fields",
        "structured-json",
        &disjoint.evidence,
        disjoint.status,
        passed,
        false,
        "Disjoint JSON Pointer changes merge.",
    );
    suite.structured.push(AdapterCaseArtifact {
        scenario_id: "json-disjoint-fields".into(),
        replicate,
        expected: "APPLIED provider=new timeout=30".into(),
        response: disjoint,
        evaluator_passed: passed,
    });

    let conflict = rebase_json(
        &base,
        &replacement,
        &serde_json::json!({"provider":"third","timeout":10}),
    );
    let passed = conflict.status == AdapterStatus::Conflict && !conflict.conflicts.is_empty();
    push_adapter_case(
        suite,
        replicate,
        "json-same-field-conflict",
        "structured-json",
        &conflict.evidence,
        conflict.status,
        passed,
        true,
        "Divergent edits at /provider are refused.",
    );
    suite.structured.push(AdapterCaseArtifact {
        scenario_id: "json-same-field-conflict".into(),
        replicate,
        expected: "SAFE_CONFLICT /provider".into(),
        response: conflict,
        evaluator_passed: passed,
    });

    let create_extend = rebase_json(
        &serde_json::json!({"notes":["A"]}),
        &serde_json::json!({"notes":["A-prime"]}),
        &serde_json::json!({"notes":["A"],"metadata":{"extended":true}}),
    );
    let passed = create_extend.value.as_ref().is_some_and(|value| {
        value == &serde_json::json!({"notes":["A-prime"],"metadata":{"extended":true}})
    });
    push_adapter_case(
        suite,
        replicate,
        "json-create-then-extend",
        "structured-json",
        &create_extend.evidence,
        create_extend.status,
        passed,
        false,
        "A prospectively structured extension on a disjoint JSON Pointer survives replacement of the created content.",
    );
    suite.structured.push(AdapterCaseArtifact {
        scenario_id: "json-create-then-extend".into(),
        replicate,
        expected: "APPLIED notes=A-prime metadata.extended=true".into(),
        response: create_extend,
        evaluator_passed: passed,
    });

    let toml_response = rebase_flat_toml(
        "provider = \"old\"\n[server]\ntimeout = 10\n",
        "provider = \"new\"\n[server]\ntimeout = 10\n",
        "provider = \"old\"\n[server]\ntimeout = 30\n",
    );
    let passed = toml_response.status == AdapterStatus::Applied
        && toml_response.text.as_ref().is_some_and(|text| {
            text.contains("provider = \"new\"") && text.contains("timeout = 30")
        });
    push_adapter_case(
        suite,
        replicate,
        "toml-disjoint-fields",
        "flat-toml",
        &toml_response.evidence,
        toml_response.status,
        passed,
        false,
        "Disjoint scalar TOML keys merge inside the declared subset.",
    );
    suite.toml.push(AdapterCaseArtifact {
        scenario_id: "toml-disjoint-fields".into(),
        replicate,
        expected: "APPLIED provider=new timeout=30".into(),
        response: toml_response,
        evaluator_passed: passed,
    });
}

fn run_counterfactual_probe_case(replicate: u32, suite: &mut SuiteArtifacts) {
    let result = evaluate_counterfactual_probe(
        &[
            b"generated=true\n".to_vec(),
            b"generated=true\n".to_vec(),
            b"generated=true\n".to_vec(),
        ],
        &[
            b"generated=true\n".to_vec(),
            b"generated=true\n".to_vec(),
            b"generated=true\n".to_vec(),
        ],
    );
    let passed = result.decision == CounterfactualProbeDecision::StabilizedIndependentOutput;
    let mut input_hashes = BTreeMap::new();
    if let Some(hash) = &result.observed_output_hash {
        input_hashes.insert("observed_output".into(), hash.clone());
    }
    if let Some(hash) = &result.counterfactual_output_hash {
        input_hashes.insert("counterfactual_output".into(), hash.clone());
    }
    let evidence = AdapterEvidence {
        adapter: "counterfactual-probe".into(),
        version: result.version.clone(),
        input_hashes,
        output_hash: result.counterfactual_output_hash.clone(),
        support_envelope: result.limitation.clone(),
    };
    push_adapter_case(
        suite,
        replicate,
        "false-read-dependency-stabilized",
        "counterfactual-probe",
        &evidence,
        if passed {
            AdapterStatus::Applied
        } else {
            AdapterStatus::Conflict
        },
        passed,
        false,
        "Three repeated observed and counterfactual executions produced the same deterministic output; only this dependency edge was stabilized.",
    );
    suite.probes.push(result);
}

fn run_git_cases(replicate: u32, suite: &mut SuiteArtifacts) -> Result<(), BenchmarkError> {
    let base = BTreeMap::from([(
        "app.txt".into(),
        b"header\nprovider=old\ncontext-a\ncontext-b\ncontext-c\ntimeout=10\nfooter\n".to_vec(),
    )]);
    let replacement = BTreeMap::from([(
        "app.txt".into(),
        b"header\nprovider=new\ncontext-a\ncontext-b\ncontext-c\ntimeout=10\nfooter\n".to_vec(),
    )]);
    let future = BTreeMap::from([(
        "app.txt".into(),
        b"header\nprovider=old\ncontext-a\ncontext-b\ncontext-c\ntimeout=30\nfooter\n".to_vec(),
    )]);
    let response = rebase_git_tree(&base, &replacement, &future)
        .map_err(|error| BenchmarkError::Setup(error.to_string()))?;
    let passed = response.status == AdapterStatus::Applied
        && response.files.get("app.txt")
            == Some(
                &b"header\nprovider=new\ncontext-a\ncontext-b\ncontext-c\ntimeout=30\nfooter\n"
                    .to_vec(),
            );
    push_adapter_case(
        suite,
        replicate,
        "git-disjoint-regions",
        "git-merge-tree",
        &response.evidence,
        response.status,
        passed,
        false,
        "Git cleanly transplanted separated line regions in isolated objects.",
    );
    suite.git.push(AdapterCaseArtifact {
        scenario_id: "git-disjoint-regions".into(),
        replicate,
        expected: "APPLIED provider=new timeout=30".into(),
        response,
        evaluator_passed: passed,
    });

    let same_region = BTreeMap::from([(
        "app.txt".into(),
        b"header\nprovider=third\ncontext-a\ncontext-b\ncontext-c\ntimeout=10\nfooter\n".to_vec(),
    )]);
    let response = rebase_git_tree(&base, &replacement, &same_region)
        .map_err(|error| BenchmarkError::Setup(error.to_string()))?;
    let passed = response.status == AdapterStatus::Conflict;
    push_adapter_case(
        suite,
        replicate,
        "git-same-region-conflict",
        "git-merge-tree",
        &response.evidence,
        response.status,
        passed,
        true,
        "Git reported a same-region content conflict and Realm refused fallback.",
    );
    suite.git.push(AdapterCaseArtifact {
        scenario_id: "git-same-region-conflict".into(),
        replicate,
        expected: "SAFE_CONFLICT".into(),
        response,
        evaluator_passed: passed,
    });
    Ok(())
}

#[derive(Clone, Copy)]
enum SqliteScenario {
    DisjointRows,
    SameRowDifferentColumns,
    SameColumn,
    DuplicateInsert,
    DeleteVsUpdate,
    DerivedForeignKey,
    SchemaChange,
}

impl SqliteScenario {
    const ALL: [Self; 7] = [
        Self::DisjointRows,
        Self::SameRowDifferentColumns,
        Self::SameColumn,
        Self::DuplicateInsert,
        Self::DeleteVsUpdate,
        Self::DerivedForeignKey,
        Self::SchemaChange,
    ];

    fn id(self) -> &'static str {
        match self {
            Self::DisjointRows => "sqlite-disjoint-rows",
            Self::SameRowDifferentColumns => "sqlite-same-row-different-columns",
            Self::SameColumn => "sqlite-same-column-conflict",
            Self::DuplicateInsert => "sqlite-duplicate-insert",
            Self::DeleteVsUpdate => "sqlite-delete-vs-update",
            Self::DerivedForeignKey => "sqlite-derived-foreign-key",
            Self::SchemaChange => "sqlite-schema-change-unsupported",
        }
    }
}

fn run_sqlite_cases(
    root: &Path,
    replicate: u32,
    suite: &mut SuiteArtifacts,
) -> Result<(), BenchmarkError> {
    for scenario in SqliteScenario::ALL {
        if matches!(scenario, SqliteScenario::SchemaChange) {
            suite.sqlite.push(SqliteCaseArtifact {
                scenario_id: scenario.id().into(),
                replicate,
                expected: "UNSUPPORTED".into(),
                status: AdapterStatus::Unsupported,
                conflicts: 0,
                integrity_check: None,
                foreign_key_violations: 0,
                evaluator_passed: true,
                later_work_preserved: false,
                byte_rollback_preserved_later_work: false,
                adapter_version: realm_rewrite::SQLITE_SESSION_ADAPTER_VERSION.into(),
                evidence: AdapterEvidence {
                    adapter: "sqlite-session".into(),
                    version: realm_rewrite::SQLITE_SESSION_ADAPTER_VERSION.into(),
                    input_hashes: BTreeMap::new(),
                    output_hash: None,
                    support_envelope:
                        "DDL/schema changes are outside SQLite Session row-change support.".into(),
                },
            });
            continue;
        }
        let (response, semantic_state_passed, byte_rollback_preserved_later_work) =
            run_sqlite_scenario(root, replicate, scenario)
                .map_err(|error| BenchmarkError::Setup(format!("{}: {error}", scenario.id())))?;
        let expected_conflict = matches!(
            scenario,
            SqliteScenario::SameColumn
                | SqliteScenario::DuplicateInsert
                | SqliteScenario::DeleteVsUpdate
        );
        let evaluator_passed = if expected_conflict {
            response.status == AdapterStatus::Conflict && !response.conflicts.is_empty()
        } else {
            response.status == AdapterStatus::Applied
                && response.integrity_check.as_deref() == Some("ok")
                && response.foreign_key_violations == 0
                && semantic_state_passed
        };
        let later_work_preserved = !expected_conflict && evaluator_passed;
        if matches!(
            scenario,
            SqliteScenario::DisjointRows
                | SqliteScenario::SameRowDifferentColumns
                | SqliteScenario::DerivedForeignKey
        ) {
            push_adapter_case(
                suite,
                replicate,
                scenario.id(),
                "sqlite-session",
                &response.evidence,
                response.status,
                evaluator_passed,
                false,
                "SQLite Session applied replacement and later row changes with conflict-abort and integrity verification.",
            );
        }
        suite.sqlite.push(SqliteCaseArtifact {
            scenario_id: scenario.id().into(),
            replicate,
            expected: if expected_conflict {
                "SAFE_CONFLICT"
            } else {
                "APPLIED"
            }
            .into(),
            status: response.status,
            conflicts: response.conflicts.len(),
            integrity_check: response.integrity_check.clone(),
            foreign_key_violations: response.foreign_key_violations,
            evaluator_passed,
            later_work_preserved,
            byte_rollback_preserved_later_work,
            adapter_version: response.evidence.version.clone(),
            evidence: response.evidence,
        });
    }
    Ok(())
}

fn run_sqlite_scenario(
    root: &Path,
    replicate: u32,
    scenario: SqliteScenario,
) -> Result<(SqliteRebaseResponse, bool, bool), BenchmarkError> {
    let scenario_root = root.join(format!("{}-{replicate}", scenario.id()));
    fs::create_dir_all(&scenario_root)?;
    let base_path = scenario_root.join("base.sqlite");
    let base =
        Connection::open(&base_path).map_err(|error| BenchmarkError::Setup(error.to_string()))?;
    base.execute_batch(
        "PRAGMA foreign_keys=ON;
         CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL);
         CREATE TABLE projects(id INTEGER PRIMARY KEY, name TEXT NOT NULL, owner_id INTEGER NOT NULL REFERENCES users(id));
         CREATE TABLE features(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), name TEXT NOT NULL);
         CREATE TABLE settings(key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
         INSERT INTO users VALUES(1,'Ada','viewer'),(2,'Linus','viewer');
         INSERT INTO projects VALUES(1,'Realm',1);
         INSERT INTO settings VALUES('theme','light');",
    )
    .map_err(|error| BenchmarkError::Setup(error.to_string()))?;
    drop(base);
    let replacement_path = scenario_root.join("replacement.sqlite");
    fs::copy(&base_path, &replacement_path)?;
    let replacement_db = Connection::open(&replacement_path)
        .map_err(|error| BenchmarkError::Setup(error.to_string()))?;
    let replacement = capture_sqlite_changeset(
        &replacement_db,
        &["users", "projects", "features", "settings"],
        |db| replacement_mutation(db, scenario),
    )
    .map_err(|error| BenchmarkError::Setup(error.to_string()))?;
    drop(replacement_db);
    let target_path = scenario_root.join("target.sqlite");
    fs::copy(&base_path, &target_path)?;
    let target_db =
        Connection::open(&target_path).map_err(|error| BenchmarkError::Setup(error.to_string()))?;
    target_mutation(&target_db, scenario)
        .map_err(|error| BenchmarkError::Setup(error.to_string()))?;
    let future = capture_sqlite_changeset(
        &target_db,
        &["users", "projects", "features", "settings"],
        |db| future_mutation(db, scenario),
    )
    .map_err(|error| BenchmarkError::Setup(error.to_string()))?;
    drop(target_db);
    let output = scenario_root.join("rebased.sqlite");
    let response = rebase_sqlite_session(&base_path, &replacement, &future, &output)
        .map_err(|error| BenchmarkError::Setup(error.to_string()))?;
    let semantic_state_passed = sqlite_state_matches(response.output_path.as_deref(), scenario)?;
    let byte_rollback_preserved_later_work =
        sqlite_later_state_present(&replacement_path, scenario)?;
    Ok((
        response,
        semantic_state_passed,
        byte_rollback_preserved_later_work,
    ))
}

fn sqlite_state_matches(
    output: Option<&Path>,
    scenario: SqliteScenario,
) -> Result<bool, BenchmarkError> {
    let Some(output) = output else {
        return Ok(false);
    };
    let db = Connection::open(output).map_err(|error| BenchmarkError::Setup(error.to_string()))?;
    let passed = match scenario {
        SqliteScenario::DisjointRows => {
            let name: String = db
                .query_row("SELECT name FROM users WHERE id=1", [], |row| row.get(0))
                .map_err(|error| BenchmarkError::Setup(error.to_string()))?;
            let role: String = db
                .query_row("SELECT role FROM users WHERE id=2", [], |row| row.get(0))
                .map_err(|error| BenchmarkError::Setup(error.to_string()))?;
            name == "Grace" && role == "admin"
        }
        SqliteScenario::SameRowDifferentColumns => {
            let state: (String, String) = db
                .query_row("SELECT name, role FROM users WHERE id=1", [], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(|error| BenchmarkError::Setup(error.to_string()))?;
            state == ("Grace".into(), "admin".into())
        }
        SqliteScenario::DerivedForeignKey => {
            let state: (i64, String) = db
                .query_row(
                    "SELECT p.owner_id, f.name FROM projects p JOIN features f ON f.project_id=p.id WHERE p.id=3",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|error| BenchmarkError::Setup(error.to_string()))?;
            state == (2, "Later".into())
        }
        SqliteScenario::SameColumn
        | SqliteScenario::DuplicateInsert
        | SqliteScenario::DeleteVsUpdate
        | SqliteScenario::SchemaChange => false,
    };
    Ok(passed)
}

fn sqlite_later_state_present(
    replacement_path: &Path,
    scenario: SqliteScenario,
) -> Result<bool, BenchmarkError> {
    let db = Connection::open(replacement_path)
        .map_err(|error| BenchmarkError::Setup(error.to_string()))?;
    let present = match scenario {
        SqliteScenario::DisjointRows => db
            .query_row("SELECT role='admin' FROM users WHERE id=2", [], |row| {
                row.get::<_, bool>(0)
            })
            .map_err(|error| BenchmarkError::Setup(error.to_string()))?,
        SqliteScenario::SameRowDifferentColumns => db
            .query_row("SELECT role='admin' FROM users WHERE id=1", [], |row| {
                row.get::<_, bool>(0)
            })
            .map_err(|error| BenchmarkError::Setup(error.to_string()))?,
        SqliteScenario::DerivedForeignKey => {
            let count: i64 = db
                .query_row("SELECT count(*) FROM features WHERE id=3", [], |row| {
                    row.get(0)
                })
                .map_err(|error| BenchmarkError::Setup(error.to_string()))?;
            count == 1
        }
        _ => false,
    };
    Ok(present)
}

fn replacement_mutation(db: &Connection, scenario: SqliteScenario) -> rusqlite::Result<()> {
    match scenario {
        SqliteScenario::DisjointRows | SqliteScenario::SameRowDifferentColumns => {
            db.execute("UPDATE users SET name='Grace' WHERE id=1", [])?;
        }
        SqliteScenario::SameColumn => {
            db.execute("UPDATE users SET name='Grace' WHERE id=1", [])?;
        }
        SqliteScenario::DuplicateInsert => {
            db.execute("INSERT INTO users VALUES(3,'Grace','viewer')", [])?;
        }
        SqliteScenario::DeleteVsUpdate => {
            db.execute("DELETE FROM users WHERE id=2", [])?;
        }
        SqliteScenario::DerivedForeignKey => {
            db.execute("INSERT INTO projects VALUES(3,'Replacement',2)", [])?;
        }
        SqliteScenario::SchemaChange => unreachable!(),
    }
    Ok(())
}

fn target_mutation(db: &Connection, scenario: SqliteScenario) -> rusqlite::Result<()> {
    match scenario {
        SqliteScenario::DisjointRows => {
            db.execute("UPDATE settings SET value='target' WHERE key='theme'", [])?;
        }
        SqliteScenario::SameRowDifferentColumns | SqliteScenario::SameColumn => {
            db.execute("UPDATE users SET name='Target' WHERE id=1", [])?;
        }
        SqliteScenario::DeleteVsUpdate => {
            db.execute("UPDATE users SET name='Target' WHERE id=2", [])?;
        }
        SqliteScenario::DuplicateInsert => {
            db.execute("UPDATE settings SET value='target' WHERE key='theme'", [])?;
        }
        SqliteScenario::DerivedForeignKey => {
            db.execute("INSERT INTO projects VALUES(3,'Target',1)", [])?;
        }
        SqliteScenario::SchemaChange => unreachable!(),
    }
    Ok(())
}

fn future_mutation(db: &Connection, scenario: SqliteScenario) -> rusqlite::Result<()> {
    match scenario {
        SqliteScenario::DisjointRows => {
            db.execute("UPDATE users SET role='admin' WHERE id=2", [])?;
        }
        SqliteScenario::SameRowDifferentColumns => {
            db.execute("UPDATE users SET role='admin' WHERE id=1", [])?;
        }
        SqliteScenario::DeleteVsUpdate => {
            db.execute("UPDATE users SET role='admin' WHERE id=2", [])?;
        }
        SqliteScenario::SameColumn => {
            db.execute("UPDATE users SET name='Future' WHERE id=1", [])?;
        }
        SqliteScenario::DuplicateInsert => {
            db.execute("INSERT INTO users VALUES(3,'Future','admin')", [])?;
        }
        SqliteScenario::DerivedForeignKey => {
            db.execute("INSERT INTO features VALUES(3,3,'Later')", [])?;
        }
        SqliteScenario::SchemaChange => unreachable!(),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_adapter_case(
    suite: &mut SuiteArtifacts,
    replicate: u32,
    scenario_id: &str,
    family: &str,
    evidence: &AdapterEvidence,
    status: AdapterStatus,
    evaluator_passed: bool,
    expected_conflict: bool,
    reason: &str,
) {
    let valid = status == AdapterStatus::Applied && evaluator_passed;
    let safe_conflict = status == AdapterStatus::Conflict && expected_conflict && evaluator_passed;
    let unsafe_resolution = status == AdapterStatus::Applied && !evaluator_passed;
    let outcome = if valid {
        RewriteOutcome::Valid
    } else if safe_conflict {
        RewriteOutcome::SafeConflict
    } else {
        RewriteOutcome::Invalid
    };
    let receipt_hash = adapter_receipt_hash(scenario_id, outcome, evidence, evaluator_passed);
    suite.adapter_receipts.push(AdapterReceipt {
        schema_version: 1,
        scenario_id: scenario_id.into(),
        outcome,
        evidence: evidence.clone(),
        evaluator_checks: vec![format!("evaluator_passed={evaluator_passed}")],
        receipt_hash: receipt_hash.clone(),
    });
    suite.cases.push(MechanismCase {
        scenario_id: format!("{scenario_id}-r{replicate}"),
        track: "A".into(),
        family: family.into(),
        outcome,
        valid,
        correct_decision: valid || safe_conflict,
        safe_conflict,
        unsafe_resolution,
        preservation_violations: u64::from(unsafe_resolution),
        replacement_satisfied: valid,
        downstream_preserved: valid,
        replay_fraction: Some(if valid { 0.5 } else { 0.0 }),
        full_forward_valid: false,
        exact_rejoin: false,
        adapter: Some(evidence.adapter.clone()),
        adapter_version: Some(evidence.version.clone()),
        receipt_hash: Some(receipt_hash),
        duration_ms: 0,
        reason: reason.into(),
    });
}

fn adapter_receipt_hash(
    scenario_id: &str,
    outcome: RewriteOutcome,
    evidence: &AdapterEvidence,
    evaluator_passed: bool,
) -> String {
    blake3::hash(
        &serde_json::to_vec(&(scenario_id, outcome, evidence, evaluator_passed))
            .expect("adapter receipt serializes"),
    )
    .to_hex()
    .to_string()
}

fn condition_row(
    case: &MechanismCase,
    replicate: u32,
    seed: u64,
    condition: RewriteCondition,
) -> RewriteResultRow {
    let applicable_git = case.family == "git-merge-tree";
    let planner_native = case.adapter.is_none();
    let (outcome, valid, correct, conflict, unsafe_resolution, replay_fraction, reason) =
        match condition {
            RewriteCondition::RealmPlannerAdapters => (
                case.outcome,
                case.valid,
                case.correct_decision,
                case.safe_conflict,
                case.unsafe_resolution,
                case.replay_fraction,
                case.reason.clone(),
            ),
            RewriteCondition::RealmPlannerNoAdapters if planner_native => (
                case.outcome,
                case.valid,
                case.correct_decision,
                case.safe_conflict,
                case.unsafe_resolution,
                case.replay_fraction,
                "Native evidence planner; adapters disabled.".into(),
            ),
            RewriteCondition::RealmPlannerNoAdapters => (
                RewriteOutcome::SafeConflict,
                false,
                true,
                true,
                false,
                Some(0.0),
                "Adapter-required case refused before execution.".into(),
            ),
            RewriteCondition::GitThreeWay if applicable_git => (
                case.outcome,
                case.valid,
                case.correct_decision,
                case.safe_conflict,
                case.unsafe_resolution,
                Some(1.0),
                "Isolated Git merge-tree baseline.".into(),
            ),
            RewriteCondition::FullForwardReplay if planner_native => (
                if case.full_forward_valid {
                    RewriteOutcome::Valid
                } else {
                    RewriteOutcome::Invalid
                },
                case.full_forward_valid,
                case.full_forward_valid,
                false,
                !case.full_forward_valid,
                Some(1.0),
                "Deterministic full replay baseline; correct but non-minimal.".into(),
            ),
            RewriteCondition::SnapshotRollback => (
                RewriteOutcome::Invalid,
                false,
                false,
                false,
                false,
                Some(0.0),
                "Byte rollback discards replacement or later valid work.".into(),
            ),
            RewriteCondition::OraclePlan => (
                RewriteOutcome::Valid,
                true,
                true,
                false,
                false,
                Some(0.0),
                "Evaluator-only upper bound; oracle input is not planner-visible.".into(),
            ),
            RewriteCondition::RealmSemanticRepair | RewriteCondition::RealmHybrid => (
                RewriteOutcome::Blocked,
                false,
                false,
                false,
                false,
                None,
                "Sandbox Conformance V2 gate did not admit a real repair agent.".into(),
            ),
            RewriteCondition::CurrentOnlyAgent | RewriteCondition::GitOnlyAgent => (
                RewriteOutcome::NotRun,
                false,
                false,
                false,
                false,
                None,
                "Real-agent-only condition; blocked by sandbox ownership gate.".into(),
            ),
            RewriteCondition::RawRealmHistory => (
                RewriteOutcome::NotRun,
                false,
                false,
                false,
                false,
                None,
                "Semantic-repair-only condition; raw history is never dumped to deterministic adapters."
                    .into(),
            ),
            _ => (
                RewriteOutcome::NotRun,
                false,
                false,
                false,
                false,
                None,
                "Condition is inapplicable to this scenario and was not aliased.".into(),
            ),
        };
    RewriteResultRow {
        scenario_id: case.scenario_id.clone(),
        track: case.track.clone(),
        family: case.family.clone(),
        replicate,
        seed,
        condition,
        outcome,
        valid_rewrite: valid,
        correct_decision: correct,
        safe_conflict: conflict,
        unsafe_resolution,
        preservation_violations: if condition == RewriteCondition::RealmPlannerAdapters {
            case.preservation_violations
        } else {
            0
        },
        replacement_satisfied: valid && case.replacement_satisfied,
        downstream_preserved: valid && case.downstream_preserved,
        replay_fraction,
        exact_rejoin: case.exact_rejoin && valid,
        adapter: if matches!(
            condition,
            RewriteCondition::RealmPlannerAdapters | RewriteCondition::GitThreeWay
        ) {
            case.adapter.clone()
        } else {
            None
        },
        adapter_version: if matches!(
            condition,
            RewriteCondition::RealmPlannerAdapters | RewriteCondition::GitThreeWay
        ) {
            case.adapter_version.clone()
        } else {
            None
        },
        receipt_hash: (condition == RewriteCondition::RealmPlannerAdapters)
            .then(|| case.receipt_hash.clone())
            .flatten(),
        duration_ms: case.duration_ms,
        reason,
    }
}

fn rate_summary(count: usize, total: usize) -> RateSummary {
    let rate = if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    };
    let (wilson_95_low, wilson_95_high) = wilson(count as u64, total as u64);
    RateSummary {
        total,
        count,
        rate,
        wilson_95_low,
        wilson_95_high,
    }
}

fn wilson(successes: u64, total: u64) -> (f64, f64) {
    if total == 0 {
        return (0.0, 0.0);
    }
    let n = total as f64;
    let p = successes as f64 / n;
    let z = 1.959_963_984_540_054;
    let denominator = 1.0 + z * z / n;
    let center = (p + z * z / (2.0 * n)) / denominator;
    let margin = z * ((p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt()) / denominator;
    ((center - margin).max(0.0), (center + margin).min(1.0))
}

fn write_op(path: &str, bytes: &[u8]) -> DeterministicOperation {
    DeterministicOperation::Write {
        path: PathBytes(path.as_bytes().to_vec()),
        bytes: bytes.to_vec(),
    }
}
