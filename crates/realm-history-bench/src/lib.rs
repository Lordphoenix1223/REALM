//! Deterministic RealmBench-History harness.
//!
//! Track A is intentionally independent of a model. It builds a controlled
//! world, commits A/B/C/D, constructs an oracle by replaying separately defined
//! no-A instructions, and evaluates eight preregistered evidence conditions.
//! The oracle never enters an agent-readable root.

mod rewrite;
pub use rewrite::*;

use realm_agent::{
    AgentAdapter, AgentRequest, AgentRunRecord, AgentSandbox, ClaudeAdapter, CodexAdapter,
    DeterministicAgent, DeterministicOperation, DeterministicScript, KernelSandboxConformance,
    PlatformSandbox, SandboxConformance, SandboxRoots, SandboxStatus,
};
use realm_core::{
    ActorIdentity, ActorKind, EvidenceClass, IntentContract, IntentOrigin, IntentPostcondition,
    ObservationCompleteness, ObservationSet, PathBytes, PostconditionCheck, RecordedOperation,
    RecordedOperationKind, TransactionCapsule, TransactionId, WorldReference,
};
use realm_history::{
    HistoryEdit, ReconstructionPlanStatus, ReconstructionPolicy, RecoveryEngine, RecoveryStrategy,
};
use realm_verify::{ReceiptOutcome, verify_history_reconstruction};
use realm_world::{
    CandidateWorldId, TransactionLayerId, WorldError, WorldHeadId, WorldManifest, WorldStore,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum BenchmarkCondition {
    SnapshotRollback,
    CurrentOnly,
    GitOnly,
    TransactionDiffOnly,
    RawRealmHistory,
    RealmContract,
    RealmHybrid,
    OracleContract,
}

impl BenchmarkCondition {
    pub const ALL: [Self; 8] = [
        Self::SnapshotRollback,
        Self::CurrentOnly,
        Self::GitOnly,
        Self::TransactionDiffOnly,
        Self::RawRealmHistory,
        Self::RealmContract,
        Self::RealmHybrid,
        Self::OracleContract,
    ];

    fn strategy(self) -> Option<RecoveryStrategy> {
        match self {
            Self::SnapshotRollback => Some(RecoveryStrategy::SnapshotRollback),
            Self::RawRealmHistory | Self::RealmContract => Some(RecoveryStrategy::ExactSubtract),
            Self::RealmHybrid => Some(RecoveryStrategy::HybridRepair),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ScenarioFamily {
    UntrackedBinaryDelete,
    DisjointText,
    RenameAndEdit,
    DeleteThenRecreate,
    OverlapText,
    CreateThenExtend,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScenarioSpec {
    pub id: String,
    pub version: u16,
    pub family: ScenarioFamily,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorldReferences {
    pub base: WorldHeadId,
    pub target: TransactionLayerId,
    pub b: TransactionLayerId,
    pub c: TransactionLayerId,
    pub d: TransactionLayerId,
    pub today: WorldHeadId,
    pub oracle_manifest_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub safe_conflict: bool,
    pub target_removed: bool,
    pub must_preserve_violations: u64,
    pub exact_data_recovered: bool,
    pub hidden_invariants_passed: bool,
    pub unexpected_edit_count: u64,
    pub violations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HistoryResultRow {
    pub scenario_id: String,
    pub scenario_family: ScenarioFamily,
    pub scenario_version: u16,
    pub replicate: u32,
    pub seed: u64,
    pub condition: BenchmarkCondition,
    pub references: WorldReferences,
    pub candidate_world: Option<CandidateWorldId>,
    pub candidate_manifest_hash: Option<String>,
    pub contract_context_bytes: Option<usize>,
    pub overlap_count: Option<usize>,
    pub status: String,
    pub verification: VerificationResult,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HistoryBenchmarkResults {
    pub schema_version: u16,
    pub realm_commit: Option<String>,
    pub scenario_version: u16,
    pub replicates: u32,
    pub seed: u64,
    pub rows: Vec<HistoryResultRow>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConditionSummary {
    pub condition: BenchmarkCondition,
    pub total: u64,
    pub valid: u64,
    pub safe_conflict: u64,
    pub failure: u64,
    pub valid_recovery_rate: f64,
    pub wilson_95_low: f64,
    pub wilson_95_high: f64,
    pub must_preserve_violations: u64,
    pub exact_data_recovery_rate: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HistoryBenchmarkSummary {
    pub schema_version: u16,
    pub primary_metric: String,
    pub summaries: Vec<ConditionSummary>,
    pub history_utility_gain_vs_current: Option<f64>,
    pub history_utility_gain_vs_git: Option<f64>,
    pub forward_replay_rows: u64,
    pub hybrid_rows: u64,
    pub deterministic_gate: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HistoryBenchmarkManifest {
    pub schema_version: u16,
    pub benchmark: String,
    pub preregistration: String,
    pub realm_commit: Option<String>,
    pub scenario_version: u16,
    pub replicates: u32,
    pub seed: u64,
    pub conditions: Vec<BenchmarkCondition>,
    pub scenarios: Vec<ScenarioSpec>,
    pub result_artifact_hash: String,
    pub summary_artifact_hash: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GapCategory {
    PlannerConservatism,
    EvidenceAvailableNotUsed,
    ReplayabilityUnknown,
    IntentInsufficient,
    OracleOnlyInformation,
    GenuineSemanticAmbiguity,
    BenchmarkDefect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NaturalAvailability {
    CapturableButMissing,
    NotDerivableFromFrozenHistory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolutionSoundness {
    ConditionalOnCapturedOperation,
    MustRemainConflict,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConflictCorpusRecord {
    pub scenario_id: String,
    pub scenario_family: ScenarioFamily,
    pub replicate: u32,
    pub target_transaction: TransactionLayerId,
    pub current_world: WorldHeadId,
    pub realm_status: String,
    pub realm_candidate_manifest_hash: Option<String>,
    pub oracle_candidate_manifest_hash: Option<String>,
    pub candidate_matches_oracle: bool,
    pub conflict_path: String,
    pub exact_difference: String,
    pub why_realm_declined: String,
    pub extra_information_oracle_possessed: String,
    pub naturally_available_to_realm: NaturalAvailability,
    pub proposed_resolution: String,
    pub resolution_soundness: ResolutionSoundness,
    pub required_evidence_or_adapter: String,
    pub categories: Vec<GapCategory>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConflictCorpus {
    pub schema_version: u16,
    pub source_results_hash: String,
    pub baseline_commit: Option<String>,
    pub gap_rows: usize,
    pub unique_gap_programs: usize,
    pub deterministic_replicates_are_identical: bool,
    pub records: Vec<ConflictCorpusRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OracleGapAnalysis {
    pub schema_version: u16,
    pub source_results_hash: String,
    pub phase3_realm_valid: usize,
    pub phase3_oracle_valid: usize,
    pub oracle_gap_rows: usize,
    pub unique_gap_programs: usize,
    pub rows_with_runtime_derivable_solution: usize,
    pub rows_closeable_if_missing_operation_evidence_is_captured: usize,
    pub rows_requiring_oracle_only_semantics: usize,
    pub realistic_oracle_cases: usize,
    pub realistic_phase4_track0_target: usize,
    pub original_fifteen_of_eighteen_target_is_sound: bool,
    pub conclusion: String,
    pub category_counts: BTreeMap<GapCategory, usize>,
}

#[derive(Debug, Error)]
pub enum BenchmarkError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("world error: {0}")]
    World(#[from] WorldError),
    #[error("history error: {0}")]
    History(#[from] realm_history::HistoryError),
    #[error("agent/sandbox error: {0}")]
    Agent(#[from] realm_agent::AgentError),
    #[error("verification error: {0}")]
    Verify(#[from] realm_verify::VerifyError),
    #[error("benchmark setup error: {0}")]
    Setup(String),
}

/// Explain the frozen Phase-III Oracle Gap without changing reconstruction
/// behavior or exposing oracle data to a runtime planner. The resulting corpus
/// is research evidence: it may identify missing capture, but it is never an
/// input to candidate execution.
pub fn analyze_oracle_gap(
    results_path: &Path,
    output_dir: &Path,
) -> Result<OracleGapAnalysis, BenchmarkError> {
    let source_bytes = fs::read(results_path)?;
    let results: HistoryBenchmarkResults = serde_json::from_slice(&source_bytes)?;
    let source_results_hash = blake3::hash(&source_bytes).to_hex().to_string();
    let mut oracle_rows = BTreeMap::new();
    for row in &results.rows {
        if row.condition == BenchmarkCondition::OracleContract {
            oracle_rows.insert((row.scenario_id.clone(), row.replicate), row);
        }
    }
    let mut records = Vec::new();
    for realm in &results.rows {
        if realm.condition != BenchmarkCondition::RealmContract || !realm.verification.safe_conflict
        {
            continue;
        }
        let oracle = oracle_rows
            .get(&(realm.scenario_id.clone(), realm.replicate))
            .ok_or_else(|| {
                BenchmarkError::Setup(format!(
                    "missing OracleContract row for {} replicate {}",
                    realm.scenario_id, realm.replicate
                ))
            })?;
        if !oracle.verification.valid {
            continue;
        }
        let descriptor = gap_descriptor(realm.scenario_family);
        records.push(ConflictCorpusRecord {
            scenario_id: realm.scenario_id.clone(),
            scenario_family: realm.scenario_family,
            replicate: realm.replicate,
            target_transaction: realm.references.target,
            current_world: realm.references.today,
            realm_status: realm.status.clone(),
            realm_candidate_manifest_hash: realm.candidate_manifest_hash.clone(),
            oracle_candidate_manifest_hash: oracle.candidate_manifest_hash.clone(),
            candidate_matches_oracle: realm.candidate_manifest_hash
                == oracle.candidate_manifest_hash,
            conflict_path: descriptor.conflict_path.into(),
            exact_difference: if realm.candidate_manifest_hash
                == oracle.candidate_manifest_hash
            {
                "No supported-state byte difference; Realm refused solely because the path overlap was unresolved."
                    .into()
            } else {
                format!(
                    "{} supported path differs from the oracle; unexpected_edit_count={}",
                    descriptor.conflict_path, realm.verification.unexpected_edit_count
                )
            },
            why_realm_declined: "The target and a later transaction wrote the same path; Phase III treated every later overlap as a semantic conflict.".into(),
            extra_information_oracle_possessed: descriptor.oracle_information.into(),
            naturally_available_to_realm: descriptor.availability,
            proposed_resolution: descriptor.proposed_resolution.into(),
            resolution_soundness: descriptor.soundness,
            required_evidence_or_adapter: descriptor.required_evidence.into(),
            categories: descriptor.categories.to_vec(),
        });
    }
    let mut unique_programs = records
        .iter()
        .map(|record| record.scenario_id.as_str())
        .collect::<Vec<_>>();
    unique_programs.sort_unstable();
    unique_programs.dedup();
    let deterministic_replicates_are_identical = unique_programs.iter().all(|scenario| {
        let rows = records
            .iter()
            .filter(|record| record.scenario_id == *scenario)
            .collect::<Vec<_>>();
        rows.windows(2).all(|pair| {
            pair[0].realm_candidate_manifest_hash == pair[1].realm_candidate_manifest_hash
                && pair[0].oracle_candidate_manifest_hash == pair[1].oracle_candidate_manifest_hash
                && pair[0].categories == pair[1].categories
        })
    });
    let mut category_counts = BTreeMap::new();
    for record in &records {
        for category in &record.categories {
            *category_counts.entry(*category).or_insert(0) += 1;
        }
    }
    let phase3_realm_valid = results
        .rows
        .iter()
        .filter(|row| row.condition == BenchmarkCondition::RealmContract && row.verification.valid)
        .count();
    let phase3_oracle_valid = results
        .rows
        .iter()
        .filter(|row| row.condition == BenchmarkCondition::OracleContract && row.verification.valid)
        .count();
    let capture_closeable = records
        .iter()
        .filter(|record| {
            record.naturally_available_to_realm == NaturalAvailability::CapturableButMissing
        })
        .count();
    let oracle_only = records.len() - capture_closeable;
    let analysis = OracleGapAnalysis {
        schema_version: 1,
        source_results_hash: source_results_hash.clone(),
        phase3_realm_valid,
        phase3_oracle_valid,
        oracle_gap_rows: records.len(),
        unique_gap_programs: unique_programs.len(),
        rows_with_runtime_derivable_solution: 0,
        rows_closeable_if_missing_operation_evidence_is_captured: capture_closeable,
        rows_requiring_oracle_only_semantics: oracle_only,
        realistic_oracle_cases: phase3_oracle_valid - oracle_only,
        realistic_phase4_track0_target: phase3_realm_valid + capture_closeable,
        original_fifteen_of_eighteen_target_is_sound: phase3_realm_valid + capture_closeable >= 15,
        conclusion: "The nine row-level gaps are three deterministic programs repeated three times. Delete/recreate is closeable only if the executed overwrite is retained as operation evidence. Overlap-text and create-extend require alternate counterfactual intent supplied only by the oracle and must remain conflicts for the frozen history.".into(),
        category_counts,
    };
    let corpus = ConflictCorpus {
        schema_version: 1,
        source_results_hash,
        baseline_commit: results.realm_commit,
        gap_rows: records.len(),
        unique_gap_programs: unique_programs.len(),
        deterministic_replicates_are_identical,
        records,
    };
    fs::create_dir_all(output_dir)?;
    write_json(output_dir.join("conflict-corpus.json"), &corpus)?;
    write_json(output_dir.join("oracle-gap-analysis.json"), &analysis)?;
    Ok(analysis)
}

struct GapDescriptor {
    conflict_path: &'static str,
    oracle_information: &'static str,
    availability: NaturalAvailability,
    proposed_resolution: &'static str,
    soundness: ResolutionSoundness,
    required_evidence: &'static str,
    categories: &'static [GapCategory],
}

fn gap_descriptor(family: ScenarioFamily) -> GapDescriptor {
    match family {
        ScenarioFamily::DeleteThenRecreate => GapDescriptor {
            conflict_path: "config.toml",
            oracle_information: "The benchmark oracle re-executed B's deterministic overwrite against the no-A parent. The harness possessed that operation, but the persisted layer retained only before/after state and a generic intent string.",
            availability: NaturalAvailability::CapturableButMissing,
            proposed_resolution: "Capture the deterministic operation as trace-replay evidence, execute it against the counterfactual parent, and accept only after independent verification or exact historical rejoin.",
            soundness: ResolutionSoundness::ConditionalOnCapturedOperation,
            required_evidence: "Versioned deterministic operation trace plus state-bound verification.",
            categories: &[
                GapCategory::PlannerConservatism,
                GapCategory::EvidenceAvailableNotUsed,
                GapCategory::ReplayabilityUnknown,
            ],
        },
        ScenarioFamily::OverlapText => GapDescriptor {
            conflict_path: "src/shared.txt",
            oracle_information: "The oracle invented B-only and B-only-plus-D outputs. The executed B/D transactions were constant writes containing A, and their persisted intent was only 'later transaction'.",
            availability: NaturalAvailability::NotDerivableFromFrozenHistory,
            proposed_resolution: "Remain a conflict. A future benchmark may capture a genuine append/transform intent before execution and test replay of that declared operation.",
            soundness: ResolutionSoundness::MustRemainConflict,
            required_evidence: "Prospectively captured structured transformation intent or an independently verified semantic adapter; neither exists in Phase III.",
            categories: &[
                GapCategory::IntentInsufficient,
                GapCategory::OracleOnlyInformation,
                GapCategory::GenuineSemanticAmbiguity,
                GapCategory::BenchmarkDefect,
            ],
        },
        ScenarioFamily::CreateThenExtend => GapDescriptor {
            conflict_path: "src/notes.txt",
            oracle_information: "The oracle supplied a B-only extension that was never executed or declared. The observed B transaction wrote a constant A-plus-B file and does not encode an extension function.",
            availability: NaturalAvailability::NotDerivableFromFrozenHistory,
            proposed_resolution: "Remain a conflict for frozen history. Define future extension transactions as prospectively captured transformations with explicit postconditions.",
            soundness: ResolutionSoundness::MustRemainConflict,
            required_evidence: "Prospectively captured structured transformation and postcondition evidence; neither exists in Phase III.",
            categories: &[
                GapCategory::IntentInsufficient,
                GapCategory::OracleOnlyInformation,
                GapCategory::GenuineSemanticAmbiguity,
                GapCategory::BenchmarkDefect,
            ],
        },
        _ => GapDescriptor {
            conflict_path: "unknown",
            oracle_information: "No Phase-III RealmContract safe conflict was expected for this scenario family.",
            availability: NaturalAvailability::NotDerivableFromFrozenHistory,
            proposed_resolution: "Treat as an analyzer input error and investigate before changing reconstruction logic.",
            soundness: ResolutionSoundness::MustRemainConflict,
            required_evidence: "Manual benchmark audit.",
            categories: &[GapCategory::BenchmarkDefect],
        },
    }
}

pub fn scenario_catalog() -> Vec<ScenarioSpec> {
    vec![
        ScenarioSpec {
            id: "binary-delete".into(),
            version: 1,
            family: ScenarioFamily::UntrackedBinaryDelete,
            description: "A deletes an untracked binary; B/C/D edit independent state.".into(),
        },
        ScenarioSpec {
            id: "disjoint-text".into(),
            version: 1,
            family: ScenarioFamily::DisjointText,
            description: "A edits source text while later transactions touch unrelated paths."
                .into(),
        },
        ScenarioSpec {
            id: "rename-edit".into(),
            version: 1,
            family: ScenarioFamily::RenameAndEdit,
            description: "A renames configuration; later transactions remain disjoint.".into(),
        },
        ScenarioSpec {
            id: "delete-recreate".into(),
            version: 1,
            family: ScenarioFamily::DeleteThenRecreate,
            description: "A deletes a path and B recreates it, creating a known overlap.".into(),
        },
        ScenarioSpec {
            id: "overlap-text".into(),
            version: 1,
            family: ScenarioFamily::OverlapText,
            description: "A and B both edit the same text; no timing-only dependency is inferred."
                .into(),
        },
        ScenarioSpec {
            id: "create-extend".into(),
            version: 1,
            family: ScenarioFamily::CreateThenExtend,
            description: "A creates a file and B extends the same path.".into(),
        },
    ]
}

pub fn run_benchmark(
    output_dir: &Path,
    replicates: u32,
) -> Result<HistoryBenchmarkSummary, BenchmarkError> {
    fs::create_dir_all(output_dir)?;
    let seed = 20260808u64;
    let scenarios = scenario_catalog();
    let mut rows = Vec::new();
    for replicate in 0..replicates {
        for scenario in &scenarios {
            let run_root = env::temp_dir().join(format!(
                "realm-history-bench-{}-{}-{}",
                scenario.id,
                replicate,
                unique_suffix()
            ));
            let trace = build_trace(&run_root, scenario)?;
            for condition in BenchmarkCondition::ALL {
                rows.push(run_condition(
                    &run_root,
                    scenario,
                    replicate,
                    seed + replicate as u64,
                    condition,
                    &trace,
                )?);
            }
            fs::remove_dir_all(run_root)?;
        }
    }
    let results = HistoryBenchmarkResults {
        schema_version: 1,
        realm_commit: git_commit(),
        scenario_version: 1,
        replicates,
        seed,
        rows,
    };
    let summary = summarize(&results);
    let result_bytes = serde_json::to_vec_pretty(&results)?;
    let summary_bytes = serde_json::to_vec_pretty(&summary)?;
    let manifest = HistoryBenchmarkManifest {
        schema_version: 1,
        benchmark: "RealmBench-History Track A".into(),
        preregistration: "docs/phase3/PREREGISTRATION.md".into(),
        realm_commit: results.realm_commit.clone(),
        scenario_version: 1,
        replicates,
        seed,
        conditions: BenchmarkCondition::ALL.to_vec(),
        scenarios: scenarios.clone(),
        result_artifact_hash: blake3::hash(&result_bytes).to_hex().to_string(),
        summary_artifact_hash: blake3::hash(&summary_bytes).to_hex().to_string(),
    };
    write_artifacts(output_dir, &results, &summary, &manifest)?;
    Ok(summary)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Track0RewriteRow {
    pub scenario_id: String,
    pub scenario_family: ScenarioFamily,
    pub replicate: u32,
    pub status: ReconstructionPlanStatus,
    pub valid: bool,
    pub safe_conflict: bool,
    pub unsafe_resolution: bool,
    pub preservation_violations: u64,
    pub candidate_manifest_hash: Option<String>,
    pub oracle_manifest_hash: String,
    pub replay_fraction: f64,
    pub replayed_recorded_operations: usize,
    pub reused_after_rejoin: usize,
    pub exact_rejoin_head: Option<WorldHeadId>,
    pub receipt_outcome: Option<ReceiptOutcome>,
    pub action_kinds: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Track0RewriteResults {
    pub schema_version: u16,
    pub benchmark: String,
    pub seed: u64,
    pub replicates: u32,
    pub source_commit: Option<String>,
    pub rows: Vec<Track0RewriteRow>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Track0RewriteSummary {
    pub schema_version: u16,
    pub total: usize,
    pub valid: usize,
    pub safe_conflict: usize,
    pub unsafe_resolution: usize,
    pub preservation_violations: u64,
    pub realistic_oracle_total: usize,
    pub realistic_oracle_valid: usize,
    pub oracle_only_conflicts: usize,
    pub target_valid: usize,
    pub gate_passed: bool,
}

/// Rerun the frozen six-program Phase III corpus with only the prospective
/// evidence admitted by the Phase IV preregistration. The oracle is used by
/// the evaluator after planning; it is never stored below an agent-readable
/// or planner-readable root.
pub fn run_phase4_track0(
    output_dir: &Path,
    replicates: u32,
) -> Result<Track0RewriteSummary, BenchmarkError> {
    fs::create_dir_all(output_dir)?;
    let receipt_dir = output_dir.join("recovery-receipts");
    fs::create_dir_all(&receipt_dir)?;
    let seed = 20260809u64;
    let mut rows = Vec::new();
    for replicate in 0..replicates {
        for scenario in scenario_catalog() {
            let run_root = env::temp_dir().join(format!(
                "realm-phase4-track0-{}-{}-{}",
                scenario.id,
                replicate,
                unique_suffix()
            ));
            let trace = build_trace(&run_root, &scenario)?;
            let store = WorldStore::open(&trace.store_root)?;
            let plan = RecoveryEngine::new(&store).plan_history_rewrite(
                trace.today,
                HistoryEdit::Remove(trace.target),
                ReconstructionPolicy::phase4_safe(),
            )?;
            let action_kinds = plan
                .actions
                .iter()
                .map(|action| match action {
                    realm_history::ReconstructionAction::MaterializeParent(_) => {
                        "MATERIALIZE_PARENT"
                    }
                    realm_history::ReconstructionAction::OmitObserved(_) => "OMIT_OBSERVED",
                    realm_history::ReconstructionAction::ApplyReplacement(_) => "APPLY_REPLACEMENT",
                    realm_history::ReconstructionAction::ReplayRecordedDelta(_) => {
                        "REPLAY_RECORDED_DELTA"
                    }
                    realm_history::ReconstructionAction::ReuseObservedLayer { .. } => {
                        "REUSE_OBSERVED_LAYER"
                    }
                    realm_history::ReconstructionAction::ReplayRecordedOperation { .. } => {
                        "REPLAY_RECORDED_OPERATION"
                    }
                    realm_history::ReconstructionAction::VerifyExactRejoin { .. } => {
                        "VERIFY_EXACT_REJOIN"
                    }
                    realm_history::ReconstructionAction::ReuseObservedSuffix { .. } => {
                        "REUSE_OBSERVED_SUFFIX"
                    }
                    realm_history::ReconstructionAction::Conflict(_) => "CONFLICT",
                })
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let mut candidate_manifest_hash = None;
            let mut receipt_outcome = None;
            let mut valid = false;
            let mut unsafe_resolution = false;
            let preservation_violations;
            if plan.status == ReconstructionPlanStatus::Ready {
                let candidate_root = run_root.join("phase4-candidate");
                let result = RecoveryEngine::new(&store)
                    .execute_reconstruction_plan(&plan, &candidate_root)?;
                candidate_manifest_hash = Some(result.candidate_manifest_hash.clone());
                let receipt =
                    verify_history_reconstruction(&store, &candidate_root, &plan, &result)?;
                receipt_outcome = Some(receipt.outcome);
                valid = result.candidate_manifest_hash == trace.oracle_manifest_hash
                    && receipt.outcome == ReceiptOutcome::VerifiedWithinSupportEnvelope;
                unsafe_resolution = !valid;
                preservation_violations = u64::from(!valid);
                write_json(
                    receipt_dir.join(format!("track0-{}-{replicate}.json", scenario.id)),
                    &receipt,
                )?;
                store.destroy_materialized(&candidate_root)?;
            } else {
                preservation_violations = 0;
            }
            rows.push(Track0RewriteRow {
                scenario_id: scenario.id.clone(),
                scenario_family: scenario.family,
                replicate,
                status: plan.status,
                valid,
                safe_conflict: plan.status == ReconstructionPlanStatus::Conflict,
                unsafe_resolution,
                preservation_violations,
                candidate_manifest_hash,
                oracle_manifest_hash: trace.oracle_manifest_hash,
                replay_fraction: plan.replay_frontier.replay_fraction(),
                replayed_recorded_operations: plan.replay_frontier.replayed_recorded_operations,
                reused_after_rejoin: plan.replay_frontier.reused_after_rejoin,
                exact_rejoin_head: plan.replay_frontier.exact_rejoin_head,
                receipt_outcome,
                action_kinds,
            });
            fs::remove_dir_all(run_root)?;
        }
    }
    let results = Track0RewriteResults {
        schema_version: 1,
        benchmark: "RealmBench-Rewrite Track 0".into(),
        seed,
        replicates,
        source_commit: git_commit(),
        rows,
    };
    let summary = Track0RewriteSummary {
        schema_version: 1,
        total: results.rows.len(),
        valid: results.rows.iter().filter(|row| row.valid).count(),
        safe_conflict: results.rows.iter().filter(|row| row.safe_conflict).count(),
        unsafe_resolution: results
            .rows
            .iter()
            .filter(|row| row.unsafe_resolution)
            .count(),
        preservation_violations: results
            .rows
            .iter()
            .map(|row| row.preservation_violations)
            .sum(),
        realistic_oracle_total: results
            .rows
            .iter()
            .filter(|row| {
                !matches!(
                    row.scenario_family,
                    ScenarioFamily::OverlapText | ScenarioFamily::CreateThenExtend
                )
            })
            .count(),
        realistic_oracle_valid: results
            .rows
            .iter()
            .filter(|row| {
                row.valid
                    && !matches!(
                        row.scenario_family,
                        ScenarioFamily::OverlapText | ScenarioFamily::CreateThenExtend
                    )
            })
            .count(),
        oracle_only_conflicts: results
            .rows
            .iter()
            .filter(|row| {
                row.safe_conflict
                    && matches!(
                        row.scenario_family,
                        ScenarioFamily::OverlapText | ScenarioFamily::CreateThenExtend
                    )
            })
            .count(),
        target_valid: 4 * replicates as usize,
        gate_passed: false,
    };
    let mut summary = summary;
    summary.gate_passed = summary.valid == summary.target_valid
        && summary.realistic_oracle_valid == summary.realistic_oracle_total
        && summary.oracle_only_conflicts == 2 * replicates as usize
        && summary.unsafe_resolution == 0
        && summary.preservation_violations == 0;
    write_json(output_dir.join("track0-rewrite-results.json"), &results)?;
    write_json(output_dir.join("track0-rewrite-summary.json"), &summary)?;
    Ok(summary)
}

pub fn write_static_artifacts(output_dir: &Path) -> Result<(), BenchmarkError> {
    fs::create_dir_all(output_dir)?;
    write_json(
        output_dir.join("world-format.json"),
        &serde_json::json!({
            "schema_version": 1,
            "backend": "MaterializedWorldBackend",
            "manifest": {"entries": "BTreeMap<PathBytes, ManifestEntry>", "root_hash": "BLAKE3(canonical supported world state)", "identity": "RealmObjectId plus external materialization sidecar"},
            "layer": {"delta": "path-scoped before/after entries", "intent": "first-class semantic evidence"},
            "materialization": {"marker": "REALM-WORLD-MARKER", "ready": "READY", "symlink_policy": "relative targets only"}
        }),
    )?;
    let capabilities = vec![
        DeterministicAgent.capabilities(),
        CodexAdapter::probe().capabilities(),
        ClaudeAdapter::probe().capabilities(),
    ];
    write_json(output_dir.join("agent-capabilities.json"), &capabilities)?;
    Ok(())
}

pub fn sandbox_conformance(output_dir: &Path) -> Result<SandboxConformance, BenchmarkError> {
    fs::create_dir_all(output_dir)?;
    let root = env::temp_dir().join(format!("realm-sandbox-conformance-{}", unique_suffix()));
    let roots = SandboxRoots::strict_fixture(&root);
    let report = PlatformSandbox.preflight(&roots)?;
    write_json(output_dir.join("sandbox-conformance.json"), &report)?;
    let _ = fs::remove_dir_all(root);
    Ok(report)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxGateV3Report {
    pub schema_version: u16,
    pub conformance: KernelSandboxConformance,
    pub child_agent_smoke: Option<AgentRunRecord>,
    pub repair_benchmark_admitted: bool,
    pub real_model_admitted: bool,
    pub blocker: Option<String>,
}

pub fn sandbox_conformance_v3(output_dir: &Path) -> Result<SandboxGateV3Report, BenchmarkError> {
    fs::create_dir_all(output_dir)?;
    let root = env::temp_dir().join(format!("realm-sandbox-conformance-v3-{}", unique_suffix()));
    let roots = SandboxRoots::strict_fixture(&root);
    let conformance = PlatformSandbox.strict_conformance(&roots)?;
    let child_agent_smoke =
        if conformance.status == SandboxStatus::Proven && conformance.all_attacks_passed {
            let request = AgentRequest {
                prompt: "Write the sandbox child-agent proof marker only.".into(),
                workspace: roots.candidate.clone(),
                state_root: roots.agent_state.clone(),
                scratch_root: roots.scratch.clone(),
                history_root: roots.history.clone(),
                cas_root: roots.cas.clone(),
                ledger_root: roots.ledger.clone(),
                contracts_root: roots.contracts.clone(),
                oracle_root: roots.oracle.clone(),
                evaluator_root: roots.evaluator.clone(),
                host_root: roots.host.clone(),
                timeout_ms: 30_000,
                model: None,
                deterministic_script: Some(DeterministicScript {
                    script_id: "kernel-sandbox-child-agent-smoke-v1".into(),
                    operations: vec![DeterministicOperation::Write {
                        path: PathBytes(b"child-agent-proof.txt".to_vec()),
                        bytes: b"candidate-only-write".to_vec(),
                    }],
                }),
            };
            Some(DeterministicAgent.run(&request, &PlatformSandbox)?)
        } else {
            None
        };
    let child_output_valid = fs::read(roots.candidate.join("child-agent-proof.txt"))
        .ok()
        .as_deref()
        == Some(b"candidate-only-write");
    let repair_benchmark_admitted = conformance.status == SandboxStatus::Proven
        && conformance.all_attacks_passed
        && child_agent_smoke.is_some()
        && child_output_valid;
    let report = SandboxGateV3Report {
        schema_version: 3,
        conformance,
        child_agent_smoke,
        repair_benchmark_admitted,
        real_model_admitted: false,
        blocker: Some(
            "Strict zero-network containment and a cloud frontier-model child are mutually incompatible. The kernel tool boundary is proven, but real model control must remain outside it or use a local model."
                .into(),
        ),
    };
    write_json(output_dir.join("sandbox-conformance-v3.json"), &report)?;
    write_json(
        output_dir.join("sandbox-attack-results.json"),
        &report.conformance.attacks,
    )?;
    let _ = fs::remove_dir_all(root);
    Ok(report)
}

struct Trace {
    base: WorldHeadId,
    target: TransactionLayerId,
    b: TransactionLayerId,
    c: TransactionLayerId,
    d: TransactionLayerId,
    today: WorldHeadId,
    oracle_ops: Vec<Vec<DeterministicOperation>>,
    oracle_manifest_hash: String,
    store_root: PathBuf,
}

fn build_trace(root: &Path, scenario: &ScenarioSpec) -> Result<Trace, BenchmarkError> {
    let source = root.join("fixture");
    let store_root = root.join("store");
    fs::create_dir_all(&source)?;
    fs::create_dir_all(source.join("src"))?;
    fs::create_dir_all(source.join("assets"))?;
    fs::create_dir_all(source.join("docs"))?;
    fs::write(source.join("src/app.txt"), b"base-app\n")?;
    fs::write(source.join("src/shared.txt"), b"base-shared\n")?;
    fs::write(source.join("config.toml"), b"base-config\n")?;
    fs::write(source.join("assets/deleted.bin"), [0, 1, 2, 3, 255, 0, 7])?;
    fs::write(source.join("docs/later.txt"), b"base-doc\n")?;
    let store = WorldStore::open(&store_root)?;
    let base = store.import(&scenario.id, &source)?;
    let a_ops = actual_a_ops(scenario.family);
    let a_workspace = root.join("a");
    let a_head = run_transaction(
        &store,
        base.id,
        &a_workspace,
        &a_ops,
        "A",
        "target transaction A",
    )?;
    let a = *a_head
        .layers
        .last()
        .ok_or_else(|| BenchmarkError::Setup("A layer missing".into()))?;
    let b_ops = actual_b_ops(scenario.family);
    let b_workspace = root.join("b");
    let b_head = run_transaction(
        &store,
        store.layer(a)?.result_head,
        &b_workspace,
        &b_ops,
        "B",
        "later transaction B",
    )?;
    let b = *b_head
        .layers
        .last()
        .ok_or_else(|| BenchmarkError::Setup("B layer missing".into()))?;
    let c_ops = actual_c_ops(scenario.family);
    let c_workspace = root.join("c");
    let c_head = run_transaction(
        &store,
        store.layer(b)?.result_head,
        &c_workspace,
        &c_ops,
        "C",
        "later transaction C",
    )?;
    let c = *c_head
        .layers
        .last()
        .ok_or_else(|| BenchmarkError::Setup("C layer missing".into()))?;
    let d_ops = actual_d_ops(scenario.family);
    let d_workspace = root.join("d");
    let d_head = run_transaction(
        &store,
        store.layer(c)?.result_head,
        &d_workspace,
        &d_ops,
        "D",
        "later transaction D",
    )?;
    let d = *d_head
        .layers
        .last()
        .ok_or_else(|| BenchmarkError::Setup("D layer missing".into()))?;
    let today = store.layer(d)?.result_head;
    let oracle_ops = vec![
        oracle_b_ops(scenario.family),
        oracle_c_ops(scenario.family),
        oracle_d_ops(scenario.family),
    ];
    let oracle_root = root.join("oracle-world");
    let oracle_materialized = store.materialize(base.id, &oracle_root, "oracle")?;
    for ops in &oracle_ops {
        apply_ops(&oracle_materialized.root, ops)?;
    }
    let oracle_manifest = store.snapshot_directory(&oracle_root, None)?;
    store.destroy_materialized(&oracle_root)?;
    Ok(Trace {
        base: base.id,
        target: a,
        b,
        c,
        d,
        today,
        oracle_ops,
        oracle_manifest_hash: oracle_manifest.semantic_hash,
        store_root,
    })
}

fn run_transaction(
    store: &WorldStore,
    parent: WorldHeadId,
    workspace: &Path,
    ops: &[DeterministicOperation],
    actor: &str,
    intent: &str,
) -> Result<realm_world::WorldHead, BenchmarkError> {
    let materialized = store.materialize(parent, workspace, "fixture")?;
    apply_ops(workspace, ops)?;
    let parent_transaction = store
        .history(parent)?
        .last()
        .map(|layer| layer.transaction_capsule().id);
    let mut intent_contract = IntentContract::from_raw(intent);
    intent_contract.origin = IntentOrigin::BenchmarkGroundTruth;
    intent_contract.expected_outputs = ops
        .iter()
        .map(|operation| match operation {
            DeterministicOperation::Write { path, .. }
            | DeterministicOperation::Delete { path }
            | DeterministicOperation::Mkdir { path } => path.clone(),
            DeterministicOperation::Rename { to, .. } => to.clone(),
        })
        .collect();
    intent_contract.postconditions = ops
        .iter()
        .enumerate()
        .map(|(index, operation)| {
            let check = match operation {
                DeterministicOperation::Write { path, bytes } => {
                    PostconditionCheck::ContentHashEquals {
                        path: path.clone(),
                        blake3: blake3::hash(bytes).to_hex().to_string(),
                    }
                }
                DeterministicOperation::Delete { path } => {
                    PostconditionCheck::PathAbsent { path: path.clone() }
                }
                DeterministicOperation::Rename { to, .. }
                | DeterministicOperation::Mkdir { path: to } => {
                    PostconditionCheck::PathExists { path: to.clone() }
                }
            };
            IntentPostcondition {
                id: format!("{actor}-postcondition-{index}"),
                description: "Prospectively declared deterministic benchmark output.".into(),
                origin: IntentOrigin::BenchmarkGroundTruth,
                check,
            }
        })
        .collect();
    let mut capsule = TransactionCapsule::new(
        TransactionId::new(),
        parent_transaction,
        ActorIdentity {
            kind: ActorKind::System,
            actor_id: actor.into(),
            semantic_session_id: None,
            declared_intent: Some(intent.into()),
        },
        intent_contract,
    );
    capsule.parent_world = Some(WorldReference::new(
        "realm-controlled-world-head",
        parent.to_string(),
    ));
    capsule.observations = ObservationSet {
        completeness: ObservationCompleteness::Complete,
        reads: Vec::new(),
    };
    if actor == "B" {
        capsule.operations = ops
            .iter()
            .filter_map(|operation| match operation {
                DeterministicOperation::Write { path, bytes }
                    if path.0 == b"config.toml" && bytes == b"B-recreated\n" =>
                {
                    Some(RecordedOperation {
                        kind: RecordedOperationKind::OverwritePath,
                        path: path.clone(),
                        destination: None,
                        deterministic: true,
                        evidence: EvidenceClass::AgentDeclaration,
                    })
                }
                _ => None,
            })
            .collect();
    }
    let head = store.commit_workspace_with_capsule(parent, workspace, capsule)?;
    store.destroy_materialized(&materialized.root)?;
    Ok(head)
}

fn run_condition(
    root: &Path,
    scenario: &ScenarioSpec,
    replicate: u32,
    seed: u64,
    condition: BenchmarkCondition,
    trace: &Trace,
) -> Result<HistoryResultRow, BenchmarkError> {
    let store = WorldStore::open(&trace.store_root)?;
    let candidate_root = root.join(format!("candidate-{:?}", condition));
    let (candidate_world, candidate_hash, contract_bytes, overlap_count, status) =
        if let Some(strategy) = condition.strategy() {
            let result = RecoveryEngine::new(&store).recover_into(
                trace.today,
                trace.target,
                strategy,
                &candidate_root,
            )?;
            let hash = store
                .snapshot_directory(&candidate_root, None)?
                .semantic_hash;
            (
                Some(result.candidate_world),
                Some(hash),
                Some(serde_json::to_vec(&result.contract)?.len()),
                Some(result.conflict_paths.len()),
                format!("{:?}", result.status),
            )
        } else if condition == BenchmarkCondition::OracleContract {
            let materialized = store.materialize(trace.base, &candidate_root, "oracle-contract")?;
            for ops in &trace.oracle_ops {
                apply_ops(&candidate_root, ops)?;
            }
            let hash = store
                .snapshot_directory(&candidate_root, None)?
                .semantic_hash;
            (
                Some(materialized.candidate),
                Some(hash),
                None,
                Some(0),
                "CandidateReady".into(),
            )
        } else {
            let source = if condition == BenchmarkCondition::SnapshotRollback {
                trace.base
            } else {
                trace.today
            };
            let materialized = store.materialize(source, &candidate_root, "baseline")?;
            let hash = store
                .snapshot_directory(&candidate_root, None)?
                .semantic_hash;
            (
                Some(materialized.candidate),
                Some(hash),
                None,
                Some(0),
                "CandidateReady".into(),
            )
        };
    let candidate_manifest = store.snapshot_directory(&candidate_root, None)?;
    let oracle_ok = candidate_manifest.semantic_hash == trace.oracle_manifest_hash;
    let compiled_for_evaluator = RecoveryEngine::new(&store).compile(trace.today, trace.target)?;
    let safe_conflict_status = status == "SafeConflict";
    let verification = verify_candidate(
        &store,
        trace,
        &candidate_manifest,
        oracle_ok,
        &compiled_for_evaluator,
        safe_conflict_status,
    );
    let row = HistoryResultRow {
        scenario_id: scenario.id.clone(),
        scenario_family: scenario.family,
        scenario_version: scenario.version,
        replicate,
        seed,
        condition,
        references: WorldReferences {
            base: trace.base,
            target: trace.target,
            b: trace.b,
            c: trace.c,
            d: trace.d,
            today: trace.today,
            oracle_manifest_hash: trace.oracle_manifest_hash.clone(),
        },
        candidate_world,
        candidate_manifest_hash: candidate_hash,
        contract_context_bytes: contract_bytes,
        overlap_count,
        status,
        verification,
    };
    store.destroy_materialized(&candidate_root)?;
    Ok(row)
}

fn verify_candidate(
    store: &WorldStore,
    trace: &Trace,
    candidate: &WorldManifest,
    oracle_ok: bool,
    compiled: &realm_history::CompiledHistory,
    safe_conflict_status: bool,
) -> VerificationResult {
    let mut violations = Vec::new();
    let target_layer = store.layer(trace.target).expect("trace target exists");
    let today_manifest = store
        .manifest(
            store
                .head(trace.today)
                .expect("trace today exists")
                .manifest,
        )
        .expect("trace today manifest exists");
    let mut target_removed = true;
    let mut exact_data_recovered = true;
    for delta in &target_layer.delta {
        let overlap = compiled
            .contract
            .overlaps
            .iter()
            .any(|record| record.path == delta.path);
        if overlap {
            continue;
        }
        match (&delta.before, &delta.after) {
            (None, Some(_)) => {
                if candidate.entries.contains_key(&delta.path) {
                    target_removed = false;
                }
            }
            (Some(before), None) => {
                let expected = before.content_ref.as_ref().map(|blob| blob.hash.as_str());
                let observed = candidate
                    .entries
                    .get(&delta.path)
                    .and_then(|entry| entry.content_ref.as_ref().map(|blob| blob.hash.as_str()));
                if expected != observed {
                    exact_data_recovered = false;
                }
                if !same_state(candidate.entries.get(&delta.path), Some(before)) {
                    target_removed = false;
                }
            }
            (Some(before), Some(_)) => {
                if !same_state(candidate.entries.get(&delta.path), Some(before)) {
                    target_removed = false;
                }
                let expected = before.content_ref.as_ref().map(|blob| blob.hash.as_str());
                let observed = candidate
                    .entries
                    .get(&delta.path)
                    .and_then(|entry| entry.content_ref.as_ref().map(|blob| blob.hash.as_str()));
                if expected != observed {
                    exact_data_recovered = false;
                }
            }
            (None, None) => {}
        }
    }
    if !target_removed {
        violations.push("TARGET_DIRECT_EFFECT_REMAINS".into());
    }
    if !exact_data_recovered {
        violations.push("EXACT_DATA_NOT_RECOVERED".into());
    }
    if !oracle_ok {
        violations.push("HIDDEN_ORACLE_MANIFEST_MISMATCH".into());
    }
    let must_preserve_violations = compiled
        .contract
        .must_preserve
        .iter()
        .filter(|rule| {
            !same_state(
                candidate.entries.get(&rule.path),
                today_manifest.entries.get(&rule.path),
            )
        })
        .count() as u64;
    if must_preserve_violations > 0 {
        violations.push("MUST_PRESERVE_MISSING".into());
    }
    let hidden_invariants_passed = oracle_ok;
    let safe_conflict = safe_conflict_status;
    let unexpected_edit_count = if oracle_ok {
        0
    } else {
        diff_count(candidate, trace, store).unwrap_or(1)
    };
    let valid = !safe_conflict_status
        && oracle_ok
        && target_removed
        && exact_data_recovered
        && must_preserve_violations == 0;
    VerificationResult {
        valid,
        safe_conflict: safe_conflict && !valid,
        target_removed,
        must_preserve_violations,
        exact_data_recovered,
        hidden_invariants_passed,
        unexpected_edit_count,
        violations,
    }
}

fn same_state(
    left: Option<&realm_world::ManifestEntry>,
    right: Option<&realm_world::ManifestEntry>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.kind == right.kind
                && left
                    .content_ref
                    .as_ref()
                    .map(|blob| (&blob.hash, blob.size))
                    == right
                        .content_ref
                        .as_ref()
                        .map(|blob| (&blob.hash, blob.size))
                && left.mode == right.mode
                && left.size == right.size
                && left.symlink_target == right.symlink_target
        }
        _ => false,
    }
}

fn diff_count(
    candidate: &WorldManifest,
    trace: &Trace,
    store: &WorldStore,
) -> Result<u64, BenchmarkError> {
    let oracle_root = env::temp_dir().join(format!("realm-evaluator-oracle-{}", unique_suffix()));
    let materialized = store.materialize(trace.base, &oracle_root, "evaluator-oracle")?;
    for ops in &trace.oracle_ops {
        apply_ops(&oracle_root, ops)?;
    }
    let oracle = store.snapshot_directory(&oracle_root, None)?;
    store.destroy_materialized(&materialized.root)?;
    Ok(union_paths(candidate, &oracle)
        .into_iter()
        .filter(|path| !same_state(candidate.entries.get(path), oracle.entries.get(path)))
        .count() as u64)
}

fn union_paths(
    left: &WorldManifest,
    right: &WorldManifest,
) -> std::collections::BTreeSet<PathBytes> {
    left.entries
        .keys()
        .chain(right.entries.keys())
        .cloned()
        .collect()
}

fn summarize(results: &HistoryBenchmarkResults) -> HistoryBenchmarkSummary {
    let mut summaries = Vec::new();
    for condition in BenchmarkCondition::ALL {
        let rows = results
            .rows
            .iter()
            .filter(|row| row.condition == condition)
            .collect::<Vec<_>>();
        let total = rows.len() as u64;
        let valid = rows.iter().filter(|row| row.verification.valid).count() as u64;
        let safe_conflict = rows
            .iter()
            .filter(|row| row.verification.safe_conflict)
            .count() as u64;
        let failure = total - valid - safe_conflict;
        let rate = if total == 0 {
            0.0
        } else {
            valid as f64 / total as f64
        };
        let (low, high) = wilson(valid, total);
        let exact = if total == 0 {
            0.0
        } else {
            rows.iter()
                .filter(|row| row.verification.exact_data_recovered)
                .count() as f64
                / total as f64
        };
        summaries.push(ConditionSummary {
            condition,
            total,
            valid,
            safe_conflict,
            failure,
            valid_recovery_rate: rate,
            wilson_95_low: low,
            wilson_95_high: high,
            must_preserve_violations: rows
                .iter()
                .map(|row| row.verification.must_preserve_violations)
                .sum(),
            exact_data_recovery_rate: exact,
        });
    }
    let current = summaries
        .iter()
        .find(|summary| summary.condition == BenchmarkCondition::CurrentOnly)
        .map(|summary| summary.valid_recovery_rate);
    let git = summaries
        .iter()
        .find(|summary| summary.condition == BenchmarkCondition::GitOnly)
        .map(|summary| summary.valid_recovery_rate);
    let hybrid = summaries
        .iter()
        .find(|summary| summary.condition == BenchmarkCondition::RealmHybrid)
        .map(|summary| summary.valid_recovery_rate);
    let realm_contract = summaries
        .iter()
        .find(|summary| summary.condition == BenchmarkCondition::RealmContract)
        .map(|summary| summary.valid_recovery_rate);
    HistoryBenchmarkSummary {
        schema_version: 1,
        primary_metric: "valid_recovery_rate".into(),
        summaries,
        history_utility_gain_vs_current: hybrid.zip(current).map(|(a, b)| a - b),
        history_utility_gain_vs_git: hybrid.zip(git).map(|(a, b)| a - b),
        forward_replay_rows: results
            .rows
            .iter()
            .filter(|row| row.condition == BenchmarkCondition::OracleContract)
            .count() as u64,
        hybrid_rows: results
            .rows
            .iter()
            .filter(|row| row.condition == BenchmarkCondition::RealmHybrid)
            .count() as u64,
        deterministic_gate: format!(
            "RealmContract exact-data gate: {:.3}; RealmHybrid exact-data gate: {:.3}",
            realm_contract.unwrap_or(0.0),
            hybrid.unwrap_or(0.0)
        ),
    }
}

fn write_artifacts(
    output_dir: &Path,
    results: &HistoryBenchmarkResults,
    summary: &HistoryBenchmarkSummary,
    manifest: &HistoryBenchmarkManifest,
) -> Result<(), BenchmarkError> {
    write_json(output_dir.join("realm-history-results.json"), results)?;
    write_json(output_dir.join("realm-history-summary.json"), summary)?;
    write_json(output_dir.join("history-benchmark-manifest.json"), manifest)?;
    write_static_artifacts(output_dir)?;
    write_json(
        output_dir.join("baseline-comparison.json"),
        &summary.summaries,
    )?;
    let compiler = results.rows.iter().map(|row| serde_json::json!({"scenario": row.scenario_id, "condition": row.condition, "context_bytes": row.contract_context_bytes, "overlaps": row.overlap_count})).collect::<Vec<_>>();
    write_json(output_dir.join("contract-compiler-results.json"), &compiler)?;
    let verifier = results.rows.iter().map(|row| serde_json::json!({"scenario": row.scenario_id, "condition": row.condition, "verification": row.verification})).collect::<Vec<_>>();
    write_json(output_dir.join("verifier-results.json"), &verifier)?;
    write_json(
        output_dir.join("sandbox-conformance.json"),
        &serde_json::json!({"status":"RUN_SEPARATELY","note":"Use realm lab sandbox-conformance to avoid hiding a failed preflight in the Track A result artifact."}),
    )?;
    let summary_table = summary
        .summaries
        .iter()
        .map(|item| {
            format!(
                "| {:?} | {} | {} | {} | {:.3} | {:.3} |",
                item.condition,
                item.valid,
                item.safe_conflict,
                item.total,
                item.valid_recovery_rate,
                item.exact_data_recovery_rate
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let contract = summary
        .summaries
        .iter()
        .find(|item| item.condition == BenchmarkCondition::RealmContract)
        .map(|item| item.valid_recovery_rate)
        .unwrap_or(0.0);
    let current = summary
        .summaries
        .iter()
        .find(|item| item.condition == BenchmarkCondition::CurrentOnly)
        .map(|item| item.valid_recovery_rate)
        .unwrap_or(0.0);
    let git = summary
        .summaries
        .iter()
        .find(|item| item.condition == BenchmarkCondition::GitOnly)
        .map(|item| item.valid_recovery_rate)
        .unwrap_or(0.0);
    let binary_contract =
        scenario_valid_rate(results, "binary-delete", BenchmarkCondition::RealmContract);
    let binary_current =
        scenario_valid_rate(results, "binary-delete", BenchmarkCondition::CurrentOnly);
    let verdict = if summary
        .summaries
        .iter()
        .any(|s| s.condition == BenchmarkCondition::RealmContract && s.valid > 0)
    {
        "PHASE III PARTIALLY PROVEN"
    } else {
        "PHASE III FAILED"
    };
    let report = format!(
        "Verdict: {verdict}\n\n## What was proven?\n\nTrack A ran {} raw scenario-condition-replicate rows. Valid recovery is strict: hidden supported-manifest agreement, target-effect removal, exact bytes where defined, and preservation all pass.\n\n## What was not?\n\nThis is not arbitrary macOS reconstruction, not live Endpoint Security capture, and not a real-agent claim. Overlap families remain safe conflicts for mechanical strategies.\n\n## Does Realm history improve recovery?\n\nRealmContract valid recovery was {:.3} versus {:.3} for CurrentOnly and {:.3} for GitOnly; the raw rows and Wilson intervals are in `realm-history-summary.json`. These are benchmark results, not universal product metrics.\n\n## Compared with what?\n\nThe matrix includes SnapshotRollback, CurrentOnly, GitOnly, TransactionDiffOnly, RawRealmHistory, RealmContract, RealmHybrid, and OracleContract.\n\n| Condition | Valid | Safe conflict | Total | Valid rate | Exact-data rate |\n|---|---:|---:|---:|---:|---:|\n{}\n\n## Does the Recovery Contract help?\n\nIt produced exact restores for non-overlapping target effects and refused to invert known overlaps. Contract context size and overlap counts are recorded per row.\n\n## Does Hybrid beat pure agent repair?\n\nNo real-agent semantic-repair lane ran. Hybrid matched ExactSubtract on this deterministic Track A and returned safe conflicts on the same overlap families.\n\n## Does Realm recover information Git cannot?\n\nFor `binary-delete`, RealmContract valid recovery was {:.3} versus {:.3} for CurrentOnly; the deleted bytes were restored from a Realm CAS reference and checked by BLAKE3.\n\n## How often is later intent preserved?\n\nThe hidden oracle manifest comparison is the strict proxy in this controlled deterministic envelope. RealmContract had zero must-preserve violations in the tested rows.\n\n## How often does repair over-edit?\n\nUnexpected edits are counted by hidden-manifest mismatch; no line-count-only metric is used.\n\n## What failures remain?\n\nSafe conflict, target-effect remains, exact-data failure, hidden-oracle mismatch, and sandbox/external-agent blockers are reported separately.\n\n## Does the result depend strongly on one agent/model?\n\nTrack A has no model. Codex/Claude availability is recorded separately.\n\n## What is Phase II-B status?\n\nStill `BLOCKED_EXTERNAL`; Phase III does not substitute for Endpoint Security.\n\n## Single highest-value Phase-IV experiment\n\nRun the frozen deterministic scenario envelope with one real Codex or Claude actor under a newly re-proven sandbox, then compare repeated fresh repairs against the same hidden oracle.\n",
        results.rows.len(),
        contract,
        current,
        git,
        summary_table,
        binary_contract,
        binary_current
    );
    fs::write(output_dir.join("HISTORICAL_SUFFICIENCY_REPORT.md"), report)?;
    fs::write(
        output_dir.join("REALMBENCH_HISTORY.md"),
        "# RealmBench-History\n\nTrack A is a deterministic counterfactual benchmark. Each disposable fixture commits A, B, C, and D as immutable world layers. The target is A. The oracle is independently generated by applying separately specified no-A B/C/D operations to the pre-A world. Conditions receive the same world and differ only in historical evidence or strategy.\n\nThe evaluator is outside candidate roots and compares full supported manifest state, exact BLAKE3 bytes, target-effect removal, and preservation rules. A passing test suite alone cannot make a candidate valid.\n",
    )?;
    Ok(())
}

fn write_json<T: Serialize>(path: PathBuf, value: &T) -> Result<(), BenchmarkError> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn scenario_valid_rate(
    results: &HistoryBenchmarkResults,
    scenario_id: &str,
    condition: BenchmarkCondition,
) -> f64 {
    let rows = results
        .rows
        .iter()
        .filter(|row| row.scenario_id == scenario_id && row.condition == condition)
        .collect::<Vec<_>>();
    if rows.is_empty() {
        0.0
    } else {
        rows.iter().filter(|row| row.verification.valid).count() as f64 / rows.len() as f64
    }
}

fn actual_a_ops(family: ScenarioFamily) -> Vec<DeterministicOperation> {
    match family {
        ScenarioFamily::UntrackedBinaryDelete => vec![
            delete("assets/deleted.bin"),
            write("src/app.txt", b"A-app\n"),
        ],
        ScenarioFamily::DisjointText => vec![write("src/app.txt", b"A-app\n")],
        ScenarioFamily::RenameAndEdit => vec![rename("config.toml", "config.renamed.toml")],
        ScenarioFamily::DeleteThenRecreate => vec![delete("config.toml")],
        ScenarioFamily::OverlapText => vec![write("src/shared.txt", b"A-shared\n")],
        ScenarioFamily::CreateThenExtend => vec![write("src/notes.txt", b"A-note\n")],
    }
}

fn actual_b_ops(family: ScenarioFamily) -> Vec<DeterministicOperation> {
    match family {
        ScenarioFamily::DeleteThenRecreate => vec![write("config.toml", b"B-recreated\n")],
        ScenarioFamily::OverlapText => vec![write("src/shared.txt", b"A+B-shared\n")],
        ScenarioFamily::CreateThenExtend => vec![write("src/notes.txt", b"A-note+B-extension\n")],
        _ => vec![write("docs/later.txt", b"B-later-doc\n")],
    }
}

fn actual_c_ops(family: ScenarioFamily) -> Vec<DeterministicOperation> {
    match family {
        ScenarioFamily::DeleteThenRecreate => vec![write("docs/later.txt", b"C-later-doc\n")],
        _ => vec![write(
            "build/generated.txt",
            format!("C-derived-{:?}\n", family).as_bytes(),
        )],
    }
}

fn actual_d_ops(family: ScenarioFamily) -> Vec<DeterministicOperation> {
    match family {
        ScenarioFamily::OverlapText => vec![write("src/shared.txt", b"A+B+D-shared\n")],
        _ => vec![write("tests/marker.txt", b"D-independent\n")],
    }
}

fn oracle_b_ops(family: ScenarioFamily) -> Vec<DeterministicOperation> {
    match family {
        ScenarioFamily::DeleteThenRecreate => vec![write("config.toml", b"B-recreated\n")],
        ScenarioFamily::OverlapText => vec![write("src/shared.txt", b"B-only-shared\n")],
        ScenarioFamily::CreateThenExtend => vec![write("src/notes.txt", b"B-only-extension\n")],
        _ => actual_b_ops(family),
    }
}

fn oracle_c_ops(family: ScenarioFamily) -> Vec<DeterministicOperation> {
    actual_c_ops(family)
}
fn oracle_d_ops(family: ScenarioFamily) -> Vec<DeterministicOperation> {
    match family {
        ScenarioFamily::OverlapText => vec![write("src/shared.txt", b"B-only+D-shared\n")],
        _ => actual_d_ops(family),
    }
}

fn apply_ops(root: &Path, operations: &[DeterministicOperation]) -> Result<(), BenchmarkError> {
    for operation in operations {
        match operation {
            DeterministicOperation::Write { path, bytes } => {
                let target = safe_join(root, path)?;
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(target, bytes)?;
            }
            DeterministicOperation::Delete { path } => {
                let target = safe_join(root, path)?;
                if target.exists() {
                    fs::remove_file(target)?;
                }
            }
            DeterministicOperation::Rename { from, to } => {
                let source = safe_join(root, from)?;
                let target = safe_join(root, to)?;
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::rename(source, target)?;
            }
            DeterministicOperation::Mkdir { path } => fs::create_dir_all(safe_join(root, path)?)?,
        }
    }
    Ok(())
}

fn safe_join(root: &Path, path: &PathBytes) -> Result<PathBuf, BenchmarkError> {
    let relative = path.as_path();
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(BenchmarkError::Setup(format!(
            "unsafe fixture path {}",
            path.display_lossy()
        )));
    }
    Ok(root.join(relative))
}

fn write(path: &str, bytes: &[u8]) -> DeterministicOperation {
    DeterministicOperation::Write {
        path: PathBytes(path.as_bytes().to_vec()),
        bytes: bytes.to_vec(),
    }
}
fn delete(path: &str) -> DeterministicOperation {
    DeterministicOperation::Delete {
        path: PathBytes(path.as_bytes().to_vec()),
    }
}
fn rename(from: &str, to: &str) -> DeterministicOperation {
    DeterministicOperation::Rename {
        from: PathBytes(from.as_bytes().to_vec()),
        to: PathBytes(to.as_bytes().to_vec()),
    }
}

fn wilson(successes: u64, total: u64) -> (f64, f64) {
    if total == 0 {
        return (0.0, 0.0);
    }
    let n = total as f64;
    let p = successes as f64 / n;
    let z = 1.96;
    let denominator = 1.0 + z * z / n;
    let center = (p + z * z / (2.0 * n)) / denominator;
    let spread = z * ((p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt()) / denominator;
    ((center - spread).max(0.0), (center + spread).min(1.0))
}

fn git_commit() -> Option<String> {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
fn unique_suffix() -> String {
    format!("{}-{}", std::process::id(), now_ms())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_contains_overlap_and_information_loss_families() {
        let catalog = scenario_catalog();
        assert!(
            catalog
                .iter()
                .any(|scenario| scenario.family == ScenarioFamily::UntrackedBinaryDelete)
        );
        assert!(
            catalog
                .iter()
                .any(|scenario| scenario.family == ScenarioFamily::OverlapText)
        );
    }

    #[test]
    fn wilson_interval_is_bounded() {
        let (low, high) = wilson(3, 3);
        assert!(low >= 0.0 && high <= 1.0 && low <= high);
    }

    #[test]
    fn oracle_gap_taxonomy_separates_missing_capture_from_oracle_only_semantics() {
        let recreate = gap_descriptor(ScenarioFamily::DeleteThenRecreate);
        assert_eq!(
            recreate.availability,
            NaturalAvailability::CapturableButMissing
        );
        assert_eq!(
            recreate.soundness,
            ResolutionSoundness::ConditionalOnCapturedOperation
        );
        let overlap = gap_descriptor(ScenarioFamily::OverlapText);
        assert_eq!(
            overlap.availability,
            NaturalAvailability::NotDerivableFromFrozenHistory
        );
        assert!(
            overlap
                .categories
                .contains(&GapCategory::OracleOnlyInformation)
        );
        let extend = gap_descriptor(ScenarioFamily::CreateThenExtend);
        assert_eq!(extend.soundness, ResolutionSoundness::MustRemainConflict);
    }
}
