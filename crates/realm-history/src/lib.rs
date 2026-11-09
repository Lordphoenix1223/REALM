//! History compilation and deterministic post-commit reconstruction.
//!
//! The compiler turns immutable transaction layers into a bounded
//! RecoveryContractV2. ExactSubtract is intentionally mechanical. ForwardReplay
//! re-applies later deterministic deltas from the pre-target world and is
//! labelled replay rather than byte-exact restoration. Ambiguous overlap is a
//! safe conflict, never an invitation to silently overwrite later state.

use realm_core::{
    EvidenceClass, EvidenceConfidence, KnownUnknown, ObservationCompleteness, PathBytes,
    RecordedOperationKind, UnknownReasonCode,
};
use realm_world::{
    CandidateWorldId, DeltaEntry, ManifestEntry, TransactionLayer, TransactionLayerId, WorldError,
    WorldHead, WorldHeadId, WorldManifest, WorldManifestId, WorldStore,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum HistoricalEvidenceKind {
    ExplicitRead,
    AgentDeclaredRead,
    ServerObservedRead,
    SharedObjectInteraction,
    CounterfactuallySupported,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum AllowedDifferenceKind {
    TargetDirectEffect,
    HistoricalExactRestore,
    KnownOverlap,
    KnownDependentOutput,
    ExplicitRepairScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreservationRule {
    pub path: PathBytes,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExactRestore {
    pub path: PathBytes,
    pub before: Option<ManifestEntry>,
    pub source_blob_hash: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OverlapRecord {
    pub path: PathBytes,
    pub target_before: Option<ManifestEntry>,
    pub target_after: Option<ManifestEntry>,
    pub later_layers: Vec<TransactionLayerId>,
    pub target_intent: String,
    pub later_intents: Vec<String>,
    pub evidence: HistoricalEvidenceKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryContractV2 {
    pub schema_version: u16,
    pub today_head: WorldHeadId,
    pub target_layer: TransactionLayerId,
    pub target_intent: String,
    pub must_preserve: Vec<PreservationRule>,
    pub must_not_modify: Vec<PreservationRule>,
    pub may_modify: Vec<PreservationRule>,
    pub allowed_differences: Vec<AllowedDifferenceKind>,
    pub exact_restores: Vec<ExactRestore>,
    pub overlaps: Vec<OverlapRecord>,
    pub known_unknowns: Vec<String>,
    pub evidence: BTreeMap<String, HistoricalEvidenceKind>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelevantHistoryIndex {
    pub target_layer: TransactionLayerId,
    pub touched_paths: Vec<(PathBytes, Vec<TransactionLayerId>)>,
    pub later_intents: Vec<String>,
    pub package_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompiledHistory {
    pub contract: RecoveryContractV2,
    pub index: RelevantHistoryIndex,
    pub target: TransactionLayer,
    pub later_layers: Vec<TransactionLayer>,
    pub context_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum RecoveryStrategy {
    SnapshotRollback,
    ExactSubtract,
    ForwardReplay,
    SemanticRepair,
    HybridRepair,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum RecoveryStatus {
    CandidateReady,
    SafeConflict,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryResult {
    pub candidate_world: CandidateWorldId,
    pub source_today: WorldHeadId,
    pub strategy: RecoveryStrategy,
    pub status: RecoveryStatus,
    pub candidate_manifest_hash: String,
    pub changed_paths: Vec<PathBytes>,
    pub conflict_paths: Vec<PathBytes>,
    pub contract: RecoveryContractV2,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HistoryViewId(pub String);

impl std::fmt::Display for HistoryViewId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum HistoryEdit {
    Remove(TransactionLayerId),
    Replace {
        target: TransactionLayerId,
        replacement: TransactionLayerId,
    },
}

impl HistoryEdit {
    pub fn target(&self) -> TransactionLayerId {
        match self {
            Self::Remove(target) | Self::Replace { target, .. } => *target,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ReconstructionPlanStatus {
    Ready,
    Conflict,
    Impossible,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ReconstructionConflictKind {
    StateOverlap,
    ReplacementParentMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReconstructionConflict {
    pub kind: ReconstructionConflictKind,
    pub path: Option<PathBytes>,
    pub layers: Vec<TransactionLayerId>,
    pub evidence: EvidenceClass,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReconstructionAction {
    MaterializeParent(WorldHeadId),
    OmitObserved(TransactionLayerId),
    ApplyReplacement(TransactionLayerId),
    ReplayRecordedDelta(TransactionLayerId),
    ReuseObservedLayer {
        layer: TransactionLayerId,
        evidence: ActionEvidence,
    },
    ReplayRecordedOperation {
        layer: TransactionLayerId,
        evidence: ActionEvidence,
    },
    VerifyExactRejoin {
        observed_head: WorldHeadId,
        semantic_hash: String,
        evidence: ActionEvidence,
    },
    ReuseObservedSuffix {
        from_head: WorldHeadId,
        layers: Vec<TransactionLayerId>,
        evidence: ActionEvidence,
    },
    Conflict(ReconstructionConflict),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionEvidence {
    pub class: EvidenceClass,
    pub strength: EvidenceConfidence,
    pub evidence_refs: Vec<String>,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayFrontier {
    pub later_transactions: usize,
    pub reconsidered: usize,
    pub reused_exactly: usize,
    pub replayed_recorded_operations: usize,
    pub adapter_rebased: usize,
    pub semantic_repaired: usize,
    pub conflicted: usize,
    pub reused_after_rejoin: usize,
    pub exact_rejoin_head: Option<WorldHeadId>,
}

impl ReplayFrontier {
    pub fn replay_fraction(&self) -> f64 {
        if self.later_transactions == 0 {
            0.0
        } else {
            (self.replayed_recorded_operations + self.semantic_repaired) as f64
                / self.later_transactions as f64
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReconstructionPolicy {
    pub schema_version: u16,
    pub allow_recorded_operation_replay: bool,
    pub require_complete_observations_for_reuse: bool,
    pub allow_exact_rejoin: bool,
}

impl ReconstructionPolicy {
    pub const SCHEMA_VERSION: u16 = 1;

    pub fn phase4_safe() -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            allow_recorded_operation_replay: true,
            require_complete_observations_for_reuse: true,
            allow_exact_rejoin: true,
        }
    }
}

impl Default for ReconstructionPolicy {
    fn default() -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            allow_recorded_operation_replay: false,
            require_complete_observations_for_reuse: false,
            allow_exact_rejoin: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReconstructionPlan {
    pub schema_version: u16,
    pub source_head: WorldHeadId,
    pub observed_history: Vec<TransactionLayerId>,
    pub edit: HistoryEdit,
    pub history_view: HistoryViewId,
    pub base_head: WorldHeadId,
    pub status: ReconstructionPlanStatus,
    pub actions: Vec<ReconstructionAction>,
    pub conflicts: Vec<ReconstructionConflict>,
    pub known_unknowns: Vec<KnownUnknown>,
    #[serde(default)]
    pub policy: ReconstructionPolicy,
    #[serde(default)]
    pub replay_frontier: ReplayFrontier,
}

impl ReconstructionPlan {
    pub const SCHEMA_VERSION: u16 = 2;

    pub fn canonical_hash(&self) -> Result<String, serde_json::Error> {
        Ok(blake3::hash(&serde_json::to_vec(self)?)
            .to_hex()
            .to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReconstructionResult {
    pub schema_version: u16,
    pub source_head: WorldHeadId,
    pub history_view: HistoryViewId,
    pub candidate_world: CandidateWorldId,
    pub candidate_manifest_hash: String,
    pub applied_layers: Vec<TransactionLayerId>,
}

#[derive(Debug, Error)]
pub enum HistoryPlanError {
    #[error("target transaction layer is not in the observed history")]
    TargetNotFound,
    #[error("replacement transaction layer is not available")]
    ReplacementNotFound,
    #[error("observed history does not terminate at the declared source head")]
    SourceHeadMismatch,
    #[error("world manifest is not available to the pure planner: {0}")]
    ManifestNotFound(WorldManifestId),
    #[error("history edit serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryBudget {
    pub max_metadata_items: usize,
    pub max_historical_versions: usize,
    pub max_raw_diff_bytes: usize,
}

impl Default for HistoryBudget {
    fn default() -> Self {
        Self {
            max_metadata_items: 256,
            max_historical_versions: 1024,
            max_raw_diff_bytes: 256 * 1024,
        }
    }
}

#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("world error: {0}")]
    World(#[from] WorldError),
    #[error("history serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("target transaction layer is not in the world history")]
    TargetNotFound,
    #[error("history budget exceeded: {0}")]
    BudgetExceeded(String),
    #[error("history-edit planning failed: {0}")]
    Plan(#[from] HistoryPlanError),
    #[error("reconstruction plan is not executable: {0:?}")]
    PlanNotExecutable(ReconstructionPlanStatus),
    #[error("reconstruction plan no longer matches immutable source history")]
    StalePlan,
    #[error("exact rejoin failed: expected {expected}, observed {observed}")]
    RejoinMismatch { expected: String, observed: String },
}

pub struct HistoryCompiler {
    budget: HistoryBudget,
}

impl HistoryCompiler {
    pub fn new(budget: HistoryBudget) -> Self {
        Self { budget }
    }

    pub fn compile(
        &self,
        store: &WorldStore,
        today: WorldHeadId,
        target: TransactionLayerId,
    ) -> Result<CompiledHistory, HistoryError> {
        let history = store.history(today)?;
        let target_position = history
            .iter()
            .position(|layer| layer.id == target)
            .ok_or(HistoryError::TargetNotFound)?;
        let target_layer = history[target_position].clone();
        let later_layers = history[target_position + 1..].to_vec();
        let today_manifest = store.manifest(store.head(today)?.manifest)?;
        let target_paths: BTreeSet<PathBytes> = target_layer
            .delta
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        let later_paths: BTreeMap<PathBytes, Vec<&TransactionLayer>> = later_layers
            .iter()
            .flat_map(|layer| {
                layer
                    .delta
                    .iter()
                    .map(move |entry| (entry.path.clone(), layer))
            })
            .fold(BTreeMap::new(), |mut map, (path, layer)| {
                map.entry(path).or_default().push(layer);
                map
            });

        let mut must_preserve = Vec::new();
        let mut must_not_modify = Vec::new();
        let mut may_modify = Vec::new();
        let mut exact_restores = Vec::new();
        let mut overlaps = Vec::new();
        for path in today_manifest.entries.keys() {
            if !target_paths.contains(path) {
                let rule = PreservationRule {
                    path: path.clone(),
                    reason: "Default-preserve: current world state is protected unless the target contract proves an allowed difference.".into(),
                };
                must_preserve.push(rule.clone());
                must_not_modify.push(rule);
            }
        }
        for delta in &target_layer.delta {
            let later = later_paths.get(&delta.path).cloned().unwrap_or_default();
            if later.is_empty() {
                may_modify.push(PreservationRule {
                    path: delta.path.clone(),
                    reason: "Direct effect of the removed target transaction.".into(),
                });
                let source_blob_hash = delta
                    .before
                    .as_ref()
                    .and_then(|entry| entry.content_ref.as_ref().map(|blob| blob.hash.clone()));
                exact_restores.push(ExactRestore {
                    path: delta.path.clone(),
                    before: delta.before.clone(),
                    source_blob_hash,
                    reason: format!("Exact inverse of target delta {:?}.", delta.kind),
                });
            } else {
                may_modify.push(PreservationRule {
                    path: delta.path.clone(),
                    reason:
                        "Target/later overlap requires semantic reconstruction or safe conflict."
                            .into(),
                });
                overlaps.push(OverlapRecord {
                    path: delta.path.clone(),
                    target_before: delta.before.clone(),
                    target_after: delta.after.clone(),
                    later_layers: later.iter().map(|layer| layer.id).collect(),
                    target_intent: target_layer.raw_intent().to_owned(),
                    later_intents: later
                        .iter()
                        .map(|layer| layer.raw_intent().to_owned())
                        .collect(),
                    evidence: HistoricalEvidenceKind::Unknown,
                });
            }
        }
        must_preserve.sort_by(|a, b| a.path.cmp(&b.path));
        must_not_modify.sort_by(|a, b| a.path.cmp(&b.path));
        may_modify.sort_by(|a, b| a.path.cmp(&b.path));
        exact_restores.sort_by(|a, b| a.path.cmp(&b.path));
        overlaps.sort_by(|a, b| a.path.cmp(&b.path));
        if exact_restores.len() > self.budget.max_historical_versions {
            return Err(HistoryError::BudgetExceeded("exact restore count".into()));
        }
        let mut touched_paths = BTreeMap::new();
        for layer in history.iter().take(self.budget.max_historical_versions) {
            for delta in &layer.delta {
                touched_paths
                    .entry(delta.path.clone())
                    .or_insert_with(Vec::new)
                    .push(layer.id);
            }
        }
        let later_intents = later_layers
            .iter()
            .map(|layer| layer.raw_intent().to_owned())
            .collect::<Vec<_>>();
        let touched_paths = touched_paths.into_iter().collect::<Vec<_>>();
        let index_bytes = serde_json::to_vec(&(&touched_paths, &later_intents))?;
        let index = RelevantHistoryIndex {
            target_layer: target,
            touched_paths,
            later_intents,
            package_hash: blake3::hash(&index_bytes).to_hex().to_string(),
        };
        let contract = RecoveryContractV2 {
            schema_version: 2,
            today_head: today,
            target_layer: target,
            target_intent: target_layer.raw_intent().to_owned(),
            must_preserve,
            must_not_modify,
            may_modify,
            allowed_differences: vec![
                AllowedDifferenceKind::TargetDirectEffect,
                AllowedDifferenceKind::HistoricalExactRestore,
                AllowedDifferenceKind::KnownOverlap,
            ],
            exact_restores,
            overlaps,
            known_unknowns: Vec::new(),
            evidence: BTreeMap::new(),
        };
        let context_bytes =
            serde_json::to_vec(&contract)?.len() + serde_json::to_vec(&index)?.len();
        if context_bytes > self.budget.max_raw_diff_bytes {
            return Err(HistoryError::BudgetExceeded(
                "compiled context bytes".into(),
            ));
        }
        Ok(CompiledHistory {
            contract,
            index,
            target: target_layer,
            later_layers,
            context_bytes,
        })
    }
}

/// Compile an immutable counterfactual view without mutating observed history.
/// This planner is pure over immutable layer metadata and supports only the
/// deterministic controlled-world subset. Any target/later state overlap is a
/// first-class conflict because path overlap does not prove intent replay is
/// safe.
pub fn plan_history_edit(
    source_head: WorldHeadId,
    observed_history: &[TransactionLayer],
    edit: HistoryEdit,
    available_layers: &BTreeMap<TransactionLayerId, TransactionLayer>,
) -> Result<ReconstructionPlan, HistoryPlanError> {
    if observed_history.last().map(|layer| layer.result_head) != Some(source_head) {
        return Err(HistoryPlanError::SourceHeadMismatch);
    }
    let target_position = observed_history
        .iter()
        .position(|layer| layer.id == edit.target())
        .ok_or(HistoryPlanError::TargetNotFound)?;
    let target = &observed_history[target_position];
    let replacement = match &edit {
        HistoryEdit::Remove(_) => None,
        HistoryEdit::Replace { replacement, .. } => Some(
            available_layers
                .get(replacement)
                .or_else(|| {
                    observed_history
                        .iter()
                        .find(|layer| layer.id == *replacement)
                })
                .ok_or(HistoryPlanError::ReplacementNotFound)?,
        ),
    };
    let observed_ids = observed_history
        .iter()
        .map(|layer| layer.id)
        .collect::<Vec<_>>();
    let view_material = serde_json::to_vec(&(
        ReconstructionPlan::SCHEMA_VERSION,
        source_head,
        observed_history,
        &edit,
        replacement,
    ))?;
    let history_view = HistoryViewId(blake3::hash(&view_material).to_hex().to_string());
    let mut actions = vec![
        ReconstructionAction::MaterializeParent(target.parent_head),
        ReconstructionAction::OmitObserved(target.id),
    ];
    let mut conflicts = Vec::new();
    let mut known_unknowns = Vec::new();
    let mut footprint = target
        .delta
        .iter()
        .map(|delta| delta.path.clone())
        .collect::<BTreeSet<_>>();
    if let Some(replacement) = replacement {
        actions.push(ReconstructionAction::ApplyReplacement(replacement.id));
        footprint.extend(replacement.delta.iter().map(|delta| delta.path.clone()));
        if replacement.parent_manifest != target.parent_manifest {
            conflicts.push(ReconstructionConflict {
                kind: ReconstructionConflictKind::ReplacementParentMismatch,
                path: None,
                layers: vec![target.id, replacement.id],
                evidence: EvidenceClass::PreservedState,
                detail: "Replacement was not committed against the target's parent manifest."
                    .into(),
            });
        }
    }
    let later_layers = &observed_history[target_position + 1..];
    let mut overlap_layers = BTreeSet::new();
    for layer in later_layers {
        for delta in &layer.delta {
            if footprint.contains(&delta.path) {
                overlap_layers.insert(layer.id);
                conflicts.push(ReconstructionConflict {
                    kind: ReconstructionConflictKind::StateOverlap,
                    path: Some(delta.path.clone()),
                    layers: vec![target.id, layer.id],
                    evidence: EvidenceClass::StateOverlap,
                    detail: "A later transaction touches the edited transaction footprint; recorded bytes do not establish intent independence.".into(),
                });
            }
        }
    }
    conflicts.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.layers.cmp(&right.layers))
    });
    conflicts.dedup();
    for layer in later_layers {
        if !overlap_layers.contains(&layer.id) {
            actions.push(ReconstructionAction::ReplayRecordedDelta(layer.id));
        }
    }
    for conflict in &conflicts {
        actions.push(ReconstructionAction::Conflict(conflict.clone()));
        known_unknowns.push(KnownUnknown {
            code: if conflict.kind == ReconstructionConflictKind::StateOverlap {
                UnknownReasonCode::SemanticConflict
            } else {
                UnknownReasonCode::HistoricalInputMissing
            },
            detail: conflict.detail.clone(),
            evidence_ref: conflict.path.as_ref().map(PathBytes::display_lossy),
        });
    }
    let status = if conflicts
        .iter()
        .any(|conflict| conflict.kind == ReconstructionConflictKind::ReplacementParentMismatch)
    {
        ReconstructionPlanStatus::Impossible
    } else if conflicts.is_empty() {
        ReconstructionPlanStatus::Ready
    } else {
        ReconstructionPlanStatus::Conflict
    };
    Ok(ReconstructionPlan {
        schema_version: ReconstructionPlan::SCHEMA_VERSION,
        source_head,
        observed_history: observed_ids,
        edit,
        history_view,
        base_head: target.parent_head,
        status,
        actions,
        conflicts,
        known_unknowns,
        policy: ReconstructionPolicy::default(),
        replay_frontier: ReplayFrontier::default(),
    })
}

/// Plan a prospective semantic history rewrite using only immutable history,
/// manifests, and evidence captured before the rewrite request. This planner
/// never consults a benchmark oracle and never treats state overlap as causal
/// proof. It can reuse a recorded layer only when complete read observations
/// prove that the layer was insulated from the counterfactual difference, or
/// replay an overlapping write only when a prospectively captured,
/// deterministic operation covers it.
pub fn plan_history_rewrite(
    source_head: WorldHeadId,
    observed_history: &[TransactionLayer],
    edit: HistoryEdit,
    available_layers: &BTreeMap<TransactionLayerId, TransactionLayer>,
    manifests: &BTreeMap<WorldManifestId, WorldManifest>,
    policy: ReconstructionPolicy,
) -> Result<ReconstructionPlan, HistoryPlanError> {
    if observed_history.last().map(|layer| layer.result_head) != Some(source_head) {
        return Err(HistoryPlanError::SourceHeadMismatch);
    }
    let target_position = observed_history
        .iter()
        .position(|layer| layer.id == edit.target())
        .ok_or(HistoryPlanError::TargetNotFound)?;
    let target = &observed_history[target_position];
    let replacement = match &edit {
        HistoryEdit::Remove(_) => None,
        HistoryEdit::Replace { replacement, .. } => Some(
            available_layers
                .get(replacement)
                .or_else(|| {
                    observed_history
                        .iter()
                        .find(|layer| layer.id == *replacement)
                })
                .ok_or(HistoryPlanError::ReplacementNotFound)?,
        ),
    };
    let observed_ids = observed_history
        .iter()
        .map(|layer| layer.id)
        .collect::<Vec<_>>();
    let view_material = serde_json::to_vec(&(
        ReconstructionPlan::SCHEMA_VERSION,
        source_head,
        observed_history,
        &edit,
        replacement,
        &policy,
    ))?;
    let history_view = HistoryViewId(blake3::hash(&view_material).to_hex().to_string());
    let parent_manifest = manifests
        .get(&target.parent_manifest)
        .ok_or(HistoryPlanError::ManifestNotFound(target.parent_manifest))?;
    let mut candidate_entries = parent_manifest.entries.clone();
    let mut actions = vec![
        ReconstructionAction::MaterializeParent(target.parent_head),
        ReconstructionAction::OmitObserved(target.id),
    ];
    let mut conflicts = Vec::new();
    let mut known_unknowns = Vec::new();

    if let Some(replacement) = replacement {
        actions.push(ReconstructionAction::ApplyReplacement(replacement.id));
        if replacement.parent_manifest != target.parent_manifest {
            conflicts.push(ReconstructionConflict {
                kind: ReconstructionConflictKind::ReplacementParentMismatch,
                path: None,
                layers: vec![target.id, replacement.id],
                evidence: EvidenceClass::PreservedState,
                detail: "Replacement was not committed against the target's parent manifest."
                    .into(),
            });
        } else {
            fold_delta(&mut candidate_entries, &replacement.delta);
        }
    }

    let later_layers = &observed_history[target_position + 1..];
    let mut replay_frontier = ReplayFrontier {
        later_transactions: later_layers.len(),
        ..ReplayFrontier::default()
    };
    if conflicts.is_empty() {
        for (position, layer) in later_layers.iter().enumerate() {
            let original_parent = manifests
                .get(&layer.parent_manifest)
                .ok_or(HistoryPlanError::ManifestNotFound(layer.parent_manifest))?;
            let candidate = WorldManifest::new(candidate_entries.clone());
            if policy.allow_exact_rejoin && candidate.semantic_hash == original_parent.semantic_hash
            {
                let suffix = later_layers[position..]
                    .iter()
                    .map(|suffix_layer| suffix_layer.id)
                    .collect::<Vec<_>>();
                actions.push(ReconstructionAction::VerifyExactRejoin {
                    observed_head: layer.parent_head,
                    semantic_hash: original_parent.semantic_hash.clone(),
                    evidence: exact_rejoin_evidence(layer.parent_manifest),
                });
                if !suffix.is_empty() {
                    actions.push(ReconstructionAction::ReuseObservedSuffix {
                        from_head: layer.parent_head,
                        layers: suffix.clone(),
                        evidence: ActionEvidence {
                            class: EvidenceClass::PreservedState,
                            strength: EvidenceConfidence::Proven,
                            evidence_refs: vec![layer.parent_manifest.to_string()],
                            detail: "The full supported semantic state exactly rejoined immutable observed history; the remaining suffix is reused byte-for-byte."
                                .into(),
                        },
                    });
                }
                replay_frontier.exact_rejoin_head = Some(layer.parent_head);
                replay_frontier.reused_after_rejoin += suffix.len();
                break;
            }

            replay_frontier.reconsidered += 1;
            let difference_frontier =
                semantic_difference_paths(&candidate_entries, &original_parent.entries);
            let capsule = layer.transaction_capsule();
            let reads = capsule
                .observations
                .reads
                .iter()
                .map(|observation| observation.path.clone())
                .collect::<BTreeSet<_>>();
            let writes = layer
                .delta
                .iter()
                .map(|delta| delta.path.clone())
                .collect::<BTreeSet<_>>();
            let read_overlap = reads
                .intersection(&difference_frontier)
                .cloned()
                .collect::<BTreeSet<_>>();
            let write_overlap = writes
                .intersection(&difference_frontier)
                .cloned()
                .collect::<BTreeSet<_>>();
            let complete = capsule.observations.completeness == ObservationCompleteness::Complete;
            let can_reuse = read_overlap.is_empty()
                && write_overlap.is_empty()
                && (complete || !policy.require_complete_observations_for_reuse);
            let can_replay_operation = policy.allow_recorded_operation_replay
                && complete
                && read_overlap.is_empty()
                && !write_overlap.is_empty()
                && write_overlap.iter().all(|path| {
                    capsule.operations.iter().any(|operation| {
                        operation.deterministic
                            && matches!(
                                operation.kind,
                                RecordedOperationKind::OverwritePath
                                    | RecordedOperationKind::DeletePath
                                    | RecordedOperationKind::RenamePath
                                    | RecordedOperationKind::CreateDirectory
                            )
                            && (operation.path == *path
                                || operation.destination.as_ref() == Some(path))
                    })
                });

            if can_reuse {
                actions.push(ReconstructionAction::ReuseObservedLayer {
                    layer: layer.id,
                    evidence: ActionEvidence {
                        class: EvidenceClass::OsObservation,
                        strength: EvidenceConfidence::Verified,
                        evidence_refs: vec![layer.id.to_string()],
                        detail: "Complete read observations and the recorded write set are disjoint from the counterfactual difference frontier."
                            .into(),
                    },
                });
                replay_frontier.reused_exactly += 1;
                fold_delta(&mut candidate_entries, &layer.delta);
            } else if can_replay_operation {
                actions.push(ReconstructionAction::ReplayRecordedOperation {
                    layer: layer.id,
                    evidence: ActionEvidence {
                        class: EvidenceClass::AgentDeclaration,
                        strength: EvidenceConfidence::Verified,
                        evidence_refs: capsule
                            .operations
                            .iter()
                            .filter(|operation| operation.deterministic)
                            .map(|operation| {
                                format!("{}:{:?}", operation.path.display_lossy(), operation.kind)
                            })
                            .collect(),
                        detail: "A prospectively captured deterministic operation covers every overlapping write, and complete observations show no changed read dependency."
                            .into(),
                    },
                });
                replay_frontier.replayed_recorded_operations += 1;
                fold_delta(&mut candidate_entries, &layer.delta);
            } else {
                let path = read_overlap
                    .iter()
                    .next()
                    .or_else(|| write_overlap.iter().next())
                    .or_else(|| difference_frontier.iter().next())
                    .cloned();
                let detail = if !complete && policy.require_complete_observations_for_reuse {
                    "A later transaction lacks a complete prospective read set, so independence from the counterfactual frontier is unproven."
                } else if !read_overlap.is_empty() {
                    "A later transaction read counterfactually changed state; no declared semantic adapter or deterministic intent replay is available."
                } else {
                    "A later transaction writes counterfactually changed state without a prospectively captured deterministic operation covering every overlap."
                };
                let conflict = ReconstructionConflict {
                    kind: ReconstructionConflictKind::StateOverlap,
                    path: path.clone(),
                    layers: vec![target.id, layer.id],
                    evidence: EvidenceClass::StateOverlap,
                    detail: detail.into(),
                };
                conflicts.push(conflict.clone());
                actions.push(ReconstructionAction::Conflict(conflict));
                known_unknowns.push(KnownUnknown {
                    code: UnknownReasonCode::SemanticConflict,
                    detail: detail.into(),
                    evidence_ref: path.as_ref().map(PathBytes::display_lossy),
                });
                replay_frontier.conflicted += 1;
                break;
            }

            let original_result = manifests
                .get(&layer.result_manifest)
                .ok_or(HistoryPlanError::ManifestNotFound(layer.result_manifest))?;
            let candidate = WorldManifest::new(candidate_entries.clone());
            if policy.allow_exact_rejoin && candidate.semantic_hash == original_result.semantic_hash
            {
                let suffix = later_layers[position + 1..]
                    .iter()
                    .map(|suffix_layer| suffix_layer.id)
                    .collect::<Vec<_>>();
                actions.push(ReconstructionAction::VerifyExactRejoin {
                    observed_head: layer.result_head,
                    semantic_hash: original_result.semantic_hash.clone(),
                    evidence: exact_rejoin_evidence(layer.result_manifest),
                });
                if !suffix.is_empty() {
                    actions.push(ReconstructionAction::ReuseObservedSuffix {
                        from_head: layer.result_head,
                        layers: suffix.clone(),
                        evidence: ActionEvidence {
                            class: EvidenceClass::PreservedState,
                            strength: EvidenceConfidence::Proven,
                            evidence_refs: vec![layer.result_manifest.to_string()],
                            detail: "The full supported semantic state exactly rejoined immutable observed history; the remaining suffix is reused byte-for-byte."
                                .into(),
                        },
                    });
                }
                replay_frontier.exact_rejoin_head = Some(layer.result_head);
                replay_frontier.reused_after_rejoin += suffix.len();
                break;
            }
        }
    }

    for conflict in &conflicts {
        if conflict.kind == ReconstructionConflictKind::ReplacementParentMismatch {
            actions.push(ReconstructionAction::Conflict(conflict.clone()));
            known_unknowns.push(KnownUnknown {
                code: UnknownReasonCode::HistoricalInputMissing,
                detail: conflict.detail.clone(),
                evidence_ref: None,
            });
        }
    }
    let status = if conflicts
        .iter()
        .any(|conflict| conflict.kind == ReconstructionConflictKind::ReplacementParentMismatch)
    {
        ReconstructionPlanStatus::Impossible
    } else if conflicts.is_empty() {
        ReconstructionPlanStatus::Ready
    } else {
        ReconstructionPlanStatus::Conflict
    };
    Ok(ReconstructionPlan {
        schema_version: ReconstructionPlan::SCHEMA_VERSION,
        source_head,
        observed_history: observed_ids,
        edit,
        history_view,
        base_head: target.parent_head,
        status,
        actions,
        conflicts,
        known_unknowns,
        policy,
        replay_frontier,
    })
}

fn exact_rejoin_evidence(manifest: WorldManifestId) -> ActionEvidence {
    ActionEvidence {
        class: EvidenceClass::PreservedState,
        strength: EvidenceConfidence::Proven,
        evidence_refs: vec![manifest.to_string()],
        detail: "Candidate and immutable observed history have the same full supported semantic manifest hash."
            .into(),
    }
}

fn fold_delta(entries: &mut BTreeMap<PathBytes, ManifestEntry>, delta: &[DeltaEntry]) {
    for entry in delta {
        match &entry.after {
            Some(after) => {
                entries.insert(entry.path.clone(), after.clone());
            }
            None => {
                entries.remove(&entry.path);
            }
        }
    }
}

fn semantic_difference_paths(
    left: &BTreeMap<PathBytes, ManifestEntry>,
    right: &BTreeMap<PathBytes, ManifestEntry>,
) -> BTreeSet<PathBytes> {
    left.keys()
        .chain(right.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|path| !semantic_entry_equal(left.get(path), right.get(path), path))
        .collect()
}

fn semantic_entry_equal(
    left: Option<&ManifestEntry>,
    right: Option<&ManifestEntry>,
    path: &PathBytes,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            let left = WorldManifest::new(BTreeMap::from([(path.clone(), left.clone())]));
            let right = WorldManifest::new(BTreeMap::from([(path.clone(), right.clone())]));
            left.semantic_hash == right.semantic_hash
        }
        _ => false,
    }
}

fn load_planning_manifests(
    store: &WorldStore,
    observed_history: &[TransactionLayer],
    available_layers: &BTreeMap<TransactionLayerId, TransactionLayer>,
) -> Result<BTreeMap<WorldManifestId, WorldManifest>, HistoryError> {
    let ids = observed_history
        .iter()
        .chain(available_layers.values())
        .flat_map(|layer| [layer.parent_manifest, layer.result_manifest])
        .collect::<BTreeSet<_>>();
    let mut manifests = BTreeMap::new();
    for id in ids {
        manifests.insert(id, store.manifest(id)?);
    }
    Ok(manifests)
}

pub struct RecoveryEngine<'a> {
    store: &'a WorldStore,
    compiler: HistoryCompiler,
}

impl<'a> RecoveryEngine<'a> {
    pub fn new(store: &'a WorldStore) -> Self {
        Self {
            store,
            compiler: HistoryCompiler::new(HistoryBudget::default()),
        }
    }

    pub fn with_compiler(store: &'a WorldStore, compiler: HistoryCompiler) -> Self {
        Self { store, compiler }
    }

    pub fn compile(
        &self,
        today: WorldHeadId,
        target: TransactionLayerId,
    ) -> Result<CompiledHistory, HistoryError> {
        self.compiler.compile(self.store, today, target)
    }

    pub fn plan_history_edit(
        &self,
        today: WorldHeadId,
        edit: HistoryEdit,
    ) -> Result<ReconstructionPlan, HistoryError> {
        let history = self.store.history(today)?;
        let mut available = BTreeMap::new();
        if let HistoryEdit::Replace { replacement, .. } = &edit {
            available.insert(*replacement, self.store.layer(*replacement)?);
        }
        Ok(plan_history_edit(today, &history, edit, &available)?)
    }

    pub fn plan_history_rewrite(
        &self,
        today: WorldHeadId,
        edit: HistoryEdit,
        policy: ReconstructionPolicy,
    ) -> Result<ReconstructionPlan, HistoryError> {
        let history = self.store.history(today)?;
        let mut available = BTreeMap::new();
        if let HistoryEdit::Replace { replacement, .. } = &edit {
            available.insert(*replacement, self.store.layer(*replacement)?);
        }
        let manifests = load_planning_manifests(self.store, &history, &available)?;
        Ok(plan_history_rewrite(
            today, &history, edit, &available, &manifests, policy,
        )?)
    }

    pub fn execute_reconstruction_plan(
        &self,
        plan: &ReconstructionPlan,
        destination: &Path,
    ) -> Result<ReconstructionResult, HistoryError> {
        if plan.status != ReconstructionPlanStatus::Ready {
            return Err(HistoryError::PlanNotExecutable(plan.status));
        }
        let history = self.store.history(plan.source_head)?;
        let mut available = BTreeMap::new();
        if let HistoryEdit::Replace { replacement, .. } = &plan.edit {
            available.insert(*replacement, self.store.layer(*replacement)?);
        }
        let rebuilt = if plan.policy == ReconstructionPolicy::default() {
            plan_history_edit(plan.source_head, &history, plan.edit.clone(), &available)?
        } else {
            let manifests = load_planning_manifests(self.store, &history, &available)?;
            plan_history_rewrite(
                plan.source_head,
                &history,
                plan.edit.clone(),
                &available,
                &manifests,
                plan.policy.clone(),
            )?
        };
        if rebuilt != *plan {
            return Err(HistoryError::StalePlan);
        }
        let materialized = self
            .store
            .materialize(plan.base_head, destination, "history-edit")?;
        let mut applied_layers = Vec::new();
        for action in &plan.actions {
            match action {
                ReconstructionAction::ApplyReplacement(layer)
                | ReconstructionAction::ReplayRecordedDelta(layer)
                | ReconstructionAction::ReuseObservedLayer { layer, .. }
                | ReconstructionAction::ReplayRecordedOperation { layer, .. } => {
                    let layer = self.store.layer(*layer)?;
                    apply_delta(self.store, &materialized.root, &layer.delta)?;
                    applied_layers.push(layer.id);
                }
                ReconstructionAction::VerifyExactRejoin { semantic_hash, .. } => {
                    let observed = self.store.snapshot_directory(&materialized.root, None)?;
                    if observed.semantic_hash != *semantic_hash {
                        return Err(HistoryError::RejoinMismatch {
                            expected: semantic_hash.clone(),
                            observed: observed.semantic_hash,
                        });
                    }
                }
                ReconstructionAction::ReuseObservedSuffix { layers, .. } => {
                    for layer in layers {
                        let layer = self.store.layer(*layer)?;
                        apply_delta(self.store, &materialized.root, &layer.delta)?;
                        applied_layers.push(layer.id);
                    }
                }
                ReconstructionAction::MaterializeParent(_)
                | ReconstructionAction::OmitObserved(_)
                | ReconstructionAction::Conflict(_) => {}
            }
        }
        let candidate = self.store.snapshot_directory(&materialized.root, None)?;
        Ok(ReconstructionResult {
            schema_version: 1,
            source_head: plan.source_head,
            history_view: plan.history_view.clone(),
            candidate_world: materialized.candidate,
            candidate_manifest_hash: candidate.semantic_hash,
            applied_layers,
        })
    }

    pub fn recover_into(
        &self,
        today: WorldHeadId,
        target: TransactionLayerId,
        strategy: RecoveryStrategy,
        destination: &Path,
    ) -> Result<RecoveryResult, HistoryError> {
        let compiled = self.compile(today, target)?;
        let materialized = match strategy {
            RecoveryStrategy::SnapshotRollback => {
                self.store
                    .materialize(compiled.target.parent_head, destination, "recovery")?
            }
            RecoveryStrategy::ExactSubtract
            | RecoveryStrategy::HybridRepair
            | RecoveryStrategy::SemanticRepair => {
                self.store.materialize(today, destination, "recovery")?
            }
            RecoveryStrategy::ForwardReplay => {
                let materialized =
                    self.store
                        .materialize(compiled.target.parent_head, destination, "recovery")?;
                for layer in &compiled.later_layers {
                    apply_delta(self.store, &materialized.root, &layer.delta)?;
                }
                materialized
            }
        };
        let mut conflict_paths = Vec::new();
        match strategy {
            RecoveryStrategy::ExactSubtract => {
                apply_exact_restores(
                    self.store,
                    &materialized.root,
                    &compiled.contract.exact_restores,
                )?;
                conflict_paths.extend(
                    compiled
                        .contract
                        .overlaps
                        .iter()
                        .map(|overlap| overlap.path.clone()),
                );
            }
            RecoveryStrategy::HybridRepair => {
                apply_exact_restores(
                    self.store,
                    &materialized.root,
                    &compiled.contract.exact_restores,
                )?;
                conflict_paths.extend(
                    compiled
                        .contract
                        .overlaps
                        .iter()
                        .map(|overlap| overlap.path.clone()),
                );
            }
            RecoveryStrategy::SemanticRepair => {
                conflict_paths.extend(
                    compiled
                        .contract
                        .overlaps
                        .iter()
                        .map(|overlap| overlap.path.clone()),
                );
            }
            RecoveryStrategy::SnapshotRollback | RecoveryStrategy::ForwardReplay => {}
        }
        let candidate_manifest = self.store.snapshot_directory(&materialized.root, None)?;
        let changed_paths = candidate_manifest.entries.keys().cloned().collect();
        Ok(RecoveryResult {
            candidate_world: materialized.candidate,
            source_today: today,
            strategy,
            status: if conflict_paths.is_empty() {
                RecoveryStatus::CandidateReady
            } else {
                RecoveryStatus::SafeConflict
            },
            candidate_manifest_hash: candidate_manifest.semantic_hash,
            changed_paths,
            conflict_paths,
            contract: compiled.contract,
        })
    }
}

fn apply_exact_restores(
    store: &WorldStore,
    root: &Path,
    restores: &[ExactRestore],
) -> Result<(), WorldError> {
    for restore in restores {
        match &restore.before {
            Some(entry) => store.write_manifest_entry(root, &restore.path, entry)?,
            None => store.remove_manifest_path(root, &restore.path)?,
        }
    }
    Ok(())
}

fn apply_delta(store: &WorldStore, root: &Path, delta: &[DeltaEntry]) -> Result<(), WorldError> {
    for entry in delta {
        match &entry.after {
            Some(after) => store.write_manifest_entry(root, &entry.path, after)?,
            None => store.remove_manifest_path(root, &entry.path)?,
        }
    }
    Ok(())
}

pub struct HistoryQuery<'a> {
    store: &'a WorldStore,
    head: WorldHead,
}

pub type PathHistoryEntry = (
    TransactionLayerId,
    Option<ManifestEntry>,
    Option<ManifestEntry>,
);

impl<'a> HistoryQuery<'a> {
    pub fn open(store: &'a WorldStore, head: WorldHeadId) -> Result<Self, HistoryError> {
        Ok(Self {
            store,
            head: store.head(head)?,
        })
    }

    pub fn path_history(&self, path: &PathBytes) -> Result<Vec<PathHistoryEntry>, HistoryError> {
        let mut result = Vec::new();
        for layer_id in &self.head.layers {
            let layer = self.store.layer(*layer_id)?;
            for delta in &layer.delta {
                if &delta.path == path {
                    result.push((layer.id, delta.before.clone(), delta.after.clone()));
                }
            }
        }
        Ok(result)
    }

    pub fn intents(&self) -> Result<Vec<(TransactionLayerId, String, String)>, HistoryError> {
        self.head
            .layers
            .iter()
            .map(|id| {
                self.store
                    .layer(*id)
                    .map(|layer| {
                        (
                            layer.id,
                            layer.actor_id().to_owned(),
                            layer.raw_intent().to_owned(),
                        )
                    })
                    .map_err(HistoryError::from)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use realm_core::{
        ActorIdentity, ActorKind, IntentContract, ObservationSet, ObservationVersion,
        RecordedOperation, TransactionCapsule, TransactionId, WorldReference,
    };
    use std::{collections::BTreeMap, fs, path::PathBuf};

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("realm-history-{name}-{}", std::process::id()))
    }

    fn prospective_capsule(
        store: &WorldStore,
        parent: WorldHeadId,
        intent: &str,
        reads: &[&str],
        operations: Vec<RecordedOperation>,
    ) -> TransactionCapsule {
        let parent_id = store
            .history(parent)
            .unwrap()
            .last()
            .map(|layer| layer.transaction_capsule().id);
        let mut capsule = TransactionCapsule::new(
            TransactionId::new(),
            parent_id,
            ActorIdentity {
                kind: ActorKind::System,
                actor_id: "phase4-test".into(),
                semantic_session_id: None,
                declared_intent: Some(intent.into()),
            },
            IntentContract::from_raw(intent),
        );
        capsule.parent_world = Some(WorldReference::new(
            "realm-controlled-world-head",
            parent.to_string(),
        ));
        capsule.observations = ObservationSet {
            completeness: ObservationCompleteness::Complete,
            reads: reads
                .iter()
                .map(|path| ObservationVersion {
                    path: PathBytes::from(Path::new(path)),
                    state_hash: None,
                    evidence: EvidenceClass::OsObservation,
                })
                .collect(),
        };
        capsule.operations = operations;
        capsule
    }

    #[test]
    fn compiler_recovers_untracked_deleted_bytes_and_preserves_later_state() {
        let root = temp("exact");
        let source = root.join("source");
        let store_root = root.join("store");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("keep.txt"), b"base").unwrap();
        fs::write(source.join("lost.bin"), [0, 1, 2, 3, 255]).unwrap();
        let store = WorldStore::open(&store_root).unwrap();
        let base = store.import("fixture", &source).unwrap();
        let a_workspace = root.join("a");
        store.materialize(base.id, &a_workspace, "fixture").unwrap();
        fs::remove_file(a_workspace.join("lost.bin")).unwrap();
        let a = store
            .commit_workspace(
                base.id,
                &a_workspace,
                "deterministic",
                "A deletes an untracked binary",
                BTreeMap::new(),
            )
            .unwrap();
        let b_workspace = root.join("b");
        store.materialize(a.id, &b_workspace, "fixture").unwrap();
        fs::write(b_workspace.join("keep.txt"), b"later").unwrap();
        let today = store
            .commit_workspace(
                a.id,
                &b_workspace,
                "deterministic",
                "B changes independent file",
                BTreeMap::new(),
            )
            .unwrap();
        let target = store.history(today.id).unwrap().first().unwrap().id;
        let compiled = HistoryCompiler::new(HistoryBudget::default())
            .compile(&store, today.id, target)
            .unwrap();
        assert!(
            compiled
                .contract
                .must_preserve
                .iter()
                .any(|rule| rule.path.0 == b"keep.txt")
        );
        let candidate_root = root.join("candidate");
        let result = RecoveryEngine::new(&store)
            .recover_into(
                today.id,
                target,
                RecoveryStrategy::ExactSubtract,
                &candidate_root,
            )
            .unwrap();
        assert_eq!(result.status, RecoveryStatus::CandidateReady);
        assert_eq!(
            fs::read(candidate_root.join("lost.bin")).unwrap(),
            [0, 1, 2, 3, 255]
        );
        assert_eq!(fs::read(candidate_root.join("keep.txt")).unwrap(), b"later");
        store.destroy_materialized(&candidate_root).unwrap();
        store.destroy_materialized(&a_workspace).unwrap();
        store.destroy_materialized(&b_workspace).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remove_and_replace_create_ready_counterfactual_views_for_disjoint_history() {
        let root = temp("history-edit");
        let _ = fs::remove_dir_all(&root);
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("target.txt"), b"base").unwrap();
        fs::write(source.join("later.txt"), b"base").unwrap();
        let store = WorldStore::open(root.join("store")).unwrap();
        let base = store.import("fixture", &source).unwrap();

        let a_root = root.join("a");
        store.materialize(base.id, &a_root, "fixture").unwrap();
        fs::write(a_root.join("target.txt"), b"bad-a").unwrap();
        let a = store
            .commit_workspace(base.id, &a_root, "A", "bad change", BTreeMap::new())
            .unwrap();
        let target = *a.layers.last().unwrap();

        let b_root = root.join("b");
        store.materialize(a.id, &b_root, "fixture").unwrap();
        fs::write(b_root.join("later.txt"), b"later-b").unwrap();
        let today = store
            .commit_workspace(a.id, &b_root, "B", "later intent", BTreeMap::new())
            .unwrap();

        let replacement_parent = store.fork(base.id).unwrap();
        let replacement_root = root.join("replacement");
        store
            .materialize(replacement_parent.id, &replacement_root, "fixture")
            .unwrap();
        fs::write(replacement_root.join("target.txt"), b"fixed-a").unwrap();
        let replacement_head = store
            .commit_workspace(
                replacement_parent.id,
                &replacement_root,
                "A-prime",
                "corrected change",
                BTreeMap::new(),
            )
            .unwrap();
        let replacement = *replacement_head.layers.last().unwrap();
        let engine = RecoveryEngine::new(&store);

        let remove = engine
            .plan_history_edit(today.id, HistoryEdit::Remove(target))
            .unwrap();
        assert_eq!(remove.status, ReconstructionPlanStatus::Ready);
        let remove_root = root.join("remove-candidate");
        engine
            .execute_reconstruction_plan(&remove, &remove_root)
            .unwrap();
        assert_eq!(fs::read(remove_root.join("target.txt")).unwrap(), b"base");
        assert_eq!(fs::read(remove_root.join("later.txt")).unwrap(), b"later-b");

        let replace = engine
            .plan_history_edit(
                today.id,
                HistoryEdit::Replace {
                    target,
                    replacement,
                },
            )
            .unwrap();
        assert_eq!(replace.status, ReconstructionPlanStatus::Ready);
        assert_ne!(replace.history_view, remove.history_view);
        let replace_root = root.join("replace-candidate");
        engine
            .execute_reconstruction_plan(&replace, &replace_root)
            .unwrap();
        assert_eq!(
            fs::read(replace_root.join("target.txt")).unwrap(),
            b"fixed-a"
        );
        assert_eq!(
            fs::read(replace_root.join("later.txt")).unwrap(),
            b"later-b"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_overlap_model_fails_closed_for_every_three_path_state() {
        let mut explored = 0u64;
        for target_mask in 1u8..8 {
            for later_mask in 0u8..8 {
                let root = temp(&format!("model-{target_mask}-{later_mask}"));
                let _ = fs::remove_dir_all(&root);
                let source = root.join("source");
                fs::create_dir_all(&source).unwrap();
                for index in 0..3 {
                    fs::write(source.join(format!("p{index}")), b"base").unwrap();
                }
                let store = WorldStore::open(root.join("store")).unwrap();
                let base = store.import("model", &source).unwrap();
                let a_root = root.join("a");
                store.materialize(base.id, &a_root, "model").unwrap();
                for index in 0..3 {
                    if target_mask & (1 << index) != 0 {
                        fs::write(a_root.join(format!("p{index}")), b"target").unwrap();
                    }
                }
                let a = store
                    .commit_workspace(base.id, &a_root, "A", "target", BTreeMap::new())
                    .unwrap();
                let target = *a.layers.last().unwrap();
                let b_root = root.join("b");
                store.materialize(a.id, &b_root, "model").unwrap();
                for index in 0..3 {
                    if later_mask & (1 << index) != 0 {
                        fs::write(b_root.join(format!("p{index}")), b"later").unwrap();
                    }
                }
                let today = store
                    .commit_workspace(a.id, &b_root, "B", "later", BTreeMap::new())
                    .unwrap();
                let plan = RecoveryEngine::new(&store)
                    .plan_history_edit(today.id, HistoryEdit::Remove(target))
                    .unwrap();
                let expected = if target_mask & later_mask == 0 {
                    ReconstructionPlanStatus::Ready
                } else {
                    ReconstructionPlanStatus::Conflict
                };
                assert_eq!(plan.status, expected);
                explored += 1;
                fs::remove_dir_all(root).unwrap();
            }
        }
        assert_eq!(explored, 56);
    }

    #[test]
    fn semantic_rewrite_replays_captured_overwrite_then_rejoins_exact_suffix() {
        let root = temp("semantic-rejoin");
        let _ = fs::remove_dir_all(&root);
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("shared.txt"), b"base").unwrap();
        fs::write(source.join("tail.txt"), b"base").unwrap();
        let store = WorldStore::open(root.join("store")).unwrap();
        let base = store.import("semantic-rejoin", &source).unwrap();

        let a_root = root.join("a");
        store
            .materialize(base.id, &a_root, "semantic-rejoin")
            .unwrap();
        fs::write(a_root.join("shared.txt"), b"target").unwrap();
        let a = store
            .commit_workspace_with_capsule(
                base.id,
                &a_root,
                prospective_capsule(&store, base.id, "target write", &[], Vec::new()),
            )
            .unwrap();
        let target = *a.layers.last().unwrap();

        let b_root = root.join("b");
        store.materialize(a.id, &b_root, "semantic-rejoin").unwrap();
        fs::write(b_root.join("shared.txt"), b"future overwrite").unwrap();
        let b = store
            .commit_workspace_with_capsule(
                a.id,
                &b_root,
                prospective_capsule(
                    &store,
                    a.id,
                    "unconditional future overwrite",
                    &[],
                    vec![RecordedOperation {
                        kind: RecordedOperationKind::OverwritePath,
                        path: PathBytes::from(Path::new("shared.txt")),
                        destination: None,
                        deterministic: true,
                        evidence: EvidenceClass::AgentDeclaration,
                    }],
                ),
            )
            .unwrap();
        let b_layer = *b.layers.last().unwrap();

        let c_root = root.join("c");
        store.materialize(b.id, &c_root, "semantic-rejoin").unwrap();
        fs::write(c_root.join("tail.txt"), b"suffix").unwrap();
        let today = store
            .commit_workspace_with_capsule(
                b.id,
                &c_root,
                prospective_capsule(&store, b.id, "independent suffix", &[], Vec::new()),
            )
            .unwrap();
        let c_layer = *today.layers.last().unwrap();

        let engine = RecoveryEngine::new(&store);
        let plan = engine
            .plan_history_rewrite(
                today.id,
                HistoryEdit::Remove(target),
                ReconstructionPolicy::phase4_safe(),
            )
            .unwrap();
        assert_eq!(plan.status, ReconstructionPlanStatus::Ready);
        assert_eq!(plan.replay_frontier.replayed_recorded_operations, 1);
        assert_eq!(plan.replay_frontier.reused_after_rejoin, 1);
        assert_eq!(plan.replay_frontier.exact_rejoin_head, Some(b.id));
        assert!(plan.actions.iter().any(|action| matches!(
            action,
            ReconstructionAction::ReplayRecordedOperation { layer, .. } if *layer == b_layer
        )));
        assert!(plan.actions.iter().any(|action| matches!(
            action,
            ReconstructionAction::ReuseObservedSuffix { layers, .. } if layers == &vec![c_layer]
        )));

        let candidate_root = root.join("candidate");
        let result = engine
            .execute_reconstruction_plan(&plan, &candidate_root)
            .unwrap();
        let today_manifest = store.manifest(today.manifest).unwrap();
        assert_eq!(result.candidate_manifest_hash, today_manifest.semantic_hash);
        assert_eq!(
            fs::read(candidate_root.join("shared.txt")).unwrap(),
            b"future overwrite"
        );
        assert_eq!(
            fs::read(candidate_root.join("tail.txt")).unwrap(),
            b"suffix"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn semantic_rewrite_refuses_overlap_without_operation_semantics() {
        let root = temp("semantic-conflict");
        let _ = fs::remove_dir_all(&root);
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("shared.txt"), b"base").unwrap();
        let store = WorldStore::open(root.join("store")).unwrap();
        let base = store.import("semantic-conflict", &source).unwrap();

        let a_root = root.join("a");
        store
            .materialize(base.id, &a_root, "semantic-conflict")
            .unwrap();
        fs::write(a_root.join("shared.txt"), b"target").unwrap();
        let a = store
            .commit_workspace_with_capsule(
                base.id,
                &a_root,
                prospective_capsule(&store, base.id, "target", &[], Vec::new()),
            )
            .unwrap();
        let target = *a.layers.last().unwrap();
        let b_root = root.join("b");
        store
            .materialize(a.id, &b_root, "semantic-conflict")
            .unwrap();
        fs::write(b_root.join("shared.txt"), b"opaque future").unwrap();
        let today = store
            .commit_workspace_with_capsule(
                a.id,
                &b_root,
                prospective_capsule(&store, a.id, "opaque future", &[], Vec::new()),
            )
            .unwrap();

        let plan = RecoveryEngine::new(&store)
            .plan_history_rewrite(
                today.id,
                HistoryEdit::Remove(target),
                ReconstructionPolicy::phase4_safe(),
            )
            .unwrap();
        assert_eq!(plan.status, ReconstructionPlanStatus::Conflict);
        assert_eq!(plan.replay_frontier.conflicted, 1);
        assert!(!plan.conflicts.is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
