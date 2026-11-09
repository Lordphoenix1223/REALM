//! Independent candidate verification. Repair agents never certify themselves.

use realm_contract::{ExactRestoreAction, RecoveryContract};
use realm_core::{CaptureStatus, PathBytes};
use realm_history::{
    HistoryEdit, HistoryViewId, ReconstructionAction, ReconstructionPlan, ReconstructionPlanStatus,
    ReconstructionResult, ReplayFrontier,
};
use realm_world::{
    CandidateWorldId, TransactionLayerId, WorldError, WorldHeadId, WorldManifest, WorldStore,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::Path,
};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileState {
    pub kind: String,
    pub content_hash: Option<String>,
    pub symlink_target: Option<Vec<u8>>,
    pub mode: u32,
    pub size: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TreeSnapshot {
    pub entries: BTreeMap<Vec<u8>, FileState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Verified,
    VerifiedWithKnownUncertainty,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub status: VerificationStatus,
    pub candidate_changes: Vec<Vec<u8>>,
    pub violations: Vec<Violation>,
    pub uncertainty: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Violation {
    pub code: String,
    pub path: Option<Vec<u8>>,
    pub description: String,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecoveryReceiptHash(pub String);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorldStateHash(pub String);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReceiptOutcome {
    VerifiedWithinSupportEnvelope,
    Rejected,
    RefusedConflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReceiptGuarantee {
    DeterministicRecordedDeltaReconstruction,
    EvidenceBoundSemanticRewrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CheckStatus {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiptCheck {
    pub id: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryReceipt {
    pub schema_version: u16,
    pub receipt_hash: RecoveryReceiptHash,
    pub verifier: String,
    pub guarantee: ReceiptGuarantee,
    pub outcome: ReceiptOutcome,
    pub source_head: WorldHeadId,
    pub source_manifest_hash: WorldStateHash,
    pub history_view: HistoryViewId,
    pub edit_hash: String,
    pub replacement_layer: Option<TransactionLayerId>,
    pub plan_hash: String,
    pub candidate_world: CandidateWorldId,
    pub candidate_manifest_hash: WorldStateHash,
    pub applied_layers: Vec<TransactionLayerId>,
    pub replay_frontier: ReplayFrontier,
    pub exact_rejoin_head: Option<WorldHeadId>,
    pub adapter_versions: Vec<String>,
    pub checks: Vec<ReceiptCheck>,
    pub unknowns: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiptValidation {
    pub valid: bool,
    pub checks: Vec<ReceiptCheck>,
}

#[derive(Serialize)]
struct RecoveryReceiptBody<'a> {
    schema_version: u16,
    verifier: &'a str,
    guarantee: ReceiptGuarantee,
    outcome: ReceiptOutcome,
    source_head: WorldHeadId,
    source_manifest_hash: &'a WorldStateHash,
    history_view: &'a HistoryViewId,
    edit_hash: &'a str,
    replacement_layer: Option<TransactionLayerId>,
    plan_hash: &'a str,
    candidate_world: CandidateWorldId,
    candidate_manifest_hash: &'a WorldStateHash,
    applied_layers: &'a [TransactionLayerId],
    replay_frontier: &'a ReplayFrontier,
    exact_rejoin_head: Option<WorldHeadId>,
    adapter_versions: &'a [String],
    checks: &'a [ReceiptCheck],
    unknowns: &'a [String],
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("verification I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("candidate and base must be distinct directories")]
    NotIsolated,
    #[error("world verification error: {0}")]
    World(#[from] WorldError),
    #[error("receipt serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Independently verify that a controlled-world history-edit result is bound
/// to the declared immutable source and exactly matches the recorded-delta
/// plan. This receipt does not claim semantic intent preservation, causal
/// attribution, or adversarial tamper resistance.
pub fn verify_history_reconstruction(
    store: &WorldStore,
    candidate_root: &Path,
    plan: &ReconstructionPlan,
    result: &ReconstructionResult,
) -> Result<RecoveryReceipt, VerifyError> {
    let source = store.head(plan.source_head)?;
    let source_manifest = store.manifest(source.manifest)?;
    let observed = store.snapshot_directory(candidate_root, None)?;
    let marker = store.materialization_marker(candidate_root)?;
    let history = store.history(plan.source_head)?;
    let expected = expected_manifest(store, plan)?;
    let expected_applied = planned_layers(plan);
    let mut checks = vec![
        receipt_check(
            "SOURCE_HISTORY_BOUND",
            history.iter().map(|layer| layer.id).collect::<Vec<_>>() == plan.observed_history
                && history.last().map(|layer| layer.result_head) == Some(plan.source_head),
            "Observed layer lineage terminates at the receipt source head.",
        ),
        receipt_check(
            "RESULT_PLAN_BOUND",
            result.source_head == plan.source_head && result.history_view == plan.history_view,
            "Execution result identifies the exact source head and history view.",
        ),
        receipt_check(
            "CANDIDATE_ID_BOUND",
            marker.candidate == result.candidate_world && marker.world_head == plan.base_head,
            "Candidate marker binds the materialization to the result and plan base.",
        ),
        receipt_check(
            "CANDIDATE_STATE_BOUND",
            observed.semantic_hash == result.candidate_manifest_hash,
            "Candidate bytes hash to the manifest recorded by execution.",
        ),
        receipt_check(
            "RECORDED_DELTA_PLAN_EXECUTED",
            expected.semantic_hash == observed.semantic_hash,
            "Candidate equals an independent manifest fold of the ready recorded-delta plan.",
        ),
        receipt_check(
            "APPLIED_LAYER_SET_BOUND",
            expected_applied == result.applied_layers,
            "Applied layer order matches the reconstruction plan.",
        ),
    ];
    if plan.status != ReconstructionPlanStatus::Ready {
        checks.push(receipt_check(
            "PLAN_READY",
            false,
            "A conflicted or impossible plan cannot receive a verified receipt.",
        ));
    }
    let any_failed = checks
        .iter()
        .any(|check| check.status == CheckStatus::Failed);
    let outcome = if plan.status != ReconstructionPlanStatus::Ready {
        ReceiptOutcome::RefusedConflict
    } else if any_failed {
        ReceiptOutcome::Rejected
    } else {
        ReceiptOutcome::VerifiedWithinSupportEnvelope
    };
    let source_manifest_hash = WorldStateHash(source_manifest.semantic_hash);
    let candidate_manifest_hash = WorldStateHash(observed.semantic_hash);
    let plan_hash = plan.canonical_hash()?;
    let edit_hash = blake3::hash(&serde_json::to_vec(&plan.edit)?)
        .to_hex()
        .to_string();
    let replacement_layer = match plan.edit {
        HistoryEdit::Remove(_) => None,
        HistoryEdit::Replace { replacement, .. } => Some(replacement),
    };
    let guarantee = if plan.policy == Default::default() {
        ReceiptGuarantee::DeterministicRecordedDeltaReconstruction
    } else {
        ReceiptGuarantee::EvidenceBoundSemanticRewrite
    };
    let adapter_versions = plan
        .actions
        .iter()
        .filter_map(|action| match action {
            ReconstructionAction::ReplayRecordedOperation { .. } => {
                Some("recorded-operation/v1".to_owned())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut unknowns = plan
        .known_unknowns
        .iter()
        .map(|unknown| format!("{:?}: {}", unknown.code, unknown.detail))
        .collect::<Vec<_>>();
    unknowns.push(
        "Receipt proves only the checks and prospective evidence named here; undeclared intent and causal claims remain unproven."
            .into(),
    );
    let body = RecoveryReceiptBody {
        schema_version: 2,
        verifier: "realm-verify/history-v2",
        guarantee,
        outcome,
        source_head: plan.source_head,
        source_manifest_hash: &source_manifest_hash,
        history_view: &plan.history_view,
        edit_hash: &edit_hash,
        replacement_layer,
        plan_hash: &plan_hash,
        candidate_world: result.candidate_world,
        candidate_manifest_hash: &candidate_manifest_hash,
        applied_layers: &result.applied_layers,
        replay_frontier: &plan.replay_frontier,
        exact_rejoin_head: plan.replay_frontier.exact_rejoin_head,
        adapter_versions: &adapter_versions,
        checks: &checks,
        unknowns: &unknowns,
    };
    let receipt_hash = RecoveryReceiptHash(
        blake3::hash(&serde_json::to_vec(&body)?)
            .to_hex()
            .to_string(),
    );
    Ok(RecoveryReceipt {
        schema_version: 2,
        receipt_hash,
        verifier: body.verifier.into(),
        guarantee: body.guarantee,
        outcome,
        source_head: plan.source_head,
        source_manifest_hash,
        history_view: plan.history_view.clone(),
        edit_hash,
        replacement_layer,
        plan_hash,
        candidate_world: result.candidate_world,
        candidate_manifest_hash,
        applied_layers: result.applied_layers.clone(),
        replay_frontier: plan.replay_frontier.clone(),
        exact_rejoin_head: plan.replay_frontier.exact_rejoin_head,
        adapter_versions,
        checks,
        unknowns,
    })
}

/// Validate a previously issued receipt against the immutable source, the
/// exact plan, and the candidate's current bytes. This catches stale receipts,
/// post-verification mutation, substituted edits, and substituted plans.
pub fn validate_history_receipt(
    store: &WorldStore,
    candidate_root: &Path,
    plan: &ReconstructionPlan,
    receipt: &RecoveryReceipt,
) -> Result<ReceiptValidation, VerifyError> {
    let source = store.head(plan.source_head)?;
    let source_manifest = store.manifest(source.manifest)?;
    let candidate = store.snapshot_directory(candidate_root, None)?;
    let marker = store.materialization_marker(candidate_root)?;
    let plan_hash = plan.canonical_hash()?;
    let edit_hash = blake3::hash(&serde_json::to_vec(&plan.edit)?)
        .to_hex()
        .to_string();
    let replacement_layer = match plan.edit {
        HistoryEdit::Remove(_) => None,
        HistoryEdit::Replace { replacement, .. } => Some(replacement),
    };
    let body = RecoveryReceiptBody {
        schema_version: receipt.schema_version,
        verifier: &receipt.verifier,
        guarantee: receipt.guarantee,
        outcome: receipt.outcome,
        source_head: receipt.source_head,
        source_manifest_hash: &receipt.source_manifest_hash,
        history_view: &receipt.history_view,
        edit_hash: &receipt.edit_hash,
        replacement_layer: receipt.replacement_layer,
        plan_hash: &receipt.plan_hash,
        candidate_world: receipt.candidate_world,
        candidate_manifest_hash: &receipt.candidate_manifest_hash,
        applied_layers: &receipt.applied_layers,
        replay_frontier: &receipt.replay_frontier,
        exact_rejoin_head: receipt.exact_rejoin_head,
        adapter_versions: &receipt.adapter_versions,
        checks: &receipt.checks,
        unknowns: &receipt.unknowns,
    };
    let expected_receipt_hash = blake3::hash(&serde_json::to_vec(&body)?)
        .to_hex()
        .to_string();
    let checks = vec![
        receipt_check(
            "RECEIPT_HASH_VALID",
            receipt.receipt_hash.0 == expected_receipt_hash,
            "Receipt body matches its content hash.",
        ),
        receipt_check(
            "SOURCE_STILL_BOUND",
            receipt.source_head == plan.source_head
                && receipt.source_manifest_hash.0 == source_manifest.semantic_hash,
            "Receipt source is the immutable plan source.",
        ),
        receipt_check(
            "PLAN_HASH_STILL_BOUND",
            receipt.plan_hash == plan_hash && receipt.history_view == plan.history_view,
            "Receipt identifies this exact reconstruction plan and history view.",
        ),
        receipt_check(
            "EDIT_HASH_STILL_BOUND",
            receipt.edit_hash == edit_hash && receipt.replacement_layer == replacement_layer,
            "Receipt identifies this exact remove or replace edit.",
        ),
        receipt_check(
            "CANDIDATE_STILL_BOUND",
            receipt.candidate_world == marker.candidate
                && receipt.candidate_manifest_hash.0 == candidate.semantic_hash,
            "Candidate identity and current bytes match the issued receipt.",
        ),
        receipt_check(
            "REJOIN_STILL_BOUND",
            receipt.exact_rejoin_head == plan.replay_frontier.exact_rejoin_head,
            "Any exact historical rejoin is bound to the plan boundary.",
        ),
    ];
    Ok(ReceiptValidation {
        valid: checks
            .iter()
            .all(|check| check.status == CheckStatus::Passed),
        checks,
    })
}

fn expected_manifest(
    store: &WorldStore,
    plan: &ReconstructionPlan,
) -> Result<WorldManifest, VerifyError> {
    let base = store.manifest(store.head(plan.base_head)?.manifest)?;
    let mut entries = base.entries;
    for layer in planned_layers(plan) {
        for delta in store.layer(layer)?.delta {
            match delta.after {
                Some(after) => {
                    entries.insert(delta.path, after);
                }
                None => {
                    entries.remove(&delta.path);
                }
            }
        }
    }
    Ok(WorldManifest::new(entries))
}

fn planned_layers(plan: &ReconstructionPlan) -> Vec<TransactionLayerId> {
    let mut layers = Vec::new();
    for action in &plan.actions {
        match action {
            ReconstructionAction::ApplyReplacement(layer)
            | ReconstructionAction::ReplayRecordedDelta(layer)
            | ReconstructionAction::ReuseObservedLayer { layer, .. }
            | ReconstructionAction::ReplayRecordedOperation { layer, .. } => {
                layers.push(*layer);
            }
            ReconstructionAction::ReuseObservedSuffix { layers: suffix, .. } => {
                layers.extend(suffix.iter().copied())
            }
            ReconstructionAction::MaterializeParent(_)
            | ReconstructionAction::OmitObserved(_)
            | ReconstructionAction::VerifyExactRejoin { .. }
            | ReconstructionAction::Conflict(_) => {}
        }
    }
    layers
}

fn receipt_check(id: &str, passed: bool, detail: &str) -> ReceiptCheck {
    ReceiptCheck {
        id: id.into(),
        status: if passed {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        },
        detail: detail.into(),
    }
}

pub fn snapshot_tree(root: &Path) -> Result<TreeSnapshot, VerifyError> {
    let mut snapshot = TreeSnapshot::default();
    visit(root, root, &mut snapshot)?;
    Ok(snapshot)
}

pub fn verify_candidate(
    base_root: &Path,
    candidate_root: &Path,
    contract: &RecoveryContract,
) -> Result<VerificationReport, VerifyError> {
    if fs::canonicalize(base_root).ok() == fs::canonicalize(candidate_root).ok() {
        return Err(VerifyError::NotIsolated);
    }
    let base = snapshot_tree(base_root)?;
    let candidate = snapshot_tree(candidate_root)?;
    let mut violations = Vec::new();
    let mut changes = Vec::new();
    let all_keys: BTreeSet<Vec<u8>> = base
        .entries
        .keys()
        .chain(candidate.entries.keys())
        .cloned()
        .collect();
    let allowed: BTreeSet<Vec<u8>> = contract
        .may_modify
        .iter()
        .map(|item| normalize_contract_path(&item.path))
        .collect();
    let ignored_marker = b".realm-recovery-marker".to_vec();
    for key in all_keys {
        if key == ignored_marker {
            continue;
        }
        if base.entries.get(&key) != candidate.entries.get(&key) {
            changes.push(key.clone());
            if !allowed.contains(&key) {
                violations.push(Violation { code: "OUT_OF_SCOPE_MODIFICATION".into(), path: Some(key), description: "Candidate differs from the materialized base outside the contract's allowed write set.".into() });
            }
        }
    }

    for expected in &contract.must_preserve {
        if let Some(path) = &expected.path {
            let key = normalize_contract_path(path);
            if base.entries.get(&key) != candidate.entries.get(&key) {
                violations.push(Violation {
                    code: "MUST_PRESERVE_CHANGED".into(),
                    path: Some(key),
                    description: expected.reason.clone(),
                });
            }
        }
    }
    for expected in &contract.must_not_modify {
        if let Some(path) = &expected.path {
            let key = normalize_contract_path(path);
            if base.entries.get(&key) != candidate.entries.get(&key) {
                violations.push(Violation {
                    code: "MUST_NOT_MODIFY_CHANGED".into(),
                    path: Some(key),
                    description: expected.reason.clone(),
                });
            }
        }
    }
    for restore in &contract.exact_restores {
        let key = normalize_contract_path(&restore.target_path);
        match &restore.action {
            ExactRestoreAction::RestoreBytes => match candidate
                .entries
                .get(&key)
                .and_then(|state| state.content_hash.as_ref())
            {
                Some(hash) if restore.source_blob.as_ref() == Some(hash) => {}
                Some(hash) => violations.push(Violation {
                    code: "EXACT_RESTORE_HASH_MISMATCH".into(),
                    path: Some(key),
                    description: format!(
                        "expected {}, found {hash}",
                        restore.source_blob.as_deref().unwrap_or("missing")
                    ),
                }),
                None => violations.push(Violation {
                    code: "EXACT_RESTORE_MISSING".into(),
                    path: Some(key),
                    description:
                        "Candidate does not contain a regular file with the required exact bytes."
                            .into(),
                }),
            },
            ExactRestoreAction::RemoveCreatedPath => {
                if candidate.entries.contains_key(&key) {
                    violations.push(Violation {
                        code: "EXACT_REMOVE_NOT_APPLIED".into(),
                        path: Some(key),
                        description:
                            "A path created by the target transaction remains in the candidate."
                                .into(),
                    });
                }
            }
            ExactRestoreAction::RenameBack { from, to } => {
                let from_key = normalize_contract_path(from);
                let to_key = normalize_contract_path(to);
                if candidate.entries.contains_key(&from_key)
                    || !candidate.entries.contains_key(&to_key)
                {
                    violations.push(Violation {
                        code: "EXACT_RENAME_NOT_REVERSED".into(),
                        path: Some(from_key),
                        description: "The candidate did not restore the historical path relation."
                            .into(),
                    });
                }
            }
        }
    }
    changes.sort();
    violations.sort_by(|a, b| a.path.cmp(&b.path).then(a.code.cmp(&b.code)));
    let uncertainty: Vec<String> = contract
        .known_unknowns
        .iter()
        .map(|unknown| format!("{}: {}", unknown.code, unknown.description))
        .collect();
    let status = if !violations.is_empty() {
        VerificationStatus::Rejected
    } else if contract.capture_quality.status == CaptureStatus::Degraded
        || !uncertainty.is_empty()
        || !contract.overlaps.is_empty()
    {
        VerificationStatus::VerifiedWithKnownUncertainty
    } else {
        VerificationStatus::Verified
    };
    Ok(VerificationReport {
        status,
        candidate_changes: changes,
        violations,
        uncertainty,
    })
}

fn normalize_contract_path(path: &PathBytes) -> Vec<u8> {
    let mut bytes = path.0.clone();
    while bytes.first() == Some(&b'/') {
        bytes.remove(0);
    }
    bytes
}

fn visit(root: &Path, current: &Path, snapshot: &mut TreeSnapshot) -> Result<(), VerifyError> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        if entry.file_name() == ".realm-recovery-marker" {
            continue;
        }
        let path = entry.path();
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let key = path_bytes(relative);
        let metadata = fs::symlink_metadata(&path)?;
        let file_type = metadata.file_type();
        #[cfg(unix)]
        let mode = std::os::unix::fs::MetadataExt::mode(&metadata);
        #[cfg(not(unix))]
        let mode = 0;
        if file_type.is_symlink() {
            let target = fs::read_link(&path)?;
            snapshot.entries.insert(
                key,
                FileState {
                    kind: "symlink".into(),
                    content_hash: None,
                    symlink_target: Some(path_bytes(&target)),
                    mode,
                    size: 0,
                },
            );
        } else if file_type.is_dir() {
            snapshot.entries.insert(
                key,
                FileState {
                    kind: "directory".into(),
                    content_hash: None,
                    symlink_target: None,
                    mode,
                    size: 0,
                },
            );
            visit(root, &path, snapshot)?;
        } else if file_type.is_file() {
            let bytes = fs::read(&path)?;
            snapshot.entries.insert(
                key,
                FileState {
                    kind: "file".into(),
                    content_hash: Some(blake3::hash(&bytes).to_hex().to_string()),
                    symlink_target: None,
                    mode,
                    size: metadata.len(),
                },
            );
        }
    }
    Ok(())
}

fn path_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use realm_contract::{CaptureQuality, ExactRestore, ExactRestoreAction, RecoveryContract};
    use realm_core::{
        CaptureStatus, Fidelity, ObjectId, ObjectVersionId, PathBytes, TransactionId,
    };
    use realm_history::{HistoryEdit, RecoveryEngine};
    use realm_world::WorldStore;

    fn contract() -> RecoveryContract {
        RecoveryContract {
            contract_version: 1,
            target_transaction: TransactionId::new(),
            objective: "test".into(),
            exact_restores: vec![ExactRestore {
                object_id: ObjectId::new(),
                target_path: PathBytes(b"target.txt".to_vec()),
                historical_version: ObjectVersionId::new(),
                source_blob: Some(blake3::hash(b"old").to_hex().to_string()),
                fidelity: Fidelity::ContentExact,
                action: ExactRestoreAction::RestoreBytes,
                event_sequence: 1,
            }],
            direct_effects_to_remove: vec![],
            must_preserve: vec![],
            may_modify: vec![realm_contract::PathExpectation {
                object_id: ObjectId::new(),
                path: PathBytes(b"target.txt".to_vec()),
            }],
            must_not_modify: vec![],
            overlaps: vec![],
            known_dependencies: vec![],
            candidate_dependencies: vec![],
            known_unknowns: vec![],
            capture_quality: CaptureQuality {
                status: CaptureStatus::Complete,
                exact_preimages: 1,
                missing_preimages: 0,
                race_detected_preimages: 0,
                unresolved_gap_count: 0,
            },
            invariants: vec![],
            external_effects: vec![],
            required_adapters: vec![],
        }
    }

    #[test]
    fn rejects_secret_unrelated_edits_even_when_target_is_fixed() {
        let base = std::env::temp_dir().join(format!("realm-verify-base-{}", std::process::id()));
        let candidate =
            std::env::temp_dir().join(format!("realm-verify-candidate-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let _ = fs::remove_dir_all(&candidate);
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(&candidate).unwrap();
        fs::write(base.join("target.txt"), b"new").unwrap();
        fs::write(base.join("secret.txt"), b"keep").unwrap();
        fs::write(candidate.join("target.txt"), b"old").unwrap();
        fs::write(candidate.join("secret.txt"), b"changed").unwrap();
        let report = verify_candidate(&base, &candidate, &contract()).unwrap();
        assert_eq!(report.status, VerificationStatus::Rejected);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.code == "OUT_OF_SCOPE_MODIFICATION")
        );
        fs::remove_dir_all(base).unwrap();
        fs::remove_dir_all(candidate).unwrap();
    }

    #[test]
    fn recovery_receipt_is_bound_to_the_exact_candidate_state() {
        let root = std::env::temp_dir().join(format!(
            "realm-receipt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("target.txt"), b"base").unwrap();
        fs::write(source.join("later.txt"), b"base").unwrap();
        let store = WorldStore::open(root.join("store")).unwrap();
        let base = store.import("receipt", &source).unwrap();
        let a_root = root.join("a");
        store.materialize(base.id, &a_root, "receipt").unwrap();
        fs::write(a_root.join("target.txt"), b"bad").unwrap();
        let a = store
            .commit_workspace(base.id, &a_root, "A", "bad", BTreeMap::new())
            .unwrap();
        let target = *a.layers.last().unwrap();
        let b_root = root.join("b");
        store.materialize(a.id, &b_root, "receipt").unwrap();
        fs::write(b_root.join("later.txt"), b"later").unwrap();
        let today = store
            .commit_workspace(a.id, &b_root, "B", "later", BTreeMap::new())
            .unwrap();
        let engine = RecoveryEngine::new(&store);
        let plan = engine
            .plan_history_edit(today.id, HistoryEdit::Remove(target))
            .unwrap();
        let candidate = root.join("candidate");
        let result = engine
            .execute_reconstruction_plan(&plan, &candidate)
            .unwrap();
        let receipt = verify_history_reconstruction(&store, &candidate, &plan, &result).unwrap();
        assert_eq!(
            receipt.outcome,
            ReceiptOutcome::VerifiedWithinSupportEnvelope
        );
        assert!(
            receipt
                .checks
                .iter()
                .all(|check| check.status == CheckStatus::Passed)
        );
        assert!(
            validate_history_receipt(&store, &candidate, &plan, &receipt)
                .unwrap()
                .valid
        );
        let mut wrong_plan_receipt = receipt.clone();
        wrong_plan_receipt.plan_hash = "substituted-plan".into();
        assert!(
            !validate_history_receipt(&store, &candidate, &plan, &wrong_plan_receipt)
                .unwrap()
                .valid
        );
        let mut wrong_edit_receipt = receipt.clone();
        wrong_edit_receipt.edit_hash = "substituted-edit".into();
        assert!(
            !validate_history_receipt(&store, &candidate, &plan, &wrong_edit_receipt)
                .unwrap()
                .valid
        );

        fs::write(
            candidate.join("target.txt"),
            b"tampered-after-verification-input",
        )
        .unwrap();
        let rejected = verify_history_reconstruction(&store, &candidate, &plan, &result).unwrap();
        assert_eq!(rejected.outcome, ReceiptOutcome::Rejected);
        assert_ne!(receipt.receipt_hash, rejected.receipt_hash);
        assert!(rejected.checks.iter().any(|check| {
            check.id == "CANDIDATE_STATE_BOUND" && check.status == CheckStatus::Failed
        }));
        assert!(
            !validate_history_receipt(&store, &candidate, &plan, &receipt)
                .unwrap()
                .valid
        );
        fs::write(candidate.join("target.txt"), b"base").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = candidate.join("target.txt");
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(path, permissions).unwrap();
            assert!(
                !validate_history_receipt(&store, &candidate, &plan, &receipt)
                    .unwrap()
                    .valid
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}
