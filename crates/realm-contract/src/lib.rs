//! Deterministic compilation of evidence into a model-agnostic Recovery Contract.

use realm_core::{
    CaptureStatus, Fidelity, ObjectId, ObjectVersion, ObjectVersionId, PathBytes,
    PreservationMethod, RealmEvent, RealmEventKind, TransactionId, TransactionMetadata,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryContract {
    pub contract_version: u16,
    pub target_transaction: TransactionId,
    pub objective: String,
    pub exact_restores: Vec<ExactRestore>,
    pub direct_effects_to_remove: Vec<DirectEffect>,
    pub must_preserve: Vec<VersionExpectation>,
    pub may_modify: Vec<PathExpectation>,
    pub must_not_modify: Vec<VersionExpectation>,
    pub overlaps: Vec<Overlap>,
    pub known_dependencies: Vec<Dependency>,
    pub candidate_dependencies: Vec<Dependency>,
    pub known_unknowns: Vec<Unknown>,
    pub capture_quality: CaptureQuality,
    pub invariants: Vec<Invariant>,
    pub external_effects: Vec<serde_json::Value>,
    pub required_adapters: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExactRestore {
    pub object_id: ObjectId,
    pub target_path: PathBytes,
    pub historical_version: ObjectVersionId,
    pub source_blob: Option<String>,
    pub fidelity: Fidelity,
    pub action: ExactRestoreAction,
    pub event_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExactRestoreAction {
    RestoreBytes,
    RemoveCreatedPath,
    RenameBack { from: PathBytes, to: PathBytes },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DirectEffect {
    pub object_id: ObjectId,
    pub paths: Vec<PathBytes>,
    pub operations: Vec<RealmEventKind>,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub before_versions: Vec<ObjectVersionId>,
    pub after_versions: Vec<ObjectVersionId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VersionExpectation {
    pub object_id: ObjectId,
    pub version: Option<ObjectVersionId>,
    pub path: Option<PathBytes>,
    pub expected_content_hash: Option<String>,
    pub expected_metadata_hash: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathExpectation {
    pub object_id: ObjectId,
    pub path: PathBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Overlap {
    pub object_id: ObjectId,
    pub target_effect: DirectEffect,
    pub later_events: Vec<LaterTouch>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LaterTouch {
    pub transaction_id: TransactionId,
    pub sequence: u64,
    pub operation: RealmEventKind,
    pub path: Option<PathBytes>,
    pub observed_version: Option<ObjectVersionId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Dependency {
    pub source_object: ObjectId,
    pub source_version: Option<ObjectVersionId>,
    pub consumer_transaction: TransactionId,
    pub consumer_sequence: u64,
    pub consumer_object: Option<ObjectId>,
    pub relation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Unknown {
    pub code: String,
    pub description: String,
    pub object_id: Option<ObjectId>,
    pub sequence: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaptureQuality {
    pub status: CaptureStatus,
    pub exact_preimages: u64,
    pub missing_preimages: u64,
    pub race_detected_preimages: u64,
    pub unresolved_gap_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Invariant {
    pub id: String,
    pub description: String,
    pub severity: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RealmExport {
    pub export_version: u16,
    pub transaction: TransactionMetadata,
    pub direct_effects: Vec<DirectEffect>,
    pub events: Vec<RealmEvent>,
    pub object_versions: Vec<ObjectVersion>,
    pub cas_blob_refs: Vec<String>,
    pub recovery_contract: RecoveryContract,
}

pub fn serialize_export(export: &RealmExport) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec_pretty(export)
}

/// Narrow read-only surface intended for future Codex/Claude/local-model adapters.
/// There are deliberately no ledger/CAS mutation or verification-approval methods.
pub trait RealmQueryApi {
    fn get_transaction(&self, id: TransactionId) -> Option<TransactionMetadata>;
    fn get_direct_effects(&self, id: TransactionId) -> Vec<DirectEffect>;
    fn get_object_history(&self, object_id: ObjectId) -> Vec<RealmEvent>;
    fn get_object_version(
        &self,
        object_id: ObjectId,
        version_id: ObjectVersionId,
    ) -> Option<ObjectVersion>;
    fn get_later_touches(&self, object_id: ObjectId, after_sequence: u64) -> Vec<LaterTouch>;
    fn get_capture_uncertainty(&self, id: TransactionId) -> Vec<Unknown>;
    fn get_recovery_contract(&self, id: TransactionId) -> Option<RecoveryContract>;
}

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("target transaction {0} has no events")]
    NoEvents(TransactionId),
}

pub fn compile_contract(
    transaction: &TransactionMetadata,
    events: &[RealmEvent],
    versions: &BTreeMap<ObjectVersionId, ObjectVersion>,
    current_versions: &BTreeMap<ObjectId, ObjectVersionId>,
) -> Result<RecoveryContract, ContractError> {
    let target_events: Vec<&RealmEvent> = events
        .iter()
        .filter(|event| event.transaction_id == transaction.id)
        .collect();
    if target_events.is_empty() {
        return Err(ContractError::NoEvents(transaction.id));
    }
    let mut grouped: BTreeMap<ObjectId, Vec<&RealmEvent>> = BTreeMap::new();
    for event in target_events
        .iter()
        .filter(|event| event.object_id.is_some() && is_effect(event.kind))
    {
        grouped
            .entry(event.object_id.unwrap())
            .or_default()
            .push(event);
    }
    let mut direct_effects_to_remove = Vec::new();
    for (object_id, mut object_events) in grouped {
        object_events.sort_by_key(|event| event.sequence);
        let mut paths = BTreeSet::new();
        let mut operations = Vec::new();
        let mut before_versions = BTreeSet::new();
        let mut after_versions = BTreeSet::new();
        for event in &object_events {
            if let Some(path) = &event.path {
                paths.insert(path.clone());
            }
            operations.push(event.kind);
            if let Some(version) = event.pre_version {
                before_versions.insert(version);
            }
            if let Some(version) = event.post_version {
                after_versions.insert(version);
            }
        }
        direct_effects_to_remove.push(DirectEffect {
            object_id,
            paths: paths.into_iter().collect(),
            operations,
            first_sequence: object_events.first().unwrap().sequence,
            last_sequence: object_events.last().unwrap().sequence,
            before_versions: before_versions.into_iter().collect(),
            after_versions: after_versions.into_iter().collect(),
        });
    }
    direct_effects_to_remove.sort_by_key(|effect| effect.object_id);
    let direct_ids: BTreeSet<ObjectId> = direct_effects_to_remove
        .iter()
        .map(|effect| effect.object_id)
        .collect();

    let mut exact_restores = Vec::new();
    let mut known_unknowns = Vec::new();
    let mut exact_preimages = 0;
    let mut missing_preimages = 0;
    let mut race_detected_preimages = 0;
    for effect in &direct_effects_to_remove {
        let later: Vec<&RealmEvent> = events
            .iter()
            .filter(|event| {
                event.sequence > effect.last_sequence
                    && event.object_id == Some(effect.object_id)
                    && event.transaction_id != transaction.id
                    && is_effect(event.kind)
            })
            .collect();
        for event in events.iter().filter(|event| {
            event.transaction_id == transaction.id
                && event.object_id == Some(effect.object_id)
                && is_inverse_candidate(event.kind)
        }) {
            let Some(pre_id) = event.pre_version else {
                missing_preimages += 1;
                known_unknowns.push(Unknown {
                    code: "MISSING_PREIMAGE".into(),
                    description: "The direct effect has no durable historical version reference."
                        .into(),
                    object_id: Some(effect.object_id),
                    sequence: Some(event.sequence),
                });
                continue;
            };
            let Some(version) = versions.get(&pre_id) else {
                missing_preimages += 1;
                known_unknowns.push(Unknown {
                    code: "MISSING_VERSION_RECORD".into(),
                    description:
                        "The event references a version that is not present in the version index."
                            .into(),
                    object_id: Some(effect.object_id),
                    sequence: Some(event.sequence),
                });
                continue;
            };
            if version.blob_ref.is_none()
                || matches!(version.fidelity, Fidelity::HashOnly | Fidelity::Unknown)
                || matches!(
                    version.preservation,
                    PreservationMethod::Missing
                        | PreservationMethod::Unsupported
                        | PreservationMethod::RaceDetected
                )
            {
                if version.preservation == PreservationMethod::RaceDetected {
                    race_detected_preimages += 1;
                } else {
                    missing_preimages += 1;
                }
                known_unknowns.push(Unknown {
                    code: format!("PREIMAGE_{:?}", version.preservation).to_uppercase(),
                    description:
                        "The historical version is not proven recoverable at byte fidelity.".into(),
                    object_id: Some(effect.object_id),
                    sequence: Some(event.sequence),
                });
                continue;
            }
            if later.is_empty() {
                exact_preimages += 1;
                let action = if event.kind == RealmEventKind::ObjectRename {
                    old_path_from_event(event)
                        .map(|old_path| ExactRestoreAction::RenameBack {
                            from: event.path.clone().unwrap_or_else(|| PathBytes(Vec::new())),
                            to: old_path,
                        })
                        .unwrap_or(ExactRestoreAction::RestoreBytes)
                } else {
                    ExactRestoreAction::RestoreBytes
                };
                exact_restores.push(ExactRestore {
                    object_id: effect.object_id,
                    target_path: event.path.clone().unwrap_or_else(|| PathBytes(Vec::new())),
                    historical_version: pre_id,
                    source_blob: version.blob_ref.clone(),
                    fidelity: version.fidelity,
                    action,
                    event_sequence: event.sequence,
                });
            }
        }
        for event in events.iter().filter(|event| {
            event.transaction_id == transaction.id
                && event.object_id == Some(effect.object_id)
                && event.kind == RealmEventKind::ObjectCreate
        }) {
            if later_for_event(events, event, transaction.id, effect.object_id).is_empty() {
                exact_restores.push(ExactRestore {
                    object_id: effect.object_id,
                    target_path: event.path.clone().unwrap_or_else(|| PathBytes(Vec::new())),
                    historical_version: ObjectVersionId::nil(),
                    source_blob: None,
                    fidelity: Fidelity::StructureExact,
                    action: ExactRestoreAction::RemoveCreatedPath,
                    event_sequence: event.sequence,
                });
            }
        }
        if !later.is_empty() {
            known_unknowns.push(Unknown {
                code: "OVERLAP_REQUIRES_SEMANTIC_DECISION".into(),
                description: "A later actor touched a target object; generic inverse is not safe."
                    .into(),
                object_id: Some(effect.object_id),
                sequence: Some(effect.last_sequence),
            });
        }
    }

    // Build overlaps separately to keep the loop above easy to audit.
    let mut overlaps = Vec::new();
    for effect in &direct_effects_to_remove {
        let later_events: Vec<LaterTouch> = events
            .iter()
            .filter(|event| {
                event.sequence > effect.last_sequence
                    && event.object_id == Some(effect.object_id)
                    && event.transaction_id != transaction.id
                    && is_effect(event.kind)
            })
            .map(|event| LaterTouch {
                transaction_id: event.transaction_id,
                sequence: event.sequence,
                operation: event.kind,
                path: event.path.clone(),
                observed_version: event.object_version_id.or(event.post_version),
            })
            .collect();
        if !later_events.is_empty() {
            overlaps.push(Overlap {
                object_id: effect.object_id,
                target_effect: effect.clone(),
                later_events,
            });
        }
    }
    overlaps.sort_by_key(|overlap| overlap.object_id);

    let target_post_versions: BTreeSet<ObjectVersionId> = direct_effects_to_remove
        .iter()
        .flat_map(|effect| effect.after_versions.iter().copied())
        .collect();
    let mut candidate_dependencies = Vec::new();
    let mut known_dependencies: Vec<Dependency> = Vec::new();
    for event in events.iter().filter(|event| {
        event.kind == RealmEventKind::ObjectRead && event.transaction_id != transaction.id
    }) {
        if target_post_versions.contains(&event.object_version_id.unwrap_or(ObjectVersionId::nil()))
        {
            candidate_dependencies.push(Dependency {
                source_object: event.object_id.unwrap_or(ObjectId::nil()),
                source_version: event.object_version_id,
                consumer_transaction: event.transaction_id,
                consumer_sequence: event.sequence,
                consumer_object: event.object_id,
                relation: "POSSIBLE_INFORMATION_DEPENDENCY".into(),
            });
        }
    }
    candidate_dependencies.sort_by_key(|dependency| dependency.consumer_sequence);
    known_dependencies.sort_by_key(|dependency| dependency.consumer_sequence);

    let mut must_preserve = Vec::new();
    for (object_id, version) in current_versions {
        if !direct_ids.contains(object_id) {
            let path = events
                .iter()
                .rev()
                .find(|event| event.object_id == Some(*object_id))
                .and_then(|event| event.path.clone());
            let version_record = versions.get(version);
            must_preserve.push(VersionExpectation {
                object_id: *object_id,
                version: Some(*version),
                path,
                expected_content_hash: version_record
                    .and_then(|record| record.content_hash.clone()),
                expected_metadata_hash: version_record
                    .and_then(|record| record.metadata_hash.clone()),
                reason: "outside target transaction affected set".into(),
            });
        }
    }
    must_preserve.sort_by_key(|expectation| expectation.object_id);
    let must_not_modify = must_preserve.clone();
    let may_modify = direct_effects_to_remove
        .iter()
        .flat_map(|effect| {
            effect.paths.iter().cloned().map(|path| PathExpectation {
                object_id: effect.object_id,
                path,
            })
        })
        .collect();
    for gap in &transaction.unresolved_gaps {
        known_unknowns.push(Unknown {
            code: "CAPTURE_GAP".into(),
            description: gap.reason.clone(),
            object_id: None,
            sequence: Some(gap.observed_sequence),
        });
    }
    exact_restores.sort_by_key(|restore| (restore.object_id, restore.event_sequence));
    known_unknowns.sort_by_key(|unknown| (unknown.object_id, unknown.sequence));
    let capture_quality = CaptureQuality {
        status: transaction.capture_status,
        exact_preimages,
        missing_preimages,
        race_detected_preimages,
        unresolved_gap_count: transaction.unresolved_gaps.len(),
    };
    let capability = if transaction.capture_status == CaptureStatus::Degraded
        || !overlaps.is_empty()
        || !known_unknowns.is_empty()
    {
        "uncertain"
    } else {
        "exact-for-listed-effects"
    };
    Ok(RecoveryContract {
        contract_version: 1,
        target_transaction: transaction.id,
        objective:
            "Remove effects attributable to target transaction while preserving protected state"
                .into(),
        exact_restores,
        direct_effects_to_remove,
        must_preserve,
        may_modify,
        must_not_modify,
        overlaps,
        known_dependencies,
        candidate_dependencies,
        known_unknowns,
        capture_quality,
        invariants: vec![
            Invariant {
                id: "capture-quality-bound".into(),
                description: format!(
                    "Recovery status may not exceed capture quality: {capability}"
                ),
                severity: "hard".into(),
            },
            Invariant {
                id: "isolated-write-scope".into(),
                description: "Candidate writes must remain inside the Recovery Workspace".into(),
                severity: "hard".into(),
            },
        ],
        external_effects: transaction
            .external_effects
            .iter()
            .map(|effect| serde_json::to_value(effect).unwrap_or_default())
            .collect(),
        required_adapters: Vec::new(),
    })
}

fn later_for_event<'a>(
    events: &'a [RealmEvent],
    event: &RealmEvent,
    transaction_id: TransactionId,
    object_id: ObjectId,
) -> Vec<&'a RealmEvent> {
    events
        .iter()
        .filter(|candidate| {
            candidate.sequence > event.sequence
                && candidate.object_id == Some(object_id)
                && candidate.transaction_id != transaction_id
                && is_effect(candidate.kind)
        })
        .collect()
}

fn old_path_from_event(event: &RealmEvent) -> Option<PathBytes> {
    event
        .metadata
        .get("old_path")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
}

fn is_effect(kind: RealmEventKind) -> bool {
    matches!(
        kind,
        RealmEventKind::ObjectCreate
            | RealmEventKind::ObjectWriteObserved
            | RealmEventKind::ObjectTruncate
            | RealmEventKind::ObjectDelete
            | RealmEventKind::ObjectRename
            | RealmEventKind::ObjectLink
            | RealmEventKind::ObjectSymlink
            | RealmEventKind::ObjectMetadataChange
            | RealmEventKind::ObjectMmap
    )
}

fn is_inverse_candidate(kind: RealmEventKind) -> bool {
    matches!(
        kind,
        RealmEventKind::ObjectWriteObserved
            | RealmEventKind::ObjectTruncate
            | RealmEventKind::ObjectDelete
            | RealmEventKind::ObjectRename
            | RealmEventKind::ObjectMetadataChange
            | RealmEventKind::ObjectMmap
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use realm_core::{
        ActorIdentity, ActorKind, EvidenceStrength, ObjectVersion, PreservationMethod,
        TransactionState,
    };

    #[test]
    fn compiles_exact_restore_and_later_overlap_without_calling_it_causal() {
        let mut tx = TransactionMetadata::new(
            ActorIdentity {
                kind: ActorKind::OtherAgent,
                actor_id: "lab".into(),
                semantic_session_id: None,
                declared_intent: None,
            },
            "synthetic",
            "test",
        );
        tx.id = TransactionId::new();
        tx.state = TransactionState::Committed;
        let object = ObjectId::new();
        let other = TransactionId::new();
        let before = ObjectVersionId::new();
        let after = ObjectVersionId::new();
        let version = ObjectVersion {
            id: before,
            object_id: object,
            content_hash: Some("h".into()),
            metadata_hash: None,
            blob_ref: Some("blob".into()),
            provenance_event: Some(1),
            fidelity: Fidelity::FullSupportedExact,
            preservation: PreservationMethod::ExactCopy,
        };
        let event = |sequence, transaction_id, kind, pre, post| RealmEvent {
            schema_version: 1,
            sequence,
            transaction_id,
            actor_id: "lab".into(),
            process_id: None,
            object_id: Some(object),
            object_version_id: post,
            path: Some(PathBytes(b"x".to_vec())),
            kind,
            evidence: EvidenceStrength::OsObserved,
            wall_time_ms: sequence as i64,
            monotonic_ns: sequence,
            pre_version: pre,
            post_version: post,
            metadata: serde_json::json!({}),
        };
        let events = vec![
            event(
                1,
                tx.id,
                RealmEventKind::ObjectWriteObserved,
                Some(before),
                Some(after),
            ),
            event(
                2,
                other,
                RealmEventKind::ObjectRead,
                Some(after),
                Some(after),
            ),
            event(
                3,
                other,
                RealmEventKind::ObjectWriteObserved,
                Some(after),
                None,
            ),
        ];
        let contract = compile_contract(
            &tx,
            &events,
            &[(before, version)].into_iter().collect(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(contract.exact_restores.is_empty());
        assert_eq!(contract.overlaps.len(), 1);
        assert_eq!(contract.candidate_dependencies.len(), 1);
        assert!(
            contract
                .known_unknowns
                .iter()
                .any(|u| u.code == "OVERLAP_REQUIRES_SEMANTIC_DECISION")
        );
    }
}
