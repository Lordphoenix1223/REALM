//! Capture abstraction and deterministic synthetic backend.
//!
//! The synthetic backend is a permanent laboratory component. It exercises
//! Realm's evidence and persistence semantics without pretending to prove an
//! operating-system capture guarantee.

use realm_core::{
    CaptureGap, CaptureStatus, EvidenceStrength, ObjectId, ObjectVersionId, PathBytes, ProcessId,
    RealmEvent, RealmEventKind, TransactionId,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaptureBatch {
    pub transaction_id: TransactionId,
    pub events: Vec<RealmEvent>,
    pub gaps: Vec<CaptureGap>,
    pub status: CaptureStatus,
}

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("capture backend is not active")]
    Inactive,
    #[error("capture sequence overflow")]
    SequenceOverflow,
}

pub trait CaptureBackend {
    fn name(&self) -> &str;
    fn start(&mut self, transaction_id: TransactionId) -> Result<(), CaptureError>;
    fn stop(&mut self) -> Result<CaptureBatch, CaptureError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SequenceGap {
    pub stream: String,
    pub expected: u64,
    pub observed: u64,
    pub reason: String,
}

/// Tracks both a per-event stream and the global ES sequence. Either gap is
/// sufficient to degrade a transaction; a global sequence cannot repair a
/// missing per-stream event.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SequenceGapDetector {
    per_stream: BTreeMap<String, u64>,
    last_global: Option<u64>,
    pub gaps: Vec<SequenceGap>,
}

impl SequenceGapDetector {
    pub fn observe(
        &mut self,
        stream: impl Into<String>,
        sequence: u64,
        global_sequence: Option<u64>,
    ) -> Vec<SequenceGap> {
        let stream = stream.into();
        let mut new_gaps = Vec::new();
        if let Some(last) = self.per_stream.get(&stream).copied() {
            let expected = last.saturating_add(1);
            if sequence != expected {
                new_gaps.push(SequenceGap {
                    stream: stream.clone(),
                    expected,
                    observed: sequence,
                    reason: if sequence < expected {
                        "duplicate_or_reordered_stream_sequence".into()
                    } else {
                        "dropped_stream_sequence".into()
                    },
                });
            }
        }
        self.per_stream.insert(stream, sequence);
        if let (Some(last), Some(global)) = (self.last_global, global_sequence) {
            let expected = last.saturating_add(1);
            if global != expected {
                new_gaps.push(SequenceGap {
                    stream: "global".into(),
                    expected,
                    observed: global,
                    reason: if global < expected {
                        "duplicate_or_reordered_global_sequence".into()
                    } else {
                        "dropped_global_sequence".into()
                    },
                });
            }
        }
        if global_sequence.is_some() {
            self.last_global = global_sequence;
        }
        self.gaps.extend(new_gaps.iter().cloned());
        new_gaps
    }

    pub fn degraded(&self) -> bool {
        !self.gaps.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct MutationCapability {
    pub effect_id: String,
    pub object_id: Option<ObjectId>,
    pub path: Option<PathBytes>,
    pub operation: RealmEventKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnexpectedMutation {
    pub code: String,
    pub object_id: Option<ObjectId>,
    pub path: Option<PathBytes>,
    pub kind: RealmEventKind,
    pub description: String,
}

/// A post-observation without an admitted capability is a safety failure, not
/// a recoverable warning. This detector is intentionally conservative about
/// matching and never attributes by timing or actor name.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UnexpectedMutationDetector {
    admitted: BTreeSet<MutationCapability>,
    pub violations: Vec<UnexpectedMutation>,
}

impl UnexpectedMutationDetector {
    pub fn admit(&mut self, capability: MutationCapability) {
        self.admitted.insert(capability);
    }

    pub fn observe(&mut self, event: &RealmEvent) -> Option<UnexpectedMutation> {
        if !is_mutation_event(event.kind) {
            return None;
        }
        let matched = self.admitted.iter().any(|capability| {
            capability.object_id == event.object_id
                && capability.path == event.path
                && capability.operation == event.kind
        });
        if matched {
            return None;
        }
        let violation = UnexpectedMutation {
            code: "UNADMITTED_MUTATION".into(),
            object_id: event.object_id,
            path: event.path.clone(),
            kind: event.kind,
            description: "OS-observed mutation has no matching admitted capability".into(),
        };
        self.violations.push(violation.clone());
        Some(violation)
    }

    pub fn degraded(&self) -> bool {
        !self.violations.is_empty()
    }
}

fn is_mutation_event(kind: RealmEventKind) -> bool {
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

#[derive(Default)]
pub struct SyntheticCaptureBackend {
    transaction_id: Option<TransactionId>,
    actor_id: String,
    process_id: Option<ProcessId>,
    sequence: u64,
    events: Vec<RealmEvent>,
    gaps: Vec<CaptureGap>,
    status: CaptureStatus,
}

impl SyntheticCaptureBackend {
    pub fn with_actor(actor_id: impl Into<String>) -> Self {
        Self {
            actor_id: actor_id.into(),
            ..Self::default()
        }
    }

    pub fn emit(
        &mut self,
        kind: RealmEventKind,
        object_id: Option<ObjectId>,
        path: Option<PathBytes>,
        pre_version: Option<ObjectVersionId>,
        post_version: Option<ObjectVersionId>,
        metadata: serde_json::Value,
    ) -> Result<u64, CaptureError> {
        let transaction_id = self.transaction_id.ok_or(CaptureError::Inactive)?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(CaptureError::SequenceOverflow)?;
        let sequence = self.sequence;
        self.events.push(RealmEvent {
            schema_version: 1,
            sequence,
            transaction_id,
            actor_id: self.actor_id.clone(),
            process_id: self.process_id,
            object_id,
            object_version_id: post_version,
            path,
            kind,
            evidence: EvidenceStrength::OsObserved,
            wall_time_ms: sequence as i64,
            monotonic_ns: sequence * 1_000,
            pre_version,
            post_version,
            metadata,
        });
        Ok(sequence)
    }

    pub fn set_process(&mut self, process_id: ProcessId) {
        self.process_id = Some(process_id);
    }

    pub fn process_spawn(
        &mut self,
        process_id: ProcessId,
        metadata: serde_json::Value,
    ) -> Result<u64, CaptureError> {
        self.process_id = Some(process_id);
        self.emit(
            RealmEventKind::ProcessSpawn,
            None,
            None,
            None,
            None,
            metadata,
        )
    }

    pub fn process_exec(&mut self, metadata: serde_json::Value) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::ProcessExec,
            None,
            None,
            None,
            None,
            metadata,
        )
    }
    pub fn process_exit(&mut self, metadata: serde_json::Value) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::ProcessExit,
            None,
            None,
            None,
            None,
            metadata,
        )
    }
    pub fn object_read(
        &mut self,
        object_id: ObjectId,
        path: PathBytes,
        version: Option<ObjectVersionId>,
    ) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::ObjectRead,
            Some(object_id),
            Some(path),
            version,
            version,
            json!({"relation":"OBSERVED_READ"}),
        )
    }
    pub fn writable_open(
        &mut self,
        object_id: ObjectId,
        path: PathBytes,
        version: Option<ObjectVersionId>,
    ) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::ObjectWritableOpen,
            Some(object_id),
            Some(path),
            version,
            version,
            json!({}),
        )
    }
    pub fn object_create(
        &mut self,
        object_id: ObjectId,
        path: PathBytes,
        version: Option<ObjectVersionId>,
    ) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::ObjectCreate,
            Some(object_id),
            Some(path),
            None,
            version,
            json!({}),
        )
    }
    pub fn object_write(
        &mut self,
        object_id: ObjectId,
        path: PathBytes,
        pre: Option<ObjectVersionId>,
        post: Option<ObjectVersionId>,
    ) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::ObjectWriteObserved,
            Some(object_id),
            Some(path),
            pre,
            post,
            json!({}),
        )
    }
    pub fn object_truncate(
        &mut self,
        object_id: ObjectId,
        path: PathBytes,
        pre: Option<ObjectVersionId>,
        post: Option<ObjectVersionId>,
    ) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::ObjectTruncate,
            Some(object_id),
            Some(path),
            pre,
            post,
            json!({}),
        )
    }
    pub fn object_delete(
        &mut self,
        object_id: ObjectId,
        path: PathBytes,
        pre: Option<ObjectVersionId>,
    ) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::ObjectDelete,
            Some(object_id),
            Some(path),
            pre,
            None,
            json!({}),
        )
    }
    pub fn object_rename(
        &mut self,
        object_id: ObjectId,
        old_path: PathBytes,
        new_path: PathBytes,
        pre: Option<ObjectVersionId>,
        post: Option<ObjectVersionId>,
    ) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::ObjectRename,
            Some(object_id),
            Some(new_path),
            pre,
            post,
            json!({"old_path":old_path}),
        )
    }
    pub fn object_link(
        &mut self,
        object_id: ObjectId,
        path: PathBytes,
    ) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::ObjectLink,
            Some(object_id),
            Some(path),
            None,
            None,
            json!({}),
        )
    }
    pub fn object_symlink(
        &mut self,
        object_id: ObjectId,
        path: PathBytes,
        target: PathBytes,
    ) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::ObjectSymlink,
            Some(object_id),
            Some(path),
            None,
            None,
            json!({"target":target}),
        )
    }
    pub fn object_metadata_change(
        &mut self,
        object_id: ObjectId,
        path: PathBytes,
        pre: Option<ObjectVersionId>,
        post: Option<ObjectVersionId>,
    ) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::ObjectMetadataChange,
            Some(object_id),
            Some(path),
            pre,
            post,
            json!({}),
        )
    }
    pub fn object_mmap(
        &mut self,
        object_id: ObjectId,
        path: PathBytes,
        pre: Option<ObjectVersionId>,
        post: Option<ObjectVersionId>,
    ) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::ObjectMmap,
            Some(object_id),
            Some(path),
            pre,
            post,
            json!({"simulated":true}),
        )
    }
    pub fn agent_event(&mut self, metadata: serde_json::Value) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::AgentSemanticEvent,
            None,
            None,
            None,
            None,
            metadata,
        )
    }
    pub fn external_effect(&mut self, metadata: serde_json::Value) -> Result<u64, CaptureError> {
        self.emit(
            RealmEventKind::ExternalEffect,
            None,
            None,
            None,
            None,
            metadata,
        )
    }

    pub fn gap(
        &mut self,
        expected_sequence: u64,
        observed_sequence: u64,
        reason: impl Into<String>,
    ) -> Result<(), CaptureError> {
        let transaction_id = self.transaction_id.ok_or(CaptureError::Inactive)?;
        self.status.degrade();
        let gap = CaptureGap {
            transaction_id,
            stream: "synthetic".into(),
            expected_sequence,
            observed_sequence,
            wall_time_ms: self.sequence as i64,
            reason: reason.into(),
        };
        self.gaps.push(gap.clone());
        self.sequence = observed_sequence.saturating_sub(1);
        self.emit(
            RealmEventKind::CaptureGap,
            None,
            None,
            None,
            None,
            serde_json::to_value(gap).unwrap_or_default(),
        )?;
        Ok(())
    }
}

impl CaptureBackend for SyntheticCaptureBackend {
    fn name(&self) -> &str {
        "synthetic"
    }

    fn start(&mut self, transaction_id: TransactionId) -> Result<(), CaptureError> {
        self.transaction_id = Some(transaction_id);
        self.sequence = 0;
        self.events.clear();
        self.gaps.clear();
        self.status = CaptureStatus::Complete;
        Ok(())
    }

    fn stop(&mut self) -> Result<CaptureBatch, CaptureError> {
        let transaction_id = self.transaction_id.take().ok_or(CaptureError::Inactive)?;
        Ok(CaptureBatch {
            transaction_id,
            events: std::mem::take(&mut self.events),
            gaps: std::mem::take(&mut self.gaps),
            status: self.status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn emits_all_synthetic_operation_families_and_degrades_monotonically() {
        let tx = TransactionId::new();
        let object = ObjectId::new();
        let version = ObjectVersionId::new();
        let mut backend = SyntheticCaptureBackend::with_actor("lab");
        backend.start(tx).unwrap();
        backend
            .object_create(object, PathBytes(b"a".to_vec()), Some(version))
            .unwrap();
        backend
            .object_write(
                object,
                PathBytes(b"a".to_vec()),
                Some(version),
                Some(ObjectVersionId::new()),
            )
            .unwrap();
        backend
            .object_mmap(object, PathBytes(b"a".to_vec()), None, None)
            .unwrap();
        backend.gap(4, 6, "dropped synthetic sequence").unwrap();
        let batch = backend.stop().unwrap();
        assert_eq!(batch.status, CaptureStatus::Degraded);
        assert!(
            batch
                .events
                .iter()
                .any(|event| event.kind == RealmEventKind::CaptureGap)
        );
        assert!(
            batch
                .events
                .iter()
                .any(|event| event.kind == RealmEventKind::ObjectMmap)
        );
    }

    #[test]
    fn sequence_detector_reports_stream_and_global_gaps() {
        let mut detector = SequenceGapDetector::default();
        assert!(detector.observe("open", 1, Some(10)).is_empty());
        let gaps = detector.observe("open", 3, Some(12));
        assert_eq!(gaps.len(), 2);
        assert!(detector.degraded());
    }

    #[test]
    fn unexpected_mutation_is_a_fail_closed_violation() {
        let tx = TransactionId::new();
        let object = ObjectId::new();
        let mut backend = SyntheticCaptureBackend::with_actor("lab");
        backend.start(tx).unwrap();
        backend
            .object_write(object, PathBytes(b"a".to_vec()), None, None)
            .unwrap();
        let event = backend.stop().unwrap().events.remove(0);
        let mut detector = UnexpectedMutationDetector::default();
        let violation = detector.observe(&event).unwrap();
        assert_eq!(violation.code, "UNADMITTED_MUTATION");
        assert!(detector.degraded());
    }
}
