//! Structural V6-to-V5 candidate binding. This does not call V5 authority.
//! The V6 branch lacks the V5 publication APIs and has no FreezeToken issuer.

use crate::freeze::FreezeEpochDraft;
use crate::frontier::{FrontierAudit, SnapshotCandidate};
use serde::{Deserialize, Serialize};

pub const V5_PROTOCOL_ID: &str = "realm-v5-identity-neutral-state-authority-v2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V5HandoffDraft {
    pub protocol_id: String,
    pub run_id: String,
    pub expected_parent: String,
    pub candidate_generation: String,
    pub snapshot_root: String,
    pub frontier_root: String,
    pub mediation_manifest_root: String,
    pub freeze_epoch: String,
    pub freeze_binding_root: String,
    pub launch_root: String,
    pub policy_root: String,
    pub dependency_root: String,
    pub receipt_root: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandoffFailure {
    InvalidDigest,
    ParentMismatch,
    FrontierMismatch,
    FreezeMismatch,
    CandidateEqualsParent,
}

fn digest_shape(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Bind exact V6 candidate fields for a future V5 adapter. The receipt bytes
/// are hashed, not verified here. No publication method accepts this draft.
pub fn draft_v5_handoff(
    snapshot: &SnapshotCandidate,
    frontier: &FrontierAudit,
    expected_parent: &str,
    candidate_generation: &str,
    receipt_bytes: &[u8],
) -> Result<V5HandoffDraft, HandoffFailure> {
    if ![
        expected_parent,
        candidate_generation,
        &snapshot.snapshot_root,
        &snapshot.frontier_head,
        &snapshot.mediation_manifest_root,
        &snapshot.launch_root,
        &snapshot.policy_root,
        &snapshot.dependency_root,
    ]
    .iter()
    .all(|s| digest_shape(s))
    {
        return Err(HandoffFailure::InvalidDigest);
    }
    if snapshot.starting_generation != expected_parent {
        return Err(HandoffFailure::ParentMismatch);
    }
    if snapshot.frontier_head != frontier.head {
        return Err(HandoffFailure::FrontierMismatch);
    }
    if candidate_generation == expected_parent {
        return Err(HandoffFailure::CandidateEqualsParent);
    }
    Ok(V5HandoffDraft {
        protocol_id: V5_PROTOCOL_ID.into(),
        run_id: snapshot.run_id.clone(),
        expected_parent: expected_parent.into(),
        candidate_generation: candidate_generation.into(),
        snapshot_root: snapshot.snapshot_root.clone(),
        frontier_root: frontier.head.clone(),
        mediation_manifest_root: snapshot.mediation_manifest_root.clone(),
        freeze_epoch: snapshot.freeze_epoch.clone(),
        freeze_binding_root: String::new(),
        launch_root: snapshot.launch_root.clone(),
        policy_root: snapshot.policy_root.clone(),
        dependency_root: snapshot.dependency_root.clone(),
        receipt_root: blake3::hash(receipt_bytes).to_hex().to_string(),
    })
}

/// A tighter non-authorizing candidate intent. The FreezeEpochDraft still
/// lacks an immutable snapshot witness, so no V5 activation accepts it.
pub fn draft_v5_handoff_bound(
    snapshot: &SnapshotCandidate,
    frontier: &FrontierAudit,
    freeze: &FreezeEpochDraft,
    expected_parent: &str,
    candidate_generation: &str,
    receipt_bytes: &[u8],
) -> Result<V5HandoffDraft, HandoffFailure> {
    let mut draft = draft_v5_handoff(
        snapshot,
        frontier,
        expected_parent,
        candidate_generation,
        receipt_bytes,
    )?;
    if freeze.run_id != snapshot.run_id
        || freeze.mediation_manifest_root != snapshot.mediation_manifest_root
        || freeze.frontier_root != frontier.head
        || freeze.staged_snapshot_root != snapshot.snapshot_root
        || freeze.freeze_epoch != snapshot.freeze_epoch
        || !digest_shape(&freeze.binding_root)
    {
        return Err(HandoffFailure::FreezeMismatch);
    }
    draft.freeze_binding_root = freeze.binding_root.clone();
    Ok(draft)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture() -> (SnapshotCandidate, FrontierAudit) {
        let a = "a".repeat(64);
        let snapshot = SnapshotCandidate {
            run_id: "run-1".into(),
            starting_generation: a.clone(),
            frontier_head: "b".repeat(64),
            mediation_manifest_root: "3".repeat(64),
            freeze_epoch: "e1".into(),
            launch_root: "c".repeat(64),
            policy_root: "d".repeat(64),
            dependency_root: "e".repeat(64),
            snapshot_dir: PathBuf::from("/host/private/snapshot"),
            input_digest: "f".repeat(64),
            output_digest: "0".repeat(64),
            snapshot_root: "1".repeat(64),
        };
        let frontier = FrontierAudit {
            records: vec![],
            head: snapshot.frontier_head.clone(),
            reads: vec![],
            committed_write_count: 0,
        };
        (snapshot, frontier)
    }

    #[test]
    fn draft_binds_exact_parent_and_frontier() {
        let (snapshot, frontier) = fixture();
        let candidate = "2".repeat(64);
        let draft = draft_v5_handoff(
            &snapshot,
            &frontier,
            &snapshot.starting_generation,
            &candidate,
            b"unverified receipt",
        )
        .unwrap();
        assert_eq!(draft.expected_parent, snapshot.starting_generation);
        assert_eq!(draft.frontier_root, frontier.head);
        assert_eq!(draft.protocol_id, V5_PROTOCOL_ID);
        assert_eq!(
            draft.receipt_root,
            blake3::hash(b"unverified receipt").to_hex().to_string()
        );
    }

    #[test]
    fn stale_parent_or_wrong_frontier_refuses_draft() {
        let (snapshot, mut frontier) = fixture();
        let candidate = "2".repeat(64);
        assert_eq!(
            draft_v5_handoff(&snapshot, &frontier, &"9".repeat(64), &candidate, b"r"),
            Err(HandoffFailure::ParentMismatch)
        );
        frontier.head = "8".repeat(64);
        assert_eq!(
            draft_v5_handoff(
                &snapshot,
                &frontier,
                &snapshot.starting_generation,
                &candidate,
                b"r"
            ),
            Err(HandoffFailure::FrontierMismatch)
        );
        assert_eq!(
            draft_v5_handoff(
                &snapshot,
                &frontier,
                &snapshot.starting_generation,
                &snapshot.starting_generation,
                b"r"
            ),
            Err(HandoffFailure::FrontierMismatch)
        );
        frontier.head = snapshot.frontier_head.clone();
        assert_eq!(
            draft_v5_handoff(
                &snapshot,
                &frontier,
                &snapshot.starting_generation,
                &snapshot.starting_generation,
                b"r"
            ),
            Err(HandoffFailure::CandidateEqualsParent)
        );
    }
}
