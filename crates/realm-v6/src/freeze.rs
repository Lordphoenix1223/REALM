//! A non-authorizing FreezeEpoch binding. This branch has no immutable
//! snapshot primitive and therefore cannot issue a publication FreezeToken.
use crate::frontier::{EffectFrontier, SnapshotCandidate};
use crate::mediation::{CapabilityLedger, CheckedMediationClaim};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreezeEpochDraft {
    pub run_id: String,
    pub mediation_manifest_root: String,
    pub frontier_root: String,
    pub input_version: String,
    pub output_version: String,
    pub staged_snapshot_root: String,
    pub immutable_snapshot_identity: Option<String>,
    pub freeze_epoch: String,
    pub binding_root: String,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FreezeFailure {
    NotTerminal,
    MismatchedBinding,
    NotSealed,
    UnverifiedImmutability,
}

pub fn draft_freeze_epoch(
    ledger: &CapabilityLedger,
    frontier: &EffectFrontier,
    claim: &CheckedMediationClaim,
    snapshot: &SnapshotCandidate,
) -> Result<FreezeEpochDraft, FreezeFailure> {
    ledger.terminal().map_err(|_| FreezeFailure::NotTerminal)?;
    if !frontier.is_sealed() || !frontier.terminal_barrier_confirmed() {
        return Err(FreezeFailure::NotSealed);
    }
    if snapshot.run_id != claim.manifest().run_id
        || snapshot.run_id != frontier.run_id()
        || snapshot.mediation_manifest_root != claim.session_binding_root()
        || snapshot.frontier_head != frontier.head()
        || snapshot.launch_root != claim.manifest().launch_identity
        || snapshot.starting_generation != claim.manifest().starting_generation
        || snapshot.input_digest != frontier.current_content_digest(false)
        || snapshot.output_digest != frontier.current_content_digest(true)
    {
        return Err(FreezeFailure::MismatchedBinding);
    }
    let mut d = FreezeEpochDraft {
        run_id: snapshot.run_id.clone(),
        mediation_manifest_root: claim.session_binding_root().into(),
        frontier_root: frontier.head().into(),
        input_version: snapshot.input_digest.clone(),
        output_version: frontier.current_version(true).into(),
        staged_snapshot_root: snapshot.snapshot_root.clone(),
        immutable_snapshot_identity: None,
        freeze_epoch: snapshot.freeze_epoch.clone(),
        binding_root: String::new(),
        status: "DRAFT_NO_IMMUTABLE_SNAPSHOT".into(),
    };
    d.binding_root =
        blake3::hash(&serde_json::to_vec(&d).map_err(|_| FreezeFailure::MismatchedBinding)?)
            .to_hex()
            .to_string();
    Ok(d)
}

/// Deliberately unavailable: staged copies are mutable paths and cannot
/// satisfy the exact-object publication condition.
pub fn publication_token(_draft: &FreezeEpochDraft) -> Result<(), FreezeFailure> {
    Err(FreezeFailure::UnverifiedImmutability)
}
