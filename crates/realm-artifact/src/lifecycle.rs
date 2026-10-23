//! Independent reconstruction of the durable V6 generation lifecycle.
//!
//! This module verifies publication evidence. It never creates a checked
//! execution, ACCEPT decision, or publication capability.

use crate::{
    ArtifactBundle, Digest, ValidationLevel,
    v6::{GENERATION_EXCHANGE_MECHANISM, GenerationPublicationEvidence},
};
use realm_v6::profile::SyncTrace as _;
use realm_v6::{
    execute::CheckedExecutionForPublication,
    filesystem_world,
    generation::{
        CommittedGeneration, GenerationError, GenerationIdentity, GenerationLayout,
        GenerationReceipt, PreparedGeneration, commit_generation_held,
    },
    publication_journal::{
        DestinationLock, PublicationJournal, PublicationJournalError, PublicationRecord,
        PublicationState,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const GENESIS_DOMAIN: &str = "realm.v6.lifecycle-genesis.v1";
const TRANSITION_DOMAIN: &str = "realm.v6.lifecycle-transition.v1";
const HEAD_DOMAIN: &str = "realm.v6.authority-head.v1";

/// A trust anchor supplied independently by the verifier's operator.
/// `root()` must be pinned outside the publication directory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisAnchor {
    pub schema_version: u16,
    pub domain: String,
    pub workspace_identity: String,
    pub initial_world_root: String,
    pub label: String,
}

impl GenesisAnchor {
    pub fn new(
        workspace_identity: impl Into<String>,
        initial_world_root: impl Into<String>,
        label: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            domain: GENESIS_DOMAIN.into(),
            workspace_identity: workspace_identity.into(),
            initial_world_root: initial_world_root.into(),
            label: label.into(),
        }
    }

    pub fn root(&self) -> Result<String, LifecycleError> {
        if self.schema_version != 1
            || self.domain != GENESIS_DOMAIN
            || self.workspace_identity.is_empty()
            || !valid_digest(&self.initial_world_root)
            || self.label.is_empty()
        {
            return Err(LifecycleError::Unknown(
                "unsupported or malformed trusted genesis".into(),
            ));
        }
        hash_json(GENESIS_DOMAIN, self)
    }
}

/// One immutable, content-addressed edge in the publication history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleTransition {
    pub schema_version: u16,
    pub domain: String,
    pub sequence: u64,
    pub parent_authority_root: String,
    pub parent_generation_root: String,
    pub parent_world_root: String,
    pub generation_identity: GenerationIdentity,
    pub semantic_run_root: Digest,
    pub artifact_digest: Digest,
    pub receipt_digest: Digest,
    pub journal_record_digest: Digest,
    pub journal_sequence: u64,
    pub world_root: String,
    pub delta_root: String,
}

impl LifecycleTransition {
    pub fn root(&self) -> Result<String, LifecycleError> {
        if self.schema_version != 1 || self.domain != TRANSITION_DOMAIN {
            return Err(LifecycleError::Unknown(
                "unsupported lifecycle transition schema or domain".into(),
            ));
        }
        hash_json(TRANSITION_DOMAIN, self)
    }
}

/// The one mutable pointer to the immutable transition chain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHead {
    pub schema_version: u16,
    pub domain: String,
    pub workspace_identity: String,
    pub sequence: u64,
    pub authority_root: String,
    pub generation_root: String,
    pub world_root: String,
    pub transition_root: Option<String>,
    pub parent_authority_root: Option<String>,
}

impl AuthorityHead {
    pub fn from_genesis(anchor: &GenesisAnchor) -> Result<Self, LifecycleError> {
        let root = anchor.root()?;
        Ok(Self {
            schema_version: 1,
            domain: HEAD_DOMAIN.into(),
            workspace_identity: anchor.workspace_identity.clone(),
            sequence: 0,
            authority_root: root.clone(),
            generation_root: root,
            world_root: anchor.initial_world_root.clone(),
            transition_root: None,
            parent_authority_root: None,
        })
    }

    pub fn from_transition(
        anchor: &GenesisAnchor,
        transition: &LifecycleTransition,
    ) -> Result<Self, LifecycleError> {
        let transition_root = transition.root()?;
        let head = Self {
            schema_version: 1,
            domain: HEAD_DOMAIN.into(),
            workspace_identity: anchor.workspace_identity.clone(),
            sequence: transition.sequence,
            authority_root: String::new(),
            generation_root: transition_root.clone(),
            world_root: transition.world_root.clone(),
            transition_root: Some(transition_root),
            parent_authority_root: Some(transition.parent_authority_root.clone()),
        };
        let authority_root = head.calculated_root()?;
        Ok(Self {
            authority_root,
            ..head
        })
    }

    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.schema_version != 1 || self.domain != HEAD_DOMAIN {
            return Err(LifecycleError::Unknown(
                "unsupported authority-head schema or domain".into(),
            ));
        }
        if self.sequence != 0 && self.authority_root != self.calculated_root()? {
            return Err(LifecycleError::Invalid(
                "authority-head content digest mismatch".into(),
            ));
        }
        if self.sequence == 0 {
            if self.transition_root.is_some() || self.parent_authority_root.is_some() {
                return Err(LifecycleError::Invalid(
                    "genesis authority head contains a transition".into(),
                ));
            }
        } else if self.transition_root.as_deref() != Some(self.generation_root.as_str())
            || self.parent_authority_root.is_none()
        {
            return Err(LifecycleError::Invalid(
                "authority head is not bound to its terminal transition".into(),
            ));
        }
        Ok(())
    }

    fn calculated_root(&self) -> Result<String, LifecycleError> {
        #[derive(Serialize)]
        struct Body<'a> {
            schema_version: u16,
            domain: &'a str,
            workspace_identity: &'a str,
            sequence: u64,
            generation_root: &'a str,
            world_root: &'a str,
            transition_root: &'a Option<String>,
            parent_authority_root: &'a Option<String>,
        }
        hash_json(
            HEAD_DOMAIN,
            &Body {
                schema_version: self.schema_version,
                domain: &self.domain,
                workspace_identity: &self.workspace_identity,
                sequence: self.sequence,
                generation_root: &self.generation_root,
                world_root: &self.world_root,
                transition_root: &self.transition_root,
                parent_authority_root: &self.parent_authority_root,
            },
        )
    }
}

/// Out-of-band pins needed to distinguish a reconstructed chain from a
/// locally rewritten or rolled-back copy of that chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleTrust {
    pub genesis_root: String,
    pub previously_trusted_head_root: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleSnapshot {
    pub head: AuthorityHead,
    pub transitions: Vec<LifecycleTransition>,
    /// Keyed by the BLAKE3 digest of the complete packed `.realm` bytes.
    pub artifacts: BTreeMap<String, Vec<u8>>,
    /// Durable receipt files keyed by their raw BLAKE3 digest.
    pub receipts: BTreeMap<String, Vec<u8>>,
    /// The complete append-only journal, including its final newline.
    pub journal: Vec<u8>,
    pub live_world_root: String,
    /// The retained previous world root for each generation ID.
    pub retained_world_roots: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationState {
    Valid,
    Invalid,
    Incomplete,
    Rollback,
    Fork,
    MixedGeneration,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub state: VerificationState,
    pub verified_transitions: u64,
    pub reconstructed_head_root: Option<String>,
    pub diagnostic: String,
}

/// A serializable public report created only after a checked execution has
/// advanced the durable generation head and the complete lifecycle verifies.
/// This type and its emitter are absent from test-support builds.
#[cfg(not(feature = "test-support"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicDecision {
    Accept,
}

#[cfg(not(feature = "test-support"))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedAcceptReport {
    schema_version: u16,
    domain: String,
    decision: PublicDecision,
    run_id: String,
    execution_id: String,
    semantic_run_root: Digest,
    generation_id: String,
    publication_id: String,
    parent_authority_head_root: String,
    authority_head_root: String,
    authority_head_sequence: u64,
    verified_transitions: u64,
    artifact_digest: Digest,
}

#[cfg(not(feature = "test-support"))]
impl PublishedAcceptReport {
    pub fn decision(&self) -> PublicDecision {
        self.decision
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub fn authority_head_root(&self) -> &str {
        &self.authority_head_root
    }

    pub fn authority_head_sequence(&self) -> u64 {
        self.authority_head_sequence
    }

    pub fn verified_transitions(&self) -> u64 {
        self.verified_transitions
    }
}

/// The production transaction output. The wrapper is not an execution or
/// publication capability; serializing its report cannot recreate authority.
#[cfg(not(feature = "test-support"))]
pub struct PublishedAccept {
    report: PublishedAcceptReport,
    bundle: ArtifactBundle,
}

#[cfg(not(feature = "test-support"))]
impl PublishedAccept {
    pub fn report(&self) -> &PublishedAcceptReport {
        &self.report
    }

    pub fn bundle(&self) -> &ArtifactBundle {
        &self.bundle
    }

    pub fn into_parts(self) -> (PublishedAcceptReport, ArtifactBundle) {
        (self.report, self.bundle)
    }
}

/// Test-only result for synthetic authority fixtures. Test-support builds do
/// not contain the public ACCEPT report type or emitter.
///
/// ```compile_fail
/// use realm_artifact::lifecycle::{PublicDecision, PublishedAcceptReport};
/// ```
#[cfg(feature = "test-support")]
pub struct TestPublicationVerification {
    bundle: ArtifactBundle,
    run_id: String,
    execution_id: String,
    generation_id: String,
    publication_id: String,
    parent_authority_head_root: String,
    authority_head_root: String,
    authority_head_sequence: u64,
    verification_state: VerificationState,
    verified_transitions: u64,
}

#[cfg(feature = "test-support")]
impl TestPublicationVerification {
    pub fn bundle(&self) -> &ArtifactBundle {
        &self.bundle
    }

    pub fn authority_head_root(&self) -> &str {
        &self.authority_head_root
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    pub fn publication_id(&self) -> &str {
        &self.publication_id
    }

    pub fn parent_authority_head_root(&self) -> &str {
        &self.parent_authority_head_root
    }

    pub fn authority_head_sequence(&self) -> u64 {
        self.authority_head_sequence
    }

    pub fn verification_state(&self) -> VerificationState {
        self.verification_state
    }

    pub fn verified_transitions(&self) -> u64 {
        self.verified_transitions
    }
}

struct VerifiedPublicationState {
    bundle: ArtifactBundle,
    head: AuthorityHead,
    verification: VerificationResult,
    identity: GenerationIdentity,
    parent_authority_head_root: String,
    run_id: String,
    execution_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("unknown lifecycle material: {0}")]
    Unknown(String),
    #[error("invalid lifecycle material: {0}")]
    Invalid(String),
    #[error("incomplete lifecycle material: {0}")]
    Incomplete(String),
    #[error("rollback detected: {0}")]
    Rollback(String),
    #[error("generation fork detected: {0}")]
    Fork(String),
    #[error("mixed generation material: {0}")]
    Mixed(String),
    #[error(transparent)]
    Artifact(#[from] crate::ArtifactError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Generation(#[from] GenerationError),
    #[error(transparent)]
    Journal(#[from] PublicationJournalError),
    #[error("filesystem scan failed: {0}")]
    Scan(String),
}

impl From<realm_v6::filesystem_world::FilesystemScanError> for LifecycleError {
    fn from(error: realm_v6::filesystem_world::FilesystemScanError) -> Self {
        Self::Scan(format!("{error:?}"))
    }
}

/// Persist the operator-selected initial S0 as the explicit trust anchor and
/// create the initial authority head. Repeating the call is idempotent only
/// for the exact same anchor and live root.
pub fn initialize_lifecycle(
    layout: &GenerationLayout,
    anchor: &GenesisAnchor,
    externally_pinned_genesis_root: &str,
) -> Result<AuthorityHead, LifecycleError> {
    let _lock = DestinationLock::acquire(layout.live_root())?;
    if anchor.root()? != externally_pinned_genesis_root {
        return Err(LifecycleError::Unknown(
            "genesis does not match the caller's external pin".into(),
        ));
    }
    if anchor.workspace_identity != layout.workspace_identity() {
        return Err(LifecycleError::Mixed(
            "genesis belongs to another managed workspace".into(),
        ));
    }
    layout.ensure_control_root()?;
    let root = lifecycle_root(layout);
    ensure_private_directory(&root)?;
    ensure_private_directory(&root.join("artifacts"))?;
    ensure_private_directory(&root.join("transitions"))?;
    let anchor_bytes = serde_json::to_vec(anchor)?;
    write_once(&root.join("GENESIS.json"), &anchor_bytes)?;
    let head = AuthorityHead::from_genesis(anchor)?;
    let path = root.join("HEAD.json");
    if path.exists() {
        let current: AuthorityHead = serde_json::from_slice(&read_private_file(&path)?)?;
        current.validate()?;
        if current.workspace_identity != anchor.workspace_identity {
            return Err(LifecycleError::Mixed(
                "existing authority head belongs to another workspace".into(),
            ));
        }
        if current.sequence == 0 && current != head {
            return Err(LifecycleError::Mixed(
                "existing genesis head differs from the supplied anchor".into(),
            ));
        }
        Ok(current)
    } else {
        let live = filesystem_world::scan_directory(layout.live_root())?;
        if live.root != anchor.initial_world_root {
            return Err(LifecycleError::Mixed(
                "live S0 differs from the operator-selected genesis world".into(),
            ));
        }
        cleanup_head_temporary_files(&root)?;
        persist_head(&root, &head, None)?;
        Ok(head)
    }
}

/// Check the caller's exact pinned head while a prepared generation owns the
/// destination lock. This prevents a stale writer from exchanging the live
/// tree before discovering that another publication advanced the head.
pub fn ensure_expected_head(
    prepared: &PreparedGeneration,
    trust: &LifecycleTrust,
) -> Result<(), LifecycleError> {
    let layout = prepared.layout();
    if prepared.identity().workspace_identity() != layout.workspace_identity() {
        return Err(LifecycleError::Mixed(
            "prepared generation belongs to another lifecycle workspace".into(),
        ));
    }
    let result = verify_lifecycle_directory(layout, trust);
    if result.state != VerificationState::Valid {
        let error = error_for_verification(&result);
        close_prepared_generation_as_conflict(prepared, &error.to_string())?;
        return Err(error);
    }
    if result.reconstructed_head_root.as_deref()
        != Some(trust.previously_trusted_head_root.as_str())
    {
        let error = LifecycleError::Rollback(
            "prepared generation's pinned head is no longer current".into(),
        );
        close_prepared_generation_as_conflict(prepared, &error.to_string())?;
        return Err(error);
    }
    Ok(())
}

fn close_prepared_generation_as_conflict(
    prepared: &PreparedGeneration,
    reason: &str,
) -> Result<(), LifecycleError> {
    let mut journal = PublicationJournal::open(prepared.layout().journal_path())?;
    journal.record_generation_state(
        prepared.identity(),
        PublicationState::Conflict,
        None,
        None,
        Some(reason.to_owned()),
    )?;
    Ok(())
}

/// Complete the lifecycle transition for a successfully committed generation.
/// `CommittedGeneration` is opaque and non-serializable; it carries the lock
/// and identity minted by the checked candidate/commit path.
pub fn bind_committed_generation(
    committed: CommittedGeneration,
    execution: &CheckedExecutionForPublication,
    bundle: &ArtifactBundle,
    externally_pinned_genesis_root: &str,
    previously_trusted_head_root: &str,
) -> Result<AuthorityHead, LifecycleError> {
    let _profile = realm_v6::profile::Span::new("lifecycle_transition_binding");
    if !execution.validate_for_evidence() {
        return Err(LifecycleError::Invalid(
            "checked execution evidence is inconsistent".into(),
        ));
    }
    let layout = committed.layout();
    let identity = committed.identity();
    let derived_identity = GenerationIdentity::from_publication_capability(execution, layout)?;
    if &derived_identity != identity || committed.receipt().identity != *identity {
        return Err(LifecycleError::Mixed(
            "committed generation differs from its opaque checked execution".into(),
        ));
    }
    bundle.validate_at(ValidationLevel::AttestationShape)?;
    let publication = bundle
        .envelope
        .publication
        .generation
        .as_ref()
        .ok_or_else(|| {
            LifecycleError::Incomplete("published artifact lacks generation evidence".into())
        })?;
    if publication.generation_identity != *identity {
        return Err(LifecycleError::Mixed(
            "artifact generation identity differs from the committed generation".into(),
        ));
    }

    let live = filesystem_world::scan_directory(layout.live_root())?;
    let previous_path = layout.generation_path(identity)?;
    let previous = filesystem_world::scan_directory(&previous_path)?;
    if live.root != identity.accepted_final_root()
        || previous.root != identity.accepted_start_root()
        || committed.receipt().live_root != live.root
        || committed.receipt().previous_root != previous.root
    {
        return Err(LifecycleError::Mixed(
            "live S1 or retained previous S0 differs from the committed receipt".into(),
        ));
    }

    let receipt_path = layout
        .receipt_directory()
        .join(format!("{}.json", identity.publication_id()));
    let receipt_file = read_private_file(&receipt_path)?;
    let receipt_bytes = local_blob(bundle, &publication.receipt_blob)?;
    if receipt_file != receipt_bytes || receipt_file != serde_json::to_vec(committed.receipt())? {
        return Err(LifecycleError::Mixed(
            "artifact, committed, and durable generation receipts differ".into(),
        ));
    }
    let record_bytes = local_blob(bundle, &publication.journal_record_blob)?;
    let record: PublicationRecord = serde_json::from_slice(&record_bytes)?;
    let journal = PublicationJournal::open(layout.journal_path())?;
    if !journal
        .generation_records_for_workspace(layout.workspace_identity())
        .iter()
        .any(|effective| effective == &record)
    {
        return Err(LifecycleError::Incomplete(
            "artifact terminal journal row is not the effective durable row".into(),
        ));
    }

    let store = lifecycle_root(layout);
    let anchor: GenesisAnchor =
        serde_json::from_slice(&read_private_file(&store.join("GENESIS.json"))?)?;
    let genesis_root = anchor.root()?;
    if genesis_root != externally_pinned_genesis_root
        || anchor.workspace_identity != layout.workspace_identity()
    {
        return Err(LifecycleError::Unknown(
            "stored genesis differs from the external trust anchor".into(),
        ));
    }
    let head: AuthorityHead =
        serde_json::from_slice(&read_private_file(&store.join("HEAD.json"))?)?;
    head.validate()?;
    if head.authority_root != previously_trusted_head_root
        || head.workspace_identity != layout.workspace_identity()
        || head.world_root != identity.accepted_start_root()
    {
        return Err(LifecycleError::Rollback(
            "authority head is stale, foreign, or does not name accepted S0".into(),
        ));
    }
    if record.state != PublicationState::Published
        || record.sequence != publication.commit_sequence
        || record.generation_identity.as_ref() != Some(identity)
    {
        return Err(LifecycleError::Mixed(
            "artifact terminal journal row differs from its committed generation".into(),
        ));
    }

    let old_trust = LifecycleTrust {
        genesis_root: genesis_root.clone(),
        previously_trusted_head_root: head.authority_root.clone(),
    };
    let (old_anchor, mut candidate_snapshot) =
        load_snapshot(layout, Some(&head.world_root), false)?;
    let old_result = verify_chain(&old_trust, &old_anchor, &candidate_snapshot);
    if old_result.state != VerificationState::Valid {
        return Err(LifecycleError::Incomplete(format!(
            "existing authority history did not verify before advance: {}",
            old_result.diagnostic
        )));
    }

    let artifact_bytes = bundle.pack()?;
    let artifact_digest = crate::hash("realm.v6-lifecycle-artifact", &artifact_bytes);
    let semantic_root = bundle.semantic_identity()?;
    if semantic_root != publication.semantic_run_root {
        return Err(LifecycleError::Mixed(
            "artifact semantic root differs from its publication envelope".into(),
        ));
    }
    let transition = LifecycleTransition {
        schema_version: 1,
        domain: TRANSITION_DOMAIN.into(),
        sequence: head.sequence + 1,
        parent_authority_root: head.authority_root.clone(),
        parent_generation_root: head.generation_root.clone(),
        parent_world_root: head.world_root.clone(),
        generation_identity: identity.clone(),
        semantic_run_root: semantic_root,
        artifact_digest: artifact_digest.clone(),
        receipt_digest: publication.receipt_identity.clone(),
        journal_record_digest: crate::hash("realm.v6-publication-journal-record", &record_bytes),
        journal_sequence: record.sequence,
        world_root: live.root,
        delta_root: identity.accepted_delta_root().into(),
    };
    let transition_root = transition.root()?;
    let transitions_dir = store.join("transitions");
    for entry in fs::read_dir(&transitions_dir)? {
        let entry = entry?;
        let bytes = read_private_file(&entry.path())?;
        let other: LifecycleTransition = serde_json::from_slice(&bytes)?;
        if other.parent_authority_root == head.authority_root && other.root()? != transition_root {
            return Err(LifecycleError::Fork(
                "another child already claims the expected authority head".into(),
            ));
        }
    }
    let next_head = AuthorityHead::from_transition(&anchor, &transition)?;
    candidate_snapshot.transitions.push(transition.clone());
    candidate_snapshot
        .artifacts
        .insert(artifact_digest.value.clone(), artifact_bytes.clone());
    candidate_snapshot.receipts.insert(
        transition.receipt_digest.value.clone(),
        receipt_bytes.clone(),
    );
    candidate_snapshot
        .retained_world_roots
        .insert(identity.generation_id().into(), previous.root);
    candidate_snapshot.live_world_root = transition.world_root.clone();
    candidate_snapshot.head = next_head.clone();
    let candidate_result = verify_chain(&old_trust, &anchor, &candidate_snapshot);
    if candidate_result.state != VerificationState::Valid {
        return Err(LifecycleError::Invalid(format!(
            "new durable transition failed independent reconstruction: {}",
            candidate_result.diagnostic
        )));
    }
    write_once(
        &store
            .join("artifacts")
            .join(format!("{}.realm", artifact_digest.value)),
        &artifact_bytes,
    )?;
    write_once(
        &transitions_dir.join(format!("{transition_root}.json")),
        &serde_json::to_vec(&transition)?,
    )?;
    persist_head(&store, &next_head, Some(previously_trusted_head_root))?;
    let final_result = verify_lifecycle_directory(layout, &old_trust);
    if final_result.state != VerificationState::Valid {
        return Err(LifecycleError::Incomplete(format!(
            "authority head advanced but final disk reconstruction refused: {}",
            final_result.diagnostic
        )));
    }
    drop(committed);
    Ok(next_head)
}

fn publish_prepared_generation_inner(
    prepared: PreparedGeneration,
    execution: CheckedExecutionForPublication,
    trust: &LifecycleTrust,
) -> Result<VerifiedPublicationState, LifecycleError> {
    let _profile = realm_v6::profile::Span::new("durable_publication");
    let layout = prepared.layout().clone();
    let expected_identity = GenerationIdentity::from_publication_capability(&execution, &layout)?;
    if &expected_identity != prepared.identity() {
        let error = LifecycleError::Mixed(
            "prepared generation does not belong to the supplied checked execution".into(),
        );
        close_prepared_generation_as_conflict(&prepared, &error.to_string())?;
        return Err(error);
    }
    ensure_expected_head(&prepared, trust)?;
    let identity = prepared.identity().clone();
    let run_id = execution.result().run_id.clone();
    let execution_id = execution.result().execution_id.clone();
    let parent_authority_head_root = trust.previously_trusted_head_root.clone();
    let mut bundle = crate::v6::from_publication_capability(&execution)?;
    let committed = commit_generation_held(prepared)?;
    let receipt = committed.receipt().clone();
    let record = PublicationJournal::open(layout.journal_path())?
        .generation_records_for_workspace(layout.workspace_identity())
        .into_iter()
        .find(|record| {
            record.publication_id == receipt.identity.publication_id()
                && record.state == PublicationState::Published
                && record.generation_identity.as_ref() == Some(&receipt.identity)
        })
        .ok_or_else(|| {
            LifecycleError::Incomplete(
                "committed generation has no matching effective PUBLISHED journal row".into(),
            )
        })?;
    crate::v6::bind_generation_publication(&mut bundle, &receipt, &record)?;
    bundle.validate_at(ValidationLevel::AttestationShape)?;

    let head = bind_committed_generation(
        committed,
        &execution,
        &bundle,
        &trust.genesis_root,
        &parent_authority_head_root,
    )?;
    let verification = verify_lifecycle_directory(&layout, trust);
    if verification.state != VerificationState::Valid
        || verification.reconstructed_head_root.as_deref() != Some(head.authority_root.as_str())
    {
        return Err(LifecycleError::Incomplete(format!(
            "post-publication full-chain reconstruction did not confirm the new authority head: {} ({:?})",
            verification.diagnostic, verification.state
        )));
    }

    Ok(VerifiedPublicationState {
        bundle,
        head,
        verification,
        identity,
        parent_authority_head_root,
        run_id,
        execution_id,
    })
}

/// Commit one prepared generation and return a public ACCEPT report only after
/// the publication receipt, journal row, lifecycle transition, AuthorityHead
/// CAS, and a full disk reconstruction all agree. This API is absent from
/// `test-support` builds so synthetic fixtures cannot emit ACCEPT.
#[cfg(not(feature = "test-support"))]
pub fn publish_prepared_generation(
    prepared: PreparedGeneration,
    execution: CheckedExecutionForPublication,
    trust: &LifecycleTrust,
) -> Result<PublishedAccept, LifecycleError> {
    let verified = publish_prepared_generation_inner(prepared, execution, trust)?;
    let artifact_bytes = verified.bundle.pack()?;
    let report = PublishedAcceptReport {
        schema_version: 1,
        domain: "realm.v6.public-accept-report.v1".into(),
        decision: PublicDecision::Accept,
        run_id: verified.run_id,
        execution_id: verified.execution_id,
        semantic_run_root: verified.bundle.semantic_identity()?,
        generation_id: verified.identity.generation_id().into(),
        publication_id: verified.identity.publication_id().into(),
        parent_authority_head_root: verified.parent_authority_head_root,
        authority_head_root: verified.head.authority_root,
        authority_head_sequence: verified.head.sequence,
        verified_transitions: verified.verification.verified_transitions,
        artifact_digest: crate::hash("realm.v6-lifecycle-artifact", &artifact_bytes),
    };
    Ok(PublishedAccept {
        report,
        bundle: verified.bundle,
    })
}

/// Exercise the same durable publisher and full-chain verifier with synthetic
/// test authority. The returned value is typed verification evidence only; it
/// has no ACCEPT field and cannot be serialized into one.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn test_publish_prepared_generation(
    prepared: PreparedGeneration,
    execution: CheckedExecutionForPublication,
    trust: &LifecycleTrust,
) -> Result<TestPublicationVerification, LifecycleError> {
    let verified = publish_prepared_generation_inner(prepared, execution, trust)?;
    Ok(TestPublicationVerification {
        bundle: verified.bundle,
        run_id: verified.run_id,
        execution_id: verified.execution_id,
        generation_id: verified.identity.generation_id().into(),
        publication_id: verified.identity.publication_id().into(),
        parent_authority_head_root: verified.parent_authority_head_root,
        authority_head_root: verified.head.authority_root,
        authority_head_sequence: verified.head.sequence,
        verification_state: verified.verification.state,
        verified_transitions: verified.verification.verified_transitions,
    })
}

/// Load all retained lifecycle objects and independently reconstruct the chain
/// against external genesis and previously trusted head pins.
pub fn verify_lifecycle_directory(
    layout: &GenerationLayout,
    trust: &LifecycleTrust,
) -> VerificationResult {
    let _profile = realm_v6::profile::Span::new("full_genesis_verification");
    match load_and_verify(layout, trust) {
        Ok(result) => result,
        Err(error) => VerificationResult {
            state: match &error {
                LifecycleError::Unknown(_) => VerificationState::Unknown,
                LifecycleError::Incomplete(_) => VerificationState::Incomplete,
                LifecycleError::Rollback(_) => VerificationState::Rollback,
                LifecycleError::Fork(_) => VerificationState::Fork,
                LifecycleError::Mixed(_) => VerificationState::MixedGeneration,
                LifecycleError::Invalid(_)
                | LifecycleError::Artifact(_)
                | LifecycleError::Json(_)
                | LifecycleError::Io(_)
                | LifecycleError::Generation(_)
                | LifecycleError::Journal(_)
                | LifecycleError::Scan(_) => VerificationState::Invalid,
            },
            verified_transitions: 0,
            reconstructed_head_root: None,
            diagnostic: error.to_string(),
        },
    }
}

/// Export evidence for an independent client. This does not export or recreate
/// a live publication capability. The caller must supply an external exact-head
/// pin; a claimed head copied from this export cannot authenticate its producer.
pub fn export_verified_lifecycle(
    layout: &GenerationLayout,
    trust: &LifecycleTrust,
) -> Result<(GenesisAnchor, LifecycleSnapshot), LifecycleError> {
    let (genesis, snapshot) = load_snapshot(layout, None, false)?;
    let result = verify_chain(trust, &genesis, &snapshot);
    if result.state != VerificationState::Valid {
        return Err(error_for_verification(&result));
    }
    if snapshot.head.authority_root != trust.previously_trusted_head_root {
        return Err(LifecycleError::Unknown(
            "export requires an externally pinned exact head".into(),
        ));
    }
    Ok((genesis, snapshot))
}

/// Complete an already-written transition whose head update was interrupted.
/// This only moves the durable verifier head from a trusted parent to its one
/// fully bound child; it does not recreate execution or publication authority.
pub fn recover_lifecycle_head(
    layout: &GenerationLayout,
    trust: &LifecycleTrust,
) -> Result<AuthorityHead, LifecycleError> {
    let _lock = DestinationLock::acquire(layout.live_root())?;
    let (genesis, snapshot) = load_snapshot(layout, None, true)?;
    let result = verify_chain(trust, &genesis, &snapshot);
    if result.state == VerificationState::Valid {
        cleanup_head_temporary_files(&lifecycle_root(layout))?;
        return Ok(snapshot.head);
    }
    if result.state != VerificationState::Rollback {
        return Err(error_for_verification(&result));
    }
    let current = &snapshot.head;
    if current.authority_root != trust.previously_trusted_head_root {
        return Err(LifecycleError::Rollback(
            "recovery head is not the externally trusted current parent".into(),
        ));
    }
    let children = snapshot
        .transitions
        .iter()
        .filter(|transition| transition.parent_authority_root == current.authority_root)
        .collect::<Vec<_>>();
    if children.is_empty() {
        return Err(LifecycleError::Incomplete(format!(
            "no durable child transition can explain the current state: {}",
            result.diagnostic
        )));
    }
    if children.len() != 1 {
        return Err(LifecycleError::Fork(
            "recovery found competing durable children for the trusted head".into(),
        ));
    }
    let child = children[0];
    if child.sequence != current.sequence + 1
        || child.parent_generation_root != current.generation_root
        || child.parent_world_root != current.world_root
    {
        return Err(LifecycleError::Mixed(
            "recovery child is not the next correctly bound generation".into(),
        ));
    }
    let journal = parse_journal(&snapshot.journal)?;
    verify_transition_package(child, &snapshot, &journal)?;
    if snapshot.live_world_root != child.world_root {
        return Err(LifecycleError::Mixed(
            "recovery live world does not match the durable child".into(),
        ));
    }
    if snapshot
        .retained_world_roots
        .get(child.generation_identity.generation_id())
        .map(String::as_str)
        != Some(child.parent_world_root.as_str())
    {
        return Err(LifecycleError::Mixed(
            "recovery retained previous S0 does not match the child".into(),
        ));
    }
    let next = AuthorityHead::from_transition(&genesis, child)?;
    cleanup_head_temporary_files(&lifecycle_root(layout))?;
    persist_head(
        &lifecycle_root(layout),
        &next,
        Some(&current.authority_root),
    )?;
    let recovered = verify_lifecycle_directory(layout, trust);
    if recovered.state != VerificationState::Valid {
        return Err(LifecycleError::Incomplete(format!(
            "recovered head did not reconstruct: {}",
            recovered.diagnostic
        )));
    }
    Ok(next)
}

fn load_and_verify(
    layout: &GenerationLayout,
    trust: &LifecycleTrust,
) -> Result<VerificationResult, LifecycleError> {
    let (genesis, snapshot) = load_snapshot(layout, None, false)?;
    Ok(verify_chain(trust, &genesis, &snapshot))
}

fn error_for_verification(result: &VerificationResult) -> LifecycleError {
    let diagnostic = result.diagnostic.clone();
    match result.state {
        VerificationState::Valid => LifecycleError::Invalid(diagnostic),
        VerificationState::Invalid => LifecycleError::Invalid(diagnostic),
        VerificationState::Incomplete => LifecycleError::Incomplete(diagnostic),
        VerificationState::Rollback => LifecycleError::Rollback(diagnostic),
        VerificationState::Fork => LifecycleError::Fork(diagnostic),
        VerificationState::MixedGeneration => LifecycleError::Mixed(diagnostic),
        VerificationState::Unknown => LifecycleError::Unknown(diagnostic),
    }
}

fn load_snapshot(
    layout: &GenerationLayout,
    live_root_override: Option<&str>,
    allow_head_temporary_files: bool,
) -> Result<(GenesisAnchor, LifecycleSnapshot), LifecycleError> {
    let store = lifecycle_root(layout);
    let entries = fs::read_dir(&store).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            LifecycleError::Incomplete("required durable lifecycle store is missing".into())
        } else {
            LifecycleError::Io(error)
        }
    })?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if matches!(
            name.as_str(),
            "GENESIS.json" | "HEAD.json" | "artifacts" | "transitions"
        ) {
            continue;
        }
        if is_head_temporary_name(&name) && allow_head_temporary_files {
            let _ = read_private_file(&entry.path())?;
            continue;
        }
        if is_head_temporary_name(&name) {
            return Err(LifecycleError::Incomplete(
                "unfinished authority-head temporary file remains".into(),
            ));
        }
        return Err(LifecycleError::Unknown(
            "unrecognized object in lifecycle store".into(),
        ));
    }
    let genesis: GenesisAnchor =
        serde_json::from_slice(&read_private_file(&store.join("GENESIS.json"))?)?;
    let head: AuthorityHead =
        serde_json::from_slice(&read_private_file(&store.join("HEAD.json"))?)?;
    let transitions_dir = store.join("transitions");
    let artifacts_dir = store.join("artifacts");
    let mut transitions = Vec::new();
    for entry in fs::read_dir(&transitions_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            return Err(LifecycleError::Incomplete(
                "unfinished lifecycle temporary file remains".into(),
            ));
        }
        if !name.ends_with(".json") {
            return Err(LifecycleError::Unknown(
                "unrecognized object in transition store".into(),
            ));
        }
        let bytes = read_private_file(&entry.path())?;
        let transition = serde_json::from_slice::<LifecycleTransition>(&bytes)?;
        let expected_name = format!("{}.json", transition.root()?);
        if name != expected_name {
            return Err(LifecycleError::Invalid(
                "transition filename differs from its content address".into(),
            ));
        }
        transitions.push(transition);
    }
    let mut artifacts = BTreeMap::new();
    let mut receipts = BTreeMap::new();
    let mut retained_world_roots = BTreeMap::new();
    for transition in &transitions {
        let artifact_path =
            artifacts_dir.join(format!("{}.realm", transition.artifact_digest.value));
        artifacts.insert(
            transition.artifact_digest.value.clone(),
            read_private_file(&artifact_path)?,
        );
        let receipt_path = layout.receipt_directory().join(format!(
            "{}.json",
            transition.generation_identity.publication_id()
        ));
        let receipt_bytes = read_private_file(&receipt_path)?;
        receipts.insert(
            blake3::hash(&receipt_bytes).to_hex().to_string(),
            receipt_bytes,
        );
        let previous_path = layout.generation_path(&transition.generation_identity)?;
        let previous = filesystem_world::scan_directory(&previous_path)?;
        retained_world_roots.insert(
            transition.generation_identity.generation_id().into(),
            previous.root,
        );
    }
    let live_world_root = match live_root_override {
        Some(root) => root.to_owned(),
        None => filesystem_world::scan_directory(layout.live_root())?.root,
    };
    let journal = match fs::read(layout.journal_path()) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    let snapshot = LifecycleSnapshot {
        head,
        transitions,
        artifacts,
        receipts,
        journal,
        live_world_root,
        retained_world_roots,
    };
    Ok((genesis, snapshot))
}

fn lifecycle_root(layout: &GenerationLayout) -> PathBuf {
    layout.control_root().join("lifecycle")
}

fn is_head_temporary_name(name: &str) -> bool {
    name.starts_with(".HEAD.") && name.ends_with(".tmp")
}

/// Remove only publisher-created HEAD temporaries after the canonical head
/// and its complete chain have been verified under the destination lock.
fn cleanup_head_temporary_files(store: &Path) -> Result<(), LifecycleError> {
    let mut removed = false;
    for entry in fs::read_dir(store)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_head_temporary_name(&name) {
            continue;
        }
        let _ = read_private_file(&entry.path())?;
        fs::remove_file(entry.path())?;
        removed = true;
    }
    if removed {
        sync_directory(store)?;
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), LifecycleError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != 0o700 {
                return Err(LifecycleError::Invalid(
                    "lifecycle directory has unsafe owner or mode".into(),
                ));
            }
        }
        Ok(_) => {
            return Err(LifecycleError::Invalid(
                "lifecycle path is not a directory".into(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn read_private_file(path: &Path) -> Result<Vec<u8>, LifecycleError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                LifecycleError::Incomplete(format!(
                    "required durable object is missing: {}",
                    path.display()
                ))
            } else {
                LifecycleError::Io(error)
            }
        })?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(LifecycleError::Invalid(
            "lifecycle file has unsafe type, owner, or mode".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn write_once(path: &Path, bytes: &[u8]) -> Result<(), LifecycleError> {
    if path.exists() {
        if read_private_file(path)? == bytes {
            return Ok(());
        }
        return Err(LifecycleError::Invalid(
            "content-addressed lifecycle object already exists with different bytes".into(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| LifecycleError::Invalid("lifecycle object has no parent".into()))?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| LifecycleError::Invalid("system clock predates Unix epoch".into()))?
        .as_nanos();
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        std::process::id(),
        nonce,
        bytes.len()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all_traced()?;
    drop(file);
    match fs::hard_link(&temporary, path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read_private_file(path)? != bytes {
                return Err(LifecycleError::Invalid(
                    "concurrent lifecycle object conflicts with expected content".into(),
                ));
            }
        }
        Err(error) => return Err(error.into()),
    }
    fs::remove_file(&temporary)?;
    sync_directory(parent)?;
    Ok(())
}

fn persist_head(
    store: &Path,
    head: &AuthorityHead,
    expected_parent: Option<&str>,
) -> Result<(), LifecycleError> {
    let _profile = realm_v6::profile::Span::new("authority_head_cas");
    let path = store.join("HEAD.json");
    if path.exists() {
        let current: AuthorityHead = serde_json::from_slice(&read_private_file(&path)?)?;
        current.validate()?;
        if current == *head {
            return Ok(());
        }
        if expected_parent != Some(current.authority_root.as_str())
            || head.parent_authority_root.as_deref() != Some(current.authority_root.as_str())
            || head.sequence != current.sequence + 1
        {
            return Err(LifecycleError::Rollback(
                "authority-head compare-and-swap expected parent failed".into(),
            ));
        }
    } else if expected_parent.is_some() {
        return Err(LifecycleError::Incomplete(
            "authority head disappeared before compare-and-swap".into(),
        ));
    }
    let bytes = serde_json::to_vec(head)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| LifecycleError::Invalid("system clock predates Unix epoch".into()))?
        .as_nanos();
    let temporary = store.join(format!(".HEAD.{}.{}.tmp", std::process::id(), nonce));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all_traced()?;
    drop(file);
    fs::rename(&temporary, &path)?;
    sync_directory(store)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), LifecycleError> {
    File::open(path)?.sync_all_traced()?;
    Ok(())
}

/// Reconstruct the chain from the externally pinned genesis and head floor.
/// No field in a `.realm` file or journal record is treated as authority.
pub fn verify_chain(
    trust: &LifecycleTrust,
    genesis: &GenesisAnchor,
    snapshot: &LifecycleSnapshot,
) -> VerificationResult {
    match verify_chain_inner(trust, genesis, snapshot) {
        Ok(root) => VerificationResult {
            state: VerificationState::Valid,
            verified_transitions: snapshot.transitions.len() as u64,
            reconstructed_head_root: Some(root),
            diagnostic: "complete genesis-to-head chain and live roots verified".into(),
        },
        Err(error) => {
            let (state, detail) = match &error {
                LifecycleError::Unknown(detail) => (VerificationState::Unknown, detail),
                LifecycleError::Invalid(detail) => (VerificationState::Invalid, detail),
                LifecycleError::Incomplete(detail) => (VerificationState::Incomplete, detail),
                LifecycleError::Rollback(detail) => (VerificationState::Rollback, detail),
                LifecycleError::Fork(detail) => (VerificationState::Fork, detail),
                LifecycleError::Mixed(detail) => (VerificationState::MixedGeneration, detail),
                LifecycleError::Artifact(_)
                | LifecycleError::Json(_)
                | LifecycleError::Io(_)
                | LifecycleError::Generation(_)
                | LifecycleError::Journal(_)
                | LifecycleError::Scan(_) => (
                    VerificationState::Invalid,
                    &"damaged or corrupt durable object".into(),
                ),
            };
            VerificationResult {
                state,
                verified_transitions: 0,
                reconstructed_head_root: None,
                diagnostic: detail.clone(),
            }
        }
    }
}

fn verify_chain_inner(
    trust: &LifecycleTrust,
    genesis: &GenesisAnchor,
    snapshot: &LifecycleSnapshot,
) -> Result<String, LifecycleError> {
    let genesis_root = genesis.root()?;
    if genesis_root != trust.genesis_root {
        return Err(LifecycleError::Unknown(
            "supplied genesis does not match the externally pinned root".into(),
        ));
    }
    let genesis_head = AuthorityHead::from_genesis(genesis)?;
    snapshot.head.validate()?;
    if snapshot.head.sequence == 0 && snapshot.head != genesis_head {
        return Err(LifecycleError::Mixed(
            "durable head differs from the externally trusted genesis".into(),
        ));
    }
    if snapshot.head.workspace_identity != genesis.workspace_identity {
        return Err(LifecycleError::Mixed(
            "authority head belongs to another workspace".into(),
        ));
    }

    let journal = parse_journal(&snapshot.journal)?;
    let mut transitions = snapshot.transitions.iter().collect::<Vec<_>>();
    transitions.sort_by_key(|transition| transition.sequence);
    if transitions
        .windows(2)
        .any(|window| window[0].sequence == window[1].sequence)
    {
        return Err(LifecycleError::Fork(
            "two transitions claim the same generation sequence".into(),
        ));
    }

    let mut child_counts = BTreeMap::<String, usize>::new();
    for transition in &transitions {
        *child_counts
            .entry(transition.parent_authority_root.clone())
            .or_default() += 1;
    }
    if child_counts.values().any(|count| *count > 1) {
        return Err(LifecycleError::Fork(
            "multiple children claim one authority-head parent".into(),
        ));
    }

    let mut seen_roots = BTreeSet::new();
    let mut seen_generation_ids = BTreeSet::new();
    let mut seen_publication_ids = BTreeSet::new();
    let mut execution_semantic_roots = BTreeMap::<String, String>::new();
    let mut used_journal_sequences = BTreeSet::new();
    let mut head = genesis_head;
    let mut head_roots = BTreeMap::from([(0, head.authority_root.clone())]);
    let mut last_journal_sequence = 0;

    for (index, transition) in transitions.iter().enumerate() {
        if transition.sequence != index as u64 + 1 {
            return Err(LifecycleError::Incomplete(
                "generation history has a missing sequence".into(),
            ));
        }
        let transition_root = transition.root()?;
        if !seen_roots.insert(transition_root.clone())
            || !seen_generation_ids
                .insert(transition.generation_identity.generation_id().to_owned())
            || !seen_publication_ids
                .insert(transition.generation_identity.publication_id().to_owned())
        {
            return Err(LifecycleError::Invalid(
                "duplicate transition, generation, or publication identity".into(),
            ));
        }
        if transition.parent_authority_root != head.authority_root
            || transition.parent_generation_root != head.generation_root
            || transition.parent_world_root != head.world_root
        {
            return Err(LifecycleError::Mixed(
                "transition parent does not match the reconstructed predecessor".into(),
            ));
        }
        let identity = &transition.generation_identity;
        identity.validate_integrity().map_err(|_| {
            LifecycleError::Invalid("generation identity digest or schema is invalid".into())
        })?;
        if identity.workspace_identity() != genesis.workspace_identity
            || identity.accepted_start_root() != transition.parent_world_root
            || identity.accepted_final_root() != transition.world_root
            || identity.accepted_delta_root() != transition.delta_root
        {
            return Err(LifecycleError::Mixed(
                "transition roots differ from the bound generation identity".into(),
            ));
        }
        if !used_journal_sequences.insert(transition.journal_sequence)
            || transition.journal_sequence <= last_journal_sequence
        {
            return Err(LifecycleError::Invalid(
                "generation journal records are duplicated or reordered".into(),
            ));
        }
        last_journal_sequence = transition.journal_sequence;

        verify_transition_package(transition, snapshot, &journal)?;
        if let Some(prior) = execution_semantic_roots.insert(
            identity.execution_id().to_owned(),
            transition.semantic_run_root.value.clone(),
        ) && prior != transition.semantic_run_root.value
        {
            return Err(LifecycleError::Mixed(
                "one execution ID is bound to different semantic roots".into(),
            ));
        }
        head = AuthorityHead::from_transition(genesis, transition)?;
        head_roots.insert(head.sequence, head.authority_root.clone());
    }

    if snapshot.head.authority_root != head.authority_root {
        if snapshot.head.sequence < head.sequence
            || head_roots
                .get(&snapshot.head.sequence)
                .is_some_and(|root| root == &snapshot.head.authority_root)
        {
            return Err(LifecycleError::Rollback(
                "durable authority head is behind retained valid history".into(),
            ));
        }
        return Err(LifecycleError::Incomplete(
            "authority head references a missing or invalid transition".into(),
        ));
    }

    let trusted_sequence = head_roots
        .iter()
        .find_map(|(sequence, root)| {
            (root == &trust.previously_trusted_head_root).then_some(*sequence)
        })
        .ok_or_else(|| {
            LifecycleError::Rollback(
                "previously trusted head is absent from the reconstructed chain".into(),
            )
        })?;
    if snapshot.head.sequence < trusted_sequence {
        return Err(LifecycleError::Rollback(
            "current authority head is older than the previously trusted head".into(),
        ));
    }

    if snapshot.live_world_root != head.world_root {
        return Err(LifecycleError::Mixed(
            "live world root differs from the reconstructed authority head".into(),
        ));
    }
    if head.sequence == 0 {
        if snapshot.live_world_root != genesis.initial_world_root
            || !snapshot.retained_world_roots.is_empty()
        {
            return Err(LifecycleError::Mixed(
                "genesis live root or retained-generation set is inconsistent".into(),
            ));
        }
    } else {
        if snapshot.retained_world_roots.len() != transitions.len() {
            return Err(LifecycleError::Incomplete(
                "retained generation set is missing or has unrecognized entries".into(),
            ));
        }
        for transition in &transitions {
            let previous = snapshot
                .retained_world_roots
                .get(transition.generation_identity.generation_id())
                .ok_or_else(|| {
                    LifecycleError::Incomplete("retained previous generation is missing".into())
                })?;
            if previous != &transition.parent_world_root {
                return Err(LifecycleError::Mixed(
                    "retained previous S0 differs from its reconstructed parent".into(),
                ));
            }
        }
    }
    Ok(head.authority_root)
}

fn verify_transition_package(
    transition: &LifecycleTransition,
    snapshot: &LifecycleSnapshot,
    journal: &[JournalLine],
) -> Result<(), LifecycleError> {
    let artifact_bytes = snapshot
        .artifacts
        .get(&transition.artifact_digest.value)
        .ok_or_else(|| LifecycleError::Incomplete("generation artifact is missing".into()))?;
    if transition.artifact_digest.algorithm != "blake3"
        || transition.artifact_digest.domain != "realm.v6-lifecycle-artifact"
        || crate::hash("realm.v6-lifecycle-artifact", artifact_bytes) != transition.artifact_digest
    {
        return Err(LifecycleError::Invalid(
            "generation artifact content digest mismatch".into(),
        ));
    }
    let bundle = ArtifactBundle::unpack(artifact_bytes)?;
    bundle.validate_at(ValidationLevel::AttestationShape)?;
    let semantic_root = bundle.semantic_identity()?;
    if semantic_root != transition.semantic_run_root {
        return Err(LifecycleError::Mixed(
            "artifact semantic root differs from its transition".into(),
        ));
    }
    let publication = bundle
        .envelope
        .publication
        .generation
        .as_ref()
        .ok_or_else(|| LifecycleError::Incomplete("artifact lacks generation evidence".into()))?;
    if publication.semantic_run_root != transition.semantic_run_root
        || publication.generation_identity != transition.generation_identity
        || publication.commit_mechanism != GENERATION_EXCHANGE_MECHANISM
        || publication.journal_state != PublicationState::Published
        || publication.live_root != transition.world_root
        || publication.previous_generation_root != transition.parent_world_root
    {
        return Err(LifecycleError::Mixed(
            "artifact envelope is bound to another lifecycle transition".into(),
        ));
    }
    let receipt_bytes = local_blob(&bundle, &publication.receipt_blob)?;
    if transition.receipt_digest.algorithm != "blake3"
        || transition.receipt_digest.domain != "realm.v6-generation-receipt"
        || blake3::hash(&receipt_bytes).to_hex().as_str() != transition.receipt_digest.value
        || publication.receipt_identity != transition.receipt_digest
    {
        return Err(LifecycleError::Invalid(
            "generation receipt digest mismatch".into(),
        ));
    }
    let receipt: GenerationReceipt = serde_json::from_slice(&receipt_bytes)?;
    if receipt.schema_version != 1
        || receipt.identity != transition.generation_identity
        || receipt.live_root != transition.world_root
        || receipt.previous_root != transition.parent_world_root
    {
        return Err(LifecycleError::Mixed(
            "generation receipt is bound to another transition".into(),
        ));
    }
    let durable_receipt = snapshot
        .receipts
        .get(&transition.receipt_digest.value)
        .ok_or_else(|| {
            LifecycleError::Incomplete("durable generation receipt is missing".into())
        })?;
    if durable_receipt != &receipt_bytes {
        return Err(LifecycleError::Mixed(
            "artifact receipt differs from the durable receipt file".into(),
        ));
    }
    let record_bytes = local_blob(&bundle, &publication.journal_record_blob)?;
    if transition.journal_record_digest.algorithm != "blake3"
        || transition.journal_record_digest.domain != "realm.v6-publication-journal-record"
        || crate::hash("realm.v6-publication-journal-record", &record_bytes)
            != transition.journal_record_digest
    {
        return Err(LifecycleError::Invalid(
            "publication journal record digest mismatch".into(),
        ));
    }
    let record: PublicationRecord = serde_json::from_slice(&record_bytes)?;
    if record.schema_version != 2
        || record.sequence != transition.journal_sequence
        || record.state != PublicationState::Published
        || record.publication_id != transition.generation_identity.publication_id()
        || record.execution_id != transition.generation_identity.execution_id()
        || record.run_id != transition.generation_identity.run_id()
        || record.decision_identity != transition.generation_identity.accepted_decision_identity()
        || record.destination_identity != transition.generation_identity.workspace_identity()
        || record.accepted_final_root != transition.world_root
        || record.accepted_delta_root != transition.delta_root
        || record.pre_publication_root != transition.parent_world_root
        || record.post_publication_root.as_deref() != Some(transition.world_root.as_str())
        || record.generation_identity.as_ref() != Some(&transition.generation_identity)
        || record.receipt_digest.as_deref() != Some(transition.receipt_digest.value.as_str())
        || record.error.is_some()
    {
        return Err(LifecycleError::Mixed(
            "PUBLISHED journal row is bound to another transition".into(),
        ));
    }
    let matching_rows = journal
        .iter()
        .filter(|line| line.sequence == record.sequence)
        .collect::<Vec<_>>();
    if matching_rows.len() != 1 || matching_rows[0].bytes != record_bytes {
        return Err(LifecycleError::Incomplete(
            "bound terminal journal row is missing, copied, or ambiguous".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct JournalLine {
    sequence: u64,
    bytes: Vec<u8>,
}

fn parse_journal(bytes: &[u8]) -> Result<Vec<JournalLine>, LifecycleError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.ends_with(b"\n") {
        return Err(LifecycleError::Incomplete(
            "publication journal ends in a partial record".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut lines = Vec::new();
    let text = std::str::from_utf8(bytes)
        .map_err(|_| LifecycleError::Invalid("publication journal is not UTF-8".into()))?;
    for (index, raw) in text.split_terminator('\n').enumerate() {
        let raw = raw.as_bytes();
        if raw.is_empty() {
            return Err(LifecycleError::Invalid(
                "publication journal contains a blank record".into(),
            ));
        }
        let record: PublicationRecord = serde_json::from_slice(raw).map_err(|_| {
            LifecycleError::Invalid("publication journal contains corrupt JSON".into())
        })?;
        if !matches!(record.schema_version, 1 | 2) {
            return Err(LifecycleError::Unknown(
                "unsupported publication journal schema".into(),
            ));
        }
        if record.sequence != index as u64 + 1 {
            return Err(LifecycleError::Invalid(
                "publication journal records are truncated or reordered".into(),
            ));
        }
        let mut normalized = record.clone();
        normalized.sequence = 0;
        let key = serde_json::to_vec(&normalized)?;
        if !seen.insert(key) {
            return Err(LifecycleError::Invalid(
                "publication journal contains a duplicated lifecycle record".into(),
            ));
        }
        lines.push(JournalLine {
            sequence: record.sequence,
            bytes: raw.to_vec(),
        });
    }
    Ok(lines)
}

fn local_blob(bundle: &ArtifactBundle, blob: &crate::BlobRef) -> Result<Vec<u8>, LifecycleError> {
    let bytes = bundle
        .blobs
        .get(&blob.digest.value)
        .ok_or_else(|| LifecycleError::Incomplete("required lifecycle blob is external".into()))?;
    if bytes.len() as u64 != blob.size || crate::hash("realm.blob", bytes) != blob.digest {
        return Err(LifecycleError::Invalid(
            "required lifecycle blob is damaged".into(),
        ));
    }
    Ok(bytes.clone())
}

fn hash_json<T: Serialize>(domain: &str, value: &T) -> Result<String, LifecycleError> {
    let bytes = serde_json::to_vec(value)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Keep the evidence type visible here so downstream callers can inspect the
/// bound schema without duplicating its definition.
pub type GenerationEvidence = GenerationPublicationEvidence;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn repeated(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn fake_identity() -> GenerationIdentity {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "execution_id": repeated('1'),
            "run_id": "head-cas-fixture",
            "capsule_id": repeated('2'),
            "challenge_binding": repeated('3'),
            "accepted_decision_identity": repeated('4'),
            "accepted_start_root": repeated('5'),
            "accepted_final_root": repeated('6'),
            "accepted_delta_root": repeated('7'),
            "workspace_identity": repeated('8'),
            "generation_id": repeated('9'),
            "publication_id": repeated('a')
        }))
        .unwrap()
    }

    fn fake_transition(parent: &AuthorityHead, sequence: u64) -> LifecycleTransition {
        LifecycleTransition {
            schema_version: 1,
            domain: TRANSITION_DOMAIN.into(),
            sequence,
            parent_authority_root: parent.authority_root.clone(),
            parent_generation_root: parent.generation_root.clone(),
            parent_world_root: parent.world_root.clone(),
            generation_identity: fake_identity(),
            semantic_run_root: Digest {
                algorithm: "blake3".into(),
                domain: "realm.run".into(),
                value: repeated('b'),
            },
            artifact_digest: Digest {
                algorithm: "blake3".into(),
                domain: "realm.v6-lifecycle-artifact".into(),
                value: repeated('c'),
            },
            receipt_digest: Digest {
                algorithm: "blake3".into(),
                domain: "realm.v6-generation-receipt".into(),
                value: repeated('d'),
            },
            journal_record_digest: Digest {
                algorithm: "blake3".into(),
                domain: "realm.v6-publication-journal-record".into(),
                value: repeated('e'),
            },
            journal_sequence: sequence,
            world_root: repeated('f'),
            delta_root: repeated('a'),
        }
    }

    fn missing_store_trust_sentinels() -> LifecycleTrust {
        // The verifier must diagnose the absent store before consuming pins.
        // These valid-format sentinels are not trust anchors.
        LifecycleTrust {
            genesis_root: repeated('0'),
            previously_trusted_head_root: repeated('1'),
        }
    }

    fn assert_missing_lifecycle_store(layout: &GenerationLayout) {
        let result = verify_lifecycle_directory(layout, &missing_store_trust_sentinels());
        assert_eq!(
            result.state,
            VerificationState::Incomplete,
            "{}",
            result.diagnostic
        );
        assert_eq!(
            result.diagnostic,
            "incomplete lifecycle material: required durable lifecycle store is missing"
        );
        println!("state={:?}; diagnostic={}", result.state, result.diagnostic);
    }

    #[test]
    fn missing_lifecycle_store_is_incomplete() {
        let temp_root = std::env::temp_dir().canonicalize().unwrap();
        let parent = temp_root.join(format!(
            "realm-lifecycle-missing-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let live = parent.join("workspace");
        fs::create_dir(&live).unwrap();
        fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(live.join("seed.txt"), b"legacy generation only\n").unwrap();
        let layout = GenerationLayout::inspect(&live).unwrap();
        layout.ensure_control_root().unwrap();
        assert!(!lifecycle_root(&layout).exists());
        assert_missing_lifecycle_store(&layout);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    #[ignore = "reads the preserved real publication; set REALM_PRESERVED_DEMO_LIVE_ROOT"]
    fn preserved_pre_lifecycle_demo_reports_incomplete_without_trust_pins() {
        let live = PathBuf::from(
            std::env::var_os("REALM_PRESERVED_DEMO_LIVE_ROOT")
                .expect("set the read-only preserved demo live-root path"),
        );
        let layout = GenerationLayout::inspect(live).unwrap();
        assert!(layout.control_root().is_dir());
        assert!(!lifecycle_root(&layout).exists());
        assert_missing_lifecycle_store(&layout);
    }

    #[test]
    fn head_file_cas_allows_exact_replay_and_rejects_stale_or_fast_forward() {
        let temp_root = std::env::temp_dir().canonicalize().unwrap();
        let parent = temp_root.join(format!(
            "realm-lifecycle-head-cas-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let genesis = GenesisAnchor::new(repeated('8'), repeated('5'), "cas-fixture");
        let old_head = AuthorityHead::from_genesis(&genesis).unwrap();
        persist_head(&parent, &old_head, None).unwrap();

        let transition = fake_transition(&old_head, 1);
        let child = AuthorityHead::from_transition(&genesis, &transition).unwrap();
        persist_head(&parent, &child, Some(&old_head.authority_root)).unwrap();
        persist_head(&parent, &child, Some(&old_head.authority_root)).unwrap();

        let mut competing_transition = fake_transition(&old_head, 1);
        competing_transition.semantic_run_root = crate::hash("realm.run", repeated('c').as_bytes());
        let stale_child = AuthorityHead::from_transition(&genesis, &competing_transition).unwrap();
        assert!(persist_head(&parent, &stale_child, Some(&old_head.authority_root)).is_err());

        let fast_forward =
            AuthorityHead::from_transition(&genesis, &fake_transition(&child, child.sequence + 2))
                .unwrap();
        assert!(persist_head(&parent, &fast_forward, Some(&child.authority_root)).is_err());
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn concurrent_same_parent_head_writers_have_one_cas_winner_without_live_mutation() {
        for round in 0..8 {
            let temp_root = std::env::temp_dir().canonicalize().unwrap();
            let parent = temp_root.join(format!(
                "realm-lifecycle-head-race-{}-{round}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&parent).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
            let live = parent.join("workspace");
            fs::create_dir(&live).unwrap();
            fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(live.join("state.txt"), b"unchanged parent\n").unwrap();
            let initial_world = filesystem_world::scan_directory(&live).unwrap();

            let store = parent.join("lifecycle");
            fs::create_dir(&store).unwrap();
            fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
            let genesis =
                GenesisAnchor::new(repeated('8'), initial_world.root.clone(), "race-fixture");
            let parent_head = AuthorityHead::from_genesis(&genesis).unwrap();
            persist_head(&store, &parent_head, None).unwrap();

            let child_a =
                AuthorityHead::from_transition(&genesis, &fake_transition(&parent_head, 1))
                    .unwrap();
            let mut transition_b = fake_transition(&parent_head, 1);
            transition_b.semantic_run_root.value = repeated('c');
            let child_b = AuthorityHead::from_transition(&genesis, &transition_b).unwrap();
            assert_ne!(child_a.authority_root, child_b.authority_root);

            let barrier = Arc::new(Barrier::new(3));
            let writers = [child_a.clone(), child_b.clone()].map(|child| {
                let barrier = Arc::clone(&barrier);
                let live = live.clone();
                let store = store.clone();
                let expected_parent = parent_head.authority_root.clone();
                thread::spawn(move || {
                    barrier.wait();
                    let _lock =
                        DestinationLock::acquire(&live).map_err(|error| error.to_string())?;
                    let current: AuthorityHead = serde_json::from_slice(
                        &read_private_file(&store.join("HEAD.json"))
                            .map_err(|error| error.to_string())?,
                    )
                    .map_err(|error| error.to_string())?;
                    if current.authority_root != expected_parent {
                        return Err("stale expected parent".to_owned());
                    }
                    persist_head(&store, &child, Some(&expected_parent))
                        .map_err(|error| error.to_string())?;
                    Ok::<_, String>(child)
                })
            });
            barrier.wait();
            let results = writers
                .into_iter()
                .map(|writer| writer.join().unwrap())
                .collect::<Vec<_>>();
            let winners = results.iter().filter(|result| result.is_ok()).count();
            assert_eq!(winners, 1, "round {round}: {results:?}");

            let winner = results.into_iter().find_map(Result::ok).unwrap();
            let persisted: AuthorityHead =
                serde_json::from_slice(&read_private_file(&store.join("HEAD.json")).unwrap())
                    .unwrap();
            assert_eq!(persisted, winner, "round {round}");
            assert_eq!(
                filesystem_world::scan_directory(&live).unwrap().root,
                initial_world.root,
                "head-only race must not change canonical live S0"
            );
            fs::remove_dir_all(parent).unwrap();
        }
    }

    #[test]
    fn genesis_lifecycle_initialization_and_recovery_are_idempotent() {
        let temp_root = std::env::temp_dir().canonicalize().unwrap();
        let parent = temp_root.join(format!(
            "realm-lifecycle-genesis-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let live = parent.join("workspace");
        fs::create_dir(&live).unwrap();
        fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(live.join("seed.txt"), b"trusted initial world\n").unwrap();
        let layout = GenerationLayout::inspect(&live).unwrap();
        let world = filesystem_world::scan_directory(&live).unwrap();
        let genesis =
            GenesisAnchor::new(layout.workspace_identity(), world.root, "unit-test-genesis");
        let root = genesis.root().unwrap();
        let head = initialize_lifecycle(&layout, &genesis, &root).unwrap();
        let repeated_init = initialize_lifecycle(&layout, &genesis, &root).unwrap();
        assert_eq!(head, repeated_init);
        let trust = LifecycleTrust {
            genesis_root: root.clone(),
            previously_trusted_head_root: root,
        };
        let verification = verify_lifecycle_directory(&layout, &trust);
        assert_eq!(
            verification.state,
            VerificationState::Valid,
            "{}",
            verification.diagnostic
        );
        assert_eq!(recover_lifecycle_head(&layout, &trust).unwrap(), head);

        let unsupported_path = lifecycle_root(&layout)
            .join("transitions")
            .join("unsupported.json");
        let mut unsupported = fake_transition(&head, 1);
        unsupported.schema_version = 2;
        let mut unsupported_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&unsupported_path)
            .unwrap();
        unsupported_file
            .write_all(&serde_json::to_vec(&unsupported).unwrap())
            .unwrap();
        unsupported_file.sync_all_traced().unwrap();
        drop(unsupported_file);
        assert!(recover_lifecycle_head(&layout, &trust).is_err());
        let persisted_head: AuthorityHead = serde_json::from_slice(
            &read_private_file(&lifecycle_root(&layout).join("HEAD.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(persisted_head, head);
        fs::remove_file(&unsupported_path).unwrap();
        sync_directory(&lifecycle_root(&layout).join("transitions")).unwrap();

        let partial_head = lifecycle_root(&layout).join(".HEAD.partial.tmp");
        let mut partial = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&partial_head)
            .unwrap();
        partial.write_all(b"{\"schema_version\":").unwrap();
        partial.sync_all_traced().unwrap();
        drop(partial);
        assert_eq!(
            verify_lifecycle_directory(&layout, &trust).state,
            VerificationState::Incomplete
        );
        assert_eq!(recover_lifecycle_head(&layout, &trust).unwrap(), head);
        assert!(!partial_head.exists());
        assert_eq!(recover_lifecycle_head(&layout, &trust).unwrap(), head);
        assert_eq!(
            verify_lifecycle_directory(&layout, &trust).state,
            VerificationState::Valid
        );

        fs::write(live.join("seed.txt"), b"later published world\n").unwrap();
        assert_eq!(
            initialize_lifecycle(&layout, &genesis, &trust.genesis_root).unwrap(),
            head
        );
        assert_eq!(
            verify_lifecycle_directory(&layout, &trust).state,
            VerificationState::MixedGeneration
        );
        fs::write(live.join("seed.txt"), b"trusted initial world\n").unwrap();
        assert_eq!(
            verify_lifecycle_directory(&layout, &trust).state,
            VerificationState::Valid
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    #[ignore = "reads the frozen first ACCEPT; set REALM_ACCEPTED_* pins and live root"]
    fn preserved_accept_head_pin_rejects_rollback_to_its_genesis_snapshot() {
        let live = PathBuf::from(
            std::env::var_os("REALM_ACCEPTED_LIVE_ROOT")
                .expect("set the preserved ACCEPT live-root path"),
        );
        let genesis_pin = std::env::var("REALM_ACCEPTED_GENESIS_ROOT")
            .expect("set the externally pinned genesis root");
        let trusted_head_pin = std::env::var("REALM_ACCEPTED_HEAD_ROOT")
            .expect("set the externally pinned accepted head root");
        let layout = GenerationLayout::inspect(live).unwrap();
        let (genesis, current) = load_snapshot(&layout, None, false).unwrap();
        assert_eq!(genesis.root().unwrap(), genesis_pin);
        assert_eq!(current.head.authority_root, trusted_head_pin);
        assert_eq!(current.head.sequence, 1);
        let current_result = verify_lifecycle_directory(
            &layout,
            &LifecycleTrust {
                genesis_root: genesis_pin.clone(),
                previously_trusted_head_root: trusted_head_pin.clone(),
            },
        );
        assert_eq!(current_result.state, VerificationState::Valid);
        assert_eq!(current_result.verified_transitions, 1);

        let child = current.transitions.first().unwrap();
        assert_eq!(child.sequence, 1);
        assert_eq!(child.parent_world_root, genesis.initial_world_root);
        assert_eq!(
            current
                .retained_world_roots
                .get(child.generation_identity.generation_id()),
            Some(&genesis.initial_world_root)
        );
        let genesis_head = AuthorityHead::from_genesis(&genesis).unwrap();
        let rolled_back = LifecycleSnapshot {
            head: genesis_head,
            transitions: Vec::new(),
            artifacts: BTreeMap::new(),
            receipts: BTreeMap::new(),
            journal: Vec::new(),
            live_world_root: genesis.initial_world_root.clone(),
            retained_world_roots: BTreeMap::new(),
        };
        let rollback_result = verify_chain(
            &LifecycleTrust {
                genesis_root: genesis_pin,
                previously_trusted_head_root: trusted_head_pin,
            },
            &genesis,
            &rolled_back,
        );
        assert_eq!(rollback_result.state, VerificationState::Rollback);
        assert_eq!(rollback_result.verified_transitions, 0);
        assert!(
            rollback_result
                .diagnostic
                .contains("previously trusted head")
        );
    }
}
