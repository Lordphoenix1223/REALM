//! Versioned, platform-neutral Realm domain types.
//!
//! This crate intentionally contains no Endpoint Security, SQLite, or filesystem
//! implementation details. It describes evidence and state; it does not infer
//! semantic causality from a read followed by a write.

use serde::{Deserialize, Serialize};
use std::{
    fmt,
    path::{Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
        )]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
            pub fn nil() -> Self {
                Self(Uuid::nil())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

uuid_id!(TransactionId);
uuid_id!(ObjectId);
uuid_id!(ObjectVersionId);
uuid_id!(ProcessId);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PathBytes(pub Vec<u8>);

impl PathBytes {
    pub fn from_path(path: &Path) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Self(path.as_os_str().as_bytes().to_vec())
        }
        #[cfg(not(unix))]
        {
            Self(path.to_string_lossy().as_bytes().to_vec())
        }
    }

    pub fn as_path(&self) -> PathBuf {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            PathBuf::from(std::ffi::OsString::from_vec(self.0.clone()))
        }
        #[cfg(not(unix))]
        {
            PathBuf::from(String::from_utf8_lossy(&self.0).into_owned())
        }
    }

    pub fn display_lossy(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }
}

impl From<&Path> for PathBytes {
    fn from(value: &Path) -> Self {
        Self::from_path(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ActorKind {
    Human,
    Codex,
    Claude,
    OtherAgent,
    System,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActorIdentity {
    pub kind: ActorKind,
    pub actor_id: String,
    pub semantic_session_id: Option<String>,
    pub declared_intent: Option<String>,
}

/// The canonical evidence vocabulary for new cross-phase records.
///
/// Older schemas retain their original evidence enums for backward
/// compatibility. New durable types use this vocabulary so an observation,
/// overlap, counterfactual experiment, and model inference cannot collapse
/// into one unqualified "dependency" relation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum EvidenceClass {
    PreservedState,
    OsAuthorization,
    OsObservation,
    ProcessLineage,
    AgentDeclaration,
    SemanticAdapter,
    DeclaredDependency,
    StateOverlap,
    CounterfactualDependency,
    ModelInference,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum EvidenceConfidence {
    Proven,
    Verified,
    CounterfactuallySupported,
    Observed,
    Declared,
    Inferred,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub class: EvidenceClass,
    pub subject: String,
    pub evidence_ref: Option<String>,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum UnknownReasonCode {
    CaptureGap,
    MissingPreimage,
    UnsupportedState,
    HistoricalInputMissing,
    ReplayNondeterminism,
    SemanticConflict,
    ExternalIrreversibility,
    VerificationFailure,
    SandboxViolation,
    StorageExpiration,
    AuthorityUnspecified,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KnownUnknown {
    pub code: UnknownReasonCode,
    pub detail: String,
    pub evidence_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ReplayPolicy {
    TraceReplay,
    IntentReplay,
    Either,
    NonReplayable,
    Unspecified,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum IntentOrigin {
    UserDeclared,
    BenchmarkGroundTruth,
    AgentDeclared,
    DerivedFromTooling,
    InferredByModel,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PostconditionCheck {
    PathExists { path: PathBytes },
    PathAbsent { path: PathBytes },
    ContentHashEquals { path: PathBytes, blake3: String },
    TextContains { path: PathBytes, text: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IntentPostcondition {
    pub id: String,
    pub description: String,
    pub origin: IntentOrigin,
    pub check: PostconditionCheck,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ExternalEffectPolicy {
    Deny,
    CompensableOnly,
    AllowDeclared,
    Unspecified,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IntentInvariant {
    pub id: String,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IntentContract {
    pub schema_version: u16,
    pub raw_intent: String,
    #[serde(default)]
    pub origin: IntentOrigin,
    pub expected_outputs: Vec<PathBytes>,
    #[serde(default)]
    pub postconditions: Vec<IntentPostcondition>,
    pub invariants: Vec<IntentInvariant>,
    pub replay_policy: ReplayPolicy,
}

impl IntentContract {
    pub const SCHEMA_VERSION: u16 = 2;

    pub fn from_raw(raw_intent: impl Into<String>) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            raw_intent: raw_intent.into(),
            origin: IntentOrigin::Unknown,
            expected_outputs: Vec::new(),
            postconditions: Vec::new(),
            invariants: Vec::new(),
            replay_policy: ReplayPolicy::Unspecified,
        }
    }
}

/// Authority is intentionally separate from reversibility. An action can be
/// mechanically reversible and still be outside the actor's allowed scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityContract {
    pub schema_version: u16,
    pub read_scope: Vec<PathBytes>,
    pub write_scope: Vec<PathBytes>,
    pub external_effect_policy: ExternalEffectPolicy,
    pub destructive_actions_allowed: Option<bool>,
}

impl AuthorityContract {
    pub const SCHEMA_VERSION: u16 = 1;

    pub fn unspecified() -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            read_scope: Vec::new(),
            write_scope: Vec::new(),
            external_effect_policy: ExternalEffectPolicy::Unspecified,
            destructive_actions_allowed: None,
        }
    }

    pub fn is_explicit(&self) -> bool {
        !self.read_scope.is_empty()
            || !self.write_scope.is_empty()
            || self.external_effect_policy != ExternalEffectPolicy::Unspecified
            || self.destructive_actions_allowed.is_some()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum InputFidelity {
    CapturedExact,
    CapturedReference,
    CapturedDigest,
    CapturedMetadata,
    Replayable,
    Regenerable,
    External,
    Uncaptured,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum NondeterminismKind {
    Environment,
    WallClock,
    Randomness,
    Network,
    ModelExecution,
    Toolchain,
    FilesystemOrdering,
    Locale,
    Timezone,
    Architecture,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NondeterministicInput {
    pub kind: NondeterminismKind,
    pub label: String,
    pub fidelity: InputFidelity,
    pub evidence_ref: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct NondeterminismCapsule {
    pub schema_version: u16,
    pub environment_fingerprint: Option<String>,
    pub inputs: Vec<NondeterministicInput>,
    pub unresolved: Vec<KnownUnknown>,
}

impl NondeterminismCapsule {
    pub const SCHEMA_VERSION: u16 = 1;

    pub fn unknown() -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            environment_fingerprint: None,
            inputs: Vec::new(),
            unresolved: vec![KnownUnknown {
                code: UnknownReasonCode::ReplayNondeterminism,
                detail: "Historical nondeterministic inputs were not classified.".into(),
                evidence_ref: None,
            }],
        }
    }
}

/// Opaque cross-phase reference to the world/frontier against which a
/// transaction began. The namespace prevents a controlled `WorldHeadId` from
/// being confused with a future host anchor or exported-world identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct WorldReference {
    pub namespace: String,
    pub id: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ObservationCompleteness {
    Complete,
    Partial,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationVersion {
    pub path: PathBytes,
    pub state_hash: Option<String>,
    pub evidence: EvidenceClass,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationSet {
    pub completeness: ObservationCompleteness,
    pub reads: Vec<ObservationVersion>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum RecordedOperationKind {
    OverwritePath,
    DeletePath,
    RenamePath,
    CreateDirectory,
}

/// Prospectively captured operation semantics for deterministic trace replay.
/// Payload bytes remain in the transaction layer/CAS; this record states what
/// operation was executed, not merely which before/after states were observed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecordedOperation {
    pub kind: RecordedOperationKind,
    pub path: PathBytes,
    pub destination: Option<PathBytes>,
    pub deterministic: bool,
    pub evidence: EvidenceClass,
}

impl WorldReference {
    pub fn new(namespace: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            id: id.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub schema_version: u16,
    pub pid: u32,
    pub start_time_ns: Option<u64>,
    pub parent_pid: Option<u32>,
    pub executable: Option<PathBytes>,
    /// Opaque platform bytes are retained so a future decoder can reinterpret them.
    pub platform_identity: Vec<u8>,
    pub signing_identity: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ObjectKind {
    RegularFile,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObjectIdentity {
    pub id: ObjectId,
    pub volume_identity: Option<Vec<u8>>,
    pub platform_file_id: Option<Vec<u8>>,
    pub generation: Option<Vec<u8>>,
    pub first_seen_generation: Uuid,
    pub kind: ObjectKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObjectVersion {
    pub id: ObjectVersionId,
    pub object_id: ObjectId,
    pub content_hash: Option<String>,
    pub metadata_hash: Option<String>,
    pub blob_ref: Option<String>,
    pub provenance_event: Option<u64>,
    pub fidelity: Fidelity,
    pub preservation: PreservationMethod,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Fidelity {
    ContentExact,
    MetadataExact,
    StructureExact,
    FullSupportedExact,
    HashOnly,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PreservationMethod {
    ExactCopy,
    PlatformClone,
    CompressedCopy,
    Missing,
    Unsupported,
    RaceDetected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EvidenceStrength {
    ExactPreservedBytes,
    OsObserved,
    ProcessIdentity,
    AgentDeclared,
    SemanticAdapter,
    Counterfactual,
    ModelInference,
}

/// Evidence provenance is deliberately richer than a single confidence score.
/// In particular, an inferred relationship can never be promoted to an OS
/// observation by arithmetic on this enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EvidenceKind {
    ExactPreservedState,
    OsAuthorized,
    OsObserved,
    ProcessLineage,
    AgentDeclared,
    DelegationObserved,
    Inferred,
    CounterfactuallySupported,
    Unknown,
}

/// A capability dimension is a statement about what was actually proven for
/// one class of evidence. It is not a mutable "fully captured" flag.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum CapabilityFidelity {
    Exact,
    SupportedSubset,
    ObservedOnly,
    #[default]
    Unknown,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExternalCapability {
    #[default]
    None,
    Compensable,
    Irreversible,
    Unknown,
}

/// The dimensions required before Realm can make the strongest capture claim.
/// Every field is derived from evidence collected for the transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReversibilityCapabilities {
    pub content: CapabilityFidelity,
    pub path: CapabilityFidelity,
    pub metadata: CapabilityFidelity,
    pub link_graph: CapabilityFidelity,
    pub actor: CapabilityFidelity,
    pub lineage: CapabilityFidelity,
    pub capture_complete: CapabilityFidelity,
    pub external: ExternalCapability,
}

impl Default for ReversibilityCapabilities {
    fn default() -> Self {
        Self {
            content: CapabilityFidelity::Unknown,
            path: CapabilityFidelity::Unknown,
            metadata: CapabilityFidelity::Unknown,
            link_graph: CapabilityFidelity::Unknown,
            actor: CapabilityFidelity::Unknown,
            lineage: CapabilityFidelity::Unknown,
            capture_complete: CapabilityFidelity::Unknown,
            external: ExternalCapability::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FullyCaptured {
    Proven,
    NotProven,
}

impl ReversibilityCapabilities {
    /// Formal predicate for the strongest claim. There is no independently
    /// writable boolean that can drift away from the evidence vector.
    pub fn fully_captured(&self) -> FullyCaptured {
        let exact = [
            self.content,
            self.path,
            self.metadata,
            self.link_graph,
            self.actor,
            self.lineage,
            self.capture_complete,
        ]
        .into_iter()
        .all(|dimension| dimension == CapabilityFidelity::Exact);
        if exact && matches!(self.external, ExternalCapability::None) {
            FullyCaptured::Proven
        } else {
            FullyCaptured::NotProven
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaptureAssessment {
    pub capabilities: ReversibilityCapabilities,
    pub evidence: Vec<EvidenceKind>,
    pub uncertainty_codes: Vec<String>,
}

impl CaptureAssessment {
    pub fn fully_captured(&self) -> FullyCaptured {
        self.capabilities.fully_captured()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum RealmEventKind {
    ProcessSpawn,
    ProcessExec,
    ProcessExit,
    ObjectRead,
    ObjectWritableOpen,
    ObjectCreate,
    ObjectWriteObserved,
    ObjectTruncate,
    ObjectDelete,
    ObjectRename,
    ObjectLink,
    ObjectSymlink,
    ObjectMetadataChange,
    ObjectMmap,
    AgentSemanticEvent,
    ExternalEffect,
    CaptureGap,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RealmEvent {
    pub schema_version: u16,
    pub sequence: u64,
    pub transaction_id: TransactionId,
    pub actor_id: String,
    pub process_id: Option<ProcessId>,
    pub object_id: Option<ObjectId>,
    pub object_version_id: Option<ObjectVersionId>,
    pub path: Option<PathBytes>,
    pub kind: RealmEventKind,
    pub evidence: EvidenceStrength,
    pub wall_time_ms: i64,
    pub monotonic_ns: u64,
    pub pre_version: Option<ObjectVersionId>,
    pub post_version: Option<ObjectVersionId>,
    pub metadata: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaptureGap {
    pub transaction_id: TransactionId,
    pub stream: String,
    pub expected_sequence: u64,
    pub observed_sequence: u64,
    pub wall_time_ms: i64,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum CaptureStatus {
    #[default]
    Complete,
    Degraded,
}

impl CaptureStatus {
    pub fn degrade(&mut self) {
        *self = Self::Degraded;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryCapability {
    Exact,
    Partial,
    HistoryOnly,
    Unsupported,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransactionState {
    Creating,
    Capturing,
    Open,
    CaptureDegraded,
    Committing,
    Committed,
    RecoveryPlanned,
    RecoveryMaterialized,
    VerificationRunning,
    Verified,
    VerifiedWithKnownUncertainty,
    Conflicted,
    PartiallyReversible,
    Unsupported,
    HistoryOnly,
    Aborted,
}

impl TransactionState {
    pub fn can_transition_to(self, next: Self) -> bool {
        use TransactionState::*;
        if self == next {
            return true;
        }
        matches!(
            (self, next),
            (Creating, Capturing | Aborted)
                | (Capturing, Open | CaptureDegraded | Aborted)
                | (Open, Committing | CaptureDegraded | Aborted)
                | (CaptureDegraded, Committing | Aborted)
                | (
                    Committing,
                    Committed | PartiallyReversible | HistoryOnly | Aborted
                )
                | (
                    Committed,
                    RecoveryPlanned | HistoryOnly | PartiallyReversible
                )
                | (RecoveryPlanned, RecoveryMaterialized | Conflicted)
                | (RecoveryMaterialized, VerificationRunning | Conflicted)
                | (
                    VerificationRunning,
                    Verified | VerifiedWithKnownUncertainty | Conflicted
                )
                | (Verified, VerifiedWithKnownUncertainty)
                | (PartiallyReversible, RecoveryPlanned | HistoryOnly)
                | (HistoryOnly, RecoveryPlanned)
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionMetadata {
    pub id: TransactionId,
    pub parent_id: Option<TransactionId>,
    pub actor: ActorIdentity,
    pub start_wall_time_ms: i64,
    pub start_monotonic_ns: u64,
    pub end_wall_time_ms: Option<i64>,
    pub capture_backend: String,
    pub platform: String,
    pub capture_status: CaptureStatus,
    pub recovery_capability: RecoveryCapability,
    pub unresolved_gaps: Vec<CaptureGap>,
    pub external_effects: Vec<ExternalEffect>,
    pub state: TransactionState,
}

impl TransactionMetadata {
    pub fn new(
        actor: ActorIdentity,
        backend: impl Into<String>,
        platform: impl Into<String>,
    ) -> Self {
        Self {
            id: TransactionId::new(),
            parent_id: None,
            actor,
            start_wall_time_ms: 0,
            start_monotonic_ns: 0,
            end_wall_time_ms: None,
            capture_backend: backend.into(),
            platform: platform.into(),
            capture_status: CaptureStatus::Complete,
            recovery_capability: RecoveryCapability::Unknown,
            unresolved_gaps: Vec::new(),
            external_effects: Vec::new(),
            state: TransactionState::Creating,
        }
    }

    pub fn transition(&mut self, next: TransactionState) -> Result<(), DomainError> {
        if !self.state.can_transition_to(next) {
            return Err(DomainError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        if next == TransactionState::CaptureDegraded {
            self.capture_status.degrade();
        }
        Ok(())
    }

    pub fn record_gap(&mut self, gap: CaptureGap) {
        self.capture_status.degrade();
        self.unresolved_gaps.push(gap);
        if matches!(
            self.state,
            TransactionState::Capturing | TransactionState::Open
        ) {
            self.state = TransactionState::CaptureDegraded;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExternalEffectClass {
    ReversibleLocal,
    Replayable,
    Compensable,
    Irreversible,
    UnknownExternal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalEffect {
    pub id: String,
    pub class: ExternalEffectClass,
    pub description: String,
    pub evidence: EvidenceStrength,
    pub metadata: serde_json::Value,
}

/// Immutable cross-phase identity and replay envelope for one committed unit
/// of work. Physical effects remain in phase-specific records (events for
/// observed-host mode and layers for controlled-world mode).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionCapsule {
    pub schema_version: u16,
    pub id: TransactionId,
    pub parent_id: Option<TransactionId>,
    pub parent_world: Option<WorldReference>,
    pub actor: ActorIdentity,
    pub intent: IntentContract,
    pub authority: AuthorityContract,
    #[serde(default)]
    pub observations: ObservationSet,
    #[serde(default)]
    pub operations: Vec<RecordedOperation>,
    pub nondeterminism: NondeterminismCapsule,
    pub evidence: Vec<EvidenceRecord>,
    pub capture_capabilities: ReversibilityCapabilities,
    pub external_effects: Vec<ExternalEffect>,
    pub known_unknowns: Vec<KnownUnknown>,
}

impl TransactionCapsule {
    pub const SCHEMA_VERSION: u16 = 2;

    pub fn new(
        id: TransactionId,
        parent_id: Option<TransactionId>,
        actor: ActorIdentity,
        intent: IntentContract,
    ) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            id,
            parent_id,
            parent_world: None,
            actor,
            intent,
            authority: AuthorityContract::unspecified(),
            observations: ObservationSet::default(),
            operations: Vec::new(),
            nondeterminism: NondeterminismCapsule::unknown(),
            evidence: Vec::new(),
            capture_capabilities: ReversibilityCapabilities::default(),
            external_effects: Vec::new(),
            known_unknowns: vec![KnownUnknown {
                code: UnknownReasonCode::AuthorityUnspecified,
                detail: "No structured authority contract was captured.".into(),
                evidence_ref: None,
            }],
        }
    }

    pub fn from_metadata(metadata: &TransactionMetadata) -> Self {
        let raw_intent = metadata.actor.declared_intent.clone().unwrap_or_default();
        let mut capsule = Self::new(
            metadata.id,
            metadata.parent_id,
            metadata.actor.clone(),
            IntentContract::from_raw(raw_intent),
        );
        capsule.external_effects = metadata.external_effects.clone();
        capsule.known_unknowns.push(KnownUnknown {
            code: UnknownReasonCode::HistoricalInputMissing,
            detail: "No starting world reference exists in legacy transaction metadata.".into(),
            evidence_ref: None,
        });
        for gap in &metadata.unresolved_gaps {
            capsule.known_unknowns.push(KnownUnknown {
                code: UnknownReasonCode::CaptureGap,
                detail: gap.reason.clone(),
                evidence_ref: Some(format!(
                    "{}:{}-{}",
                    gap.stream, gap.expected_sequence, gap.observed_sequence
                )),
            });
        }
        capsule
    }
}

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("invalid transaction state transition: {from:?} -> {to:?}")]
    InvalidTransition {
        from: TransactionState,
        to: TransactionState,
    },
}

pub fn now_wall_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

pub fn monotonic_ns() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_projection_preserves_unknownness_instead_of_inventing_authority() {
        let mut metadata = TransactionMetadata::new(
            ActorIdentity {
                kind: ActorKind::OtherAgent,
                actor_id: "agent".into(),
                semantic_session_id: None,
                declared_intent: Some("repair auth".into()),
            },
            "synthetic",
            "test",
        );
        metadata.record_gap(CaptureGap {
            transaction_id: metadata.id,
            stream: "global".into(),
            expected_sequence: 2,
            observed_sequence: 4,
            wall_time_ms: 0,
            reason: "lost events".into(),
        });
        let capsule = TransactionCapsule::from_metadata(&metadata);
        assert_eq!(capsule.intent.raw_intent, "repair auth");
        assert!(!capsule.authority.is_explicit());
        assert!(capsule.known_unknowns.iter().any(|unknown| {
            unknown.code == UnknownReasonCode::CaptureGap && unknown.detail == "lost events"
        }));
    }
}
