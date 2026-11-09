//! Write-ahead reversibility admission.
//!
//! This crate contains the fail-closed decision boundary between an observed
//! authorization request and releasing that authorization. It is deliberately
//! independent of Endpoint Security so it can be exhaustively tested without
//! pretending that synthetic events are live OS capture.

use realm_core::{
    CapabilityFidelity, CaptureStatus, ObjectId, ProcessId, ReversibilityCapabilities,
    TransactionId,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct EffectId(pub Uuid);

impl EffectId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for EffectId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MutationOperation {
    Create,
    Write,
    Fwrite,
    Truncate,
    Delete,
    Rename,
    RenameOverwrite,
    Link,
    Symlink,
    Metadata,
    MmapShared,
    MmapPrivate,
    Xattr,
    Flags,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PreimageConsistency {
    AtomicSnapshot,
    StableValidatedCopy,
    RetriedStableCopy,
    RaceDetected,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PreimageRef {
    StagedClone {
        stage_id: String,
        path: PathBuf,
        size: u64,
        consistency: PreimageConsistency,
    },
    StagedCopy {
        stage_id: String,
        path: PathBuf,
        size: u64,
        consistency: PreimageConsistency,
    },
    CanonicalCas {
        hash: String,
        size: u64,
        consistency: PreimageConsistency,
    },
    MetadataSnapshot {
        snapshot_id: String,
        consistency: PreimageConsistency,
    },
    Missing,
    Unsupported {
        reason: String,
    },
    RaceDetected {
        reason: String,
    },
}

impl PreimageRef {
    pub fn is_durable(&self) -> bool {
        matches!(
            self,
            Self::StagedClone { consistency, .. }
                | Self::StagedCopy { consistency, .. }
                | Self::CanonicalCas { consistency, .. }
                | Self::MetadataSnapshot { consistency, .. }
                if matches!(
                    consistency,
                    PreimageConsistency::AtomicSnapshot
                        | PreimageConsistency::StableValidatedCopy
                        | PreimageConsistency::RetriedStableCopy
                )
        )
    }

    pub fn consistency(&self) -> Option<PreimageConsistency> {
        match self {
            Self::StagedClone { consistency, .. }
            | Self::StagedCopy { consistency, .. }
            | Self::CanonicalCas { consistency, .. }
            | Self::MetadataSnapshot { consistency, .. } => Some(*consistency),
            Self::Missing | Self::Unsupported { .. } | Self::RaceDetected { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AdmissionDenial {
    InsufficientDeadline,
    InsufficientStorage,
    CaptureDegraded,
    DurabilityFailure,
    Backpressure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AdmissionDecision {
    ExactAlreadyProtected {
        preimage: PreimageRef,
    },
    StagedClone {
        preimage: PreimageRef,
    },
    StagedCopy {
        preimage: PreimageRef,
    },
    ExactMetadata {
        preimage: PreimageRef,
    },
    NoPreimageRequired,
    Deny {
        reason: AdmissionDenial,
    },
    UnsupportedObject {
        reason: String,
    },
    UnsupportedOperation {
        operation: MutationOperation,
        reason: String,
    },
    Race {
        reason: String,
    },
    Unknown {
        reason: String,
    },
}

impl AdmissionDecision {
    pub fn is_admitted(&self) -> bool {
        matches!(
            self,
            Self::ExactAlreadyProtected { .. }
                | Self::StagedClone { .. }
                | Self::StagedCopy { .. }
                | Self::ExactMetadata { .. }
                | Self::NoPreimageRequired
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeadlineBudget {
    pub deadline_ns: u64,
    pub observed_ns: u64,
    pub worker_start_ns: Option<u64>,
    pub reserved_response_margin_ns: u64,
    pub estimated_preserve_ns: u64,
    pub estimated_journal_ns: u64,
}

impl DeadlineBudget {
    pub fn remaining_ns(&self, now_ns: u64) -> u64 {
        self.deadline_ns.saturating_sub(now_ns)
    }

    pub fn required_ns(&self) -> u64 {
        self.reserved_response_margin_ns
            .saturating_add(self.estimated_preserve_ns)
            .saturating_add(self.estimated_journal_ns)
    }

    pub fn plausible_at(&self, now_ns: u64) -> bool {
        self.remaining_ns(now_ns) >= self.required_ns()
    }

    pub fn worker_delay_ns(&self, now_ns: u64) -> Option<u64> {
        self.worker_start_ns.map(|worker_start| {
            worker_start
                .saturating_sub(self.observed_ns)
                .max(now_ns.saturating_sub(worker_start))
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PreimageStrategy {
    AlreadyProtected,
    StagedClone,
    StagedCopy,
    CanonicalCas,
    MetadataOnly,
    None,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CostEstimate {
    pub preserve_ns: u64,
    pub journal_ns: u64,
    pub total_ns: u64,
    pub strategy: PreimageStrategy,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CostEstimator {
    pub filesystem: String,
    pub samples: Vec<CostSample>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CostSample {
    pub operation: MutationOperation,
    pub size_bytes: u64,
    pub strategy: PreimageStrategy,
    pub elapsed_ns: u64,
}

impl CostEstimator {
    pub fn new(filesystem: impl Into<String>) -> Self {
        Self {
            filesystem: filesystem.into(),
            samples: Vec::new(),
        }
    }

    pub fn record(&mut self, sample: CostSample) {
        self.samples.push(sample);
        if self.samples.len() > 4096 {
            self.samples.drain(..self.samples.len() - 4096);
        }
    }

    pub fn estimate(
        &self,
        operation: MutationOperation,
        size_bytes: u64,
        strategy: PreimageStrategy,
    ) -> CostEstimate {
        let matching: Vec<u64> = self
            .samples
            .iter()
            .filter(|sample| sample.operation == operation && sample.strategy == strategy)
            .map(|sample| sample.elapsed_ns)
            .collect();
        let preserve_ns = if matching.is_empty() {
            match strategy {
                PreimageStrategy::None => 0,
                PreimageStrategy::MetadataOnly => 100_000,
                PreimageStrategy::AlreadyProtected => 50_000,
                PreimageStrategy::StagedClone => 500_000,
                PreimageStrategy::StagedCopy | PreimageStrategy::CanonicalCas => {
                    1_000_000u64.saturating_add(size_bytes.saturating_mul(20))
                }
            }
        } else {
            matching.iter().copied().max().unwrap_or_default()
        };
        let journal_ns = 250_000u64.saturating_add((matching.len() as u64).saturating_mul(10_000));
        CostEstimate {
            preserve_ns,
            journal_ns,
            total_ns: preserve_ns.saturating_add(journal_ns),
            strategy,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdmissionRequest {
    pub effect_id: EffectId,
    pub transaction_id: TransactionId,
    pub process_id: ProcessId,
    pub object_id: Option<ObjectId>,
    pub operation: MutationOperation,
    pub object_size_bytes: u64,
    pub capture_status: CaptureStatus,
    pub capabilities: ReversibilityCapabilities,
    pub preimage: PreimageRef,
    pub deadline: DeadlineBudget,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MutationPhase {
    ObservedAuthorization,
    PreimagePreparing,
    PreimageDurable,
    AdmissionPrepared,
    AuthorizationReleased,
    MutationObserved,
    MutationCommitted,
    Failed,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MutationLifecycle {
    pub effect_id: EffectId,
    pub phase: MutationPhase,
    pub transitions: Vec<MutationPhase>,
}

impl MutationLifecycle {
    pub fn new(effect_id: EffectId) -> Self {
        Self {
            effect_id,
            phase: MutationPhase::ObservedAuthorization,
            transitions: vec![MutationPhase::ObservedAuthorization],
        }
    }

    pub fn transition(&mut self, next: MutationPhase) -> Result<(), AdmissionError> {
        if !valid_transition(&self.phase, &next) {
            return Err(AdmissionError::InvalidLifecycle {
                from: self.phase.clone(),
                to: next,
            });
        }
        self.phase = next.clone();
        self.transitions.push(next);
        Ok(())
    }
}

fn valid_transition(from: &MutationPhase, to: &MutationPhase) -> bool {
    use MutationPhase::*;
    matches!(
        (from, to),
        (
            ObservedAuthorization,
            PreimagePreparing | Failed | OutcomeUnknown
        ) | (PreimagePreparing, PreimageDurable | Failed | OutcomeUnknown)
            | (PreimageDurable, AdmissionPrepared | Failed | OutcomeUnknown)
            | (
                AdmissionPrepared,
                AuthorizationReleased | Failed | OutcomeUnknown
            )
            | (
                AuthorizationReleased,
                MutationObserved | Failed | OutcomeUnknown
            )
            | (
                MutationObserved,
                MutationCommitted | Failed | OutcomeUnknown
            )
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreparedAdmission {
    pub request: AdmissionRequest,
    pub decision: AdmissionDecision,
    pub lifecycle: MutationLifecycle,
    pub prepared_record: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DurabilityReceipt {
    pub barrier_id: String,
    pub effect_ids: Vec<EffectId>,
    pub durable_at_ns: u64,
    pub batch_size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GroupCommitWindow {
    Us100,
    Us250,
    Us500,
    Ms1,
    Ms2,
    Adaptive,
}

impl GroupCommitWindow {
    pub fn nanoseconds(self) -> Option<u64> {
        match self {
            Self::Us100 => Some(100_000),
            Self::Us250 => Some(250_000),
            Self::Us500 => Some(500_000),
            Self::Ms1 => Some(1_000_000),
            Self::Ms2 => Some(2_000_000),
            Self::Adaptive => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdmissionResult {
    pub effect_id: EffectId,
    pub decision: AdmissionDecision,
    pub receipt: Option<DurabilityReceipt>,
    pub lifecycle: MutationLifecycle,
}

#[derive(Debug, Error)]
pub enum BarrierError {
    #[error("durability barrier failed: {0}")]
    Io(#[from] io::Error),
    #[error("durability barrier rejected the batch: {0}")]
    Rejected(String),
}

/// A barrier must make the whole batch durable or reject the whole batch.
/// Partial success is not an admissible result because the caller would not
/// know which authorizations were safe to release.
pub trait DurabilityBarrier {
    fn persist_batch(
        &mut self,
        batch: &[PreparedAdmission],
        now_ns: u64,
    ) -> Result<DurabilityReceipt, BarrierError>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryDurabilityBarrier {
    pub fail: bool,
    pub barrier_count: usize,
    pub durable_effects: BTreeSet<EffectId>,
}

impl DurabilityBarrier for InMemoryDurabilityBarrier {
    fn persist_batch(
        &mut self,
        batch: &[PreparedAdmission],
        now_ns: u64,
    ) -> Result<DurabilityReceipt, BarrierError> {
        if self.fail {
            return Err(BarrierError::Rejected("injected barrier failure".into()));
        }
        self.barrier_count += 1;
        let effect_ids: Vec<_> = batch.iter().map(|item| item.request.effect_id).collect();
        self.durable_effects.extend(effect_ids.iter().copied());
        Ok(DurabilityReceipt {
            barrier_id: format!("memory-{}", self.barrier_count),
            effect_ids,
            durable_at_ns: now_ns,
            batch_size: batch.len(),
        })
    }
}

pub struct FileDurabilityBarrier {
    path: PathBuf,
    file: File,
    next_id: u64,
}

impl FileDurabilityBarrier {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BarrierError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            file,
            next_id: 1,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl DurabilityBarrier for FileDurabilityBarrier {
    fn persist_batch(
        &mut self,
        batch: &[PreparedAdmission],
        now_ns: u64,
    ) -> Result<DurabilityReceipt, BarrierError> {
        let barrier_id = format!("file-{}", self.next_id);
        self.next_id += 1;
        let receipt = DurabilityReceipt {
            barrier_id: barrier_id.clone(),
            effect_ids: batch.iter().map(|item| item.request.effect_id).collect(),
            durable_at_ns: now_ns,
            batch_size: batch.len(),
        };
        let encoded = serde_json::to_vec(&(barrier_id, batch, &receipt))
            .map_err(|error| BarrierError::Rejected(error.to_string()))?;
        self.file.write_all(&encoded)?;
        self.file.write_all(b"\n")?;
        self.file.sync_all()?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(receipt)
    }
}

pub struct DurabilityCoordinator<B> {
    barrier: B,
    pending: Vec<PreparedAdmission>,
    pub window_ns: u64,
}

impl<B: DurabilityBarrier> DurabilityCoordinator<B> {
    pub fn new(barrier: B, window_ns: u64) -> Self {
        Self {
            barrier,
            pending: Vec::new(),
            window_ns,
        }
    }

    pub fn with_window_policy(barrier: B, policy: GroupCommitWindow) -> Self {
        Self::new(barrier, policy.nanoseconds().unwrap_or(500_000))
    }

    pub fn queue(&mut self, prepared: PreparedAdmission) -> Result<(), AdmissionError> {
        if !prepared.decision.is_admitted() {
            return Err(AdmissionError::NotAdmissible(prepared.decision));
        }
        self.pending.push(prepared);
        Ok(())
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn flush(&mut self, now_ns: u64) -> Vec<AdmissionResult> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let batch = std::mem::take(&mut self.pending);
        if batch
            .iter()
            .any(|prepared| !prepared.request.deadline.plausible_at(now_ns))
        {
            return batch
                .into_iter()
                .map(|prepared| denied_result(prepared, AdmissionDenial::InsufficientDeadline))
                .collect();
        }
        match self.barrier.persist_batch(&batch, now_ns) {
            Ok(receipt) => batch
                .into_iter()
                .map(|mut prepared| {
                    let _ = prepared
                        .lifecycle
                        .transition(MutationPhase::AuthorizationReleased);
                    AdmissionResult {
                        effect_id: prepared.request.effect_id,
                        decision: prepared.decision,
                        receipt: Some(receipt.clone()),
                        lifecycle: prepared.lifecycle,
                    }
                })
                .collect(),
            Err(_) => batch
                .into_iter()
                .map(|prepared| denied_result(prepared, AdmissionDenial::DurabilityFailure))
                .collect(),
        }
    }

    pub fn into_barrier(self) -> B {
        self.barrier
    }
}

fn denied_result(mut prepared: PreparedAdmission, reason: AdmissionDenial) -> AdmissionResult {
    let _ = prepared.lifecycle.transition(MutationPhase::Failed);
    AdmissionResult {
        effect_id: prepared.request.effect_id,
        decision: AdmissionDecision::Deny { reason },
        receipt: None,
        lifecycle: prepared.lifecycle,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MutationProofRecord {
    pub effect_id: EffectId,
    pub transaction_id: TransactionId,
    pub process_id: ProcessId,
    pub object_id: Option<ObjectId>,
    pub operation: MutationOperation,
    pub preimage: PreimageRef,
    pub fidelity: CapabilityFidelity,
    pub durability_barrier: Option<DurabilityReceipt>,
    pub prepared_journal_sequence: Option<u64>,
    pub authorization_observed_ns: u64,
    pub authorization_released_ns: Option<u64>,
    pub mutation_observed_ns: Option<u64>,
    pub reconciliation_sequence: Option<u64>,
    pub deadline: DeadlineBudget,
    pub decision: AdmissionDecision,
    pub uncertainties: Vec<String>,
    pub final_phase: MutationPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LaunchBarrierState {
    Created,
    TransactionInitialized,
    CaptureInitialized,
    RunnerSpawned,
    TransactionArmed,
    GoReleased,
    TargetStarted,
    Failed,
}

/// The process target must remain blocked until journal, capture, and the
/// admission barrier have all reported readiness. This state machine is the
/// platform-neutral part of the runner; the macOS implementation supplies the
/// actual IPC and process creation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LaunchBarrier {
    pub state: LaunchBarrierState,
    pub target: Vec<String>,
    pub transaction_id: TransactionId,
}

impl LaunchBarrier {
    pub fn new(transaction_id: TransactionId, target: Vec<String>) -> Self {
        Self {
            state: LaunchBarrierState::Created,
            target,
            transaction_id,
        }
    }

    pub fn initialize_transaction(&mut self) -> Result<(), AdmissionError> {
        self.move_to(LaunchBarrierState::TransactionInitialized)
    }

    pub fn initialize_capture(&mut self) -> Result<(), AdmissionError> {
        self.move_to(LaunchBarrierState::CaptureInitialized)
    }

    pub fn runner_spawned(&mut self) -> Result<(), AdmissionError> {
        self.move_to(LaunchBarrierState::RunnerSpawned)
    }

    pub fn arm(&mut self) -> Result<(), AdmissionError> {
        self.move_to(LaunchBarrierState::TransactionArmed)
    }

    pub fn release_go(&mut self) -> Result<(), AdmissionError> {
        self.move_to(LaunchBarrierState::GoReleased)
    }

    pub fn target_started(&mut self) -> Result<(), AdmissionError> {
        self.move_to(LaunchBarrierState::TargetStarted)
    }

    fn move_to(&mut self, next: LaunchBarrierState) -> Result<(), AdmissionError> {
        let valid = matches!(
            (self.state, next),
            (
                LaunchBarrierState::Created,
                LaunchBarrierState::TransactionInitialized
            ) | (
                LaunchBarrierState::TransactionInitialized,
                LaunchBarrierState::CaptureInitialized
            ) | (
                LaunchBarrierState::CaptureInitialized,
                LaunchBarrierState::RunnerSpawned
            ) | (
                LaunchBarrierState::RunnerSpawned,
                LaunchBarrierState::TransactionArmed
            ) | (
                LaunchBarrierState::TransactionArmed,
                LaunchBarrierState::GoReleased
            ) | (
                LaunchBarrierState::GoReleased,
                LaunchBarrierState::TargetStarted
            )
        );
        if !valid {
            return Err(AdmissionError::InvalidLaunchTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FdCapability {
    ReadOnly,
    Writable,
    Directory,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FdTransfer {
    Open,
    Dup,
    FcntlDup,
    Fork,
    Exec,
    ScmRights,
    Close,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FdCapabilityEdge {
    pub from_fd: u32,
    pub to_fd: Option<u32>,
    pub capability: FdCapability,
    pub transfer: FdTransfer,
    pub process_id: ProcessId,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FdCapabilityGraph {
    pub edges: Vec<FdCapabilityEdge>,
    pub unknown_inherited_fds: Vec<u32>,
}

impl FdCapabilityGraph {
    pub fn record(&mut self, edge: FdCapabilityEdge) {
        self.edges.push(edge);
    }

    pub fn record_unknown_inherited(&mut self, fd: u32) {
        self.unknown_inherited_fds.push(fd);
    }

    pub fn has_writable_path(&self, fd: u32) -> bool {
        self.edges.iter().any(|edge| {
            edge.from_fd == fd
                && matches!(
                    edge.capability,
                    FdCapability::Writable | FdCapability::Unknown
                )
        })
    }

    pub fn can_claim_sanitized_inheritance(&self) -> bool {
        self.unknown_inherited_fds.is_empty()
    }
}

impl MutationProofRecord {
    pub fn exactness_is_claimable(&self) -> bool {
        self.final_phase == MutationPhase::MutationCommitted
            && self.durability_barrier.is_some()
            && self.preimage.is_durable()
            && matches!(
                self.decision,
                AdmissionDecision::ExactAlreadyProtected { .. }
                    | AdmissionDecision::StagedClone { .. }
                    | AdmissionDecision::StagedCopy { .. }
                    | AdmissionDecision::ExactMetadata { .. }
                    | AdmissionDecision::NoPreimageRequired
            )
            && self.uncertainties.is_empty()
    }
}

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("invalid mutation lifecycle transition: {from:?} -> {to:?}")]
    InvalidLifecycle {
        from: MutationPhase,
        to: MutationPhase,
    },
    #[error("mutation is not admissible: {0:?}")]
    NotAdmissible(AdmissionDecision),
    #[error("unsupported operation: {0:?}")]
    UnsupportedOperation(MutationOperation),
    #[error("invalid launch barrier transition: {from:?} -> {to:?}")]
    InvalidLaunchTransition {
        from: LaunchBarrierState,
        to: LaunchBarrierState,
    },
}

pub fn decide(request: &AdmissionRequest, now_ns: u64) -> AdmissionDecision {
    if request.capture_status == CaptureStatus::Degraded {
        return AdmissionDecision::Deny {
            reason: AdmissionDenial::CaptureDegraded,
        };
    }
    if !request.deadline.plausible_at(now_ns) {
        return AdmissionDecision::Deny {
            reason: AdmissionDenial::InsufficientDeadline,
        };
    }
    if request
        .capabilities
        .capture_complete
        .eq(&CapabilityFidelity::Unsupported)
    {
        return AdmissionDecision::Unknown {
            reason: "capture completeness is unsupported".into(),
        };
    }
    if request.capabilities.actor != CapabilityFidelity::Exact
        || request.capabilities.lineage != CapabilityFidelity::Exact
        || request.capabilities.capture_complete != CapabilityFidelity::Exact
        || request.capabilities.path != CapabilityFidelity::Exact
        || request.capabilities.external != realm_core::ExternalCapability::None
    {
        return AdmissionDecision::Unknown {
            reason: "actor, lineage, path, complete capture, and external-effect dimensions are not all exact".into(),
        };
    }
    let metadata_required = matches!(
        request.operation,
        MutationOperation::Metadata | MutationOperation::Xattr | MutationOperation::Flags
    );
    let links_required = matches!(
        request.operation,
        MutationOperation::Link | MutationOperation::Symlink | MutationOperation::RenameOverwrite
    );
    if (metadata_required && request.capabilities.metadata != CapabilityFidelity::Exact)
        || (links_required && request.capabilities.link_graph != CapabilityFidelity::Exact)
        || (!matches!(request.operation, MutationOperation::Create)
            && request.capabilities.content != CapabilityFidelity::Exact)
    {
        return AdmissionDecision::Unknown {
            reason: "the operation's required fidelity dimension is not exact".into(),
        };
    }
    if matches!(request.operation, MutationOperation::MmapShared) {
        return AdmissionDecision::UnsupportedOperation {
            operation: request.operation,
            reason: "writable shared mmap is not in the exact support envelope".into(),
        };
    }
    match &request.preimage {
        preimage @ PreimageRef::StagedClone { .. } if !preimage.is_durable() => {
            AdmissionDecision::Race {
                reason: "staged clone consistency is not validated".into(),
            }
        }
        PreimageRef::StagedClone { .. } => AdmissionDecision::StagedClone {
            preimage: request.preimage.clone(),
        },
        preimage @ PreimageRef::StagedCopy { .. } if !preimage.is_durable() => {
            AdmissionDecision::Race {
                reason: "staged copy consistency is not validated".into(),
            }
        }
        PreimageRef::StagedCopy { .. } => AdmissionDecision::StagedCopy {
            preimage: request.preimage.clone(),
        },
        preimage @ PreimageRef::CanonicalCas { .. } if !preimage.is_durable() => {
            AdmissionDecision::Race {
                reason: "canonical preimage consistency is not validated".into(),
            }
        }
        PreimageRef::CanonicalCas { .. } => AdmissionDecision::ExactAlreadyProtected {
            preimage: request.preimage.clone(),
        },
        preimage @ PreimageRef::MetadataSnapshot { .. } if !preimage.is_durable() => {
            AdmissionDecision::Race {
                reason: "metadata snapshot consistency is not validated".into(),
            }
        }
        PreimageRef::MetadataSnapshot { .. } => AdmissionDecision::ExactMetadata {
            preimage: request.preimage.clone(),
        },
        PreimageRef::Missing => {
            if request.operation == MutationOperation::Create {
                AdmissionDecision::NoPreimageRequired
            } else {
                AdmissionDecision::Deny {
                    reason: AdmissionDenial::InsufficientStorage,
                }
            }
        }
        PreimageRef::Unsupported { reason } => AdmissionDecision::UnsupportedObject {
            reason: reason.clone(),
        },
        PreimageRef::RaceDetected { reason } => AdmissionDecision::Race {
            reason: reason.clone(),
        },
    }
}

pub fn prepare(request: AdmissionRequest, now_ns: u64) -> PreparedAdmission {
    let decision = decide(&request, now_ns);
    let mut lifecycle = MutationLifecycle::new(request.effect_id);
    if decision.is_admitted() {
        let _ = lifecycle.transition(MutationPhase::PreimagePreparing);
        let _ = lifecycle.transition(MutationPhase::PreimageDurable);
        let _ = lifecycle.transition(MutationPhase::AdmissionPrepared);
    } else {
        let _ = lifecycle.transition(MutationPhase::Failed);
    }
    let prepared_record = serde_json::to_vec(&(&request, &decision)).unwrap_or_default();
    PreparedAdmission {
        request,
        decision,
        lifecycle,
        prepared_record,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use realm_core::{ExternalCapability, ProcessId, TransactionId};

    fn request(preimage: PreimageRef) -> AdmissionRequest {
        AdmissionRequest {
            effect_id: EffectId::new(),
            transaction_id: TransactionId::new(),
            process_id: ProcessId::new(),
            object_id: Some(ObjectId::new()),
            operation: MutationOperation::Write,
            object_size_bytes: 4,
            capture_status: CaptureStatus::Complete,
            capabilities: ReversibilityCapabilities {
                content: CapabilityFidelity::Exact,
                path: CapabilityFidelity::Exact,
                metadata: CapabilityFidelity::Exact,
                link_graph: CapabilityFidelity::Exact,
                actor: CapabilityFidelity::Exact,
                lineage: CapabilityFidelity::Exact,
                capture_complete: CapabilityFidelity::Exact,
                external: ExternalCapability::None,
            },
            preimage,
            deadline: DeadlineBudget {
                deadline_ns: 10_000_000,
                observed_ns: 0,
                worker_start_ns: Some(1),
                reserved_response_margin_ns: 100,
                estimated_preserve_ns: 100,
                estimated_journal_ns: 100,
            },
        }
    }

    #[test]
    fn fully_captured_is_derived_from_all_dimensions() {
        let req = request(PreimageRef::CanonicalCas {
            hash: "abc".into(),
            size: 4,
            consistency: PreimageConsistency::StableValidatedCopy,
        });
        assert_eq!(
            req.capabilities.fully_captured(),
            realm_core::FullyCaptured::Proven
        );
        let mut degraded = req.capabilities.clone();
        degraded.metadata = CapabilityFidelity::SupportedSubset;
        assert_eq!(
            degraded.fully_captured(),
            realm_core::FullyCaptured::NotProven
        );
    }

    #[test]
    fn degraded_capture_and_race_fail_closed() {
        let mut req = request(PreimageRef::RaceDetected {
            reason: "signature changed".into(),
        });
        assert!(matches!(decide(&req, 1), AdmissionDecision::Race { .. }));
        req.capture_status = CaptureStatus::Degraded;
        assert_eq!(
            decide(&req, 1),
            AdmissionDecision::Deny {
                reason: AdmissionDenial::CaptureDegraded
            }
        );
    }

    #[test]
    fn group_barrier_failure_denies_every_pending_effect() {
        let preimage = PreimageRef::CanonicalCas {
            hash: "abc".into(),
            size: 4,
            consistency: PreimageConsistency::StableValidatedCopy,
        };
        let first = prepare(request(preimage.clone()), 1);
        let second = prepare(request(preimage), 1);
        let barrier = InMemoryDurabilityBarrier {
            fail: true,
            ..Default::default()
        };
        let mut coordinator = DurabilityCoordinator::new(barrier, 100);
        coordinator.queue(first).unwrap();
        coordinator.queue(second).unwrap();
        let results = coordinator.flush(2);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|result| result.receipt.is_none()));
        assert!(results.iter().all(|result| matches!(
            result.decision,
            AdmissionDecision::Deny {
                reason: AdmissionDenial::DurabilityFailure
            }
        )));
        let barrier = coordinator.into_barrier();
        assert_eq!(barrier.barrier_count, 0);
    }

    #[test]
    fn launch_barrier_cannot_release_go_early() {
        let mut barrier = LaunchBarrier::new(TransactionId::new(), vec!["mutator".into()]);
        assert!(barrier.release_go().is_err());
        barrier.initialize_transaction().unwrap();
        barrier.initialize_capture().unwrap();
        barrier.runner_spawned().unwrap();
        barrier.arm().unwrap();
        barrier.release_go().unwrap();
        barrier.target_started().unwrap();
        assert_eq!(barrier.state, LaunchBarrierState::TargetStarted);
    }

    #[test]
    fn unknown_inherited_fd_blocks_sanitized_claim() {
        let mut graph = FdCapabilityGraph::default();
        graph.record_unknown_inherited(3);
        assert!(!graph.can_claim_sanitized_inheritance());
    }

    #[test]
    fn group_commit_windows_are_explicit() {
        assert_eq!(GroupCommitWindow::Us100.nanoseconds(), Some(100_000));
        assert_eq!(GroupCommitWindow::Ms2.nanoseconds(), Some(2_000_000));
        assert_eq!(GroupCommitWindow::Adaptive.nanoseconds(), None);
    }
}
