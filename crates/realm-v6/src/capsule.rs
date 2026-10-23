//! Host-owned capsule observation contract.
//!
//! The Linux backend below is deliberately fail-closed until the measured
//! Firecracker supervisor supplies the private host facts required by C1.
//! Observation is evidence, never a policy decision.

use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSpec {
    pub task_version: String,
    pub image_digest: String,
    pub kernel_digest: String,
    pub vmm_digest: String,
    pub toolchain_digest: String,
    pub policy_digest: String,
    pub argv: Vec<String>,
    pub environment: Vec<(String, String)>,
    pub cwd: String,
    pub uid: u32,
    pub limits_digest: String,
    pub time_seed: u64,
    pub random_seed: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckResult {
    Verified,
    Failed,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackendKind {
    FirecrackerMeasured,
    NamespaceContained,
    DiagnosticOnly,
}

/// Host-owned facts. Fields and constructors are crate-private so an external
/// task cannot manufacture a verified backend or check result:
/// ```compile_fail
/// use realm_v6::capsule::{BackendKind, CapsuleFacts};
/// let _ = CapsuleFacts {
///     run_id: "run".into(),
///     execution_id: "execution".into(),
///     backend: BackendKind::FirecrackerMeasured,
///     ..unimplemented!()
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapsuleFacts {
    pub(crate) run_id: String,
    pub(crate) execution_id: String,
    pub(crate) backend: BackendKind,
    pub(crate) workspace_identity: String,
    /// Logical capsule identity, distinct from host process identity.
    pub(crate) capsule_id: String,
    /// Host-observed run-owned process identity; absent evidence cannot join.
    pub(crate) custody_process_identity: Option<String>,
    pub(crate) descendants: Vec<String>,
    pub(crate) starting_world: String,
    pub(crate) final_world: Option<String>,
    pub(crate) observed_effects: Vec<String>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) crashed: bool,
    pub(crate) quiescence: CheckResult,
    pub(crate) monitor_loss: CheckResult,
    pub(crate) network: CheckResult,
    pub(crate) filesystem: CheckResult,
    pub(crate) frozen: CheckResult,
    pub(crate) evidence_root: Option<String>,
    pub(crate) sequence_start: u64,
    pub(crate) sequence_end: Option<u64>,
    pub(crate) unsupported_effects: Vec<String>,
    pub(crate) runtime_identity: String,
    pub(crate) network_policy_identity: String,
    pub(crate) completion_evidence: String,
    pub(crate) finalization_evidence: String,
    pub(crate) pause_snapshot_evidence: String,
    /// Host-observed VMM-cgroup closure evidence. This only establishes that
    /// the measured VMM subtree became empty; it does not prove effect-channel
    /// revocation, broker drain, or absence of capabilities copied elsewhere.
    pub(crate) vmm_terminal_observation_root: Option<String>,
    pub(crate) delta_root: String,
}

/// Evidence carrying a private host-observation marker. Ordinary task code
/// can deserialize facts for diagnostics, but cannot construct this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsuleObservation {
    facts: CapsuleFacts,
    host_observed: HostObservationMarker,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostObservationMarker {
    backend_measurement: String,
}

impl CapsuleObservation {
    pub fn facts(&self) -> &CapsuleFacts {
        &self.facts
    }

    #[allow(dead_code)]
    pub(crate) fn from_host_facts(
        facts: CapsuleFacts,
        backend_measurement: String,
    ) -> Result<Self, CapsuleFailure> {
        if backend_measurement.is_empty()
            || facts.run_id.is_empty()
            || facts.execution_id.is_empty()
        {
            return Err(CapsuleFailure::IncompleteEvidence);
        }
        Ok(Self {
            facts,
            host_observed: HostObservationMarker {
                backend_measurement,
            },
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn from_supervisor_facts(
        facts: CapsuleFacts,
        backend_measurement: String,
    ) -> Result<Self, CapsuleFailure> {
        Self::from_host_facts(facts, backend_measurement)
    }

    #[cfg(test)]
    pub(crate) fn test_host_observation(facts: CapsuleFacts) -> Self {
        Self::from_host_facts(facts, "test-firecracker-measurement".into())
            .expect("test observation must be complete")
    }

    pub(crate) fn is_host_observed(&self) -> bool {
        !self.host_observed.backend_measurement.is_empty()
    }
}

macro_rules! capsule_fact_accessors {
    ($($name:ident : $ty:ty),* $(,)?) => {
        $(pub fn $name(&self) -> &$ty { &self.$name })*
    };
}

impl CapsuleFacts {
    capsule_fact_accessors!(
        run_id: String,
        execution_id: String,
        backend: BackendKind,
        workspace_identity: String,
        capsule_id: String,
        custody_process_identity: Option<String>,
        descendants: Vec<String>,
        starting_world: String,
        final_world: Option<String>,
        observed_effects: Vec<String>,
        exit_code: Option<i32>,
        crashed: bool,
        quiescence: CheckResult,
        monitor_loss: CheckResult,
        network: CheckResult,
        filesystem: CheckResult,
        frozen: CheckResult,
        evidence_root: Option<String>,
        sequence_start: u64,
        sequence_end: Option<u64>,
        unsupported_effects: Vec<String>,
        runtime_identity: String,
        network_policy_identity: String,
        completion_evidence: String,
        finalization_evidence: String,
        pause_snapshot_evidence: String,
        vmm_terminal_observation_root: Option<String>,
        delta_root: String,
    );
}

pub(crate) fn legacy_evidence_binding_root(facts: &CapsuleFacts) -> String {
    let mut hasher = blake3::Hasher::new();
    for value in [
        facts.runtime_identity(),
        facts.workspace_identity(),
        facts.capsule_id(),
        facts.starting_world(),
        facts.final_world().as_deref().unwrap_or(""),
        facts.completion_evidence(),
        facts.finalization_evidence(),
        facts.pause_snapshot_evidence(),
        facts
            .vmm_terminal_observation_root()
            .as_deref()
            .unwrap_or(""),
        facts.delta_root(),
        facts.network_policy_identity(),
    ] {
        hasher.update(value.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

pub(crate) fn evidence_binding_root_v2(facts: &CapsuleFacts) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"REALM::V6CapsuleEvidenceBinding\0");
    hasher.update(&2_u16.to_le_bytes());
    for value in [
        facts.runtime_identity(),
        facts.workspace_identity(),
        facts.capsule_id(),
        facts.starting_world(),
        facts.final_world().as_deref().unwrap_or(""),
        facts.completion_evidence(),
        facts.finalization_evidence(),
        facts.pause_snapshot_evidence(),
        facts
            .vmm_terminal_observation_root()
            .as_deref()
            .unwrap_or(""),
        facts.delta_root(),
        facts.network_policy_identity(),
    ] {
        let bytes = value.as_bytes();
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().to_hex().to_string()
}

/// Current evidence binding. Version 3 adds the host custody process
/// identity so a serialized evidence package cannot be paired with a
/// same-run join that observed a different custodian incarnation.
pub(crate) fn evidence_binding_root(facts: &CapsuleFacts) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"REALM::V6CapsuleEvidenceBinding\0");
    hasher.update(&3_u16.to_le_bytes());
    for value in [
        facts.runtime_identity(),
        facts.workspace_identity(),
        facts.capsule_id(),
        facts.starting_world(),
        facts.final_world().as_deref().unwrap_or(""),
        facts.completion_evidence(),
        facts.finalization_evidence(),
        facts.pause_snapshot_evidence(),
        facts
            .vmm_terminal_observation_root()
            .as_deref()
            .unwrap_or(""),
        facts.delta_root(),
        facts.network_policy_identity(),
        facts.custody_process_identity().as_deref().unwrap_or(""),
    ] {
        let bytes = value.as_bytes();
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().to_hex().to_string()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostChecks {
    pub frozen_world: CheckResult,
    pub process_and_fd_quiescence: CheckResult,
    pub network_boundary: CheckResult,
    pub device_boundary: CheckResult,
    pub executable_bytes: CheckResult,
    pub monitor_liveness_and_loss: CheckResult,
    pub effect_replay_agreement: CheckResult,
}

#[derive(Clone, Debug)]
pub struct CandidateEvidence {
    pub receipt_bytes: Vec<u8>,
    pub frozen_world_path: PathBuf,
    pub vm_cgroup_path: PathBuf,
}

#[derive(Clone, Debug)]
pub enum CapsuleFailure {
    Unavailable,
    PolicyViolation,
    MonitorFailure,
    IncompleteEvidence,
}

/// Implementations must be host-owned and isolated from task credentials.
/// This interface intentionally does not expose an acceptance capability.
pub trait CapsuleObserver {
    fn execute(&self, launch: &LaunchSpec) -> Result<CandidateEvidence, CapsuleFailure>;

    fn observe(&self, _launch: &LaunchSpec) -> Result<CapsuleObservation, CapsuleFailure> {
        Err(CapsuleFailure::Unavailable)
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub struct LinuxCapsuleObserver {
    pub workspace_root: PathBuf,
    pub cgroup_root: PathBuf,
    pub backend: BackendKind,
}

#[cfg(target_os = "linux")]
impl LinuxCapsuleObserver {
    pub fn firecracker(workspace_root: PathBuf, cgroup_root: PathBuf) -> Self {
        Self {
            workspace_root,
            cgroup_root,
            backend: BackendKind::FirecrackerMeasured,
        }
    }

    /// The supervisor integration point. Until Firecracker launch, pidfd,
    /// cgroup, monitor, and frozen-image facts are supplied by one host-owned
    /// implementation, this returns UNKNOWN rather than running on the host.
    pub fn collect(&self, _launch: &LaunchSpec) -> Result<CapsuleObservation, CapsuleFailure> {
        let _ = (&self.workspace_root, &self.cgroup_root, &self.backend);
        Err(CapsuleFailure::Unavailable)
    }

    /// Host prerequisite report used by the Linux launch supervisor. This is
    /// never sufficient for a claim; it only prevents silently attempting C1
    /// on a host without the required kernel facilities.
    pub fn preflight(&self) -> LinuxPreflight {
        LinuxPreflight {
            kvm: PathBuf::from("/dev/kvm").exists(),
            cgroup_v2: fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").is_ok(),
            workspace_is_absolute: self.workspace_root.is_absolute(),
            cgroup_is_absolute: self.cgroup_root.is_absolute(),
            hardware_validated: false,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LinuxPreflight {
    pub kvm: bool,
    pub cgroup_v2: bool,
    pub workspace_is_absolute: bool,
    pub cgroup_is_absolute: bool,
    pub hardware_validated: bool,
}

#[cfg(target_os = "linux")]
impl CapsuleObserver for LinuxCapsuleObserver {
    fn execute(&self, _launch: &LaunchSpec) -> Result<CandidateEvidence, CapsuleFailure> {
        Err(CapsuleFailure::Unavailable)
    }

    fn observe(&self, launch: &LaunchSpec) -> Result<CapsuleObservation, CapsuleFailure> {
        self.collect(launch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> CapsuleFacts {
        CapsuleFacts {
            run_id: "run".into(),
            execution_id: "execution".into(),
            backend: BackendKind::FirecrackerMeasured,
            workspace_identity: "a".repeat(64),
            capsule_id: "b".repeat(64),
            custody_process_identity: None,
            descendants: vec![],
            starting_world: "c".repeat(64),
            final_world: Some("d".repeat(64)),
            observed_effects: vec!["write:target".into()],
            exit_code: Some(0),
            crashed: false,
            quiescence: CheckResult::Verified,
            monitor_loss: CheckResult::Verified,
            network: CheckResult::Verified,
            filesystem: CheckResult::Verified,
            frozen: CheckResult::Verified,
            evidence_root: Some("e".repeat(64)),
            sequence_start: 0,
            sequence_end: Some(1),
            unsupported_effects: vec![],
            runtime_identity: "runtime".repeat(64),
            network_policy_identity: "network".repeat(64),
            completion_evidence: "completion".repeat(64),
            finalization_evidence: "finalization".repeat(64),
            pause_snapshot_evidence: "pause".repeat(64),
            vmm_terminal_observation_root: None,
            delta_root: "delta".repeat(64),
        }
    }

    #[test]
    fn host_observation_requires_private_marker() {
        assert!(CapsuleObservation::from_host_facts(facts(), "measurement".into()).is_ok());
        assert!(CapsuleObservation::from_host_facts(facts(), String::new()).is_err());
    }

    #[test]
    fn evidence_binding_root_uses_domain_and_length_prefixes() {
        let mut left = facts();
        left.workspace_identity = "ab".into();
        left.capsule_id = "c".into();
        let mut right = facts();
        right.workspace_identity = "a".into();
        right.capsule_id = "bc".into();
        assert_ne!(evidence_binding_root(&left), evidence_binding_root(&right));
    }

    #[test]
    fn evidence_binding_root_commits_to_vmm_terminal_observation() {
        let mut observation = facts();
        observation.vmm_terminal_observation_root = Some("a".repeat(64));
        let first = evidence_binding_root(&observation);
        observation.vmm_terminal_observation_root = Some("b".repeat(64));
        assert_ne!(first, evidence_binding_root(&observation));
    }

    #[test]
    fn evidence_binding_root_commits_to_custody_process_identity() {
        let mut observation = facts();
        observation.custody_process_identity = Some("a".repeat(64));
        let first = evidence_binding_root(&observation);
        observation.custody_process_identity = Some("b".repeat(64));
        assert_ne!(first, evidence_binding_root(&observation));
    }
}
