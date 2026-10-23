//! Host-side topology claims and capability accounting. These checks are
//! necessary but cannot attest that a VM actually booted with this topology.
use crate::capsule::{BackendKind, CapsuleObservation, CheckResult, evidence_binding_root};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

fn digest_shape(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachedDevice {
    pub kind: String,
    pub identity: String,
    pub read_only: bool,
}

/// Serializable topology description. Callers can construct it, so it is not
/// evidence that these devices or policies were actually loaded. A host
/// session must compare it with `/vm/config`; unknown fields/devices refuse.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediationManifest {
    pub schema: u32,
    pub run_id: String,
    pub vm_config_blake3: String,
    pub guest_kernel_blake3: String,
    pub rootfs_blake3: String,
    pub task_blake3: String,
    pub guest_policy_blake3: String,
    pub seccomp_blake3: String,
    pub measured_launch_hash_domain: String,
    pub measured_launch_hash_version: u16,
    pub measured_launch_blake3: String,
    pub broker_endpoint_identity: String,
    pub host_policy_identifier: String,
    pub host_policy_version: String,
    pub host_policy_blake3: String,
    pub launch_identity: String,
    pub starting_generation: String,
    pub final_world: String,
    pub delta_root: String,
    pub runtime_identity: String,
    pub network_policy_identity: String,
    pub broker_identity: String,
    pub broker_endpoint: String,
    pub devices: Vec<AttachedDevice>,
    pub network_devices: Vec<String>,
    pub shared_mounts: Vec<String>,
    pub inherited_fds: Vec<String>,
    pub writable_mappings: Vec<String>,
    pub other_storage_aliases: Vec<String>,
    pub max_task_processes: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MediationFailure {
    Malformed,
    Unanchored,
    AlternatePath,
    UnexpectedProcess,
    UnknownCapability,
    CapabilitySurvives,
    RequestInFlight,
    DuplicateIdentity,
    MissingTrustedObservation,
    UnsupportedBackend,
    WorldBindingMismatch,
    EvidenceBindingMismatch,
    MeasuredSessionMismatch,
    ChallengeMismatch,
}

/// A host-minted per-run challenge. The guest-facing value is non-secret; the
/// opaque type ensures broker startup binds the exact challenge the
/// supervisor issued for this run rather than a caller-selected digest.
#[derive(Debug, Eq, PartialEq)]
pub struct MediationChallenge {
    value: String,
}

impl MediationChallenge {
    /// Create a fresh challenge from the operating system random source.
    /// Possessing this value does not grant authority; it only prevents later
    /// evidence from silently substituting another run's challenge.
    pub fn fresh() -> Result<Self, std::io::Error> {
        let mut entropy = [0u8; 32];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut entropy)?;
        Ok(Self::from_entropy(&entropy))
    }

    fn from_entropy(entropy: &[u8; 32]) -> Self {
        Self {
            value: blake3::hash(entropy).to_hex().to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only(value: &str) -> Self {
        assert!(digest_shape(value));
        Self {
            value: value.to_owned(),
        }
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn root(&self) -> &str {
        &self.value
    }
}

/// Opaque pre-run binding for starting the canonical broker from a measured
/// Firecracker session. It binds the host challenge as well as launch-time
/// facts, and cannot authorize publication.
#[derive(Debug, Eq, PartialEq)]
pub struct MediationSessionBinding {
    root: String,
    run_id: String,
    execution_id: String,
    challenge_root: String,
    measured_launch_root: String,
    frontier_launch_identity: String,
    initial_process: ProcessIncarnation,
    broker_identity: String,
    endpoint_identity: String,
    starting_generation: String,
    policy_root: String,
}

impl MediationSessionBinding {
    /// Bind broker startup to the host-measured launch, semantic launch root,
    /// per-run challenge, and pinned parent world. `MeasuredLaunchSession`
    /// has no deserializer or public constructor; the fixed C0 profile derives
    /// its sole task-process identity from the held VMM incarnation.
    pub fn from_measured_launch(
        launch: &crate::measured_launch::MeasuredLaunchSession,
        frontier_launch_identity: &str,
        starting_generation: &str,
        challenge: &MediationChallenge,
    ) -> Result<Self, MediationFailure> {
        if !launch.supports_measured_brokered_c0_profile() {
            return Err(MediationFailure::MeasuredSessionMismatch);
        }
        launch
            .revalidate_inputs()
            .map_err(|_| MediationFailure::MeasuredSessionMismatch)?;
        launch
            .broker_endpoint()
            .revalidate()
            .map_err(|_| MediationFailure::MeasuredSessionMismatch)?;
        let endpoint_identity = launch.broker_endpoint_blake3();
        if launch.run_id().is_empty()
            || launch.execution_id().is_empty()
            || !digest_shape(starting_generation)
            || !digest_shape(frontier_launch_identity)
            || !digest_shape(launch.canonical_hash_blake3())
            || !digest_shape(&endpoint_identity)
            || !digest_shape(launch.firecracker_identity().blake3())
            || !digest_shape(launch.policy_identity().blake3())
        {
            return Err(MediationFailure::MeasuredSessionMismatch);
        }
        let run_id = launch.run_id().to_owned();
        let execution_id = launch.execution_id().to_owned();
        let challenge_root = challenge.root().to_owned();
        let measured_launch_root = launch.canonical_hash_blake3().to_owned();
        let frontier_launch_identity = frontier_launch_identity.to_owned();
        let initial_process = ProcessIncarnation {
            launch: execution_id.clone(),
            serial: 1,
            // The supported rootfs-only C0 profile has exactly one task
            // process. Its stable birth binding is the host-measured VMM
            // incarnation; guest supplied PID values are never accepted.
            birth: launch.vmm().start_time_ticks(),
        };
        let broker_identity = launch.firecracker_identity().blake3().to_owned();
        let starting_generation = starting_generation.to_owned();
        let policy_root = launch.policy_identity().blake3().to_owned();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"realm.mediation-session-binding.v3\0");
        for value in [
            &run_id,
            &execution_id,
            &challenge_root,
            &measured_launch_root,
            &frontier_launch_identity,
            &broker_identity,
            &endpoint_identity,
            &starting_generation,
            &policy_root,
        ] {
            let bytes = value.as_bytes();
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        Ok(Self {
            root: hasher.finalize().to_hex().to_string(),
            run_id,
            execution_id,
            challenge_root,
            measured_launch_root,
            frontier_launch_identity,
            initial_process,
            broker_identity,
            endpoint_identity,
            starting_generation,
            policy_root,
        })
    }

    pub fn root(&self) -> &str {
        &self.root
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub fn challenge_root(&self) -> &str {
        &self.challenge_root
    }

    pub(crate) fn frontier_launch_identity(&self) -> &str {
        &self.frontier_launch_identity
    }

    pub(crate) fn initial_process(&self) -> &ProcessIncarnation {
        &self.initial_process
    }

    pub(crate) fn broker_identity(&self) -> &str {
        &self.broker_identity
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn endpoint_identity_root(&self) -> &str {
        &self.endpoint_identity
    }

    pub fn starting_generation(&self) -> &str {
        &self.starting_generation
    }
}

/// Non-serializable proof that a canonical measured broker session sealed its
/// frontier. Only `BrokerRpc::finish_measured_session` can produce this token
/// in production.
/// ```compile_fail
/// use realm_v6::mediation::MeasuredBrokerCompletion;
/// let _forged = MeasuredBrokerCompletion {
///     root: "0".repeat(64),
///     session_binding_root: "0".repeat(64),
///     run_id: "run".into(),
///     execution_id: "execution".into(),
///     frontier_root: "0".repeat(64),
/// };
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct MeasuredBrokerCompletion {
    root: String,
    session_binding_root: String,
    run_id: String,
    execution_id: String,
    challenge_root: String,
    frontier_root: String,
}

impl MeasuredBrokerCompletion {
    pub(crate) fn from_sealed_session(
        session: &MediationSessionBinding,
        frontier_root: &str,
    ) -> Result<Self, MediationFailure> {
        if !digest_shape(frontier_root) {
            return Err(MediationFailure::EvidenceBindingMismatch);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"realm.measured-broker-completion.v2\0");
        for value in [
            session.root(),
            session.run_id(),
            session.execution_id(),
            session.challenge_root(),
            frontier_root,
        ] {
            let bytes = value.as_bytes();
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        Ok(Self {
            root: hasher.finalize().to_hex().to_string(),
            session_binding_root: session.root().to_owned(),
            run_id: session.run_id().to_owned(),
            execution_id: session.execution_id().to_owned(),
            challenge_root: session.challenge_root().to_owned(),
            frontier_root: frontier_root.to_owned(),
        })
    }

    #[cfg(test)]
    pub(crate) fn test_only_from_sealed_session(
        session: &MediationSessionBinding,
        frontier_root: &str,
    ) -> Self {
        Self::from_sealed_session(session, frontier_root)
            .expect("test broker completion has a valid frontier root")
    }

    pub fn root(&self) -> &str {
        &self.root
    }

    pub(crate) fn session_binding_root(&self) -> &str {
        &self.session_binding_root
    }

    pub(crate) fn run_id(&self) -> &str {
        &self.run_id
    }

    pub(crate) fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub(crate) fn challenge_root(&self) -> &str {
        &self.challenge_root
    }

    pub fn frontier_root(&self) -> &str {
        &self.frontier_root
    }
}

/// Syntactically checked, but untrusted: the caller may have chosen both the
/// bytes and the comparison root. This type cannot start a broker session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedMediationClaim {
    pub root: String,
    pub manifest: MediationManifest,
}

/// This claim is host-checkable but is not terminal authority. Its issuer
/// accepts only host-observed facts and a strict topology manifest; even a
/// successfully issued claim cannot make public admission or publication
/// succeed. Private fields prevent outside construction. A parsed claim must
/// never be promotable by ordinary conversion:
/// ```compile_fail
/// use realm_v6::mediation::{CheckedMediationClaim, ParsedMediationClaim};
/// fn forge(parsed: ParsedMediationClaim) -> CheckedMediationClaim { parsed.into() }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct CheckedMediationClaim {
    root: String,
    session_binding_root: String,
    broker_completion_root: Option<String>,
    broker_frontier_root: Option<String>,
    manifest: MediationManifest,
}

impl CheckedMediationClaim {
    pub fn root(&self) -> &str {
        &self.root
    }

    pub fn session_binding_root(&self) -> &str {
        &self.session_binding_root
    }

    pub fn broker_completion_root(&self) -> Option<&str> {
        self.broker_completion_root.as_deref()
    }

    pub fn broker_frontier_root(&self) -> Option<&str> {
        self.broker_frontier_root.as_deref()
    }

    /// Issue the only production C1 claim. The caller must provide a
    /// `CapsuleObservation` obtained from a host observer; serialized facts or
    /// agent-controlled manifest metadata cannot construct that value.
    pub fn issue_c1_claim(
        manifest_bytes: &[u8],
        comparison_root: &str,
        observation: &CapsuleObservation,
    ) -> Result<CheckedMediationClaim, MediationFailure> {
        Self::issue_observed_claim(manifest_bytes, comparison_root, observation, false)
    }

    // Shutdown-only completion is available solely to the private producer,
    // after it matches the contained launch and frozen broker capabilities.
    fn issue_observed_claim(
        manifest_bytes: &[u8],
        comparison_root: &str,
        observation: &CapsuleObservation,
        contained_shutdown: bool,
    ) -> Result<CheckedMediationClaim, MediationFailure> {
        if !observation.is_host_observed() {
            return Err(MediationFailure::MissingTrustedObservation);
        }
        let parsed = check_manifest_claim_shape(manifest_bytes, comparison_root)?;
        let facts = observation.facts();
        if facts.backend() != &BackendKind::FirecrackerMeasured {
            return Err(MediationFailure::UnsupportedBackend);
        }
        if facts.run_id() != &parsed.manifest.run_id
            || facts.execution_id() != &parsed.manifest.launch_identity
            || facts.starting_world() != &parsed.manifest.starting_generation
            || facts.final_world().as_deref() != Some(parsed.manifest.final_world.as_str())
            || facts.delta_root() != &parsed.manifest.delta_root
            || facts.runtime_identity() != &parsed.manifest.runtime_identity
            || facts.network_policy_identity() != &parsed.manifest.network_policy_identity
            || facts.final_world().is_none()
            || facts.evidence_root().is_none()
            || facts.sequence_end() != &Some(1)
            || facts.runtime_identity().is_empty()
            || facts.network_policy_identity().is_empty()
            || facts.completion_evidence().is_empty()
            || facts.finalization_evidence().is_empty()
            || facts.pause_snapshot_evidence().is_empty()
            || facts.delta_root().is_empty()
            || facts.evidence_root().as_deref() != Some(evidence_binding_root(facts).as_str())
        {
            return Err(MediationFailure::EvidenceBindingMismatch);
        }
        if facts.filesystem() != &CheckResult::Verified
            || facts.quiescence() != &CheckResult::Verified
            || facts.monitor_loss() != &CheckResult::Verified
            || facts.network() != &CheckResult::Verified
            || facts.frozen() != &CheckResult::Verified
            || *facts.crashed()
            || if contained_shutdown {
                facts.exit_code().is_some() || facts.vmm_terminal_observation_root().is_none()
            } else {
                facts.exit_code() != &Some(0)
            }
            || !facts.unsupported_effects().is_empty()
        {
            return Err(MediationFailure::MissingTrustedObservation);
        }
        if parsed.manifest.max_task_processes != 1 || !facts.descendants().is_empty() {
            return Err(MediationFailure::UnexpectedProcess);
        }
        Ok(CheckedMediationClaim {
            session_binding_root: parsed.root.clone(),
            root: parsed.root,
            broker_completion_root: None,
            broker_frontier_root: None,
            manifest: parsed.manifest,
        })
    }

    /// Promote a completion to a checked mediation claim only after matching
    /// it against the exact pre-run binding used to start broker service.
    pub fn issue_for_measured_session(
        manifest_bytes: &[u8],
        comparison_root: &str,
        observation: &CapsuleObservation,
        session: &MediationSessionBinding,
        completion: &MeasuredBrokerCompletion,
    ) -> Result<CheckedMediationClaim, MediationFailure> {
        let parsed = check_manifest_claim_shape(manifest_bytes, comparison_root)?;
        let manifest = &parsed.manifest;
        if manifest.run_id != session.run_id
            || manifest.launch_identity != session.execution_id
            || manifest.measured_launch_blake3 != session.measured_launch_root
            || manifest.broker_identity != session.broker_identity
            || manifest.broker_endpoint_identity != session.endpoint_identity
            || manifest.starting_generation != session.starting_generation
            || manifest.host_policy_blake3 != session.policy_root
            || completion.session_binding_root() != session.root()
            || completion.run_id() != session.run_id()
            || completion.execution_id() != session.execution_id()
        {
            return Err(MediationFailure::MeasuredSessionMismatch);
        }
        if completion.challenge_root() != session.challenge_root()
            || observation.facts().completion_evidence() != session.challenge_root()
        {
            return Err(MediationFailure::ChallengeMismatch);
        }
        let mut claim = Self::issue_c1_claim(manifest_bytes, comparison_root, observation)?;
        claim.session_binding_root = session.root.clone();
        claim.broker_completion_root = Some(completion.root().to_owned());
        claim.broker_frontier_root = Some(completion.frontier_root().to_owned());
        Ok(claim)
    }

    /// Join the sealed pre-run broker binding to the canonical post-exit
    /// capability, whose lineage contains that exact prepared measurement.
    #[cfg(target_os = "linux")]
    pub(crate) fn issue_for_production_session(
        bytes: &[u8],
        root: &str,
        observation: &CapsuleObservation,
        session: &MediationSessionBinding,
        completion: &MeasuredBrokerCompletion,
        production: &crate::measured_launch::ProductionContainedLaunch,
    ) -> Result<Self, MediationFailure> {
        let parsed = check_manifest_claim_shape(bytes, root)?;
        let m = &parsed.manifest;
        if !production.supports_measured_brokered_c0_profile()
            || !production.matches_manifest(m)
            || production.prepared_measurement_root() != session.measured_launch_root
            || production.bound_challenge() != Some(session.challenge_root())
            || m.run_id != session.run_id
            || m.launch_identity != session.execution_id
            || m.broker_identity != session.broker_identity
            || m.broker_endpoint_identity != session.endpoint_identity
            || m.starting_generation != session.starting_generation
            || m.host_policy_blake3 != session.policy_root
            || completion.session_binding_root() != session.root()
            || completion.run_id() != session.run_id()
            || completion.execution_id() != session.execution_id()
            || completion.challenge_root() != session.challenge_root()
            || observation.facts().completion_evidence() != session.challenge_root()
        {
            return Err(MediationFailure::MeasuredSessionMismatch);
        }
        let mut claim = Self::issue_observed_claim(bytes, root, observation, true)?;
        claim.session_binding_root = session.root().into();
        claim.broker_completion_root = Some(completion.root().into());
        claim.broker_frontier_root = Some(completion.frontier_root().into());
        Ok(claim)
    }

    pub fn manifest(&self) -> &MediationManifest {
        &self.manifest
    }
}

pub fn issue_c1_claim(
    manifest_bytes: &[u8],
    comparison_root: &str,
    observation: &CapsuleObservation,
) -> Result<CheckedMediationClaim, MediationFailure> {
    CheckedMediationClaim::issue_c1_claim(manifest_bytes, comparison_root, observation)
}

pub fn check_manifest_claim_shape(
    bytes: &[u8],
    comparison_root: &str,
) -> Result<ParsedMediationClaim, MediationFailure> {
    if bytes.len() > 65536 || !digest_shape(comparison_root) {
        return Err(MediationFailure::Malformed);
    }
    let root = blake3::hash(bytes).to_hex().to_string();
    if root != comparison_root {
        return Err(MediationFailure::Unanchored);
    }
    let m: MediationManifest =
        serde_json::from_slice(bytes).map_err(|_| MediationFailure::Malformed)?;
    if m.schema != 2
        || m.run_id.is_empty()
        || m.run_id.contains('/')
        || m.broker_identity.is_empty()
        || ![
            &m.vm_config_blake3,
            &m.guest_kernel_blake3,
            &m.rootfs_blake3,
            &m.task_blake3,
            &m.guest_policy_blake3,
            &m.seccomp_blake3,
            &m.measured_launch_blake3,
            &m.broker_endpoint_identity,
            &m.host_policy_blake3,
            &m.launch_identity,
            &m.starting_generation,
            &m.final_world,
            &m.delta_root,
            &m.runtime_identity,
            &m.network_policy_identity,
        ]
        .iter()
        .all(|s| digest_shape(s))
        || m.broker_endpoint != "vsock:host:7000"
        || m.measured_launch_hash_domain != crate::measured_launch::MEASURED_LAUNCH_HASH_DOMAIN
        || m.measured_launch_hash_version != crate::measured_launch::MEASURED_LAUNCH_HASH_VERSION
        || m.host_policy_identifier.is_empty()
        || m.host_policy_version.is_empty()
        || m.max_task_processes != 1
    {
        return Err(MediationFailure::Malformed);
    }
    // One read-only root image and one vsock endpoint. The authoritative
    // workspace backing objects and journal are not attached to the VM.
    if !m.network_devices.is_empty()
        || !m.shared_mounts.is_empty()
        || !m.inherited_fds.is_empty()
        || !m.writable_mappings.is_empty()
        || !m.other_storage_aliases.is_empty()
        || m.devices.len() != 2
        || m.devices[0].kind != "rootfs"
        || !m.devices[0].read_only
        || m.devices[0].identity != m.rootfs_blake3
        || m.devices[1].kind != "broker_vsock"
        || !m.devices[1].read_only
        || m.devices[1].identity != m.broker_endpoint
    {
        return Err(MediationFailure::AlternatePath);
    }
    Ok(ParsedMediationClaim { root, manifest: m })
}

#[cfg(test)]
mod claim_replay_tests {
    use super::*;
    use crate::capsule::{BackendKind, CapsuleFacts, CheckResult, evidence_binding_root};

    fn digest(byte: u8) -> String {
        std::iter::repeat_n(byte as char, 64).collect()
    }

    fn valid_fixture() -> (Vec<u8>, String, CapsuleObservation) {
        let run_id = "run-replay-fixture";
        let execution_id = digest(b'e');
        let starting = digest(b'a');
        let facts_without_evidence = CapsuleFacts {
            run_id: run_id.into(),
            execution_id: execution_id.clone(),
            backend: BackendKind::FirecrackerMeasured,
            workspace_identity: digest(b'w'),
            capsule_id: digest(b'p'),
            custody_process_identity: None,
            descendants: vec![],
            starting_world: starting.clone(),
            final_world: Some(digest(b'f')),
            observed_effects: vec![],
            exit_code: Some(0),
            crashed: false,
            quiescence: CheckResult::Verified,
            monitor_loss: CheckResult::Verified,
            network: CheckResult::Verified,
            filesystem: CheckResult::Verified,
            frozen: CheckResult::Verified,
            evidence_root: None,
            sequence_start: 0,
            sequence_end: Some(1),
            unsupported_effects: vec![],
            runtime_identity: digest(b'7'),
            network_policy_identity: digest(b'8'),
            completion_evidence: digest(b'c'),
            finalization_evidence: digest(b'l'),
            pause_snapshot_evidence: digest(b'a'),
            vmm_terminal_observation_root: None,
            delta_root: digest(b'd'),
        };
        let mut facts = facts_without_evidence;
        facts.evidence_root = Some(evidence_binding_root(&facts));
        let observation = crate::capsule::CapsuleObservation::test_host_observation(facts);
        let manifest = MediationManifest {
            schema: 2,
            run_id: run_id.into(),
            vm_config_blake3: digest(b'1'),
            guest_kernel_blake3: digest(b'2'),
            rootfs_blake3: digest(b'3'),
            task_blake3: digest(b'4'),
            guest_policy_blake3: digest(b'5'),
            seccomp_blake3: digest(b'6'),
            measured_launch_hash_domain: crate::measured_launch::MEASURED_LAUNCH_HASH_DOMAIN.into(),
            measured_launch_hash_version: crate::measured_launch::MEASURED_LAUNCH_HASH_VERSION,
            measured_launch_blake3: digest(b'a'),
            broker_endpoint_identity: digest(b'b'),
            host_policy_identifier: "fixture-policy".into(),
            host_policy_version: "1".into(),
            host_policy_blake3: digest(b'c'),
            launch_identity: execution_id,
            starting_generation: starting,
            final_world: digest(b'f'),
            delta_root: digest(b'd'),
            runtime_identity: digest(b'7'),
            network_policy_identity: digest(b'8'),
            broker_identity: "broker".into(),
            broker_endpoint: "vsock:host:7000".into(),
            devices: vec![
                AttachedDevice {
                    kind: "rootfs".into(),
                    identity: digest(b'3'),
                    read_only: true,
                },
                AttachedDevice {
                    kind: "broker_vsock".into(),
                    identity: "vsock:host:7000".into(),
                    read_only: true,
                },
            ],
            network_devices: vec![],
            shared_mounts: vec![],
            inherited_fds: vec![],
            writable_mappings: vec![],
            other_storage_aliases: vec![],
            max_task_processes: 1,
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let root = blake3::hash(&bytes).to_hex().to_string();
        (bytes, root, observation)
    }

    #[test]
    fn public_claim_issuer_does_not_accept_shutdown_only_facts() {
        let (bytes, root, observation) = valid_fixture();
        let mut facts = observation.facts().clone();
        facts.exit_code = None;
        facts.vmm_terminal_observation_root = Some(digest(b'a'));
        facts.evidence_root = Some(evidence_binding_root(&facts));
        let observation = CapsuleObservation::test_host_observation(facts);
        assert!(matches!(
            CheckedMediationClaim::issue_c1_claim(&bytes, &root, &observation),
            Err(MediationFailure::MissingTrustedObservation)
        ));
    }

    #[test]
    fn host_measured_claim_accepts_only_exact_binding() {
        let (bytes, root, observation) = valid_fixture();
        if let Err(error) = check_manifest_claim_shape(&bytes, &root) {
            panic!("valid manifest rejected: {error:?}");
        }
        let claim = issue_c1_claim(&bytes, &root, &observation)
            .expect("fixture should produce a non-authorizing checked claim");
        assert_eq!(
            crate::integration::admission_for_c1(&claim, &observation),
            crate::Admission::Refuse(crate::Refusal::UnverifiedBoundary)
        );
    }

    #[test]
    fn claim_replay_and_substitution_fail_closed() {
        let (bytes, root, observation) = valid_fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for field in [
            "run_id",
            "launch_identity",
            "starting_generation",
            "rootfs_blake3",
            "guest_policy_blake3",
            "final_world",
            "delta_root",
            "runtime_identity",
            "network_policy_identity",
        ] {
            let original = value[field].clone();
            value[field] = serde_json::Value::String(digest(b'x'));
            let substituted = serde_json::to_vec(&value).unwrap();
            let substituted_root = blake3::hash(&substituted).to_hex().to_string();
            assert!(
                issue_c1_claim(&substituted, &substituted_root, &observation).is_err(),
                "substitution unexpectedly authorized for {field}"
            );
            value[field] = original;
        }
        let stale_root = format!(
            "{}{}",
            if &root[..1] == "0" { "1" } else { "0" },
            &root[1..]
        );
        assert!(issue_c1_claim(&bytes, &stale_root, &observation).is_err());
    }

    #[test]
    fn stale_completion_capsule_and_duplicate_terminal_records_refuse() {
        let (bytes, root, observation) = valid_fixture();
        let mut facts = observation.facts().clone();
        facts.sequence_end = Some(2);
        let duplicate = crate::capsule::CapsuleObservation::test_host_observation(facts);
        assert_eq!(
            issue_c1_claim(&bytes, &root, &duplicate),
            Err(MediationFailure::EvidenceBindingMismatch)
        );

        let mut facts = observation.facts().clone();
        facts.completion_evidence = digest(b'f');
        let stale_completion = crate::capsule::CapsuleObservation::test_host_observation(facts);
        assert_eq!(
            issue_c1_claim(&bytes, &root, &stale_completion),
            Err(MediationFailure::EvidenceBindingMismatch)
        );

        let mut facts = observation.facts().clone();
        facts.capsule_id = digest(b'x');
        let wrong_capsule = crate::capsule::CapsuleObservation::test_host_observation(facts);
        assert_eq!(
            issue_c1_claim(&bytes, &root, &wrong_capsule),
            Err(MediationFailure::EvidenceBindingMismatch)
        );
    }
}

#[cfg(test)]
pub(crate) fn test_only_checked_claim(
    bytes: &[u8],
    comparison_root: &str,
) -> Result<CheckedMediationClaim, MediationFailure> {
    let parsed = check_manifest_claim_shape(bytes, comparison_root)?;
    Ok(CheckedMediationClaim {
        session_binding_root: parsed.root.clone(),
        root: parsed.root,
        broker_completion_root: None,
        broker_frontier_root: None,
        manifest: parsed.manifest,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIncarnation {
    pub launch: String,
    pub serial: u64,
    pub birth: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Capability {
    owner: ProcessIncarnation,
    live: bool,
}

/// IDs are opaque handles in the broker; numeric PID/FD values never identify
/// a process or workspace capability. Only the trusted launch monitor may
/// report spawn/exit. For slice C0, any child is a policy violation.
#[derive(Clone, Debug)]
pub struct CapabilityLedger {
    launch: String,
    processes: BTreeMap<ProcessIncarnation, Option<ProcessIncarnation>>,
    exited: BTreeSet<ProcessIncarnation>,
    capabilities: BTreeMap<u64, Capability>,
    next_capability: u64,
    in_flight: BTreeSet<String>,
    poisoned: bool,
}

impl CapabilityLedger {
    pub fn launch_identity(&self) -> &str {
        &self.launch
    }

    pub(crate) fn initial_process(&self) -> Option<&ProcessIncarnation> {
        self.processes
            .iter()
            .find_map(|(process, parent)| parent.is_none().then_some(process))
    }

    pub(crate) fn initial_capability(&self) -> Option<u64> {
        self.capabilities
            .get(&1)
            .filter(|capability| capability.live)
            .map(|_| 1)
    }

    pub fn new(launch: &str, root: ProcessIncarnation) -> Result<(Self, u64), MediationFailure> {
        if !digest_shape(launch) || root.launch != launch || root.serial == 0 || root.birth == 0 {
            return Err(MediationFailure::Malformed);
        }
        let mut processes = BTreeMap::new();
        processes.insert(root.clone(), None);
        let mut capabilities = BTreeMap::new();
        capabilities.insert(
            1,
            Capability {
                owner: root,
                live: true,
            },
        );
        Ok((
            Self {
                launch: launch.into(),
                processes,
                exited: BTreeSet::new(),
                capabilities,
                next_capability: 2,
                in_flight: BTreeSet::new(),
                poisoned: false,
            },
            1,
        ))
    }
    pub fn authorize(
        &mut self,
        who: &ProcessIncarnation,
        cap: u64,
    ) -> Result<(), MediationFailure> {
        if self.poisoned
            || who.launch != self.launch
            || self.exited.contains(who)
            || !self.processes.contains_key(who)
            || !self
                .capabilities
                .get(&cap)
                .is_some_and(|c| c.live && &c.owner == who)
        {
            self.poisoned = true;
            return Err(MediationFailure::UnknownCapability);
        }
        Ok(())
    }
    pub fn duplicate(
        &mut self,
        who: &ProcessIncarnation,
        cap: u64,
    ) -> Result<u64, MediationFailure> {
        self.authorize(who, cap)?;
        let id = self.next_capability;
        self.next_capability += 1;
        self.capabilities.insert(
            id,
            Capability {
                owner: who.clone(),
                live: true,
            },
        );
        Ok(id)
    }
    pub fn spawn(
        &mut self,
        parent: &ProcessIncarnation,
        child: ProcessIncarnation,
        inherited_caps: &[u64],
    ) -> Result<(), MediationFailure> {
        if self.poisoned
            || !self.processes.contains_key(parent)
            || self.exited.contains(parent)
            || child.launch != self.launch
            || self.processes.contains_key(&child)
        {
            self.poisoned = true;
            return Err(MediationFailure::UnexpectedProcess);
        }
        // Locked C0 policy allows exactly one task process. Any child or
        // inherited broker capability refuses, even if the child exits.
        self.poisoned = true;
        let _ = inherited_caps;
        Err(MediationFailure::UnexpectedProcess)
    }
    pub fn begin(
        &mut self,
        who: &ProcessIncarnation,
        cap: u64,
        op: &str,
    ) -> Result<(), MediationFailure> {
        self.authorize(who, cap)?;
        if op.is_empty() || !self.in_flight.insert(op.into()) {
            self.poisoned = true;
            return Err(MediationFailure::DuplicateIdentity);
        }
        Ok(())
    }
    pub fn end(&mut self, op: &str) -> Result<(), MediationFailure> {
        if !self.in_flight.remove(op) {
            self.poisoned = true;
            return Err(MediationFailure::RequestInFlight);
        }
        Ok(())
    }
    pub fn close(&mut self, who: &ProcessIncarnation, cap: u64) -> Result<(), MediationFailure> {
        self.authorize(who, cap)?;
        self.capabilities.get_mut(&cap).unwrap().live = false;
        Ok(())
    }
    pub fn exit(&mut self, who: &ProcessIncarnation) -> Result<(), MediationFailure> {
        if !self.processes.contains_key(who) || !self.exited.insert(who.clone()) {
            self.poisoned = true;
            return Err(MediationFailure::UnexpectedProcess);
        }
        Ok(())
    }
    pub fn terminal(&self) -> Result<(), MediationFailure> {
        if self.poisoned || self.exited.len() != self.processes.len() {
            return Err(MediationFailure::UnexpectedProcess);
        }
        if !self.in_flight.is_empty() {
            return Err(MediationFailure::RequestInFlight);
        }
        if self.capabilities.values().any(|c| c.live) {
            return Err(MediationFailure::CapabilitySurvives);
        }
        Ok(())
    }

    /// Check that task effect authority has been revoked and no request is in
    /// flight. This is intentionally weaker than `terminal`: process closure
    /// remains a separate host observation supplied to the terminal join.
    #[cfg(target_os = "linux")]
    pub(crate) fn effect_authority_closed(&self) -> Result<(), MediationFailure> {
        if self.poisoned {
            return Err(MediationFailure::UnexpectedProcess);
        }
        if !self.in_flight.is_empty() {
            return Err(MediationFailure::RequestInFlight);
        }
        if self.capabilities.is_empty() || self.capabilities.values().any(|cap| cap.live) {
            return Err(MediationFailure::CapabilitySurvives);
        }
        Ok(())
    }
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn refuse(&mut self) {
        self.poisoned = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::{CapsuleFacts, CapsuleObservation, evidence_binding_root};
    fn manifest() -> MediationManifest {
        MediationManifest {
            schema: 2,
            run_id: "r".into(),
            vm_config_blake3: "a".repeat(64),
            guest_kernel_blake3: "b".repeat(64),
            rootfs_blake3: "c".repeat(64),
            task_blake3: "d".repeat(64),
            guest_policy_blake3: "e".repeat(64),
            seccomp_blake3: "f".repeat(64),
            measured_launch_hash_domain: crate::measured_launch::MEASURED_LAUNCH_HASH_DOMAIN.into(),
            measured_launch_hash_version: crate::measured_launch::MEASURED_LAUNCH_HASH_VERSION,
            measured_launch_blake3: "9".repeat(64),
            broker_endpoint_identity: "8".repeat(64),
            host_policy_identifier: "fixture-policy".into(),
            host_policy_version: "1".into(),
            host_policy_blake3: "7".repeat(64),
            launch_identity: "1".repeat(64),
            starting_generation: "2".repeat(64),
            final_world: "d".repeat(64),
            delta_root: "4".repeat(64),
            runtime_identity: "7".repeat(64),
            network_policy_identity: "8".repeat(64),
            broker_identity: "host-broker".into(),
            broker_endpoint: "vsock:host:7000".into(),
            devices: vec![
                AttachedDevice {
                    kind: "rootfs".into(),
                    identity: "c".repeat(64),
                    read_only: true,
                },
                AttachedDevice {
                    kind: "broker_vsock".into(),
                    identity: "vsock:host:7000".into(),
                    read_only: true,
                },
            ],
            network_devices: vec![],
            shared_mounts: vec![],
            inherited_fds: vec![],
            writable_mappings: vec![],
            other_storage_aliases: vec![],
            max_task_processes: 1,
        }
    }
    fn check(m: &MediationManifest) -> Result<ParsedMediationClaim, MediationFailure> {
        let b = serde_json::to_vec(m).unwrap();
        let root = blake3::hash(&b).to_hex().to_string();
        check_manifest_claim_shape(&b, &root)
    }

    fn c1_observation(run_id: &str) -> CapsuleObservation {
        let mut facts = CapsuleFacts {
            run_id: run_id.into(),
            execution_id: "1".repeat(64),
            backend: BackendKind::FirecrackerMeasured,
            workspace_identity: "a".repeat(64),
            capsule_id: "b".repeat(64),
            custody_process_identity: None,
            descendants: vec![],
            starting_world: "2".repeat(64),
            final_world: Some("d".repeat(64)),
            observed_effects: vec!["write:target".into()],
            exit_code: Some(0),
            crashed: false,
            quiescence: CheckResult::Verified,
            monitor_loss: CheckResult::Verified,
            network: CheckResult::Verified,
            filesystem: CheckResult::Verified,
            frozen: CheckResult::Verified,
            evidence_root: None,
            sequence_start: 0,
            sequence_end: Some(1),
            unsupported_effects: vec![],
            runtime_identity: "7".repeat(64),
            network_policy_identity: "8".repeat(64),
            completion_evidence: "completion".repeat(64),
            finalization_evidence: "finalization".repeat(64),
            pause_snapshot_evidence: "pause".repeat(64),
            vmm_terminal_observation_root: None,
            delta_root: "4".repeat(64),
        };
        facts.evidence_root = Some(evidence_binding_root(&facts));
        CapsuleObservation::from_host_facts(facts, "host-measurement".into()).unwrap()
    }

    #[test]
    fn c1_issuer_requires_host_facts_and_exact_run_binding() {
        let m = manifest();
        let bytes = serde_json::to_vec(&m).unwrap();
        let root = blake3::hash(&bytes).to_hex().to_string();
        let observation = c1_observation("r");
        assert!(issue_c1_claim(&bytes, &root, &observation).is_ok());
        let wrong = c1_observation("other");
        assert_eq!(
            issue_c1_claim(&bytes, &root, &wrong),
            Err(MediationFailure::EvidenceBindingMismatch)
        );
    }

    #[test]
    fn c1_issuer_rejects_diagnostic_backend_and_unfrozen_runs() {
        let m = manifest();
        let bytes = serde_json::to_vec(&m).unwrap();
        let root = blake3::hash(&bytes).to_hex().to_string();
        let mut facts = c1_observation("r").facts().clone();
        facts.backend = BackendKind::DiagnosticOnly;
        let diagnostic = CapsuleObservation::from_host_facts(facts, "diagnostic".into()).unwrap();
        assert_eq!(
            issue_c1_claim(&bytes, &root, &diagnostic),
            Err(MediationFailure::UnsupportedBackend)
        );
        let mut facts = c1_observation("r").facts().clone();
        facts.frozen = CheckResult::Unavailable;
        let unfrozen = CapsuleObservation::from_host_facts(facts, "host".into()).unwrap();
        assert_eq!(
            issue_c1_claim(&bytes, &root, &unfrozen),
            Err(MediationFailure::MissingTrustedObservation)
        );
    }
    #[test]
    fn topology_mutants_refuse() {
        let m = manifest();
        assert!(check(&m).is_ok());
        let mut x = m.clone();
        x.devices.push(AttachedDevice {
            kind: "workspace_disk".into(),
            identity: "raw".into(),
            read_only: false,
        });
        assert_eq!(check(&x), Err(MediationFailure::AlternatePath));
        let mut x = m.clone();
        x.shared_mounts.push("/workspace".into());
        assert_eq!(check(&x), Err(MediationFailure::AlternatePath));
        let mut x = m.clone();
        x.inherited_fds.push("fd:4".into());
        assert_eq!(check(&x), Err(MediationFailure::AlternatePath));
        let mut x = m.clone();
        x.other_storage_aliases.push("unknown-device".into());
        assert_eq!(check(&x), Err(MediationFailure::AlternatePath));
        let mut x = m.clone();
        x.writable_mappings.push("workspace".into());
        assert_eq!(check(&x), Err(MediationFailure::AlternatePath));
        let mut x = m.clone();
        x.guest_policy_blake3.clear();
        assert_eq!(check(&x), Err(MediationFailure::Malformed));
        let b = serde_json::to_vec(&m).unwrap();
        let original_root = blake3::hash(&b).to_hex().to_string();
        let mut x = m.clone();
        x.guest_policy_blake3 = "9".repeat(64);
        assert_eq!(
            check_manifest_claim_shape(&serde_json::to_vec(&x).unwrap(), &original_root),
            Err(MediationFailure::Unanchored)
        );
        let mut x = m.clone();
        x.other_storage_aliases.push("unmeasured-alias".into());
        assert_eq!(check(&x), Err(MediationFailure::AlternatePath));
        let mut x = m.clone();
        x.broker_endpoint = "vsock:host:7001".into();
        assert_eq!(check(&x), Err(MediationFailure::Malformed));
        let mut x = m.clone();
        x.max_task_processes = 2;
        assert_eq!(check(&x), Err(MediationFailure::Malformed));
        assert_eq!(
            check_manifest_claim_shape(&b, &"0".repeat(64)),
            Err(MediationFailure::Unanchored)
        );
    }
    #[test]
    fn capability_lifetime_and_child() {
        let launch = "1".repeat(64);
        let root = ProcessIncarnation {
            launch: launch.clone(),
            serial: 1,
            birth: 1,
        };
        let (mut l, c) = CapabilityLedger::new(&launch, root.clone()).unwrap();
        let dup = l.duplicate(&root, c).unwrap();
        l.begin(&root, c, "op").unwrap();
        assert_eq!(l.terminal(), Err(MediationFailure::UnexpectedProcess));
        l.end("op").unwrap();
        l.close(&root, c).unwrap();
        l.exit(&root).unwrap();
        assert_eq!(l.terminal(), Err(MediationFailure::CapabilitySurvives));
        // A live cap after exit cannot be silently discarded.
        assert_eq!(
            l.close(&root, dup),
            Err(MediationFailure::UnknownCapability)
        );
        let (mut l, c) = CapabilityLedger::new(&launch, root.clone()).unwrap();
        l.close(&root, c).unwrap();
        l.exit(&root).unwrap();
        assert!(l.terminal().is_ok());
        let (mut l, c) = CapabilityLedger::new(&launch, root.clone()).unwrap();
        let child = ProcessIncarnation {
            launch: launch.clone(),
            serial: 2,
            birth: 2,
        };
        assert_eq!(
            l.spawn(&root, child, &[c]),
            Err(MediationFailure::UnexpectedProcess)
        );
        assert!(l.poisoned());
    }
}
