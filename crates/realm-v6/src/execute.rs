//! Public task-execution boundary.
//!
//! This boundary can run the narrow Firecracker diagnostic path, but its
//! observation and measured launch are not terminal authority. Until the host
//! can prove consumed input identity, complete effect/custody closure, and an
//! immutable freeze joined to semantic evidence, execution results REFUSE.

#[cfg(target_os = "linux")]
use crate::profile::SyncTrace as _;
use crate::{Admission, integration::CheckedSameRunEvidence};
#[cfg(target_os = "linux")]
use crate::{
    measured_launch::{FileIdentity, MeasuredLaunchSession, PolicyIdentity},
    mediation::{AttachedDevice, MediationManifest},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteRequest {
    pub run_id: String,
    pub root: PathBuf,
    pub command: Vec<String>,
    pub timeout_ms: u64,
    pub allowed_effects: Vec<String>,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    #[serde(default)]
    pub rootfs: Option<PathBuf>,
    pub workspace_device: Option<PathBuf>,
    #[serde(default)]
    pub guest_supervisor: Option<PathBuf>,
    #[serde(default)]
    pub firecracker: Option<PathBuf>,
    #[serde(default)]
    pub kernel: Option<PathBuf>,
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
}

/// Untrusted path bundle supplied at the request boundary. It becomes
/// `PreparedExecutionInputs` only after host validation and resource pinning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct C1BackendInputPaths {
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub workspace_device: PathBuf,
    pub guest_supervisor: PathBuf,
    pub state_dir: PathBuf,
    #[serde(default)]
    pub production_jailer: Option<ProductionJailerConfig>,
}

/// Explicit production jailer configuration. The supervisor derives each
/// jail ID from a fresh execution identity so callers cannot request reuse.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionJailerConfig {
    pub jailer: PathBuf,
    pub uid: u32,
    pub gid: u32,
    pub chroot_base_dir: PathBuf,
    pub cgroup_parent: PathBuf,
    pub memory_max_bytes: u64,
    pub pids_max: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteResult {
    pub schema_version: u16,
    pub run_id: String,
    pub execution_id: String,
    #[serde(default)]
    pub guest_exit_code: Option<i32>,
    #[serde(default)]
    pub guest_crashed: Option<bool>,
    #[serde(default)]
    pub vmm_pid: Option<u32>,
    #[serde(default)]
    pub vmm_start_time_ticks: Option<u64>,
    pub starting_world_commitment: String,
    pub final_world_commitment: Option<String>,
    pub delta_root: Option<String>,
    pub starting_workspace_image: Option<PathBuf>,
    pub final_workspace_image: Option<PathBuf>,
    pub observed_effects: Vec<String>,
    pub proposed_effects: Vec<String>,
    pub evidence_root: Option<String>,
    pub receipt_path: Option<PathBuf>,
    pub verifier_decision: Admission,
    pub reason_code: String,
    pub task_success: bool,
    pub unsupported_effects: Vec<String>,
    pub runtime_ms: u128,
    pub overhead_ms: u128,
}

/// Output of a host execution. A publication capability is distinct from
/// both this report and the durable publication result.
pub struct ExecuteOutcome {
    pub result: ExecuteResult,
    pub publication_capability: Option<CheckedExecutionForPublication>,
}

/// Content-bound execution inputs and C1 outputs exposed for evidence adapters.
/// This is serializable evidence, not an acceptance or publication capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckedC1Evidence {
    pub schema_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_contract: Option<crate::c0_contract::C0FileContract>,
    pub verifier_decision: String,
    pub run_id: String,
    pub execution_id: String,
    pub capsule_id: String,
    #[serde(default)]
    pub custody_process_identity: Option<String>,
    pub challenge_binding: String,
    pub checked_claim_root: String,
    pub accepted_decision_identity: String,
    pub same_run_join_root: String,
    pub accepted_start_root: String,
    pub accepted_final_root: String,
    pub accepted_delta_root: String,
    pub evidence_root: String,
    #[serde(default)]
    pub vmm_terminal_observation_root: Option<String>,
    pub finalization_evidence: String,
    pub pause_snapshot_evidence: String,
    pub c1_manifest_root: String,
    pub c1_manifest: Vec<u8>,
    pub command: Vec<String>,
    pub allowed_effects: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub observed_effects: Vec<String>,
    pub unsupported_effects: Vec<String>,
    pub timeout_ms: u64,
    pub intent_identity: String,
    pub effect_contract_identity: String,
}

/// In-process capability carrying the identities needed by publication.
/// Its fields are private to this crate and it has no serde implementation.
/// The public `ExecuteResult` remains a report, not a publication authority.
/// ```compile_fail
/// use realm_v6::execute::CheckedExecutionForPublication;
/// let _forged = CheckedExecutionForPublication {
///     result: todo!(), capsule_id: String::new(), challenge_binding: String::new(),
///     decision_identity: String::new(), accepted_start_root: String::new(),
///     accepted_final_root: String::new(), accepted_delta_root: String::new(),
/// };
/// ```
pub struct CheckedExecutionForPublication {
    schema_version: u16,
    file_contract: Option<crate::c0_contract::C0FileContract>,
    result: ExecuteResult,
    capsule_id: String,
    custody_process_identity: Option<String>,
    challenge_binding: String,
    decision_identity: String,
    checked_claim_root: String,
    c1_manifest_root: String,
    c1_manifest: Vec<u8>,
    evidence_root: String,
    vmm_terminal_observation_root: String,
    finalization_evidence: String,
    pause_snapshot_evidence: String,
    command: Vec<String>,
    allowed_effects: Vec<String>,
    allowed_paths: Vec<String>,
    timeout_ms: u64,
    intent_identity: String,
    effect_contract_identity: String,
    accepted_start_root: String,
    accepted_final_root: String,
    accepted_delta_root: String,
    same_run_join_root: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationCapabilityRefusal {
    InvalidEvidence,
    ResultMismatch,
    SameRunJoinMismatch,
}

impl CheckedExecutionForPublication {
    /// The only production issuer for the publication capability. Serialized
    /// C1 evidence is insufficient: it must be joined with the process-local
    /// same-run token minted from host observation, measured launch, semantic
    /// frontier, and terminal closure evidence.
    pub fn issue_for_publication(
        result: ExecuteResult,
        evidence: CheckedC1Evidence,
        same_run: CheckedSameRunEvidence,
    ) -> Result<Self, PublicationCapabilityRefusal> {
        if !matches!(evidence.schema_version, 5..=8) || !validate_checked_c1_evidence(&evidence) {
            return Err(PublicationCapabilityRefusal::InvalidEvidence);
        }
        if !same_run.matches_c1_evidence(&evidence) {
            return Err(PublicationCapabilityRefusal::SameRunJoinMismatch);
        }
        if result.run_id != evidence.run_id
            || result.execution_id != evidence.execution_id
            || result.starting_world_commitment != evidence.accepted_start_root
            || result.final_world_commitment.as_deref()
                != Some(evidence.accepted_final_root.as_str())
            || result.delta_root.as_deref() != Some(evidence.accepted_delta_root.as_str())
            || result.evidence_root.as_deref() != Some(evidence.evidence_root.as_str())
            || result.observed_effects != evidence.observed_effects
            || result.unsupported_effects != evidence.unsupported_effects
        {
            return Err(PublicationCapabilityRefusal::ResultMismatch);
        }
        Ok(Self {
            schema_version: evidence.schema_version,
            file_contract: evidence.file_contract,
            result,
            capsule_id: evidence.capsule_id,
            custody_process_identity: evidence.custody_process_identity,
            challenge_binding: evidence.challenge_binding,
            decision_identity: evidence.accepted_decision_identity,
            checked_claim_root: evidence.checked_claim_root,
            c1_manifest_root: evidence.c1_manifest_root,
            c1_manifest: evidence.c1_manifest,
            evidence_root: evidence.evidence_root,
            vmm_terminal_observation_root: evidence
                .vmm_terminal_observation_root
                .expect("schema 3 evidence requires VMM terminal observation root"),
            finalization_evidence: evidence.finalization_evidence,
            pause_snapshot_evidence: evidence.pause_snapshot_evidence,
            command: evidence.command,
            allowed_effects: evidence.allowed_effects,
            allowed_paths: evidence.allowed_paths,
            timeout_ms: evidence.timeout_ms,
            intent_identity: evidence.intent_identity,
            effect_contract_identity: evidence.effect_contract_identity,
            accepted_start_root: evidence.accepted_start_root,
            accepted_final_root: evidence.accepted_final_root,
            accepted_delta_root: evidence.accepted_delta_root,
            same_run_join_root: evidence.same_run_join_root,
        })
    }

    pub fn result(&self) -> &ExecuteResult {
        &self.result
    }

    pub(crate) fn capsule_id(&self) -> &str {
        &self.capsule_id
    }

    pub(crate) fn challenge_binding(&self) -> &str {
        &self.challenge_binding
    }

    pub(crate) fn decision_identity(&self) -> &str {
        &self.decision_identity
    }

    pub(crate) fn accepted_start_root(&self) -> &str {
        &self.accepted_start_root
    }

    pub(crate) fn accepted_final_root(&self) -> &str {
        &self.accepted_final_root
    }

    pub(crate) fn accepted_delta_root(&self) -> &str {
        &self.accepted_delta_root
    }

    /// Returns immutable, content-bound C1 facts for artifact and review
    /// tooling. The returned value cannot authorize execution or publication.
    pub fn checked_c1_evidence(&self) -> CheckedC1Evidence {
        CheckedC1Evidence {
            schema_version: self.schema_version,
            file_contract: self.file_contract.clone(),
            verifier_decision: "CHECKED_FOR_PUBLICATION".into(),
            run_id: self.result.run_id.clone(),
            execution_id: self.result.execution_id.clone(),
            capsule_id: self.capsule_id.clone(),
            custody_process_identity: self.custody_process_identity.clone(),
            challenge_binding: self.challenge_binding.clone(),
            checked_claim_root: self.checked_claim_root.clone(),
            accepted_decision_identity: self.decision_identity.clone(),
            same_run_join_root: self.same_run_join_root.clone(),
            accepted_start_root: self.accepted_start_root.clone(),
            accepted_final_root: self.accepted_final_root.clone(),
            accepted_delta_root: self.accepted_delta_root.clone(),
            evidence_root: self.evidence_root.clone(),
            vmm_terminal_observation_root: Some(self.vmm_terminal_observation_root.clone()),
            finalization_evidence: self.finalization_evidence.clone(),
            pause_snapshot_evidence: self.pause_snapshot_evidence.clone(),
            c1_manifest_root: self.c1_manifest_root.clone(),
            c1_manifest: self.c1_manifest.clone(),
            command: self.command.clone(),
            allowed_effects: self.allowed_effects.clone(),
            allowed_paths: self.allowed_paths.clone(),
            observed_effects: self.result.observed_effects.clone(),
            unsupported_effects: self.result.unsupported_effects.clone(),
            timeout_ms: self.timeout_ms,
            intent_identity: self.intent_identity.clone(),
            effect_contract_identity: self.effect_contract_identity.clone(),
        }
    }

    pub(crate) fn validate_bindings(&self) -> bool {
        let evidence = self.checked_c1_evidence();
        self.result.run_id == evidence.run_id
            && self.result.execution_id == evidence.execution_id
            && self.result.starting_world_commitment == evidence.accepted_start_root
            && self.result.final_world_commitment.as_deref()
                == Some(evidence.accepted_final_root.as_str())
            && self.result.delta_root.as_deref() == Some(evidence.accepted_delta_root.as_str())
            && self.result.evidence_root.as_deref() == Some(evidence.evidence_root.as_str())
            && self.result.observed_effects == evidence.observed_effects
            && self.result.unsupported_effects == evidence.unsupported_effects
            && validate_checked_c1_evidence(&evidence)
    }

    /// Rechecks the immutable evidence carried by this already-issued
    /// capability. This does not construct or promote a capability from a
    /// serialized report.
    pub fn validate_for_evidence(&self) -> bool {
        self.validate_bindings()
    }
}

/// Validate content and identity relationships in a serialized C1 evidence
/// snapshot. A successful check validates the recorded relationships only;
/// it cannot recreate the private host observation marker or ACCEPT
/// capability.
pub fn validate_checked_c1_evidence(evidence: &CheckedC1Evidence) -> bool {
    if !matches!(evidence.schema_version, 2..=8)
        || evidence.verifier_decision != "CHECKED_FOR_PUBLICATION"
        || evidence.run_id.is_empty()
        || evidence.execution_id.is_empty()
        || !is_digest_string(&evidence.capsule_id)
        || (matches!(evidence.schema_version, 5..=8)
            && !evidence
                .custody_process_identity
                .as_deref()
                .is_some_and(is_digest_string))
        || (evidence.schema_version <= 4 && evidence.custody_process_identity.is_some())
        || !is_digest_string(&evidence.challenge_binding)
        || !is_digest_string(&evidence.checked_claim_root)
        || !is_digest_string(&evidence.accepted_decision_identity)
        || !is_digest_string(&evidence.same_run_join_root)
        || !is_digest_string(&evidence.accepted_start_root)
        || !is_digest_string(&evidence.accepted_final_root)
        || !is_digest_string(&evidence.accepted_delta_root)
        || !is_digest_string(&evidence.evidence_root)
        || (matches!(evidence.schema_version, 3..=8)
            && !evidence
                .vmm_terminal_observation_root
                .as_deref()
                .is_some_and(is_digest_string))
        || (evidence.schema_version == 2 && evidence.vmm_terminal_observation_root.is_some())
        || !is_digest_string(&evidence.finalization_evidence)
        || !is_digest_string(&evidence.pause_snapshot_evidence)
        || !is_digest_string(&evidence.c1_manifest_root)
        || !is_digest_string(&evidence.intent_identity)
        || !is_digest_string(&evidence.effect_contract_identity)
        || evidence.command.is_empty()
        || evidence.timeout_ms == 0
        || !evidence.unsupported_effects.is_empty()
        || evidence
            .observed_effects
            .iter()
            .any(|path| !evidence.allowed_paths.contains(path))
    {
        return false;
    }

    if matches!(evidence.schema_version, 6 | 8) {
        let Some(contract) = &evidence.file_contract else {
            return false;
        };
        if contract.validate().is_err()
            || evidence.command != ["c0"]
            || evidence.allowed_effects != ["filesystem"]
            || evidence.allowed_paths != [contract.output_path.clone()]
            || contract.commitments().ok()
                != Some((
                    evidence.accepted_start_root.clone(),
                    evidence.accepted_final_root.clone(),
                    evidence.accepted_delta_root.clone(),
                ))
        {
            return false;
        }
    } else if evidence.file_contract.is_some() {
        return false;
    }
    let mut normalized_effects = evidence.allowed_effects.clone();
    normalized_effects.sort();
    normalized_effects.dedup();
    let mut normalized_paths = evidence.allowed_paths.clone();
    normalized_paths.sort();
    normalized_paths.dedup();
    if normalized_effects != evidence.allowed_effects
        || normalized_paths != evidence.allowed_paths
        || evidence.allowed_paths.iter().any(|path| {
            path.is_empty()
                || path.starts_with('/')
                || path.contains('\\')
                || path
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
        })
    {
        return false;
    }

    let Ok(parsed) = crate::mediation::check_manifest_claim_shape(
        &evidence.c1_manifest,
        &evidence.c1_manifest_root,
    ) else {
        return false;
    };
    let manifest = parsed.manifest;
    if manifest.run_id != evidence.run_id
        || manifest.launch_identity != evidence.execution_id
        || manifest.starting_generation != evidence.accepted_start_root
        || manifest.final_world != evidence.accepted_final_root
        || manifest.delta_root != evidence.accepted_delta_root
        || evidence.checked_claim_root != evidence.c1_manifest_root
    {
        return false;
    }

    let Ok(intent_bytes) = serde_json::to_vec(&evidence.command) else {
        return false;
    };
    let Ok(effect_contract_bytes) = checked_effect_contract_bytes(evidence) else {
        return false;
    };
    if digest_bytes(&evidence.c1_manifest) != evidence.c1_manifest_root
        || (if matches!(evidence.schema_version, 4..=8) {
            crate::measured_launch::PolicyIdentity::new(
                "realm-c1-workspace-policy".into(),
                "2".into(),
                b"",
                &intent_bytes,
            )
            .task_blake3()
            .to_owned()
        } else {
            digest_bytes(&intent_bytes)
        }) != manifest.task_blake3
        || domain_digest("realm.intent", &intent_bytes) != evidence.intent_identity
        || domain_digest("realm.policy", &effect_contract_bytes)
            != evidence.effect_contract_identity
    {
        return false;
    }
    if matches!(evidence.schema_version, 4..=8) {
        if manifest.host_policy_identifier != "realm-c1-workspace-policy"
            || manifest.host_policy_version
                != if matches!(evidence.schema_version, 6 | 8) {
                    "3"
                } else {
                    "2"
                }
        {
            return false;
        }
        let Ok(policy_bytes) = effective_policy_bytes(
            &evidence.command,
            &evidence.allowed_effects,
            &evidence.allowed_paths,
            evidence.timeout_ms,
        ) else {
            return false;
        };
        let policy_bytes = match evidence.file_contract.as_ref() {
            Some(contract) => match contract_policy_bytes(&policy_bytes, contract) {
                Ok(bytes) => bytes,
                Err(_) => return false,
            },
            None => policy_bytes,
        };
        let policy = crate::measured_launch::PolicyIdentity::new(
            "realm-c1-workspace-policy".into(),
            if matches!(evidence.schema_version, 6 | 8) {
                "3"
            } else {
                "2"
            }
            .into(),
            &policy_bytes,
            &intent_bytes,
        );
        if policy.blake3() != manifest.host_policy_blake3 {
            return false;
        }
    }

    let facts = capsule_facts_for_checked_evidence(
        evidence,
        &manifest,
        evidence.custody_process_identity.clone(),
    );
    let expected_evidence_root = match evidence.schema_version {
        2 => crate::capsule::legacy_evidence_binding_root(&facts),
        3 | 4 => crate::capsule::evidence_binding_root_v2(&facts),
        5..=8 => crate::capsule::evidence_binding_root(&facts),
        _ => return false,
    };
    expected_evidence_root == evidence.evidence_root
        && evidence.accepted_decision_identity
            == accepted_decision_identity(
                evidence.schema_version,
                &evidence.checked_claim_root,
                &evidence.c1_manifest_root,
                &evidence.run_id,
                &evidence.execution_id,
                &evidence.capsule_id,
                &evidence.challenge_binding,
                &evidence.evidence_root,
                &evidence.same_run_join_root,
                &evidence.intent_identity,
                &evidence.effect_contract_identity,
                &evidence.accepted_start_root,
                &evidence.accepted_final_root,
                &evidence.accepted_delta_root,
            )
}

fn capsule_facts_for_checked_evidence(
    evidence: &CheckedC1Evidence,
    manifest: &crate::mediation::MediationManifest,
    custody_process_identity: Option<String>,
) -> crate::capsule::CapsuleFacts {
    crate::capsule::CapsuleFacts {
        run_id: evidence.run_id.clone(),
        execution_id: evidence.execution_id.clone(),
        backend: crate::capsule::BackendKind::FirecrackerMeasured,
        workspace_identity: manifest.starting_generation.clone(),
        capsule_id: evidence.capsule_id.clone(),
        custody_process_identity,
        descendants: Vec::new(),
        starting_world: manifest.starting_generation.clone(),
        final_world: Some(manifest.final_world.clone()),
        observed_effects: evidence.observed_effects.clone(),
        exit_code: (evidence.schema_version <= 6).then_some(0),
        crashed: false,
        quiescence: crate::capsule::CheckResult::Verified,
        monitor_loss: crate::capsule::CheckResult::Verified,
        network: crate::capsule::CheckResult::Verified,
        filesystem: crate::capsule::CheckResult::Verified,
        frozen: crate::capsule::CheckResult::Verified,
        evidence_root: Some(evidence.evidence_root.clone()),
        sequence_start: 0,
        sequence_end: Some(1),
        unsupported_effects: evidence.unsupported_effects.clone(),
        runtime_identity: manifest.runtime_identity.clone(),
        network_policy_identity: manifest.network_policy_identity.clone(),
        completion_evidence: evidence.challenge_binding.clone(),
        finalization_evidence: evidence.finalization_evidence.clone(),
        pause_snapshot_evidence: evidence.pause_snapshot_evidence.clone(),
        vmm_terminal_observation_root: evidence.vmm_terminal_observation_root.clone(),
        delta_root: manifest.delta_root.clone(),
    }
}

fn is_digest_string(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug)]
pub enum ExecuteError {
    Invalid(String),
    Io(io::Error),
    Supervisor(String),
}

impl std::fmt::Display for ExecuteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "{reason}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::Supervisor(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ExecuteError {}

impl From<io::Error> for ExecuteError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn fresh_execution_id() -> Result<String, ExecuteError> {
    let mut nonce = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    Ok(blake3::hash(&nonce).to_hex().to_string())
}

fn digest_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn domain_digest(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

pub fn checked_effect_contract_bytes(
    evidence: &CheckedC1Evidence,
) -> Result<Vec<u8>, serde_json::Error> {
    match &evidence.file_contract {
        Some(contract) => serde_json::to_vec(&(
            &evidence.allowed_effects,
            &evidence.allowed_paths,
            evidence.timeout_ms,
            contract,
        )),
        None => serde_json::to_vec(&(
            &evidence.allowed_effects,
            &evidence.allowed_paths,
            evidence.timeout_ms,
        )),
    }
}
fn contract_policy_bytes(
    base: &[u8],
    contract: &crate::c0_contract::C0FileContract,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut policy: serde_json::Value = serde_json::from_slice(base)?;
    policy["policy_version"] = 3.into();
    policy["c0_file_contract"] = serde_json::to_value(contract)?;
    serde_json::to_vec(&policy)
}

fn effective_policy_bytes(
    command: &[String],
    allowed_effects: &[String],
    allowed_paths: &[String],
    timeout_ms: u64,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::json!({
        "policy_id": "realm-c1-workspace-policy",
        "policy_version": 2,
        "allowed_effects": allowed_effects,
        "allowed_paths": allowed_paths,
        "argv": command,
        "cwd": ".",
        "timeout_ms": timeout_ms
    }))
}

#[cfg(target_os = "linux")]
pub(crate) struct PreparedWorkspaceImages {
    pub(crate) starting: PathBuf,
    pub(crate) working: PathBuf,
    pub(crate) execution_state: PathBuf,
}

/// Make the VMM's writable workspace a private per-execution copy. The
/// caller-supplied image remains an input and is never attached writable.
/// Both copies must match one stable source identity before execution starts.
#[cfg(target_os = "linux")]
pub(crate) fn prepare_workspace_images(
    source: &Path,
    state_dir: &Path,
    run_id: &str,
    execution_id: &str,
) -> Result<PreparedWorkspaceImages, ExecuteError> {
    let _profile = crate::profile::Span::new("mutable_state_materialization");
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fs::create_dir_all(state_dir)?;
    let state_root = state_dir
        .canonicalize()
        .map_err(|_| ExecuteError::Invalid("state directory is unavailable".into()))?;
    let state_metadata = fs::symlink_metadata(&state_root)?;
    let effective_uid = unsafe { libc::geteuid() };
    if !state_metadata.is_dir()
        || state_metadata.uid() != effective_uid
        || state_metadata.mode() & 0o022 != 0
    {
        return Err(ExecuteError::Invalid(
            "state directory is not a host-owned non-writable parent".into(),
        ));
    }

    let run_digest = blake3::hash(run_id.as_bytes()).to_hex();
    let execution_state = state_root.join(format!("v6-{run_digest}-{execution_id}"));
    fs::create_dir(&execution_state)?;
    fs::set_permissions(&execution_state, fs::Permissions::from_mode(0o700))?;
    let execution_metadata = fs::symlink_metadata(&execution_state)?;
    if !execution_metadata.is_dir()
        || execution_metadata.uid() != effective_uid
        || execution_metadata.mode() & 0o077 != 0
    {
        return Err(ExecuteError::Invalid(
            "per-execution state directory is not private".into(),
        ));
    }

    let source_before = FileIdentity::measure(source).map_err(|error| {
        ExecuteError::Invalid(format!("workspace input identity refused: {error:?}"))
    })?;
    let starting = execution_state.join("starting-workspace.ext4");
    let working = execution_state.join("working-workspace.ext4");
    let copied_start = fs::copy(source_before.path(), &starting)?;
    let copied_work = fs::copy(source_before.path(), &working)?;
    crate::profile::bytes(
        "mutable_state_materialization",
        "copied_logical",
        copied_start + copied_work,
    );

    let source_after = FileIdentity::measure(source).map_err(|error| {
        ExecuteError::Invalid(format!("workspace input changed during copy: {error:?}"))
    })?;
    let starting_identity = FileIdentity::measure(&starting).map_err(|error| {
        ExecuteError::Invalid(format!("S0 workspace copy identity refused: {error:?}"))
    })?;
    let working_identity = FileIdentity::measure(&working).map_err(|error| {
        ExecuteError::Invalid(format!(
            "working workspace copy identity refused: {error:?}"
        ))
    })?;
    if source_before != source_after
        || starting_identity.blake3() != source_before.blake3()
        || working_identity.blake3() != source_before.blake3()
    {
        return Err(ExecuteError::Invalid(
            "workspace input was unstable or copy did not match its measured source".into(),
        ));
    }

    fs::set_permissions(&starting, fs::Permissions::from_mode(0o400))?;
    fs::set_permissions(&working, fs::Permissions::from_mode(0o600))?;
    FileIdentity::measure(&starting)
        .map_err(|error| ExecuteError::Invalid(format!("S0 copy changed: {error:?}")))?;
    FileIdentity::measure(&working)
        .map_err(|error| ExecuteError::Invalid(format!("working copy changed: {error:?}")))?;
    fs::File::open(&starting)?.sync_all_traced()?;
    fs::File::open(&working)?.sync_all_traced()?;
    fs::File::open(&execution_state)?.sync_all_traced()?;

    Ok(PreparedWorkspaceImages {
        starting,
        working,
        execution_state,
    })
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn c1_manifest(
    run_id: &str,
    starting_generation: &str,
    final_world: &str,
    delta_root: &str,
    launch: &MeasuredLaunchSession,
) -> Result<Vec<u8>, ExecuteError> {
    let mut devices = launch
        .drives()
        .iter()
        .map(|drive| AttachedDevice {
            kind: drive.id().to_owned(),
            identity: drive.identity().blake3().to_owned(),
            read_only: drive.read_only(),
        })
        .collect::<Vec<_>>();
    devices.push(AttachedDevice {
        kind: "broker_vsock".into(),
        identity: "vsock:host:7000".into(),
        read_only: true,
    });
    let writable_mappings = launch
        .drives()
        .iter()
        .filter(|drive| !drive.read_only())
        .map(|drive| format!("drive:{}:rw", drive.id()))
        .collect();
    let manifest = MediationManifest {
        schema: 2,
        run_id: run_id.into(),
        vm_config_blake3: launch.vm_config_blake3().into(),
        guest_kernel_blake3: launch.kernel_identity().blake3().into(),
        rootfs_blake3: launch.rootfs_identity().blake3().into(),
        task_blake3: launch.policy_identity().task_blake3().into(),
        guest_policy_blake3: launch.guest_policy_identity().blake3().into(),
        seccomp_blake3: launch.seccomp_policy_blake3(),
        measured_launch_hash_domain: launch.canonical_hash_domain().into(),
        measured_launch_hash_version: launch.canonical_hash_version(),
        measured_launch_blake3: launch.canonical_hash_blake3().into(),
        broker_endpoint_identity: launch.broker_endpoint_blake3(),
        host_policy_identifier: launch.policy_identity().identifier().into(),
        host_policy_version: launch.policy_identity().version().into(),
        host_policy_blake3: launch.policy_identity().blake3().into(),
        launch_identity: launch.execution_id().into(),
        starting_generation: starting_generation.into(),
        final_world: final_world.into(),
        delta_root: delta_root.into(),
        runtime_identity: launch.runtime_identity().into(),
        network_policy_identity: launch.network_policy_blake3(),
        broker_identity: launch.firecracker_identity().blake3().into(),
        broker_endpoint: "vsock:host:7000".into(),
        devices,
        network_devices: launch
            .full_config()
            .get("network-interfaces")
            .and_then(serde_json::Value::as_array)
            .map(|interfaces| {
                interfaces
                    .iter()
                    .filter_map(|interface| {
                        interface
                            .get("iface_id")
                            .and_then(serde_json::Value::as_str)
                    })
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        shared_mounts: Vec::new(),
        inherited_fds: Vec::new(),
        writable_mappings,
        other_storage_aliases: Vec::new(),
        max_task_processes: 1,
    };
    serde_json::to_vec(&manifest).map_err(|error| ExecuteError::Invalid(error.to_string()))
}

fn world_commitment(root: &Path) -> Result<String, ExecuteError> {
    let mut entries = BTreeMap::new();
    for entry in walk(root)? {
        let relative = entry
            .strip_prefix(root)
            .map_err(|_| ExecuteError::Invalid("root traversal escaped workspace".into()))?
            .to_string_lossy()
            .into_owned();
        let metadata = fs::symlink_metadata(&entry)?;
        if metadata.file_type().is_symlink() {
            return Err(ExecuteError::Invalid(
                "symlink workspace entries are unsupported".into(),
            ));
        }
        let bytes = if metadata.is_file() {
            fs::read(&entry)?
        } else {
            Vec::new()
        };
        entries.insert(
            relative,
            (metadata.len(), blake3::hash(&bytes).to_hex().to_string()),
        );
    }
    Ok(blake3::hash(
        &serde_json::to_vec(&entries).map_err(|error| ExecuteError::Invalid(error.to_string()))?,
    )
    .to_hex()
    .to_string())
}

fn walk(root: &Path) -> Result<Vec<PathBuf>, ExecuteError> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        result.push(path.clone());
        if path.is_dir() {
            result.extend(walk(&path)?);
        }
    }
    Ok(result)
}

/// Validate and bind an invocation without executing it outside a measured
/// capsule. This is intentionally conservative and is the only supported V0
/// behavior for arbitrary commands.
/// Execute and retain a non-serializable accepted value only when the
/// host-observed C1 claim and verifier decision both succeed.
pub fn execute_with_authority(request: &ExecuteRequest) -> Result<ExecuteOutcome, ExecuteError> {
    if request.run_id.is_empty()
        || request.run_id.contains('/')
        || request.command.is_empty()
        || request.timeout_ms == 0
        || request.timeout_ms > 300_000
    {
        return Err(ExecuteError::Invalid("malformed execution request".into()));
    }
    let root = request
        .root
        .canonicalize()
        .map_err(|_| ExecuteError::Invalid("workspace root is unavailable".into()))?;
    if !root.is_dir() {
        return Err(ExecuteError::Invalid(
            "workspace root is not a directory".into(),
        ));
    }
    let supervisor_options = [
        request.rootfs.is_some(),
        request.workspace_device.is_some(),
        request.guest_supervisor.is_some(),
        request.firecracker.is_some(),
        request.kernel.is_some(),
        request.state_dir.is_some(),
    ];
    if supervisor_options.iter().any(|present| *present)
        && !supervisor_options.iter().all(|present| *present)
    {
        return Err(ExecuteError::Invalid(
            "rootfs, workspace-device, firecracker, kernel, and state-dir must be supplied together".into(),
        ));
    }
    let started = std::time::Instant::now();
    let starting_world_commitment = world_commitment(&root)?;
    let execution_id = fresh_execution_id()?;
    let runtime_ms = started.elapsed().as_millis();
    #[cfg(target_os = "linux")]
    if let (
        Some(rootfs),
        Some(workspace_device),
        Some(guest_supervisor),
        Some(firecracker),
        Some(kernel),
        Some(state_dir),
    ) = (
        request.rootfs.clone(),
        request.workspace_device.clone(),
        request.guest_supervisor.clone(),
        request.firecracker.clone(),
        request.kernel.clone(),
        request.state_dir.clone(),
    ) {
        let images = prepare_workspace_images(
            &workspace_device,
            &state_dir,
            &request.run_id,
            &execution_id,
        )?;
        let starting_workspace_image = images.starting;
        let working_workspace_image = images.working;
        let policy_bytes = effective_policy_bytes(
            &request.command,
            &request.allowed_effects,
            &request.allowed_paths,
            request.timeout_ms,
        )
        .map_err(|error| ExecuteError::Invalid(error.to_string()))?;
        let task_bytes = serde_json::to_vec(&request.command)
            .map_err(|error| ExecuteError::Invalid(error.to_string()))?;
        let policy = PolicyIdentity::new(
            "realm-c1-workspace-policy".into(),
            "2".into(),
            &policy_bytes,
            &task_bytes,
        );
        let supervisor = crate::supervisor::FirecrackerSupervisor {
            backend: C1BackendInputPaths {
                firecracker,
                kernel,
                rootfs,
                workspace_device,
                guest_supervisor,
                state_dir: images.execution_state,
                production_jailer: None,
            },
            starting_workspace_image: starting_workspace_image.clone(),
            working_workspace_image: working_workspace_image.clone(),
            timeout: std::time::Duration::from_millis(request.timeout_ms),
        };
        match supervisor.run_measured(crate::supervisor::MeasuredExecutionRequest {
            run_id: &request.run_id,
            execution_id: &execution_id,
            argv: &request.command,
            cwd: ".",
            safe_environment: &[],
            effect_contract: &[],
            policy,
        }) {
            Ok((observation, launch)) => {
                let facts = observation.facts();
                let manifest_bytes = c1_manifest(
                    &request.run_id,
                    facts.starting_world(),
                    facts.final_world().as_deref().ok_or_else(|| {
                        ExecuteError::Invalid("missing final world commitment".into())
                    })?,
                    facts.delta_root(),
                    &launch,
                )?;
                let manifest_root = digest_bytes(&manifest_bytes);
                let manifest_matches_launch =
                    serde_json::from_slice::<MediationManifest>(&manifest_bytes)
                        .is_ok_and(|manifest| launch.matches_manifest(&manifest));
                let unauthorized_path = facts
                    .observed_effects()
                    .iter()
                    .find(|path| !request.allowed_paths.iter().any(|allowed| allowed == *path));
                let (admission, reason_code, checked_claim_root) = if !manifest_matches_launch {
                    (
                        Admission::Refuse(crate::Refusal::UnverifiedBoundary),
                        "C1_MANIFEST_DOES_NOT_MATCH_MEASURED_LAUNCH".to_string(),
                        None,
                    )
                } else if !launch.consumable_input_binding() {
                    (
                        Admission::Refuse(crate::Refusal::UnverifiedBoundary),
                        "C1_LAUNCH_INPUT_CONSUMPTION_NOT_BOUND".to_string(),
                        None,
                    )
                } else if let Some(path) = unauthorized_path {
                    (
                        Admission::Refuse(crate::Refusal::UnverifiedBoundary),
                        format!("C1_POLICY_REFUSED_UNAUTHORIZED_PATH_{path}"),
                        None,
                    )
                } else {
                    match crate::mediation::issue_c1_claim(
                        &manifest_bytes,
                        &manifest_root,
                        &observation,
                    ) {
                        Ok(claim) => {
                            let claim_root = claim.root().to_string();
                            let candidate =
                                crate::integration::admission_for_c1(&claim, &observation);
                            let Admission::Refuse(refusal) = candidate;
                            (
                                Admission::Refuse(crate::Refusal::UnverifiedBoundary),
                                format!("C1_TERMINAL_JOIN_UNAVAILABLE_{refusal:?}"),
                                Some(claim_root),
                            )
                        }
                        Err(error) => (
                            Admission::Refuse(crate::Refusal::UnverifiedBoundary),
                            format!("C1_CLAIM_REFUSED_{error:?}"),
                            None,
                        ),
                    }
                };
                let result = ExecuteResult {
                    schema_version: 1,
                    run_id: request.run_id.clone(),
                    execution_id,
                    guest_exit_code: *facts.exit_code(),
                    guest_crashed: Some(*facts.crashed()),
                    vmm_pid: Some(launch.vmm().pid()),
                    vmm_start_time_ticks: Some(launch.vmm().start_time_ticks()),
                    starting_world_commitment: facts.starting_world().clone(),
                    final_world_commitment: facts.final_world().clone(),
                    delta_root: Some(facts.delta_root().clone()),
                    starting_workspace_image: Some(starting_workspace_image),
                    final_workspace_image: Some(working_workspace_image),
                    observed_effects: facts.observed_effects().clone(),
                    proposed_effects: Vec::new(),
                    evidence_root: facts.evidence_root().clone(),
                    receipt_path: None,
                    verifier_decision: admission,
                    reason_code,
                    // The guest exit claim is diagnostic only until it has a
                    // host-authenticated terminal witness.
                    task_success: false,
                    unsupported_effects: facts.unsupported_effects().clone(),
                    runtime_ms: started.elapsed().as_millis(),
                    overhead_ms: started.elapsed().as_millis(),
                };
                // This lane has measured launch and mediation evidence, but
                // no complete same-run terminal join. It cannot mint the
                // private generation-publication capability.
                let _checked_claim_root = checked_claim_root;
                return Ok(ExecuteOutcome {
                    result,
                    publication_capability: None,
                });
            }
            Err(error) => {
                return Ok(ExecuteOutcome {
                    result: ExecuteResult {
                        schema_version: 1,
                        run_id: request.run_id.clone(),
                        execution_id,
                        guest_exit_code: None,
                        guest_crashed: None,
                        vmm_pid: None,
                        vmm_start_time_ticks: None,
                        starting_world_commitment,
                        final_world_commitment: None,
                        delta_root: None,
                        starting_workspace_image: Some(starting_workspace_image),
                        final_workspace_image: Some(working_workspace_image),
                        observed_effects: Vec::new(),
                        proposed_effects: Vec::new(),
                        evidence_root: None,
                        receipt_path: None,
                        verifier_decision: Admission::Refuse(crate::Refusal::UnverifiedBoundary),
                        reason_code: "SUPERVISOR_UNAVAILABLE".into(),
                        task_success: false,
                        unsupported_effects: vec![error.to_string()],
                        runtime_ms: started.elapsed().as_millis(),
                        overhead_ms: started.elapsed().as_millis(),
                    },
                    publication_capability: None,
                });
            }
        }
    }
    Ok(ExecuteOutcome {
        result: ExecuteResult {
            schema_version: 1,
            run_id: request.run_id.clone(),
            execution_id,
            guest_exit_code: None,
            guest_crashed: None,
            vmm_pid: None,
            vmm_start_time_ticks: None,
            starting_world_commitment,
            final_world_commitment: None,
            delta_root: None,
            starting_workspace_image: None,
            final_workspace_image: None,
            observed_effects: Vec::new(),
            proposed_effects: Vec::new(),
            evidence_root: None,
            receipt_path: None,
            verifier_decision: Admission::Refuse(crate::Refusal::UnverifiedBoundary),
            reason_code: "CAPSULE_OBSERVER_UNAVAILABLE".into(),
            task_success: false,
            unsupported_effects: vec![
                "arbitrary command execution".into(),
                "filesystem effect observation".into(),
                "process and descendant effects".into(),
                "network and external effects".into(),
            ],
            runtime_ms,
            overhead_ms: runtime_ms,
        },
        publication_capability: None,
    })
}

/// Validate and execute as above, retaining an unforgeable in-process
/// capability when the measured C1 chain is accepted.
pub fn execute(request: &ExecuteRequest) -> Result<ExecuteResult, ExecuteError> {
    execute_with_authority(request).map(|outcome| outcome.result)
}

#[allow(clippy::too_many_arguments)]
fn accepted_decision_identity(
    schema_version: u16,
    claim_root: &str,
    manifest_root: &str,
    run_id: &str,
    execution_id: &str,
    capsule_id: &str,
    challenge_binding: &str,
    evidence_root: &str,
    same_run_join_root: &str,
    intent_identity: &str,
    effect_contract_identity: &str,
    starting_root: &str,
    final_root: &str,
    delta_root: &str,
) -> String {
    let material = (
        if schema_version == 8 {
            "realm-v6-checked-c1-accept-v8"
        } else if schema_version == 7 {
            "realm-v6-checked-c1-accept-v7"
        } else if schema_version == 6 {
            "realm-v6-checked-c1-accept-v6"
        } else if schema_version == 5 {
            "realm-v6-checked-c1-accept-v5"
        } else if schema_version == 4 {
            "realm-v6-checked-c1-accept-v4"
        } else {
            "realm-v6-checked-c1-accept-v3"
        },
        claim_root,
        manifest_root,
        run_id,
        execution_id,
        capsule_id,
        challenge_binding,
        evidence_root,
        same_run_join_root,
        intent_identity,
        effect_contract_identity,
        starting_root,
        final_root,
        delta_root,
    );
    let bytes = serde_json::to_vec(&material).expect("decision identity tuple is serializable");
    blake3::hash(&bytes).to_hex().to_string()
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn test_checked_execution(
    run_id: &str,
    execution_id: &str,
    start_root: &str,
    final_root: &str,
    delta_root: &str,
) -> CheckedExecutionForPublication {
    use crate::capsule::{BackendKind, CapsuleFacts, CheckResult, evidence_binding_root};
    use crate::mediation::{AttachedDevice, MediationManifest};

    let command = vec!["/bin/true".to_string()];
    let allowed_effects = vec!["filesystem".to_string()];
    let allowed_paths = vec!["target.txt".to_string()];
    let timeout_ms = 1_000;
    let intent_identity = domain_digest(
        "realm.intent",
        &serde_json::to_vec(&command).expect("fixture command serializes"),
    );
    let effect_contract_identity = domain_digest(
        "realm.policy",
        &serde_json::to_vec(&(&allowed_effects, &allowed_paths, timeout_ms))
            .expect("fixture contract serializes"),
    );
    let runtime_identity = "a".repeat(64);
    let network_policy_identity = "b".repeat(64);
    let rootfs_blake3 = "c".repeat(64);
    let task_bytes = serde_json::to_vec(&command).expect("fixture task serializes");
    let policy_bytes =
        effective_policy_bytes(&command, &allowed_effects, &allowed_paths, timeout_ms)
            .expect("fixture policy serializes");
    let policy_identity = crate::measured_launch::PolicyIdentity::new(
        "realm-c1-workspace-policy".into(),
        "2".into(),
        &policy_bytes,
        &task_bytes,
    );
    let manifest = MediationManifest {
        schema: 2,
        run_id: run_id.into(),
        vm_config_blake3: "d".repeat(64),
        guest_kernel_blake3: "e".repeat(64),
        rootfs_blake3: rootfs_blake3.clone(),
        task_blake3: policy_identity.task_blake3().to_owned(),
        guest_policy_blake3: "f".repeat(64),
        seccomp_blake3: "1".repeat(64),
        measured_launch_hash_domain: crate::measured_launch::MEASURED_LAUNCH_HASH_DOMAIN.into(),
        measured_launch_hash_version: crate::measured_launch::MEASURED_LAUNCH_HASH_VERSION,
        measured_launch_blake3: "2".repeat(64),
        broker_endpoint_identity: "3".repeat(64),
        host_policy_identifier: "realm-c1-workspace-policy".into(),
        host_policy_version: "2".into(),
        host_policy_blake3: policy_identity.blake3().into(),
        launch_identity: execution_id.into(),
        starting_generation: start_root.into(),
        final_world: final_root.into(),
        delta_root: delta_root.into(),
        runtime_identity: runtime_identity.clone(),
        network_policy_identity: network_policy_identity.clone(),
        broker_identity: "2".repeat(64),
        broker_endpoint: "vsock:host:7000".into(),
        devices: vec![
            AttachedDevice {
                kind: "rootfs".into(),
                identity: rootfs_blake3,
                read_only: true,
            },
            AttachedDevice {
                kind: "broker_vsock".into(),
                identity: "vsock:host:7000".into(),
                read_only: true,
            },
        ],
        network_devices: Vec::new(),
        shared_mounts: Vec::new(),
        inherited_fds: Vec::new(),
        writable_mappings: Vec::new(),
        other_storage_aliases: Vec::new(),
        max_task_processes: 1,
    };
    let c1_manifest = serde_json::to_vec(&manifest).expect("fixture manifest serializes");
    let c1_manifest_root = digest_bytes(&c1_manifest);
    let capsule_id = "3".repeat(64);
    let challenge_binding = "4".repeat(64);
    let checked_claim_root = c1_manifest_root.clone();
    let finalization_evidence = "6".repeat(64);
    let pause_snapshot_evidence = "7".repeat(64);
    let vmm_terminal_observation_root = "5".repeat(64);
    let facts = CapsuleFacts {
        run_id: run_id.into(),
        execution_id: execution_id.into(),
        backend: BackendKind::FirecrackerMeasured,
        workspace_identity: start_root.into(),
        capsule_id: capsule_id.clone(),
        custody_process_identity: Some("8".repeat(64)),
        descendants: Vec::new(),
        starting_world: start_root.into(),
        final_world: Some(final_root.into()),
        observed_effects: Vec::new(),
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
        unsupported_effects: Vec::new(),
        runtime_identity,
        network_policy_identity,
        completion_evidence: challenge_binding.clone(),
        finalization_evidence: finalization_evidence.clone(),
        pause_snapshot_evidence: pause_snapshot_evidence.clone(),
        vmm_terminal_observation_root: Some(vmm_terminal_observation_root.clone()),
        delta_root: delta_root.into(),
    };
    let evidence_root = evidence_binding_root(&facts);
    let same_run_join_root = domain_digest(
        "realm.same-run-publication-join.test-fixture.v1",
        &serde_json::to_vec(&(run_id, execution_id, start_root, final_root, delta_root))
            .expect("test-only join binding serializes"),
    );
    let decision_identity = accepted_decision_identity(
        5,
        &checked_claim_root,
        &c1_manifest_root,
        run_id,
        execution_id,
        &capsule_id,
        &challenge_binding,
        &evidence_root,
        &same_run_join_root,
        &intent_identity,
        &effect_contract_identity,
        start_root,
        final_root,
        delta_root,
    );
    let result = ExecuteResult {
        schema_version: 1,
        run_id: run_id.into(),
        execution_id: execution_id.into(),
        guest_exit_code: None,
        guest_crashed: None,
        vmm_pid: None,
        vmm_start_time_ticks: None,
        starting_world_commitment: start_root.into(),
        final_world_commitment: Some(final_root.into()),
        delta_root: Some(delta_root.into()),
        starting_workspace_image: None,
        final_workspace_image: None,
        observed_effects: Vec::new(),
        proposed_effects: Vec::new(),
        evidence_root: Some(evidence_root.clone()),
        receipt_path: None,
        verifier_decision: Admission::Refuse(crate::Refusal::UnverifiedBoundary),
        reason_code: "C1_CHECKED_FOR_PUBLICATION".into(),
        task_success: false,
        unsupported_effects: Vec::new(),
        runtime_ms: 1,
        overhead_ms: 1,
    };
    let checked = CheckedExecutionForPublication {
        schema_version: 5,
        file_contract: None,
        result,
        capsule_id,
        custody_process_identity: Some("8".repeat(64)),
        challenge_binding,
        decision_identity,
        checked_claim_root,
        c1_manifest_root,
        c1_manifest,
        evidence_root,
        vmm_terminal_observation_root,
        finalization_evidence,
        pause_snapshot_evidence,
        command,
        allowed_effects,
        allowed_paths,
        timeout_ms,
        intent_identity,
        effect_contract_identity,
        accepted_start_root: start_root.into(),
        accepted_final_root: final_root.into(),
        accepted_delta_root: delta_root.into(),
        same_run_join_root,
    };
    assert!(checked.validate_bindings());
    let evidence = checked.checked_c1_evidence();
    let same_run = crate::integration::test_checked_same_run_evidence(&evidence);
    CheckedExecutionForPublication::issue_for_publication(
        checked.result.clone(),
        evidence,
        same_run,
    )
    .expect("test fixture capability must pass the typed same-run issuer")
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn test_checked_execution_with_images(
    run_id: &str,
    execution_id: &str,
    start_root: &str,
    final_root: &str,
    delta_root: &str,
    starting_image: &std::path::Path,
    final_image: &std::path::Path,
) -> CheckedExecutionForPublication {
    let mut execution =
        test_checked_execution(run_id, execution_id, start_root, final_root, delta_root);
    execution.result.starting_workspace_image = Some(starting_image.to_path_buf());
    execution.result.final_workspace_image = Some(final_image.to_path_buf());
    execution
}

use std::io::Read;

/// Execute the single supported production broker profile. Serialized reports
/// never reconstruct either the contained launch or publication authority.
#[cfg(target_os = "linux")]
pub fn execute_rootfs_brokered(
    request: &ExecuteRequest,
    backend: &C1BackendInputPaths,
    custodian: &Path,
    custodian_uid: u32,
    custodian_gid: u32,
) -> Result<ExecuteOutcome, ExecuteError> {
    execute_rootfs_brokered_inner(
        request,
        &crate::c0_contract::C0FileContract::frozen(),
        backend,
        custodian,
        custodian_uid,
        custodian_gid,
        false,
    )
}

/// Explicit bounded variation; the legacy API retains its literal contract.
/// S0/S1 roots and output path are bound by the unchanged checked C1 chain.
#[cfg(target_os = "linux")]
pub fn execute_rootfs_brokered_contract(
    request: &ExecuteRequest,
    contract: &crate::c0_contract::C0FileContract,
    backend: &C1BackendInputPaths,
    custodian: &Path,
    custodian_uid: u32,
    custodian_gid: u32,
) -> Result<ExecuteOutcome, ExecuteError> {
    execute_rootfs_brokered_inner(
        request,
        contract,
        backend,
        custodian,
        custodian_uid,
        custodian_gid,
        true,
    )
}
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn execute_rootfs_brokered_inner(
    request: &ExecuteRequest,
    contract: &crate::c0_contract::C0FileContract,
    backend: &C1BackendInputPaths,
    custodian: &Path,
    custodian_uid: u32,
    custodian_gid: u32,
    bind_contract: bool,
) -> Result<ExecuteOutcome, ExecuteError> {
    contract
        .validate()
        .map_err(|e| ExecuteError::Invalid(e.into()))?;
    let _profile = crate::profile::Span::new("execute_checked_pipeline");
    if request.run_id.len() != 64
        || !request
            .run_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || request.command != ["c0"]
        || request.allowed_effects != ["filesystem"]
        || request.allowed_paths != [contract.output_path.clone()]
        || request.timeout_ms == 0
        || request.timeout_ms > 300_000
        || backend.production_jailer.is_none()
    {
        return Err(ExecuteError::Invalid(
            "only a bounded C0 read/create-output contract is supported".into(),
        ));
    }
    let started = std::time::Instant::now();
    let execution_id = fresh_execution_id()?;
    let images = prepare_workspace_images(
        &backend.workspace_device,
        &backend.state_dir,
        &request.run_id,
        &execution_id,
    )?;
    let task_bytes =
        serde_json::to_vec(&request.command).map_err(|e| ExecuteError::Invalid(e.to_string()))?;
    let policy_bytes = effective_policy_bytes(
        &request.command,
        &request.allowed_effects,
        &request.allowed_paths,
        request.timeout_ms,
    )
    .map_err(|e| ExecuteError::Invalid(e.to_string()))?;
    let policy_bytes = if bind_contract {
        contract_policy_bytes(&policy_bytes, contract)
            .map_err(|e| ExecuteError::Invalid(e.to_string()))?
    } else {
        policy_bytes
    };
    let policy = PolicyIdentity::new(
        "realm-c1-workspace-policy".into(),
        if bind_contract { "3" } else { "2" }.into(),
        &policy_bytes,
        &task_bytes,
    );
    let mut actual_backend = backend.clone();
    actual_backend.state_dir = images.execution_state;
    let supervisor = crate::supervisor::FirecrackerSupervisor {
        backend: actual_backend,
        starting_workspace_image: images.starting.clone(),
        working_workspace_image: images.working,
        timeout: std::time::Duration::from_millis(request.timeout_ms),
    };
    let live = crate::production_session::run_contract(
        &supervisor,
        request,
        contract,
        &execution_id,
        policy,
        custodian,
        custodian_uid,
        custodian_gid,
    )?;
    let facts = live.observation.facts();
    let manifest_bytes = c1_manifest(
        &request.run_id,
        &live.before.root,
        &live.after.root,
        facts.delta_root(),
        &live.production,
    )?;
    let manifest_root = digest_bytes(&manifest_bytes);
    let claim = crate::mediation::CheckedMediationClaim::issue_for_production_session(
        &manifest_bytes,
        &manifest_root,
        &live.observation,
        &live.session,
        &live.frozen,
        &live.production,
    )
    .map_err(|e| ExecuteError::Supervisor(format!("production mediation join refused: {e:?}")))?;
    let same_run = live
        .semantic
        .checked_same_run(&claim, &live.observation, &live.production, &live.closure)
        .map_err(|e| {
            ExecuteError::Supervisor(format!("production same-run join refused: {e:?}"))
        })?;
    let intent_identity = domain_digest("realm.intent", &task_bytes);
    let effect_contract_bytes = if bind_contract {
        serde_json::to_vec(&(
            &request.allowed_effects,
            &request.allowed_paths,
            request.timeout_ms,
            contract,
        ))
    } else {
        serde_json::to_vec(&(
            &request.allowed_effects,
            &request.allowed_paths,
            request.timeout_ms,
        ))
    }
    .map_err(|e| ExecuteError::Invalid(e.to_string()))?;
    let effect_contract_identity = domain_digest("realm.policy", &effect_contract_bytes);
    let schema_version = if bind_contract { 8 } else { 7 };
    let evidence = CheckedC1Evidence {
        schema_version,
        file_contract: bind_contract.then(|| contract.clone()),
        verifier_decision: "CHECKED_FOR_PUBLICATION".into(),
        run_id: request.run_id.clone(),
        execution_id: execution_id.clone(),
        capsule_id: facts.capsule_id().clone(),
        custody_process_identity: facts.custody_process_identity().clone(),
        challenge_binding: facts.completion_evidence().clone(),
        checked_claim_root: claim.root().into(),
        accepted_decision_identity: accepted_decision_identity(
            schema_version,
            claim.root(),
            &manifest_root,
            &request.run_id,
            &execution_id,
            facts.capsule_id(),
            facts.completion_evidence(),
            facts
                .evidence_root()
                .as_deref()
                .expect("observed evidence is bound"),
            same_run.root(),
            &intent_identity,
            &effect_contract_identity,
            &live.before.root,
            &live.after.root,
            facts.delta_root(),
        ),
        same_run_join_root: same_run.root().into(),
        accepted_start_root: live.before.root.clone(),
        accepted_final_root: live.after.root.clone(),
        accepted_delta_root: facts.delta_root().clone(),
        evidence_root: facts
            .evidence_root()
            .clone()
            .expect("observed evidence is bound"),
        vmm_terminal_observation_root: facts.vmm_terminal_observation_root().clone(),
        finalization_evidence: facts.finalization_evidence().clone(),
        pause_snapshot_evidence: facts.pause_snapshot_evidence().clone(),
        c1_manifest_root: manifest_root,
        c1_manifest: manifest_bytes,
        command: request.command.clone(),
        allowed_effects: request.allowed_effects.clone(),
        allowed_paths: request.allowed_paths.clone(),
        observed_effects: facts.observed_effects().clone(),
        unsupported_effects: vec![],
        timeout_ms: request.timeout_ms,
        intent_identity,
        effect_contract_identity,
    };
    let receipt_path = live.state.join("checked-c1-evidence.json");
    let result = ExecuteResult {
        schema_version: 1,
        run_id: request.run_id.clone(),
        execution_id,
        guest_exit_code: None,
        guest_crashed: None,
        vmm_pid: None,
        vmm_start_time_ticks: None,
        starting_world_commitment: live.before.root,
        final_world_commitment: Some(live.after.root),
        delta_root: Some(facts.delta_root().clone()),
        starting_workspace_image: Some(images.starting),
        final_workspace_image: Some(live.final_image),
        observed_effects: facts.observed_effects().clone(),
        proposed_effects: request.allowed_effects.clone(),
        evidence_root: facts.evidence_root().clone(),
        receipt_path: Some(receipt_path.clone()),
        verifier_decision: Admission::Refuse(crate::Refusal::UnverifiedBoundary),
        reason_code: "CHECKED_FOR_PUBLICATION".into(),
        task_success: false,
        unsupported_effects: vec![],
        runtime_ms: started.elapsed().as_millis(),
        overhead_ms: 0,
    };
    let capability =
        CheckedExecutionForPublication::issue_for_publication(result.clone(), evidence, same_run)
            .map_err(|e| {
            ExecuteError::Supervisor(format!("checked publication capability refused: {e:?}"))
        })?;
    let mut receipt = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&receipt_path)?;
    use std::io::Write;
    receipt.write_all(
        &serde_json::to_vec_pretty(&capability.checked_c1_evidence())
            .map_err(|e| ExecuteError::Invalid(e.to_string()))?,
    )?;
    receipt.sync_all_traced()?;
    fs::File::open(&live.state)?.sync_all_traced()?;
    Ok(ExecuteOutcome {
        result,
        publication_capability: Some(capability),
    })
}

/// Non-authorizing qualification using two real contained, frozen and closed
/// executions. Reports never reconstruct capabilities or emit public ACCEPT.
#[cfg(target_os = "linux")]
pub fn qualify_real_production_joins(
    first: &ExecuteRequest,
    second: &ExecuteRequest,
    backend: &C1BackendInputPaths,
    custodian: &Path,
    uid: u32,
    gid: u32,
) -> Result<serde_json::Value, ExecuteError> {
    if first.run_id == second.run_id {
        return Err(ExecuteError::Invalid(
            "qualification needs independent run IDs".into(),
        ));
    }
    fn prepare(
        r: &ExecuteRequest,
        b: &C1BackendInputPaths,
        c: &Path,
        u: u32,
        g: u32,
    ) -> Result<crate::production_session::ProductionRun, ExecuteError> {
        if r.run_id.len() != 64
            || !r
                .run_id
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
            || r.command != ["c0"]
            || r.allowed_effects != ["filesystem"]
            || r.allowed_paths != ["output.txt"]
            || r.timeout_ms == 0
            || r.timeout_ms > 300_000
            || b.production_jailer.is_none()
        {
            return Err(ExecuteError::Invalid(
                "unsupported qualification contract".into(),
            ));
        }
        let id = fresh_execution_id()?;
        let images = prepare_workspace_images(&b.workspace_device, &b.state_dir, &r.run_id, &id)?;
        let task =
            serde_json::to_vec(&r.command).map_err(|e| ExecuteError::Invalid(e.to_string()))?;
        let policy = effective_policy_bytes(
            &r.command,
            &r.allowed_effects,
            &r.allowed_paths,
            r.timeout_ms,
        )
        .map_err(|e| ExecuteError::Invalid(e.to_string()))?;
        let identity = PolicyIdentity::new(
            "realm-c1-workspace-policy".into(),
            "2".into(),
            &policy,
            &task,
        );
        let mut backend = b.clone();
        backend.state_dir = images.execution_state;
        let supervisor = crate::supervisor::FirecrackerSupervisor {
            backend,
            starting_workspace_image: images.starting,
            working_workspace_image: images.working,
            timeout: std::time::Duration::from_millis(r.timeout_ms),
        };
        crate::production_session::run(&supervisor, r, &id, identity, c, u, g)
    }
    let a = prepare(first, backend, custodian, uid, gid)?;
    let b = prepare(second, backend, custodian, uid, gid)?;
    crate::production_session::audit_real_foreign_joins(&a, &b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt;

    fn request(root: &Path) -> ExecuteRequest {
        ExecuteRequest {
            run_id: "run-v0".into(),
            root: root.into(),
            command: vec!["/bin/sh".into(), "-c".into(), "touch escaped".into()],
            timeout_ms: 1000,
            allowed_effects: vec!["filesystem".into()],
            allowed_paths: vec![],
            rootfs: None,
            workspace_device: None,
            guest_supervisor: None,
            firecracker: None,
            kernel: None,
            state_dir: None,
        }
    }

    #[test]
    fn shutdown_schema_is_distinct_and_legacy_completion_is_preserved() {
        let checked = test_checked_execution(
            "schema-run",
            &"e".repeat(64),
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
        );
        let mut evidence = checked.checked_c1_evidence();
        let parsed = crate::mediation::check_manifest_claim_shape(
            &evidence.c1_manifest,
            &evidence.c1_manifest_root,
        )
        .unwrap();
        assert!(validate_checked_c1_evidence(&evidence));
        assert_eq!(
            capsule_facts_for_checked_evidence(
                &evidence,
                &parsed.manifest,
                evidence.custody_process_identity.clone()
            )
            .exit_code,
            Some(0)
        );
        evidence.schema_version = 7;
        assert!(!validate_checked_c1_evidence(&evidence)); // old decision domain cannot be reused
        evidence.accepted_decision_identity = accepted_decision_identity(
            7,
            &evidence.checked_claim_root,
            &evidence.c1_manifest_root,
            &evidence.run_id,
            &evidence.execution_id,
            &evidence.capsule_id,
            &evidence.challenge_binding,
            &evidence.evidence_root,
            &evidence.same_run_join_root,
            &evidence.intent_identity,
            &evidence.effect_contract_identity,
            &evidence.accepted_start_root,
            &evidence.accepted_final_root,
            &evidence.accepted_delta_root,
        );
        assert!(validate_checked_c1_evidence(&evidence)); // structural evidence, never a live capability
        assert_eq!(
            capsule_facts_for_checked_evidence(
                &evidence,
                &parsed.manifest,
                evidence.custody_process_identity.clone()
            )
            .exit_code,
            None
        );
        evidence.schema_version = 9;
        assert!(!validate_checked_c1_evidence(&evidence));
    }

    #[test]
    fn arbitrary_command_is_not_run_without_capsule_observer() {
        let root = std::env::temp_dir().join(format!("realm-v6-execute-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let outcome = execute_with_authority(&request(&root)).unwrap();
        assert!(outcome.publication_capability.is_none());
        let result = outcome.result;
        assert_eq!(
            result.verifier_decision,
            Admission::Refuse(crate::Refusal::UnverifiedBoundary)
        );
        assert!(!root.join("escaped").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn publication_capability_issuer_requires_the_original_same_run_join() {
        let checked = test_checked_execution(
            "run-join-capability-test",
            &"e".repeat(64),
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
        );
        let result = checked.result().clone();
        let evidence = checked.checked_c1_evidence();
        let joined = crate::integration::test_checked_same_run_evidence(&evidence);
        assert!(
            CheckedExecutionForPublication::issue_for_publication(
                result.clone(),
                evidence.clone(),
                joined,
            )
            .is_ok()
        );

        let mut substituted = evidence.clone();
        substituted.same_run_join_root = "f".repeat(64);
        substituted.accepted_decision_identity = accepted_decision_identity(
            substituted.schema_version,
            &substituted.checked_claim_root,
            &substituted.c1_manifest_root,
            &substituted.run_id,
            &substituted.execution_id,
            &substituted.capsule_id,
            &substituted.challenge_binding,
            &substituted.evidence_root,
            &substituted.same_run_join_root,
            &substituted.intent_identity,
            &substituted.effect_contract_identity,
            &substituted.accepted_start_root,
            &substituted.accepted_final_root,
            &substituted.accepted_delta_root,
        );
        assert!(matches!(
            CheckedExecutionForPublication::issue_for_publication(
                result.clone(),
                substituted,
                crate::integration::test_checked_same_run_evidence(&evidence),
            ),
            Err(PublicationCapabilityRefusal::SameRunJoinMismatch)
        ));

        let mut stale_result = result;
        stale_result.final_world_commitment = Some("d".repeat(64));
        assert!(matches!(
            CheckedExecutionForPublication::issue_for_publication(
                stale_result,
                evidence.clone(),
                crate::integration::test_checked_same_run_evidence(&evidence),
            ),
            Err(PublicationCapabilityRefusal::ResultMismatch)
        ));
    }

    #[test]
    fn publication_capability_rejects_recomputed_custody_substitution() {
        let checked = test_checked_execution(
            "run-custody-substitution-test",
            &"e".repeat(64),
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
        );
        let result = checked.result().clone();
        let evidence = checked.checked_c1_evidence();
        let same_run = crate::integration::test_checked_same_run_evidence(&evidence);
        let mut missing_custody = evidence.clone();
        missing_custody.custody_process_identity = None;
        assert!(!validate_checked_c1_evidence(&missing_custody));
        let foreign_custody = "f".repeat(64);
        let manifest = crate::mediation::check_manifest_claim_shape(
            &evidence.c1_manifest,
            &evidence.c1_manifest_root,
        )
        .unwrap()
        .manifest;

        let mut substituted = evidence.clone();
        substituted.custody_process_identity = Some(foreign_custody.clone());
        let facts =
            capsule_facts_for_checked_evidence(&substituted, &manifest, Some(foreign_custody));
        substituted.evidence_root = crate::capsule::evidence_binding_root(&facts);
        substituted.accepted_decision_identity = accepted_decision_identity(
            substituted.schema_version,
            &substituted.checked_claim_root,
            &substituted.c1_manifest_root,
            &substituted.run_id,
            &substituted.execution_id,
            &substituted.capsule_id,
            &substituted.challenge_binding,
            &substituted.evidence_root,
            &substituted.same_run_join_root,
            &substituted.intent_identity,
            &substituted.effect_contract_identity,
            &substituted.accepted_start_root,
            &substituted.accepted_final_root,
            &substituted.accepted_delta_root,
        );

        // The attacker can make the serialized package internally consistent.
        // The opaque token still rejects it because it names another custodian.
        assert!(validate_checked_c1_evidence(&substituted));
        assert!(matches!(
            CheckedExecutionForPublication::issue_for_publication(result, substituted, same_run,),
            Err(PublicationCapabilityRefusal::SameRunJoinMismatch)
        ));
    }

    #[test]
    fn publication_capability_rejects_same_run_policy_substitution() {
        let checked = test_checked_execution(
            "run-policy-substitution-test",
            &"e".repeat(64),
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
        );
        let result = checked.result().clone();
        let evidence = checked.checked_c1_evidence();
        let same_run = crate::integration::test_checked_same_run_evidence(&evidence);

        let mut legacy = evidence.clone();
        legacy.schema_version = 3;
        legacy.custody_process_identity = None;
        let mut legacy_wire: crate::mediation::MediationManifest =
            serde_json::from_slice(&legacy.c1_manifest).unwrap();
        legacy_wire.task_blake3 = digest_bytes(&serde_json::to_vec(&legacy.command).unwrap());
        legacy.c1_manifest = serde_json::to_vec(&legacy_wire).unwrap();
        legacy.c1_manifest_root = digest_bytes(&legacy.c1_manifest);
        legacy.checked_claim_root = legacy.c1_manifest_root.clone();
        let legacy_manifest = crate::mediation::check_manifest_claim_shape(
            &legacy.c1_manifest,
            &legacy.c1_manifest_root,
        )
        .unwrap()
        .manifest;
        let legacy_facts = capsule_facts_for_checked_evidence(&legacy, &legacy_manifest, None);
        legacy.evidence_root = crate::capsule::evidence_binding_root_v2(&legacy_facts);
        legacy.accepted_decision_identity = accepted_decision_identity(
            legacy.schema_version,
            &legacy.checked_claim_root,
            &legacy.c1_manifest_root,
            &legacy.run_id,
            &legacy.execution_id,
            &legacy.capsule_id,
            &legacy.challenge_binding,
            &legacy.evidence_root,
            &legacy.same_run_join_root,
            &legacy.intent_identity,
            &legacy.effect_contract_identity,
            &legacy.accepted_start_root,
            &legacy.accepted_final_root,
            &legacy.accepted_delta_root,
        );
        assert!(validate_checked_c1_evidence(&legacy));
        assert!(matches!(
            CheckedExecutionForPublication::issue_for_publication(
                result.clone(),
                legacy,
                crate::integration::test_checked_same_run_evidence(&evidence),
            ),
            Err(PublicationCapabilityRefusal::InvalidEvidence)
        ));

        // Mutate policy fields while preserving the measured manifest root.
        // Recompute every public, unkeyed self-consistency digest an attacker
        // can recompute from the serialized evidence.
        let mut substituted = evidence.clone();
        substituted.allowed_effects.clear();
        substituted.allowed_paths.clear();
        substituted.timeout_ms += 1;
        let contract = serde_json::to_vec(&(
            &substituted.allowed_effects,
            &substituted.allowed_paths,
            substituted.timeout_ms,
        ))
        .unwrap();
        substituted.effect_contract_identity = domain_digest("realm.policy", &contract);
        substituted.accepted_decision_identity = accepted_decision_identity(
            substituted.schema_version,
            &substituted.checked_claim_root,
            &substituted.c1_manifest_root,
            &substituted.run_id,
            &substituted.execution_id,
            &substituted.capsule_id,
            &substituted.challenge_binding,
            &substituted.evidence_root,
            &substituted.same_run_join_root,
            &substituted.intent_identity,
            &substituted.effect_contract_identity,
            &substituted.accepted_start_root,
            &substituted.accepted_final_root,
            &substituted.accepted_delta_root,
        );

        assert!(matches!(
            CheckedExecutionForPublication::issue_for_publication(result, substituted, same_run,),
            Err(PublicationCapabilityRefusal::InvalidEvidence)
        ));
    }

    #[test]
    fn publication_capability_rejects_generated_policy_substitution_corpus() {
        let checked = test_checked_execution(
            "run-policy-corpus-test",
            &"e".repeat(64),
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
        );
        let result = checked.result().clone();
        let evidence = checked.checked_c1_evidence();
        let mut attempted = 0;

        for variant in 0..25 {
            for field in 0..4 {
                let mut substituted = evidence.clone();
                match field {
                    0 => substituted.allowed_effects = vec![format!("effect-{variant:02}")],
                    1 => substituted.allowed_paths = vec![format!("foreign/{variant:02}.txt")],
                    2 => substituted.timeout_ms = evidence.timeout_ms + variant + 1,
                    3 => substituted.command[0] = format!("/foreign/command-{variant:02}"),
                    _ => unreachable!(),
                }
                let contract = serde_json::to_vec(&(
                    &substituted.allowed_effects,
                    &substituted.allowed_paths,
                    substituted.timeout_ms,
                ))
                .unwrap();
                substituted.effect_contract_identity = domain_digest("realm.policy", &contract);
                let intent = serde_json::to_vec(&substituted.command).unwrap();
                substituted.intent_identity = domain_digest("realm.intent", &intent);
                substituted.accepted_decision_identity = accepted_decision_identity(
                    substituted.schema_version,
                    &substituted.checked_claim_root,
                    &substituted.c1_manifest_root,
                    &substituted.run_id,
                    &substituted.execution_id,
                    &substituted.capsule_id,
                    &substituted.challenge_binding,
                    &substituted.evidence_root,
                    &substituted.same_run_join_root,
                    &substituted.intent_identity,
                    &substituted.effect_contract_identity,
                    &substituted.accepted_start_root,
                    &substituted.accepted_final_root,
                    &substituted.accepted_delta_root,
                );

                assert!(
                    !validate_checked_c1_evidence(&substituted),
                    "policy field {field} accepted generated mutation {variant}"
                );
                assert!(matches!(
                    CheckedExecutionForPublication::issue_for_publication(
                        result.clone(),
                        substituted,
                        crate::integration::test_checked_same_run_evidence(&evidence),
                    ),
                    Err(PublicationCapabilityRefusal::InvalidEvidence)
                ));
                attempted += 1;
            }
        }

        assert_eq!(attempted, 100);
    }

    #[test]
    fn every_invocation_gets_fresh_identity() {
        let root = std::env::temp_dir().join(format!("realm-v6-execute-id-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let first = execute(&request(&root)).unwrap();
        let second = execute(&request(&root)).unwrap();
        assert_ne!(first.execution_id, second.execution_id);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn vmm_workspace_is_a_private_copy_and_does_not_mutate_the_input() {
        let root = std::env::temp_dir().join(format!(
            "realm-v6-workspace-copy-{}-{}",
            std::process::id(),
            fresh_execution_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("pinned-input.ext4");
        fs::write(&source, b"immutable input image").unwrap();
        let state = root.join("state");
        let images =
            prepare_workspace_images(&source, &state, "run-copy-test", &"a".repeat(64)).unwrap();

        assert_eq!(fs::read(&source).unwrap(), b"immutable input image");
        assert_eq!(
            fs::read(&images.starting).unwrap(),
            b"immutable input image"
        );
        assert_eq!(fs::read(&images.working).unwrap(), b"immutable input image");
        assert_eq!(
            fs::metadata(&images.execution_state).unwrap().mode() & 0o777,
            0o700
        );

        fs::write(&images.working, b"guest effect in private copy").unwrap();
        assert_eq!(fs::read(&source).unwrap(), b"immutable input image");
        assert_eq!(
            fs::read(&images.starting).unwrap(),
            b"immutable input image"
        );
        assert_eq!(
            fs::read(&images.working).unwrap(),
            b"guest effect in private copy"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execution_workspace_copy_names_are_never_reused_or_overwritten() {
        let root = std::env::temp_dir().join(format!(
            "realm-v6-workspace-copy-replay-{}-{}",
            std::process::id(),
            fresh_execution_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("pinned-input.ext4");
        fs::write(&source, b"input").unwrap();
        let state = root.join("state");
        let execution_id = "b".repeat(64);
        let first =
            prepare_workspace_images(&source, &state, "run-replay-test", &execution_id).unwrap();
        fs::write(&first.working, b"first execution output").unwrap();
        assert!(
            prepare_workspace_images(&source, &state, "run-replay-test", &execution_id).is_err()
        );
        assert_eq!(fs::read(&first.working).unwrap(), b"first execution output");
        fs::remove_dir_all(root).unwrap();
    }
}
