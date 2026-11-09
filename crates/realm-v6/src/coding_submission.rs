//! Untrusted coding submission framing. Structural checks are not semantics,
//! measured execution, custody, closure, publication, or host authority.
//! The native diagnostic broker accepts exactly one bounded submission then Close.
#[cfg(any(target_os = "linux", test))]
pub(crate) mod custody_files;
use serde::{Deserialize, Serialize};

pub const PATHS: [&str; 3] = ["totals.py", "report.py", "test_totals.py"];
pub const MAX_FILE: usize = 32 * 1024;
pub const MAX_SUBMISSION: usize = 128 * 1024;

/// Operator-supplied labels. This type is not a capability or proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionContract {
    pub run_id: String,
    pub execution_id: String,
    pub challenge_root: String,
    pub task_sha256: String,
    pub worker_sha256: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateFile {
    pub path: String,
    pub text: String,
    pub mode: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub schema: String,
    pub binding: SubmissionContract,
    /// Guest assertion only. Never authenticates history or a successful check.
    pub transcript_head: String,
    pub files: [CandidateFile; 3],
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl SubmissionContract {
    pub fn validate(&self) -> Result<(), &'static str> {
        if [
            &self.run_id,
            &self.execution_id,
            &self.challenge_root,
            &self.task_sha256,
            &self.worker_sha256,
        ]
        .into_iter()
        .all(|s| digest(s))
        {
            Ok(())
        } else {
            Err("invalid submission binding")
        }
    }
    /// Parse only after checking the byte bound. Reject duplicate keys using
    /// the existing strict parser before typed deserialization. No code runs.
    pub fn decode(&self, bytes: &[u8]) -> Result<Submission, &'static str> {
        self.validate()?;
        if bytes.is_empty() || bytes.len() > MAX_SUBMISSION {
            return Err("submission size limit");
        }
        let value = crate::strict_json::parse(bytes).map_err(|_| "malformed submission")?;
        let submission: Submission =
            serde_json::from_value(value).map_err(|_| "submission shape")?;
        if submission.schema != "realm.coding-submission.v1"
            || submission.binding != *self
            || !digest(&submission.transcript_head)
        {
            return Err("submission identity differs");
        }
        for (file, path) in submission.files.iter().zip(PATHS) {
            if file.path != path
                || file.mode != 0o600
                || file.text.is_empty()
                || file.text.len() > MAX_FILE
            {
                return Err("submission projection differs");
            }
        }
        Ok(submission)
    }
}

/// Pre-execution expectations, never a checker result or an authority token.
/// The trusted launcher commits these before InstanceStart; an independent
/// checker must later establish that it actually consumed these exact inputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingExecutionScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_inputs_blake3: Option<String>,
    pub submission: SubmissionContract,
    pub source_commit: String,
    pub checker_sha256: String,
    pub checker_scope_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_admission_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_subtask: Option<crate::native_workflow::NativeSubtask>,
}
impl CodingExecutionScope {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.task_inputs_blake3.as_ref().is_some_and(|r| !digest(r))
            || self.task_inputs_blake3.is_some() && self.native_subtask.is_none()
        {
            return Err("task inputs require registered native workflow");
        }
        self.submission.validate()?;
        if let Some(step) = &self.native_subtask {
            step.validate()?;
        }
        if self
            .runtime_admission_id
            .as_ref()
            .is_some_and(|v| !digest(v))
        {
            return Err("invalid runtime admission identity");
        }
        if self.source_commit.len() != 40
            || !self
                .source_commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !digest(&self.checker_sha256)
            || !digest(&self.checker_scope_sha256)
        {
            return Err("unsupported prelaunch source/checker commitment");
        }
        Ok(())
    }
    /// Policy4's stable scope is shared with the canonical content adapter.
    /// No answer bytes, agent-selected tests or posthoc semantic result enter it.
    pub fn policy_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let base = serde_json::to_vec(&serde_json::json!({
            "policy_id":"realm-c1-workspace-policy", "policy_version":2,
            "allowed_effects":["write"], "allowed_paths":["output"],
            "argv":[CODING_PROFILE], "cwd":".", "timeout_ms":120000
        }))?;
        crate::execute::coding_scope_policy_bytes(
            &base,
            &self.submission,
            &self.source_commit,
            1,
            CODING_PROFILE,
        )
    }
    pub(crate) fn policy_identity(
        &self,
    ) -> Result<crate::measured_launch::PolicyIdentity, serde_json::Error> {
        Ok(crate::measured_launch::PolicyIdentity::new(
            "realm-c1-workspace-policy".into(),
            "4".into(),
            &self.policy_bytes()?,
            &serde_json::to_vec(self)?,
        ))
    }
}

/// Failure before a submission is sent is distinct from unknown delivery after
/// dispatch. A missing/refused reply does not prove the custodian did not write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryFailure {
    NotDispatched,
    Unknown,
}

/// Submit over the existing framed broker protocol. Success means only a
/// matching write reply and capability-revocation reply; it does NOT establish
/// semantics, authenticated execution, terminal closure, publication, or apply.
pub fn send<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    contract: &SubmissionContract,
    bytes: &[u8],
) -> Result<(), DeliveryFailure> {
    use crate::broker_rpc::{
        RpcKind, RpcRequest, RpcResponse, RpcStatus, read_bootstrap, read_frame, write_frame,
    };
    contract
        .decode(bytes)
        .map_err(|_| DeliveryFailure::NotDispatched)?;
    let boot = read_bootstrap(stream).map_err(|_| DeliveryFailure::NotDispatched)?;
    if boot.run_id != contract.run_id
        || boot.process.launch != contract.execution_id
        || boot.challenge_root != contract.challenge_root
        || boot.process.serial != 1
    {
        return Err(DeliveryFailure::NotDispatched);
    }
    let mut version = boot.output_version;
    for (id, kind, payload, sequence) in [
        ("coding:submit", RpcKind::WriteRange, bytes.to_vec(), 2),
        ("coding:close", RpcKind::Close, Vec::new(), 3),
    ] {
        let requested_length = payload.len() as u64;
        let request = RpcRequest {
            run_id: boot.run_id.clone(),
            process: boot.process.clone(),
            capability: boot.capability,
            challenge_root: boot.challenge_root.clone(),
            operation_id: id.into(),
            kind,
            object_id: "output".into(),
            expected_version: version.clone(),
            offset: 0,
            requested_length,
            bytes: payload,
        };
        // From the first attempted write onward every failure is UNKNOWN.
        write_frame(stream, &request).map_err(|_| DeliveryFailure::Unknown)?;
        let reply: RpcResponse = read_frame(stream).map_err(|_| DeliveryFailure::Unknown)?;
        if reply.run_id != boot.run_id
            || reply.operation_id != id
            || reply.status != RpcStatus::Ok
            || reply.completed != requested_length
            || !reply.bytes.is_empty()
            || reply.evidence_sequence != sequence
            || !digest(&reply.resulting_version)
            || (sequence == 3 && reply.resulting_version != version)
        {
            return Err(DeliveryFailure::Unknown);
        }
        version = reply.resulting_version;
    }
    Ok(())
}

// Shared producer/consumer content contract only. This does not extend any
// native qualification, same-run or publication capability issuer.
use crate::filesystem_world::FilesystemObject;
use std::collections::BTreeMap;
#[derive(Debug, thiserror::Error)]
pub enum CodingContractError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
}
pub const CODING_PROFILE: &str = "realm.v7.coding-totals/v1";
/// Prelaunch native execution profile; its bytes are committed in CodingTools input bindings.
pub const NATIVE_EXECUTION_PROFILE: &str = include_str!("../native/coding_profile.json");
pub const TRANSFER_CONTRACT_DOMAIN: &str = "realm.v7.coding-transfer-contract.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingFileCommitment {
    pub path: String,
    pub content_blake3: String,
    pub bytes: u64,
    pub mode: u32,
}
/// Exact operator-reviewed expectation, also retained as canonical artifact
/// evidence `v7-coding-contract`. These fields are assertions until native
/// same-run verification succeeds. There are no commands or authority booleans.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingTransferContract {
    pub schema_version: u16,
    pub profile: String,
    pub submission: SubmissionContract,
    pub source_commit: String,
    pub semantic_commitment: String,
    pub files: [CodingFileCommitment; 3],
}
impl CodingTransferContract {
    pub fn validate(&self) -> Result<(), CodingContractError> {
        self.submission
            .validate()
            .map_err(CodingContractError::Invalid)?;
        if self.schema_version != 1
            || self.profile != CODING_PROFILE
            || self.source_commit.len() != 40
            || !self
                .source_commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !digest(&self.semantic_commitment)
        {
            return Err(CodingContractError::Invalid(
                "unsupported coding contract/profile/source/semantic identity",
            ));
        }
        for (file, path) in self.files.iter().zip(PATHS) {
            if file.path != path
                || file.mode != 0o600
                || file.bytes == 0
                || file.bytes > MAX_FILE as u64
                || !digest(&file.content_blake3)
            {
                return Err(CodingContractError::Invalid(
                    "unsupported coding file scope, order, mode or size",
                ));
            }
        }
        Ok(())
    }
    pub fn identity(&self) -> Result<String, CodingContractError> {
        self.validate()?;
        Ok(blake3::hash(
            &[
                TRANSFER_CONTRACT_DOMAIN.as_bytes(),
                &[0],
                &serde_json::to_vec(self)?,
            ]
            .concat(),
        )
        .to_hex()
        .to_string())
    }
    pub fn worlds(&self) -> Result<(String, String), CodingContractError> {
        self.validate()?;
        let before = blake3::hash(&serde_json::to_vec(
            &BTreeMap::<String, FilesystemObject>::new(),
        )?)
        .to_hex()
        .to_string();
        let entries: BTreeMap<_, _> = self
            .files
            .iter()
            .map(|f| {
                (
                    f.path.clone(),
                    FilesystemObject::File {
                        content_blake3: f.content_blake3.clone(),
                        mode: f.mode,
                    },
                )
            })
            .collect();
        Ok((
            before,
            blake3::hash(&serde_json::to_vec(&entries)?)
                .to_hex()
                .to_string(),
        ))
    }
}

/// Portable inputs for the canonical coding projection. Assertions only until
/// the sole publication issuer checks its same-run capability. Native world
/// roots are deliberately separate from destination projection roots.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingPublicationData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_evidence: Option<crate::coding_semantics::CodingSemanticEvidence>,
    pub contract: CodingTransferContract,
    pub submission: Vec<u8>,
    pub native_before: crate::filesystem_world::FilesystemWorld,
    pub native_after: crate::filesystem_world::FilesystemWorld,
}
impl CodingPublicationData {
    pub fn validate(&self) -> Result<(), CodingContractError> {
        self.contract.validate()?;
        if self
            .semantic_evidence
            .as_ref()
            .is_some_and(|s| !s.matches_data(self))
        {
            return Err(CodingContractError::Invalid(
                "coding semantic receipt differs",
            ));
        }
        let packet = self
            .contract
            .submission
            .decode(&self.submission)
            .map_err(CodingContractError::Invalid)?;
        for (file, expected) in packet.files.iter().zip(&self.contract.files) {
            if file.text.len() as u64 != expected.bytes
                || blake3::hash(file.text.as_bytes()).to_hex().as_str() != expected.content_blake3
                || file.mode != expected.mode
                || file.path != expected.path
            {
                return Err(CodingContractError::Invalid(
                    "native packet differs from approved coding projection",
                ));
            }
        }
        // The existing coding custodian writes one bounded packet to `output`.
        // Three destination creates must never be relabelled native I/O.
        let before = BTreeMap::from([(
            "output".into(),
            FilesystemObject::File {
                content_blake3: blake3::hash(b"").to_hex().to_string(),
                mode: 0o600,
            },
        )]);
        let after = BTreeMap::from([(
            "output".into(),
            FilesystemObject::File {
                content_blake3: blake3::hash(&self.submission).to_hex().to_string(),
                mode: 0o600,
            },
        )]);
        for (world, entries) in [(&self.native_before, before), (&self.native_after, after)] {
            if world.entries != entries
                || world.root
                    != blake3::hash(&serde_json::to_vec(&entries)?)
                        .to_hex()
                        .as_str()
            {
                return Err(CodingContractError::Invalid(
                    "unsupported native coding packet world",
                ));
            }
        }
        Ok(())
    }
    pub fn native_delta(&self) -> Result<String, CodingContractError> {
        self.validate()?;
        Ok(
            blake3::hash(&serde_json::to_vec(&crate::filesystem_world::delta(
                &self.native_before,
                &self.native_after,
            ))?)
            .to_hex()
            .to_string(),
        )
    }
}

#[cfg(test)]
mod admission_scope_tests {
    #[test]
    fn admission_is_committed_before_launch_without_changing_effect_privileges() {
        let legacy = crate::coding_semantics::tests::fixture()
            .semantic_evidence
            .unwrap()
            .prelaunch;
        let encoded = serde_json::to_value(&legacy).unwrap();
        assert!(encoded.get("runtime_admission_id").is_none());
        let decoded: super::CodingExecutionScope = serde_json::from_value(encoded).unwrap();
        assert_eq!(legacy, decoded);
        let mut admitted = legacy.clone();
        admitted.runtime_admission_id = Some("a".repeat(64));
        assert_eq!(
            legacy.policy_bytes().unwrap(),
            admitted.policy_bytes().unwrap()
        );
        assert_ne!(
            legacy.policy_identity().unwrap().task_blake3(),
            admitted.policy_identity().unwrap().task_blake3()
        );
        // The policy digest describes the unchanged effect restrictions;
        // the separate task digest commits the complete prelaunch scope.
        assert_eq!(
            legacy.policy_identity().unwrap().blake3(),
            admitted.policy_identity().unwrap().blake3()
        );
        admitted.runtime_admission_id = Some("untrusted label".into());
        assert!(admitted.validate().is_err());
    }
}
