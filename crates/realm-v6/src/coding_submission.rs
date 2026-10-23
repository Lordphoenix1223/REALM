//! Untrusted coding submission framing. Structural checks are not semantics,
//! measured execution, custody, closure, publication, or host authority.
//! The native diagnostic broker accepts exactly one bounded submission then Close.
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
