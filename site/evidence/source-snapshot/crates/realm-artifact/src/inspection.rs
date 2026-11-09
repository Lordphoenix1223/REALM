//! Read-only reporting over the existing verifier. Reports confer no authority.
use crate::{ArtifactBundle, ArtifactError, ValidationLevel};
use serde::Serialize;
use serde_json::{Value, json};
use std::{fs::OpenOptions, io::Read, path::Path};

pub const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
pub const REPORT_SCHEMA: &str = "realm.artifact-check.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Valid,
    Invalid,
    Incomplete,
    Unsupported,
    IoError,
}

#[derive(Debug, Serialize)]
pub struct Checks {
    pub artifact_integrity: &'static str,
    pub referenced_content: &'static str,
    pub observation_completeness: &'static str,
    pub execution_authorization: &'static str,
}

#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub schema: &'static str,
    pub checker_version: &'static str,
    pub status: Status,
    pub diagnostic: String,
    pub checks: Checks,
    pub metadata: Option<Value>,
}

impl CheckReport {
    pub fn exit_code(&self) -> i32 {
        match self.status {
            Status::Valid => 0,
            Status::Invalid => 1,
            Status::Incomplete => 3,
            Status::Unsupported => 4,
            Status::IoError => 5,
        }
    }

    fn new(status: Status, diagnostic: impl Into<String>) -> Self {
        Self {
            schema: REPORT_SCHEMA,
            checker_version: env!("CARGO_PKG_VERSION"),
            status,
            diagnostic: diagnostic.into(),
            checks: Checks {
                artifact_integrity: "NOT_CHECKED",
                referenced_content: "NOT_CHECKED",
                observation_completeness: "UNKNOWN",
                execution_authorization: "NOT_CHECKED",
            },
            metadata: None,
        }
    }
}

/// Read at most `limit` bytes from an opened regular file. Symlinks are followed.
///
/// Validate the held descriptor rather than a prior pathname lookup. On supported
/// Unix targets, nonblocking open prevents a replacement FIFO from hanging before
/// that check; O_NOCTTY also prevents acquisition of a controlling terminal.
/// This does not freeze contents against concurrent writes or establish custody.
pub fn read_regular_prefix(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("expected a regular input file"));
    }
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Check a local file without executing it, fetching content, or accepting trust pins.
pub fn check_file(path: &Path, require_execution: bool) -> CheckReport {
    match read_regular_prefix(path, MAX_ARTIFACT_BYTES + 1) {
        Ok(bytes) => check_bytes(&bytes, require_execution),
        Err(error) => CheckReport::new(Status::IoError, error.to_string()),
    }
}

/// Integrity/completeness are established by ArtifactBundle, not a second checker.
pub fn check_bytes(bytes: &[u8], require_execution: bool) -> CheckReport {
    if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
        return CheckReport::new(
            Status::Unsupported,
            "reader limit is 64 MiB; use a smaller supported bundle",
        );
    }
    if bytes.starts_with(b"REALM-PORTABLE-")
        && let Some(end) = bytes.iter().take(64).position(|byte| *byte == b'\n')
        && &bytes[..=end] != b"REALM-PORTABLE-3\n"
    {
        return CheckReport::new(
            Status::Unsupported,
            "unsupported portable format; this reader supports REALM-PORTABLE-3 (schema 3)",
        );
    }
    let bundle = match ArtifactBundle::unpack(bytes) {
        Ok(bundle) => bundle,
        Err(ArtifactError::Invalid(message)) if message == "unsupported schema" => {
            return CheckReport::new(
                Status::Unsupported,
                "unsupported run schema; this reader supports schema 3",
            );
        }
        Err(error) => {
            let mut report = CheckReport::new(Status::Invalid, error.to_string());
            report.checks.artifact_integrity = "FAIL";
            return report;
        }
    };
    let mut report = CheckReport::new(
        Status::Valid,
        "artifact integrity and referenced content checked; observer honesty and execution authorization are not established",
    );
    report.checks.artifact_integrity = "PASS";
    report.metadata = Some(json!({
        "input_blake3": blake3::hash(bytes).to_hex().to_string(),
        "format": "REALM-PORTABLE-3", "schema_version": bundle.run.schema_version,
        "semantic_identity": bundle.semantic_identity().expect("unpack validated integrity"),
        "transport_identity": bundle.transport_identity().expect("unpack validated integrity"),
        "run": bundle.run.run, "lifecycle": bundle.run.lifecycle,
        "environment": bundle.run.environment, "intent": bundle.run.intent,
        "inputs": bundle.run.inputs, "outputs": bundle.run.outputs,
        "checkpoints": bundle.run.checkpoints.len(), "observations": bundle.run.observations,
        "proposed_effects": bundle.run.proposed_effects, "evidence": bundle.run.evidence,
        "unknown_effects": bundle.run.unknown_effects,
        "reported_verification": bundle.envelope.verification,
        "reported_publication": bundle.envelope.publication,
        "content_mode": bundle.envelope.content, "local_blobs": bundle.blobs.len(),
        "attestations": bundle.envelope.attestations.len(),
    }));
    match bundle.validate_at(ValidationLevel::ContentComplete) {
        Ok(()) => report.checks.referenced_content = "COMPLETE",
        Err(ArtifactError::MissingBlob(_)) => {
            report.status = Status::Incomplete;
            report.checks.referenced_content = "INCOMPLETE";
            report.diagnostic = "included bytes passed integrity checks, but referenced content is missing; no network resolution was attempted".into();
        }
        Err(error) => {
            report.status = Status::Invalid;
            report.checks.referenced_content = "FAIL";
            report.diagnostic = error.to_string();
        }
    }
    if require_execution && report.status == Status::Valid {
        report.status = Status::Incomplete;
        report.diagnostic = "artifact content checked, but this read-only interface cannot establish execution authorization; use the qualified pipeline and independently provisioned trust pins".into();
    }
    report
}
