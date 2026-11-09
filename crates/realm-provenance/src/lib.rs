//! Reproducibility fingerprints and tamper-evident artifact attestations.
//!
//! An attestation is a digest over the result payload and the environment
//! fingerprint. It detects accidental or post-hoc artifact changes; it is not
//! a signature and does not establish trust against a writer who can replace
//! both the artifact and its digest.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProvenanceStatus {
    Complete,
    Incomplete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceContext {
    pub backend: String,
    pub fixture_id: Option<String>,
    pub seed: Option<u64>,
    pub started_at_unix_ms: Option<i64>,
    pub duration_ms: Option<u64>,
    pub live_capture_relevant: bool,
}

impl ProvenanceContext {
    pub fn synthetic(backend: impl Into<String>) -> Self {
        Self {
            backend: backend.into(),
            fixture_id: None,
            seed: None,
            started_at_unix_ms: None,
            duration_ms: None,
            live_capture_relevant: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentFingerprint {
    pub schema_version: u16,
    pub provenance_status: ProvenanceStatus,
    pub incomplete_fields: Vec<String>,
    pub git_commit: Option<String>,
    pub git_dirty: Option<bool>,
    pub git_diff_hash: Option<String>,
    pub realm_version: String,
    pub rustc_version: String,
    pub cargo_version: String,
    pub cargo_lock_hash: Option<String>,
    pub os: String,
    pub os_version: String,
    pub kernel: String,
    pub architecture: String,
    pub hardware: String,
    pub filesystem: String,
    pub mount: String,
    pub xcode_version: String,
    pub sdk_path: String,
    pub sdk_version: String,
    pub capture_backend: String,
    pub endpoint_security_api: BTreeMap<String, String>,
    pub codesign_identity: String,
    pub entitlements: BTreeMap<String, String>,
    pub tcc_fda_state: String,
    pub fixture_id: Option<String>,
    pub seed: Option<u64>,
    pub started_at_unix_ms: Option<i64>,
    pub duration_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttestedArtifact<T> {
    pub schema_version: u16,
    pub artifact_hash: String,
    pub commit_identity: Option<String>,
    pub provenance_status: ProvenanceStatus,
    pub environment: EnvironmentFingerprint,
    pub payload: T,
}

#[derive(Debug, Error)]
pub enum ProvenanceError {
    #[error("provenance serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("provenance I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub fn collect(context: &ProvenanceContext) -> EnvironmentFingerprint {
    let repo = repository_root();
    let status_output = repo
        .as_ref()
        .and_then(|root| git_output(root, &["status", "--porcelain=v1"]));
    let git_commit = repo
        .as_ref()
        .and_then(|root| git_output(root, &["rev-parse", "HEAD"]));
    let git_dirty = status_output.as_ref().map(|status| !status.is_empty());
    let git_diff_hash = repo.as_ref().and_then(|root| git_state_hash(root));
    let cargo_lock_hash = repo.as_ref().and_then(|root| {
        fs::read(root.join("Cargo.lock"))
            .ok()
            .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
    });

    let sdk_path = command_output("xcrun", &["--sdk", "macosx", "--show-sdk-path"]);
    let sdk_headers = Path::new(&sdk_path).join("usr/include/EndpointSecurity");
    let standard_es = sdk_headers.join("ESClient.h").exists();
    let descendants = read_header_contains(&sdk_headers, "es_new_descendants_client");
    let retain = read_header_contains(&sdk_headers, "es_retain_message");
    let mut endpoint_security_api = BTreeMap::new();
    endpoint_security_api.insert("standard_client_header".into(), bool_text(standard_es));
    endpoint_security_api.insert("descendants_client_header".into(), bool_text(descendants));
    endpoint_security_api.insert("message_retention_header".into(), bool_text(retain));

    let mut entitlements = BTreeMap::new();
    entitlements.insert(
        "com.apple.developer.endpoint-security.client".into(),
        "NOT_PROVEN".into(),
    );
    let mut incomplete_fields = Vec::new();
    if git_commit.is_none() {
        incomplete_fields.push("git_commit".into());
    }
    if cargo_lock_hash.is_none() {
        incomplete_fields.push("cargo_lock_hash".into());
    }
    if context.live_capture_relevant {
        incomplete_fields.push("tcc_fda_state".into());
    }

    EnvironmentFingerprint {
        schema_version: 2,
        provenance_status: if incomplete_fields.is_empty() {
            ProvenanceStatus::Complete
        } else {
            ProvenanceStatus::Incomplete
        },
        incomplete_fields,
        git_commit,
        git_dirty,
        git_diff_hash,
        realm_version: env!("CARGO_PKG_VERSION").into(),
        rustc_version: command_output("rustc", &["--version"]),
        cargo_version: command_output("cargo", &["--version"]),
        cargo_lock_hash,
        os: std::env::consts::OS.into(),
        os_version: command_output("sw_vers", &["-productVersion"]),
        kernel: command_output("uname", &["-srvm"]),
        architecture: std::env::consts::ARCH.into(),
        hardware: command_output("sysctl", &["-n", "hw.model"]),
        filesystem: command_output("df", &["-T", "."]),
        mount: command_output("mount", &[]),
        xcode_version: command_output("xcodebuild", &["-version"]),
        sdk_path: sdk_path.clone(),
        sdk_version: sdk_path.rsplit('/').next().unwrap_or("unknown").into(),
        capture_backend: context.backend.clone(),
        endpoint_security_api,
        codesign_identity: current_codesign_identity(),
        entitlements,
        tcc_fda_state: if context.live_capture_relevant {
            "NOT_INSPECTED".into()
        } else {
            "NOT_APPLICABLE_SYNTHETIC".into()
        },
        fixture_id: context.fixture_id.clone(),
        seed: context.seed,
        started_at_unix_ms: context.started_at_unix_ms,
        duration_ms: context.duration_ms,
    }
}

pub fn attest<T: Serialize>(
    payload: &T,
    environment: EnvironmentFingerprint,
) -> Result<AttestedArtifact<Value>, ProvenanceError> {
    let payload = serde_json::to_value(payload)?;
    let commit_identity = environment.git_commit.clone();
    let material = serde_json::json!({
        "payload": payload,
        "environment": environment,
        "commit_identity": commit_identity,
    });
    let canonical = canonical_json_bytes(&material)?;
    let artifact_hash = blake3::hash(&canonical).to_hex().to_string();
    let environment = material["environment"].clone();
    let environment: EnvironmentFingerprint = serde_json::from_value(environment)?;
    let payload = material["payload"].clone();
    Ok(AttestedArtifact {
        schema_version: 1,
        artifact_hash,
        commit_identity,
        provenance_status: environment.provenance_status,
        environment,
        payload,
    })
}

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, ProvenanceError> {
    Ok(serde_json::to_vec(&canonicalize(value))?)
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut sorted = Map::new();
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            for (key, value) in entries {
                sorted.insert(key.clone(), canonicalize(value));
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

fn repository_root() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    git_output(&cwd, &["rev-parse", "--show-toplevel"]).map(PathBuf::from)
}

fn git_output(root: &Path, args: &[&str]) -> Option<String> {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().into())
}

fn git_bytes(root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| output.stdout)
}

fn git_state_hash(root: &Path) -> Option<String> {
    let mut bytes = git_bytes(root, &["diff", "--binary"])?;
    if let Some(staged) = git_bytes(root, &["diff", "--cached", "--binary"]) {
        bytes.extend_from_slice(&staged);
    }
    if let Some(status) = git_output(root, &["status", "--porcelain=v1"]) {
        // Include the dirty file set even when the repository has no commit
        // yet and `git diff` is necessarily empty.
        bytes.extend_from_slice(status.as_bytes());
    }
    if let Some(untracked) = git_bytes(root, &["ls-files", "--others", "--exclude-standard", "-z"])
    {
        for relative in untracked
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
        {
            let relative = Path::new(std::str::from_utf8(relative).unwrap_or_default());
            if generated_artifact(relative) {
                continue;
            }
            let absolute = root.join(relative);
            if let Ok(contents) = fs::read(&absolute) {
                bytes.extend_from_slice(relative.as_os_str().to_string_lossy().as_bytes());
                bytes.extend_from_slice(&contents);
            }
        }
    }
    Some(blake3::hash(&bytes).to_hex().to_string())
}

fn generated_artifact(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(
            "LIVE_CAPTURE_REPORT.md"
                | "LIVE_CAPTURE_BLOCKER.md"
                | "realm-bench-results.json"
                | "realm-live-results.json"
                | "capture-conformance.json"
                | "event-support-matrix.json"
                | "authorization-latency.json"
                | "preimage-race-results.json"
                | "storage-results.json"
                | "process-attribution-results.json"
                | "crash-results.json"
                | "capability-matrix.json"
        )
    )
}

fn current_codesign_identity() -> String {
    let executable = std::env::current_exe().unwrap_or_default();
    let output = Command::new("codesign")
        .args(["-d", "--verbose=4"])
        .arg(executable)
        .output();
    output
        .ok()
        .map(|output| {
            let stderr = String::from_utf8_lossy(&output.stderr);
            stderr
                .lines()
                .find(|line| line.starts_with("Authority="))
                .unwrap_or("UNSIGNED_OR_UNKNOWN")
                .into()
        })
        .unwrap_or_else(|| "UNAVAILABLE".into())
}

fn read_header_contains(directory: &Path, needle: &str) -> bool {
    fs::read_dir(directory)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read(entry.path()).ok())
        .any(|bytes| String::from_utf8_lossy(&bytes).contains(needle))
}

fn bool_text(value: bool) -> String {
    value.to_string()
}

fn command_output(command: &str, args: &[&str]) -> String {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .replace('\n', " | ")
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unavailable".into())
}

pub fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_attestation_is_order_independent() {
        let first = serde_json::json!({"z": 1, "a": {"d": 4, "b": 2}});
        let second = serde_json::json!({"a": {"b": 2, "d": 4}, "z": 1});
        assert_eq!(
            canonical_json_bytes(&first).unwrap(),
            canonical_json_bytes(&second).unwrap()
        );
    }

    #[test]
    fn missing_git_commit_is_explicitly_incomplete() {
        let mut fingerprint = collect(&ProvenanceContext::synthetic("test"));
        fingerprint.git_commit = None;
        fingerprint.provenance_status = ProvenanceStatus::Incomplete;
        fingerprint.incomplete_fields.push("git_commit".into());
        let artifact = attest(&serde_json::json!({"ok": true}), fingerprint).unwrap();
        assert_eq!(artifact.provenance_status, ProvenanceStatus::Incomplete);
        assert!(!artifact.artifact_hash.is_empty());
    }
}
