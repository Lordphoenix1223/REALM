//! Independent runtime admission is a separate deployment trust input, NOT a
//! run proof. No reviewer keys are registered by default. Candidate/planner
//! inputs cannot supply a key, crypto executable or policy extension.
use crate::{coding_semantics, coding_submission::CodingExecutionScope};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};
#[cfg(any(test, feature = "test-support"))]
mod fixtures;
pub mod inputs;
pub(crate) mod installed;
#[cfg(target_os = "linux")]
pub(crate) use installed::protected_running_supervisor;
mod observations;
#[cfg(any(test, feature = "test-support"))]
pub use fixtures::{FixtureBundle, FixtureCandidate, finish_fixture, fixture_candidate};
#[cfg(any(test, feature = "test-support"))]
pub use installed::{
    check_fixture_installed_statement, fixture_check_executable, fixture_issue_installed_statement,
    inspect_fixture_setup,
};

const DOMAIN: &str = "realm.native-runtime-admission/v1";
const SIGNING_PREFIX: &[u8] = b"REALM::IndependentRuntimeAdmission/v1\0";
const MAX_POLICY: usize = 128 * 1024;
type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTuple {
    pub source_commit: String,
    pub task_sha256: String,
    pub worker_sha256: String,
    pub checker_sha256: String,
    pub checker_scope_sha256: String,
    pub native_controller_blake3: String,
    pub controller_policy_blake3: String,
    pub stage_blake3: String,
    pub jailer_blake3: String,
    pub vmm_blake3: String,
    pub kernel_blake3: String,
    pub rootfs_blake3: String,
    pub checker_python_blake3: String,
    pub checker_bwrap_blake3: String,
    pub checker_sources: BTreeMap<String, String>,
    pub kernel_release: String,
    pub kernel_version: String,
    pub machine: String,
    pub landlock_abi: u32,
    pub vmm_uid: u32,
    pub vmm_gid: u32,
    pub memory_max_bytes: u64,
    pub pids_max: u32,
    pub cpu_max: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBuildReview {
    pub schema: String,
    pub source_commit: String,
    pub cargo_lock_blake3: String,
    /// Externally reviewed compiler/linker/input identities. They are not
    /// observations made by the execution process after compilation.
    pub build_inputs: BTreeMap<String, String>,
    pub review_evidence_blake3: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAdmissionPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_input_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_inputs: Option<inputs::NativeTaskInputs>,
    pub schema_version: u16,
    pub authorization_domain: String,
    pub profile_source_blake3: String,
    pub semantic_scope: String,
    pub excluded_claims: Vec<String>,
    pub expected: RuntimeTuple,
    pub build: RuntimeBuildReview,
    pub official_campaign_blake3: String,
    pub nonce: String,
    pub not_before_unix: u64,
    pub expires_at_unix: u64,
}
/// Signed trust data. Parsing this value does not verify it, select a trusted
/// reviewer or construct any native execution/publication capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRuntimeAdmission {
    pub schema: String,
    pub reviewer_key_id: String,
    pub policy_json: String,
    pub signature_hex: String,
}
struct Reviewer<'a> {
    id: &'a str,
    public_key_pem: &'a [u8],
    crypto_path: &'a str,
    crypto_blake3: &'a str,
}
// Provisioning the autonomous supervisor authority is a privileged setup decision.
// Never populate from a candidate, environment variable, local test key or a
// self-supplied policy. No production authority has been provisioned here.
const REVIEWERS: &[Reviewer<'static>] = &[];

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.contains('\0')
}
fn string(value: &Value, name: &str) -> Result<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|v| text(v))
        .map(str::to_owned)
        .ok_or_else(|| format!("missing actual runtime field: {name}"))
}
fn file_digest(value: &Value) -> Result<String> {
    let result = string(value, "blake3")?;
    if !digest(&result) {
        return Err("invalid actual file digest".into());
    }
    Ok(result)
}
pub fn profile_source_root() -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"REALM::FixedCodingProfileSources/v1\0");
    for bytes in [
        include_bytes!("../native/coding_profile.json").as_slice(),
        include_bytes!("../native/coding_fence.c").as_slice(),
        include_bytes!("controller_guard.rs").as_slice(),
        include_bytes!("runtime_admission.rs").as_slice(),
        include_bytes!("runtime_admission/observations.rs").as_slice(),
        include_bytes!("runtime_admission/installed.rs").as_slice(),
        include_bytes!("runtime_admission/inputs.rs").as_slice(),
        include_bytes!("native_workflow.rs").as_slice(),
        include_bytes!("coding_runtime/attempt_history.rs").as_slice(),
    ] {
        h.update(&(bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    h.finalize().to_hex().to_string()
}
impl RuntimeTuple {
    pub fn validate(&self) -> Result<()> {
        let digests = [
            &self.task_sha256,
            &self.worker_sha256,
            &self.checker_sha256,
            &self.checker_scope_sha256,
            &self.native_controller_blake3,
            &self.controller_policy_blake3,
            &self.stage_blake3,
            &self.jailer_blake3,
            &self.vmm_blake3,
            &self.kernel_blake3,
            &self.rootfs_blake3,
            &self.checker_python_blake3,
            &self.checker_bwrap_blake3,
        ];
        if self.source_commit.len() != 40
            || !self
                .source_commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || digests.iter().any(|v| !digest(v))
            || !text(&self.kernel_release)
            || !text(&self.kernel_version)
            || self.machine != "x86_64"
            || self.landlock_abi < 3
            || self.vmm_uid == 0
            || self.vmm_gid == 0
            || self.memory_max_bytes == 0
            || self.pids_max == 0
            || !text(&self.cpu_max)
            || self.checker_sources.len() != crate::coding_referee::COMPILED_SOURCES.len()
        {
            return Err("unsupported runtime tuple".into());
        }
        for (name, bytes) in crate::coding_referee::COMPILED_SOURCES {
            if self.checker_sources.get(name).map(String::as_str)
                != Some(blake3::hash(bytes).to_hex().as_str())
            {
                return Err("unsupported checker source tuple".into());
            }
        }
        Ok(())
    }
    /// Derive identity ONLY from the full native-generated observation record.
    /// This is also usable on detached data, but is not an admission operation.
    pub fn from_observations(record: &Value, scope: &CodingExecutionScope) -> Result<Self> {
        if record["domain"] != "realm.native-coding-provenance/v2"
            || record["scope"] != serde_json::to_value(scope).map_err(|e| e.to_string())?
        {
            return Err("native observation scope differs".into());
        }
        let raw = record["resources_raw_json"]
            .as_str()
            .ok_or("original resource JSON missing")?;
        if raw.len() > 512 * 1024
            || record["resources_root"] != blake3::hash(raw.as_bytes()).to_hex().as_str()
        {
            return Err("original resource bytes differ".into());
        }
        let resources =
            crate::strict_json::parse(raw.as_bytes()).map_err(|_| "invalid resource JSON")?;
        let resource = resources
            .as_array()
            .filter(|r| r.len() == 5 && r[0] == "realm.actual-vmm-resources/v1")
            .ok_or("unsupported resource record")?;
        let referee = &record["referee_identity_record"];
        if !(scope.native_subtask.is_some()
            && referee["domain"] == "realm.owned-coding-task-refusal/v1")
            && referee["domain"]
                != if scope
                    .native_subtask
                    .as_ref()
                    .is_some_and(|s| s.role == crate::native_workflow::NativeTaskRole::Api)
                {
                    "realm.owned-native-api-check/v1"
                } else {
                    "realm.owned-coding-task-check/v2"
                }
        {
            return Err("referee domain differs".into());
        }
        let mut sources = BTreeMap::new();
        for item in referee["sources"]
            .as_array()
            .filter(|v| v.len() == crate::coding_referee::COMPILED_SOURCES.len())
            .ok_or("checker source inventory missing")?
        {
            let pair = item
                .as_array()
                .filter(|v| v.len() == 2)
                .ok_or("checker source pair differs")?;
            let name = Path::new(pair[0].as_str().ok_or("checker source path missing")?)
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or("checker source name missing")?;
            if sources
                .insert(name.to_owned(), file_digest(&pair[1])?)
                .is_some()
            {
                return Err("duplicate checker source".into());
            }
        }
        let host = &record["host"];
        if host["sysname"] != "Linux" {
            return Err("unsupported host kernel".into());
        }
        let integer = |v: &Value| {
            v.as_u64()
                .and_then(|x| u32::try_from(x).ok())
                .ok_or("runtime integer missing".to_owned())
        };
        let tuple = Self {
            source_commit: scope.source_commit.clone(),
            task_sha256: scope.submission.task_sha256.clone(),
            worker_sha256: scope.submission.worker_sha256.clone(),
            checker_sha256: scope.checker_sha256.clone(),
            checker_scope_sha256: scope.checker_scope_sha256.clone(),
            native_controller_blake3: file_digest(&record["controller"])?,
            controller_policy_blake3: string(record, "controller_policy_blake3")?,
            stage_blake3: file_digest(&record["fence"]["stage"])?,
            jailer_blake3: file_digest(&record["containment"]["jailer"])?,
            vmm_blake3: file_digest(&record["fence"]["official"])?,
            kernel_blake3: file_digest(&resource[2])?,
            rootfs_blake3: file_digest(&resource[3])?,
            checker_python_blake3: file_digest(&referee["python"])?,
            checker_bwrap_blake3: file_digest(&referee["bwrap"])?,
            checker_sources: sources,
            kernel_release: string(host, "release")?,
            kernel_version: string(host, "version")?,
            machine: string(host, "machine")?,
            landlock_abi: integer(&host["landlock_abi"])?,
            vmm_uid: integer(&record["containment"]["uid"])?,
            vmm_gid: integer(&record["containment"]["gid"])?,
            memory_max_bytes: record["containment"]["cgroup"]["memory_max_bytes"]
                .as_u64()
                .ok_or("memory bound missing")?,
            pids_max: integer(&record["containment"]["cgroup"]["pids_max"])?,
            cpu_max: string(&record["containment"]["cgroup"], "cpu_max")?,
        };
        tuple.validate()?;
        Ok(tuple)
    }
}
impl RuntimeAdmissionPolicy {
    pub fn input_policy_root(&self) -> Result<String> {
        let mut template = self.clone();
        template.task_inputs = None;
        template.nonce = "0".repeat(64);
        template.not_before_unix = 0;
        template.expires_at_unix = 1;
        Ok(
            blake3::hash(&serde_json::to_vec(&template).map_err(|e| e.to_string())?)
                .to_hex()
                .to_string(),
        )
    }
    pub fn validate(&self) -> Result<()> {
        self.expected.validate()?;
        if self
            .task_input_protocol
            .as_ref()
            .is_some_and(|p| p != &inputs::protocol_root())
            || self.task_inputs.is_some() && self.task_input_protocol.is_none()
        {
            return Err("unreviewed task input protocol".into());
        }
        if let Some(inputs) = &self.task_inputs {
            inputs.validate_policy(self)?;
        }

        if self.schema_version != 1
            || self.authorization_domain != DOMAIN
            || self.profile_source_blake3 != profile_source_root()
            || self.semantic_scope != coding_semantics::SCOPE
            || self.excluded_claims != coding_semantics::EXCLUDED
            || self.build.schema != "realm.runtime-build-review/v1"
            || self.build.source_commit != self.expected.source_commit
            || self.build.cargo_lock_blake3
                != blake3::hash(include_bytes!("../../../Cargo.lock"))
                    .to_hex()
                    .as_str()
            || self.build.build_inputs.is_empty()
            || self.build.build_inputs.len() > 64
            || self
                .build
                .build_inputs
                .iter()
                .any(|(k, v)| !text(k) || !digest(v))
            || ![
                &self.build.review_evidence_blake3,
                &self.official_campaign_blake3,
                &self.nonce,
            ]
            .iter()
            .all(|v| digest(v))
            || self.expires_at_unix <= self.not_before_unix
            || self.expires_at_unix - self.not_before_unix > 86400
        {
            return Err("unsupported admission domain/profile/build/claims/window".into());
        }
        Ok(())
    }
    pub fn permits_time(&self, now: u64) -> bool {
        self.not_before_unix <= now && now < self.expires_at_unix
    }
}
impl SignedRuntimeAdmission {
    pub fn identity(&self) -> Result<String> {
        let raw = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if raw.len() > MAX_POLICY * 2 {
            return Err("admission envelope bound".into());
        }
        let mut h = blake3::Hasher::new();
        h.update(b"REALM::SignedRuntimeAdmission/v1\0");
        h.update(&raw);
        Ok(h.finalize().to_hex().to_string())
    }
    pub fn policy(&self) -> Result<RuntimeAdmissionPolicy> {
        if self.schema != "realm.signed-runtime-admission/v1"
            || !digest(&self.reviewer_key_id)
            || self.policy_json.is_empty()
            || self.policy_json.len() > MAX_POLICY
            || self.signature_hex.len() != 768
            || !self
                .signature_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("unsupported admission envelope".into());
        }
        let value = crate::strict_json::parse(self.policy_json.as_bytes())
            .map_err(|_| "invalid admission JSON")?;
        let policy: RuntimeAdmissionPolicy =
            serde_json::from_value(value).map_err(|e| e.to_string())?;
        policy.validate()?;
        if policy.task_input_protocol.is_some() && policy.task_inputs.is_none() {
            return Err("admission omitted original task inputs".into());
        }
        Ok(policy)
    }
    /// Verify an independently source-registered admission authority. No runtime
    /// input can configure a reviewer key or crypto program. A signature attests
    /// the admission statement, never the current run's physical observations.
    pub fn verify(&self) -> Result<RuntimeAdmissionPolicy> {
        let policy = self.policy()?;
        let Some(key) = REVIEWERS.iter().find(|k| k.id == self.reviewer_key_id) else {
            return installed::InstalledAuthority::load()?.verify(self);
        };
        if blake3::hash(key.public_key_pem).to_hex().as_str() != key.id {
            return Err("invalid reviewer registration".into());
        }
        verify_signature(self, key)?;
        Ok(policy)
    }
}

/// Verified setup-provisioned admission, deliberately not serializable and not
/// constructible from receipt data or fixture trust. The installed authority
/// may automate policy issuance; no human action is required per execution.
pub struct ReviewedRuntimeAdmission {
    envelope: SignedRuntimeAdmission,
    policy: RuntimeAdmissionPolicy,
    admitted_at_unix: u64,
    identity: String,
}
impl ReviewedRuntimeAdmission {
    pub fn identity(&self) -> &str {
        &self.identity
    }
    pub fn policy(&self) -> &RuntimeAdmissionPolicy {
        &self.policy
    }
    pub fn admitted_at_unix(&self) -> u64 {
        self.admitted_at_unix
    }
    pub fn envelope(&self) -> &SignedRuntimeAdmission {
        &self.envelope
    }
}
impl SignedRuntimeAdmission {
    pub fn admit_now(&self) -> Result<ReviewedRuntimeAdmission> {
        let policy = self.verify()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        if !policy.permits_time(now) {
            return Err("runtime admission outside permitted window".into());
        }
        Ok(ReviewedRuntimeAdmission {
            envelope: self.clone(),
            policy,
            admitted_at_unix: now,
            identity: self.identity()?,
        })
    }
}

fn verify_signature(value: &SignedRuntimeAdmission, key: &Reviewer<'_>) -> Result<()> {
    use crate::measured_launch::FileIdentity;
    use std::{
        fs::{self, File, OpenOptions},
        io::Write,
        os::unix::fs::OpenOptionsExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let crypto = Path::new(key.crypto_path);
    if !crypto.is_absolute()
        || fs::metadata(crypto).map_err(|e| e.to_string())?.len() > 32 * 1024 * 1024
    {
        return Err("trusted admission crypto unavailable".into());
    }
    let before = FileIdentity::measure(crypto).map_err(|e| format!("crypto identity: {e:?}"))?;
    if before.owner() != (0, 0)
        || !before.trusted_parent_chain()
        || before.mode() & 0o022 != 0
        || before.blake3() != key.crypto_blake3
        || key.public_key_pem.len() > 16384
    {
        return Err("admission crypto source pin differs".into());
    }
    let root = private_scratch_path("realm-admission")?;
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let scratch = Scratch(root);
    let write = |name: &str, bytes: &[u8]| -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(scratch.0.join(name))
            .map_err(|e| e.to_string())?;
        f.write_all(bytes).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())
    };
    let signature: Vec<u8> = value
        .signature_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("checked ASCII"), 16)
                .expect("checked hex")
        })
        .collect();
    let body = signing_bytes(&value.policy_json);
    write("reviewer.pem", key.public_key_pem)?;
    write("signature", &signature)?;
    write("statement", &body)?;
    // Enforce the fixed RSA-3072 suite, including key type and modulus width.
    let modulus_path = scratch.0.join("modulus");
    let modulus_output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&modulus_path)
        .map_err(|e| e.to_string())?;
    let mut modulus_child = Command::new(crypto)
        .args(["rsa", "-pubin", "-modulus", "-noout", "-in"])
        .arg(scratch.0.join("reviewer.pem"))
        .env_clear()
        .env("LC_ALL", "C")
        .env("OPENSSL_CONF", "/dev/null")
        .stdin(Stdio::null())
        .stdout(modulus_output)
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let modulus_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match modulus_child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(None) if Instant::now() < modulus_deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            other => {
                let _ = modulus_child.kill();
                let _ = modulus_child.wait();
                return Err(format!("RSA key suite refused: {other:?}"));
            }
        }
    }
    if fs::metadata(&modulus_path)
        .map_err(|e| e.to_string())?
        .len()
        > 1024
    {
        return Err("RSA modulus output bound".into());
    }
    let modulus = fs::read_to_string(&modulus_path).map_err(|e| e.to_string())?;
    let modulus = modulus
        .trim()
        .strip_prefix("Modulus=")
        .ok_or("RSA modulus unavailable")?;
    if modulus.len() != 768
        || !modulus.bytes().all(|b| b.is_ascii_hexdigit())
        || !matches!(modulus.as_bytes()[0], b'8'..=b'9' | b'A'..=b'F' | b'a'..=b'f')
    {
        return Err("RSA-3072 key required".into());
    }
    let mut child = Command::new(crypto)
        .args(["dgst", "-sha256", "-verify"])
        .arg(scratch.0.join("reviewer.pem"))
        .arg("-signature")
        .arg(scratch.0.join("signature"))
        .env_clear()
        .env("LC_ALL", "C")
        .env("OPENSSL_CONF", "/dev/null")
        .stdin(File::open(scratch.0.join("statement")).map_err(|e| e.to_string())?)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            other => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("admission crypto timeout/wait failure: {other:?}"));
            }
        }
    };
    if !status.success()
        || FileIdentity::measure(crypto).map_err(|e| format!("crypto changed: {e:?}"))? != before
    {
        return Err("admission signature or crypto identity refused".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn data_tuple_requires_the_complete_compiled_referee_source_catalog() {
        let original = super::fixtures::fixture_candidate().policy.expected;
        assert!(original.validate().is_ok());
        assert_eq!(
            original.checker_sources.len(),
            crate::coding_referee::COMPILED_SOURCES.len()
        );
        let mut missing = original.clone();
        missing
            .checker_sources
            .remove("development_task_oracles.py");
        assert!(missing.validate().is_err());
        let mut changed = original.clone();
        changed
            .checker_sources
            .insert("development_task_oracles.py".into(), "0".repeat(64));
        assert!(changed.validate().is_err());
        let mut extra = original;
        extra
            .checker_sources
            .insert("candidate_selected.py".into(), "0".repeat(64));
        assert!(extra.validate().is_err());
    }
    #[test]
    fn no_runtime_input_can_provision_an_authority() {
        assert!(REVIEWERS.is_empty());
        let value = SignedRuntimeAdmission {
            schema: "realm.signed-runtime-admission/v1".into(),
            reviewer_key_id: "a".repeat(64),
            policy_json: "{}".into(),
            signature_hex: "0".repeat(768),
        };
        assert!(value.verify().is_err());
        assert!(
            serde_json::from_value::<SignedRuntimeAdmission>(serde_json::json!({
            "schema":value.schema,"reviewer_key_id":value.reviewer_key_id,"policy_json":"{}",
            "signature_hex":value.signature_hex,"trusted":true}))
            .is_err()
        );
    }
    #[test]
    fn sparse_diagnostic_records_cannot_be_runtime_admission_tuples() {
        let scope = crate::coding_semantics::tests::fixture()
            .semantic_evidence
            .unwrap()
            .prelaunch;
        assert!(
            RuntimeTuple::from_observations(
                &serde_json::json!({"domain":"realm.native-coding-provenance/v2","scope":scope}),
                &scope
            )
            .is_err()
        );
    }
}

/// The exact signed payload, shared with independent (including fixture-only)
/// signers. No signer or private key is implemented by this crate.
pub fn signing_bytes(policy_json: &str) -> Vec<u8> {
    let mut value = SIGNING_PREFIX.to_vec();
    value.extend_from_slice(policy_json.as_bytes());
    value
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationEvidence {
    pub schema_version: u16,
    pub admission: SignedRuntimeAdmission,
    pub admission_identity: String,
    pub observed_runtime: RuntimeTuple,
    pub observation_root: String,
    pub admitted_at_unix: u64,
    pub qualified_at_unix: u64,
}
impl QualificationEvidence {
    pub fn identity(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if bytes.len() > 512 * 1024 {
            return Err("qualification material bound".into());
        }
        let mut h = blake3::Hasher::new();
        h.update(b"REALM::NativeRuntimeQualification/v1\0");
        h.update(&bytes);
        Ok(h.finalize().to_hex().to_string())
    }
    /// Complete DATA binding checks only. No signature trust or physical
    /// observation is reconstructed by this method.
    pub fn matches_data(
        &self,
        receipt: &coding_semantics::CodingSemanticEvidence,
        permitted: &SignedRuntimeAdmission,
    ) -> Result<()> {
        let scope = &receipt.prelaunch;
        scope.validate().map_err(str::to_owned)?;
        let policy = self.admission.policy()?;
        let actual = receipt
            .runtime_provenance_record
            .as_ref()
            .ok_or("complete native observations missing")?;
        observations::validate(actual, scope)?;
        match (
            &self.admission.policy()?.task_inputs,
            &scope.task_inputs_blake3,
        ) {
            (None, None) => {}
            (Some(inputs), Some(_)) if inputs.matches_scope(scope) => {}
            _ => return Err("qualified task input/run/predecessor binding differs".into()),
        }

        if self.schema_version != 1
            || &self.admission != permitted
            || self.admission_identity != self.admission.identity()?
            || scope.runtime_admission_id.as_ref() != Some(&self.admission_identity)
            || self.admitted_at_unix > self.qualified_at_unix
            || !policy.permits_time(self.admitted_at_unix)
            || !policy.permits_time(self.qualified_at_unix)
            || self.observation_root
                != blake3::hash(&serde_json::to_vec(actual).map_err(|e| e.to_string())?)
                    .to_hex()
                    .as_str()
            || self.observed_runtime != RuntimeTuple::from_observations(actual, scope)?
            || self.observed_runtime != policy.expected
            || self.identity()? != receipt.provenance_root
        {
            return Err("qualification/admission/actual tuple binding differs".into());
        }
        let referee = &actual["referee_identity_record"];
        if receipt.referee_identity_record.as_ref() != Some(referee)
            || actual["referee_root"] != receipt.referee_root
            || actual["measurement"] != receipt.measurement_root
            || actual["frontier"] != receipt.frontier_root
            || actual["barrier"] != receipt.barrier_root
            || referee["native_custody"] != receipt.custody_root
            || referee["broker_completion"] != receipt.broker_completion_root
            || referee["request_blake3"] != receipt.consumed_request_blake3
            || referee["packet"] != receipt.packet_blake3
        {
            return Err("qualified receipt joins another subject/custody/run".into());
        }
        Ok(())
    }
}
/// Production trust check. The caller MUST independently select the permitted
/// admission; data may never select its own signer, policy or trust anchor.
pub fn check_qualified_receipt(
    receipt: &coding_semantics::CodingSemanticEvidence,
    permitted: &SignedRuntimeAdmission,
) -> Result<()> {
    receipt.validate_shape().map_err(str::to_owned)?;
    let q = receipt
        .runtime_qualification
        .as_ref()
        .ok_or("qualified runtime evidence missing")?;
    q.matches_data(receipt, permitted)?;
    q.admission.verify()?;
    Ok(())
}
#[cfg(any(test, feature = "test-support"))]
pub struct FixtureAdmissionTrust {
    pub key_id: String,
    pub public_key_pem: Vec<u8>,
    pub crypto_path: String,
    pub crypto_blake3: String,
}
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Serialize)]
pub struct FixtureVerdict {
    pub authority: &'static str,
    pub evidence_class: &'static str,
    pub status: &'static str,
}
/// Controlled software verification only. This returns NONE data and cannot
/// create a reviewed production admission or an original native owner.
#[cfg(any(test, feature = "test-support"))]
pub fn check_fixture_receipt(
    receipt: &coding_semantics::CodingSemanticEvidence,
    permitted: &SignedRuntimeAdmission,
    trust: &FixtureAdmissionTrust,
) -> Result<FixtureVerdict> {
    receipt.validate_shape().map_err(str::to_owned)?;
    let q = receipt
        .runtime_qualification
        .as_ref()
        .ok_or("fixture qualification missing")?;
    q.matches_data(receipt, permitted)?;
    if trust.key_id != q.admission.reviewer_key_id
        || trust.key_id != blake3::hash(&trust.public_key_pem).to_hex().as_str()
    {
        return Err("independently selected fixture signer differs".into());
    }
    let key = Reviewer {
        id: &trust.key_id,
        public_key_pem: &trust.public_key_pem,
        crypto_path: &trust.crypto_path,
        crypto_blake3: &trust.crypto_blake3,
    };
    verify_signature(&q.admission, &key)?;
    Ok(FixtureVerdict {
        authority: "NONE",
        evidence_class: "NON_AUTHORIZING_ADMISSION_FIXTURE",
        status: "DATA_CONTRACT_VALID",
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_observations(record: &Value, scope: &CodingExecutionScope) -> Result<()> {
    observations::validate(record, scope)
}

/// Issue only the independently installed baseline with fresh bounded time and
/// nonce. Missing protected setup refuses; this creates no run qualification.
pub fn issue_installed_admission() -> Result<SignedRuntimeAdmission> {
    installed::issue()
}

/// Select only an independently installed exact role template. No runtime
/// caller can supply a key, policy or broaden the installation authorization.
pub fn issue_installed_workflow_admission(
    role: crate::native_workflow::NativeTaskRole,
) -> Result<SignedRuntimeAdmission> {
    installed::issue_for_role(Some(role))
}

/// Read-only setup data, not a run qualification or an admission capability.
/// The root and reviewer are installation-owned; callers supply only pins to
/// compare with that fixed installation, never a replacement trust source.
#[derive(Clone, Debug, Serialize)]
pub struct InstalledRuntimeConfiguration {
    pub manifest_blake3: String,
    pub reviewer_key_id: String,
    pub approved_profile: RuntimeAdmissionPolicy,
    pub issuance_not_before_unix: u64,
    pub issuance_expires_at_unix: u64,
}

pub fn installed_runtime_configuration(
    manifest_pin: &str,
    reviewer_pin: &str,
) -> Result<InstalledRuntimeConfiguration> {
    installed::configuration(manifest_pin, reviewer_pin)
}

/// Verify an actual statement against both the installed authority and the
/// receiver administrator's independently provisioned authority pins.
pub fn verify_installed_runtime_admission(
    statement: &SignedRuntimeAdmission,
    manifest_pin: &str,
    reviewer_pin: &str,
) -> Result<RuntimeAdmissionPolicy> {
    installed::verify_pinned(statement, manifest_pin, reviewer_pin)
}

// A fixed root-owned sticky scratch parent protects the directory entry from
// an unprivileged agent. TMPDIR is intentionally never consulted by trusted
// signing/verification: mode0700 alone cannot protect an attacker-owned parent.
fn private_scratch_path(prefix: &str) -> Result<std::path::PathBuf> {
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, MetadataExt},
        time::{SystemTime, UNIX_EPOCH},
    };
    let base = std::path::Path::new("/tmp")
        .canonicalize()
        .map_err(|_| "trusted scratch parent unavailable")?;
    for p in base.ancestors() {
        let m = fs::symlink_metadata(p).map_err(|_| "scratch parent metadata unavailable")?;
        if !m.is_dir()
            || m.uid() != 0
            || m.gid() != 0
            || (m.mode() & 0o022 != 0 && !(p == base && m.mode() & 0o1000 != 0))
        {
            return Err("unprotected scratch directory ancestry".into());
        }
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "scratch clock unavailable")?
        .as_nanos();
    let root = base.join(format!("{prefix}-{}-{nonce}", std::process::id()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .map_err(|_| "fresh protected scratch unavailable")?;
    Ok(root)
}
