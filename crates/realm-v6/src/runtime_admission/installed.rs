//! Fixed installation-owned authority. No caller-selected trust path, key or
//! policy can enter the production loader. This module never creates keys.
use super::*;
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
#[cfg(target_os = "macos")]
const ROOT: &str = "/private/etc/realm/runtime-admission";
#[cfg(not(target_os = "macos"))]
const ROOT: &str = "/etc/realm/runtime-admission";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    public_key_blake3: String,
    crypto_path: PathBuf,
    crypto_blake3: String,
    validity_seconds: u64,
    issuance_not_before_unix: u64,
    issuance_expires_at_unix: u64,
    coding_agent_host_uid: u32,
    coding_agent_host_gid: u32,
    approved_profile_template: RuntimeAdmissionPolicy,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    approved_workflow_profiles: std::collections::BTreeMap<String, RuntimeAdmissionPolicy>,
}
pub(super) struct InstalledAuthority {
    manifest: Manifest,
    public_key: Vec<u8>,
    manifest_blake3: String,
}
/// Read only regular, single-link, root-owned files under a root-owned,
/// non-writable directory chain. A symlink anywhere in that chain refuses.
fn protected_read(path: &Path, limit: u64, private: bool) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err("absolute installed authority path required".into());
    }
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)
            .map_err(|_| "protected authority directory unavailable")?;
        if !m.is_dir() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o022 != 0 {
            return Err("unprotected authority directory".into());
        }
    }
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "installed authority file unavailable")?;
    let before = f.metadata().map_err(|_| "authority metadata unavailable")?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != 0
        || before.gid() != 0
        || before.mode() & 0o7022 != 0
        || private && before.mode() & 0o777 != 0o600
        || before.len() == 0
        || before.len() > limit
    {
        return Err("unprotected or unbounded authority file".into());
    }
    let mut bytes = Vec::new();
    f.by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "authority read refused")?;
    let after = f.metadata().map_err(|_| "authority metadata unavailable")?;
    if bytes.len() as u64 != before.len()
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err("authority file changed during read".into());
    }
    Ok(bytes)
}
impl InstalledAuthority {
    fn load_at(root: &Path) -> Result<Self> {
        let raw = protected_read(&root.join("manifest.json"), 256 * 1024, false)?;
        let value = crate::strict_json::parse(&raw)
            .map_err(|_| "strict installed authority manifest required")?;
        let manifest: Manifest = serde_json::from_value(value)
            .map_err(|_| "unsupported installed authority manifest")?;
        manifest.approved_profile_template.validate()?;
        if manifest.approved_profile_template.task_inputs.is_some()
            || manifest
                .approved_workflow_profiles
                .values()
                .any(|p| p.task_inputs.is_some())
        {
            return Err("installed templates cannot contain another attempt's inputs".into());
        }
        if !manifest.approved_workflow_profiles.is_empty() {
            if manifest.approved_workflow_profiles.len() != 2
                || !manifest.approved_workflow_profiles.contains_key("api")
                || !manifest.approved_workflow_profiles.contains_key("cli")
            {
                return Err("exact API/CLI installed profiles required".into());
            }
            for profile in manifest.approved_workflow_profiles.values() {
                profile.validate()?;
                let base = &manifest.approved_profile_template;
                if profile.build != base.build
                    || profile.expected.native_controller_blake3
                        != base.expected.native_controller_blake3
                    || profile.expected.source_commit != base.expected.source_commit
                    || profile.expected.task_sha256 != base.expected.task_sha256
                    || profile.expected.worker_sha256 != base.expected.worker_sha256
                    || profile.expected.vmm_uid != base.expected.vmm_uid
                    || profile.expected.vmm_gid != base.expected.vmm_gid
                {
                    return Err(
                        "installed workflow source/build/task/controller widens baseline".into(),
                    );
                }
            }
        }
        if manifest.schema != "realm.installed-runtime-authority/v1"
            || !digest(&manifest.public_key_blake3)
            || !digest(&manifest.crypto_blake3)
            || !manifest.crypto_path.is_absolute()
            || !(1..=3600).contains(&manifest.validity_seconds)
            || manifest.issuance_expires_at_unix <= manifest.issuance_not_before_unix
            || manifest.issuance_expires_at_unix - manifest.issuance_not_before_unix > 31 * 86400
            || manifest.coding_agent_host_uid == 0
            || manifest.coding_agent_host_gid == 0
            || manifest.coding_agent_host_uid != manifest.approved_profile_template.expected.vmm_uid
            || manifest.coding_agent_host_gid != manifest.approved_profile_template.expected.vmm_gid
        {
            return Err("unsupported installed authority profile".into());
        }
        let public_key = protected_read(&root.join("public.pem"), 16384, false)?;
        if blake3::hash(&public_key).to_hex().as_str() != manifest.public_key_blake3 {
            return Err("installed public key pin differs".into());
        }
        if protected_read(&root.join("manifest.json"), 256 * 1024, false)? != raw {
            return Err("installed authority changed while loading".into());
        }
        Ok(Self {
            manifest,
            public_key,
            manifest_blake3: blake3::hash(&raw).to_hex().to_string(),
        })
    }
    pub(super) fn load() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Self::load_at(Path::new(ROOT))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(
                "installed authority filesystem and ACL boundary is not qualified on this platform"
                    .into(),
            )
        }
    }
    pub(super) fn reviewer(&self) -> Reviewer<'_> {
        Reviewer {
            id: &self.manifest.public_key_blake3,
            public_key_pem: &self.public_key,
            crypto_path: self.manifest.crypto_path.to_str().unwrap_or(""),
            crypto_blake3: &self.manifest.crypto_blake3,
        }
    }
    fn require_pins(&self, manifest_pin: &str, reviewer_pin: &str) -> Result<()> {
        if !digest(manifest_pin)
            || !digest(reviewer_pin)
            || self.manifest_blake3 != manifest_pin
            || self.manifest.public_key_blake3 != reviewer_pin
        {
            return Err("receiver-provisioned runtime authority pins differ".into());
        }
        Ok(())
    }
    fn configuration(&self) -> InstalledRuntimeConfiguration {
        InstalledRuntimeConfiguration {
            manifest_blake3: self.manifest_blake3.clone(),
            reviewer_key_id: self.manifest.public_key_blake3.clone(),
            approved_profile: self.manifest.approved_profile_template.clone(),
            issuance_not_before_unix: self.manifest.issuance_not_before_unix,
            issuance_expires_at_unix: self.manifest.issuance_expires_at_unix,
        }
    }
    fn permits(&self, envelope: &SignedRuntimeAdmission) -> Result<()> {
        let actual = envelope.policy()?;
        if actual.expires_at_unix - actual.not_before_unix > self.manifest.validity_seconds
            || actual.not_before_unix < self.manifest.issuance_not_before_unix
            || actual.expires_at_unix > self.manifest.issuance_expires_at_unix
        {
            return Err("installed admission lifetime differs".into());
        }
        // The profile is an explicit enduring template within a separately
        // bounded installation authorization. Its timestamp/nonce placeholders
        // are not an issuance lease. Only fresh per-run time/nonce may differ.
        // All task/runtime/build/profile
        // and campaign claims remain the independently installed exact baseline.
        for approved in std::iter::once(&self.manifest.approved_profile_template)
            .chain(self.manifest.approved_workflow_profiles.values())
        {
            let mut normalized = actual.clone();
            normalized.not_before_unix = approved.not_before_unix;
            normalized.expires_at_unix = approved.expires_at_unix;
            normalized.nonce = approved.nonce.clone();
            if let Some(inputs) = &actual.task_inputs {
                if inputs.validate_policy(approved).is_err() {
                    continue;
                }
                normalized.task_inputs = approved.task_inputs.clone();
            }

            if &normalized == approved {
                return Ok(());
            }
        }
        Err("admission widens installed approved profile".into())
    }
    pub(super) fn verify(
        &self,
        envelope: &SignedRuntimeAdmission,
    ) -> Result<RuntimeAdmissionPolicy> {
        self.permits(envelope)?;
        if envelope.reviewer_key_id != self.manifest.public_key_blake3 {
            return Err("unknown installed authority".into());
        }
        verify_signature(envelope, &self.reviewer())?;
        envelope.policy()
    }
}
pub(super) fn configuration(
    manifest_pin: &str,
    reviewer_pin: &str,
) -> Result<InstalledRuntimeConfiguration> {
    let authority = InstalledAuthority::load()?;
    authority.require_pins(manifest_pin, reviewer_pin)?;
    Ok(authority.configuration())
}
pub(super) fn verify_pinned(
    statement: &SignedRuntimeAdmission,
    manifest_pin: &str,
    reviewer_pin: &str,
) -> Result<RuntimeAdmissionPolicy> {
    let authority = InstalledAuthority::load()?;
    authority.require_pins(manifest_pin, reviewer_pin)?;
    let policy = authority.verify(statement)?;
    if !policy.permits_time(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "admission clock unavailable")?
            .as_secs(),
    ) {
        return Err("installed statement is future or expired".into());
    }
    let current = InstalledAuthority::load()?;
    current.require_pins(manifest_pin, reviewer_pin)?;
    Ok(policy)
}
/// Automatic source-profile issuance in the trusted supervisor. It grants no
/// run qualification: original native owners and independent receiving still
/// remain mandatory. No argument can select a key, trust root or policy.
pub(super) fn issue() -> Result<SignedRuntimeAdmission> {
    issue_for_role(None)
}
pub(super) fn issue_for_role(
    role: Option<crate::native_workflow::NativeTaskRole>,
) -> Result<SignedRuntimeAdmission> {
    if std::env::consts::OS != "linux"
        || std::env::consts::ARCH != "x86_64"
        || unsafe { libc::geteuid() } != 0
    {
        return Err("installed admission issuer requires the root Linux x86 supervisor".into());
    }
    // Only the installed supervisor ELF may use the protected signer. Running
    // an arbitrary root-linked client is not an admission identity proof.
    let authority = InstalledAuthority::load()?;
    let (_held, actual) = protected_running_supervisor()?;
    if unsafe { libc::getuid() } != 0
        || unsafe { libc::getgid() } != 0
        || unsafe { libc::getegid() } != 0
        || actual.blake3()
            != authority
                .manifest
                .approved_profile_template
                .expected
                .native_controller_blake3
    {
        return Err("unapproved installed supervisor principal or executable".into());
    }
    issue_with_authority(Path::new(ROOT), authority, role, None)
}
#[cfg(any(test, feature = "test-support"))]
fn issue_at_root(root: &Path) -> Result<SignedRuntimeAdmission> {
    issue_with_authority(root, InstalledAuthority::load_at(root)?, None, None)
}
fn issue_with_authority(
    root: &Path,
    authority: InstalledAuthority,
    role: Option<crate::native_workflow::NativeTaskRole>,
    inputs: Option<&super::inputs::NativeTaskInputs>,
) -> Result<SignedRuntimeAdmission> {
    let private = root.join("private.pem");
    // Never return or log private material; permission/version checks precede
    // fixed-path crypto access. No routine task can create or replace this file.
    let mut secret = protected_read(&private, 16384, true)?;
    secret.fill(0);
    drop(secret);
    let before = crate::measured_launch::FileIdentity::measure(&private)
        .map_err(|_| "private key identity unavailable")?;
    let mut policy = match role {
        None => authority.manifest.approved_profile_template.clone(),
        Some(role) => authority
            .manifest
            .approved_workflow_profiles
            .get(match role {
                crate::native_workflow::NativeTaskRole::Api => "api",
                crate::native_workflow::NativeTaskRole::Cli => "cli",
            })
            .ok_or("installed native workflow role has not been approved")?
            .clone(),
    };
    if policy.task_input_protocol.is_some() && inputs.is_none() {
        return Err("original sealed task inputs required for input-profile issuance".into());
    }
    if let Some(inputs) = inputs {
        inputs.validate_policy(&policy)?;
        policy.task_inputs = Some(inputs.clone());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock unavailable")?
        .as_secs();
    if now < authority.manifest.issuance_not_before_unix
        || now >= authority.manifest.issuance_expires_at_unix
    {
        return Err("installed profile issuance authorization expired or not yet valid".into());
    }
    policy.not_before_unix = now;
    policy.expires_at_unix = now
        .checked_add(authority.manifest.validity_seconds)
        .ok_or("admission clock overflow")?
        .min(authority.manifest.issuance_expires_at_unix);
    policy.nonce = crate::mediation::MediationChallenge::fresh()
        .map_err(|_| "kernel admission nonce unavailable")?
        .root()
        .into();
    let policy_json = serde_json::to_string(&policy).map_err(|_| "admission encoding refused")?;
    let signature = sign_installed(&authority, &private, &signing_bytes(&policy_json))?;
    if crate::measured_launch::FileIdentity::measure(&private).map_err(|_| "private key changed")?
        != before
    {
        return Err("private key changed during issuance".into());
    }
    let envelope = SignedRuntimeAdmission {
        schema: "realm.signed-runtime-admission/v1".into(),
        reviewer_key_id: authority.manifest.public_key_blake3.clone(),
        policy_json,
        signature_hex: signature.iter().map(|v| format!("{v:02x}")).collect(),
    };
    // Verify actual signature/key suite and exact installed policy before any
    // opaque admission constructor can see the statement.
    authority.verify(&envelope)?;
    Ok(envelope)
}

#[cfg(target_os = "linux")]
fn workflow_template(
    authority: &InstalledAuthority,
    role: crate::native_workflow::NativeTaskRole,
) -> Result<&RuntimeAdmissionPolicy> {
    authority
        .manifest
        .approved_workflow_profiles
        .get(match role {
            crate::native_workflow::NativeTaskRole::Api => "api",
            crate::native_workflow::NativeTaskRole::Cli => "cli",
        })
        .ok_or("independently installed native input profile absent".into())
}
#[cfg(target_os = "linux")]
fn require_original_supervisor(authority: &InstalledAuthority) -> Result<()> {
    if std::env::consts::ARCH != "x86_64"
        || unsafe { libc::getuid() } != 0
        || unsafe { libc::geteuid() } != 0
        || unsafe { libc::getgid() } != 0
        || unsafe { libc::getegid() } != 0
    {
        return Err("original protected root Linux x86 supervisor required".into());
    }
    let (_held, actual) = protected_running_supervisor()?;
    if actual.blake3()
        != authority
            .manifest
            .approved_profile_template
            .expected
            .native_controller_blake3
    {
        return Err("unapproved native input supervisor".into());
    }
    Ok(())
}
#[cfg(target_os = "linux")]
pub(crate) fn prepare_workflow_inputs(
    role: crate::native_workflow::NativeTaskRole,
    binding: &crate::coding_submission::SubmissionContract,
    step: &crate::native_workflow::NativeSubtask,
) -> Result<super::inputs::OwnedTaskInputs> {
    let authority = InstalledAuthority::load()?;
    require_original_supervisor(&authority)?;
    if step.role != role {
        return Err("original keeper role differs".into());
    }
    super::inputs::OwnedTaskInputs::create(workflow_template(&authority, role)?, binding, step)
}
#[cfg(target_os = "linux")]
pub(crate) fn input_rootfs_digest(
    role: crate::native_workflow::NativeTaskRole,
    inputs: &super::inputs::NativeTaskInputs,
) -> Result<String> {
    let authority = InstalledAuthority::load()?;
    require_original_supervisor(&authority)?;
    let profile = workflow_template(&authority, role)?;
    inputs.validate_policy(profile)?;
    Ok(profile.expected.rootfs_blake3.clone())
}
#[cfg(target_os = "linux")]
pub(crate) fn issue_for_inputs(
    role: crate::native_workflow::NativeTaskRole,
    inputs: &super::inputs::OwnedTaskInputs,
) -> Result<SignedRuntimeAdmission> {
    let authority = InstalledAuthority::load()?;
    require_original_supervisor(&authority)?;
    inputs.validate_policy(workflow_template(&authority, role)?)?;
    issue_with_authority(Path::new(ROOT), authority, Some(role), Some(inputs.data()))
}

fn sign_installed(authority: &InstalledAuthority, private: &Path, body: &[u8]) -> Result<Vec<u8>> {
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let crypto = &authority.manifest.crypto_path;
    let before = crate::measured_launch::FileIdentity::measure(crypto)
        .map_err(|_| "installed crypto unavailable")?;
    if before.owner() != (0, 0)
        || !before.trusted_parent_chain()
        || before.mode() & 0o022 != 0
        || before.blake3() != authority.manifest.crypto_blake3
    {
        return Err("installed crypto pin differs".into());
    }
    let root = super::private_scratch_path("realm-installed-statement")?;
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let scratch = Scratch(root);
    let message = scratch.0.join("statement");
    let signature = scratch.0.join("signature");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&message)
        .map_err(|_| "statement scratch refused")?;
    f.write_all(body).map_err(|_| "statement write refused")?;
    f.sync_all().map_err(|_| "statement sync refused")?;
    drop(f);
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&signature)
        .map_err(|_| "signature scratch refused")?;
    let mut child = Command::new(crypto)
        .args(["dgst", "-sha256", "-sign"])
        .arg(private)
        .env_clear()
        .env("LC_ALL", "C")
        .env("OPENSSL_CONF", "/dev/null")
        .stdin(File::open(&message).map_err(|_| "statement read refused")?)
        .stdout(output)
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "installed signing process unavailable")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("installed signature refused or timed out".into());
            }
        }
    }
    if fs::metadata(&signature)
        .map_err(|_| "signature unavailable")?
        .len()
        != 384
        || crate::measured_launch::FileIdentity::measure(crypto).map_err(|_| "crypto changed")?
            != before
    {
        return Err("installed signature suite or crypto identity differs".into());
    }
    fs::read(signature).map_err(|_| "signature read refused".into())
}

#[cfg(all(test, target_os = "linux"))]
mod pin_tests {
    use super::*;
    #[test]
    fn protected_authority_manifest_and_reviewer_pins_are_independent() {
        let Ok(root) = std::env::var("REALM_POLICY_FIXTURE_ROOT") else {
            return;
        };
        assert_eq!(root, "/fixture-policy");
        assert_eq!(std::env::var("REALM_TEST_ONLY_CONTAINER").unwrap(), "1");
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert!(
            fs::read_to_string("/proc/mounts")
                .unwrap()
                .lines()
                .any(|l| {
                    let p: Vec<_> = l.split_whitespace().collect();
                    p.get(1) == Some(&"/fixture-policy") && p.get(2) == Some(&"tmpfs")
                })
        );
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let root = Path::new(&root).join("test-only-authority-pins");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let public = b"TEST_ONLY_INVALID_PUBLIC_KEY_NO_AUTHORITY";
        let key = blake3::hash(public).to_hex().to_string();
        let policy = fixture_candidate().policy;
        let mut manifest = serde_json::json!({
            "schema":"realm.installed-runtime-authority/v1",
            "public_key_blake3":key, "crypto_path":"/usr/bin/openssl",
            "crypto_blake3":"a".repeat(64), "validity_seconds":300,
            "issuance_not_before_unix":900,"issuance_expires_at_unix":2000,
            "coding_agent_host_uid":policy.expected.vmm_uid,
            "coding_agent_host_gid":policy.expected.vmm_gid,
            "approved_profile_template":policy,
        });
        for (name, raw) in [
            ("manifest.json", serde_json::to_vec(&manifest).unwrap()),
            ("public.pem", public.to_vec()),
        ] {
            fs::write(root.join(name), raw).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let authority = InstalledAuthority::load_at(&root).unwrap();
        let original_pin = authority.manifest_blake3.clone();
        authority.require_pins(&original_pin, &key).unwrap();
        assert_eq!(authority.configuration().manifest_blake3, original_pin);
        for (m, k) in [
            ("".into(), key.clone()),
            ("0".repeat(64), key.clone()),
            (original_pin.clone(), "0".repeat(64)),
        ] {
            assert!(authority.require_pins(&m, &k).is_err());
        }
        manifest["approved_profile_template"]["build"]["review_evidence_blake3"] =
            serde_json::json!("0".repeat(64));
        fs::write(
            root.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(
            InstalledAuthority::load_at(&root)
                .unwrap()
                .require_pins(&original_pin, &key)
                .is_err()
        );
        fs::write(root.join("public.pem"), b"SUBSTITUTED_TEST_ONLY_KEY").unwrap();
        assert!(InstalledAuthority::load_at(&root).is_err());
        println!(
            "PINNED_AUTHORITY_SETUP_DATA=PASS authority=NONE signatures=NOT_VERIFIED native=NOT_RUN"
        );
    }
}

/// Permission tests return diagnostics only and cannot return an admission,
/// key, signer, native owner or destination capability.
#[cfg(any(test, feature = "test-support"))]
pub fn inspect_fixture_setup(root: &Path) -> Result<serde_json::Value> {
    refuse_fixture_production_namespace(root)?;
    let authority = InstalledAuthority::load_at(root)?;
    let mut secret = protected_read(&root.join("private.pem"), 16384, true)?;
    secret.fill(0);
    Ok(
        serde_json::json!({"authority":"NONE","evidence_class":"TEST_ONLY_SETUP_PERMISSIONS",
        "public_key_id":authority.manifest.public_key_blake3,"profile":authority.manifest.approved_profile_template.semantic_scope}),
    )
}

#[cfg(any(test, feature = "test-support"))]
pub fn check_fixture_installed_statement(
    root: &Path,
    statement: &SignedRuntimeAdmission,
) -> Result<Value> {
    refuse_fixture_production_namespace(root)?;
    InstalledAuthority::load_at(root)?.verify(statement)?;
    Ok(
        serde_json::json!({"authority":"NONE","evidence_class":"TEST_ONLY_INSTALLED_STATEMENT","status":"DATA_CONTRACT_VALID"}),
    )
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Serialize)]
pub struct FixtureIssuedStatement {
    pub statement: SignedRuntimeAdmission,
    pub authority: &'static str,
    pub evidence_class: &'static str,
}
/// Execute the same issuance algorithm on a separately selected TEST-only
/// protected directory. This exports data, never opaque production admission;
/// the fixed production loader cannot trust this alternate directory.
#[cfg(any(test, feature = "test-support"))]
pub fn fixture_issue_installed_statement(root: &Path) -> Result<FixtureIssuedStatement> {
    refuse_fixture_production_namespace(root)?;
    if unsafe { libc::geteuid() } != 0 {
        return Err("fixture protected issuer requires root test principal".into());
    }
    Ok(FixtureIssuedStatement {
        statement: issue_at_root(root)?,
        authority: "NONE",
        evidence_class: "TEST_ONLY_INSTALLED_STATEMENT",
    })
}

fn join_protected_executable(
    named: &Path,
    held: &File,
) -> Result<crate::measured_launch::FileIdentity> {
    use crate::measured_launch::FileIdentity;
    let m = fs::symlink_metadata(named).map_err(|_| "installed executable pathname unavailable")?;
    if !named.is_absolute() || !m.is_file() {
        return Err("installed executable must have a regular protected name".into());
    }
    let named_identity =
        FileIdentity::measure(named).map_err(|_| "installed named executable refused")?;
    let actual = FileIdentity::measure_open_file(named, held)
        .map_err(|_| "held installed executable refused")?;
    if !actual.same_pinned_resource(&named_identity)
        || !actual.trusted_parent_chain()
        || actual.owner() != (0, 0)
        || actual.mode() & 0o7022 != 0
        || actual.mode() & 0o100 == 0
    {
        return Err("held executable differs from protected installation".into());
    }
    Ok(actual)
}
/// Hold the kernel-selected object before joining its protected installed name.
pub(crate) fn protected_running_supervisor() -> Result<(File, crate::measured_launch::FileIdentity)>
{
    let held = File::open("/proc/self/exe").map_err(|_| "running supervisor unavailable")?;
    let named =
        fs::read_link("/proc/self/exe").map_err(|_| "running supervisor name unavailable")?;
    let identity = join_protected_executable(&named, &held)?;
    Ok((held, identity))
}
#[cfg(any(test, feature = "test-support"))]
pub fn fixture_check_executable(named: &Path, held_path: &Path) -> Result<Value> {
    let held = File::open(held_path).map_err(|_| "test held executable unavailable")?;
    let id = join_protected_executable(named, &held)?;
    Ok(
        serde_json::json!({"authority":"NONE","evidence_class":"TEST_ONLY_EXECUTABLE_JOIN","blake3":id.blake3()}),
    )
}

// Fixture signing is categorically unavailable on a configured production
// authority host, even with an alternate path/key encoding. This prevents a
// test-support client from using the installed key while skipping the actual
// production supervisor ELF/principal check. No production namespace is opened
// or created by these tests.
#[cfg(any(test, feature = "test-support"))]
fn refuse_fixture_production_namespace(root: &Path) -> Result<()> {
    use std::path::Component;
    if !root.is_absolute() {
        return Err("absolute fixture root required".into());
    }
    let mut clean = PathBuf::from("/");
    for part in root.components() {
        match part {
            Component::Normal(p) => clean.push(p),
            Component::ParentDir => {
                if !clean.pop() {
                    return Err("fixture root escapes namespace".into());
                }
            }
            Component::RootDir | Component::CurDir => {}
            _ => return Err("unsupported fixture namespace".into()),
        }
    }
    let actual = root.canonicalize().unwrap_or_else(|_| clean.clone());
    for name in [
        "/etc/realm/runtime-admission",
        "/private/etc/realm/runtime-admission",
    ] {
        let production = Path::new(name);
        if clean.starts_with(production)
            || production.starts_with(&clean)
            || actual.starts_with(production)
            || production.starts_with(&actual)
        {
            return Err("fixture production namespace forbidden".into());
        }
        match fs::symlink_metadata(production) {
            Ok(_) => {
                return Err(
                    "fixture authority APIs disabled on a configured production host".into(),
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("production namespace isolation cannot be established".into()),
        }
    }
    Ok(())
}
