//! Destination authorization from independently installed setup. No signer,
//! executor or publisher. Automatic receiving reuses the existing apply and
//! final-state verifier only after qualification and the installed grant agree.
use super::coding_transfer::{self, CodingContract, CodingTransferPolicy};
use super::*;
use realm_v6::{measured_launch::FileIdentity, runtime_admission::RuntimeTuple};
use serde_json::Value;
use std::path::PathBuf;

const MANIFEST: &str = "/etc/realm/coding-transfer/manifest.json";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InstalledGrant {
    schema: String,
    provisioner_blake3: String,
    publication_root: PathBuf,
    genesis_root: String,
    approved_runtime: RuntimeTuple,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workflow: Option<InstalledWorkflowGrant>,
    runtime_authority_manifest_blake3: String,
    runtime_reviewer_key_id: String,
    destination: PathBuf,
    destination_identity: DirectoryIdentity,
    state_root: PathBuf,
    grant_nonce: String,
    not_before_unix: u64,
    expires_at_unix: u64,
    policy_seconds: u64,
}

/// Exact setup-owned API runtime and workflow; final CLI runtime remains the
/// existing approved_runtime. Candidate sidecars cannot install these pins.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InstalledWorkflowGrant {
    workflow: String,
    approved_api_runtime: RuntimeTuple,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationHandoff {
    schema: String,
    authority: String,
    run_id: String,
    execution_id: String,
    artifact_blake3: String,
    transfer_proof_blake3: String,
    genesis_root: String,
    exact_head_root: String,
    semantic_root: String,
    contract: CodingContract,
    runtime_admission: realm_v6::runtime_admission::SignedRuntimeAdmission,
    runtime_admission_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workflow_trust: Option<super::coding_qualification::NativeWorkflowTrust>,
    destination_policy: Value,
    approval_id: Value,
    application_dispatched: bool,
}
/// The existing receiver's policy and exact preflight approval, restricted by
/// installed setup. Producing this record performs no destination mutation.
#[derive(Serialize)]
pub struct ProvisionedCodingPolicy {
    pub schema: &'static str,
    pub grant_blake3: String,
    pub policy: CodingTransferPolicy,
    pub plan: ordered_create::OrderedPlan,
    pub approval_id: String,
    pub destination: PathBuf,
    pub state: PathBuf,
    pub application_dispatched: bool,
}
fn unaliased(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
}
fn protected_directory(path: &Path) -> Result<()> {
    if !unaliased(path) {
        return refuse("unaliased absolute installed path required");
    }
    for p in path.ancestors() {
        let m = std::fs::symlink_metadata(p)?;
        if !m.is_dir() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7022 != 0 {
            return refuse("unprotected installed destination grant directory");
        }
    }
    Ok(())
}
fn protected_bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    protected_directory(
        path.parent()
            .ok_or_else(|| ApplyError::Refuse("missing parent".into()))?,
    )?;
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != 0
        || m.gid() != 0
        || m.mode() & 0o7022 != 0
        || m.len() == 0
        || m.len() > limit
    {
        return refuse("unprotected or unbounded installed policy input");
    }
    let before = FileIdentity::measure(path)
        .map_err(|e| ApplyError::Refuse(format!("installed input: {e:?}")))?;
    let bytes = read_transfer_file(path)?;
    let after = FileIdentity::measure(path)
        .map_err(|e| ApplyError::Refuse(format!("installed input reread: {e:?}")))?;
    if !before.trusted_parent_chain() || before != after || before.blake3() != digest(&bytes) {
        return refuse("installed policy input replaced during read");
    }
    Ok(bytes)
}
impl InstalledGrant {
    fn validate(&self, now: u64) -> Result<()> {
        self.approved_runtime
            .validate()
            .map_err(ApplyError::Refuse)?;
        if self.schema != "realm.installed-coding-destination-grant/v2"
            || ![
                &self.provisioner_blake3,
                &self.genesis_root,
                &self.grant_nonce,
                &self.runtime_authority_manifest_blake3,
                &self.runtime_reviewer_key_id,
            ]
            .iter()
            .all(|v| valid_digest(v))
            || self.destination_identity.uid != 0
            || self.expires_at_unix <= self.not_before_unix
            || self.expires_at_unix - self.not_before_unix > 31 * 86400
            || !(1..=3600).contains(&self.policy_seconds)
            || now < self.not_before_unix
            || now >= self.expires_at_unix
        {
            return refuse("invalid, future or expired installed destination grant");
        }
        if let Some(workflow) = &self.workflow {
            workflow
                .approved_api_runtime
                .validate()
                .map_err(ApplyError::Refuse)?;
            if !valid_digest(&workflow.workflow)
                || workflow.approved_api_runtime.source_commit
                    != self.approved_runtime.source_commit
                || workflow.approved_api_runtime.task_sha256 != self.approved_runtime.task_sha256
                || workflow.approved_api_runtime.worker_sha256
                    != self.approved_runtime.worker_sha256
                || workflow.approved_api_runtime.native_controller_blake3
                    != self.approved_runtime.native_controller_blake3
                || workflow.approved_api_runtime.checker_scope_sha256
                    == self.approved_runtime.checker_scope_sha256
            {
                return refuse("installed API/CLI workflow profiles differ");
            }
        }
        let paths = [&self.publication_root, &self.destination, &self.state_root];
        if paths.iter().any(|p| !unaliased(p))
            || paths.iter().enumerate().any(|(i, p)| {
                paths
                    .iter()
                    .enumerate()
                    .any(|(j, q)| i != j && p.starts_with(q))
            })
        {
            return refuse("installed publication/destination/state paths overlap or alias");
        }
        Ok(())
    }
}
fn derive_policy(
    grant: &InstalledGrant,
    grant_pin: &str,
    handoff: &PublicationHandoff,
    now: u64,
) -> Result<CodingTransferPolicy> {
    grant.validate(now)?;
    handoff.contract.validate()?;
    let admitted = handoff
        .runtime_admission
        .policy()
        .map_err(ApplyError::Refuse)?;
    if handoff.schema != "realm.native-coding-publication-handoff.v1"
        || handoff.authority != "NONE: transport record; independent receiver trust required"
        || !valid_digest(&handoff.run_id)
        || !valid_digest(&handoff.execution_id)
        || handoff.run_id != handoff.contract.submission.run_id
        || handoff.execution_id != handoff.contract.submission.execution_id
        || handoff.genesis_root != grant.genesis_root
        || handoff.runtime_admission.reviewer_key_id != grant.runtime_reviewer_key_id
        || admitted.expected != grant.approved_runtime
        || handoff.contract.source_commit != grant.approved_runtime.source_commit
        || handoff.contract.submission.task_sha256 != grant.approved_runtime.task_sha256
        || handoff.contract.submission.worker_sha256 != grant.approved_runtime.worker_sha256
        || handoff
            .runtime_admission
            .identity()
            .map_err(ApplyError::Refuse)?
            != handoff.runtime_admission_id
        || !handoff.destination_policy.is_null()
        || !handoff.approval_id.is_null()
        || handoff.application_dispatched
    {
        return refuse("publication outside independently installed destination grant");
    }
    let mut not_before_unix = grant.not_before_unix.max(admitted.not_before_unix);
    let mut expires_at_unix = grant
        .expires_at_unix
        .min(admitted.expires_at_unix)
        .min(not_before_unix.saturating_add(grant.policy_seconds));
    match (&grant.workflow, &handoff.workflow_trust) {
        (None, None) => {}
        (Some(approved), Some(history))
            if approved.workflow == history.workflow
                && (1..=3).contains(&history.prior_admissions.len()) =>
        {
            for prior in &history.prior_admissions {
                let policy = prior.policy().map_err(ApplyError::Refuse)?;
                if prior.reviewer_key_id != grant.runtime_reviewer_key_id
                    || (policy.expected != approved.approved_api_runtime
                        && policy.expected != grant.approved_runtime)
                {
                    return refuse("prior attempt outside independently installed runtime grant");
                }
                not_before_unix = not_before_unix.max(policy.not_before_unix);
                expires_at_unix = expires_at_unix.min(policy.expires_at_unix);
            }
        }
        _ => return refuse("missing or substituted installed native workflow authorization"),
    }
    // Stable per-grant/per-publication identity: retries cannot renew the lease
    // or silently change the policy/approval for an already-started application.
    let nonce = crate::hash(
        "realm.installed-coding-policy-nonce/v1",
        &serde_json::to_vec(&(
            grant_pin,
            &grant.grant_nonce,
            &handoff.run_id,
            &handoff.artifact_blake3,
            &handoff.exact_head_root,
        ))?,
    )
    .value;
    let policy = CodingTransferPolicy {
        schema_version: 2,
        authorization_domain: coding_transfer::AUTHORIZATION_DOMAIN.into(),
        artifact_blake3: handoff.artifact_blake3.clone(),
        genesis_root: grant.genesis_root.clone(),
        exact_head_root: handoff.exact_head_root.clone(),
        semantic_root: handoff.semantic_root.clone(),
        contract: handoff.contract.clone(),
        runtime_admission: Some(handoff.runtime_admission.clone()),
        workflow_trust: handoff.workflow_trust.clone(),
        destination: grant.destination_identity.clone(),
        nonce,
        not_before_unix,
        expires_at_unix,
    };
    policy.validate(now)?;
    Ok(policy)
}
struct LoadedPublication {
    grant: InstalledGrant,
    raw_grant: Vec<u8>,
    artifact: Vec<u8>,
    proof_raw: Vec<u8>,
    proof: TransferProof,
    policy: CodingTransferPolicy,
    run_id: String,
}
/// Data-only preflight; it creates no qualification, approval or destination
/// mutation. Production callers still consume actual native owners afterward.
#[derive(Serialize)]
pub struct InstalledCodingSetup {
    pub schema: &'static str,
    pub authority: &'static str,
    pub grant_blake3: String,
    pub runtime_authority_manifest_blake3: String,
    pub runtime_reviewer_key_id: String,
    pub source_commit: String,
    pub genesis_root: String,
}
fn check_configuration(
    grant: &InstalledGrant,
    configuration: &realm_v6::runtime_admission::InstalledRuntimeConfiguration,
    genesis: &str,
    now: u64,
) -> Result<()> {
    grant.validate(now)?;
    if !valid_digest(genesis)
        || genesis != grant.genesis_root
        || configuration.manifest_blake3 != grant.runtime_authority_manifest_blake3
        || configuration.reviewer_key_id != grant.runtime_reviewer_key_id
        || configuration.approved_profile.expected != grant.approved_runtime
        || configuration
            .approved_profile
            .expected
            .native_controller_blake3
            != grant.provisioner_blake3
        || now < configuration.issuance_not_before_unix
        || now >= configuration.issuance_expires_at_unix
    {
        return refuse("installed runtime authority, destination grant or genesis differ");
    }
    Ok(())
}
pub fn preflight_installed(
    genesis: &str,
    statement: &realm_v6::runtime_admission::SignedRuntimeAdmission,
) -> Result<InstalledCodingSetup> {
    let (grant, raw) = load_grant()?;
    let configuration = realm_v6::runtime_admission::installed_runtime_configuration(
        &grant.runtime_authority_manifest_blake3,
        &grant.runtime_reviewer_key_id,
    )
    .map_err(ApplyError::Refuse)?;
    check_configuration(
        &grant,
        &configuration,
        genesis,
        coding_transfer::now_unix()?,
    )?;
    let admitted = realm_v6::runtime_admission::verify_installed_runtime_admission(
        statement,
        &grant.runtime_authority_manifest_blake3,
        &grant.runtime_reviewer_key_id,
    )
    .map_err(ApplyError::Refuse)?;
    if admitted.expected != grant.approved_runtime
        || protected_bytes(Path::new(MANIFEST), 256 * 1024)? != raw
    {
        return refuse("installed setup changed before native execution");
    }
    Ok(InstalledCodingSetup {
        schema: "realm.installed-coding-setup-preflight/v1",
        authority: "NONE: setup coherence only; native run owners still required",
        grant_blake3: digest(&raw),
        runtime_authority_manifest_blake3: grant.runtime_authority_manifest_blake3,
        runtime_reviewer_key_id: grant.runtime_reviewer_key_id,
        source_commit: grant.approved_runtime.source_commit,
        genesis_root: grant.genesis_root,
    })
}
fn load_grant() -> Result<(InstalledGrant, Vec<u8>)> {
    if !cfg!(target_os = "linux")
        || unsafe { libc::getuid() } != 0
        || unsafe { libc::geteuid() } != 0
    {
        return refuse("INCOMPLETE: installed coding policy requires protected Linux supervisor");
    }
    let raw = protected_bytes(Path::new(MANIFEST), 256 * 1024).map_err(|error| match error {
        ApplyError::Io(ref e) if e.kind() == io::ErrorKind::NotFound => ApplyError::Refuse(
            "INCOMPLETE: independently installed destination grant unavailable".into(),
        ),
        other => other,
    })?;
    let grant: InstalledGrant = coding_transfer::strict_json(&raw)?;
    let now = coding_transfer::now_unix()?;
    grant.validate(now)?;
    // Open the kernel-selected executable FIRST, then join it to its protected
    // installed pathname. Root ownership alone is not the approved ELF pin.
    let mut held = File::open("/proc/self/exe")?;
    let held_before = held.metadata()?;
    let named = std::fs::read_link("/proc/self/exe")?;
    let installed = FileIdentity::measure(&named)
        .map_err(|e| ApplyError::Refuse(format!("policy provisioner installation: {e:?}")))?;
    if !held_before.is_file() || held_before.nlink() != 1 || held_before.len() > MAX_TRANSFER_BYTES
    {
        return refuse("unsupported policy provisioner executable");
    }
    let mut elf = Vec::new();
    (&mut held)
        .take(MAX_TRANSFER_BYTES + 1)
        .read_to_end(&mut elf)?;
    if !stable_meta(&held_before, &held.metadata()?)
        || !stable_meta(&held_before, &std::fs::symlink_metadata(&named)?)
        || !installed.trusted_parent_chain()
        || installed.owner() != (0, 0)
        || installed.mode() & 0o7022 != 0
        || installed.blake3() != digest(&elf)
        || installed.blake3() != grant.provisioner_blake3
    {
        return refuse("unapproved installed policy provisioner executable");
    }
    protected_directory(&grant.publication_root)?;
    protected_directory(&grant.state_root)?;
    protected_directory(&grant.destination)?;
    if Directory::open(&grant.destination)?.identity()? != grant.destination_identity {
        return refuse("installed destination identity changed");
    }
    Ok((grant, raw))
}
fn load_installed(publication_handle: &str) -> Result<LoadedPublication> {
    if !valid_digest(publication_handle) {
        return refuse("publication selector must be a bounded storage handle");
    }
    let (grant, raw) = load_grant()?;
    let now = coding_transfer::now_unix()?;
    let publication = grant.publication_root.join(publication_handle);
    let artifact = protected_bytes(&publication.join("accepted.realm"), MAX_TRANSFER_BYTES)?;
    let proof_raw = protected_bytes(&publication.join("transfer-proof.json"), MAX_TRANSFER_BYTES)?;
    let handoff_raw = protected_bytes(&publication.join("publication-handoff.json"), 512 * 1024)?;
    let handoff: PublicationHandoff = coding_transfer::strict_json(&handoff_raw)?;
    if handoff.artifact_blake3 != digest(&artifact)
        || handoff.transfer_proof_blake3 != digest(&proof_raw)
    {
        return refuse("protected publication record substituted or cross-run");
    }
    realm_v6::runtime_admission::verify_installed_runtime_admission(
        &handoff.runtime_admission,
        &grant.runtime_authority_manifest_blake3,
        &grant.runtime_reviewer_key_id,
    )
    .map_err(ApplyError::Refuse)?;
    if let Some(history) = &handoff.workflow_trust {
        for statement in &history.prior_admissions {
            realm_v6::runtime_admission::verify_installed_runtime_admission(
                statement,
                &grant.runtime_authority_manifest_blake3,
                &grant.runtime_reviewer_key_id,
            )
            .map_err(ApplyError::Refuse)?;
        }
    }
    let policy = derive_policy(&grant, &digest(&raw), &handoff, now)?;
    let proof: TransferProof = coding_transfer::strict_json(&proof_raw)?;
    Ok(LoadedPublication {
        grant,
        raw_grant: raw,
        artifact,
        proof_raw,
        proof,
        policy,
        run_id: handoff.run_id,
    })
}
/// Read-only policy/preflight interface, retained for existing callers.
pub fn provision_installed(publication_handle: &str) -> Result<ProvisionedCodingPolicy> {
    let c = load_installed(publication_handle)?;
    let verified = coding_transfer::verify_transfer(&c.artifact, &c.proof, &c.policy)?;
    let plan = ordered_create::preflight(&verified, &c.grant.destination)?;
    if plan.destination != c.grant.destination_identity {
        return refuse("installed destination identity changed");
    }
    if protected_bytes(Path::new(MANIFEST), 256 * 1024)? != c.raw_grant {
        return refuse("installed destination grant changed during provisioning");
    }
    Ok(ProvisionedCodingPolicy {
        schema: "realm.provisioned-coding-destination-policy/v1",
        grant_blake3: digest(&c.raw_grant),
        approval_id: plan.approval_id()?,
        policy: c.policy,
        plan,
        destination: c.grant.destination,
        state: c.grant.state_root.join(&c.run_id),
        application_dispatched: false,
    })
}

/// Integrity, task evidence, execution qualification and destination authority
/// are deliberately distinct. A sealed artifact cannot select its own grant.
#[derive(Serialize)]
pub struct InstalledHandoffAttempt {
    pub schema: &'static str,
    pub status: String,
    pub artifact_integrity: &'static str,
    pub task_status: &'static str,
    pub execution_qualification: &'static str,
    pub application_authorization: &'static str,
    /// Conservative across retained prior attempts; the nested transfer gives
    /// exact current-call dispatch. A durable marker alone means POSSIBLE.
    pub application_dispatched: bool,
    /// UNKNOWN before protected history is read; never infer no prior effects
    /// from a missing reply, expired lease or unavailable grant.
    pub prior_dispatch: &'static str,
    pub detail: String,
    pub transfer: Option<super::coding_lifecycle::TransferAttempt>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedHandoff {
    schema: String,
    grant_blake3: String,
    artifact_blake3: String,
    proof_blake3: String,
    run_id: String,
    policy: CodingTransferPolicy,
    plan: ordered_create::OrderedPlan,
    approval_id: String,
    destination: PathBuf,
    state: PathBuf,
}
fn retain_once(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    File::open(
        path.parent()
            .ok_or_else(|| ApplyError::Refuse("handoff parent absent".into()))?,
    )?
    .sync_all()?;
    Ok(())
}
fn retained_handoff(raw: &[u8], expected: &RetainedHandoff) -> Result<RetainedHandoff> {
    let found: RetainedHandoff = coding_transfer::strict_json(raw)?;
    if &found != expected || found.approval_id != found.plan.approval_id()? {
        return refuse(
            "retained handoff differs: preserve original policy, pins, run, destination and lease",
        );
    }
    Ok(found)
}
fn dispatch_marker(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            if protected_bytes(path, 128)? != b"DISPATCH_MAY_HAVE_OCCURRED\n" {
                return refuse("unknown dispatch marker: preserve and reconcile");
            }
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
/// Protected automatic handoff. Input bytes/pins are only a publisher binding;
/// all destination permission still comes from the fixed installed grant.
/// Never substitutes a diagnostic receipt, fixture verifier or apply callback.
pub fn receive_installed(
    publication_handle: &str,
    artifact: &[u8],
    expected_artifact_pin: &str,
    expected_run_id: &str,
) -> InstalledHandoffAttempt {
    let mut report = InstalledHandoffAttempt {
        schema: "realm.installed-coding-handoff-attempt/v1",
        status: "INCOMPLETE".into(),
        artifact_integrity: "NOT_CHECKED",
        task_status: "NOT_ESTABLISHED",
        execution_qualification: "INCOMPLETE",
        application_authorization: "NONE",
        application_dispatched: false,
        prior_dispatch: "UNKNOWN",
        detail: String::new(),
        transfer: None,
    };
    let result = (|| -> Result<()> {
        if artifact.len() as u64 > MAX_TRANSFER_BYTES
            || !valid_digest(expected_artifact_pin)
            || digest(artifact) != expected_artifact_pin
        {
            return refuse("publisher artifact pin or byte bound differs");
        }
        let bundle = ArtifactBundle::unpack(artifact)?;
        report.artifact_integrity = "VALID";
        if expected_run_id.is_empty()
            || expected_run_id.len() > 128
            || !expected_run_id.is_ascii()
            || bundle.run.run.run_id != expected_run_id
        {
            return refuse("publisher run identity differs");
        }
        let c = load_installed(publication_handle)?;
        if c.artifact != artifact || c.run_id != expected_run_id {
            return refuse("publisher bytes/run differ from protected retained publication");
        }
        let verified = coding_transfer::verify_transfer(&c.artifact, &c.proof, &c.policy)?;
        report.task_status = "CHECKED_SAME_RUN_FINITE_TASK";
        report.execution_qualification = "QUALIFIED";
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let records = c.grant.state_root.join(".handoffs");
        match std::fs::DirBuilder::new().mode(0o700).create(&records) {
            Ok(()) => File::open(&c.grant.state_root)?.sync_all()?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        protected_directory(&records)?;
        let lock_path = records.join(format!("{}.lock", c.run_id));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lock_path)?;
        let m = file.metadata()?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != 0
            || m.gid() != 0
            || m.mode() & 0o7777 != 0o600
        {
            return refuse("unprotected handoff lock");
        }
        let _lock = ordered_create::OwnedJournalLock::acquire(file)?;
        File::open(&records)?.sync_all()?;
        let checkpoint = records.join(format!("{}.json", c.run_id));
        let marker = records.join(format!("{}.dispatch", c.run_id));
        // Read possible history BEFORE decoding a checkpoint which may have
        // been torn by interruption. Bad markers mean unknown prior dispatch.
        let dispatched = dispatch_marker(&marker).inspect_err(|_| {
            report.prior_dispatch = "UNKNOWN";
            report.application_dispatched = true;
        })?;
        report.prior_dispatch = if dispatched {
            "POSSIBLE"
        } else {
            "NO_RETAINED_MARKER"
        };
        report.application_dispatched = dispatched;
        let retained = match std::fs::symlink_metadata(&checkpoint) {
            Ok(_) => true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        if dispatched && !retained {
            return refuse("interrupted handoff: dispatch marker without original policy");
        }
        let plan = if retained {
            ordered_create::bound_plan(&verified, &c.grant.destination)?
        } else {
            ordered_create::preflight(&verified, &c.grant.destination)?
        };
        if plan.destination != c.grant.destination_identity {
            return refuse("installed destination changed");
        }
        let expected = RetainedHandoff {
            schema: "realm.retained-installed-coding-handoff/v1".into(),
            grant_blake3: digest(&c.raw_grant),
            artifact_blake3: digest(&c.artifact),
            proof_blake3: digest(&c.proof_raw),
            run_id: c.run_id.clone(),
            policy: c.policy.clone(),
            approval_id: plan.approval_id()?,
            plan,
            destination: c.grant.destination.clone(),
            state: c.grant.state_root.join(&c.run_id),
        };
        if retained {
            retained_handoff(&protected_bytes(&checkpoint, 1024 * 1024)?, &expected)?;
        } else {
            retain_once(&checkpoint, &serde_json::to_vec(&expected)?)?;
        }
        // The initial policy is immutable and non-renewing. Recheck the fixed
        // grant immediately before dispatch; existing receive re-verifies all
        // canonical/native bindings and checks the lease before each effect.
        if protected_bytes(Path::new(MANIFEST), 256 * 1024)? != c.raw_grant {
            return refuse("installed grant changed before dispatch");
        }
        if !dispatched {
            retain_once(&marker, b"DISPATCH_MAY_HAVE_OCCURRED\n")?;
        }
        report.application_dispatched = true;
        let transfer = super::coding_lifecycle::receive(
            &c.artifact,
            &c.proof,
            &expected.policy,
            &expected.destination,
            &expected.state,
            Some(&expected.approval_id),
        );
        report.status = transfer.status.clone();
        report.application_dispatched = dispatched || transfer.application_dispatched;
        if transfer
            .stages
            .get(3)
            .is_some_and(|stage| stage.status == "PASS")
        {
            report.application_authorization = "AUTHORIZED_INSTALLED_GRANT";
        }
        report.transfer = Some(transfer);
        // Preserve each result separately; no acknowledgement overwrites an
        // original UNKNOWN or interrupted attempt. Effect recovery remains the
        // existing ordered journal's responsibility.
        let attempt = records.join(format!(
            "{}-{}-{}.attempt.json",
            c.run_id,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| ApplyError::Refuse("handoff clock unavailable".into()))?
                .as_nanos()
        ));
        retain_once(&attempt, &serde_json::to_vec(&report)?)?;
        Ok(())
    })();
    if let Err(error) = result {
        report.status = if report.application_dispatched {
            "INCOMPLETE_APPLICATION"
        } else if error.to_string().contains("INCOMPLETE") {
            "INCOMPLETE"
        } else if matches!(error, ApplyError::Io(_)) {
            "UNKNOWN"
        } else {
            "REFUSED"
        }
        .into();
        report.detail = error.to_string();
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    fn controlled() -> (InstalledGrant, PublicationHandoff) {
        let (_, p) = coding_transfer::tests::prospective();
        let mut policy = realm_v6::runtime_admission::fixture_candidate().policy;
        policy.expected.source_commit = p.contract.source_commit.clone();
        policy.build.source_commit = p.contract.source_commit.clone();
        policy.expected.task_sha256 = p.contract.submission.task_sha256.clone();
        policy.expected.worker_sha256 = p.contract.submission.worker_sha256.clone();
        policy.not_before_unix = 1000;
        policy.expires_at_unix = 2000;
        let admission = realm_v6::runtime_admission::SignedRuntimeAdmission {
            schema: "realm.signed-runtime-admission/v1".into(),
            reviewer_key_id: "a".repeat(64),
            policy_json: serde_json::to_string(&policy).unwrap(),
            signature_hex: "0".repeat(768),
        };
        let h = PublicationHandoff {
            workflow_trust: None,
            schema: "realm.native-coding-publication-handoff.v1".into(),
            authority: "NONE: transport record; independent receiver trust required".into(),
            run_id: p.contract.submission.run_id.clone(),
            execution_id: p.contract.submission.execution_id.clone(),
            artifact_blake3: p.artifact_blake3,
            transfer_proof_blake3: "b".repeat(64),
            genesis_root: p.genesis_root.clone(),
            exact_head_root: p.exact_head_root,
            semantic_root: p.semantic_root,
            contract: p.contract,
            runtime_admission_id: admission.identity().unwrap(),
            runtime_admission: admission,
            destination_policy: Value::Null,
            approval_id: Value::Null,
            application_dispatched: false,
        };
        (
            InstalledGrant {
                workflow: None,
                schema: "realm.installed-coding-destination-grant/v2".into(),
                provisioner_blake3: "c".repeat(64),
                publication_root: "/publisher".into(),
                genesis_root: p.genesis_root,
                approved_runtime: policy.expected,
                runtime_authority_manifest_blake3: "e".repeat(64),
                runtime_reviewer_key_id: "a".repeat(64),
                destination: "/destination".into(),
                destination_identity: DirectoryIdentity {
                    device: 1,
                    inode: 2,
                    uid: 0,
                },
                state_root: "/receiver-state".into(),
                grant_nonce: "d".repeat(64),
                not_before_unix: 900,
                expires_at_unix: 1900,
                policy_seconds: 300,
            },
            h,
        )
    }
    #[test]
    fn workflow_policy_requires_setup_owned_profiles_and_preserves_attempt_lease() {
        // Data-only policy derivation: zero signatures cannot pass the actual
        // installed loader or independent receiver; no native owners exist here.
        let (mut grant, mut handoff) = controlled();
        let mut api = grant.approved_runtime.clone();
        api.checker_scope_sha256 = "8".repeat(64);
        grant.workflow = Some(InstalledWorkflowGrant {
            workflow: "9".repeat(64),
            approved_api_runtime: api.clone(),
        });
        assert!(derive_policy(&grant, &"e".repeat(64), &handoff, 1001).is_err());
        let mut policy = handoff.runtime_admission.policy().unwrap();
        policy.expected = api;
        policy.expires_at_unix = 1200;
        let mut prior = handoff.runtime_admission.clone();
        prior.policy_json = serde_json::to_string(&policy).unwrap();
        handoff.workflow_trust = Some(super::super::coding_qualification::NativeWorkflowTrust {
            workflow: "9".repeat(64),
            prior_admissions: vec![prior],
        });
        let derived = derive_policy(&grant, &"e".repeat(64), &handoff, 1001).unwrap();
        assert_eq!(derived.expires_at_unix, 1200);
        assert!(derived.workflow_trust.is_some());
        assert!(derive_policy(&grant, &"e".repeat(64), &handoff, 1200).is_err());
        let mut changed = handoff;
        changed.workflow_trust.as_mut().unwrap().workflow = "7".repeat(64);
        assert!(derive_policy(&grant, &"e".repeat(64), &changed, 1001).is_err());
    }

    #[test]
    fn controlled_policy_data_is_bounded_stable_and_never_runtime_authority() {
        let (g, h) = controlled();
        let a = derive_policy(&g, &"e".repeat(64), &h, 1001).unwrap();
        let retry = derive_policy(&g, &"e".repeat(64), &h, 1100).unwrap();
        assert_eq!(a, retry);
        assert_eq!((a.not_before_unix, a.expires_at_unix), (1000, 1300));
        assert!(derive_policy(&g, &"e".repeat(64), &h, 1300).is_err());
        assert!(a.runtime_admission.as_ref().unwrap().verify().is_err());
        assert!(derive_policy(&g, &"f".repeat(64), &h, 1001).unwrap().nonce != a.nonce);
        println!("CONTROLLED_POLICY_DATA=PASS authority=NONE production_admission=REFUSE");
    }
    #[test]
    fn receiver_authority_pins_and_prelaunch_setup_cannot_be_substituted() {
        let (mut g, h) = controlled();
        g.provisioner_blake3 = g.approved_runtime.native_controller_blake3.clone();
        let configuration = realm_v6::runtime_admission::InstalledRuntimeConfiguration {
            manifest_blake3: g.runtime_authority_manifest_blake3.clone(),
            reviewer_key_id: g.runtime_reviewer_key_id.clone(),
            approved_profile: h.runtime_admission.policy().unwrap(),
            issuance_not_before_unix: 900,
            issuance_expires_at_unix: 1900,
        };
        check_configuration(&g, &configuration, &g.genesis_root, 1001).unwrap();
        for case in 0..11 {
            let mut bad = configuration.clone();
            let mut grant = g.clone();
            let mut genesis = g.genesis_root.clone();
            match case {
                0 => bad.manifest_blake3 = "0".repeat(64),
                1 => bad.reviewer_key_id = "0".repeat(64),
                2 => bad.approved_profile.expected.task_sha256 = "0".repeat(64),
                3 => bad.approved_profile.expected.source_commit = "0".repeat(40),
                4 => bad.approved_profile.expected.kernel_blake3 = "0".repeat(64),
                5 => bad.issuance_not_before_unix = 1002,
                6 => bad.issuance_expires_at_unix = 1001,
                7 => genesis = "0".repeat(64),
                8 => grant.provisioner_blake3 = "0".repeat(64),
                9 => grant.runtime_reviewer_key_id = "0".repeat(64),
                10 => grant.schema = "realm.installed-coding-destination-grant/v1".into(),
                _ => unreachable!(),
            }
            assert!(
                check_configuration(&grant, &bad, &genesis, 1001).is_err(),
                "case {case}"
            );
        }
        let mut substituted = h;
        substituted.runtime_admission.reviewer_key_id = "0".repeat(64);
        assert!(derive_policy(&g, &"e".repeat(64), &substituted, 1001).is_err());
        println!("SETUP_COHERENCE_DATA=PASS authority=NONE substitutions=REFUSE native=NOT_RUN");
    }
    #[test]
    fn grant_scope_expiry_destination_and_runtime_substitution_refuse() {
        for i in 0..12 {
            let (mut g, mut h) = controlled();
            match i {
                0 => g.not_before_unix = 1100,
                1 => g.expires_at_unix = 999,
                2 => g.policy_seconds = 0,
                3 => g.genesis_root = "0".repeat(64),
                4 => g.destination_identity.uid = 501,
                5 => g.approved_runtime.task_sha256 = "0".repeat(64),
                6 => g.approved_runtime.checker_sha256 = "0".repeat(64),
                7 => h.run_id = "0".repeat(64),
                8 => h.execution_id = "0".repeat(64),
                9 => h.runtime_admission_id = "0".repeat(64),
                10 => h.approval_id = Value::String("0".repeat(64)),
                11 => h.application_dispatched = true,
                _ => unreachable!(),
            }
            assert!(
                derive_policy(&g, &"e".repeat(64), &h, 1001).is_err(),
                "case {i}"
            );
        }
    }
    #[test]
    fn grant_paths_cannot_overlap_or_traverse() {
        for p in [
            "/publisher",
            "/publisher/sub",
            "/",
            "/a/../b",
            "/a/./b",
            "relative",
        ] {
            let (mut g, h) = controlled();
            g.destination = p.into();
            assert!(derive_policy(&g, &"e".repeat(64), &h, 1001).is_err(), "{p}");
        }
        for p in ["", "../outside", "/outside", "a/b", &"a".repeat(65)] {
            assert!(provision_installed(p).is_err());
        }
    }
    #[test]
    fn grant_decoder_rejects_duplicate_and_unknown_fields() {
        let (g, _) = controlled();
        let raw = serde_json::to_string(&g).unwrap();
        let duplicate = format!("{{\"schema\":\"substitution\",{}", &raw[1..]);
        assert!(coding_transfer::strict_json::<InstalledGrant>(duplicate.as_bytes()).is_err());
        let mut v = serde_json::to_value(g).unwrap();
        v["agent_can_select_destination"] = true.into();
        assert!(
            coding_transfer::strict_json::<InstalledGrant>(&serde_json::to_vec(&v).unwrap())
                .is_err()
        );
    }
    fn controlled_checkpoint() -> RetainedHandoff {
        let (g, h) = controlled();
        let policy = derive_policy(&g, &"e".repeat(64), &h, 1001).unwrap();
        // DATA ONLY: no verifier callback or VerifiedCreateBatch is created.
        let plan = ordered_create::OrderedPlan {
            schema: "TEST_ONLY_NO_APPLICATION_AUTHORITY".into(),
            artifact: h.artifact_blake3.clone(),
            run: h.run_id.clone(),
            head: h.exact_head_root.clone(),
            semantic: h.semantic_root.clone(),
            destination: g.destination_identity.clone(),
            before: "1".repeat(64),
            after: "2".repeat(64),
            operations: Vec::new(),
            authorization: Some(policy.authorization_binding().unwrap()),
        };
        RetainedHandoff {
            schema: "realm.retained-installed-coding-handoff/v1".into(),
            grant_blake3: "e".repeat(64),
            artifact_blake3: h.artifact_blake3,
            proof_blake3: h.transfer_proof_blake3,
            run_id: h.run_id.clone(),
            policy,
            approval_id: plan.approval_id().unwrap(),
            plan,
            destination: g.destination,
            state: g.state_root.join(h.run_id),
        }
    }
    #[test]
    fn handoff_checkpoint_rejects_substitution_and_interrupted_data() {
        let expected = controlled_checkpoint();
        let raw = serde_json::to_vec(&expected).unwrap();
        assert_eq!(retained_handoff(&raw, &expected).unwrap(), expected);
        for bytes in [b"".as_slice(), b"{", &raw[..raw.len() - 1]] {
            assert!(retained_handoff(bytes, &expected).is_err());
        }
        for i in 0..8 {
            let mut bad = expected.clone();
            match i {
                0 => bad.artifact_blake3 = "0".repeat(64),
                1 => bad.proof_blake3 = "0".repeat(64),
                2 => bad.run_id = "0".repeat(64),
                3 => bad.grant_blake3 = "0".repeat(64),
                4 => bad.destination = "/invalid-destination".into(),
                5 => bad.state = "/other-state".into(),
                6 => bad.policy.expires_at_unix += 1,
                7 => bad.approval_id = "0".repeat(64),
                _ => unreachable!(),
            }
            assert!(
                retained_handoff(&serde_json::to_vec(&bad).unwrap(), &expected).is_err(),
                "case{i}"
            );
        }
        println!("HANDOFF_DATA=PASS authority=NONE interrupted_and_substituted=REFUSE");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn handoff_persistence_never_overwrites_interrupted_history() {
        let Ok(root) = std::env::var("REALM_POLICY_FIXTURE_ROOT") else {
            return;
        };
        assert_eq!(root, "/fixture-policy");
        assert_eq!(std::env::var("REALM_TEST_ONLY_CONTAINER").unwrap(), "1");
        assert!(
            std::fs::read_to_string("/proc/mounts")
                .unwrap()
                .lines()
                .any(|s| s.split_whitespace().nth(1) == Some("/fixture-policy")
                    && s.split_whitespace().nth(2) == Some("tmpfs"))
        );
        let dir = Path::new(&root).join("handoff-persistence");
        std::fs::create_dir(&dir).unwrap();
        let expected = controlled_checkpoint();
        let raw = serde_json::to_vec(&expected).unwrap();
        let p = dir.join("checkpoint.json");
        retain_once(&p, &raw).unwrap();
        assert!(retain_once(&p, b"replacement").is_err());
        assert_eq!(std::fs::read(&p).unwrap(), raw);
        assert_eq!(
            retained_handoff(&protected_bytes(&p, 1024 * 1024).unwrap(), &expected).unwrap(),
            expected
        );
        let partial = dir.join("partial.json");
        retain_once(&partial, b"{").unwrap();
        assert!(retained_handoff(&protected_bytes(&partial, 100).unwrap(), &expected).is_err());
        assert_eq!(std::fs::read(partial).unwrap(), b"{");
        let missing = dir.join("missing.dispatch");
        assert!(!dispatch_marker(&missing).unwrap());
        let marker = dir.join("actual.dispatch");
        retain_once(&marker, b"DISPATCH_MAY_HAVE_OCCURRED\n").unwrap();
        assert!(dispatch_marker(&marker).unwrap());
        let torn = dir.join("torn.dispatch");
        retain_once(&torn, b"DISPATCH_").unwrap();
        assert!(dispatch_marker(&torn).is_err());
        let lock = dir.join("lock");
        let first = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&lock)
            .unwrap();
        let owned = ordered_create::OwnedJournalLock::acquire(first).unwrap();
        assert!(ordered_create::OwnedJournalLock::acquire(File::open(&lock).unwrap()).is_err());
        drop(owned);
        assert!(ordered_create::OwnedJournalLock::acquire(File::open(&lock).unwrap()).is_ok());
        println!(
            "HANDOFF_PERSISTENCE=PASS authority=NONE tmpfs_only=true dispatch_history=CONSERVATIVE"
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn protected_reader_controls_on_disposable_linux_tmpfs_only() {
        let Ok(root) = std::env::var("REALM_POLICY_FIXTURE_ROOT") else {
            return;
        };
        assert_eq!(std::env::var("REALM_TEST_ONLY_CONTAINER").unwrap(), "1");
        assert_eq!(root, "/fixture-policy");
        assert!(
            std::fs::read_to_string("/proc/mounts")
                .unwrap()
                .lines()
                .any(|s| {
                    let p: Vec<_> = s.split_whitespace().collect();
                    p.get(1) == Some(&"/fixture-policy") && p.get(2) == Some(&"tmpfs")
                })
        );
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = Path::new(&root);
        let file = root.join("record.json");
        std::fs::write(&file, b"TEST_ONLY_NO_AUTHORITY").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            protected_bytes(&file, 100).unwrap(),
            b"TEST_ONLY_NO_AUTHORITY"
        );
        assert!(protected_bytes(&file, 1).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(protected_bytes(&file, 100).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let alias = root.join("alias");
        symlink(&file, &alias).unwrap();
        assert!(protected_bytes(&alias, 100).is_err());
        let hard = root.join("hard");
        std::fs::hard_link(&file, &hard).unwrap();
        assert!(protected_bytes(&file, 100).is_err());
        std::fs::remove_file(hard).unwrap();
        let c = std::ffi::CString::new(file.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(c.as_ptr(), 501, 501) }, 0);
        assert!(protected_bytes(&file, 100).is_err());
        println!("PROTECTED_READER=PASS authority=NONE tmpfs_only=true");
    }
}
