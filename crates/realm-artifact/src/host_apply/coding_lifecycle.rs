//! One receiving harness over canonical verification, planning, application and
//! final observation. No executor, signer, issuer, shell replay or callback.
use super::coding_transfer::{CodingTransferPolicy, inspect_content, now_unix};
use super::ordered_create::{
    self, OrderedPlan, OrderedProgress, OrderedReceipt, VerifiedCreateBatch,
};
use super::*;

/// Operator-supplied acceptance inputs, authenticated by an independent raw pin.
/// This describes an approval; parsing it never grants publication authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingTransferBinding {
    pub schema_version: u16,
    pub artifact: std::path::PathBuf,
    pub proof: std::path::PathBuf,
    pub policy: std::path::PathBuf,
    pub destination: std::path::PathBuf,
    pub state: std::path::PathBuf,
    pub approval_id: String,
}
pub struct BoundCodingTransfer {
    pub binding_bytes: Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub policy_bytes: Vec<u8>,
    pub binding: CodingTransferBinding,
    pub artifact: Vec<u8>,
    pub proof: TransferProof,
    pub policy: CodingTransferPolicy,
}
/// Reopen every input through the shared no-follow reader. No destination is
/// opened, created or modified. An artifact-supplied binding is not trusted.
pub fn load_bound_transfer(path: &Path, independent_pin: &str) -> Result<BoundCodingTransfer> {
    if !valid_digest(independent_pin) {
        return refuse("independent coding binding pin required");
    }
    let raw = read_transfer_file(path)?;
    if digest(&raw) != independent_pin {
        return refuse("independent coding binding pin differs");
    }
    let binding: CodingTransferBinding = coding_transfer::strict_json(&raw)?;
    let absolute_unaliased = |p: &Path| {
        p.is_absolute()
            && p.components().collect::<std::path::PathBuf>().as_os_str() == p.as_os_str()
    };
    if binding.schema_version != 1
        || !valid_digest(&binding.approval_id)
        || [
            &binding.artifact,
            &binding.proof,
            &binding.policy,
            &binding.destination,
            &binding.state,
        ]
        .into_iter()
        .any(|p| !absolute_unaliased(p))
        || binding.state.starts_with(&binding.destination)
        || binding.destination.starts_with(&binding.state)
        || [
            &binding.artifact,
            &binding.proof,
            &binding.policy,
            &path.to_owned(),
        ]
        .into_iter()
        .any(|p| p.starts_with(&binding.destination) || p.starts_with(&binding.state))
    {
        return refuse(
            "coding binding requires exact approval and separate unaliased absolute inputs/destination/state",
        );
    }
    let artifact = read_transfer_file(&binding.artifact)?;
    let proof_bytes = read_transfer_file(&binding.proof)?;
    let policy_bytes = read_transfer_file(&binding.policy)?;
    let proof = coding_transfer::strict_json(&proof_bytes)?;
    let policy = coding_transfer::strict_json(&policy_bytes)?;
    Ok(BoundCodingTransfer {
        binding_bytes: raw,
        proof_bytes,
        policy_bytes,
        binding,
        artifact,
        proof,
        policy,
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct StageCheck {
    pub stage: String,
    pub status: String,
    pub detail: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct TransferAttempt {
    pub schema: String,
    pub evidence_class: String,
    pub authority: String,
    pub status: String,
    pub artifact_blake3: String,
    pub stages: Vec<StageCheck>,
    pub plan: Option<OrderedPlan>,
    pub approval_id: Option<String>,
    pub progress: Option<OrderedProgress>,
    pub receipt: Option<OrderedReceipt>,
    /// True after application dispatch, even when an error prevents a reply.
    /// False is never inferred from a missing acknowledgement.
    pub application_dispatched: bool,
}
impl TransferAttempt {
    fn new(bytes: &[u8], fixture: bool) -> Self {
        Self {
            schema: "realm.v7.destination-transfer-attempt.v1".into(),
            evidence_class: if fixture {
                "NON_AUTHORIZING_RECEIVER_FIXTURE"
            } else {
                "PRODUCTION_CODING_ATTEMPT"
            }
            .into(),
            authority: "NONE".into(),
            status: "NOT_RUN".into(),
            artifact_blake3: digest(bytes),
            stages: [
                "canonical-content-and-contract",
                "publication-and-native-authority",
                "destination-plan",
                "separate-destination-approval",
                "restricted-application",
                "independent-final-verification",
            ]
            .map(|stage| StageCheck {
                stage: stage.into(),
                status: "NOT_RUN".into(),
                detail: String::new(),
            })
            .to_vec(),
            plan: None,
            approval_id: None,
            progress: None,
            receipt: None,
            application_dispatched: false,
        }
    }
    fn pass(&mut self, index: usize, detail: &str) {
        self.stages[index].status = "PASS".into();
        self.stages[index].detail = detail.into();
    }
    fn error(&mut self, index: usize, error: &ApplyError) {
        let unknown = matches!(error, ApplyError::Io(_));
        self.stages[index].status = if unknown { "UNKNOWN" } else { "REFUSE" }.into();
        self.stages[index].detail = error.to_string();
        self.status = if self.application_dispatched {
            "INCOMPLETE_APPLICATION"
        } else if unknown {
            "UNKNOWN"
        } else {
            "REFUSED"
        }
        .into();
    }
}

/// The genuine artifact acceptance test. There is no fixture fallback. Native
/// authority must be established before the destination or journal is opened.
pub fn receive(
    bytes: &[u8],
    proof: &TransferProof,
    policy: &CodingTransferPolicy,
    destination: &Path,
    state: &Path,
    approval: Option<&str>,
) -> TransferAttempt {
    let mut r = TransferAttempt::new(bytes, false);
    let content = now_unix().and_then(|now| inspect_content(bytes, policy, now));
    if let Err(e) = content {
        r.error(0, &e);
        return r;
    }
    r.pass(0, "canonical contents, approved task/source/run/submission/projection and policy window match; no native authority inferred");
    let v = match coding_transfer::verify_transfer(bytes, proof, policy) {
        Ok(v) => v,
        Err(e) => {
            r.error(1, &e);
            return r;
        }
    };
    r.pass(1, "canonical exact-head publication and registered native coding authority independently verified");
    r.authority = "QUALIFIED_CODING".into();
    receive_verified(&v, destination, state, approval, r)
}

// Only crate-owned production verification or the isolated fixture wrapper may
// enter this function. Callers cannot inject a verifier, signer, or executor.
fn receive_verified(
    v: &VerifiedCreateBatch,
    destination: &Path,
    state: &Path,
    approval: Option<&str>,
    mut r: TransferAttempt,
) -> TransferAttempt {
    let plan = match if approval.is_none() {
        ordered_create::preflight(v, destination)
    } else {
        ordered_create::bound_plan(v, destination)
    } {
        Ok(p) => p,
        Err(e) => {
            r.error(2, &e);
            return r;
        }
    };
    r.pass(2, if approval.is_none() { "initial empty destination, private directory identity and exact operation plan verified" } else { "destination identity and plan bound; current owned prefix must be reconciled by journal before any effect" });
    let id = match plan.approval_id() {
        Ok(id) => id,
        Err(e) => {
            r.error(2, &e);
            return r;
        }
    };
    r.approval_id = Some(id.clone());
    r.plan = Some(plan);
    let Some(approval) = approval else {
        r.status = "PREPARED_REQUIRES_SEPARATE_APPROVAL".into();
        return r;
    };
    if approval != id {
        r.error(
            3,
            &ApplyError::Refuse(
                "destination approval differs from exact independently verified plan".into(),
            ),
        );
        return r;
    }
    r.pass(3, "explicit exact destination-bound approval supplied; validity rechecked before dispatch and each publication");
    r.application_dispatched = true;
    if let Err(e) = ordered_create::apply(v, destination, state, approval) {
        r.error(4, &e);
        r.progress = ordered_create::progress(v, destination, state).ok();
        return r;
    }
    r.pass(
        4,
        "three permitted create effects durably complete; batch is not atomic",
    );
    match ordered_create::verify_host(v, destination, state) {
        Ok(receipt) => {
            r.pass(5, "fresh independent descriptor-based journal, inode, bytes, mode and receipt verification");
            r.receipt = Some(receipt);
            r.progress = ordered_create::progress(v, destination, state).ok();
            r.status = if r.authority == "NONE" {
                "NON_AUTHORIZING_FIXTURE_APPLIED"
            } else {
                "APPLIED_AND_FINAL_VERIFIED"
            }
            .into();
        }
        Err(e) => r.error(5, &e),
    }
    r
}

#[cfg(any(test, feature = "receiver-fixtures"))]
pub(super) fn fixture_receive(
    artifact_pin: &str,
    v: &VerifiedCreateBatch,
    destination: &Path,
    state: &Path,
    approval: Option<&str>,
) -> TransferAttempt {
    let mut r = TransferAttempt::new(&[], true);
    // The wrapper already verified canonical fixture bytes and exact pin.
    r.artifact_blake3 = artifact_pin.into();
    r.pass(
        0,
        "NON_AUTHORIZING canonical fixture and independent exact pin checked",
    );
    r.stages[1].status = "NOT_APPLICABLE_FIXTURE".into();
    r.stages[1].detail =
        "No production execution, publication or native authority exists for this fixture".into();
    receive_verified(v, destination, state, approval, r)
}
