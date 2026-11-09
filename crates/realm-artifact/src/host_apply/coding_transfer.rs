//! Coding producer/receiver adapter over the sole native publication issuer.
//! Detached verification requires an independently authenticated exact head.
//! The native coding-scoped same-run proof remains unavailable; content and
//! development signatures cannot replace it.
use super::*;
#[cfg(test)]
use realm_v6::coding_submission::{PATHS, SubmissionContract};

pub use realm_v6::coding_submission::{
    CODING_PROFILE as PROFILE, CodingFileCommitment as CodingFile,
    CodingTransferContract as CodingContract, TRANSFER_CONTRACT_DOMAIN as CONTRACT_DOMAIN,
};
pub const AUTHORIZATION_DOMAIN: &str = "realm.v7.destination-authorization.v1";

/// Receiver trust input. Must arrive through an independently authenticated
/// operator channel, never from the transferred candidate. Follows existing
/// ArtifactPermit exact raw-artifact/genesis/head trust conventions. The coding
/// profile uses a distinct strict shape, while C0 schema-1 permits are unchanged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingTransferPolicy {
    pub schema_version: u16,
    pub authorization_domain: String,
    pub artifact_blake3: String,
    pub genesis_root: String,
    pub exact_head_root: String,
    pub semantic_root: String,
    pub contract: CodingContract,
    /// Independently provisioned admission statement, never selected from the
    /// artifact. Version 1 remains readable as non-authorizing legacy data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_admission: Option<realm_v6::runtime_admission::SignedRuntimeAdmission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_trust: Option<super::coding_qualification::NativeWorkflowTrust>,
    pub destination: DirectoryIdentity,
    pub nonce: String,
    pub not_before_unix: u64,
    pub expires_at_unix: u64,
}
impl CodingTransferPolicy {
    pub fn validate_structure(&self) -> Result<()> {
        self.contract.validate()?;
        if !matches!(
            (self.schema_version, &self.runtime_admission),
            (1, None) | (2, Some(_))
        ) || self.authorization_domain != AUTHORIZATION_DOMAIN
            || ![
                &self.artifact_blake3,
                &self.genesis_root,
                &self.exact_head_root,
                &self.semantic_root,
                &self.nonce,
            ]
            .iter()
            .all(|s| valid_digest(s))
            || self.expires_at_unix <= self.not_before_unix
            || self.expires_at_unix - self.not_before_unix > 86400
        {
            return refuse("invalid, expired, future, or wrong-domain coding transfer policy");
        }
        if let Some(workflow) = &self.workflow_trust
            && (self.schema_version != 2
                || !valid_digest(&workflow.workflow)
                || !(1..=3).contains(&workflow.prior_admissions.len()))
        {
            return refuse("invalid independently provisioned native workflow policy");
        }
        if let Some(admission) = &self.runtime_admission {
            // Parsing a permitted statement is not verification of its signer
            // or proof that a runtime executed. Those checks precede authority.
            let admitted = admission.policy().map_err(ApplyError::Refuse)?;
            if admitted.expected.source_commit != self.contract.source_commit
                || admitted.expected.task_sha256 != self.contract.submission.task_sha256
                || admitted.expected.worker_sha256 != self.contract.submission.worker_sha256
            {
                return refuse("independent runtime admission and destination task policy differ");
            }
        }
        Ok(())
    }
    pub fn validate(&self, now: u64) -> Result<()> {
        self.validate_structure()?;
        if now < self.not_before_unix || now >= self.expires_at_unix {
            return refuse("coding transfer policy expired or not yet valid");
        }
        if let Some(admission) = &self.runtime_admission
            && !admission
                .policy()
                .map_err(ApplyError::Refuse)?
                .permits_time(now)
        {
            return refuse("runtime admission expired or not yet valid at receiving");
        }
        Ok(())
    }
    pub fn authorization_binding(&self) -> Result<ordered_create::AuthorizationBinding> {
        self.validate_structure()?;
        // Observation may happen after expiry. A batch returned for that
        // purpose must remain unable to apply outside BOTH trust windows.
        let (mut not_before_unix, mut expires_at_unix) =
            (self.not_before_unix, self.expires_at_unix);
        if let Some(admission) = &self.runtime_admission {
            let runtime = admission.policy().map_err(ApplyError::Refuse)?;
            not_before_unix = not_before_unix.max(runtime.not_before_unix);
            expires_at_unix = expires_at_unix.min(runtime.expires_at_unix);
        }
        if expires_at_unix <= not_before_unix {
            return refuse("destination and runtime admission windows do not overlap");
        }
        Ok(ordered_create::AuthorizationBinding {
            policy_id: self.identity()?,
            domain: self.authorization_domain.clone(),
            nonce: self.nonce.clone(),
            destination: self.destination.clone(),
            not_before_unix,
            expires_at_unix,
        })
    }
    pub fn identity(&self) -> Result<String> {
        Ok(crate::hash(AUTHORIZATION_DOMAIN, &serde_json::to_vec(self)?).value)
    }
}
/// Strict JSON for trust sidecars and manifests; duplicate nested map keys must
/// never be silently collapsed before policy or lifecycle checks.
pub fn strict_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value = realm_v6::strict_json::parse(bytes)
        .map_err(|_| ApplyError::Refuse("malformed or duplicate-key transfer JSON".into()))?;
    Ok(serde_json::from_value(value)?)
}
pub fn now_unix() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ApplyError::Refuse("trusted clock unavailable".into()))
}

#[derive(Clone, Debug, Serialize)]
pub struct CodingTransferInspection {
    pub authority: String,
    pub policy_id: String,
    pub run_id: String,
    pub execution_id: String,
    pub source_commit: String,
    pub artifact_blake3: String,
    pub semantic_root: String,
    pub operations: [CodingFile; 3],
    pub native_authority: String,
}
/// Checks canonical bytes and SAME-RUN CONTENT bindings only, without issuing
/// any capability. Useful independently of a missing producer publication.
pub fn inspect_content(
    bytes: &[u8],
    policy: &CodingTransferPolicy,
    now: u64,
) -> Result<CodingTransferInspection> {
    policy.validate(now)?;
    inspect_bound_content(bytes, policy)
}

/// Read-only observation remains possible after application approval expires.
/// The policy still has to be structurally valid and every identity must match.
pub fn inspect_for_observation(
    bytes: &[u8],
    policy: &CodingTransferPolicy,
) -> Result<CodingTransferInspection> {
    policy.validate_structure()?;
    inspect_bound_content(bytes, policy)
}
fn inspect_bound_content(
    bytes: &[u8],
    policy: &CodingTransferPolicy,
) -> Result<CodingTransferInspection> {
    if digest(bytes) != policy.artifact_blake3 {
        return refuse("coding artifact external pin differs");
    }
    let bundle = ordered_create::candidate::decode(bytes)?;
    if bundle.run.effect_contract.identity != CONTRACT_DOMAIN
        || bundle.run.environment.runtime == "NON_AUTHORIZING_RECEIVER_FIXTURE"
        || bundle.semantic_identity()?.value != policy.semantic_root
        || bundle.run.run.run_id != policy.contract.submission.run_id
        || bundle.run.run.execution_id != policy.contract.submission.execution_id
        || bundle
            .run
            .challenge
            .nonce
            .as_ref()
            .map(|d| d.value.as_str())
            != Some(policy.contract.submission.challenge_root.as_str())
        || bundle.run.effect_contract.digest
            != crate::hash(CONTRACT_DOMAIN, &serde_json::to_vec(&policy.contract)?)
    {
        return refuse("coding run/execution/challenge/semantic/task contract substitution");
    }
    let evidence = |id: &str| -> Result<&[u8]> {
        let refs: Vec<_> = bundle.run.evidence.iter().filter(|r| r.id == id).collect();
        if refs.len() != 1
            || refs[0].run_id != policy.contract.submission.run_id
            || refs[0].checkpoint.is_some()
        {
            return refuse("missing, ambiguous or cross-run coding evidence reference");
        }
        bundle
            .blobs
            .get(&refs[0].digest.value)
            .map(Vec::as_slice)
            .ok_or_else(|| ApplyError::Refuse("coding evidence unavailable".into()))
    };
    let raw_contract = evidence("v7-coding-contract")?;
    let received: CodingContract = strict_json(raw_contract)?;
    if received != policy.contract || raw_contract != serde_json::to_vec(&received)? {
        return refuse("approved coding contract/source differs or is noncanonical");
    }
    let submission = policy
        .contract
        .submission
        .decode(evidence("v7-coding-submission")?)
        .map_err(|s| ApplyError::Refuse(s.into()))?;
    for (i, expected) in policy.contract.files.iter().enumerate() {
        let output = &bundle.run.outputs[i];
        let content = &bundle.blobs[&output.digest.value];
        if digest(content) != expected.content_blake3
            || content.len() as u64 != expected.bytes
            || submission.files[i].text.as_bytes() != content
            || submission.files[i].mode != expected.mode
        {
            return refuse("output, native submission and approved projection differ");
        }
    }
    // Native run world commitments describe the custodian's bounded packet
    // object, not the three destination files. The canonical V6 validator binds
    // those native worlds; destination projection is checked by its own plan.
    Ok(CodingTransferInspection {
        authority: "NONE: authenticated publication and native authority still required".into(),
        policy_id: policy.identity()?,
        run_id: policy.contract.submission.run_id.clone(),
        execution_id: policy.contract.submission.execution_id.clone(),
        source_commit: policy.contract.source_commit.clone(),
        artifact_blake3: policy.artifact_blake3.clone(),
        semantic_root: policy.semantic_root.clone(),
        operations: policy.contract.files.clone(),
        native_authority: "NOT_VERIFIED".into(),
    })
}

/// Complete detached entry point, reusing the sole canonical lifecycle verifier.
/// The last native coding join is unavailable, including on otherwise perfectly
/// pinned content. No development/test signature or fixture can bypass it.
pub fn verify_transfer(
    bytes: &[u8],
    proof: &TransferProof,
    policy: &CodingTransferPolicy,
) -> Result<ordered_create::VerifiedCreateBatch> {
    inspect_content(bytes, policy, now_unix()?)?;
    publication_and_native_batch(bytes, proof, policy)
}

/// Native authority is still required for final/progress observation, but an
/// expired application window does not hide a previously applied result.
/// Application of any returned batch must recheck its bound policy window.
pub fn verify_for_observation(
    bytes: &[u8],
    proof: &TransferProof,
    policy: &CodingTransferPolicy,
) -> Result<ordered_create::VerifiedCreateBatch> {
    inspect_for_observation(bytes, policy)?;
    publication_and_native_batch(bytes, proof, policy)
}
fn publication_and_native_batch(
    bytes: &[u8],
    proof: &TransferProof,
    policy: &CodingTransferPolicy,
) -> Result<ordered_create::VerifiedCreateBatch> {
    // Bound the retained history before the generic lifecycle verifier walks it.
    // C0's historical verifier and artifact schema are unchanged.
    if proof.snapshot.transitions.len() > 64
        || proof.snapshot.artifacts.len() > 64
        || proof.snapshot.receipts.len() > 64
        || proof.snapshot.retained_world_roots.len() > 64
        || proof.snapshot.journal.len() > 4 * 1024 * 1024
        || proof
            .snapshot
            .artifacts
            .values()
            .fold(0usize, |n, b| n.saturating_add(b.len()))
            > MAX_TRANSFER_BYTES as usize
        || proof
            .snapshot
            .receipts
            .values()
            .fold(0usize, |n, b| n.saturating_add(b.len()))
            > 4 * 1024 * 1024
    {
        return refuse("coding retained-publication resource budget exceeded");
    }
    let bundle = pinned_publication(
        bytes,
        proof,
        &policy.artifact_blake3,
        &policy.genesis_root,
        &policy.exact_head_root,
    )?;
    let references: Vec<_> = bundle
        .run
        .evidence
        .iter()
        .filter(|r| r.id == "v6-checked-c1")
        .collect();
    if references.len() != 1
        || references[0].run_id != policy.contract.submission.run_id
        || references[0].checkpoint.is_some()
    {
        return refuse("missing, ambiguous or cross-run canonical native coding evidence");
    }
    let reference = references[0];
    let checked: realm_v6::execute::CheckedC1Evidence =
        strict_json(&bundle.blobs[&reference.digest.value])?;
    let coding = checked.coding.as_ref().ok_or_else(|| {
        ApplyError::Refuse(
            "REFUSE_UNVERIFIED_BOUNDARY: C0/diagnostic evidence cannot authorize coding transfer"
                .into(),
        )
    })?;
    if !coding.semantic_evidence.as_ref().is_some_and(|semantic| {
        semantic.matches_data(coding)
            && realm_v6::mediation::check_coding_manifest_claim_shape(
                &checked.c1_manifest,
                &checked.c1_manifest_root,
            )
            .is_ok_and(|manifest| {
                semantic.measurement_root == manifest.manifest.measured_launch_blake3
            })
    }) {
        return Err(ApplyError::Refuse("REFUSE_UNVERIFIED_BOUNDARY: qualified finite coding semantic evidence is missing or differs".into()));
    }

    if checked.schema_version != 9
        || !realm_v6::execute::validate_checked_c1_evidence(&checked)
        || coding.contract != policy.contract
        || coding.submission.as_slice()
            != bundle.blobs[&bundle
                .run
                .evidence
                .iter()
                .find(|r| r.id == "v7-coding-submission")
                .ok_or_else(|| ApplyError::Refuse("coding submission unavailable".into()))?
                .digest
                .value]
                .as_slice()
        || checked.run_id != policy.contract.submission.run_id
        || checked.execution_id != policy.contract.submission.execution_id
    {
        return refuse(
            "REFUSE_UNVERIFIED_BOUNDARY: native coding task/profile/packet/publication binding differs",
        );
    }
    let permitted = policy.runtime_admission.as_ref().ok_or_else(|| {
        ApplyError::Refuse(
            "REFUSE_UNVERIFIED_BOUNDARY: independently provisioned runtime admission missing"
                .into(),
        )
    })?;
    let semantic = coding.semantic_evidence.as_ref().ok_or_else(|| {
        ApplyError::Refuse("REFUSE_UNVERIFIED_BOUNDARY: qualification receipt missing".into())
    })?;
    match &policy.workflow_trust {
        Some(trust) => coding_qualification::check_workflow_receipt(semantic, permitted, trust)?,
        None => coding_qualification::check_receipt(semantic, permitted)?,
    }
    // Only the common exact-head verifier plus the canonical native validator
    // reaches this private constructor. No external verifier callback is used.
    Ok(ordered_create::VerifiedCreateBatch::from_verified_coding(
        policy.artifact_blake3.clone(),
        checked.run_id,
        policy.exact_head_root.clone(),
        policy.semantic_root.clone(),
        std::array::from_fn(|i| bundle.blobs[&bundle.run.outputs[i].digest.value].clone()),
        policy.authorization_binding()?,
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::host_apply::ordered_create::fixtures;
    use crate::{EvidenceRef, Lifecycle};

    pub(crate) fn prospective() -> (Vec<u8>, CodingTransferPolicy) {
        let files = [
            b"# UNIT_TEST_ONLY totals\n".to_vec(),
            b"# UNIT_TEST_ONLY report\n".to_vec(),
            b"# UNIT_TEST_ONLY checks\n".to_vec(),
        ];
        let raw = fixtures::artifact(&"a".repeat(64), files.clone()).unwrap();
        let submission = SubmissionContract {
            run_id: "a".repeat(64),
            execution_id: "b".repeat(64),
            challenge_root: "c".repeat(64),
            task_sha256: "d".repeat(64),
            worker_sha256: "e".repeat(64),
        };
        let contract = CodingContract {
            schema_version: 1,
            profile: PROFILE.into(),
            submission: submission.clone(),
            source_commit: "f".repeat(40),
            semantic_commitment: "1".repeat(64),
            files: std::array::from_fn(|i| CodingFile {
                path: PATHS[i].into(),
                content_blake3: digest(&files[i]),
                bytes: files[i].len() as u64,
                mode: 0o600,
            }),
        };
        let mut bundle = ArtifactBundle::unpack(&raw).unwrap();
        bundle.run.run.execution_id = submission.execution_id.clone();
        bundle.run.effect_contract.identity = CONTRACT_DOMAIN.into();
        bundle.run.environment.runtime = "UNIT_TEST_ONLY_NO_EXECUTION".into();
        bundle.run.challenge.nonce.as_mut().unwrap().value = submission.challenge_root.clone();
        bundle.run.effect_contract.digest =
            crate::hash(CONTRACT_DOMAIN, &serde_json::to_vec(&contract).unwrap());
        let (before, after) = contract.worlds().unwrap();
        bundle.run.starting_state.digest.value = before;
        bundle.run.starting_state.digest.domain = "realm.world".into();
        bundle.run.final_state.as_mut().unwrap().digest.value = after;
        bundle.run.final_state.as_mut().unwrap().digest.domain = "realm.world".into();
        let packet = realm_v6::coding_submission::Submission {
            schema: "realm.coding-submission.v1".into(),
            binding: submission.clone(),
            transcript_head: "2".repeat(64),
            files: std::array::from_fn(|i| realm_v6::coding_submission::CandidateFile {
                path: PATHS[i].into(),
                text: String::from_utf8(files[i].clone()).unwrap(),
                mode: 0o600,
            }),
        };
        for (id, raw) in [
            ("v7-coding-contract", serde_json::to_vec(&contract).unwrap()),
            ("v7-coding-submission", serde_json::to_vec(&packet).unwrap()),
        ] {
            let blob = bundle.add_blob(raw, "application/json");
            bundle.run.evidence.push(EvidenceRef {
                id: id.into(),
                evidence_type: "UNIT_TEST_ONLY_content_binding".into(),
                digest: blob.digest,
                size: Some(blob.size),
                run_id: submission.run_id.clone(),
                checkpoint: None,
                supports: vec![],
                authoritative: false,
            });
        }
        bundle.run.lifecycle = Lifecycle::Frozen;
        bundle.run.seal = None;
        bundle.seal().unwrap();
        let bytes = bundle.pack().unwrap();
        let now = now_unix().unwrap();
        let policy = CodingTransferPolicy {
            schema_version: 1,
            authorization_domain: AUTHORIZATION_DOMAIN.into(),
            artifact_blake3: digest(&bytes),
            genesis_root: "3".repeat(64),
            exact_head_root: "4".repeat(64),
            semantic_root: bundle.semantic_identity().unwrap().value,
            contract,
            runtime_admission: None,
            workflow_trust: None,
            destination: DirectoryIdentity {
                device: 1,
                inode: 2,
                uid: 3,
            },
            nonce: "5".repeat(64),
            not_before_unix: now - 10,
            expires_at_unix: now + 3600,
        };
        (bytes, policy)
    }
    #[test]
    fn canonical_contract_and_native_packet_content_bind_without_granting_authority() {
        let (bytes, p) = prospective();
        let report = inspect_content(&bytes, &p, now_unix().unwrap()).unwrap();
        assert_eq!(report.native_authority, "NOT_VERIFIED");
        assert!(report.authority.starts_with("NONE"));
        assert_eq!(report.operations, p.contract.files);
        assert_eq!(
            p.contract.identity().unwrap(),
            crate::hash(CONTRACT_DOMAIN, &serde_json::to_vec(&p.contract).unwrap()).value
        );
        assert!(ordered_create::candidate::verify(&bytes).is_err());
    }
    #[test]
    fn admission_policy_versions_cannot_upgrade_missing_legacy_authority() {
        let (_, legacy) = prospective();
        let encoded = serde_json::to_vec(&legacy).unwrap();
        let decoded: CodingTransferPolicy = strict_json(&encoded).unwrap();
        assert_eq!(decoded, legacy);
        assert!(
            !serde_json::from_slice::<serde_json::Value>(&encoded)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("runtime_admission")
        );
        let mut missing = legacy.clone();
        missing.schema_version = 2;
        assert!(missing.validate_structure().is_err());
        let mut unexpected = serde_json::to_value(&legacy).unwrap();
        unexpected["runtime_admission"] = serde_json::json!({
            "schema":"realm.signed-runtime-admission/v1",
            "reviewer_key_id":"a".repeat(64), "policy_json":"{}",
            "signature_hex":"0".repeat(768)
        });
        let unexpected: CodingTransferPolicy =
            strict_json(&serde_json::to_vec(&unexpected).unwrap()).unwrap();
        assert!(unexpected.validate_structure().is_err());
    }
    #[test]
    fn every_external_identity_projection_and_window_substitution_refuses() {
        let (bytes, p) = prospective();
        let now = now_unix().unwrap();
        for kind in 0..15 {
            let mut bad = p.clone();
            match kind {
                0 => bad.contract.submission.run_id = "6".repeat(64),
                1 => bad.contract.submission.execution_id = "6".repeat(64),
                2 => bad.contract.submission.challenge_root = "6".repeat(64),
                3 => bad.contract.submission.task_sha256 = "6".repeat(64),
                4 => bad.contract.submission.worker_sha256 = "6".repeat(64),
                5 => bad.contract.source_commit = "6".repeat(40),
                6 => bad.contract.semantic_commitment = "6".repeat(64),
                7 => bad.semantic_root = "6".repeat(64),
                8 => bad.contract.files[0].content_blake3 = "6".repeat(64),
                9 => bad.contract.files[0].path = "../escape".into(),
                10 => bad.contract.files[0].mode = 0o777,
                11 => bad.expires_at_unix = now,
                12 => bad.not_before_unix = now + 1,
                13 => bad.authorization_domain = "C0".into(),
                _ => bad.contract.files.swap(0, 1),
            }
            assert!(inspect_content(&bytes, &bad, now).is_err(), "case {kind}");
        }
    }
    #[test]
    fn missing_publication_refuses_before_any_destination_access() {
        use crate::lifecycle::{AuthorityHead, GenesisAnchor, LifecycleSnapshot};
        let (bytes, p) = prospective();
        let genesis = GenesisAnchor::new("UNIT_TEST_ONLY", "0".repeat(64), "no publication");
        let snapshot = LifecycleSnapshot {
            head: AuthorityHead::from_genesis(&genesis).unwrap(),
            transitions: vec![],
            artifacts: BTreeMap::new(),
            receipts: BTreeMap::new(),
            journal: vec![],
            live_world_root: "0".repeat(64),
            retained_world_roots: BTreeMap::new(),
        };
        let proof = TransferProof {
            schema_version: 1,
            genesis,
            snapshot,
        };
        let report = super::super::coding_lifecycle::receive(
            &bytes,
            &proof,
            &p,
            Path::new("/destination-must-not-be-accessed"),
            Path::new("/state-must-not-be-accessed"),
            Some("forged approval"),
        );
        assert_eq!(report.status, "REFUSED");
        assert_eq!(report.authority, "NONE");
        assert!(!report.application_dispatched);
        assert_eq!(report.stages[0].status, "PASS");
        assert_eq!(report.stages[1].status, "REFUSE");
        assert!(report.stages[2..].iter().all(|s| s.status == "NOT_RUN"));
        assert!(report.plan.is_none());
        assert!(report.receipt.is_none());
        let mut oversized = proof.clone();
        oversized.snapshot.artifacts = (0..65).map(|i| (format!("extra-{i}"), vec![])).collect();
        let rejected = super::super::coding_lifecycle::receive(
            &bytes,
            &oversized,
            &p,
            Path::new("/destination-must-not-be-accessed"),
            Path::new("/state-must-not-be-accessed"),
            None,
        );
        assert!(rejected.stages[1].detail.contains("resource budget"));
        assert!(!rejected.application_dispatched);
    }
    #[test]
    fn expired_policy_can_be_observed_but_cannot_authorize_application() {
        let (bytes, mut policy) = prospective();
        let now = now_unix().unwrap();
        policy.not_before_unix = now - 10;
        policy.expires_at_unix = now;
        assert!(inspect_content(&bytes, &policy, now).is_err());
        assert!(inspect_for_observation(&bytes, &policy).is_ok());
        let mut altered = bytes.clone();
        altered[0] ^= 1;
        assert!(inspect_for_observation(&altered, &policy).is_err());
    }
    #[test]
    fn duplicate_nested_trust_map_keys_refuse_before_typed_deserialization() {
        for raw in [br#"{"x":{"key":1,"key":2}}"#.as_slice(), br#"{"x":NaN}"#] {
            assert!(strict_json::<serde_json::Value>(raw).is_err());
        }
        let (_, p) = prospective();
        let mut v = serde_json::to_value(&p).unwrap();
        v["authority"] = true.into();
        assert!(strict_json::<CodingTransferPolicy>(&serde_json::to_vec(&v).unwrap()).is_err());
    }
}
