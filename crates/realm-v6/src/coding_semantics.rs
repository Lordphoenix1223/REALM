//! Portable commitment to the bounded coding predicate. This record is data,
//! never a native capability. Native issuance must consume original run owners.
use crate::coding_submission::{CodingExecutionScope, CodingPublicationData};
use serde::{Deserialize, Serialize};

pub const SCOPE: &str = "realm.coding-finite-effects/v1";
pub const API_SCOPE: &str = "realm.native-api-finite-effects/v1";
pub const REFUSAL_SCOPE: &str = "realm.native-refused-effects/v1";
/// These exclusions travel with the evidence; a finite task result must not be
/// promoted into complete planner history or causal replay authority.
pub const EXCLUDED: [&str; 5] = [
    "causal-reuse",
    "complete-planner-inputs",
    "complete-guest-syscall-history",
    "guest-process-count",
    "universal-python-correctness",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingSemanticEvidence {
    pub scope: String,
    pub prelaunch: CodingExecutionScope,
    pub packet_blake3: String,
    pub consumed_request_blake3: String,
    pub referee_root: String,
    /// Exact native-generated referee commitment preimage. Optional for legacy
    /// non-authorizing data; actual native issuance supplies and validates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referee_identity_record: Option<serde_json::Value>,
    pub provenance_root: String,
    /// Full same-run native observation preimage; still not admission authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_provenance_record: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_qualification: Option<crate::runtime_admission::QualificationEvidence>,
    pub custody_root: String,
    pub broker_completion_root: String,
    pub frontier_root: String,
    pub measurement_root: String,
    pub barrier_root: String,
    pub excluded_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<Box<crate::native_workflow::NativeWorkflowReceipt>>,
}
impl CodingSemanticEvidence {
    pub fn root(&self) -> Result<String, &'static str> {
        self.validate_shape()?;
        let bytes = serde_json::to_vec(self).map_err(|_| "semantic evidence encoding")?;
        let mut hash = blake3::Hasher::new();
        hash.update(b"REALM::CodingFiniteEffects/v1\0");
        hash.update(&bytes);
        Ok(hash.finalize().to_hex().to_string())
    }
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        self.prelaunch.validate()?;
        if let Some(identity) = &self.referee_identity_record {
            let bytes = serde_json::to_vec(identity).map_err(|_| "referee identity encoding")?;
            let expected_domain = match self.scope.as_str() {
                API_SCOPE => "realm.owned-native-api-check/v1",
                REFUSAL_SCOPE => "realm.owned-coding-task-refusal/v1",
                _ => "realm.owned-coding-task-check/v2",
            };
            const FIELDS: [&str; 16] = [
                "domain",
                "prelaunch_scope",
                "binding",
                "packet",
                "native_custody",
                "broker_completion",
                "measurement",
                "barrier",
                "process",
                "python",
                "bwrap",
                "sources",
                "request_blake3",
                "subject_packet_blake3",
                "seed",
                "result_blake3",
            ];
            let fields = identity
                .as_object()
                .ok_or("referee identity object required")?;
            if bytes.len() > 256 * 1024
                || fields.len() != FIELDS.len() + usize::from(self.scope == REFUSAL_SCOPE)
                || self.scope == REFUSAL_SCOPE && identity["child_exit_code"] != 2
                || FIELDS.iter().any(|key| !fields.contains_key(*key))
                || identity["domain"] != expected_domain
                || identity["prelaunch_scope"]
                    != serde_json::to_value(&self.prelaunch)
                        .map_err(|_| "referee scope encoding")?
                || identity["binding"]
                    != serde_json::to_value(&self.prelaunch.submission)
                        .map_err(|_| "referee binding encoding")?
                || identity["packet"] != self.packet_blake3
                || identity["subject_packet_blake3"] != self.packet_blake3
                || identity["native_custody"] != self.custody_root
                || identity["broker_completion"] != self.broker_completion_root
                || identity["measurement"] != self.measurement_root
                || identity["barrier"] != self.barrier_root
                || identity["request_blake3"] != self.consumed_request_blake3
                || blake3::hash(&bytes).to_hex().as_str() != self.referee_root
            {
                return Err("referee identity preimage or same-run binding differs");
            }
        }
        if let Some(identity) = &self.runtime_provenance_record {
            let bytes = serde_json::to_vec(identity).map_err(|_| "runtime identity encoding")?;
            let resources = identity["resources_raw_json"]
                .as_str()
                .ok_or("original resource bytes absent")?;
            if bytes.len() > 512 * 1024
                || blake3::hash(resources.as_bytes()).to_hex().as_str()
                    != identity["resources_root"]
                || identity["domain"] != "realm.native-coding-provenance/v2"
                || identity["measurement"] != self.measurement_root
                || identity["scope"]
                    != serde_json::to_value(&self.prelaunch)
                        .map_err(|_| "runtime scope encoding")?
                || identity["frontier"] != self.frontier_root
                || identity["barrier"] != self.barrier_root
                || identity["referee_root"] != self.referee_root
                || identity.get("referee_identity_record") != self.referee_identity_record.as_ref()
                || self.runtime_qualification.is_none()
                    && blake3::hash(&bytes).to_hex().as_str() != self.provenance_root
            {
                return Err("runtime observation preimage or same-run binding differs");
            }
        }
        if let Some(q) = &self.runtime_qualification {
            q.matches_data(self, &q.admission)
                .map_err(|_| "qualified runtime evidence differs")?;
        }
        if !matches!(self.scope.as_str(), SCOPE | API_SCOPE | REFUSAL_SCOPE)
            || self.excluded_claims != EXCLUDED
            || self.scope != SCOPE && self.prelaunch.native_subtask.is_none()
            || self.scope == SCOPE
                && self
                    .prelaunch
                    .native_subtask
                    .as_ref()
                    .is_some_and(|s| s.role == crate::native_workflow::NativeTaskRole::Api)
            || self.scope == API_SCOPE
                && !self
                    .prelaunch
                    .native_subtask
                    .as_ref()
                    .is_some_and(|s| s.role == crate::native_workflow::NativeTaskRole::Api)
        {
            return Err("unsupported coding semantic scope or claims");
        }
        for value in [
            &self.packet_blake3,
            &self.consumed_request_blake3,
            &self.referee_root,
            &self.provenance_root,
            &self.custody_root,
            &self.broker_completion_root,
            &self.frontier_root,
            &self.measurement_root,
            &self.barrier_root,
        ] {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("invalid coding semantic binding");
            }
        }
        if let Some(history) = &self.workflow {
            history.validate(self)?;
        }
        Ok(())
    }
    pub fn matches_data(&self, data: &CodingPublicationData) -> bool {
        self.scope == SCOPE
            && self
                .root()
                .is_ok_and(|root| root == data.contract.semantic_commitment)
            && self.prelaunch.submission == data.contract.submission
            && self.prelaunch.source_commit == data.contract.source_commit
            && self.packet_blake3 == blake3::hash(&data.submission).to_hex().as_str()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn fixture() -> CodingPublicationData {
        // Structural fixture only. It does not exercise native execution or
        // construct any authority-bearing owner.
        let (_, mut checked) = crate::execute::test_coding_evidence_content();
        let mut data = checked.coding.take().unwrap();
        let digest = "a".repeat(64);
        let receipt = CodingSemanticEvidence {
            scope: SCOPE.into(),
            prelaunch: CodingExecutionScope {
                submission: data.contract.submission.clone(),
                source_commit: data.contract.source_commit.clone(),
                checker_sha256: digest.clone(),
                checker_scope_sha256: digest.clone(),
                runtime_admission_id: None,
                native_subtask: None,
                task_inputs_blake3: None,
            },
            packet_blake3: blake3::hash(&data.submission).to_hex().to_string(),
            consumed_request_blake3: digest.clone(),
            referee_root: digest.clone(),
            referee_identity_record: None,
            provenance_root: digest.clone(),
            runtime_provenance_record: None,
            runtime_qualification: None,
            custody_root: digest.clone(),
            broker_completion_root: digest.clone(),
            frontier_root: digest.clone(),
            measurement_root: digest.clone(),
            barrier_root: digest,
            excluded_claims: EXCLUDED.map(str::to_owned).to_vec(),
            workflow: None,
        };
        data.contract.semantic_commitment = receipt.root().unwrap();
        data.semantic_evidence = Some(receipt);
        data
    }
    #[test]
    fn finite_scope_binds_exact_subject_task_request_source_and_native_roots() {
        let data = fixture();
        assert!(data.validate().is_ok());
        let original = data.semantic_evidence.as_ref().unwrap();
        for case in 0..13 {
            let mut changed = original.clone();
            let foreign = blake3::hash(format!("foreign case {case}").as_bytes())
                .to_hex()
                .to_string();
            match case {
                0 => changed.packet_blake3 = foreign,
                1 => changed.prelaunch.submission.run_id = foreign,
                2 => changed.prelaunch.submission.execution_id = foreign,
                3 => changed.prelaunch.submission.challenge_root = foreign,
                4 => changed.prelaunch.source_commit = "b".repeat(40),
                5 => changed.consumed_request_blake3 = foreign,
                6 => changed.referee_root = foreign,
                7 => changed.provenance_root = foreign,
                8 => changed.custody_root = foreign,
                9 => changed.broker_completion_root = foreign,
                10 => changed.frontier_root = foreign,
                11 => changed.measurement_root = foreign,
                _ => changed.barrier_root = foreign,
            }
            assert!(!changed.matches_data(&data), "case {case}");
        }
    }
    #[test]
    fn claim_expansion_and_unknown_fields_refuse() {
        let data = fixture();
        let mut receipt = data.semantic_evidence.unwrap();
        receipt
            .excluded_claims
            .retain(|c| c != "complete-planner-inputs");
        assert!(receipt.root().is_err());
        receipt.excluded_claims = EXCLUDED.map(str::to_owned).to_vec();
        receipt.scope = "guest-resident-complete-history".into();
        assert!(receipt.root().is_err());
        let mut json = serde_json::to_value(receipt).unwrap();
        json["qualified"] = true.into();
        assert!(serde_json::from_value::<CodingSemanticEvidence>(json).is_err());
    }
    #[test]
    fn retained_referee_identity_is_bound_but_remains_non_authorizing_data() {
        let mut data = fixture();
        let receipt = data.semantic_evidence.as_mut().unwrap();
        // Structural data only: no native owner or authority is constructed.
        let identity = serde_json::json!({
            "domain":"realm.owned-coding-task-check/v2", "prelaunch_scope":receipt.prelaunch,
            "binding":receipt.prelaunch.submission, "packet":receipt.packet_blake3,
            "native_custody":receipt.custody_root, "broker_completion":receipt.broker_completion_root,
            "measurement":receipt.measurement_root, "barrier":receipt.barrier_root,
            "request_blake3":receipt.consumed_request_blake3, "subject_packet_blake3":receipt.packet_blake3,
            "process":{}, "python":{}, "bwrap":{}, "sources":{}, "seed":"1", "result_blake3":"a".repeat(64)
        });
        receipt.referee_root = blake3::hash(&serde_json::to_vec(&identity).unwrap())
            .to_hex()
            .to_string();
        receipt.referee_identity_record = Some(identity);
        let runtime = serde_json::json!({
            "domain":"realm.native-coding-provenance/v2", "measurement":receipt.measurement_root,
            "scope":receipt.prelaunch, "frontier":receipt.frontier_root, "barrier":receipt.barrier_root,
            "referee_root":receipt.referee_root, "referee_identity_record":receipt.referee_identity_record,
            "resources_raw_json":"[]", "resources_root":blake3::hash(b"[]").to_hex().to_string()
        });
        receipt.provenance_root = blake3::hash(&serde_json::to_vec(&runtime).unwrap())
            .to_hex()
            .to_string();
        receipt.runtime_provenance_record = Some(runtime);
        let mut foreign_runtime = receipt.clone();
        foreign_runtime.runtime_provenance_record.as_mut().unwrap()["measurement"] =
            "b".repeat(64).into();
        foreign_runtime.provenance_root = blake3::hash(
            &serde_json::to_vec(foreign_runtime.runtime_provenance_record.as_ref().unwrap())
                .unwrap(),
        )
        .to_hex()
        .to_string();
        assert!(foreign_runtime.root().is_err());
        data.contract.semantic_commitment = receipt.root().unwrap();
        assert!(data.validate().is_ok());
        // Even re-pinning a foreign measurement cannot repair the receipt join.
        let receipt = data.semantic_evidence.as_mut().unwrap();
        receipt.referee_identity_record.as_mut().unwrap()["measurement"] = "b".repeat(64).into();
        receipt.referee_root = blake3::hash(
            &serde_json::to_vec(receipt.referee_identity_record.as_ref().unwrap()).unwrap(),
        )
        .to_hex()
        .to_string();
        assert!(receipt.root().is_err());
        assert!(crate::integration::coding::require_registered_coding_semantics().is_err());
    }
    #[test]
    fn legacy_omitted_referee_material_preserves_serialized_receipt_root() {
        let data = fixture();
        let receipt = data.semantic_evidence.unwrap();
        let bytes = serde_json::to_vec(&receipt).unwrap();
        assert!(
            !serde_json::from_slice::<serde_json::Value>(&bytes)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("referee_identity_record")
        );
        let old: CodingSemanticEvidence = serde_json::from_slice(&bytes).unwrap();
        assert!(old.referee_identity_record.is_none());
        assert!(old.runtime_provenance_record.is_none());
        assert_eq!(old.root().unwrap(), receipt.root().unwrap());
        assert_eq!(serde_json::to_vec(&old).unwrap(), bytes);
        assert!(crate::integration::coding::require_registered_coding_semantics().is_err());
    }
    #[test]
    fn self_consistent_receipt_remains_data_and_cannot_register_runtime_authority() {
        let mut data = fixture();
        data.semantic_evidence.as_mut().unwrap().provenance_root = "b".repeat(64);
        data.contract.semantic_commitment =
            data.semantic_evidence.as_ref().unwrap().root().unwrap();
        assert!(data.validate().is_ok());
        assert!(crate::integration::coding::require_registered_coding_semantics().is_err());
        // A digest over an invented provenance root never supplies the owned
        // native argument required by RetiredCodingVmm::finalize_coding.
    }
}
