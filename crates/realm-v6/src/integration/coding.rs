//! Native coding pre-admission. Reports are not proofs. Only process-local
//! observation/launch/mediation/closure values may enter the join. In particular,
//! the existing V2 file-I/O semantic proof cannot certify a coding task outcome.
use super::*;
use crate::execute::CheckedC1Evidence;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, thiserror::Error)]
#[serde(tag = "code", content = "detail", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CodingAdmissionCode {
    #[error("native coding evidence content/profile/task/packet is inconsistent")]
    InvalidCodingEvidence,
    #[error("host-observed same-run capsule evidence is missing")]
    MissingHostObservation,
    #[error("owned production measured launch is missing")]
    MissingProductionLaunch,
    #[error("trusted native mediation completion is missing")]
    MissingMediationCompletion,
    #[error("native closure/freeze/retirement proof is missing")]
    MissingNativeClosure,
    #[error("trusted semantic evidence is missing")]
    MissingSemanticEvidence,
    #[error("owned same-run build-pinned coding referee is missing")]
    MissingOwnedCodingReferee,
    #[error("native same-run run/task/policy/custody/world/closure bindings differ")]
    NativeBindingMismatch,
    #[error("existing native join refused: {0:?}")]
    NativeJoin(SameRunJoinRefusal),
    #[error("native semantic receipt differs from the coding contract")]
    SemanticCommitmentMismatch,
    #[error(
        "bounded filesystem I/O semantics do not verify the approved coding task or completeness of planner observations"
    )]
    UnsupportedCodingSemanticScope,
}

/// Native task semantics are a separate capability from the V2 I/O model.
/// Only the owner-consuming native finalizer can establish this value.
/// ```compile_fail
/// let _: realm_v6::integration::coding::JoinedCodingEvidence = serde_json::from_str("{}").unwrap();
/// ```
pub struct JoinedCodingEvidence {
    pub(crate) binding: SemanticFrontierBinding,
    receipt: crate::coding_semantics::CodingSemanticEvidence,
}
impl JoinedCodingEvidence {
    #[cfg(target_os = "linux")]
    pub(crate) fn receipt(&self) -> &crate::coding_semantics::CodingSemanticEvidence {
        &self.receipt
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn from_native(
        custody: &crate::coding_custody::ClosedCodingCustody,
        referee: &crate::coding_referee::OwnedCodingTaskCheck,
        provenance: &crate::coding_provenance::OwnedCodingProvenance,
        launch: &ProductionContainedLaunch,
        kernel: &crate::run_closure::KernelClosureObservation,
        workflow: Option<&crate::coding_runtime::attempt_history::OwnedNativeWorkflow>,
    ) -> Result<Self, CodingAdmissionCode> {
        custody
            .validate_retired(launch)
            .map_err(|_| CodingAdmissionCode::NativeBindingMismatch)?;
        let (scope, packet, native, frozen, starting) = custody.publication_inputs();
        if !provenance.has_verified_vmm_fd_boundary()
            || !referee.native_binding(scope, packet, &native.root, frozen.completion.root())
            || !provenance.matches_native(
                launch,
                scope,
                frozen.completion.frontier_root(),
                &frozen.barrier,
            )
        {
            return Err(CodingAdmissionCode::NativeBindingMismatch);
        }
        let mut receipt = receipt_from_owners(
            custody,
            referee,
            provenance,
            launch,
            crate::coding_semantics::SCOPE,
        )
        .map_err(|_| CodingAdmissionCode::InvalidCodingEvidence)?;
        if let Some(owner) = workflow {
            owner
                .attach(&mut receipt)
                .map_err(|_| CodingAdmissionCode::NativeBindingMismatch)?;
        } else if scope.native_subtask.is_some() {
            return Err(CodingAdmissionCode::NativeBindingMismatch);
        }
        let semantic_root = receipt
            .root()
            .map_err(|_| CodingAdmissionCode::InvalidCodingEvidence)?;
        let policy = scope
            .policy_identity()
            .map_err(|_| CodingAdmissionCode::InvalidCodingEvidence)?;
        Ok(Self {
            binding: SemanticFrontierBinding {
                run_id: scope.submission.run_id.clone(),
                manifest_root: frozen.completion.session_binding_root().into(),
                semantic_launch_root: policy.task_blake3().into(),
                semantic_argv: vec![crate::coding_submission::CODING_PROFILE.into()],
                semantic_policy_root: policy.blake3().into(),
                starting_generation: starting.into(),
                freeze_epoch: frozen.barrier.clone(),
                frontier_head: frozen.completion.frontier_root().into(),
                semantic_receipt_root: semantic_root,
                poweroff_observation_root: Some(kernel.raw_evidence_root().into()),
            },
            receipt,
        })
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn kernel_root(&self) -> Option<&str> {
        self.binding.poweroff_observation_root.as_deref()
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn terminal_binding(&self) -> (&str, &str, &str, &str) {
        (
            &self.binding.run_id,
            &self.binding.frontier_head,
            &self.binding.semantic_receipt_root,
            &self.binding.freeze_epoch,
        )
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn receipt_from_owners(
    custody: &crate::coding_custody::ClosedCodingCustody,
    referee: &(impl crate::coding_referee::NativeRefereeEvidence + ?Sized),
    provenance: &crate::coding_provenance::OwnedCodingProvenance,
    launch: &ProductionContainedLaunch,
    semantic_scope: &str,
) -> Result<crate::coding_semantics::CodingSemanticEvidence, &'static str> {
    custody
        .validate_retired(launch)
        .map_err(|_| "native custody changed")?;
    let (scope, packet, native, frozen, _) = custody.publication_inputs();
    if !referee.native_binding(scope, packet, &native.root, frozen.completion.root())
        || !provenance.matches_native(
            launch,
            scope,
            frozen.completion.frontier_root(),
            &frozen.barrier,
        )
    {
        return Err("native original owner join differs");
    }
    let receipt = crate::coding_semantics::CodingSemanticEvidence {
        scope: semantic_scope.into(),
        prelaunch: scope.clone(),
        packet_blake3: blake3::hash(packet).to_hex().to_string(),
        consumed_request_blake3: referee.request_root().into(),
        referee_root: referee.root().into(),
        referee_identity_record: Some(referee.identity_record().clone()),
        provenance_root: provenance.root().into(),
        runtime_provenance_record: Some(provenance.identity_record().clone()),
        runtime_qualification: provenance.qualification_evidence().cloned(),
        custody_root: native.root.clone(),
        broker_completion_root: frozen.completion.root().into(),
        frontier_root: frozen.completion.frontier_root().into(),
        measurement_root: launch.canonical_hash_blake3().into(),
        barrier_root: frozen.barrier.clone(),
        excluded_claims: crate::coding_semantics::EXCLUDED
            .iter()
            .map(|s| s.to_string())
            .collect(),
        workflow: None,
    };
    receipt.validate_shape()?;
    Ok(receipt)
}

/// Source-registered semantic scope of the native verifier currently available
/// in this crate. An authenticated head or signed record cannot register a new
/// task semantics implementation. Keep native issuance and detached admission
/// consistent until a real coding verifier/observation boundary is qualified.
pub fn require_registered_coding_semantics() -> Result<(), CodingAdmissionCode> {
    // The typed finite model is implemented, but its runtime provenance producer
    // is not qualified. Keep detached receiving fail-closed until that exists.
    Err(CodingAdmissionCode::UnsupportedCodingSemanticScope)
}

#[derive(Clone, Debug, Serialize)]
pub struct CodingAdmissionCheck {
    pub boundary: &'static str,
    pub status: &'static str,
    pub code: Option<CodingAdmissionCode>,
}
#[derive(Clone, Debug, Serialize)]
pub struct CodingAdmissionReport {
    pub schema: &'static str,
    pub authority: &'static str,
    pub admission: &'static str,
    pub checks: Vec<CodingAdmissionCheck>,
}
/// These are actual native capability references, never serialized reports.
/// A JSON PASS row, journal root or valid development signature cannot populate
/// any field here. Missing capabilities are reported, not reconstructed.
#[derive(Default)]
pub struct CodingNativeEvidence<'a> {
    pub finite_referee: Option<&'a crate::coding_referee::OwnedCodingTaskCheck>,
    pub observation: Option<&'a CapsuleObservation>,
    pub production: Option<&'a ProductionContainedLaunch>,
    pub mediation: Option<&'a CheckedMediationClaim>,
    pub closure: Option<&'a RunClosureProofV3>,
    pub semantics: Option<&'a JoinedCodingEvidence>,
}

/// Executable failure map over the actual admission inputs. "PRESENT" below
/// denotes only an opaque value's presence; PASS is reserved for checked joins.
pub fn inspect_coding_admission(
    evidence: &CheckedC1Evidence,
    native: &CodingNativeEvidence<'_>,
) -> CodingAdmissionReport {
    admission_report(coding_content(evidence), native)
}
/// Even a malformed/development input still reports which real native values
/// are absent. No replacement CheckedC1Evidence or capability is fabricated.
pub fn invalid_coding_admission() -> CodingAdmissionReport {
    admission_report(false, &CodingNativeEvidence::default())
}
fn admission_report(
    content_valid: bool,
    native: &CodingNativeEvidence<'_>,
) -> CodingAdmissionReport {
    let mut checks = vec![CodingAdmissionCheck {
        boundary: "coding-content-and-approved-scope",
        status: if content_valid {
            "PASS_CONTENT_ONLY"
        } else {
            "REFUSE"
        },
        code: (!content_valid).then_some(CodingAdmissionCode::InvalidCodingEvidence),
    }];
    for (boundary, present, code) in [
        (
            "owned-coding-task-referee",
            native.finite_referee.is_some(),
            CodingAdmissionCode::MissingOwnedCodingReferee,
        ),
        (
            "host-observation",
            native.observation.is_some(),
            CodingAdmissionCode::MissingHostObservation,
        ),
        (
            "production-measured-launch",
            native.production.is_some(),
            CodingAdmissionCode::MissingProductionLaunch,
        ),
        (
            "broker-mediation-completion",
            native.mediation.is_some(),
            CodingAdmissionCode::MissingMediationCompletion,
        ),
        (
            "native-terminal-closure",
            native.closure.is_some(),
            CodingAdmissionCode::MissingNativeClosure,
        ),
        (
            "independent-semantic-evidence",
            native.semantics.is_some(),
            CodingAdmissionCode::MissingSemanticEvidence,
        ),
    ] {
        checks.push(CodingAdmissionCheck {
            boundary,
            status: if present {
                "PRESENT_NOT_JOINED"
            } else {
                "MISSING"
            },
            code: (!present).then_some(code),
        });
    }
    if native.semantics.is_some() {
        checks.push(CodingAdmissionCheck {
            boundary: "finite-coding-task-and-native-provenance",
            status: "PRESENT_NOT_JOINED",
            code: None,
        });
    }
    CodingAdmissionReport {
        schema: "realm.coding-same-run-admission.v1",
        authority: "NONE",
        admission: "REFUSE",
        checks,
    }
}
fn coding_content(e: &CheckedC1Evidence) -> bool {
    e.schema_version == 9 && e.coding.is_some() && crate::execute::validate_checked_c1_evidence(e)
}

/// Native producer bridge through the existing identity/closure checker and
/// canonical issuer. A finite task receipt is separate from V2 file I/O and
/// requires an owned native runtime provenance capability. Current external
/// planner execution cannot construct that capability.
pub fn checked_coding_same_run(
    evidence: &CheckedC1Evidence,
    native: CodingNativeEvidence<'_>,
) -> Result<CheckedSameRunEvidence, CodingAdmissionCode> {
    if !coding_content(evidence) {
        return Err(CodingAdmissionCode::InvalidCodingEvidence);
    }
    let observation = native
        .observation
        .ok_or(CodingAdmissionCode::MissingHostObservation)?;
    let production = native
        .production
        .ok_or(CodingAdmissionCode::MissingProductionLaunch)?;
    let mediation = native
        .mediation
        .ok_or(CodingAdmissionCode::MissingMediationCompletion)?;
    let closure = native
        .closure
        .ok_or(CodingAdmissionCode::MissingNativeClosure)?;
    let semantic = native
        .semantics
        .ok_or(CodingAdmissionCode::MissingSemanticEvidence)?;
    let referee = native
        .finite_referee
        .ok_or(CodingAdmissionCode::MissingOwnedCodingReferee)?;
    if !referee.matches(evidence)
        || !evidence.coding.as_ref().is_some_and(|data| {
            data.semantic_evidence.as_ref() == Some(&semantic.receipt)
                && semantic.receipt.matches_data(data)
        })
    {
        return Err(CodingAdmissionCode::SemanticCommitmentMismatch);
    }
    // Reuse every existing native identity/manifest/policy/frontier/freeze and
    // VMM incarnation check before considering an extension of semantic scope.
    let mut joined = join_native_binding(
        &semantic.binding,
        mediation,
        observation,
        production,
        closure,
        Some(production.production_launch_root()),
        SameRunSemanticScope::CodingFiniteEffects,
    )
    .map_err(CodingAdmissionCode::NativeJoin)?;
    joined
        .check_execution_bindings(evidence)
        .map_err(CodingAdmissionCode::NativeJoin)?;
    if semantic.binding.semantic_receipt_root
        != evidence
            .coding
            .as_ref()
            .expect("checked above")
            .contract
            .semantic_commitment
    {
        return Err(CodingAdmissionCode::SemanticCommitmentMismatch);
    }
    // The private scope marker comes only from the owned coding join; an IO
    // proof with matching digest slots cannot pass this boundary.
    joined.require_coding_semantic_scope()?;
    let contract = &evidence.coding.as_ref().expect("checked above").contract;
    joined.coding_binding = Some((
        contract
            .identity()
            .map_err(|_| CodingAdmissionCode::InvalidCodingEvidence)?,
        contract.semantic_commitment.clone(),
    ));
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn self_consistent_data_and_hash_assignment_cannot_upgrade_io_proof() {
        let (result, evidence) = crate::execute::test_coding_evidence_content();
        let mut io_proof = crate::integration::test_checked_same_run_evidence(&evidence);
        // Demonstrate why the previous two-hash slot is insufficient even if a
        // future adapter were to populate it from self-consistent JSON.
        let contract = &evidence.coding.as_ref().unwrap().contract;
        io_proof.coding_binding = Some((
            contract.identity().unwrap(),
            contract.semantic_commitment.clone(),
        ));
        assert!(io_proof.matches_c1_evidence(&evidence));
        assert!(matches!(
            crate::execute::CheckedExecutionForPublication::issue_for_publication(
                result, evidence, io_proof
            ),
            Err(crate::execute::PublicationCapabilityRefusal::CodingSemanticScopeUnavailable)
        ));
    }
    #[test]
    fn native_adapter_and_detached_verifier_share_refusal_of_missing_authority() {
        let (result, evidence) = crate::execute::test_coding_evidence_content();
        let error = match crate::execute::CheckedExecutionForPublication::issue_coding_from_native(
            result,
            evidence,
            CodingNativeEvidence::default(),
        ) {
            Err(error) => error,
            Ok(_) => panic!("ordinary evidence must never supply host observation"),
        };
        let encoded = serde_json::to_value(error).unwrap();
        assert_eq!(encoded["boundary"], "NATIVE");
        assert_eq!(encoded["reason"]["code"], "MISSING_HOST_OBSERVATION");
        assert_eq!(
            require_registered_coding_semantics(),
            Err(CodingAdmissionCode::UnsupportedCodingSemanticScope)
        );
    }
    #[test]
    fn native_bindings_keep_precise_cross_run_challenge_world_and_custody_failures() {
        let (_, evidence) = crate::execute::test_coding_evidence_content();
        let token = crate::integration::test_checked_same_run_evidence(&evidence);
        assert!(token.check_execution_bindings(&evidence).is_ok());
        for case in 0..8 {
            let mut bad = evidence.clone();
            let foreign = "0".repeat(64);
            let expected = match case {
                0 => {
                    bad.run_id = foreign;
                    SameRunJoinRefusal::WrongRun
                }
                1 => {
                    bad.execution_id = foreign;
                    SameRunJoinRefusal::WrongExecution
                }
                2 => {
                    bad.challenge_binding = foreign;
                    SameRunJoinRefusal::WrongChallenge
                }
                3 => {
                    bad.custody_process_identity = Some(foreign);
                    SameRunJoinRefusal::WrongCustodyIdentity
                }
                4 => {
                    bad.same_run_join_root = foreign;
                    SameRunJoinRefusal::WrongEvidenceRoot
                }
                5 => {
                    bad.accepted_start_root = foreign;
                    SameRunJoinRefusal::WrongParent
                }
                6 => {
                    bad.accepted_final_root = foreign;
                    SameRunJoinRefusal::WrongWorld
                }
                _ => {
                    bad.accepted_delta_root = foreign;
                    SameRunJoinRefusal::WrongDelta
                }
            };
            assert_eq!(token.check_execution_bindings(&bad), Err(expected));
        }
    }
    #[test]
    fn serialized_reports_do_not_supply_native_capabilities() {
        let (_, evidence) = crate::execute::test_coding_evidence_content();
        let report = inspect_coding_admission(&evidence, &CodingNativeEvidence::default());
        assert_eq!(report.authority, "NONE");
        assert_eq!(report.admission, "REFUSE");
        assert_eq!(
            report
                .checks
                .iter()
                .filter(|c| c.status == "MISSING")
                .count(),
            6
        );
        assert!(matches!(
            checked_coding_same_run(&evidence, CodingNativeEvidence::default()),
            Err(CodingAdmissionCode::MissingHostObservation)
        ));
        let failure =
            serde_json::to_value(CodingAdmissionCode::UnsupportedCodingSemanticScope).unwrap();
        assert_eq!(failure["code"], "UNSUPPORTED_CODING_SEMANTIC_SCOPE");
    }
}
