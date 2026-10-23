//! Adapters for the checked V6 C1 execution and managed-generation receipt.
//!
//! These records remain evidence. Only the opaque
//! `CheckedExecutionForPublication` is accepted by the adapter, and no
//! artifact type can recreate that in-process capability.

use crate::{
    ArtifactBundle, ArtifactError, BlobRef, Challenge, Claim, ClaimKind, Commitment, Digest,
    EnvironmentIdentity, EvidenceRef, Lifecycle, ObservedEvent, PublicationMetadata,
    PublicationStatus, RealmRun, UnknownEffect, VerificationDecision, VerificationRef, hash,
};
use realm_v6::{
    Admission,
    execute::{CheckedC1Evidence, CheckedExecutionForPublication, ExecuteResult},
    generation::{GenerationIdentity, GenerationReceipt},
    mediation::{MediationManifest, check_manifest_claim_shape},
    publication_journal::{PublicationRecord, PublicationState},
};
use serde::{Deserialize, Serialize};

pub const GENERATION_EXCHANGE_MECHANISM: &str = "linux-renameat2-rename-exchange-v1";
const VERIFIER_EVIDENCE_ID: &str = "v6-c1-verifier-result";

/// Outer-envelope record that binds the actual generation receipt and journal
/// terminal record back to one immutable semantic run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationPublicationEvidence {
    pub semantic_run_root: Digest,
    pub generation_identity: GenerationIdentity,
    pub commit_sequence: u64,
    pub commit_mechanism: String,
    pub journal_state: PublicationState,
    pub live_root: String,
    pub previous_generation_root: String,
    pub receipt_identity: Digest,
    pub receipt_blob: BlobRef,
    pub journal_record_blob: BlobRef,
}

/// Immutable decision evidence included in `RealmRun`; the outer verifier
/// reference repeats this result and is checked against it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V6VerifierDecisionEvidence {
    pub schema_version: u16,
    pub decision: String,
    pub verifier: String,
    pub run_id: String,
    pub execution_id: String,
    pub checked_claim_root: String,
    pub accepted_decision_identity: String,
    pub c1_manifest_root: String,
    pub evidence_root: String,
}

/// Create the existing `.realm` artifact from the opaque pre-publication capability.
/// A public/deserialized `ExecuteResult` cannot be passed here.
///
/// ```compile_fail
/// use realm_artifact::v6::from_publication_capability;
/// use realm_v6::execute::ExecuteResult;
/// let report: ExecuteResult = todo!();
/// let _ = from_publication_capability(&report);
/// ```
/// A parsed `.realm` file also cannot be used as the generation authority.
///
/// ```compile_fail
/// use realm_artifact::ArtifactBundle;
/// use realm_v6::generation::prepare_candidate;
/// let artifact = ArtifactBundle::open("run.realm").unwrap();
/// let _ = prepare_candidate(&artifact, "workspace");
/// ```
pub fn from_publication_capability(
    execution: &CheckedExecutionForPublication,
) -> Result<ArtifactBundle, ArtifactError> {
    let _profile = realm_v6::profile::Span::new("realm_artifact_construction");
    if !execution.validate_for_evidence() {
        return Err(ArtifactError::Invalid(
            "checked C1 execution evidence is inconsistent".into(),
        ));
    }
    bundle_from_checked_data(execution.result(), &execution.checked_c1_evidence())
}

fn bundle_from_checked_data(
    result: &ExecuteResult,
    evidence: &CheckedC1Evidence,
) -> Result<ArtifactBundle, ArtifactError> {
    validate_execution_evidence(result, evidence)?;
    let manifest = checked_manifest(evidence)?;
    let intent_bytes = serde_json::to_vec(&evidence.command)?;
    let effect_contract_bytes = realm_v6::execute::checked_effect_contract_bytes(evidence)?;
    let checked_bytes = serde_json::to_vec(evidence)?;
    let decision = verifier_decision(evidence);
    let decision_bytes = serde_json::to_vec(&decision)?;
    let decision_digest = hash("realm.verifier-result", &decision_bytes);

    let run = RealmRun {
        schema_version: crate::SCHEMA_VERSION,
        lifecycle: Lifecycle::Frozen,
        run: crate::RunIdentity {
            run_id: evidence.run_id.clone(),
            execution_id: evidence.execution_id.clone(),
        },
        challenge: Challenge {
            nonce: Some(Digest {
                algorithm: "blake3".into(),
                domain: "realm.challenge-binding".into(),
                value: evidence.challenge_binding.clone(),
            }),
            issued_by: "realm-v6-measured-supervisor".into(),
            expires_at: None,
        },
        intent: Commitment {
            identity: "v6-command-intent".into(),
            digest: hash("realm.intent", &intent_bytes),
        },
        starting_state: world_commitment("v6-starting-world", &evidence.accepted_start_root),
        environment: EnvironmentIdentity {
            runtime: "realm-v6".into(),
            runtime_digest: Digest {
                algorithm: "blake3".into(),
                domain: "realm.runtime".into(),
                value: manifest.runtime_identity.clone(),
            },
            backend: "firecracker-measured".into(),
            architecture: "x86_64".into(),
        },
        effect_contract: Commitment {
            identity: "v6-allowed-effects-paths-timeout".into(),
            digest: hash("realm.policy", &effect_contract_bytes),
        },
        inputs: Vec::new(),
        outputs: Vec::new(),
        checkpoints: Vec::new(),
        observations: Vec::new(),
        proposed_effects: Vec::new(),
        unknown_effects: evidence
            .unsupported_effects
            .iter()
            .map(|effect| UnknownEffect {
                kind: "unsupported-c1-effect".into(),
                target: Some(effect.clone()),
                reason: "the checked execution reported an unsupported effect".into(),
            })
            .collect(),
        evidence: Vec::new(),
        claims: Vec::new(),
        final_state: Some(world_commitment(
            "v6-accepted-final-world",
            &evidence.accepted_final_root,
        )),
        seal: None,
    };

    let mut bundle = ArtifactBundle::new(run);
    let manifest_blob = bundle.add_blob(
        evidence.c1_manifest.clone(),
        "application/vnd.realm.v6.c1-manifest+json",
    );
    let intent_blob = bundle.add_blob(intent_bytes, "application/vnd.realm.v6.task-intent+json");
    let contract_blob = bundle.add_blob(
        effect_contract_bytes,
        "application/vnd.realm.v6.effect-contract+json",
    );
    let checked_blob = bundle.add_blob(
        checked_bytes,
        "application/vnd.realm.v6.checked-c1-evidence+json",
    );
    let decision_blob = bundle.add_blob(
        decision_bytes,
        "application/vnd.realm.v6.verifier-decision+json",
    );

    let mut observed_ids = Vec::new();
    for (index, path) in evidence.observed_effects.iter().enumerate() {
        let observation_id = format!("v6-observed-effect-event-{index}");
        let claim_id = format!("v6-observed-effect-claim-{index}");
        observed_ids.push(observation_id.clone());
        observed_ids.push(claim_id.clone());
        bundle.run.observations.push(ObservedEvent {
            id: observation_id,
            kind: "c1-host-observed-filesystem-effect".into(),
            target: path.clone(),
            checkpoint: None,
            evidence: vec!["v6-checked-c1".into()],
        });
        bundle.run.claims.push(Claim {
            id: claim_id,
            kind: ClaimKind::Observed,
            statement: hash(
                "realm.v6.observed-effect",
                &serde_json::to_vec(&(index, path))?,
            ),
            run_id: evidence.run_id.clone(),
            checkpoint: None,
            evidence: vec!["v6-checked-c1".into()],
        });
    }

    let intent_digest = bundle.run.intent.digest.clone();
    let policy_digest = bundle.run.effect_contract.digest.clone();
    let start_digest = bundle.run.starting_state.digest.clone();
    let final_digest = bundle
        .run
        .final_state
        .as_ref()
        .expect("final state constructed")
        .digest
        .clone();
    let manifest_digest = hash("realm.v6.c1-manifest", &evidence.c1_manifest);
    let accepted_digest = hash(
        "realm.v6.checked-accept",
        evidence.accepted_decision_identity.as_bytes(),
    );
    let delta_digest = Digest {
        algorithm: "blake3".into(),
        domain: "realm.delta".into(),
        value: evidence.accepted_delta_root.clone(),
    };
    let claims = [
        ("v6-intent", ClaimKind::Agent, intent_digest),
        ("v6-effect-contract", ClaimKind::Agent, policy_digest),
        ("v6-starting-world", ClaimKind::Observed, start_digest),
        ("v6-final-world", ClaimKind::Observed, final_digest),
        ("v6-c1-manifest", ClaimKind::Observed, manifest_digest),
        ("v6-checked-accept", ClaimKind::Observed, accepted_digest),
        ("v6-semantic-delta", ClaimKind::Proposed, delta_digest),
        (
            "v6-verifier-result",
            ClaimKind::Observed,
            decision_digest.clone(),
        ),
    ];
    for (id, kind, statement) in claims {
        bundle.run.claims.push(Claim {
            id: id.into(),
            kind,
            statement,
            run_id: evidence.run_id.clone(),
            checkpoint: None,
            evidence: vec!["v6-checked-c1".into()],
        });
    }

    let mut checked_supports = vec![
        "v6-intent",
        "v6-effect-contract",
        "v6-starting-world",
        "v6-final-world",
        "v6-c1-manifest",
        "v6-checked-accept",
        "v6-semantic-delta",
        "v6-verifier-result",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    checked_supports.extend(observed_ids);
    bundle.run.evidence = vec![
        evidence_ref(
            "v6-intent",
            "v6-task-intent",
            intent_blob,
            &evidence.run_id,
            false,
            vec!["v6-intent"],
        ),
        evidence_ref(
            "v6-effect-contract",
            "v6-effect-contract",
            contract_blob,
            &evidence.run_id,
            false,
            vec!["v6-effect-contract"],
        ),
        evidence_ref(
            "v6-c1-manifest",
            "v6-c1-manifest",
            manifest_blob,
            &evidence.run_id,
            true,
            vec!["v6-c1-manifest", "v6-checked-accept"],
        ),
        evidence_ref(
            "v6-checked-c1",
            "v6-checked-c1-evidence",
            checked_blob,
            &evidence.run_id,
            true,
            checked_supports,
        ),
        evidence_ref(
            VERIFIER_EVIDENCE_ID,
            "v6-verifier-decision",
            decision_blob,
            &evidence.run_id,
            true,
            vec!["v6-verifier-result"],
        ),
    ];
    bundle.seal()?;
    bundle.envelope.verification.push(VerificationRef {
        id: "v6-c1-verification".into(),
        verifier: decision.verifier,
        result_digest: decision_digest,
        decision: VerificationDecision::Accept,
        run_id: evidence.run_id.clone(),
        checkpoint: None,
        supports: vec!["v6-verifier-result".into(), "v6-checked-accept".into()],
    });
    bundle.validate_at(crate::ValidationLevel::AttestationShape)?;
    Ok(bundle)
}

fn evidence_ref<S: AsRef<str>>(
    id: &str,
    evidence_type: &str,
    blob: BlobRef,
    run_id: &str,
    authoritative: bool,
    supports: Vec<S>,
) -> EvidenceRef {
    EvidenceRef {
        id: id.into(),
        evidence_type: evidence_type.into(),
        digest: blob.digest,
        size: Some(blob.size),
        run_id: run_id.into(),
        checkpoint: None,
        supports: supports
            .into_iter()
            .map(|support| support.as_ref().to_owned())
            .collect(),
        authoritative,
    }
}

fn world_commitment(identity: &str, root: &str) -> Commitment {
    Commitment {
        identity: identity.into(),
        digest: Digest {
            algorithm: "blake3".into(),
            domain: "realm.world".into(),
            value: root.into(),
        },
    }
}

fn validate_execution_evidence(
    result: &ExecuteResult,
    evidence: &CheckedC1Evidence,
) -> Result<(), ArtifactError> {
    if !matches!(&result.verifier_decision, Admission::Refuse(_))
        || evidence.verifier_decision != "CHECKED_FOR_PUBLICATION"
        || result.run_id != evidence.run_id
        || result.execution_id != evidence.execution_id
        || result.starting_world_commitment != evidence.accepted_start_root
        || result.final_world_commitment.as_deref() != Some(evidence.accepted_final_root.as_str())
        || result.delta_root.as_deref() != Some(evidence.accepted_delta_root.as_str())
        || result.evidence_root.as_deref() != Some(evidence.evidence_root.as_str())
        || result.observed_effects != evidence.observed_effects
        || result.unsupported_effects != evidence.unsupported_effects
        || !realm_v6::execute::validate_checked_c1_evidence(evidence)
    {
        return Err(ArtifactError::Invalid(
            "checked execution report and C1 evidence disagree".into(),
        ));
    }
    Ok(())
}

fn checked_manifest(evidence: &CheckedC1Evidence) -> Result<MediationManifest, ArtifactError> {
    check_manifest_claim_shape(&evidence.c1_manifest, &evidence.c1_manifest_root)
        .map(|claim| claim.manifest)
        .map_err(|error| ArtifactError::Invalid(format!("C1 manifest rejected: {error:?}")))
}

fn verifier_decision(evidence: &CheckedC1Evidence) -> V6VerifierDecisionEvidence {
    V6VerifierDecisionEvidence {
        schema_version: 1,
        decision: evidence.verifier_decision.clone(),
        verifier: "realm-v6/c1-checked-execution-v2".into(),
        run_id: evidence.run_id.clone(),
        execution_id: evidence.execution_id.clone(),
        checked_claim_root: evidence.checked_claim_root.clone(),
        accepted_decision_identity: evidence.accepted_decision_identity.clone(),
        c1_manifest_root: evidence.c1_manifest_root.clone(),
        evidence_root: evidence.evidence_root.clone(),
    }
}

fn valid_digest(digest: &Digest) -> bool {
    digest.algorithm == "blake3"
        && !digest.domain.is_empty()
        && digest.value.len() == 64
        && digest.value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn blob_bytes(
    bundle: &ArtifactBundle,
    blob: &BlobRef,
    resolver: Option<&dyn crate::ContentResolver>,
) -> Result<Vec<u8>, ArtifactError> {
    let bytes = match bundle.blobs.get(&blob.digest.value) {
        Some(bytes) => bytes.clone(),
        None => resolver
            .map(|resolver| resolver.resolve(&blob.digest))
            .transpose()?
            .flatten()
            .ok_or_else(|| ArtifactError::MissingBlob(blob.digest.value.clone()))?,
    };
    if bytes.len() as u64 != blob.size || hash("realm.blob", &bytes) != blob.digest {
        return Err(ArtifactError::Invalid(
            "publication evidence blob digest or size mismatch".into(),
        ));
    }
    Ok(bytes)
}

fn checked_run_evidence(
    bundle: &ArtifactBundle,
    resolver: Option<&dyn crate::ContentResolver>,
) -> Result<Option<CheckedC1Evidence>, ArtifactError> {
    let Some(reference) = bundle
        .run
        .evidence
        .iter()
        .find(|reference| reference.id == "v6-checked-c1")
    else {
        return Ok(None);
    };
    if reference.evidence_type != "v6-checked-c1-evidence"
        || reference.run_id != bundle.run.run.run_id
        || !reference.authoritative
    {
        return Err(ArtifactError::Invalid(
            "checked C1 evidence reference has the wrong type or identity".into(),
        ));
    }
    let bytes = evidence_blob(bundle, reference, resolver)?;
    let evidence: CheckedC1Evidence = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&evidence)? != bytes {
        return Err(ArtifactError::Invalid(
            "checked C1 evidence is not canonically encoded".into(),
        ));
    }
    Ok(Some(evidence))
}

fn evidence_blob(
    bundle: &ArtifactBundle,
    reference: &EvidenceRef,
    resolver: Option<&dyn crate::ContentResolver>,
) -> Result<Vec<u8>, ArtifactError> {
    let size = reference
        .size
        .ok_or_else(|| ArtifactError::Invalid("V6 evidence size is absent".into()))?;
    blob_bytes(
        bundle,
        &BlobRef {
            digest: reference.digest.clone(),
            size,
            media_type: "application/octet-stream".into(),
        },
        resolver,
    )
}

/// Cross-check V6 execution and generation claims after generic artifact
/// integrity validation. This is structural verification only.
pub(crate) fn validate_v6_evidence(
    bundle: &ArtifactBundle,
    semantic_root: &Digest,
    _level: crate::ValidationLevel,
    resolver: Option<&dyn crate::ContentResolver>,
) -> Result<(), ArtifactError> {
    let Some(evidence) = checked_run_evidence(bundle, resolver)? else {
        if bundle.envelope.publication.generation.is_some() {
            return Err(ArtifactError::Invalid(
                "generation publication has no checked C1 execution".into(),
            ));
        }
        return Ok(());
    };
    if !realm_v6::execute::validate_checked_c1_evidence(&evidence)
        || bundle.run.lifecycle != Lifecycle::Frozen && bundle.run.lifecycle != Lifecycle::Sealed
        || bundle.run.run.run_id != evidence.run_id
        || bundle.run.run.execution_id != evidence.execution_id
        || bundle.run.starting_state.digest.value != evidence.accepted_start_root
        || bundle.run.starting_state.identity != "v6-starting-world"
        || bundle
            .run
            .final_state
            .as_ref()
            .map(|state| state.digest.value.as_str())
            != Some(evidence.accepted_final_root.as_str())
        || bundle
            .run
            .final_state
            .as_ref()
            .map(|state| state.identity.as_str())
            != Some("v6-accepted-final-world")
        || bundle.run.intent.identity != "v6-command-intent"
        || bundle.run.intent.digest != hash("realm.intent", &serde_json::to_vec(&evidence.command)?)
        || bundle.run.effect_contract.identity != "v6-allowed-effects-paths-timeout"
        || bundle.run.effect_contract.digest
            != hash(
                "realm.policy",
                &realm_v6::execute::checked_effect_contract_bytes(&evidence)?,
            )
    {
        return Err(ArtifactError::Invalid(
            "sealed RealmRun does not bind the checked C1 execution".into(),
        ));
    }
    let manifest = checked_manifest(&evidence)?;
    if bundle.run.environment.runtime_digest.value != manifest.runtime_identity
        || bundle
            .run
            .challenge
            .nonce
            .as_ref()
            .map(|nonce| nonce.value.as_str())
            != Some(evidence.challenge_binding.as_str())
        || bundle.run.challenge.issued_by != "realm-v6-measured-supervisor"
        || bundle.run.challenge.expires_at.is_some()
        || bundle.run.environment.runtime != "realm-v6"
        || bundle.run.environment.backend != "firecracker-measured"
        || bundle.run.environment.architecture != "x86_64"
    {
        return Err(ArtifactError::Invalid(
            "RealmRun runtime or challenge differs from checked C1 evidence".into(),
        ));
    }

    for (id, expected_type, expected_bytes, authoritative) in [
        (
            "v6-c1-manifest",
            "v6-c1-manifest",
            evidence.c1_manifest.clone(),
            true,
        ),
        (
            "v6-intent",
            "v6-task-intent",
            serde_json::to_vec(&evidence.command)?,
            false,
        ),
        (
            "v6-effect-contract",
            "v6-effect-contract",
            realm_v6::execute::checked_effect_contract_bytes(&evidence)?,
            false,
        ),
    ] {
        let reference = bundle
            .run
            .evidence
            .iter()
            .find(|reference| reference.id == id)
            .ok_or_else(|| ArtifactError::Invalid(format!("missing V6 evidence {id}")))?;
        if reference.evidence_type != expected_type
            || reference.run_id != evidence.run_id
            || reference.authoritative != authoritative
            || evidence_blob(bundle, reference, resolver)? != expected_bytes
        {
            return Err(ArtifactError::Invalid(format!(
                "V6 evidence {id} differs from the checked execution"
            )));
        }
    }

    let decision = verifier_decision(&evidence);
    let decision_bytes = serde_json::to_vec(&decision)?;
    let decision_digest = hash("realm.verifier-result", &decision_bytes);
    validate_semantic_projection(bundle, &evidence, &decision_digest)?;
    let decision_reference = bundle
        .run
        .evidence
        .iter()
        .find(|reference| reference.id == VERIFIER_EVIDENCE_ID)
        .ok_or_else(|| ArtifactError::Invalid("missing immutable V6 verifier evidence".into()))?;
    if decision_reference.evidence_type != "v6-verifier-decision"
        || decision_reference.run_id != evidence.run_id
        || !decision_reference.authoritative
        || evidence_blob(bundle, decision_reference, resolver)? != decision_bytes
    {
        return Err(ArtifactError::Invalid(
            "immutable V6 verifier evidence differs from checked execution".into(),
        ));
    }
    let verification = bundle
        .envelope
        .verification
        .iter()
        .filter(|reference| reference.id == "v6-c1-verification")
        .collect::<Vec<_>>();
    if bundle.run.lifecycle == Lifecycle::Sealed {
        if verification.len() != 1
            || verification[0].run_id != evidence.run_id
            || verification[0].decision != VerificationDecision::Accept
            || verification[0].result_digest != decision_digest
            || !verification[0]
                .supports
                .iter()
                .any(|id| id == "v6-verifier-result")
        {
            return Err(ArtifactError::Invalid(
                "outer verifier reference does not bind immutable V6 ACCEPT evidence".into(),
            ));
        }
    } else if !verification.is_empty() {
        return Err(ArtifactError::Invalid(
            "unsealed V6 evidence cannot carry a verifier decision".into(),
        ));
    }

    if let Some(publication) = &bundle.envelope.publication.generation {
        validate_generation_publication(bundle, publication, semantic_root, &evidence, resolver)?;
    } else if bundle.envelope.publication.status == PublicationStatus::Published {
        return Err(ArtifactError::Invalid(
            "V6 PUBLISHED status lacks typed generation evidence".into(),
        ));
    }
    Ok(())
}

fn validate_semantic_projection(
    bundle: &ArtifactBundle,
    evidence: &CheckedC1Evidence,
    decision_digest: &Digest,
) -> Result<(), ArtifactError> {
    let run = &bundle.run;
    if !run.inputs.is_empty()
        || !run.outputs.is_empty()
        || !run.checkpoints.is_empty()
        || !run.proposed_effects.is_empty()
    {
        return Err(ArtifactError::Invalid(
            "V6 RealmRun contains semantic objects outside the checked C1 projection".into(),
        ));
    }

    let expected_unknown = evidence
        .unsupported_effects
        .iter()
        .map(|effect| UnknownEffect {
            kind: "unsupported-c1-effect".into(),
            target: Some(effect.clone()),
            reason: "the checked execution reported an unsupported effect".into(),
        })
        .collect::<Vec<_>>();
    if run.unknown_effects != expected_unknown {
        return Err(ArtifactError::Invalid(
            "V6 unknown effects differ from checked C1 evidence".into(),
        ));
    }

    let mut expected_observations = Vec::new();
    let mut expected_claims = Vec::new();
    for (index, path) in evidence.observed_effects.iter().enumerate() {
        expected_observations.push(ObservedEvent {
            id: format!("v6-observed-effect-event-{index}"),
            kind: "c1-host-observed-filesystem-effect".into(),
            target: path.clone(),
            checkpoint: None,
            evidence: vec!["v6-checked-c1".into()],
        });
        expected_claims.push(Claim {
            id: format!("v6-observed-effect-claim-{index}"),
            kind: ClaimKind::Observed,
            statement: hash(
                "realm.v6.observed-effect",
                &serde_json::to_vec(&(index, path))?,
            ),
            run_id: evidence.run_id.clone(),
            checkpoint: None,
            evidence: vec!["v6-checked-c1".into()],
        });
    }

    let expected_claim_fields = [
        ("v6-intent", ClaimKind::Agent, run.intent.digest.clone()),
        (
            "v6-effect-contract",
            ClaimKind::Agent,
            run.effect_contract.digest.clone(),
        ),
        (
            "v6-starting-world",
            ClaimKind::Observed,
            run.starting_state.digest.clone(),
        ),
        (
            "v6-final-world",
            ClaimKind::Observed,
            run.final_state
                .as_ref()
                .expect("validated V6 final state")
                .digest
                .clone(),
        ),
        (
            "v6-c1-manifest",
            ClaimKind::Observed,
            hash("realm.v6.c1-manifest", &evidence.c1_manifest),
        ),
        (
            "v6-checked-accept",
            ClaimKind::Observed,
            hash(
                "realm.v6.checked-accept",
                evidence.accepted_decision_identity.as_bytes(),
            ),
        ),
        (
            "v6-semantic-delta",
            ClaimKind::Proposed,
            Digest {
                algorithm: "blake3".into(),
                domain: "realm.delta".into(),
                value: evidence.accepted_delta_root.clone(),
            },
        ),
        (
            "v6-verifier-result",
            ClaimKind::Observed,
            decision_digest.clone(),
        ),
    ];
    expected_claims.extend(
        expected_claim_fields
            .into_iter()
            .map(|(id, kind, statement)| Claim {
                id: id.into(),
                kind,
                statement,
                run_id: evidence.run_id.clone(),
                checkpoint: None,
                evidence: vec!["v6-checked-c1".into()],
            }),
    );

    if run.observations != expected_observations || run.claims != expected_claims {
        return Err(ArtifactError::Invalid(
            "V6 observations or claims differ from checked C1 evidence".into(),
        ));
    }
    Ok(())
}

/// Attach a real generation receipt and its terminal journal record to the
/// envelope of the exact sealed semantic run. This records publication
/// evidence only; it does not authorize publication or recreate the checked
/// execution capability.
pub fn bind_generation_publication(
    bundle: &mut ArtifactBundle,
    receipt: &GenerationReceipt,
    journal_record: &PublicationRecord,
) -> Result<(), ArtifactError> {
    if bundle.run.lifecycle != Lifecycle::Sealed {
        return Err(ArtifactError::Invalid(
            "generation evidence requires a sealed semantic run".into(),
        ));
    }
    bundle.validate_at(crate::ValidationLevel::AttestationShape)?;
    let evidence = checked_run_evidence(bundle, None)?
        .ok_or_else(|| ArtifactError::Invalid("missing checked C1 execution evidence".into()))?;
    let identity = &receipt.identity;
    identity.validate_integrity().map_err(|error| {
        ArtifactError::Invalid(format!("generation identity rejected: {error}"))
    })?;
    if receipt.schema_version != 1
        || receipt.live_root != evidence.accepted_final_root
        || receipt.previous_root != evidence.accepted_start_root
        || identity.run_id() != evidence.run_id
        || identity.execution_id() != evidence.execution_id
        || identity.capsule_id() != evidence.capsule_id
        || identity.challenge_binding() != evidence.challenge_binding
        || identity.accepted_decision_identity() != evidence.accepted_decision_identity
        || identity.accepted_start_root() != evidence.accepted_start_root
        || identity.accepted_final_root() != evidence.accepted_final_root
        || identity.accepted_delta_root() != evidence.accepted_delta_root
    {
        return Err(ArtifactError::Invalid(
            "generation receipt substitutes a different checked execution".into(),
        ));
    }
    let receipt_bytes = serde_json::to_vec(receipt)?;
    let receipt_raw_digest = blake3::hash(&receipt_bytes).to_hex().to_string();
    if journal_record.schema_version != 2
        || journal_record.state != PublicationState::Published
        || journal_record.sequence == 0
        || journal_record.publication_id != identity.publication_id()
        || journal_record.execution_id != identity.execution_id()
        || journal_record.run_id != identity.run_id()
        || journal_record.decision_identity != identity.accepted_decision_identity()
        || journal_record.destination_identity != identity.workspace_identity()
        || journal_record.accepted_final_root != identity.accepted_final_root()
        || journal_record.accepted_delta_root != identity.accepted_delta_root()
        || journal_record.pre_publication_root != identity.accepted_start_root()
        || journal_record.post_publication_root.as_deref() != Some(identity.accepted_final_root())
        || journal_record.generation_identity.as_ref() != Some(identity)
        || journal_record.receipt_digest.as_deref() != Some(receipt_raw_digest.as_str())
        || journal_record.error.is_some()
    {
        return Err(ArtifactError::Invalid(
            "journal record does not prove this generation reached PUBLISHED".into(),
        ));
    }

    let record_bytes = serde_json::to_vec(journal_record)?;
    let semantic_run_root = bundle.semantic_identity()?;
    let mut candidate = bundle.clone();
    let receipt_blob = candidate.add_blob(
        receipt_bytes,
        "application/vnd.realm.v6.generation-receipt+json",
    );
    let journal_record_blob = candidate.add_blob(
        record_bytes,
        "application/vnd.realm.v6.publication-journal-record+json",
    );
    let publication = GenerationPublicationEvidence {
        semantic_run_root,
        generation_identity: identity.clone(),
        commit_sequence: journal_record.sequence,
        commit_mechanism: GENERATION_EXCHANGE_MECHANISM.into(),
        journal_state: PublicationState::Published,
        live_root: receipt.live_root.clone(),
        previous_generation_root: receipt.previous_root.clone(),
        receipt_identity: Digest {
            algorithm: "blake3".into(),
            domain: "realm.v6-generation-receipt".into(),
            value: receipt_raw_digest,
        },
        receipt_blob,
        journal_record_blob,
    };
    candidate.envelope.publication = PublicationMetadata {
        status: PublicationStatus::Published,
        reference: Some(identity.publication_id().into()),
        policy_identity: Some(hash(
            "realm.v6-publication-mechanism",
            GENERATION_EXCHANGE_MECHANISM.as_bytes(),
        )),
        generation: Some(publication),
    };
    candidate.validate_at(crate::ValidationLevel::AttestationShape)?;
    *bundle = candidate;
    Ok(())
}

fn validate_generation_publication(
    bundle: &ArtifactBundle,
    publication: &GenerationPublicationEvidence,
    semantic_root: &Digest,
    evidence: &CheckedC1Evidence,
    resolver: Option<&dyn crate::ContentResolver>,
) -> Result<(), ArtifactError> {
    if bundle.run.lifecycle != Lifecycle::Sealed
        || bundle.envelope.publication.status != PublicationStatus::Published
        || bundle.envelope.publication.reference.as_deref()
            != Some(publication.generation_identity.publication_id())
        || publication.semantic_run_root != *semantic_root
        || publication.commit_mechanism != GENERATION_EXCHANGE_MECHANISM
        || publication.journal_state != PublicationState::Published
        || publication.live_root != evidence.accepted_final_root
        || publication.previous_generation_root != evidence.accepted_start_root
        || !valid_digest(&publication.semantic_run_root)
        || !valid_digest(&publication.receipt_identity)
    {
        return Err(ArtifactError::Invalid(
            "generation publication metadata is inconsistent with the sealed run".into(),
        ));
    }
    let identity = &publication.generation_identity;
    identity.validate_integrity().map_err(|error| {
        ArtifactError::Invalid(format!("generation identity rejected: {error}"))
    })?;
    if identity.run_id() != evidence.run_id
        || identity.execution_id() != evidence.execution_id
        || identity.capsule_id() != evidence.capsule_id
        || identity.challenge_binding() != evidence.challenge_binding
        || identity.accepted_decision_identity() != evidence.accepted_decision_identity
        || identity.accepted_start_root() != evidence.accepted_start_root
        || identity.accepted_final_root() != evidence.accepted_final_root
        || identity.accepted_delta_root() != evidence.accepted_delta_root
    {
        return Err(ArtifactError::Invalid(
            "generation identity does not match the checked semantic execution".into(),
        ));
    }

    let receipt_bytes = blob_bytes(bundle, &publication.receipt_blob, resolver)?;
    let receipt: GenerationReceipt = serde_json::from_slice(&receipt_bytes)?;
    let raw_receipt_digest = blake3::hash(&receipt_bytes).to_hex().to_string();
    let record_bytes = blob_bytes(bundle, &publication.journal_record_blob, resolver)?;
    let record: PublicationRecord = serde_json::from_slice(&record_bytes)?;
    if publication.receipt_identity.algorithm != "blake3"
        || publication.receipt_identity.domain != "realm.v6-generation-receipt"
        || publication.receipt_identity.value != raw_receipt_digest
        || receipt.schema_version != 1
        || receipt.identity != *identity
        || receipt.live_root != evidence.accepted_final_root
        || receipt.previous_root != evidence.accepted_start_root
        || record.schema_version != 2
        || record.sequence != publication.commit_sequence
        || record.state != PublicationState::Published
        || record.publication_id != identity.publication_id()
        || record.execution_id != identity.execution_id()
        || record.run_id != identity.run_id()
        || record.decision_identity != identity.accepted_decision_identity()
        || record.destination_identity != identity.workspace_identity()
        || record.accepted_final_root != identity.accepted_final_root()
        || record.accepted_delta_root != identity.accepted_delta_root()
        || record.pre_publication_root != identity.accepted_start_root()
        || record.post_publication_root.as_deref() != Some(identity.accepted_final_root())
        || record.generation_identity.as_ref() != Some(identity)
        || record.receipt_digest.as_deref() != Some(raw_receipt_digest.as_str())
        || record.error.is_some()
    {
        return Err(ArtifactError::Invalid(
            "generation receipt and terminal journal record disagree".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{
        AuthorityHead, GenesisAnchor, LifecycleSnapshot, LifecycleTransition, LifecycleTrust,
        VerificationState, verify_chain,
    };
    use realm_v6::{filesystem_world, generation::GenerationLayout, mediation::AttachedDevice};
    use std::{
        collections::BTreeMap,
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::Path,
    };

    fn repeated(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn repeated_hex_offset(base: u8, offset: u8) -> String {
        let nibble = base.wrapping_add(offset) % 16;
        repeated(char::from_digit(u32::from(nibble), 16).unwrap())
    }

    fn execution_fixture(run_id: &str, offset: u8) -> (ExecuteResult, CheckedC1Evidence) {
        execution_fixture_with_roots(
            run_id,
            offset,
            repeated_hex_offset(1, offset),
            repeated_hex_offset(2, offset),
            repeated_hex_offset(3, offset),
        )
    }

    fn execution_fixture_with_roots(
        run_id: &str,
        offset: u8,
        start: String,
        final_root: String,
        delta: String,
    ) -> (ExecuteResult, CheckedC1Evidence) {
        let capsule_id = repeated_hex_offset(4, offset);
        let challenge_binding = repeated_hex_offset(5, offset);
        let finalization_evidence = repeated_hex_offset(7, offset);
        let pause_snapshot_evidence = repeated_hex_offset(8, offset);
        let execution_id = repeated_hex_offset(9, offset);
        let runtime_identity = repeated('a');
        let network_policy_identity = repeated('b');
        let command = vec!["/bin/true".to_owned()];
        let allowed_effects = vec!["filesystem".to_owned()];
        let allowed_paths = vec!["target.txt".to_owned()];
        let timeout_ms = 1_000;
        let intent_identity = hash("realm.intent", &serde_json::to_vec(&command).unwrap()).value;
        let effect_contract_identity = hash(
            "realm.policy",
            &serde_json::to_vec(&(&allowed_effects, &allowed_paths, timeout_ms)).unwrap(),
        )
        .value;
        let observed_effects = vec!["target.txt".to_owned()];
        let unsupported_effects = Vec::new();

        let vmm_terminal_observation_root = repeated_hex_offset(10, offset);
        let mut evidence_hasher = blake3::Hasher::new();
        evidence_hasher.update(b"REALM::V6CapsuleEvidenceBinding\0");
        evidence_hasher.update(&2_u16.to_le_bytes());
        for value in [
            runtime_identity.as_str(),
            start.as_str(),
            capsule_id.as_str(),
            start.as_str(),
            final_root.as_str(),
            challenge_binding.as_str(),
            finalization_evidence.as_str(),
            pause_snapshot_evidence.as_str(),
            vmm_terminal_observation_root.as_str(),
            delta.as_str(),
            network_policy_identity.as_str(),
        ] {
            evidence_hasher.update(&(value.len() as u64).to_le_bytes());
            evidence_hasher.update(value.as_bytes());
        }
        let evidence_root = evidence_hasher.finalize().to_hex().to_string();

        let rootfs = repeated('c');
        let manifest = MediationManifest {
            schema: 2,
            run_id: run_id.into(),
            vm_config_blake3: repeated('d'),
            guest_kernel_blake3: repeated('e'),
            rootfs_blake3: rootfs.clone(),
            task_blake3: blake3::hash(&serde_json::to_vec(&command).unwrap())
                .to_hex()
                .to_string(),
            guest_policy_blake3: repeated('f'),
            seccomp_blake3: repeated('a'),
            measured_launch_hash_domain: realm_v6::measured_launch::MEASURED_LAUNCH_HASH_DOMAIN
                .into(),
            measured_launch_hash_version: realm_v6::measured_launch::MEASURED_LAUNCH_HASH_VERSION,
            measured_launch_blake3: repeated('9'),
            broker_endpoint_identity: repeated('8'),
            host_policy_identifier: "fixture-policy".into(),
            host_policy_version: "1".into(),
            host_policy_blake3: repeated('7'),
            launch_identity: execution_id.clone(),
            starting_generation: start.clone(),
            final_world: final_root.clone(),
            delta_root: delta.clone(),
            runtime_identity: runtime_identity.clone(),
            network_policy_identity,
            broker_identity: repeated('b'),
            broker_endpoint: "vsock:host:7000".into(),
            devices: vec![
                AttachedDevice {
                    kind: "rootfs".into(),
                    identity: rootfs.clone(),
                    read_only: true,
                },
                AttachedDevice {
                    kind: "broker_vsock".into(),
                    identity: "vsock:host:7000".into(),
                    read_only: true,
                },
            ],
            network_devices: Vec::new(),
            shared_mounts: Vec::new(),
            inherited_fds: Vec::new(),
            writable_mappings: Vec::new(),
            other_storage_aliases: Vec::new(),
            max_task_processes: 1,
        };
        let c1_manifest = serde_json::to_vec(&manifest).unwrap();
        let c1_manifest_root = blake3::hash(&c1_manifest).to_hex().to_string();
        let checked_claim_root = c1_manifest_root.clone();
        let same_run_join_root = repeated_hex_offset(6, offset);
        let decision_material = (
            "realm-v6-checked-c1-accept-v3",
            &checked_claim_root,
            &c1_manifest_root,
            run_id,
            &execution_id,
            &capsule_id,
            &challenge_binding,
            &evidence_root,
            &same_run_join_root,
            &intent_identity,
            &effect_contract_identity,
            &start,
            &final_root,
            &delta,
        );
        let accepted_decision_identity =
            blake3::hash(&serde_json::to_vec(&decision_material).unwrap())
                .to_hex()
                .to_string();
        let evidence = CheckedC1Evidence {
            schema_version: 3,
            file_contract: None,
            verifier_decision: "CHECKED_FOR_PUBLICATION".into(),
            run_id: run_id.into(),
            execution_id: execution_id.clone(),
            capsule_id,
            // This is an intentionally legacy v3 fixture. It predates the
            // custody process identity required by current publication joins.
            custody_process_identity: None,
            challenge_binding,
            checked_claim_root,
            accepted_decision_identity,
            same_run_join_root,
            accepted_start_root: start.clone(),
            accepted_final_root: final_root.clone(),
            accepted_delta_root: delta.clone(),
            evidence_root: evidence_root.clone(),
            vmm_terminal_observation_root: Some(vmm_terminal_observation_root),
            finalization_evidence,
            pause_snapshot_evidence,
            c1_manifest_root,
            c1_manifest,
            command,
            allowed_effects,
            allowed_paths,
            observed_effects: observed_effects.clone(),
            unsupported_effects: unsupported_effects.clone(),
            timeout_ms,
            intent_identity,
            effect_contract_identity,
        };
        let result = ExecuteResult {
            guest_exit_code: None,
            guest_crashed: None,
            vmm_pid: None,
            vmm_start_time_ticks: None,
            schema_version: 1,
            run_id: run_id.into(),
            execution_id,
            starting_world_commitment: start,
            final_world_commitment: Some(final_root),
            delta_root: Some(delta),
            starting_workspace_image: None,
            final_workspace_image: None,
            observed_effects,
            proposed_effects: Vec::new(),
            evidence_root: Some(evidence_root),
            receipt_path: None,
            verifier_decision: Admission::Refuse(realm_v6::Refusal::UnverifiedBoundary),
            reason_code: "C1_OBSERVATION_COMPLETE".into(),
            task_success: true,
            unsupported_effects,
            runtime_ms: 1,
            overhead_ms: 1,
        };
        (result, evidence)
    }

    fn sealed_artifact(run_id: &str, offset: u8) -> ArtifactBundle {
        let (result, evidence) = execution_fixture(run_id, offset);
        bundle_from_checked_data(&result, &evidence).unwrap()
    }

    fn reseal_without_validation(bundle: &mut ArtifactBundle) {
        bundle.run.seal = None;
        let root = hash("realm.seal", &crate::canonical_json(&bundle.run).unwrap());
        bundle.run.seal = Some(crate::Seal {
            root,
            lifecycle: Lifecycle::Sealed,
        });
    }

    fn fake_generation_identity(evidence: &CheckedC1Evidence) -> GenerationIdentity {
        fake_generation_identity_with_roots(
            evidence,
            &evidence.accepted_start_root,
            &evidence.accepted_final_root,
            &evidence.accepted_delta_root,
        )
    }

    fn fake_generation_identity_with_roots(
        evidence: &CheckedC1Evidence,
        start_root: &str,
        final_root: &str,
        delta_root: &str,
    ) -> GenerationIdentity {
        fake_generation_identity_for_workspace(
            evidence,
            &repeated('f'),
            start_root,
            final_root,
            delta_root,
        )
    }

    fn fake_generation_identity_for_workspace(
        evidence: &CheckedC1Evidence,
        workspace_identity: &str,
        start_root: &str,
        final_root: &str,
        delta_root: &str,
    ) -> GenerationIdentity {
        let generation_material = (
            "realm-v6-generation-v1",
            &evidence.run_id,
            &evidence.execution_id,
            &evidence.accepted_decision_identity,
            &evidence.capsule_id,
            &evidence.challenge_binding,
            workspace_identity,
            start_root,
            final_root,
            delta_root,
        );
        let generation_id = blake3::hash(&serde_json::to_vec(&generation_material).unwrap())
            .to_hex()
            .to_string();
        let publication_id = blake3::hash(
            &serde_json::to_vec(&("realm-v6-publication-v1", &generation_id)).unwrap(),
        )
        .to_hex()
        .to_string();
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "execution_id": evidence.execution_id,
            "run_id": evidence.run_id,
            "capsule_id": evidence.capsule_id,
            "challenge_binding": evidence.challenge_binding,
            "accepted_decision_identity": evidence.accepted_decision_identity,
            "accepted_start_root": start_root,
            "accepted_final_root": final_root,
            "accepted_delta_root": delta_root,
            "workspace_identity": workspace_identity,
            "generation_id": generation_id,
            "publication_id": publication_id
        }))
        .unwrap()
    }

    fn fake_published_records(
        evidence: &CheckedC1Evidence,
    ) -> (GenerationReceipt, PublicationRecord) {
        fake_published_records_for_identity(fake_generation_identity(evidence))
    }

    fn fake_published_records_for_identity(
        identity: GenerationIdentity,
    ) -> (GenerationReceipt, PublicationRecord) {
        let receipt = GenerationReceipt {
            schema_version: 1,
            identity: identity.clone(),
            live_root: identity.accepted_final_root().into(),
            previous_root: identity.accepted_start_root().into(),
        };
        let receipt_digest = blake3::hash(&serde_json::to_vec(&receipt).unwrap())
            .to_hex()
            .to_string();
        let record = PublicationRecord {
            schema_version: 2,
            sequence: 9,
            publication_id: identity.publication_id().into(),
            execution_id: identity.execution_id().into(),
            run_id: identity.run_id().into(),
            decision_identity: identity.accepted_decision_identity().into(),
            destination_identity: identity.workspace_identity().into(),
            accepted_final_root: identity.accepted_final_root().into(),
            accepted_delta_root: identity.accepted_delta_root().into(),
            pre_publication_root: identity.accepted_start_root().into(),
            post_publication_root: Some(identity.accepted_final_root().into()),
            generation_identity: Some(identity),
            receipt_digest: Some(receipt_digest),
            state: PublicationState::Published,
            error: None,
        };
        (receipt, record)
    }

    fn lifecycle_fixture(
        run_id: &str,
        offset: u8,
        sequence: u64,
        parent: &AuthorityHead,
    ) -> (LifecycleTransition, Vec<u8>, Vec<u8>, Vec<u8>) {
        let start = parent.world_root.clone();
        let final_root = repeated_hex_offset(2, offset);
        let delta_root = repeated_hex_offset(3, offset);
        let (result, evidence) =
            execution_fixture_with_roots(run_id, offset, start, final_root, delta_root);
        let identity = fake_generation_identity(&evidence);
        let (receipt, mut record) = fake_published_records_for_identity(identity.clone());
        record.sequence = sequence;
        let mut bundle = bundle_from_checked_data(&result, &evidence).unwrap();
        bind_generation_publication(&mut bundle, &receipt, &record).unwrap();
        let publication = bundle.envelope.publication.generation.as_ref().unwrap();
        let receipt_bytes = bundle
            .blobs
            .get(&publication.receipt_blob.digest.value)
            .unwrap()
            .clone();
        let record_bytes = bundle
            .blobs
            .get(&publication.journal_record_blob.digest.value)
            .unwrap()
            .clone();
        let artifact_bytes = bundle.pack().unwrap();
        let transition = LifecycleTransition {
            schema_version: 1,
            domain: "realm.v6.lifecycle-transition.v1".into(),
            sequence: parent.sequence + 1,
            parent_authority_root: parent.authority_root.clone(),
            parent_generation_root: parent.generation_root.clone(),
            parent_world_root: parent.world_root.clone(),
            generation_identity: identity.clone(),
            semantic_run_root: bundle.semantic_identity().unwrap(),
            artifact_digest: crate::hash("realm.v6-lifecycle-artifact", &artifact_bytes),
            receipt_digest: publication.receipt_identity.clone(),
            journal_record_digest: crate::hash(
                "realm.v6-publication-journal-record",
                &record_bytes,
            ),
            journal_sequence: record.sequence,
            world_root: identity.accepted_final_root().into(),
            delta_root: identity.accepted_delta_root().into(),
        };
        (transition, artifact_bytes, receipt_bytes, record_bytes)
    }

    fn filler_journal_record(sequence: u64) -> PublicationRecord {
        PublicationRecord {
            schema_version: 1,
            sequence,
            publication_id: format!("legacy-fixture-{sequence}"),
            execution_id: format!("legacy-execution-{sequence}"),
            run_id: format!("legacy-run-{sequence}"),
            decision_identity: repeated('a'),
            destination_identity: repeated('b'),
            accepted_final_root: repeated('c'),
            accepted_delta_root: repeated('d'),
            pre_publication_root: repeated('e'),
            post_publication_root: None,
            generation_identity: None,
            receipt_digest: None,
            state: PublicationState::Failed,
            error: Some("historical fixture row".into()),
        }
    }

    fn append_journal_row(journal: &mut Vec<u8>, record: &PublicationRecord) {
        journal.extend(serde_json::to_vec(record).unwrap());
        journal.push(b'\n');
    }

    fn create_fixture_world(root: &Path, state: &[u8]) {
        fs::create_dir(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("state.txt"), state).unwrap();
    }

    fn write_fixture_private_file(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn file_backed_lifecycle_package(
        run_id: &str,
        offset: u8,
        layout: &GenerationLayout,
        parent: &AuthorityHead,
        start_root: &str,
        final_root: &str,
        journal_sequence: u64,
    ) -> (LifecycleTransition, Vec<u8>, Vec<u8>, Vec<u8>) {
        let delta_root = repeated_hex_offset(3, offset);
        let (result, evidence) = execution_fixture_with_roots(
            run_id,
            offset,
            start_root.to_owned(),
            final_root.to_owned(),
            delta_root,
        );
        let identity = fake_generation_identity_for_workspace(
            &evidence,
            layout.workspace_identity(),
            start_root,
            final_root,
            &evidence.accepted_delta_root,
        );
        let (receipt, mut record) = fake_published_records_for_identity(identity.clone());
        record.sequence = journal_sequence;
        let mut bundle = bundle_from_checked_data(&result, &evidence).unwrap();
        bind_generation_publication(&mut bundle, &receipt, &record).unwrap();

        let publication = bundle.envelope.publication.generation.as_ref().unwrap();
        let receipt_bytes = bundle
            .blobs
            .get(&publication.receipt_blob.digest.value)
            .unwrap()
            .clone();
        let record_bytes = bundle
            .blobs
            .get(&publication.journal_record_blob.digest.value)
            .unwrap()
            .clone();
        let artifact_bytes = bundle.pack().unwrap();
        let transition = LifecycleTransition {
            schema_version: 1,
            domain: "realm.v6.lifecycle-transition.v1".into(),
            sequence: parent.sequence + 1,
            parent_authority_root: parent.authority_root.clone(),
            parent_generation_root: parent.generation_root.clone(),
            parent_world_root: parent.world_root.clone(),
            generation_identity: identity.clone(),
            semantic_run_root: bundle.semantic_identity().unwrap(),
            artifact_digest: crate::hash("realm.v6-lifecycle-artifact", &artifact_bytes),
            receipt_digest: publication.receipt_identity.clone(),
            journal_record_digest: crate::hash(
                "realm.v6-publication-journal-record",
                &record_bytes,
            ),
            journal_sequence,
            world_root: final_root.into(),
            delta_root: identity.accepted_delta_root().into(),
        };
        (transition, artifact_bytes, receipt_bytes, record_bytes)
    }

    fn persist_file_backed_lifecycle_package(
        layout: &GenerationLayout,
        transition: &LifecycleTransition,
        artifact_bytes: &[u8],
        receipt_bytes: &[u8],
        record_bytes: &[u8],
        first_journal_sequence: u64,
    ) {
        let store = layout.control_root().join("lifecycle");
        let artifact_path = store
            .join("artifacts")
            .join(format!("{}.realm", transition.artifact_digest.value));
        write_fixture_private_file(&artifact_path, artifact_bytes);
        let receipt_path = layout.receipt_directory().join(format!(
            "{}.json",
            transition.generation_identity.publication_id()
        ));
        write_fixture_private_file(&receipt_path, receipt_bytes);
        let transition_path = store
            .join("transitions")
            .join(format!("{}.json", transition.root().unwrap()));
        write_fixture_private_file(&transition_path, &serde_json::to_vec(transition).unwrap());

        let mut journal_batch = Vec::new();
        for sequence in first_journal_sequence..=transition.journal_sequence {
            if sequence == transition.journal_sequence {
                journal_batch.extend_from_slice(record_bytes);
                journal_batch.push(b'\n');
            } else {
                append_journal_row(&mut journal_batch, &filler_journal_record(sequence));
            }
        }
        let mut journal = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(layout.journal_path())
            .unwrap();
        journal.write_all(&journal_batch).unwrap();
        journal.sync_all().unwrap();
    }

    fn two_generation_snapshot() -> (GenesisAnchor, LifecycleTrust, LifecycleSnapshot) {
        two_generation_snapshot_for("chain-a-g1", 0, "chain-a-g2", 1)
    }

    fn two_generation_snapshot_for(
        first_run_id: &str,
        first_offset: u8,
        second_run_id: &str,
        second_offset: u8,
    ) -> (GenesisAnchor, LifecycleTrust, LifecycleSnapshot) {
        let start = repeated('1');
        let genesis = GenesisAnchor::new(repeated('f'), start.clone(), "fixture-genesis");
        let genesis_root = genesis.root().unwrap();
        let initial_head = AuthorityHead::from_genesis(&genesis).unwrap();
        let (first, first_artifact, first_receipt, first_record) =
            lifecycle_fixture(first_run_id, first_offset, 9, &initial_head);
        let first_head = AuthorityHead::from_transition(&genesis, &first).unwrap();
        let (second, second_artifact, second_receipt, second_record) =
            lifecycle_fixture(second_run_id, second_offset, 18, &first_head);
        let head = AuthorityHead::from_transition(&genesis, &second).unwrap();

        let mut journal = Vec::new();
        for sequence in 1..=18 {
            match sequence {
                9 => append_journal_row(
                    &mut journal,
                    &serde_json::from_slice(&first_record).unwrap(),
                ),
                18 => append_journal_row(
                    &mut journal,
                    &serde_json::from_slice(&second_record).unwrap(),
                ),
                _ => append_journal_row(&mut journal, &filler_journal_record(sequence)),
            }
        }
        let mut artifacts = BTreeMap::new();
        artifacts.insert(first.artifact_digest.value.clone(), first_artifact);
        artifacts.insert(second.artifact_digest.value.clone(), second_artifact);
        let mut receipts = BTreeMap::new();
        receipts.insert(first.receipt_digest.value.clone(), first_receipt);
        receipts.insert(second.receipt_digest.value.clone(), second_receipt);
        let mut retained_world_roots = BTreeMap::new();
        retained_world_roots.insert(
            first.generation_identity.generation_id().to_owned(),
            first.parent_world_root.clone(),
        );
        retained_world_roots.insert(
            second.generation_identity.generation_id().to_owned(),
            second.parent_world_root.clone(),
        );
        let trust = LifecycleTrust {
            genesis_root: genesis_root.clone(),
            previously_trusted_head_root: genesis_root,
        };
        (
            genesis,
            trust,
            LifecycleSnapshot {
                head,
                transitions: vec![first, second.clone()],
                artifacts,
                receipts,
                journal,
                live_world_root: second.world_root,
                retained_world_roots,
            },
        )
    }

    #[test]
    fn checked_execution_builds_sealed_non_authorizing_artifact() {
        let mut bundle = sealed_artifact("run-a", 0);
        let identity = bundle.semantic_identity().unwrap();
        assert_eq!(bundle.run.lifecycle, Lifecycle::Sealed);
        assert_eq!(bundle.run.run.run_id, "run-a");
        assert_eq!(
            bundle.run.final_state.as_ref().unwrap().digest.value,
            repeated('2')
        );
        assert_eq!(
            bundle.envelope.verification[0].decision,
            VerificationDecision::Accept
        );
        assert!(!bundle.is_authorizing());

        bundle.envelope.publication.reference = Some("envelope-only-change".into());
        assert_eq!(bundle.semantic_identity().unwrap(), identity);
        bundle.envelope.publication.reference = None;
    }

    #[test]
    fn deserialized_accept_artifact_and_forged_publication_remain_non_authorizing() {
        let accepted = sealed_artifact("run-a", 0);
        let encoded = accepted.pack().unwrap();
        let reopened = ArtifactBundle::unpack(&encoded).unwrap();
        assert_eq!(
            reopened.envelope.verification[0].decision,
            VerificationDecision::Accept
        );
        assert!(!reopened.is_authorizing());

        let mut forged = reopened;
        forged.envelope.publication.status = PublicationStatus::Published;
        forged.envelope.publication.reference = Some("forged-publication".into());
        assert!(!forged.is_authorizing());
        assert!(forged.pack().is_err());
    }

    #[test]
    fn report_and_evidence_cross_run_substitution_refuse() {
        let (result_a, _) = execution_fixture("run-a", 0);
        let (_, evidence_b) = execution_fixture("run-b", 1);
        assert!(bundle_from_checked_data(&result_a, &evidence_b).is_err());

        let mut bundle = sealed_artifact("run-a", 0);
        bundle.run.run.run_id = "run-b".into();
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn verifier_accept_cannot_be_substituted_in_the_outer_envelope() {
        let mut bundle = sealed_artifact("run-a", 0);
        bundle.envelope.verification[0].decision = VerificationDecision::Reject;
        assert!(bundle.validate().is_err());
        assert!(!bundle.is_authorizing());
    }

    #[test]
    fn verifier_result_from_another_execution_cannot_bind_this_semantic_run() {
        let mut run_b = sealed_artifact("same-run", 1);
        let run_a = sealed_artifact("same-run", 0);
        run_b.envelope.verification = run_a.envelope.verification;
        assert!(run_b.validate().is_err());
    }

    #[test]
    fn resealed_semantic_claim_mutation_still_fails_checked_projection() {
        let mut bundle = sealed_artifact("run-a", 0);
        bundle
            .run
            .claims
            .iter_mut()
            .find(|claim| claim.id == "v6-starting-world")
            .unwrap()
            .statement = hash("realm.world", repeated('f').as_bytes());
        reseal_without_validation(&mut bundle);
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn attestation_from_another_semantic_run_is_rejected() {
        let mut run_a = sealed_artifact("run-a", 0);
        let root_a = run_a.semantic_identity().unwrap();
        let signature = run_a.add_blob(vec![1, 2, 3], "application/octet-stream");
        let attestation_a = crate::Attestation {
            id: "attestation-a".into(),
            kind: "test-signature".into(),
            signer: "test-key".into(),
            signed_root: root_a,
            signature,
            run_id: "run-a".into(),
            key_hint: Some("test-key".into()),
        };

        let mut run_b = sealed_artifact("run-b", 1);
        run_b.blobs.extend(run_a.blobs);
        run_b.envelope.attestations.push(attestation_a);
        assert!(run_b.validate().is_err());
    }

    #[test]
    fn generation_receipt_is_bound_to_exact_semantic_execution() {
        let mut bundle = sealed_artifact("run-a", 0);
        let (_, evidence_b) = execution_fixture("run-b", 1);
        let (receipt_b, record_b) = fake_published_records(&evidence_b);
        assert!(bind_generation_publication(&mut bundle, &receipt_b, &record_b).is_err());

        let evidence_a = execution_fixture("run-a", 0).1;
        let (receipt_a, record_a) = fake_published_records(&evidence_a);
        let semantic_identity = bundle.semantic_identity().unwrap();
        bind_generation_publication(&mut bundle, &receipt_a, &record_a).unwrap();
        assert_eq!(bundle.semantic_identity().unwrap(), semantic_identity);
        assert_eq!(
            bundle
                .envelope
                .publication
                .generation
                .as_ref()
                .unwrap()
                .journal_state,
            PublicationState::Published
        );
        assert!(
            bundle
                .validate_at(crate::ValidationLevel::AttestationShape)
                .is_ok()
        );

        let mut substituted = bundle.clone();
        substituted
            .envelope
            .publication
            .generation
            .as_mut()
            .unwrap()
            .previous_generation_root = repeated('e');
        assert!(substituted.validate().is_err());

        let mut substituted = bundle.clone();
        substituted
            .envelope
            .publication
            .generation
            .as_mut()
            .unwrap()
            .semantic_run_root
            .value = repeated('e');
        assert!(substituted.validate().is_err());

        let run_b = sealed_artifact("run-b", 1);
        let mut copied_envelope = run_b;
        copied_envelope.blobs.extend(bundle.blobs.clone());
        copied_envelope.envelope.publication = bundle.envelope.publication.clone();
        assert!(copied_envelope.validate().is_err());
    }

    #[test]
    fn mixed_start_final_and_delta_roots_cannot_form_a_generation() {
        let semantic_a = sealed_artifact("run-a", 0);
        let evidence_a = execution_fixture("run-a", 0).1;
        let evidence_b = execution_fixture("run-b", 1).1;

        for (start, final_root, delta) in [
            (
                evidence_a.accepted_start_root.as_str(),
                evidence_b.accepted_final_root.as_str(),
                evidence_a.accepted_delta_root.as_str(),
            ),
            (
                evidence_b.accepted_start_root.as_str(),
                evidence_a.accepted_final_root.as_str(),
                evidence_a.accepted_delta_root.as_str(),
            ),
            (
                evidence_a.accepted_start_root.as_str(),
                evidence_a.accepted_final_root.as_str(),
                evidence_b.accepted_delta_root.as_str(),
            ),
        ] {
            let identity =
                fake_generation_identity_with_roots(&evidence_a, start, final_root, delta);
            let (receipt, record) = fake_published_records_for_identity(identity);
            assert!(
                bind_generation_publication(&mut semantic_a.clone(), &receipt, &record).is_err()
            );
        }
    }

    #[test]
    fn journal_sequence_and_receipt_digest_must_match() {
        let mut bundle = sealed_artifact("run-a", 0);
        let evidence = execution_fixture("run-a", 0).1;
        let (receipt, record) = fake_published_records(&evidence);
        bind_generation_publication(&mut bundle, &receipt, &record).unwrap();
        bundle
            .envelope
            .publication
            .generation
            .as_mut()
            .unwrap()
            .commit_sequence += 1;
        assert!(bundle.validate().is_err());

        let mut bundle = sealed_artifact("run-a", 0);
        let (_, mut record) = fake_published_records(&evidence);
        record.receipt_digest = Some(repeated('d'));
        assert!(bind_generation_publication(&mut bundle, &receipt, &record).is_err());
    }

    #[test]
    fn lifecycle_verifier_reconstructs_a_synthetic_two_generation_chain() {
        let (genesis, trust, snapshot) = two_generation_snapshot();
        let result = verify_chain(&trust, &genesis, &snapshot);
        assert_eq!(
            result.state,
            VerificationState::Valid,
            "{}",
            result.diagnostic
        );
        assert_eq!(result.verified_transitions, 2);
        assert_eq!(
            result.reconstructed_head_root.as_deref(),
            Some(snapshot.head.authority_root.as_str())
        );
    }

    #[test]
    fn lifecycle_verifier_rejects_one_execution_id_with_two_semantic_roots() {
        let (genesis, trust, snapshot) =
            two_generation_snapshot_for("duplicate-execution-a", 0, "duplicate-execution-b", 0);
        assert_eq!(
            snapshot.transitions[0].generation_identity.execution_id(),
            snapshot.transitions[1].generation_identity.execution_id()
        );
        assert_ne!(
            snapshot.transitions[0].semantic_run_root,
            snapshot.transitions[1].semantic_run_root
        );
        assert_eq!(
            verify_chain(&trust, &genesis, &snapshot).state,
            VerificationState::MixedGeneration
        );
    }

    #[test]
    fn lifecycle_directory_reconstructs_filesystem_backed_synthetic_g0_g1_g2() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let parent = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "realm-lifecycle-filesystem-chain-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();

        let live = parent.join("workspace");
        let staged_g1 = parent.join("stage-g1");
        let staged_g2 = parent.join("stage-g2");
        create_fixture_world(&live, b"G0\n");
        create_fixture_world(&staged_g1, b"G1\n");
        create_fixture_world(&staged_g2, b"G2\n");
        let g0 = filesystem_world::scan_directory(&live).unwrap();
        let g1 = filesystem_world::scan_directory(&staged_g1).unwrap();
        let g2 = filesystem_world::scan_directory(&staged_g2).unwrap();
        let layout = GenerationLayout::inspect(&live).unwrap();
        let genesis = GenesisAnchor::new(
            layout.workspace_identity(),
            g0.root.clone(),
            "synthetic-filesystem-chain-g0",
        );
        let genesis_root = genesis.root().unwrap();
        let head0 =
            crate::lifecycle::initialize_lifecycle(&layout, &genesis, &genesis_root).unwrap();
        fs::create_dir(layout.receipt_directory()).unwrap();
        fs::set_permissions(
            layout.receipt_directory(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        let (transition1, artifact1, receipt1, record1) = file_backed_lifecycle_package(
            "filesystem-chain-g1",
            0,
            &layout,
            &head0,
            &g0.root,
            &g1.root,
            9,
        );
        let retained_g0 = layout
            .generation_path(&transition1.generation_identity)
            .unwrap();
        create_fixture_world(&retained_g0, b"G0\n");
        persist_file_backed_lifecycle_package(
            &layout,
            &transition1,
            &artifact1,
            &receipt1,
            &record1,
            1,
        );
        fs::write(live.join("state.txt"), b"G1\n").unwrap();
        let trust0 = LifecycleTrust {
            genesis_root: genesis_root.clone(),
            previously_trusted_head_root: head0.authority_root.clone(),
        };
        let head1 = crate::lifecycle::recover_lifecycle_head(&layout, &trust0).unwrap();
        assert_eq!(head1.sequence, 1);

        let (transition2, artifact2, receipt2, record2) = file_backed_lifecycle_package(
            "filesystem-chain-g2",
            1,
            &layout,
            &head1,
            &g1.root,
            &g2.root,
            18,
        );
        let retained_g1 = layout
            .generation_path(&transition2.generation_identity)
            .unwrap();
        create_fixture_world(&retained_g1, b"G1\n");
        persist_file_backed_lifecycle_package(
            &layout,
            &transition2,
            &artifact2,
            &receipt2,
            &record2,
            10,
        );
        fs::write(live.join("state.txt"), b"G2\n").unwrap();
        let trust1 = LifecycleTrust {
            genesis_root: genesis_root.clone(),
            previously_trusted_head_root: head1.authority_root.clone(),
        };
        let head2 = crate::lifecycle::recover_lifecycle_head(&layout, &trust1).unwrap();
        assert_eq!(head2.sequence, 2);

        let trust2 = LifecycleTrust {
            genesis_root,
            previously_trusted_head_root: head2.authority_root.clone(),
        };
        assert_eq!(
            crate::lifecycle::recover_lifecycle_head(&layout, &trust2).unwrap(),
            head2
        );
        assert_eq!(
            crate::lifecycle::recover_lifecycle_head(&layout, &trust2).unwrap(),
            head2
        );
        let result = crate::lifecycle::verify_lifecycle_directory(&layout, &trust2);
        assert_eq!(
            result.state,
            VerificationState::Valid,
            "{}",
            result.diagnostic
        );
        assert_eq!(result.verified_transitions, 2);
        assert_eq!(
            result.reconstructed_head_root.as_deref(),
            Some(head2.authority_root.as_str())
        );

        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn external_head_pin_detects_whole_store_rollback_that_genesis_cannot() {
        let (genesis, genesis_only_trust, complete) = two_generation_snapshot();
        let externally_trusted_g2 = complete.head.authority_root.clone();

        // Simulate restoring the entire durable store to its internally valid G1
        // snapshot after G2 had already been trusted elsewhere.
        let mut rolled_back = complete.clone();
        let second = rolled_back.transitions[1].clone();
        rolled_back.transitions.truncate(1);
        rolled_back.artifacts.remove(&second.artifact_digest.value);
        rolled_back.receipts.remove(&second.receipt_digest.value);
        rolled_back.head =
            AuthorityHead::from_transition(&genesis, rolled_back.transitions.first().unwrap())
                .unwrap();
        rolled_back.live_world_root = rolled_back.transitions[0].world_root.clone();
        rolled_back
            .retained_world_roots
            .remove(second.generation_identity.generation_id());
        rolled_back.journal = rolled_back
            .journal
            .split_inclusive(|byte| *byte == b'\n')
            .take(rolled_back.transitions[0].journal_sequence as usize)
            .flatten()
            .copied()
            .collect();

        // Genesis-only verification can establish internal consistency, but it
        // has no information that G2 ever existed.
        assert_eq!(
            verify_chain(&genesis_only_trust, &genesis, &rolled_back).state,
            VerificationState::Valid
        );

        // A separately retained G2 pin makes the same restored G1 store stale.
        let newer_external_pin = LifecycleTrust {
            genesis_root: genesis_only_trust.genesis_root.clone(),
            previously_trusted_head_root: externally_trusted_g2,
        };
        assert_eq!(
            verify_chain(&newer_external_pin, &genesis, &rolled_back).state,
            VerificationState::Rollback
        );
    }

    #[test]
    fn lifecycle_verifier_refuses_fork_rollback_and_truncated_history() {
        let (genesis, trust, valid) = two_generation_snapshot();

        let mut fork = valid.clone();
        let genesis_head = AuthorityHead::from_genesis(&genesis).unwrap();
        let (competing, artifact, receipt, record) =
            lifecycle_fixture("fork-child", 0, 19, &genesis_head);
        fork.transitions.push(competing);
        let competing = fork.transitions.last().unwrap();
        fork.artifacts
            .insert(competing.artifact_digest.value.clone(), artifact);
        fork.receipts
            .insert(competing.receipt_digest.value.clone(), receipt);
        fork.retained_world_roots.insert(
            competing.generation_identity.generation_id().into(),
            competing.parent_world_root.clone(),
        );
        append_journal_row(&mut fork.journal, &serde_json::from_slice(&record).unwrap());
        assert_eq!(
            verify_chain(&trust, &genesis, &fork).state,
            VerificationState::Fork
        );

        let mut rollback = valid.clone();
        let first = &rollback.transitions[0];
        rollback.head = AuthorityHead::from_transition(&genesis, first).unwrap();
        assert_eq!(
            verify_chain(&trust, &genesis, &rollback).state,
            VerificationState::Rollback
        );

        let mut replayed = valid.clone();
        replayed.transitions.push(replayed.transitions[0].clone());
        assert_eq!(
            verify_chain(&trust, &genesis, &replayed).state,
            VerificationState::Fork
        );

        let mut missing_child = valid.clone();
        missing_child.transitions.pop();
        assert_eq!(
            verify_chain(&trust, &genesis, &missing_child).state,
            VerificationState::Incomplete
        );

        let mut wrong_parent = valid.clone();
        wrong_parent.transitions[1].parent_authority_root = repeated('0');
        assert_eq!(
            verify_chain(&trust, &genesis, &wrong_parent).state,
            VerificationState::MixedGeneration
        );

        let mut unsupported = valid.clone();
        unsupported.transitions[0].schema_version += 1;
        assert_eq!(
            verify_chain(&trust, &genesis, &unsupported).state,
            VerificationState::Unknown
        );

        let mut unknown_genesis = trust.clone();
        unknown_genesis.genesis_root = repeated('0');
        assert_eq!(
            verify_chain(&unknown_genesis, &genesis, &valid).state,
            VerificationState::Unknown
        );

        let mut truncated = valid;
        truncated.transitions.remove(0);
        assert_eq!(
            verify_chain(&trust, &genesis, &truncated).state,
            VerificationState::Incomplete
        );
    }

    #[test]
    fn lifecycle_verifier_refuses_mixed_artifact_journal_and_world_composition() {
        let (genesis, trust, valid) = two_generation_snapshot();

        let mut foreign = valid.clone();
        let (foreign_transition, foreign_artifact, foreign_receipt, _) = {
            let parent = AuthorityHead::from_transition(&genesis, &valid.transitions[0]).unwrap();
            lifecycle_fixture("foreign-chain", 1, 18, &parent)
        };
        foreign.artifacts.insert(
            foreign_transition.artifact_digest.value.clone(),
            foreign_artifact,
        );
        foreign.receipts.insert(
            foreign_transition.receipt_digest.value.clone(),
            foreign_receipt,
        );
        foreign.transitions[1].artifact_digest = foreign_transition.artifact_digest;
        foreign.head = AuthorityHead::from_transition(&genesis, &foreign.transitions[1]).unwrap();
        assert_eq!(
            verify_chain(&trust, &genesis, &foreign).state,
            VerificationState::MixedGeneration
        );

        let mut wrong_live = valid.clone();
        wrong_live.live_world_root = repeated('4');
        assert_eq!(
            verify_chain(&trust, &genesis, &wrong_live).state,
            VerificationState::MixedGeneration
        );

        let mut wrong_previous = valid.clone();
        wrong_previous.retained_world_roots.insert(
            wrong_previous.transitions[1]
                .generation_identity
                .generation_id()
                .to_owned(),
            repeated('5'),
        );
        assert_eq!(
            verify_chain(&trust, &genesis, &wrong_previous).state,
            VerificationState::MixedGeneration
        );

        let mut copied_receipt = valid.clone();
        copied_receipt.receipts.insert(
            copied_receipt.transitions[1].receipt_digest.value.clone(),
            copied_receipt
                .receipts
                .get(&copied_receipt.transitions[0].receipt_digest.value)
                .unwrap()
                .clone(),
        );
        assert_eq!(
            verify_chain(&trust, &genesis, &copied_receipt).state,
            VerificationState::MixedGeneration
        );

        let mut foreign_journal = valid.clone();
        let parent = AuthorityHead::from_transition(&genesis, &valid.transitions[0]).unwrap();
        let (_, _, _, foreign_record) = lifecycle_fixture("copied-suffix", 1, 18, &parent);
        let mut lines = foreign_journal
            .journal
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        lines[17] = foreign_record;
        foreign_journal.journal = Vec::new();
        for line in lines {
            foreign_journal.journal.extend(line);
            foreign_journal.journal.push(b'\n');
        }
        assert_eq!(
            verify_chain(&trust, &genesis, &foreign_journal).state,
            VerificationState::Incomplete
        );

        let second_artifact_digest = valid.transitions[1].artifact_digest.value.clone();
        let mut changed_envelope = valid.clone();
        let mut second_bundle = ArtifactBundle::unpack(
            changed_envelope
                .artifacts
                .get(&second_artifact_digest)
                .unwrap(),
        )
        .unwrap();
        let original_semantic_root = second_bundle.semantic_identity().unwrap();
        second_bundle.envelope.content = crate::ContentMode::Thin;
        assert_eq!(
            second_bundle.semantic_identity().unwrap(),
            original_semantic_root
        );
        changed_envelope
            .artifacts
            .insert(second_artifact_digest, second_bundle.pack().unwrap());
        assert_eq!(
            verify_chain(&trust, &genesis, &changed_envelope).state,
            VerificationState::Invalid
        );
    }

    #[test]
    fn lifecycle_hostile_cross_generation_composition_corpus_rejects_all_mixes() {
        let (genesis, trust, chain_a) =
            two_generation_snapshot_for("corpus-a-g1", 0, "corpus-a-g2", 1);
        let (_, _, chain_b) = two_generation_snapshot_for("corpus-b-g1", 2, "corpus-b-g2", 3);
        assert_eq!(
            verify_chain(&trust, &genesis, &chain_a).state,
            VerificationState::Valid
        );
        assert_eq!(
            verify_chain(&trust, &genesis, &chain_b).state,
            VerificationState::Valid
        );

        let source = |select_b: bool| if select_b { &chain_b } else { &chain_a };
        let journal_row = |snapshot: &LifecycleSnapshot, sequence: u64| {
            snapshot
                .journal
                .split(|byte| *byte == b'\n')
                .find(|line| {
                    !line.is_empty()
                        && serde_json::from_slice::<PublicationRecord>(line)
                            .is_ok_and(|record| record.sequence == sequence)
                })
                .expect("fixture journal row exists")
                .to_vec()
        };
        let mut invalid_states = BTreeMap::<String, usize>::new();
        let mut false_accepts = Vec::new();

        // Ten independently selected components create 1,024 durable
        // compositions from two valid, same-genesis histories. The two
        // homogeneous packages are controls; every other package mixes at
        // least one transition, artifact, receipt, journal, head, or live
        // root from the competing history.
        for mask in 1_u16..1023 {
            let mut transitions = Vec::with_capacity(2);
            let mut artifacts = BTreeMap::new();
            let mut receipts = BTreeMap::new();
            let mut retained_world_roots = BTreeMap::new();

            for index in 0..2 {
                let transition_source = source(mask & (1 << index) != 0);
                let transition = transition_source.transitions[index].clone();
                let artifact_source = source(mask & (1 << (2 + index)) != 0);
                let artifact_digest = &transition_source.transitions[index].artifact_digest.value;
                let candidate_artifact_digest =
                    &artifact_source.transitions[index].artifact_digest.value;
                artifacts.insert(
                    artifact_digest.clone(),
                    artifact_source.artifacts[candidate_artifact_digest].clone(),
                );

                let receipt_source = source(mask & (1 << (4 + index)) != 0);
                let receipt_digest = &transition_source.transitions[index].receipt_digest.value;
                let candidate_receipt_digest =
                    &receipt_source.transitions[index].receipt_digest.value;
                receipts.insert(
                    receipt_digest.clone(),
                    receipt_source.receipts[candidate_receipt_digest].clone(),
                );

                let generation_id = transition.generation_identity.generation_id();
                let retained = transition_source
                    .retained_world_roots
                    .get(generation_id)
                    .expect("fixture retained parent exists")
                    .clone();
                retained_world_roots.insert(generation_id.to_owned(), retained);
                transitions.push(transition);
            }

            let mut journal = Vec::new();
            for sequence in 1..=18 {
                let bytes = match sequence {
                    9 => journal_row(source(mask & (1 << 6) != 0), sequence),
                    18 => journal_row(source(mask & (1 << 7) != 0), sequence),
                    _ => serde_json::to_vec(&filler_journal_record(sequence)).unwrap(),
                };
                journal.extend(bytes);
                journal.push(b'\n');
            }

            let head_source = source(mask & (1 << 8) != 0);
            let live_source = source(mask & (1 << 9) != 0);
            let composition = LifecycleSnapshot {
                head: head_source.head.clone(),
                transitions,
                artifacts,
                receipts,
                journal,
                live_world_root: live_source.live_world_root.clone(),
                retained_world_roots,
            };
            let result = verify_chain(&trust, &genesis, &composition);
            if result.state == VerificationState::Valid {
                false_accepts.push((mask, result.diagnostic));
            } else {
                *invalid_states
                    .entry(format!("{:?}", result.state))
                    .or_default() += 1;
            }
        }

        assert!(false_accepts.is_empty(), "false accepts: {false_accepts:?}");
        let rejected: usize = invalid_states.values().sum();
        assert_eq!(rejected, 1022);
        println!(
            "hostile_compositions={rejected} false_accepts=0 typed_refusals={invalid_states:?}"
        );
    }

    #[test]
    fn lifecycle_durable_object_corruption_corpus_never_verifies() {
        let (genesis, trust, valid) = two_generation_snapshot();
        assert_eq!(
            verify_chain(&trust, &genesis, &valid).state,
            VerificationState::Valid
        );
        let mut cases = 0usize;

        for transition in &valid.transitions {
            let artifact_digest = transition.artifact_digest.value.clone();
            let artifact = valid.artifacts[&artifact_digest].clone();
            for offset in (0..artifact.len().min(96)).step_by(3) {
                let mut damaged = valid.clone();
                let mut bytes = artifact.clone();
                bytes[offset] ^= 1;
                damaged.artifacts.insert(artifact_digest.clone(), bytes);
                assert_ne!(
                    verify_chain(&trust, &genesis, &damaged).state,
                    VerificationState::Valid,
                    "artifact byte offset {offset} was accepted"
                );
                cases += 1;
            }

            let receipt_digest = transition.receipt_digest.value.clone();
            let receipt = valid.receipts[&receipt_digest].clone();
            for offset in (0..receipt.len().min(96)).step_by(3) {
                let mut damaged = valid.clone();
                let mut bytes = receipt.clone();
                bytes[offset] ^= 1;
                damaged.receipts.insert(receipt_digest.clone(), bytes);
                assert_ne!(
                    verify_chain(&trust, &genesis, &damaged).state,
                    VerificationState::Valid,
                    "receipt byte offset {offset} was accepted"
                );
                cases += 1;
            }
        }

        for sequence in [9_u64, 18] {
            let mut damaged = valid.clone();
            let start = damaged
                .journal
                .split(|byte| *byte == b'\n')
                .take_while(|line| {
                    !line.is_empty()
                        && !serde_json::from_slice::<PublicationRecord>(line)
                            .is_ok_and(|record| record.sequence == sequence)
                })
                .map(|line| line.len() + 1)
                .sum::<usize>();
            let end = damaged.journal[start..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|offset| start + offset)
                .expect("journal row is newline terminated");
            for offset in (start..end.min(start + 48)).step_by(4) {
                damaged = valid.clone();
                damaged.journal[offset] ^= 1;
                assert_ne!(
                    verify_chain(&trust, &genesis, &damaged).state,
                    VerificationState::Valid,
                    "journal byte offset {offset} was accepted"
                );
                cases += 1;
            }
        }

        for index in 0..valid.transitions.len() {
            for mutation in 0..8 {
                let mut damaged = valid.clone();
                match mutation {
                    0 => damaged.transitions[index].domain.push_str("-changed"),
                    1 => damaged.transitions[index].schema_version += 1,
                    2 => damaged.transitions[index].parent_authority_root = repeated('a'),
                    3 => damaged.transitions[index].parent_generation_root = repeated('b'),
                    4 => damaged.transitions[index].parent_world_root = repeated('c'),
                    5 => damaged.transitions[index].semantic_run_root.value = repeated('d'),
                    6 => damaged.transitions[index].delta_root = repeated('e'),
                    _ => damaged.transitions[index].journal_sequence += 1,
                }
                assert_ne!(
                    verify_chain(&trust, &genesis, &damaged).state,
                    VerificationState::Valid,
                    "transition {index} mutation {mutation} was accepted"
                );
                cases += 1;
            }
        }

        assert!(cases >= 100);
        println!("durable_object_corruptions={cases} false_accepts=0");
    }

    #[test]
    fn lifecycle_verifier_classifies_each_modeled_persistence_cut() {
        let (genesis, trust, complete) = two_generation_snapshot();
        let first = &complete.transitions[0];
        let second = &complete.transitions[1];
        let parent_head = AuthorityHead::from_transition(&genesis, first).unwrap();

        let mut parent_state = complete.clone();
        parent_state.transitions.truncate(1);
        parent_state.artifacts.remove(&second.artifact_digest.value);
        parent_state.receipts.remove(&second.receipt_digest.value);
        parent_state
            .retained_world_roots
            .remove(second.generation_identity.generation_id());
        parent_state.head = parent_head.clone();
        parent_state.live_world_root = first.world_root.clone();
        parent_state.journal.truncate(
            parent_state
                .journal
                .split(|byte| *byte == b'\n')
                .take(first.journal_sequence as usize)
                .map(|line| line.len() + 1)
                .sum(),
        );
        assert_eq!(
            verify_chain(&trust, &genesis, &parent_state).state,
            VerificationState::Valid
        );

        // Generation publication has committed S1 and its PUBLISHED row, but
        // lifecycle content-addressed material has not yet been recorded.
        let mut published_without_lifecycle = parent_state.clone();
        published_without_lifecycle.live_world_root = second.world_root.clone();
        published_without_lifecycle.journal = complete.journal.clone();
        assert_eq!(
            verify_chain(&trust, &genesis, &published_without_lifecycle).state,
            VerificationState::MixedGeneration
        );

        // The .realm artifact and receipt are durable, but no immutable edge
        // exists yet; the PUBLISHED label alone still cannot advance the head.
        let mut artifact_durable = published_without_lifecycle.clone();
        artifact_durable.artifacts.insert(
            second.artifact_digest.value.clone(),
            complete.artifacts[&second.artifact_digest.value].clone(),
        );
        artifact_durable.receipts.insert(
            second.receipt_digest.value.clone(),
            complete.receipts[&second.receipt_digest.value].clone(),
        );
        artifact_durable.retained_world_roots.insert(
            second.generation_identity.generation_id().into(),
            second.parent_world_root.clone(),
        );
        assert_eq!(
            verify_chain(&trust, &genesis, &artifact_durable).state,
            VerificationState::MixedGeneration
        );

        // The transition file is durable, but HEAD still names its parent.
        // Recovery can validate and finish that single edge; read-only verify
        // reports rollback/incomplete instead of treating it as published.
        let mut transition_durable = complete.clone();
        transition_durable.head = parent_head;
        assert_eq!(
            verify_chain(&trust, &genesis, &transition_durable).state,
            VerificationState::Rollback
        );

        // Atomic HEAD rename plus its containing-directory sync is the final
        // lifecycle barrier. Once present, the complete child reconstructs.
        assert_eq!(
            verify_chain(&trust, &genesis, &complete).state,
            VerificationState::Valid
        );

        let mut missing_artifact = complete.clone();
        missing_artifact
            .artifacts
            .remove(&second.artifact_digest.value);
        assert_eq!(
            verify_chain(&trust, &genesis, &missing_artifact).state,
            VerificationState::Incomplete
        );
    }

    #[test]
    fn lifecycle_verifier_rejects_reordered_or_duplicated_journal_rows() {
        let (genesis, trust, valid) = two_generation_snapshot();

        let mut reordered = valid.clone();
        let mut lines = reordered
            .journal
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        lines.swap(0, 1);
        reordered.journal = lines
            .into_iter()
            .flat_map(|line| [line, vec![b'\n']].concat())
            .collect();
        assert_eq!(
            verify_chain(&trust, &genesis, &reordered).state,
            VerificationState::Invalid
        );

        let mut duplicate = valid.clone();
        let mut lines = duplicate
            .journal
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let mut duplicated_record: PublicationRecord = serde_json::from_slice(&lines[0]).unwrap();
        duplicated_record.sequence = 2;
        lines[1] = serde_json::to_vec(&duplicated_record).unwrap();
        duplicate.journal = Vec::new();
        for line in lines {
            duplicate.journal.extend(line);
            duplicate.journal.push(b'\n');
        }
        assert_eq!(
            verify_chain(&trust, &genesis, &duplicate).state,
            VerificationState::Invalid
        );
    }
}
