use realm_artifact::{
    ArtifactBundle, Attestation, ContentMode, ContentResolver, Lifecycle, ProposedEffect,
    ValidationLevel,
};

fn fixture(path: &str) -> ArtifactBundle {
    ArtifactBundle::open(path).unwrap()
}

#[test]
fn thin_present_bytes_are_authenticated() {
    let mut a = fixture("examples/minimal.realm");
    a.envelope.content = ContentMode::Thin;
    let key = a.blobs.keys().next().unwrap().clone();
    a.blobs.get_mut(&key).unwrap().reverse();
    assert!(a.validate_at(ValidationLevel::Integrity).is_err());
}

#[test]
fn evidence_references_must_resolve_and_authenticate() {
    let mut a = fixture("examples/minimal.realm");
    a.run.evidence[0].digest.value = "0".repeat(64);
    assert!(a.validate_at(ValidationLevel::Integrity).is_err());
}

#[test]
fn attestations_require_a_sealed_run() {
    let mut a = fixture("examples/minimal.realm");
    let root = a.semantic_identity().unwrap();
    let sig = a.add_blob(vec![1], "application/octet-stream");
    a.envelope.attestations.push(Attestation {
        id: "att".into(),
        kind: "opaque".into(),
        signer: "external".into(),
        signed_root: root,
        signature: sig,
        run_id: a.run.run.run_id.clone(),
        key_hint: None,
    });
    assert!(a.validate_at(ValidationLevel::AttestationShape).is_err());
}

#[test]
fn checkpoint_lineage_rejects_self_parent_and_cycles() {
    let mut a = fixture("examples/minimal.realm");
    a.run.checkpoints[0].parent = Some(a.run.checkpoints[0].id.clone());
    assert!(a.validate_at(ValidationLevel::Integrity).is_err());
}

#[test]
fn resealing_is_a_new_identity() {
    let mut a = fixture("examples/sealed.realm");
    let old = a.semantic_identity().unwrap();
    a.run.seal = None;
    a.run.lifecycle = Lifecycle::Frozen;
    a.run.intent.identity.push_str("-changed");
    a.seal().unwrap();
    assert_ne!(old, a.semantic_identity().unwrap());
}

#[test]
fn semantic_object_ids_are_unique_and_evidence_scope_matches() {
    let mut a = fixture("examples/minimal.realm");
    a.run.proposed_effects.push(ProposedEffect {
        id: a.run.observations[0].id.clone(),
        kind: "write".into(),
        target: "/other".into(),
        before: None,
        after: None,
        checkpoint: None,
        evidence: vec![],
    });
    assert!(a.validate_at(ValidationLevel::Integrity).is_err());
}

#[test]
fn object_evidence_lists_cannot_cross_checkpoint_scope() {
    let mut a = fixture("examples/minimal.realm");
    let evidence = a.run.evidence[0].id.clone();
    let mut other = a.run.checkpoints[0].clone();
    other.id = "checkpoint-other".into();
    other.sequence = a.run.checkpoints[0].sequence + 1;
    other.parent = Some(a.run.checkpoints[0].id.clone());
    other.evidence.clear();
    a.run.checkpoints.push(other);
    a.run.claims.push(realm_artifact::Claim {
        id: "claim-cross-checkpoint".into(),
        kind: realm_artifact::ClaimKind::Observed,
        statement: realm_artifact::hash("realm.claim", b"cross-scope"),
        run_id: a.run.run.run_id.clone(),
        checkpoint: Some("checkpoint-other".into()),
        evidence: vec![evidence],
    });
    assert!(
        a.validate_at(ValidationLevel::Integrity).is_err(),
        "an object accepted evidence from a different checkpoint"
    );
}

#[test]
fn observation_and_effect_evidence_must_match_checkpoint_scope() {
    let mut a = fixture("examples/minimal.realm");
    let mut other = a.run.checkpoints[0].clone();
    other.id = "checkpoint-other".into();
    other.sequence += 1;
    other.parent = Some(a.run.checkpoints[0].id.clone());
    other.evidence.clear();
    a.run.checkpoints.push(other);

    a.run.observations[0].checkpoint = Some("checkpoint-other".into());
    assert!(a.validate_at(ValidationLevel::Integrity).is_err());

    let mut a = fixture("examples/minimal.realm");
    let mut other = a.run.checkpoints[0].clone();
    other.id = "checkpoint-other".into();
    other.sequence += 1;
    other.parent = Some(a.run.checkpoints[0].id.clone());
    other.evidence.clear();
    a.run.checkpoints.push(other);
    a.run.proposed_effects[0].checkpoint = Some("checkpoint-other".into());
    assert!(a.validate_at(ValidationLevel::Integrity).is_err());
}

struct WrongResolver;

impl ContentResolver for WrongResolver {
    fn resolve(
        &self,
        _digest: &realm_artifact::Digest,
    ) -> Result<Option<Vec<u8>>, realm_artifact::ArtifactError> {
        Ok(Some(b"wrong bytes".to_vec()))
    }
}

#[test]
fn resolver_bytes_are_authenticated_before_completeness() {
    let mut a = fixture("examples/minimal.realm");
    a.envelope.content = ContentMode::Thin;
    a.blobs.clear();
    assert!(
        a.validate_with_resolver(ValidationLevel::ContentComplete, Some(&WrongResolver))
            .is_err()
    );
}

#[test]
fn sealed_run_snapshot_is_not_affected_by_bundle_mutation() {
    let mut a = fixture("examples/sealed.realm");
    let snapshot = a.sealed_run().unwrap();
    let original = snapshot.identity().clone();
    a.run.intent.identity.push_str("-mutated");
    a.run.seal = None;
    a.run.lifecycle = Lifecycle::Frozen;
    assert_eq!(original, *snapshot.identity());
    assert!(a.seal().is_ok());
    assert_ne!(original, a.semantic_identity().unwrap());
}
