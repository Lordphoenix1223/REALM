//! Import caller-supplied file observations. This is never execution attestation.
use crate::*;

/// Package snapshots/log bytes supplied by an external harness, retaining UNKNOWN.
/// The caller may be dishonest. Hashes establish content identity, not provenance.
pub fn from_file_observation(
    run_id: &str,
    before: Vec<u8>,
    after: Vec<u8>,
    log: Vec<u8>,
) -> Result<ArtifactBundle, ArtifactError> {
    let commit = |identity: &str, domain: &str, bytes: &[u8]| Commitment {
        identity: identity.into(),
        digest: hash(domain, bytes),
    };
    let mut bundle = ArtifactBundle::new(RealmRun {
        schema_version: SCHEMA_VERSION, lifecycle: Lifecycle::Frozen,
        run: RunIdentity { run_id: run_id.into(), execution_id: format!("observation:{run_id}") },
        challenge: Challenge { nonce: None, issued_by: "external-observation-import".into(), expires_at: None },
        intent: commit("caller-supplied file observation", "realm.intent", b"observation-only"),
        starting_state: commit("supplied-before-bytes", "realm.world", &before),
        final_state: Some(commit("supplied-after-bytes", "realm.world", &after)),
        environment: EnvironmentIdentity {
            runtime: "external-observation-import".into(),
            runtime_digest: hash("realm.runtime", b"unqualified-observation-import-v1"),
            backend: "caller-supplied-files; no custody".into(),
            architecture: "unspecified".into(),
        },
        effect_contract: commit("no authorized effect contract", "realm.policy", b"authority=NONE"),
        inputs: vec![], outputs: vec![], checkpoints: vec![],
        observations: vec![ObservedEvent {
            id: "supplied-observation".into(), kind: "caller-supplied-file-snapshots".into(),
            target: "observed-file".into(), checkpoint: None, evidence: vec!["external-log".into()],
        }],
        proposed_effects: vec![],
        unknown_effects: vec![UnknownEffect {
            kind: "unmediated-execution".into(), target: None,
            reason: "caller-supplied snapshots and log do not establish process custody, complete observations, terminal closure, or authorization".into(),
        }],
        evidence: vec![], claims: vec![], seal: None,
    });
    let input = bundle.add_blob(before, "application/octet-stream");
    let output = bundle.add_blob(after, "application/octet-stream");
    let evidence = bundle.add_blob(log, "application/octet-stream");
    bundle.run.inputs.push(input);
    bundle.run.outputs.push(output);
    bundle.run.evidence.push(EvidenceRef {
        id: "external-log".into(),
        evidence_type: "caller-supplied-log".into(),
        digest: evidence.digest,
        size: Some(evidence.size),
        run_id: run_id.into(),
        checkpoint: None,
        supports: vec!["supplied-observation".into()],
        authoritative: false,
    });
    bundle.envelope.verification.push(VerificationRef {
        id: "observation-import".into(),
        verifier: "none".into(),
        result_digest: hash("realm.verifier-result", b"UNKNOWN"),
        decision: VerificationDecision::Unknown,
        run_id: run_id.into(),
        checkpoint: None,
        supports: vec!["supplied-observation".into()],
    });
    bundle.validate()?;
    Ok(bundle)
}
