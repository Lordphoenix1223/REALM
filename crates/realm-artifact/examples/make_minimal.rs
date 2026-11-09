use realm_artifact::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let d = |domain: &str, bytes: &[u8]| hash(domain, bytes);
    let mut b = ArtifactBundle::new(RealmRun {
        schema_version: SCHEMA_VERSION,
        lifecycle: Lifecycle::Frozen,
        run: RunIdentity {
            run_id: "example-run".into(),
            execution_id: "example-execution".into(),
        },
        challenge: Challenge {
            nonce: Some(d("realm.challenge", b"nonce")),
            issued_by: "fixture-issuer".into(),
            expires_at: None,
        },
        intent: Commitment {
            identity: "example-task".into(),
            digest: d("realm.intent", b"task"),
        },
        starting_state: Commitment {
            identity: "initial-world".into(),
            digest: d("realm.world", b"initial"),
        },
        environment: EnvironmentIdentity {
            runtime: "realm-v6".into(),
            runtime_digest: d("realm.runtime", b"runtime"),
            backend: "fixture".into(),
            architecture: "portable".into(),
        },
        effect_contract: Commitment {
            identity: "policy".into(),
            digest: d("realm.policy", b"policy"),
        },
        inputs: vec![],
        outputs: vec![],
        checkpoints: vec![Checkpoint {
            id: "checkpoint-a".into(),
            sequence: 1,
            parent: None,
            state: Commitment {
                identity: "checkpoint-world".into(),
                digest: d("realm.world", b"checkpoint"),
            },
            evidence: vec!["evidence-1".into()],
        }],
        observations: vec![ObservedEvent {
            id: "observation-1".into(),
            kind: "filesystem-observed".into(),
            target: "output/result.txt".into(),
            checkpoint: Some("checkpoint-a".into()),
            evidence: vec!["evidence-1".into()],
        }],
        proposed_effects: vec![ProposedEffect {
            id: "proposal-1".into(),
            kind: "create".into(),
            target: "output/result.txt".into(),
            before: None,
            after: Some(d("realm.blob", b"portable result\n")),
            checkpoint: Some("checkpoint-a".into()),
            evidence: vec!["evidence-1".into()],
        }],
        unknown_effects: vec![UnknownEffect {
            kind: "external-network".into(),
            target: None,
            reason: "no authoritative network oracle".into(),
        }],
        evidence: vec![EvidenceRef {
            id: "evidence-1".into(),
            evidence_type: "fixture-observer-log".into(),
            digest: d("realm.blob", b"observer log"),
            size: Some(b"observer log".len() as u64),
            run_id: "example-run".into(),
            checkpoint: Some("checkpoint-a".into()),
            supports: vec!["observation-1".into(), "proposal-1".into()],
            authoritative: false,
        }],
        claims: vec![Claim {
            id: "claim-1".into(),
            kind: ClaimKind::Agent,
            statement: d("realm.claim", b"transform"),
            run_id: "example-run".into(),
            checkpoint: Some("checkpoint-a".into()),
            evidence: vec!["evidence-1".into()],
        }],
        final_state: Some(Commitment {
            identity: "final-world".into(),
            digest: d("realm.world", b"final"),
        }),
        seal: None,
    });
    let evidence = b.add_blob(b"observer log".to_vec(), "application/x-ndjson");
    b.run.evidence[0].digest = evidence.digest;
    let input = b.add_blob(b"input payload\n".to_vec(), "text/plain");
    let output = b.add_blob(b"portable result\n".to_vec(), "text/plain");
    b.run.inputs.push(input);
    b.run.outputs.push(output);
    b.envelope.verification.push(VerificationRef {
        id: "verification-1".into(),
        verifier: "fixture-verifier".into(),
        result_digest: d("realm.verifier-result", b"unknown"),
        decision: VerificationDecision::Unknown,
        run_id: "example-run".into(),
        checkpoint: Some("checkpoint-a".into()),
        supports: vec!["proposal-1".into()],
    });
    b.write("crates/realm-artifact/examples/minimal.realm")?;
    Ok(())
}
