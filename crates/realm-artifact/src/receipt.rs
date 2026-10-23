//! Lossless raw-receipt adapter. Receipt events become observations and
//! proposed effects; no net delta or verifier authority is inferred.

use crate::*;
use realm_v6::{Disposition, EffectKind, Receipt, validate_receipt};

#[derive(Clone, Debug)]
pub struct ValidatedReceipt(Receipt);

impl TryFrom<Receipt> for ValidatedReceipt {
    type Error = ArtifactError;

    fn try_from(receipt: Receipt) -> Result<Self, Self::Error> {
        validate_receipt(&receipt)
            .map_err(|e| ArtifactError::Invalid(format!("receipt validation failed: {e:?}")))?;
        Ok(Self(receipt))
    }
}

impl ValidatedReceipt {
    pub fn as_receipt(&self) -> &Receipt {
        &self.0
    }
}

pub fn from_receipt(receipt: &Receipt, raw: &[u8]) -> Result<ArtifactBundle, ArtifactError> {
    let validated = ValidatedReceipt::try_from(receipt.clone())?;
    from_unvalidated_receipt(validated.as_receipt(), raw)
}

pub fn from_validated_receipt(
    receipt: &ValidatedReceipt,
    raw: &[u8],
    challenge: Challenge,
) -> Result<ArtifactBundle, ArtifactError> {
    let mut bundle = from_unvalidated_receipt(&receipt.0, raw)?;
    bundle.run.challenge = challenge;
    Ok(bundle)
}

pub fn from_unvalidated_receipt(
    receipt: &Receipt,
    raw: &[u8],
) -> Result<ArtifactBundle, ArtifactError> {
    let h = |domain: &str, bytes: &[u8]| Digest {
        algorithm: "blake3".into(),
        domain: domain.into(),
        value: blake3::hash(&[domain.as_bytes(), &[0], bytes].concat())
            .to_hex()
            .to_string(),
    };
    let mut b = ArtifactBundle::new(RealmRun {
        schema_version: SCHEMA_VERSION,
        lifecycle: Lifecycle::Frozen,
        challenge: Challenge {
            nonce: None,
            issued_by: "v6-adapter".into(),
            expires_at: None,
        },
        run: RunIdentity {
            run_id: receipt.execution_id.clone(),
            execution_id: receipt.execution_id.clone(),
        },
        intent: Commitment {
            identity: receipt.bindings.task_version.clone(),
            digest: h("realm.intent", receipt.bindings.task_version.as_bytes()),
        },
        starting_state: Commitment {
            identity: "v6.starting-world".into(),
            digest: Digest {
                algorithm: "blake3".into(),
                domain: "realm.world".into(),
                value: receipt.bindings.starting_state.clone(),
            },
        },
        environment: EnvironmentIdentity {
            runtime: "realm-v6".into(),
            runtime_digest: Digest {
                algorithm: "blake3".into(),
                domain: "realm.runtime".into(),
                value: receipt.bindings.executable_sha256.clone(),
            },
            backend: receipt.bindings.environment.clone(),
            architecture: "receipt-bound".into(),
        },
        effect_contract: Commitment {
            identity: "v6.effect-contract".into(),
            digest: Digest {
                algorithm: "blake3".into(),
                domain: "realm.policy".into(),
                value: receipt.bindings.capsule_policy.clone(),
            },
        },
        inputs: vec![],
        outputs: vec![],
        checkpoints: vec![],
        observations: vec![],
        proposed_effects: vec![],
        unknown_effects: vec![],
        evidence: vec![],
        claims: vec![],
        final_state: Some(Commitment {
            identity: "v6.final-world".into(),
            digest: Digest {
                algorithm: "blake3".into(),
                domain: "realm.world".into(),
                value: receipt.final_world_root.clone(),
            },
        }),
        seal: None,
    });
    let raw_ref = b.add_blob(raw.to_vec(), "application/json");
    b.run.inputs.push(raw_ref.clone());
    b.run.evidence.push(EvidenceRef {
        id: "v6-raw-receipt".into(),
        evidence_type: "v6-receipt".into(),
        digest: raw_ref.digest.clone(),
        size: Some(raw.len() as u64),
        run_id: receipt.execution_id.clone(),
        checkpoint: None,
        supports: vec![],
        authoritative: false,
    });
    let world_ref = b.add_blob(
        serde_json::to_vec(&receipt.final_world)?,
        "application/vnd.realm.world+json",
    );
    b.run.outputs.push(world_ref);
    let effect_root_bytes = serde_json::to_vec(&receipt.effect_root)?;
    let effect_root_ref = b.add_blob(
        effect_root_bytes.clone(),
        "application/vnd.realm.effect-root+json",
    );
    b.run.evidence.push(EvidenceRef {
        id: "v6-effect-root".into(),
        evidence_type: "v6-effect-root".into(),
        digest: effect_root_ref.digest,
        size: Some(effect_root_bytes.len() as u64),
        run_id: receipt.execution_id.clone(),
        checkpoint: None,
        supports: vec![],
        authoritative: false,
    });
    for (i, e) in receipt.ordered_effects.iter().enumerate() {
        if matches!(
            e.kind,
            EffectKind::ProcessStart | EffectKind::ProcessExit | EffectKind::Quiescence
        ) {
            continue;
        }
        let id = format!("event-{i}");
        let target = e.path.clone().unwrap_or_else(|| "<unknown>".into());
        b.run.observations.push(ObservedEvent {
            id: id.clone(),
            kind: format!("{:?}", e.kind),
            target: target.clone(),
            checkpoint: None,
            evidence: vec!["v6-raw-receipt".into()],
        });
        if e.disposition == Disposition::Committed {
            b.run.proposed_effects.push(ProposedEffect {
                id: format!("proposal-{i}"),
                kind: format!("{:?}", e.kind),
                target,
                before: None,
                after: e
                    .after
                    .as_ref()
                    .and_then(|x| x.content_blake3.as_ref())
                    .map(|v| Digest {
                        algorithm: "blake3".into(),
                        domain: "realm.blob".into(),
                        value: v.clone(),
                    }),
                checkpoint: None,
                evidence: vec![id],
            });
        } else {
            b.run.unknown_effects.push(UnknownEffect {
                kind: format!("{:?}", e.kind),
                target: Some(target),
                reason: "receipt event was not committed".into(),
            });
        }
    }
    for e in &mut b.run.evidence {
        if e.id == "v6-raw-receipt" {
            e.supports = b.run.observations.iter().map(|o| o.id.clone()).collect();
        }
    }
    b.envelope.verification.push(VerificationRef {
        id: "v6-verification".into(),
        verifier: receipt.bindings.verifier_identity.clone(),
        result_digest: h("realm.verifier-result", receipt.verifier_result.as_bytes()),
        decision: VerificationDecision::Unknown,
        run_id: receipt.execution_id.clone(),
        checkpoint: None,
        supports: vec![],
    });
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use realm_v6::{Bindings, Receipt};
    use std::collections::BTreeMap;
    #[test]
    fn raw_receipt_round_trips_as_unknown() {
        let h = |x: &[u8]| {
            blake3::hash(&[b"fixture".as_slice(), &[0], x].concat())
                .to_hex()
                .to_string()
        };
        let r = Receipt {
            format_version: 1,
            execution_id: "fixture".into(),
            bindings: Bindings {
                task_version: "task".into(),
                starting_state: h(b"s"),
                generation_identity: "g".into(),
                authority_lineage: "l".into(),
                capsule_policy: h(b"p"),
                executable_sha256: h(b"r"),
                toolchain_sha256: h(b"t"),
                guest_kernel_sha256: h(b"k"),
                vmm_sha256: h(b"v"),
                image_sha256: h(b"i"),
                environment: h(b"e"),
                argv: vec!["x".into()],
                cwd: "/".into(),
                uid: 1,
                limits: h(b"lim"),
                outcome_contract: h(b"c"),
                verifier_identity: "verifier".into(),
            },
            starting_world: BTreeMap::new(),
            ordered_effects: vec![],
            effect_root: h(b"er"),
            segments: vec![],
            segment_root: h(b"sr"),
            verifier_derived_dependencies: vec![],
            final_world: BTreeMap::new(),
            final_world_root: h(b"f"),
            outcome: "unknown".into(),
            verifier_result: "unknown".into(),
        };
        let raw = serde_json::to_vec(&r).unwrap();
        let b = from_unvalidated_receipt(&r, &raw).unwrap();
        let id = b.identity().unwrap();
        let o = ArtifactBundle::unpack(&b.pack().unwrap()).unwrap();
        assert_eq!(id, o.identity().unwrap());
        assert!(!o.is_authorizing());
        assert!(from_receipt(&r, &raw).is_err());
    }
}
