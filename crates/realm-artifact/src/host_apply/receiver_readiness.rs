//! SYNTHETIC receiver relationship tests. No observed execution, policy ACCEPT,
//! coding authority or production publication is created by these fixtures.
use super::*;
use crate::lifecycle::VerificationState;
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

fn chain() -> (Vec<u8>, TransferProof) {
    let (genesis, _, snapshot) = crate::v6::tests::two_generation_snapshot();
    let head = snapshot.transitions.last().unwrap();
    let bytes = snapshot.artifacts[&head.artifact_digest.value].clone();
    (
        bytes,
        TransferProof {
            schema_version: 1,
            genesis,
            snapshot,
        },
    )
}
fn publication(bytes: &[u8], proof: &TransferProof) -> Result<ArtifactBundle> {
    pinned_publication(
        bytes,
        proof,
        &digest(bytes),
        &proof.genesis.root().unwrap(),
        &proof.snapshot.head.authority_root,
    )
}

#[test]
fn synthetic_chain_positive_is_only_pinned_continuity_not_coding_authority() {
    let (bytes, proof) = chain();
    let b = publication(&bytes, &proof).unwrap();
    assert!(!b.is_authorizing());
    assert_eq!(proof.snapshot.transitions.len(), 2);
    assert!(ordered_create::candidate::verify(&bytes).is_err());
    assert!(realm_v6::integration::coding::require_registered_coding_semantics().is_err());
}

#[test]
fn independently_supplied_pins_detect_substitution_and_whole_history_rollback() {
    let (bytes, proof) = chain();
    let a = digest(&bytes);
    let g = proof.genesis.root().unwrap();
    let h = &proof.snapshot.head.authority_root;
    for (label, artifact, genesis, head) in [
        ("missing artifact pin", "", g.as_str(), h.as_str()),
        ("missing genesis pin", a.as_str(), "", h.as_str()),
        ("missing exact head", a.as_str(), g.as_str(), ""),
        ("foreign artifact", &"0".repeat(64), g.as_str(), h.as_str()),
        ("foreign genesis", a.as_str(), &"0".repeat(64), h.as_str()),
        ("rollback to genesis", a.as_str(), g.as_str(), g.as_str()),
    ] {
        assert!(
            pinned_publication(&bytes, &proof, artifact, genesis, head).is_err(),
            "{label}"
        );
    }
    let mut tampered = bytes.clone();
    tampered[0] ^= 1;
    assert!(pinned_publication(&tampered, &proof, &a, &g, h).is_err());
}

#[test]
fn incomplete_and_cross_run_canonical_histories_cannot_reach_receiver_authority() {
    let (bytes, proof) = chain();
    let (_, _, foreign) = crate::v6::tests::two_generation_snapshot_for(
        "SYNTHETIC_FOREIGN_G1",
        2,
        "SYNTHETIC_FOREIGN_G2",
        3,
    );
    for kind in 0..7 {
        let mut bad = proof.clone();
        match kind {
            0 => bad.snapshot.artifacts.clear(),
            1 => bad.snapshot.receipts.clear(),
            2 => bad.snapshot.journal.clear(),
            3 => bad.snapshot.transitions.pop().map(|_| ()).unwrap(),
            4 => bad.snapshot.transitions[1].sequence = bad.snapshot.transitions[0].sequence,
            5 => bad.snapshot.receipts = foreign.receipts.clone(),
            _ => bad.snapshot.artifacts = foreign.artifacts.clone(),
        }
        let trust = LifecycleTrust {
            genesis_root: proof.genesis.root().unwrap(),
            previously_trusted_head_root: proof.snapshot.head.authority_root.clone(),
        };
        let result = lifecycle::verify_chain(&trust, &bad.genesis, &bad.snapshot);
        assert_ne!(result.state, VerificationState::Valid, "case {kind}");
        assert!(publication(&bytes, &bad).is_err(), "case {kind}");
    }
}

#[test]
fn synthetic_native_content_requires_identity_observation_policy_and_terminal_bindings() {
    use realm_v6::execute::{test_coding_evidence_content, validate_checked_c1_evidence};
    let (_, original) = test_coding_evidence_content();
    assert!(validate_checked_c1_evidence(&original)); // content ONLY, no owners
    for kind in 0..10 {
        let mut e = original.clone();
        match kind {
            0 => e.run_id = "0".repeat(64),
            1 => e.execution_id = "0".repeat(64),
            2 => e.challenge_binding = "0".repeat(64),
            3 => e.vmm_terminal_observation_root = None,
            4 => e.custody_process_identity = None,
            5 => e.observed_effects.clear(),
            6 => e
                .observed_effects
                .push("forbidden-intermediate-effect".into()),
            7 => e.unsupported_effects.push("unobserved-channel".into()),
            8 => e.finalization_evidence.clear(),
            _ => e.c1_manifest[0] ^= 1,
        }
        assert!(!validate_checked_c1_evidence(&e), "case {kind}");
    }
}

struct Inputs(PathBuf);
impl Inputs {
    fn new() -> Self {
        let p = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "realm-SYNTHETIC-receiver-inputs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
    fn binding(&self) -> (PathBuf, String, coding_lifecycle::CodingTransferBinding) {
        let (bytes, policy) = coding_transfer::tests::prospective();
        let (_, proof) = chain();
        let b = coding_lifecycle::CodingTransferBinding {
            schema_version: 1,
            artifact: self.0.join("SYNTHETIC.realm"),
            proof: self.0.join("proof.json"),
            policy: self.0.join("policy.json"),
            destination: self.0.join("never-opened-destination"),
            state: self.0.join("never-opened-state"),
            approval_id: "a".repeat(64),
        };
        std::fs::write(&b.artifact, bytes).unwrap();
        std::fs::write(&b.proof, serde_json::to_vec(&proof).unwrap()).unwrap();
        std::fs::write(&b.policy, serde_json::to_vec(&policy).unwrap()).unwrap();
        let path = self.0.join("operator-binding.json");
        let raw = serde_json::to_vec(&b).unwrap();
        std::fs::write(&path, &raw).unwrap();
        (path, digest(&raw), b)
    }
}
impl Drop for Inputs {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn independent_binding_pin_is_required_and_loading_claims_grants_no_authority() {
    let f = Inputs::new();
    let (path, pin, b) = f.binding();
    for wrong in ["", &"0".repeat(64)] {
        assert!(coding_lifecycle::load_bound_transfer(&path, wrong).is_err());
    }
    let loaded = coding_lifecycle::load_bound_transfer(&path, &pin).unwrap();
    let r = coding_lifecycle::receive(
        &loaded.artifact,
        &loaded.proof,
        &loaded.policy,
        &b.destination,
        &b.state,
        Some(&b.approval_id),
    );
    assert_eq!(r.status, "REFUSED");
    assert_eq!(r.authority, "NONE");
    assert!(!r.application_dispatched);
    assert!(r.stages[2..].iter().all(|s| s.status == "NOT_RUN"));
    assert!(!b.destination.exists() && !b.state.exists());
    std::fs::write(&path, b"{}").unwrap();
    assert!(coding_lifecycle::load_bound_transfer(&path, &pin).is_err());
}

#[test]
fn externally_repinned_sidecar_cannot_smuggle_aliases_overlap_or_unknown_authority() {
    let f = Inputs::new();
    let (path, _, original) = f.binding();
    for kind in 0..5 {
        let mut b = original.clone();
        match kind {
            0 => b.artifact = PathBuf::from("relative.realm"),
            1 => b.state = b.destination.join("nested-state"),
            2 => b.policy = b.destination.join("policy.json"),
            3 => b.approval_id.clear(),
            _ => {
                let link = f.0.join("linked-policy.json");
                std::os::unix::fs::symlink(&b.policy, &link).unwrap();
                b.policy = link;
            }
        }
        let raw = serde_json::to_vec(&b).unwrap();
        std::fs::write(&path, &raw).unwrap();
        assert!(
            coding_lifecycle::load_bound_transfer(&path, &digest(&raw)).is_err(),
            "case {kind}"
        );
    }
    let mut value = serde_json::to_value(&original).unwrap();
    value["authority"] = true.into();
    let raw = serde_json::to_vec(&value).unwrap();
    std::fs::write(&path, &raw).unwrap();
    assert!(coding_lifecycle::load_bound_transfer(&path, &digest(&raw)).is_err());
    // These are re-pinned malformed claims, not forged production authority.
    assert!(!original.destination.exists() && !original.state.exists());
}

#[test]
fn transport_order_is_not_confused_with_authenticated_transition_order() {
    let (bytes, mut proof) = chain();
    proof.snapshot.transitions.reverse();
    assert!(!publication(&bytes, &proof).unwrap().is_authorizing());
}

#[test]
fn content_rejects_forbidden_effects_even_after_test_operator_repins_bytes() {
    for kind in 0..4 {
        let (bytes, mut policy) = coding_transfer::tests::prospective();
        let mut b = ArtifactBundle::unpack(&bytes).unwrap();
        if kind == 0 {
            b.run.proposed_effects[0].kind = "shell".into();
        } else if kind == 1 {
            b.run.proposed_effects[0].target = "forbidden.txt".into();
        } else if kind == 2 {
            b.run.unknown_effects.push(crate::UnknownEffect {
                kind: "missing-observation".into(),
                target: None,
                reason: "SYNTHETIC unobserved effect channel".into(),
            });
        } else {
            // Wrong result bytes versus the independently approved projection,
            // not an attempt to execute/grade Python in the receiver.
            let blob = b.add_blob(b"# SYNTHETIC wrong result\n".to_vec(), "text/plain");
            b.run.outputs[0].digest = blob.digest.clone();
            b.run.outputs[0].size = blob.size;
            b.run.proposed_effects[0].after = Some(blob.digest);
        }
        b.run.lifecycle = crate::Lifecycle::Frozen;
        b.run.seal = None;
        b.seal().unwrap();
        let bytes = b.pack().unwrap();
        policy.artifact_blake3 = digest(&bytes);
        policy.semantic_root = b.semantic_identity().unwrap().value;
        assert!(
            coding_transfer::inspect_content(&bytes, &policy, coding_transfer::now_unix().unwrap())
                .is_err()
        );
    }
}
