//! This ignored acceptance test is intentionally not a fixture. Explicitly run
//! with independently authenticated production inputs and destination approval.
//! Missing native authority must fail the test, never skip or pass it.
use realm_artifact::host_apply::{coding_lifecycle, coding_transfer, ordered_create};

#[test]
#[ignore = "NOT_RUN: requires independently pinned genuine qualified coding artifact, proof, policy and explicit disposable destination approval"]
fn genuine_qualified_coding_artifact_is_applied_and_independently_verified() {
    let path = std::env::var("REALM_CODING_TRANSFER_BINDING")
        .expect("required independent production binding path");
    let pin = std::env::var("REALM_CODING_TRANSFER_BINDING_BLAKE3")
        .expect("required independently authenticated binding pin");
    assert!(
        coding_lifecycle::load_bound_transfer(std::path::Path::new(&path), &"0".repeat(64))
            .is_err()
    );
    let bound = coding_lifecycle::load_bound_transfer(std::path::Path::new(&path), &pin).unwrap();
    let binding = &bound.binding;
    // Independently check authority before the real destination can be touched.
    coding_transfer::verify_transfer(&bound.artifact, &bound.proof, &bound.policy).unwrap();
    for kind in 0..4 {
        let mut policy = bound.policy.clone();
        match kind {
            0 => policy.exact_head_root = "0".repeat(64),
            1 => policy.genesis_root = "0".repeat(64),
            2 => policy.contract.submission.run_id = "0".repeat(64),
            _ => policy.contract.submission.task_sha256 = "0".repeat(64),
        }
        let negative = coding_lifecycle::receive(
            &bound.artifact,
            &bound.proof,
            &policy,
            std::path::Path::new("/negative-destination-must-not-be-opened"),
            std::path::Path::new("/negative-state-must-not-be-opened"),
            None,
        );
        assert_eq!(negative.authority, "NONE", "negative case {kind}");
        assert_eq!(negative.status, "REFUSED", "negative case {kind}");
        assert!(!negative.application_dispatched);
        assert!(negative.stages[2..].iter().all(|s| s.status == "NOT_RUN"));
    }
    let mut damaged = bound.artifact.clone();
    damaged[0] ^= 1;
    assert!(coding_transfer::verify_transfer(&damaged, &bound.proof, &bound.policy).is_err());
    let preview = coding_lifecycle::receive(
        &bound.artifact,
        &bound.proof,
        &bound.policy,
        &binding.destination,
        &binding.state,
        None,
    );
    assert_eq!(preview.status, "PREPARED_REQUIRES_SEPARATE_APPROVAL");
    assert_eq!(preview.authority, "QUALIFIED_CODING");
    assert!(!preview.application_dispatched);
    assert_eq!(
        preview.approval_id.as_deref(),
        Some(binding.approval_id.as_str())
    );
    let report = coding_lifecycle::receive(
        &bound.artifact,
        &bound.proof,
        &bound.policy,
        &binding.destination,
        &binding.state,
        Some(&binding.approval_id),
    );
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    assert_eq!(report.status, "APPLIED_AND_FINAL_VERIFIED");
    assert_eq!(report.authority, "QUALIFIED_CODING");
    assert_eq!(report.evidence_class, "PRODUCTION_CODING_ATTEMPT");
    assert!(report.application_dispatched);
    assert!(report.stages.iter().all(|s| s.status == "PASS"));
    let receipt = report.receipt.unwrap();
    assert!(receipt.verified);
    assert_eq!(receipt.completed_operations, 3);
    // Fresh proof verification plus a fresh descriptor/journal/bytes observation;
    // do not treat the application's own returned receipt as the final oracle.
    let independently_verified =
        coding_transfer::verify_for_observation(&bound.artifact, &bound.proof, &bound.policy)
            .unwrap();
    let observed = ordered_create::verify_host(
        &independently_verified,
        &binding.destination,
        &binding.state,
    )
    .unwrap();
    assert!(observed.verified);
    assert_eq!(observed.completed_operations, 3);
    let reopened =
        coding_lifecycle::load_bound_transfer(std::path::Path::new(&path), &pin).unwrap();
    assert_eq!(reopened.artifact, bound.artifact);
    assert_eq!(reopened.proof_bytes, bound.proof_bytes);
    assert_eq!(reopened.policy_bytes, bound.policy_bytes);
}
