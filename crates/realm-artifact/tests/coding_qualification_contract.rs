//! Controlled SOFTWARE contract campaign. No native owners, qualified run,
//! canonical publication, destination capability or application is constructed.
#![cfg(feature = "receiver-fixtures")]

#[path = "support/fixture_admission.rs"]
mod fixture_admission;

use realm_artifact::host_apply::{DirectoryIdentity, coding_qualification, coding_transfer};
use realm_v6::runtime_admission::{self, check_fixture_receipt};

#[test]
fn frozen_receiver_rejects_unjoined_pr85_checker_catalog() {
    // Exact original PR85/60653d22 sources, not fabricated qualification data.
    // The compatibility join adopts frozen PR79's catalog without relaxing it.
    let current = runtime_admission::fixture_candidate().policy.expected;
    current.validate().unwrap();
    for (name, prior) in [
        (
            "coding_worker.py",
            "df89a66b94820bab99dc91ff2a85fc04677c3f04e44d0bd04f59465a7efef6b8",
        ),
        (
            "candidate_channel_guard.py",
            "5aa3b1e130f9dbdef2eb930a7e5cacb54beadba9b7b8e07167dbc7b72947e664",
        ),
    ] {
        assert_ne!(current.checker_sources[name], prior);
        let mut foreign = current.clone();
        foreign.checker_sources.insert(name.into(), prior.into());
        assert_eq!(
            foreign.validate().unwrap_err(),
            "unsupported checker source tuple"
        );
    }
}

fn retain(root: &Option<std::path::PathBuf>, name: &str, bytes: &[u8]) {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    if let Some(root) = root {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
    }
}

#[test]
fn producer_bytes_reach_independent_receiver_with_real_signature_checks_and_no_authority() {
    let candidate = runtime_admission::fixture_candidate();
    let (signed, trust) = fixture_admission::sign(&candidate.policy);
    let bundle = runtime_admission::finish_fixture(candidate, signed);
    let bytes = serde_json::to_vec(&bundle.semantic).unwrap();
    let decoded = coding_qualification::decode_receipt(&bytes).unwrap();
    let verdict = check_fixture_receipt(&decoded, &bundle.permitted, &trust).unwrap();
    assert_eq!(verdict.authority, "NONE");
    assert_eq!(verdict.evidence_class, "NON_AUTHORIZING_ADMISSION_FIXTURE");
    let retained = std::env::var_os("REALM_CONTRACT_FIXTURE_OUTPUT").map(std::path::PathBuf::from);
    if let Some(root) = &retained {
        use std::os::unix::fs::DirBuilderExt;
        assert!(root.is_absolute());
        std::fs::DirBuilder::new().mode(0o700).create(root).unwrap();
    }
    retain(&retained, "TEST-ONLY-receipt.json", &bytes);
    retain(
        &retained,
        "TEST-ONLY-permitted.json",
        &serde_json::to_vec(&bundle.permitted).unwrap(),
    );
    retain(
        &retained,
        "TEST-ONLY-reviewer-public.pem",
        &trust.public_key_pem,
    );
    retain(
        &retained,
        "TEST-ONLY-verdict.json",
        &serde_json::to_vec(&verdict).unwrap(),
    );
    // The SAME fully matching fixture never enters the production registry.
    assert!(coding_qualification::check_receipt(&decoded, &bundle.permitted).is_err());
    assert!(bundle.permitted.verify().is_err());
    let admission_policy = bundle.permitted.policy().unwrap();
    let now = admission_policy.not_before_unix + 1;
    let destination_policy = coding_transfer::CodingTransferPolicy {
        schema_version: 2,
        authorization_domain: coding_transfer::AUTHORIZATION_DOMAIN.into(),
        artifact_blake3: "1".repeat(64),
        genesis_root: "2".repeat(64),
        exact_head_root: "3".repeat(64),
        semantic_root: "4".repeat(64),
        contract: coding_transfer::CodingContract {
            schema_version: 1,
            profile: coding_transfer::PROFILE.into(),
            submission: decoded.prelaunch.submission.clone(),
            source_commit: decoded.prelaunch.source_commit.clone(),
            semantic_commitment: decoded.root().unwrap(),
            files: std::array::from_fn(|i| coding_transfer::CodingFile {
                path: realm_v6::coding_submission::PATHS[i].into(),
                content_blake3: "5".repeat(64),
                bytes: 1,
                mode: 0o600,
            }),
        },
        runtime_admission: Some(bundle.permitted.clone()),
        workflow_trust: None,
        destination: DirectoryIdentity {
            device: 1,
            inode: 2,
            uid: 3,
        },
        nonce: "6".repeat(64),
        not_before_unix: now,
        expires_at_unix: now + 60,
    };
    destination_policy.validate(now).unwrap();
    assert!(
        destination_policy
            .validate(admission_policy.expires_at_unix)
            .is_err()
    );
    let mut extends_past_admission = destination_policy.clone();
    extends_past_admission.expires_at_unix = admission_policy.expires_at_unix + 60;
    let effective = extends_past_admission.authorization_binding().unwrap();
    assert_eq!(effective.expires_at_unix, admission_policy.expires_at_unix);
    assert!(
        extends_past_admission
            .validate(admission_policy.expires_at_unix)
            .is_err()
    );
    let mut wrong_task = destination_policy.clone();
    wrong_task.contract.submission.task_sha256 = "7".repeat(64);
    assert!(wrong_task.validate_structure().is_err());
    println!("CONTROLLED_CONTRACT=PASS authority=NONE evidence_class=NON_AUTHORIZING");

    let foreign = "f".repeat(64);
    for case in [
        "signature-substitution",
        "wrong-runtime",
        "cross-run",
        "incomplete-capture",
        "missing-referee",
        "missing-qualification",
        "expired",
        "wrong-admission-pin",
        "missing-closure",
        "forbidden-effect",
        "substituted-jailer",
        "old-fence-profile",
        "tampered-fence-profile",
    ] {
        let mut changed = serde_json::to_value(&decoded).unwrap();
        match case {
            "signature-substitution" => {
                changed["runtime_qualification"]["admission"]["signature_hex"] =
                    "0".repeat(768).into()
            }
            "wrong-runtime" => {
                changed["runtime_qualification"]["observed_runtime"]["vmm_blake3"] =
                    foreign.clone().into();
                changed["runtime_provenance_record"]["fence"]["official"]["blake3"] =
                    foreign.clone().into();
            }
            "old-fence-profile" | "tampered-fence-profile" => {
                changed["runtime_provenance_record"]["fence"]["prelaunch_profile_blake3"] =
                    if case == "old-fence-profile" {
                        "a83522a3ea12c2a063a603bc12f0751b2696f84d38459f7e9af527baa87b63e2".into()
                    } else {
                        "f".repeat(64).into()
                    };
            }
            "cross-run" => changed["prelaunch"]["submission"]["run_id"] = foreign.clone().into(),
            "incomplete-capture" => {
                changed["runtime_provenance_record"]
                    .as_object_mut()
                    .unwrap()
                    .remove("capture_root");
            }
            "missing-referee" => {
                changed
                    .as_object_mut()
                    .unwrap()
                    .remove("referee_identity_record");
            }
            "missing-qualification" => {
                changed
                    .as_object_mut()
                    .unwrap()
                    .remove("runtime_qualification");
            }
            "expired" => changed["runtime_qualification"]["qualified_at_unix"] = u64::MAX.into(),
            "wrong-admission-pin" => {
                changed["prelaunch"]["runtime_admission_id"] = foreign.clone().into()
            }
            "missing-closure" => {
                changed["runtime_provenance_record"]
                    .as_object_mut()
                    .unwrap()
                    .remove("terminal");
            }
            "forbidden-effect" => {
                changed["runtime_provenance_record"]["unapproved_effect"] = true.into()
            }
            "substituted-jailer" => {
                changed["runtime_provenance_record"]["containment"]["jailer_process"]["executable"]
                    ["blake3"] = foreign.clone().into()
            }
            _ => unreachable!(),
        }
        if matches!(
            case,
            "incomplete-capture"
                | "missing-closure"
                | "forbidden-effect"
                | "substituted-jailer"
                | "wrong-runtime"
                | "old-fence-profile"
                | "tampered-fence-profile"
        ) {
            // Recommit the altered data. These controls must fail the complete
            // observation matcher, rather than only an obsolete hash.
            let root =
                blake3::hash(&serde_json::to_vec(&changed["runtime_provenance_record"]).unwrap())
                    .to_hex()
                    .to_string();
            changed["runtime_qualification"]["observation_root"] = root.into();
            let qualification: runtime_admission::QualificationEvidence =
                serde_json::from_value(changed["runtime_qualification"].clone()).unwrap();
            changed["provenance_root"] = qualification.identity().unwrap().into();
        }
        if matches!(case, "old-fence-profile" | "tampered-fence-profile") {
            // Identity derivation alone is not the independent policy check.
            // Exercise the same full matcher used by both receiver paths.
            let candidate: realm_v6::coding_semantics::CodingSemanticEvidence =
                serde_json::from_value(changed.clone()).unwrap();
            let error = candidate
                .runtime_qualification
                .as_ref()
                .unwrap()
                .matches_data(&candidate, &bundle.permitted)
                .unwrap_err();
            assert!(error.contains("unsupported fence profile"), "{error}");
        }
        let raw = serde_json::to_vec(&changed).unwrap();
        retain(&retained, &format!("{case}.json"), &raw);
        let refused = match coding_qualification::decode_receipt(&raw) {
            Err(_) => true,
            Ok(receipt) => check_fixture_receipt(&receipt, &bundle.permitted, &trust).is_err(),
        };
        assert!(refused, "{case} must refuse");
        println!("{case}=REFUSE authority=NONE");
    }
    let (substituted, _) = fixture_admission::sign(&bundle.permitted.policy().unwrap());
    assert!(check_fixture_receipt(&decoded, &substituted, &trust).is_err());
    // Rebuild all ordinary bindings around an invalid signature, so this
    // control exercises cryptography rather than just an admission hash join.
    let candidate = runtime_admission::fixture_candidate();
    let (mut invalid_signature, invalid_trust) = fixture_admission::sign(&candidate.policy);
    invalid_signature.signature_hex = "0".repeat(768);
    let invalid = runtime_admission::finish_fixture(candidate, invalid_signature);
    retain(
        &retained,
        "self-consistent-invalid-signature.json",
        &serde_json::to_vec(&invalid.semantic).unwrap(),
    );
    invalid
        .semantic
        .runtime_qualification
        .as_ref()
        .unwrap()
        .matches_data(&invalid.semantic, &invalid.permitted)
        .unwrap();
    assert!(check_fixture_receipt(&invalid.semantic, &invalid.permitted, &invalid_trust).is_err());
    println!("self-consistent-invalid-signature=REFUSE authority=NONE");
    let mut unknown = serde_json::to_value(&decoded).unwrap();
    unknown["runtime_qualification"]["authorized_by_agent"] = true.into();
    assert!(coding_qualification::decode_receipt(&serde_json::to_vec(&unknown).unwrap()).is_err());
}

#[test]
fn separate_input_admission_reaches_independent_receiver_and_tampering_refuses() {
    // Controlled SOFTWARE data and test signatures only; real FD ownership is
    // exercised separately by the non-root Linux native-input component tests.
    let candidate = runtime_admission::fixture_candidate().with_native_task_inputs();
    let (signed, trust) = fixture_admission::sign(&candidate.policy);
    let bundle = runtime_admission::finish_fixture(candidate, signed);
    let bytes = serde_json::to_vec(&bundle.semantic).unwrap();
    let receipt = coding_qualification::decode_receipt(&bytes).unwrap();
    assert_eq!(
        check_fixture_receipt(&receipt, &bundle.permitted, &trust)
            .unwrap()
            .authority,
        "NONE"
    );
    assert!(coding_qualification::check_receipt(&receipt, &bundle.permitted).is_err());
    for case in 0..5 {
        let mut bad = serde_json::to_value(&receipt).unwrap();
        match case {
            0 => bad["prelaunch"]["task_inputs_blake3"] = "f".repeat(64).into(),
            1 => bad["prelaunch"]["submission"]["run_id"] = "f".repeat(64).into(),
            2 => {
                bad["prelaunch"]["native_subtask"]["history_prefix_blake3"] = "f".repeat(64).into()
            }
            3 => {
                bad["runtime_qualification"]["observed_runtime"]["rootfs_blake3"] =
                    "f".repeat(64).into()
            }
            _ => {
                bad["prelaunch"]
                    .as_object_mut()
                    .unwrap()
                    .remove("task_inputs_blake3");
            }
        }
        let rejected = coding_qualification::decode_receipt(&serde_json::to_vec(&bad).unwrap());
        assert!(
            rejected.is_err()
                || check_fixture_receipt(&rejected.unwrap(), &bundle.permitted, &trust).is_err(),
            "case {case}"
        );
    }
}
