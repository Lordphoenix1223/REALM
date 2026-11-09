use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[cfg(target_os = "linux")]
#[test]
fn publication_only_flag_routes_before_paths_and_keeps_admission_gate() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "realm-publication-only-refusal-{}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let path = root.join("invalid-admission.json");
    fs::write(&path, b"{}").unwrap();
    for deferred in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_realm"));
        command.args(["task", "run-coding-native"]);
        if deferred {
            command.arg("--publication-only");
        }
        let result = command
            .args([
                "/NOT_USED_WORLD",
                "/NOT_USED_EVIDENCE",
                "/NOT_USED_TRUST",
                "--native-referee-launch",
                "--runtime-admission",
                path.to_str().unwrap(),
                &"0".repeat(64),
            ])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains("runtime admission raw pin or bound differs")
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        assert_eq!(fs::read(&path).unwrap(), b"{}");
    }
    fs::remove_file(path).unwrap();
    fs::remove_dir(root).unwrap();
    println!("PUBLICATION_ONLY_ROUTING=PASS native=NOT_RUN application=NOT_RUN authority=NONE");
}

#[test]
fn installed_prelaunch_refuses_untrusted_statement_and_missing_setup() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("realm-prelaunch-negative-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let path = root.join("test-only-statement.json");
    let raw = serde_json::to_vec(&serde_json::json!({
        "schema":"realm.signed-runtime-admission/v1", "reviewer_key_id":"a".repeat(64),
        "policy_json":"{}", "signature_hex":"0".repeat(768),
    }))
    .unwrap();
    fs::write(&path, &raw).unwrap();
    for pin in [blake3::hash(&raw).to_hex().to_string(), "0".repeat(64)] {
        let r = Command::new(env!("CARGO_BIN_EXE_realm"))
            .args([
                "artifact",
                "preflight-installed-coding",
                &"b".repeat(64),
                path.to_str().unwrap(),
                &pin,
            ])
            .output()
            .unwrap();
        assert!(!r.status.success());
        assert!(
            r.stdout.is_empty(),
            "unqualified input returned setup or authority"
        );
        assert_eq!(fs::read(&path).unwrap(), raw);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    }
    fs::remove_file(path).unwrap();
    fs::remove_dir(root).unwrap();
    println!(
        "INSTALLED_PRELAUNCH_REFUSAL=PASS authority=NONE trust_installed=false native=NOT_RUN"
    );
}

#[test]
fn primary_cli_exposes_transfer_and_refuses_duplicate_trust_inputs() {
    let help = Command::new(env!("CARGO_BIN_EXE_realm"))
        .args(["transfer", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("transfer preflight"));
    assert!(text.contains("progress-coding"));
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("realm-primary-transfer-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    struct Owned(std::path::PathBuf);
    impl Drop for Owned {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let _owned = Owned(root.clone());
    let proof = root.join("proof.json");
    fs::write(
        &proof,
        br#"{"snapshot":{"artifacts":{"same-key":[1],"same-key":[2]}}}"#,
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_realm"))
        .args([
            "artifact",
            "verify",
            "unused.realm",
            proof.to_str().unwrap(),
            "unused-permit.json",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("duplicate-key transfer JSON"),
        "{:?}",
        out
    );
}

#[test]
fn pinned_binding_cli_refuses_public_fixture_without_destination_effects() {
    use realm_artifact::host_apply::{
        DirectoryIdentity,
        coding_lifecycle::CodingTransferBinding,
        coding_transfer::{AUTHORIZATION_DOMAIN, CONTRACT_DOMAIN, CodingTransferPolicy, PROFILE},
    };
    use realm_v6::coding_submission::{
        CodingFileCommitment, CodingTransferContract, PATHS, SubmissionContract,
    };
    use std::os::unix::fs::MetadataExt;
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("realm-bound-transfer-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    struct Owned(std::path::PathBuf);
    impl Drop for Owned {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let _owned = Owned(root.clone());
    for name in ["destination", "state"] {
        fs::create_dir(root.join(name)).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let artifact = include_bytes!("../../realm-artifact/examples/minimal.realm");
    fs::write(root.join("candidate.realm"), artifact).unwrap();
    fs::write(root.join("proof.json"), b"{}").unwrap();
    let m = fs::metadata(root.join("destination")).unwrap();
    let contract = CodingTransferContract {
        schema_version: 1,
        profile: PROFILE.into(),
        submission: SubmissionContract {
            run_id: "a".repeat(64),
            execution_id: "b".repeat(64),
            challenge_root: "c".repeat(64),
            task_sha256: "d".repeat(64),
            worker_sha256: "e".repeat(64),
        },
        source_commit: "f".repeat(40),
        semantic_commitment: "1".repeat(64),
        files: std::array::from_fn(|i| CodingFileCommitment {
            path: PATHS[i].into(),
            content_blake3: "2".repeat(64),
            bytes: 1,
            mode: 0o600,
        }),
    };
    assert_eq!(
        contract.identity().unwrap(),
        realm_artifact::hash(CONTRACT_DOMAIN, &serde_json::to_vec(&contract).unwrap()).value
    );
    let policy = CodingTransferPolicy {
        workflow_trust: None,
        runtime_admission: None,
        schema_version: 1,
        authorization_domain: AUTHORIZATION_DOMAIN.into(),
        artifact_blake3: blake3::hash(artifact).to_hex().to_string(),
        genesis_root: "3".repeat(64),
        exact_head_root: "4".repeat(64),
        semantic_root: "5".repeat(64),
        contract,
        destination: DirectoryIdentity {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
        },
        nonce: "6".repeat(64),
        not_before_unix: 1,
        expires_at_unix: 2,
    };
    fs::write(
        root.join("policy.json"),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    let binding = CodingTransferBinding {
        schema_version: 1,
        artifact: root.join("candidate.realm"),
        proof: root.join("proof.json"),
        policy: root.join("policy.json"),
        destination: root.join("destination"),
        state: root.join("state"),
        approval_id: "7".repeat(64),
    };
    let binding_path = root.join("binding.json");
    // Malformed proof must refuse before canonical artifact/destination checks.
    let raw = serde_json::to_vec(&binding).unwrap();
    fs::write(&binding_path, &raw).unwrap();
    let pin = blake3::hash(&raw).to_hex().to_string();
    for supplied_pin in [pin.as_str(), &"0".repeat(64)] {
        let out = Command::new(env!("CARGO_BIN_EXE_realm"))
            .args([
                "transfer",
                "run-bound",
                binding_path.to_str().unwrap(),
                supplied_pin,
            ])
            .output()
            .unwrap();
        assert!(!out.status.success());
    }
    // A shape-valid detached proof and current policy still cannot promote the
    // public non-authorizing artifact fixture. No test capability enters this path.
    let genesis = realm_artifact::lifecycle::GenesisAnchor::new(
        "NON_AUTHORIZING",
        "0".repeat(64),
        "no native publication",
    );
    let head = realm_artifact::lifecycle::AuthorityHead::from_genesis(&genesis).unwrap();
    let proof = realm_artifact::host_apply::TransferProof {
        schema_version: 1,
        genesis,
        snapshot: realm_artifact::lifecycle::LifecycleSnapshot {
            head,
            transitions: vec![],
            artifacts: Default::default(),
            receipts: Default::default(),
            journal: vec![],
            live_world_root: "0".repeat(64),
            retained_world_roots: Default::default(),
        },
    };
    fs::write(&binding.proof, serde_json::to_vec(&proof).unwrap()).unwrap();
    let now = realm_artifact::host_apply::coding_transfer::now_unix().unwrap();
    let mut policy = policy;
    policy.not_before_unix = now - 1;
    policy.expires_at_unix = now + 3600;
    fs::write(&binding.policy, serde_json::to_vec(&policy).unwrap()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_realm"))
        .args([
            "transfer",
            "run-bound",
            binding_path.to_str().unwrap(),
            &pin,
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["authority"], "NONE");
    assert_eq!(report["application_dispatched"], false);
    assert_eq!(report["status"], "REFUSED");
    assert!(
        report["stages"].as_array().unwrap()[1..]
            .iter()
            .all(|s| s["status"] == "NOT_RUN")
    );
    assert!(fs::read_dir(&binding.destination).unwrap().next().is_none());
    assert!(fs::read_dir(&binding.state).unwrap().next().is_none());
    let mut alias = binding.clone();
    alias.proof = root.join("state/proof.json");
    let raw = serde_json::to_vec(&alias).unwrap();
    fs::write(&binding_path, &raw).unwrap();
    assert!(
        realm_artifact::host_apply::coding_lifecycle::load_bound_transfer(
            &binding_path,
            blake3::hash(&raw).to_hex().as_str()
        )
        .is_err()
    );
}

#[test]
fn public_admission_reports_missing_native_facts_without_upgrading_checked_json() {
    let (_, evidence) = realm_v6::execute::test_coding_evidence_content();
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("realm-native-admission-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("ordinary-record-not-capability.json");
    fs::write(&path, serde_json::to_vec(&evidence).unwrap()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_realm"))
        .args(["artifact", "coding-admission", path.to_str().unwrap()])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!out.status.success());
    assert_eq!(report["authority"], "NONE");
    assert_eq!(report["admission"], "REFUSE");
    let checks = report["checks"].as_array().unwrap();
    assert_eq!(checks[0]["status"], "PASS_CONTENT_ONLY");
    assert_eq!(
        checks
            .iter()
            .filter(|row| row["status"] == "MISSING")
            .count(),
        6
    );
    assert!(
        checks
            .iter()
            .any(|row| row["code"]["code"] == "MISSING_HOST_OBSERVATION")
    );
    fs::remove_dir_all(root).unwrap();
}
