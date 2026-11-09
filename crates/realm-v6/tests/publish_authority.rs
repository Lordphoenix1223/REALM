use realm_v6::{Admission, execute::ExecuteResult};
use std::{
    fs,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEST_PATH: AtomicU64 = AtomicU64::new(0);

#[test]
fn serialized_accept_cannot_publish_or_create_a_journal() {
    let root = std::env::temp_dir().join(format!(
        "realm-publish-authority-test-{}-{}",
        std::process::id(),
        NEXT_TEST_PATH.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let destination = root.join("live");
    fs::create_dir(&destination).unwrap();
    let protected = destination.join("existing.txt");
    fs::write(&protected, b"host state").unwrap();

    let result = ExecuteResult {
        guest_exit_code: None,
        guest_crashed: None,
        vmm_pid: None,
        vmm_start_time_ticks: None,
        schema_version: 1,
        run_id: "forged-run".into(),
        execution_id: "forged-execution".into(),
        starting_world_commitment: "forged-start-root".into(),
        final_world_commitment: Some("forged-final-root".into()),
        delta_root: Some("forged-delta-root".into()),
        starting_workspace_image: None,
        final_workspace_image: None,
        observed_effects: vec!["existing.txt".into()],
        proposed_effects: Vec::new(),
        evidence_root: Some("forged-evidence".into()),
        receipt_path: None,
        verifier_decision: Admission::Refuse(realm_v6::Refusal::UnverifiedBoundary),
        reason_code: "C1_TERMINAL_JOIN_UNAVAILABLE".into(),
        task_success: false,
        unsupported_effects: Vec::new(),
        runtime_ms: 1,
        overhead_ms: 1,
    };
    let result_path = root.join("result.json");
    let mut serialized = serde_json::to_value(&result).unwrap();
    serialized["verifier_decision"] = serde_json::json!({"decision": "ACCEPT"});
    fs::write(&result_path, serde_json::to_vec(&serialized).unwrap()).unwrap();
    let journal_path = root.join("publication.jsonl");

    let output = Command::new(env!("CARGO_BIN_EXE_publish"))
        .args([
            "--execution-result",
            result_path.to_str().unwrap(),
            "--destination",
            destination.to_str().unwrap(),
            "--journal",
            journal_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("refuses serialized ExecuteResult"));
    assert_eq!(fs::read(&protected).unwrap(), b"host state");
    assert_eq!(fs::read_dir(&destination).unwrap().count(), 1);
    assert!(!journal_path.exists());
    fs::remove_dir_all(root).unwrap();
}
