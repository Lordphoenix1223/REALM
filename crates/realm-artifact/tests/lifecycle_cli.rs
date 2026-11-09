use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn lifecycle_cli_emits_typed_incomplete_without_a_store() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let private_parent = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("realm-lifecycle-cli-{nonce}"));
    fs::create_dir(&private_parent).unwrap();
    fs::set_permissions(&private_parent, fs::Permissions::from_mode(0o700)).unwrap();
    let live_root = private_parent.join("workspace");
    fs::create_dir(&live_root).unwrap();
    fs::set_permissions(&live_root, fs::Permissions::from_mode(0o700)).unwrap();

    let pin = "f".repeat(64);
    let output = Command::new(env!("CARGO_BIN_EXE_realm-artifact"))
        .args(["verify-lifecycle", live_root.to_str().unwrap(), &pin, &pin])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "lifecycle CLI emitted no JSON: {error}; status={:?}; stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(result["state"], "INCOMPLETE");
    assert!(result["diagnostic"].as_str().unwrap().contains("missing"));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Incomplete")
    );

    fs::remove_dir_all(private_parent).unwrap();
}
