use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_realm-artifact"))
        .args(args)
        .output()
        .unwrap()
}
#[cfg(not(feature = "receiver-fixtures"))]
#[test]
fn default_binary_contains_no_fixture_receiver() {
    let out = run(&[
        "fixture-receiver",
        "make",
        "/this-must-never-be-created.realm",
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("fixture receiver absent"));
}

#[cfg(feature = "receiver-fixtures")]
#[test]
fn independent_cli_invocations_prepare_authorize_apply_resume_observe_and_refuse() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("realm-receiver-cli-{}", std::process::id()));
    // Collision refuses; no cleanup of any preexisting path.
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
    let artifact = root.join("fixture.realm");
    let dest = root.join("destination");
    let state = root.join("state");
    let a = artifact.to_str().unwrap();
    let d = dest.to_str().unwrap();
    let s = state.to_str().unwrap();
    let make = run(&["fixture-receiver", "make", a]);
    assert!(make.status.success(), "{:?}", make);
    let created: serde_json::Value = serde_json::from_slice(&make.stdout).unwrap();
    let pin = created["artifact_blake3"].as_str().unwrap();
    let inspection = run(&["inspect-coding", a]);
    assert!(inspection.status.success());
    let production = run(&["verify-coding", a]);
    assert!(!production.status.success());
    assert!(String::from_utf8_lossy(&production.stderr).contains("REFUSE_UNVERIFIED_BOUNDARY"));
    let pipeline_preview = run(&["fixture-receiver", "receive", a, pin, d, s]);
    assert!(pipeline_preview.status.success(), "{:?}", pipeline_preview);
    let pipeline: serde_json::Value = serde_json::from_slice(&pipeline_preview.stdout).unwrap();
    assert_eq!(pipeline["status"], "PREPARED_REQUIRES_SEPARATE_APPROVAL");
    assert_eq!(pipeline["application_dispatched"], false);
    assert_eq!(pipeline["stages"][1]["status"], "NOT_APPLICABLE_FIXTURE");
    let prepare = run(&["fixture-receiver", "prepare", a, pin, d]);
    assert!(prepare.status.success(), "{:?}", prepare);
    let plan: serde_json::Value = serde_json::from_slice(&prepare.stdout).unwrap();
    let approval = plan["approval_id"].as_str().unwrap();
    assert_eq!(fs::read_dir(&state).unwrap().count(), 0);
    let bad = run(&[
        "fixture-receiver",
        "apply",
        a,
        pin,
        d,
        s,
        "--approve",
        "bad",
    ]);
    assert!(!bad.status.success());
    assert_eq!(fs::read_dir(&state).unwrap().count(), 0);
    for _ in 0..2 {
        let out = run(&[
            "fixture-receiver",
            "apply",
            a,
            pin,
            d,
            s,
            "--approve",
            approval,
        ]);
        assert!(out.status.success(), "{:?}", out);
        let receipt: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(receipt["authority"], "NONE");
        assert_eq!(receipt["result"]["completed_operations"], 3);
    }
    let complete = run(&[
        "fixture-receiver",
        "receive",
        a,
        pin,
        d,
        s,
        "--approve",
        approval,
    ]);
    assert!(complete.status.success(), "{:?}", complete);
    let completed: serde_json::Value = serde_json::from_slice(&complete.stdout).unwrap();
    assert_eq!(completed["status"], "NON_AUTHORIZING_FIXTURE_APPLIED");
    assert_eq!(completed["authority"], "NONE");
    let journal = fs::read(state.join("journal.jsonl")).unwrap();
    for command in ["progress", "final-verify"] {
        let out = run(&["fixture-receiver", command, a, pin, d, s]);
        assert!(out.status.success(), "{:?}", out);
    }
    assert_eq!(fs::read(state.join("journal.jsonl")).unwrap(), journal);
    assert!(
        !run(&["fixture-receiver", "prepare", a, pin, d])
            .status
            .success()
    );
    let other = root.join("link.realm");
    std::os::unix::fs::symlink(&artifact, &other).unwrap();
    assert!(
        !run(&["inspect-coding", other.to_str().unwrap()])
            .status
            .success()
    );
    fs::write(dest.join("report.py"), b"wrong final bytes").unwrap();
    assert!(
        !run(&["fixture-receiver", "final-verify", a, pin, d, s])
            .status
            .success()
    );
}
