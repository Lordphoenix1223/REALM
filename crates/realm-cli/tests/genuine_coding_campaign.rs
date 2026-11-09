//! Explicit production campaign through the public CLI. No producer, certificate,
//! constructor or fixture fallback. Requires independently authenticated inputs.
use realm_artifact::host_apply::coding_lifecycle::load_bound_transfer;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

fn snapshot(root: &Path) -> std::collections::BTreeMap<String, (u64, u32, String)> {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let p = entry.unwrap().path();
            let m = fs::symlink_metadata(&p).unwrap();
            assert!(
                m.is_file() && m.nlink() == 1,
                "unexpected destination/state object"
            );
            (
                p.file_name().unwrap().to_str().unwrap().to_string(),
                (
                    m.ino(),
                    m.mode(),
                    blake3::hash(&fs::read(&p).unwrap()).to_hex().to_string(),
                ),
            )
        })
        .collect()
}

#[test]
#[ignore = "NOT_RUN: genuine native-issued coding publication, external pins, exact destination approval and clean receiver source pin required"]
fn genuine_native_coding_publication_completes_public_cli_campaign() {
    let required =
        |name| std::env::var(name).unwrap_or_else(|_| panic!("required independent input: {name}"));
    let binding = PathBuf::from(required("REALM_CODING_TRANSFER_BINDING"));
    let pin = required("REALM_CODING_TRANSFER_BINDING_BLAKE3");
    let expected_source = required("REALM_CODING_RECEIVER_SOURCE_COMMIT");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(&source)
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    assert_eq!(git(&["rev-parse", "HEAD"]).trim(), expected_source);
    assert!(
        git(&[
            "status",
            "--porcelain",
            "--",
            "Cargo.toml",
            "Cargo.lock",
            "crates",
            "scripts"
        ])
        .trim()
        .is_empty(),
        "receiver source must be clean and pinned before campaign"
    );
    let bound = load_bound_transfer(&binding, &pin)
        .expect("pinned operator binding and bounded inputs must reopen");
    let output = PathBuf::from(required("REALM_CODING_CAMPAIGN_OUTPUT"));
    assert!(output.is_absolute());
    assert_eq!(
        output.parent().unwrap().canonicalize().unwrap(),
        output.parent().unwrap()
    );
    assert!(
        !output.starts_with(&bound.binding.destination)
            && !bound.binding.destination.starts_with(&output)
    );
    assert!(!output.starts_with(&bound.binding.state) && !bound.binding.state.starts_with(&output));
    fs::create_dir(&output).expect("campaign output must be fresh; never overwrite evidence");
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
    let retain = |name: &str, bytes: &[u8]| {
        let p = output.join(name);
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
    };
    retain("receiver-source.txt", expected_source.as_bytes());
    let exe = env!("CARGO_BIN_EXE_realm");
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(fs::File::open(exe).unwrap()).unwrap();
    retain(
        "receiver-binary-blake3.txt",
        hasher.finalize().to_hex().as_bytes(),
    );
    let invoke = |label: &str, args: Vec<&str>, expected_ok: bool| {
        let out = Command::new(exe).args(&args).output().unwrap();
        retain(&format!("{label}.stdout"), &out.stdout);
        retain(&format!("{label}.stderr"), &out.stderr);
        retain(
            &format!("{label}.command.json"),
            &serde_json::to_vec_pretty(
                &serde_json::json!({"argv":args,"exit_code":out.status.code()}),
            )
            .unwrap(),
        );
        assert_eq!(
            out.status.success(),
            expected_ok,
            "stage {label}; retained stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    };
    retain("operator-binding.json", &bound.binding_bytes);
    retain("candidate.realm", &bound.artifact);
    retain("proof.json", &bound.proof_bytes);
    retain("policy.json", &bound.policy_bytes);
    let b = &bound.binding;
    let a = b.artifact.to_str().unwrap();
    let p = b.proof.to_str().unwrap();
    let t = b.policy.to_str().unwrap();
    let d = b.destination.to_str().unwrap();
    let s = b.state.to_str().unwrap();
    let binding = binding.to_str().unwrap();
    invoke("01-inspect", vec!["artifact", "inspect-coding", a, t], true);
    invoke(
        "02-verify-native-publication",
        vec!["artifact", "verify-coding", a, p, t],
        true,
    );
    let prepared = invoke(
        "03-prepare",
        vec!["transfer", "preflight-bound", binding, &pin],
        true,
    );
    let preview: serde_json::Value = serde_json::from_slice(&prepared).unwrap();
    assert_eq!(
        preview["approval_id"], b.approval_id,
        "operator approval must already match; campaign never grants itself approval"
    );
    let initial_dest = snapshot(&b.destination);
    let initial_state = snapshot(&b.state);
    assert!(
        initial_dest.is_empty() && initial_state.is_empty(),
        "genuine campaign requires fresh separate operator-selected directories"
    );
    invoke(
        "04-wrong-approval-refuses",
        vec!["transfer", "run", a, p, t, d, s, "--approve", "invalid"],
        false,
    );
    assert_eq!(snapshot(&b.destination), initial_dest);
    assert_eq!(snapshot(&b.state), initial_state);
    let applied = invoke(
        "05-apply",
        vec!["transfer", "run-bound", binding, &pin],
        true,
    );
    let attempt: serde_json::Value = serde_json::from_slice(&applied).unwrap();
    assert_eq!(attempt["status"], "APPLIED_AND_FINAL_VERIFIED");
    assert_eq!(attempt["authority"], "QUALIFIED_CODING");
    let complete_dest = snapshot(&b.destination);
    let complete_state = snapshot(&b.state);
    invoke(
        "06-resume",
        vec![
            "transfer",
            "resume",
            a,
            p,
            t,
            d,
            s,
            "--approve",
            &b.approval_id,
        ],
        true,
    );
    assert_eq!(snapshot(&b.destination), complete_dest);
    assert_eq!(snapshot(&b.state), complete_state);
    invoke(
        "07-progress",
        vec!["apply", "progress-coding", a, p, t, d, s],
        true,
    );
    let final_bytes = invoke(
        "08-independent-final-receipt",
        vec!["apply", "verify-coding", a, p, t, d, s],
        true,
    );
    let receipt: serde_json::Value = serde_json::from_slice(&final_bytes).unwrap();
    assert_eq!(receipt["verified"], true);
    assert_eq!(receipt["completed_operations"], 3);
    assert_eq!(snapshot(&b.destination), complete_dest);
    assert_eq!(snapshot(&b.state), complete_state);
    retain("PASS.json", &serde_json::to_vec_pretty(&serde_json::json!({"status":"APPLIED_AND_FINAL_VERIFIED","receiver_source":expected_source,"artifact_blake3":bound.policy.artifact_blake3,"policy_id":bound.policy.identity().unwrap(),"receipt":receipt})).unwrap());
}
