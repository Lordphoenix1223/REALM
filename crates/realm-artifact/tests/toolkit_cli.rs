use realm_artifact::{ArtifactBundle, VerificationDecision, inspection, observations};
use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "realm-toolkit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_realm-artifact"))
        .args(args)
        .output()
        .unwrap()
}
fn check(path: &std::path::Path, execution: bool) -> (i32, Value) {
    let mut args = vec!["verify", "--json", path.to_str().unwrap()];
    if execution {
        args.push("--require-execution");
    }
    let out = cli(&args);
    (
        out.status.code().unwrap(),
        serde_json::from_slice(&out.stdout).unwrap(),
    )
}

#[test]
fn installed_style_demo_creates_three_distinguishable_controls_and_never_overwrites() {
    let root = Workspace::new();
    let output = root.0.join("demo");
    let result = cli(&["demo", "--output", output.to_str().unwrap()]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for (name, exit, status) in [
        ("valid", 0, "VALID"),
        ("tampered", 1, "INVALID"),
        ("incomplete", 3, "INCOMPLETE"),
    ] {
        let path = output.join(format!("{name}.realm"));
        let before = fs::read(&path).unwrap();
        let (code, report) = check(&path, false);
        assert_eq!(code, exit);
        assert_eq!(report["status"], status);
        assert_eq!(report["checks"]["execution_authorization"], "NOT_CHECKED");
        assert_eq!(before, fs::read(&path).unwrap(), "checker modified input");
    }
    let (_, bad) = check(&output.join("tampered.realm"), false);
    assert!(
        bad["diagnostic"]
            .as_str()
            .unwrap()
            .contains("blob substitution")
    );
    let (code, execution) = check(&output.join("valid.realm"), true);
    assert_eq!(code, 3);
    assert_eq!(execution["checks"]["artifact_integrity"], "PASS");
    assert_eq!(
        cli(&["demo", "--output", output.to_str().unwrap()])
            .status
            .code(),
        Some(5)
    );
}

#[test]
fn errors_distinguish_bad_bytes_future_formats_io_and_usage() {
    let root = Workspace::new();
    let path = root.0.join("sample.realm");
    for data in [b"garbage".as_slice(), b"REALM-PORTABLE-3\n".as_slice()] {
        fs::write(&path, data).unwrap();
        let (code, report) = check(&path, false);
        assert_eq!(code, 1);
        assert_eq!(report["status"], "INVALID");
    }
    fs::write(&path, b"REALM-PORTABLE-99\n").unwrap();
    let (code, report) = check(&path, false);
    assert_eq!(code, 4);
    assert_eq!(report["status"], "UNSUPPORTED");
    fs::remove_file(&path).unwrap();
    let (code, report) = check(&path, false);
    assert_eq!(code, 5);
    assert_eq!(report["status"], "IO_ERROR");
    assert_eq!(cli(&["verify", "--made-up"]).status.code(), Some(2));
    assert!(cli(&["--help"]).status.success());
    let version = cli(&["version", "--json"]);
    let version: Value = serde_json::from_slice(&version.stdout).unwrap();
    assert_eq!(version["artifact_schema"], 3);
}

#[test]
fn imported_real_bytes_remain_unknown_even_if_caller_forges_accept() {
    let mut bundle = observations::from_file_observation(
        "external-run",
        b"before".to_vec(),
        b"after".to_vec(),
        b"untrusted log".to_vec(),
    )
    .unwrap();
    assert!(!bundle.is_authorizing());
    assert!(!bundle.run.evidence[0].authoritative);
    bundle.envelope.verification[0].decision = VerificationDecision::Accept;
    let report = inspection::check_bytes(&bundle.pack().unwrap(), true);
    assert_eq!(report.status, inspection::Status::Incomplete);
    assert_eq!(report.checks.artifact_integrity, "PASS");
    assert_eq!(report.checks.execution_authorization, "NOT_CHECKED");
    assert_eq!(
        report.metadata.unwrap()["reported_verification"][0]["decision"],
        "ACCEPT"
    );
}

#[test]
fn record_cli_refuses_existing_outputs_and_commits_exact_observed_payloads() {
    let root = Workspace::new();
    for (name, data) in [
        ("before", b"a".as_slice()),
        ("after", b"b".as_slice()),
        ("log", b"log".as_slice()),
    ] {
        fs::write(root.0.join(name), data).unwrap();
    }
    let paths: Vec<_> = ["before", "after", "log", "out.realm"]
        .map(|n| root.0.join(n))
        .into_iter()
        .collect();
    let args = [
        "record",
        "run",
        paths[0].to_str().unwrap(),
        paths[1].to_str().unwrap(),
        paths[2].to_str().unwrap(),
        paths[3].to_str().unwrap(),
    ];
    assert!(cli(&args).status.success());
    let bundle = ArtifactBundle::open(&paths[3]).unwrap();
    assert_eq!(bundle.blobs[&bundle.run.outputs[0].digest.value], b"b");
    assert_eq!(check(&paths[3], false).0, 0);
    assert_eq!(check(&paths[3], true).0, 3);
    let original = fs::read(&paths[3]).unwrap();
    assert_eq!(cli(&args).status.code(), Some(5));
    assert_eq!(original, fs::read(&paths[3]).unwrap());
}

#[test]
fn unsupported_run_schema_and_reader_limit_are_not_reported_as_verified() {
    let original = include_bytes!("../examples/minimal.realm");
    let mut bytes = original.to_vec();
    let needle = b"\"schema_version\":3";
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap();
    bytes[offset + needle.len() - 1] = b'9';
    assert_eq!(
        inspection::check_bytes(&bytes, false).status,
        inspection::Status::Unsupported
    );
    assert_eq!(
        inspection::check_bytes(b"REALM-PORTABLE-3", false).status,
        inspection::Status::Invalid
    );
    let oversized = vec![0; inspection::MAX_ARTIFACT_BYTES as usize + 1];
    let report = inspection::check_bytes(&oversized, false);
    assert_eq!(report.status, inspection::Status::Unsupported);
    assert_eq!(report.checks.artifact_integrity, "NOT_CHECKED");
    assert_eq!(cli(&["verfy"]).status.code(), Some(2));
}

#[cfg(unix)]
fn bounded_cli(args: &[&str]) -> Output {
    use std::{
        process::Stdio,
        time::{Duration, Instant},
    };
    let mut child = Command::new(env!("CARGO_BIN_EXE_realm-artifact"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("artifact CLI hung on a potentially replaced input");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(unix)]
fn fifo(path: &std::path::Path) {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: the path is a NUL-terminated string valid for this call.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
}

#[test]
#[cfg(unix)]
fn reader_checks_opened_objects_and_limits_the_read_without_waiting_on_fifos() {
    use std::os::unix::fs::symlink;
    let root = Workspace::new();
    let regular = root.0.join("regular");
    let link = root.0.join("link");
    let pipe = root.0.join("fifo");
    fs::write(&regular, b"0123456789").unwrap();
    symlink(&regular, &link).unwrap();
    fifo(&pipe);
    assert_eq!(inspection::read_regular_prefix(&link, 4).unwrap(), b"0123");
    assert!(inspection::read_regular_prefix(&root.0, 4).is_err());
    for source in [&pipe, &root.0] {
        let out = bounded_cli(&["verify", source.to_str().unwrap(), "--json"]);
        assert_eq!(out.status.code(), Some(5));
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["status"], "IO_ERROR");
        assert_eq!(report["checks"]["artifact_integrity"], "NOT_CHECKED");
        let output = root.0.join("never-created.realm");
        let out = bounded_cli(&[
            "record",
            "run",
            source.to_str().unwrap(),
            regular.to_str().unwrap(),
            regular.to_str().unwrap(),
            output.to_str().unwrap(),
        ]);
        assert_eq!(out.status.code(), Some(5));
        assert!(!output.exists());
    }
}

#[test]
#[cfg(unix)]
fn concurrent_regular_file_to_fifo_replacement_does_not_hang_or_confer_authority() {
    use std::{
        os::unix::fs::symlink,
        sync::{Arc, atomic::AtomicBool},
    };
    let root = Workspace::new();
    let regular = root.0.join("valid.realm");
    let pipe = root.0.join("fifo");
    let input = root.0.join("input");
    fs::write(&regular, include_bytes!("../examples/minimal.realm")).unwrap();
    fifo(&pipe);
    symlink(&regular, &input).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let next = root.0.join("next");
    let worker_input = input.clone();
    let thread = std::thread::spawn(move || {
        while !worker_stop.load(Ordering::Relaxed) {
            for target in [&pipe, &regular] {
                symlink(target, &next).unwrap();
                fs::rename(&next, &worker_input).unwrap();
            }
        }
    });
    let results = std::panic::catch_unwind(|| {
        (0..100)
            .map(|_| bounded_cli(&["verify", input.to_str().unwrap(), "--json"]))
            .collect::<Vec<_>>()
    });
    stop.store(true, Ordering::Relaxed);
    thread.join().unwrap();
    for result in results.unwrap() {
        assert!(matches!(result.status.code(), Some(0 | 5)));
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(matches!(
            report["status"].as_str(),
            Some("VALID" | "IO_ERROR")
        ));
        assert_eq!(report["checks"]["execution_authorization"], "NOT_CHECKED");
    }
}
