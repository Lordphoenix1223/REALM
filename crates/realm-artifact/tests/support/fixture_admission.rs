//! Ephemeral TEST authority for software-contract controls only. No private key
//! is retained, registered, or usable by the production admission entrypoint.
use realm_v6::runtime_admission::{
    FixtureAdmissionTrust, RuntimeAdmissionPolicy, SignedRuntimeAdmission,
};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(program: &str, args: &[&str]) {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("OPENSSL_CONF", "/dev/null")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait().unwrap() {
            Some(status) => {
                assert!(status.success(), "fixture crypto failed");
                break;
            }
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("fixture crypto timed out");
            }
        }
    }
}

pub fn sign(policy: &RuntimeAdmissionPolicy) -> (SignedRuntimeAdmission, FixtureAdmissionTrust) {
    let crypto = "/usr/bin/openssl";
    let root = std::env::temp_dir().join(format!(
        "realm-TEST-admission-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let scratch = Scratch(root);
    let path = |name: &str| scratch.0.join(name).to_str().unwrap().to_owned();
    let key = path("TEST-private.pem");
    let public = path("TEST-public.pem");
    let statement = path("TEST-statement");
    let signature = path("TEST-signature");
    run(crypto, &["genrsa", "-out", &key, "3072"]);
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    run(crypto, &["rsa", "-in", &key, "-pubout", "-out", &public]);
    let policy_json = serde_json::to_string(policy).unwrap();
    fs::write(
        &statement,
        realm_v6::runtime_admission::signing_bytes(&policy_json),
    )
    .unwrap();
    run(
        crypto,
        &[
            "dgst", "-sha256", "-sign", &key, "-out", &signature, &statement,
        ],
    );
    let public_key_pem = fs::read(&public).unwrap();
    let key_id = blake3::hash(&public_key_pem).to_hex().to_string();
    let envelope = SignedRuntimeAdmission {
        schema: "realm.signed-runtime-admission/v1".into(),
        reviewer_key_id: key_id.clone(),
        policy_json,
        signature_hex: fs::read(&signature)
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    };
    let trust = FixtureAdmissionTrust {
        key_id,
        public_key_pem,
        crypto_path: crypto.into(),
        crypto_blake3: blake3::hash(&fs::read(crypto).unwrap())
            .to_hex()
            .to_string(),
    };
    // Drop removes all scratch material including the ephemeral private key.
    (envelope, trust)
}
