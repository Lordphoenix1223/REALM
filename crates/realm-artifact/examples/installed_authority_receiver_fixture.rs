//! TEST-only data harness. Never constructs ReviewedRuntimeAdmission or QFR.
use realm_v6::runtime_admission as a;
use serde_json::{Value, json};
use std::path::Path;
fn run() -> Result<Value, String> {
    let v: Vec<String> = std::env::args().skip(1).collect();
    match v.as_slice() {
        [c] if c == "candidate" => {
            serde_json::to_value(a::fixture_candidate().policy).map_err(|e| e.to_string())
        }
        [c, p] if c == "hash" => Ok(json!(
            blake3::hash(&std::fs::read(p).map_err(|e| e.to_string())?)
                .to_hex()
                .to_string()
        )),
        [c, p, h] if c == "exe-join" => a::fixture_check_executable(Path::new(p), Path::new(h)),
        [c, p] if c == "inspect" => a::inspect_fixture_setup(Path::new(p)),
        [c, p] if c == "issue" => {
            serde_json::to_value(a::fixture_issue_installed_statement(Path::new(p))?)
                .map_err(|e| e.to_string())
        }
        [c, p, f] if c == "verify" => {
            let raw = std::fs::read(f).map_err(|e| e.to_string())?;
            let x: a::SignedRuntimeAdmission = serde_json::from_value(
                realm_v6::strict_json::parse(&raw).map_err(|_| "strict fixture statement")?,
            )
            .map_err(|e| e.to_string())?;
            a::check_fixture_installed_statement(Path::new(p), &x)
        }
        [c, f] if c == "production-verify" => {
            let x: a::SignedRuntimeAdmission =
                serde_json::from_slice(&std::fs::read(f).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            Ok(json!({"authority":"NONE","policy":x.verify()?}))
        }
        [c, p, f] if c == "integrate" => {
            let raw = std::fs::read(f).map_err(|e| e.to_string())?;
            let issued: a::SignedRuntimeAdmission = serde_json::from_value(
                realm_v6::strict_json::parse(&raw).map_err(|_| "strict TEST admission")?,
            )
            .map_err(|e| e.to_string())?;
            let mut candidate = a::fixture_candidate();
            candidate.policy = issued.policy()?;
            let bundle = a::finish_fixture(candidate, issued);
            let wire = serde_json::to_vec(&bundle.semantic).map_err(|e| e.to_string())?;
            let decoded = realm_artifact::host_apply::coding_qualification::decode_receipt(&wire)
                .map_err(|e| e.to_string())?;
            // Receiver-selected full statement and public trust are read independently
            // from the producer's portable receipt, never selected by the candidate.
            let permitted: a::SignedRuntimeAdmission =
                serde_json::from_slice(&std::fs::read(f).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let public =
                std::fs::read(Path::new(p).join("public.pem")).map_err(|e| e.to_string())?;
            let trust = a::FixtureAdmissionTrust {
                key_id: blake3::hash(&public).to_hex().to_string(),
                public_key_pem: public,
                crypto_path: "/usr/bin/openssl".into(),
                crypto_blake3: blake3::hash(
                    &std::fs::read("/usr/bin/openssl").map_err(|e| e.to_string())?,
                )
                .to_hex()
                .to_string(),
            };
            let verdict = a::check_fixture_receipt(&decoded, &permitted, &trust)?;
            if realm_artifact::host_apply::coding_qualification::check_receipt(&decoded, &permitted)
                .is_ok()
            {
                return Err("TEST statement acquired production trust".into());
            }
            Ok(
                json!({"authority":"NONE","evidence_class":"TEST_ONLY_AUTO_ISSUER_TO_RECEIVER","receiver":verdict,"receipt":decoded,"production_verification":"REFUSE","realm_artifact":null,"destination_access":false}),
            )
        }
        [c] if c == "production-issue" => {
            Ok(json!({"authority":"NONE","statement":a::issue_installed_admission()?}))
        }
        _ => Err("unsupported fixture harness arguments".into()),
    }
}
fn main() {
    match run() {
        Ok(v) => println!("{}", serde_json::to_string(&v).unwrap()),
        Err(e) => {
            eprintln!("REFUSE: {e}");
            std::process::exit(1)
        }
    }
}
