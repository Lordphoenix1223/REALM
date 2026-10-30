//! Capture-derived development artifacts. No execution authorization, native
//! binding synthesis, destination access, approval or protected application API.
use super::*;
use realm_v6::coding_submission::{CandidateFile, MAX_FILE, PATHS};
use serde_json::Value;

const MAX_INPUT: usize = 512 * 1024;
const NAMES: [&str; 6] = [
    "journal",
    "task_contract",
    "referee_scope",
    "pre_agent_freeze",
    "referee_result",
    "transcript_audit",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentInput {
    schema: String,
    run_label: String,
    files: [CandidateFile; 3],
    evidence: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentExpectations {
    schema: String,
    run_label: String,
    task_sha256: String,
    worker_sha256: String,
    checker_sha256: String,
    checker_scope_sha256: String,
}
#[derive(Debug, Serialize)]
pub struct DevelopmentDisposition {
    pub schema: &'static str,
    pub evidence_class: &'static str,
    pub status: &'static str,
    pub authority: &'static str,
    pub run_label: String,
    pub payload_blake3: String,
    pub expectations_blake3: String,
    pub candidate_files: Vec<Value>,
    pub journal_frames: usize,
    pub checks: Vec<&'static str>,
    pub evidence_blake3: BTreeMap<String, String>,
    pub referee_reported_status: String,
    pub referee_subject_binding: &'static str,
    pub native_admission: &'static str,
    pub detached_registration: String,
    pub production_stages: BTreeMap<&'static str, &'static str>,
    pub realm_artifact: Option<()>,
    pub plan: Option<()>,
    pub approval_id: Option<()>,
    pub application_dispatched: bool,
    pub destination_access: bool,
}
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.is_empty() || bytes.len() > MAX_INPUT {
        return refuse("development input byte bound");
    }
    Ok(serde_json::from_value(diagnostic_json(bytes)?)?)
}
/// Pins authenticate diagnostic input bytes only. Expected identity labels are
/// not execution attestation, policy authorization or a native qualification.
/// This pure function has no filesystem/process operations and returns no cap.
pub fn inspect(
    payload: &[u8],
    payload_pin: &str,
    expectations: &[u8],
    expectations_pin: &str,
) -> Result<DevelopmentDisposition> {
    if !valid_digest(payload_pin)
        || !valid_digest(expectations_pin)
        || digest(payload) != payload_pin
        || digest(expectations) != expectations_pin
    {
        return refuse("development input independent byte pin differs");
    }
    let input: DevelopmentInput = parse(payload)?;
    let expected: DevelopmentExpectations = parse(expectations)?;
    if input.schema != "realm.coding-development-intake.v1"
        || expected.schema != "realm.coding-development-expectations.v1"
        || input.run_label != expected.run_label
        || input.run_label.is_empty()
        || input.run_label.len() > 128
        || !input.run_label.is_ascii()
        || [
            &expected.task_sha256,
            &expected.worker_sha256,
            &expected.checker_sha256,
            &expected.checker_scope_sha256,
        ]
        .iter()
        .any(|v| !valid_digest(v))
    {
        return refuse("development schema/declared identity differs");
    }
    if input.evidence.len() != NAMES.len() || NAMES.iter().any(|n| !input.evidence.contains_key(*n))
    {
        return refuse("six original development evidence members required");
    }
    let mut candidate_files = Vec::new();
    for (file, path) in input.files.iter().zip(PATHS) {
        if file.path != path
            || file.mode != 0o600
            || file.text.is_empty()
            || file.text.len() > MAX_FILE
        {
            return refuse("development candidate projection differs");
        }
        candidate_files.push(serde_json::json!({"path":file.path,"mode":file.mode,"bytes":file.text.len(),"content_blake3":digest(file.text.as_bytes())}));
    }
    let mut frames = 0;
    for line in input.evidence["journal"].lines() {
        let _ = diagnostic_json(line.as_bytes())?;
        frames += 1;
        if frames > 128 {
            return refuse("development journal frame bound");
        }
    }
    if frames == 0 {
        return refuse("development journal absent");
    }
    let values: BTreeMap<_, Value> = input
        .evidence
        .iter()
        .filter(|(name, _)| name.as_str() != "journal")
        .map(|(name, raw)| diagnostic_json(raw.as_bytes()).map(|v| (name.as_str(), v)))
        .collect::<Result<_>>()?;
    let scope = &values["referee_scope"];
    let result = &values["referee_result"];
    let frozen = &values["pre_agent_freeze"];
    let audit = &values["transcript_audit"];
    if frozen["task_sha256"] != expected.task_sha256
        || frozen["authority"] != "NONE"
        || frozen["development_only"] != true
        || values["task_contract"]["authority"] != "NONE"
        || scope["sha256"] != expected.checker_scope_sha256
        || scope["scope"]["original_task_sha256"] != expected.task_sha256
        || scope["scope"]["oracle_worker_sha256"] != expected.worker_sha256
        || scope["scope"]["checker_sha256"] != expected.checker_sha256
        || result["schema"] != "realm.coding-task-referee-result.v1"
        || result["scope"] != scope["scope"]
        || result["scope_sha256"] != expected.checker_scope_sha256
        || result["authority"] != "NONE"
        || result["realm_artifact"] != Value::Null
        || audit["authority"] != "NONE"
        || audit["realm_artifact"] != Value::Null
        || audit["history_complete"] != false
        || audit["execution_authenticated"] != false
        || audit["containment_qualified"] != false
    {
        return refuse("development declared identity/qualification claim differs");
    }
    if result["status"] != "PASS_BOUNDED_PROPERTIES" || result["subject_unchanged"] != true {
        return refuse("development referee does not report bounded unchanged-subject success");
    }
    Ok(DevelopmentDisposition {
        schema: "realm.coding-development-disposition.v1",
        evidence_class: "UNQUALIFIED_DEVELOPMENT",
        status: "INCOMPLETE",
        authority: "NONE",
        run_label: input.run_label,
        payload_blake3: digest(payload),
        expectations_blake3: digest(expectations),
        candidate_files,
        journal_frames: frames,
        checks: vec![
            "PINNED_BYTES_ONLY_NOT_AUTHORITY",
            "CANDIDATE_PROJECTION_FORMAT_ONLY",
            "STRICT_DIAGNOSTIC_JSON_FRAMES_NOT_AUTHENTICATED_HISTORY",
            "DECLARED_IDENTITIES_MATCH_PINNED_EXPECTATIONS",
            "NATIVE_PACKET_NOT_RUN_MISSING_NATIVE_BINDING",
        ],
        evidence_blake3: input
            .evidence
            .iter()
            .map(|(n, r)| (n.clone(), digest(r.as_bytes())))
            .collect(),
        referee_reported_status: "PASS_BOUNDED_PROPERTIES".into(),
        referee_subject_binding: "SHA256_SUBJECT_CLAIMS_NOT_INDEPENDENTLY_VERIFIED_BY_THIS_INTAKE",
        native_admission: "NOT_AVAILABLE_IN_DEVELOPMENT_PREVIEW",
        detached_registration: "REFUSE: development evidence cannot register production semantics"
            .into(),
        production_stages: [
            "native_qualification",
            "canonical_publication",
            "destination_plan",
            "destination_approval",
            "application",
            "final_state_verification",
        ]
        .into_iter()
        .map(|n| (n, "NOT_RUN"))
        .collect(),
        realm_artifact: None,
        plan: None,
        approval_id: None,
        application_dispatched: false,
        destination_access: false,
    })
}

// Diagnostic telemetry legitimately contains timing floats. Do not broaden the
// integer-only production parser. Duplicate keys still refuse at every depth;
// raw bytes, rather than this parsed view, are committed in the disposition.
fn diagnostic_json(bytes: &[u8]) -> Result<Value> {
    use serde::de::{self, MapAccess, SeqAccess, Visitor};
    struct Diagnostic(Value);
    impl<'de> Deserialize<'de> for Diagnostic {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Diagnostic;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("finite diagnostic JSON with unique object keys")
                }
                fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Diagnostic, E> {
                    Ok(Diagnostic(v.into()))
                }
                fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Diagnostic, E> {
                    Ok(Diagnostic(v.into()))
                }
                fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Diagnostic, E> {
                    Ok(Diagnostic(v.into()))
                }
                fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Diagnostic, E> {
                    serde_json::Number::from_f64(v)
                        .map(|n| Diagnostic(Value::Number(n)))
                        .ok_or_else(|| E::custom("nonfinite diagnostic number"))
                }
                fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Diagnostic, E> {
                    Ok(Diagnostic(v.into()))
                }
                fn visit_string<E: de::Error>(
                    self,
                    v: String,
                ) -> std::result::Result<Diagnostic, E> {
                    Ok(Diagnostic(v.into()))
                }
                fn visit_unit<E: de::Error>(self) -> std::result::Result<Diagnostic, E> {
                    Ok(Diagnostic(Value::Null))
                }
                fn visit_seq<A: SeqAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Diagnostic, A::Error> {
                    let mut values = Vec::new();
                    while let Some(Diagnostic(v)) = a.next_element()? {
                        values.push(v);
                    }
                    Ok(Diagnostic(Value::Array(values)))
                }
                fn visit_map<A: MapAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Diagnostic, A::Error> {
                    let mut values = serde_json::Map::new();
                    while let Some((k, Diagnostic(v))) = a.next_entry::<String, Diagnostic>()? {
                        if values.insert(k, v).is_some() {
                            return Err(de::Error::custom("duplicate diagnostic key"));
                        }
                    }
                    Ok(Diagnostic(Value::Object(values)))
                }
            }
            d.deserialize_any(V)
        }
    }
    if bytes.is_empty() || bytes.len() > MAX_INPUT {
        return refuse("diagnostic JSON byte bound");
    }
    serde_json::from_slice::<Diagnostic>(bytes)
        .map(|d| d.0)
        .map_err(|_| {
            ApplyError::Refuse("malformed, duplicate-key or nonfinite diagnostic JSON".into())
        })
}

/// Inspect ordered diagnostic effects. This is consistency checking, not an
/// authenticated observation or a constructor for a native capability.
fn captured_outputs(payload: &[u8]) -> Result<([Vec<u8>; 3], String)> {
    let input: DevelopmentInput = parse(payload)?;
    let audit = diagnostic_json(input.evidence["transcript_audit"].as_bytes())?;
    let referee = diagnostic_json(input.evidence["referee_result"].as_bytes())?;
    let mut state =
        diagnostic_json(input.evidence["task_contract"].as_bytes())?["baseline"].clone();
    let mut previous = "0".repeat(64);
    let mut files = BTreeMap::new();
    let mut checked = false;
    let mut finished = false;
    for (sequence, line) in input.evidence["journal"].lines().enumerate() {
        let row = diagnostic_json(line.as_bytes())?;
        if finished
            || row["sequence"].as_u64() != Some(sequence as u64)
            || row["previous"].as_str() != Some(&previous)
        {
            return refuse("development capture order/closure differs");
        }
        previous = row["sha256"]
            .as_str()
            .filter(|s| valid_digest(s))
            .ok_or_else(|| ApplyError::Refuse("capture head missing".into()))?
            .into();
        let event = &row["event"];
        if sequence == 0 {
            continue;
        }
        if !event["refusal"].is_null() {
            checked = false;
            continue;
        }
        if event["before"] != state {
            return refuse("development capture state differs");
        }
        let request = &event["request"];
        match request["tool"].as_str() {
            Some("write") => {
                let name = request["path"]
                    .as_str()
                    .ok_or_else(|| ApplyError::Refuse("capture path missing".into()))?;
                let text = request["text"]
                    .as_str()
                    .ok_or_else(|| ApplyError::Refuse("capture text missing".into()))?;
                if !PATHS.contains(&name) || text.len() > MAX_FILE {
                    return refuse("captured effect outside scope");
                }
                files.insert(name.to_owned(), text.as_bytes().to_vec());
                checked = false;
            }
            Some("check") => checked = event["result"]["passed"] == true,
            Some("finish") => {
                if !checked
                    || event["result"]["status"] != "DEVELOPMENT_TASK_CHECKED"
                    || event["result"]["authority"] != "NONE"
                    || event["result"]["files"] != state
                {
                    return refuse("development finish lacks exact checked state");
                }
                finished = true;
            }
            Some("read" | "list") => {}
            _ => return refuse("unsupported captured tool"),
        }
        if request["tool"] != "write" && event["after"] != state {
            return refuse("unexpected captured mutation");
        }
        state = event["after"].clone();
    }
    if !finished
        || audit["finished"] != true
        || audit["journal_head"] != previous
        || audit["files"] != state
    {
        return refuse("missing or cross-run terminal capture");
    }
    let mut outputs = [Vec::new(), Vec::new(), Vec::new()];
    for (i, path) in PATHS.iter().enumerate() {
        let bytes = files
            .remove(*path)
            .ok_or_else(|| ApplyError::Refuse("all three captured writes required".into()))?;
        if input.files[i].text.as_bytes() != bytes
            || referee["subject"][path]["sha256"] != state[path]
            || referee["subject"][path]["bytes"].as_u64() != Some(bytes.len() as u64)
        {
            return refuse("projection/referee differs from captured effects");
        }
        outputs[i] = bytes;
    }
    Ok((outputs, previous))
}

const DEVELOPMENT_RUNTIME: &str = "UNQUALIFIED_DEVELOPMENT_CAPTURE";

/// Serialize the original capture through the existing encoder. Never publishes
/// or grants authority. Outputs come from captured writes, not a candidate path.
pub fn pack_capture(
    payload: &[u8],
    payload_pin: &str,
    expectations: &[u8],
    expectations_pin: &str,
) -> Result<Vec<u8>> {
    use crate::*;
    inspect(payload, payload_pin, expectations, expectations_pin)?;
    let (files, head) = captured_outputs(payload)?;
    let input: DevelopmentInput = parse(payload)?;
    let commit = |identity: &str, bytes: &[u8]| Commitment {
        identity: identity.into(),
        digest: hash(identity, bytes),
    };
    let mut bundle = ArtifactBundle::new(RealmRun {
        schema_version: SCHEMA_VERSION,
        lifecycle: Lifecycle::Frozen,
        run: RunIdentity {
            run_id: input.run_label.clone(),
            execution_id: head.clone(),
        },
        challenge: Challenge {
            nonce: Some(hash(DEVELOPMENT_RUNTIME, payload)),
            issued_by: DEVELOPMENT_RUNTIME.into(),
            expires_at: None,
        },
        intent: commit(
            "development-task",
            input.evidence["task_contract"].as_bytes(),
        ),
        starting_state: commit(
            "development-baseline",
            input.evidence["task_contract"].as_bytes(),
        ),
        environment: EnvironmentIdentity {
            runtime: DEVELOPMENT_RUNTIME.into(),
            runtime_digest: hash(DEVELOPMENT_RUNTIME, payload),
            backend: "kernel-child-development-only".into(),
            architecture: "unqualified".into(),
        },
        effect_contract: commit(
            DEVELOPMENT_RUNTIME,
            b"NO EXECUTION OR DESTINATION AUTHORITY",
        ),
        inputs: vec![],
        outputs: vec![],
        checkpoints: vec![],
        observations: vec![],
        proposed_effects: vec![],
        unknown_effects: vec![],
        evidence: vec![],
        claims: vec![],
        final_state: Some(commit("development-transcript-head", head.as_bytes())),
        seal: None,
    });
    for raw in [payload, expectations] {
        let blob = bundle.add_blob(raw.to_vec(), "application/json");
        bundle.run.inputs.push(blob);
    }
    for name in NAMES {
        let raw = input.evidence[name].as_bytes();
        let blob = bundle.add_blob(raw.to_vec(), "application/json");
        bundle.run.evidence.push(EvidenceRef {
            id: name.into(),
            evidence_type: "UNAUTHENTICATED_DEVELOPMENT_RECORD".into(),
            digest: blob.digest,
            size: Some(raw.len() as u64),
            run_id: input.run_label.clone(),
            checkpoint: None,
            supports: vec![],
            authoritative: false,
        });
    }
    for bytes in files {
        let blob = bundle.add_blob(bytes, "text/x-python");
        bundle.run.outputs.push(blob);
    }
    bundle
        .seal()
        .map_err(|e| ApplyError::Refuse(e.to_string()))?;
    bundle.pack().map_err(|e| ApplyError::Refuse(e.to_string()))
}

/// Reopen and reconstruct the same diagnostic artifact independently. No
/// destination parameter, capability or application route is exposed.
pub fn inspect_capture(
    bytes: &[u8],
    artifact_pin: &str,
    expectations: &[u8],
    expectations_pin: &str,
) -> Result<DevelopmentDisposition> {
    if bytes.len() > 2 * 1024 * 1024 || digest(bytes) != artifact_pin {
        return refuse("development artifact pin/size differs");
    }
    let bundle = ArtifactBundle::unpack(bytes).map_err(|e| ApplyError::Refuse(e.to_string()))?;
    if bundle.run.inputs.len() != 2 || bundle.run.environment.runtime != DEVELOPMENT_RUNTIME {
        return refuse("not a development capture");
    }
    let payload = bundle
        .blobs
        .get(&bundle.run.inputs[0].digest.value)
        .ok_or_else(|| ApplyError::Refuse("capture payload missing".into()))?;
    let reproduced = pack_capture(payload, &digest(payload), expectations, expectations_pin)?;
    if reproduced != bytes {
        return refuse("development artifact evidence/output reconstruction differs");
    }
    inspect(payload, &digest(payload), expectations, expectations_pin)
}

/// Export original diagnostic bytes for the separate transcript auditor. The
/// caller must still independently verify the original contract and journal.
pub fn capture_payload(
    bytes: &[u8],
    pin: &str,
    expectations: &[u8],
    expectations_pin: &str,
) -> Result<Vec<u8>> {
    inspect_capture(bytes, pin, expectations, expectations_pin)?;
    let bundle = ArtifactBundle::unpack(bytes).map_err(|e| ApplyError::Refuse(e.to_string()))?;
    Ok(bundle.blobs[&bundle.run.inputs[0].digest.value].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn floats_are_diagnostic_only_and_ambiguous_frames_refuse() {
        assert!(diagnostic_json(br#"{"seconds":0.125,"nested":[1,true,null]}"#).is_ok());
        assert!(parse::<DevelopmentInput>(br#"{"seconds":0.125}"#).is_err());
        for bad in [
            br#"{"x":{"id":1,"id":2}}"#.as_slice(),
            br#"{"x":NaN}"#,
            br#"{"x":1e999}"#,
        ] {
            assert!(diagnostic_json(bad).is_err());
        }
    }
    #[test]
    fn byte_pins_and_production_fields_cannot_be_waived() {
        assert!(inspect(b"{}", "", b"{}", "").is_err());
        let p=br#"{"schema":"realm.coding-development-intake.v1","run_label":"test","files":[],"evidence":{},"destination":"/must-not-open"}"#;
        let e = b"{}";
        assert!(inspect(p, &digest(p), e, &digest(e)).is_err());
    }
}
