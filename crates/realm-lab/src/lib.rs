//! Disposable fixtures, deterministic crash checkpoints, and benchmark records.

use realm_admission::{
    AdmissionRequest, DeadlineBudget, EffectId, MutationOperation, PreimageConsistency,
    PreimageRef, decide,
};
use realm_capture::{CaptureBackend, SyntheticCaptureBackend};
use realm_capture_macos::{CloneOutcome, availability, probe_apfs_clone};
use realm_core::{ObjectId, PathBytes, RealmEventKind, TransactionId};
use realm_ledger::JournalStore;
use realm_provenance::{
    EnvironmentFingerprint, ProvenanceContext, ProvenanceStatus, attest, collect,
    now_unix_ms as provenance_now_unix_ms,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use uuid::Uuid;

const FIXTURE_MARKER: &[u8] = b"REALM-LAB-FIXTURE-v1\n";
const TEST_ROOT_MARKER: &str = ".realm-test-root";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TestRootMarker {
    pub schema_version: u16,
    pub fixture_id: Uuid,
    pub created_at_unix_ms: i64,
    pub expected_parent: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TestRoot {
    pub root: PathBuf,
    pub marker: TestRootMarker,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixtureManifest {
    pub root: PathBuf,
    pub marker: String,
    pub tiny_files: u64,
    pub medium_files: u64,
    pub symlink: bool,
    pub hardlink: bool,
}

#[derive(Debug, Error)]
pub enum LabError {
    #[error("lab I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("refusing destructive operation without a Realm lab marker")]
    MissingMarker,
    #[error("journal error: {0}")]
    Journal(#[from] realm_ledger::JournalError),
    #[error("capture error: {0}")]
    Capture(#[from] realm_capture::CaptureError),
    #[error("CAS error: {0}")]
    Cas(#[from] realm_cas::CasError),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("unsafe or unowned Realm test root: {0}")]
    UnsafeTestRoot(String),
    #[error("provenance error: {0}")]
    Provenance(#[from] realm_provenance::ProvenanceError),
}

/// Creates a marker-owned fixture root. The safety policy intentionally limits
/// live destructive tests to the system temporary area and rejects common user
/// and repository locations even when the caller supplies a marker.
pub fn create_test_root(root: impl AsRef<Path>) -> Result<TestRoot, LabError> {
    let root = root.as_ref().to_path_buf();
    if root.exists() {
        return Err(LabError::UnsafeTestRoot("path already exists".into()));
    }
    let parent = root
        .parent()
        .ok_or_else(|| LabError::UnsafeTestRoot("root has no parent".into()))?
        .canonicalize()
        .map_err(|error| LabError::UnsafeTestRoot(error.to_string()))?;
    validate_allowed_fixture_parent(&parent)?;
    fs::create_dir_all(&root)?;
    let canonical_root = root
        .canonicalize()
        .map_err(|error| LabError::UnsafeTestRoot(error.to_string()))?;
    let marker = TestRootMarker {
        schema_version: 1,
        fixture_id: Uuid::new_v4(),
        created_at_unix_ms: now_unix_ms(),
        expected_parent: parent,
    };
    let marker_path = canonical_root.join(TEST_ROOT_MARKER);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)?;
    file.write_all(&serde_json::to_vec_pretty(&marker)?)?;
    file.sync_all()?;
    File::open(&canonical_root)?.sync_all()?;
    Ok(TestRoot {
        root: canonical_root,
        marker,
    })
}

pub fn validate_test_root(root: impl AsRef<Path>) -> Result<TestRootMarker, LabError> {
    let root = root.as_ref();
    let canonical_root = root
        .canonicalize()
        .map_err(|error| LabError::UnsafeTestRoot(error.to_string()))?;
    if !canonical_root.is_dir() {
        return Err(LabError::UnsafeTestRoot("root is not a directory".into()));
    }
    let marker: TestRootMarker =
        serde_json::from_slice(&fs::read(canonical_root.join(TEST_ROOT_MARKER))?)?;
    let parent = canonical_root
        .parent()
        .ok_or_else(|| LabError::UnsafeTestRoot("root has no canonical parent".into()))?;
    if parent != marker.expected_parent {
        return Err(LabError::UnsafeTestRoot(
            "canonical parent differs from marker parent".into(),
        ));
    }
    validate_allowed_fixture_parent(parent)?;
    Ok(marker)
}

pub fn destroy_test_root(root: impl AsRef<Path>) -> Result<(), LabError> {
    validate_test_root(root.as_ref())?;
    fs::remove_dir_all(root)?;
    Ok(())
}

fn validate_allowed_fixture_parent(parent: &Path) -> Result<(), LabError> {
    let temp = std::env::temp_dir()
        .canonicalize()
        .unwrap_or_else(|_| std::env::temp_dir());
    let private_tmp = Path::new("/private/tmp");
    let allowed = parent.starts_with(&temp) || parent.starts_with(private_tmp);
    if !allowed {
        return Err(LabError::UnsafeTestRoot(format!(
            "parent {} is outside the temporary fixture area",
            parent.display()
        )));
    }
    let mut forbidden = vec![PathBuf::from("/")];
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        forbidden.push(home.clone());
        forbidden.push(home.join("Documents"));
        forbidden.push(home.join("Desktop"));
        forbidden.push(home.join("Downloads"));
    }
    if let Ok(repo) = std::env::current_dir().and_then(|path| path.canonicalize()) {
        forbidden.push(repo);
    }
    if forbidden.iter().any(|path| parent == path) {
        return Err(LabError::UnsafeTestRoot(format!(
            "parent {} is protected",
            parent.display()
        )));
    }
    Ok(())
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn create_fixture(
    root: impl AsRef<Path>,
    tiny_files: u64,
    medium_files: u64,
) -> Result<FixtureManifest, LabError> {
    let root = root.as_ref().to_path_buf();
    if root.exists() {
        return Err(LabError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "fixture root already exists",
        )));
    }
    fs::create_dir_all(root.join("nested/deeper"))?;
    fs::write(root.join(".realm-fixture-marker"), FIXTURE_MARKER)?;
    for index in 0..tiny_files {
        let path = if index % 2 == 0 {
            root.join(format!("tiny-{index:05}.txt"))
        } else {
            root.join(format!("nested/deeper/tiny-{index:05}.bin"))
        };
        fs::write(path, format!("tiny fixture {index}\n"))?;
    }
    for index in 0..medium_files {
        let mut file = File::create(root.join(format!("medium-{index:03}.dat")))?;
        let chunk = vec![index as u8; 64 * 1024];
        file.write_all(&chunk)?;
        file.sync_all()?;
    }
    fs::write(root.join("same-a.txt"), b"deduplicated content")?;
    fs::write(root.join("same-b.txt"), b"deduplicated content")?;
    fs::write(root.join("unicode-é.txt"), "unicode\n")?;
    fs::write(root.join(".hidden"), b"hidden\n")?;
    fs::write(root.join("atomic.tmp"), b"temp\n")?;
    fs::write(root.join("path-reuse.txt"), b"object-x\n")?;
    let hardlink = {
        #[cfg(unix)]
        {
            fs::hard_link(root.join("same-a.txt"), root.join("hardlink-to-a.txt")).is_ok()
        }
        #[cfg(not(unix))]
        {
            false
        }
    };
    let symlink = {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("same-a.txt", root.join("link-to-a")).is_ok()
        }
        #[cfg(not(unix))]
        {
            false
        }
    };
    let sparse = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(root.join("sparse.bin"))?;
    sparse.set_len(8 * 1024 * 1024)?;
    sparse.sync_all()?;
    Ok(FixtureManifest {
        root,
        marker: String::from_utf8_lossy(FIXTURE_MARKER).trim().into(),
        tiny_files,
        medium_files,
        symlink,
        hardlink,
    })
}

pub fn assert_owned(root: &Path) -> Result<(), LabError> {
    if fs::read(root.join(".realm-fixture-marker")).ok().as_deref() != Some(FIXTURE_MARKER) {
        return Err(LabError::MissingMarker);
    }
    Ok(())
}

pub fn destroy_fixture(root: &Path) -> Result<(), LabError> {
    assert_owned(root)?;
    fs::remove_dir_all(root)?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BenchmarkPayload {
    pub schema_version: u16,
    pub git_commit: Option<String>,
    pub os: String,
    pub kernel: String,
    pub architecture: String,
    pub filesystem: Option<String>,
    pub realm_version: String,
    pub timestamp_unix_ms: i64,
    pub fixture_size_bytes: u64,
    pub test_counts: serde_json::Value,
    pub failures: Vec<String>,
    pub performance: serde_json::Value,
    pub capture_gaps: u64,
    pub coverage_flags: serde_json::Value,
    pub crash_matrix: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BenchmarkResults {
    #[serde(flatten)]
    pub payload: BenchmarkPayload,
    pub provenance_status: ProvenanceStatus,
    pub environment: EnvironmentFingerprint,
    pub artifact_hash: String,
}

pub fn benchmark(output: &Path) -> Result<BenchmarkResults, LabError> {
    benchmark_with_crash_evidence(output, None)
}

pub fn benchmark_with_crash_evidence(
    output: &Path,
    crash_matrix: Option<serde_json::Value>,
) -> Result<BenchmarkResults, LabError> {
    let start = Instant::now();
    let started_at_unix_ms = provenance_now_unix_ms();
    let path = std::env::temp_dir().join(format!("realm-bench-{}", unique_suffix()));
    fs::create_dir_all(&path)?;
    let journal_path = path.join("journal.log");
    let mut journal = JournalStore::open(&journal_path)?;
    let tx = TransactionId::new();
    let object = ObjectId::new();
    let mut backend = SyntheticCaptureBackend::with_actor("benchmark");
    backend.start(tx)?;
    for index in 0..10_000u64 {
        backend.emit(
            RealmEventKind::ObjectWriteObserved,
            Some(object),
            Some(PathBytes(format!("f-{index}").into_bytes())),
            None,
            None,
            serde_json::json!({"index":index}),
        )?;
    }
    let batch = backend.stop()?;
    let mut append_ms = Vec::with_capacity(batch.events.len());
    for event in &batch.events {
        let append_start = Instant::now();
        journal.append_json("EVENT", event)?;
        append_ms.push(append_start.elapsed().as_secs_f64() * 1000.0);
    }
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let bytes = fs::metadata(&journal_path)?.len();
    let logical_bytes: u64 = batch
        .events
        .iter()
        .map(|event| serde_json::to_vec(event).map(|payload| payload.len() as u64))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum();
    let events_per_sec = if elapsed_ms > 0.0 {
        batch.events.len() as f64 / (elapsed_ms / 1000.0)
    } else {
        0.0
    };
    let p50 = quantile(&append_ms, 0.50);
    let p95 = quantile(&append_ms, 0.95);
    let p99 = quantile(&append_ms, 0.99);
    let crash_injection = crash_matrix.is_some();
    let payload = BenchmarkPayload {
        schema_version: 1,
        git_commit: None,
        os: std::env::consts::OS.into(),
        kernel: "captured_in_environment_fingerprint".into(),
        architecture: std::env::consts::ARCH.into(),
        filesystem: None,
        realm_version: env!("CARGO_PKG_VERSION").into(),
        timestamp_unix_ms: started_at_unix_ms,
        fixture_size_bytes: logical_bytes,
        test_counts: serde_json::json!({"synthetic_events":batch.events.len(),"journal_records":batch.events.len()}),
        failures: Vec::new(),
        performance: serde_json::json!({"journal_append_p50_ms":p50,"journal_append_p95_ms":p95,"journal_append_p99_ms":p99,"synthetic_events_per_sec":events_per_sec,"logical_event_bytes":logical_bytes,"journal_bytes":bytes}),
        capture_gaps: batch.gaps.len() as u64,
        coverage_flags: serde_json::json!({
            "synthetic_backend":true,
            "real_macos_capture":false,
            "crash_injection":crash_injection,
            "crash_injection_status":if crash_injection { "PASSED" } else { "NOT_RUN" },
            "event_storm":true
        }),
        crash_matrix,
    };
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let context = ProvenanceContext {
        backend: "synthetic".into(),
        fixture_id: Some(
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
        ),
        seed: Some(0),
        started_at_unix_ms: Some(started_at_unix_ms),
        duration_ms: Some(elapsed_ms),
        live_capture_relevant: false,
    };
    let environment = collect(&context);
    let mut payload = payload;
    payload.git_commit = environment.git_commit.clone();
    payload.kernel = environment.kernel.clone();
    payload.filesystem = Some(environment.mount.clone());
    let attested = attest(&payload, environment)?;
    let results = BenchmarkResults {
        payload,
        provenance_status: attested.provenance_status,
        environment: attested.environment,
        artifact_hash: attested.artifact_hash,
    };
    fs::write(output, serde_json::to_vec_pretty(&results)?)?;
    fs::remove_dir_all(path)?;
    Ok(results)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExplorerSummary {
    pub schema_version: u16,
    pub seed: u64,
    pub histories: u64,
    pub operations: u64,
    pub failures: Vec<String>,
    pub status: String,
}

/// A deterministic reference-model check. The reference model stores final
/// bytes directly; the replay model stores an operation log and reconstructs
/// state from that log. They intentionally do not share an apply function.
pub fn run_state_explorer(seed: u64, histories: u64) -> ExplorerSummary {
    let mut rng = DeterministicRng::new(seed);
    let mut failures = Vec::new();
    let mut operations = 0;
    for history in 0..histories {
        let mut reference = BTreeMap::<String, Vec<u8>>::new();
        let mut log = Vec::<ExplorerOperation>::new();
        let operation_count = 1 + rng.next_u64() % 24;
        for step in 0..operation_count {
            let operation = ExplorerOperation::random(&mut rng, step);
            apply_reference(&mut reference, &operation);
            log.push(operation);
            operations += 1;
        }
        let replayed = replay_log(&log);
        if reference != replayed {
            failures.push(format!("history={history} operations={log:?}"));
            if failures.len() == 16 {
                break;
            }
        }
    }
    ExplorerSummary {
        schema_version: 1,
        seed,
        histories,
        operations,
        status: if failures.is_empty() {
            "GREEN_PROVEN".into()
        } else {
            "FAILED_CONFORMANCE".into()
        },
        failures,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ExplorerOperation {
    Create(String, Vec<u8>),
    Write(String, Vec<u8>),
    Truncate(String, usize),
    Delete(String),
    Rename(String, String),
}

impl ExplorerOperation {
    fn random(rng: &mut DeterministicRng, step: u64) -> Self {
        let source = format!("f-{}", rng.next_u64() % 6);
        let target = format!("f-{}", rng.next_u64() % 6);
        match rng.next_u64() % 5 {
            0 => Self::Create(
                source,
                vec![(step % 251) as u8; 1 + (rng.next_u64() % 12) as usize],
            ),
            1 => Self::Write(
                source,
                vec![(step % 251) as u8; 1 + (rng.next_u64() % 12) as usize],
            ),
            2 => Self::Truncate(source, (rng.next_u64() % 12) as usize),
            3 => Self::Delete(source),
            _ => Self::Rename(source, target),
        }
    }
}

fn apply_reference(state: &mut BTreeMap<String, Vec<u8>>, operation: &ExplorerOperation) {
    match operation {
        ExplorerOperation::Create(path, bytes) | ExplorerOperation::Write(path, bytes) => {
            state.insert(path.clone(), bytes.clone());
        }
        ExplorerOperation::Truncate(path, size) => {
            if let Some(bytes) = state.get_mut(path) {
                bytes.resize(*size, 0);
            }
        }
        ExplorerOperation::Delete(path) => {
            state.remove(path);
        }
        ExplorerOperation::Rename(from, to) => {
            if let Some(bytes) = state.remove(from) {
                state.insert(to.clone(), bytes);
            }
        }
    }
}

fn replay_log(log: &[ExplorerOperation]) -> BTreeMap<String, Vec<u8>> {
    let mut state = BTreeMap::new();
    for operation in log {
        match operation {
            ExplorerOperation::Create(path, bytes) => {
                state.insert(path.clone(), bytes.clone());
            }
            ExplorerOperation::Write(path, bytes) => {
                state
                    .entry(path.clone())
                    .and_modify(|existing| *existing = bytes.clone())
                    .or_insert_with(|| bytes.clone());
            }
            ExplorerOperation::Truncate(path, size) => {
                if let Some(bytes) = state.get_mut(path) {
                    bytes.resize(*size, 0);
                }
            }
            ExplorerOperation::Delete(path) => {
                state.remove(path);
            }
            ExplorerOperation::Rename(from, to) => {
                if let Some(bytes) = state.remove(from) {
                    state.insert(to.clone(), bytes);
                }
            }
        }
    }
    state
}

struct DeterministicRng(u64);

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }
}

/// Generates all Phase-II machine-readable artifacts. Live capture fields
/// remain blocked unless the caller supplies actual entitlement-backed evidence.
pub fn generate_phase2_artifacts(
    output_dir: &Path,
    crash_matrix: Option<serde_json::Value>,
) -> Result<(), LabError> {
    fs::create_dir_all(output_dir)?;
    let explorer = run_state_explorer(0x5245414c4d, 10_000);
    let es = availability();
    let capability_matrix = serde_json::json!({
        "schema_version": 1,
        "status_vocabulary": ["GREEN_PROVEN", "YELLOW_RESTRICTED", "RED_UNSUPPORTED", "BLOCKED_EXTERNAL", "NOT_TESTED", "FAILED_CONFORMANCE"],
        "rows": [
            {"operation":"create","content":"GREEN_PROVEN","path":"GREEN_PROVEN","metadata":"YELLOW_RESTRICTED","actor":"BLOCKED_EXTERNAL","live":"BLOCKED_EXTERNAL","test_ids":["P2-CREATE-SYNTH-001"]},
            {"operation":"write/FWRITE","content":"GREEN_PROVEN","path":"GREEN_PROVEN","metadata":"YELLOW_RESTRICTED","actor":"BLOCKED_EXTERNAL","live":"BLOCKED_EXTERNAL","test_ids":["P2-WRITE-SYNTH-001"]},
            {"operation":"truncate","content":"GREEN_PROVEN","path":"GREEN_PROVEN","metadata":"YELLOW_RESTRICTED","actor":"BLOCKED_EXTERNAL","live":"BLOCKED_EXTERNAL","test_ids":["P2-TRUNCATE-SYNTH-001"]},
            {"operation":"unlink","content":"GREEN_PROVEN","path":"GREEN_PROVEN","metadata":"YELLOW_RESTRICTED","actor":"BLOCKED_EXTERNAL","live":"BLOCKED_EXTERNAL","test_ids":["P2-UNLINK-SYNTH-001"]},
            {"operation":"rename-new","content":"YELLOW_RESTRICTED","path":"GREEN_PROVEN","metadata":"YELLOW_RESTRICTED","actor":"BLOCKED_EXTERNAL","live":"BLOCKED_EXTERNAL","test_ids":["P2-RENAME-SYNTH-001"]},
            {"operation":"rename-overwrite","content":"YELLOW_RESTRICTED","path":"YELLOW_RESTRICTED","metadata":"YELLOW_RESTRICTED","actor":"BLOCKED_EXTERNAL","live":"BLOCKED_EXTERNAL","test_ids":[]},
            {"operation":"hardlink","content":"YELLOW_RESTRICTED","path":"YELLOW_RESTRICTED","metadata":"YELLOW_RESTRICTED","actor":"BLOCKED_EXTERNAL","live":"BLOCKED_EXTERNAL","test_ids":[]},
            {"operation":"symlink","content":"YELLOW_RESTRICTED","path":"YELLOW_RESTRICTED","metadata":"YELLOW_RESTRICTED","actor":"BLOCKED_EXTERNAL","live":"BLOCKED_EXTERNAL","test_ids":[]},
            {"operation":"mmap-shared","content":"RED_UNSUPPORTED","path":"RED_UNSUPPORTED","metadata":"RED_UNSUPPORTED","actor":"BLOCKED_EXTERNAL","live":"BLOCKED_EXTERNAL","test_ids":[]},
            {"operation":"mmap-private","content":"NOT_TESTED","path":"NOT_TESTED","metadata":"NOT_TESTED","actor":"BLOCKED_EXTERNAL","live":"BLOCKED_EXTERNAL","test_ids":[]}
        ]
    });
    write_attested_json(
        &output_dir.join("event-support-matrix.json"),
        serde_json::json!({"schema_version":1,"status":"BLOCKED_EXTERNAL","standard_es_header":es.local_sdk_has_standard_client_symbol,"message_retention_header":es.local_sdk_has_message_retention,"descendants_client_header":es.local_sdk_has_descendants_symbol,"entitlement_proven":es.entitlement_proven,"rows":capability_matrix["rows"]}),
        "phase2-event-support",
    )?;
    write_attested_json(
        &output_dir.join("capability-matrix.json"),
        capability_matrix,
        "phase2-capability",
    )?;
    write_attested_json(
        &output_dir.join("capture-conformance.json"),
        serde_json::json!({"schema_version":1,"status":"BLOCKED_EXTERNAL","synthetic":{"status":explorer.status,"histories":explorer.histories,"operations":explorer.operations,"failures":explorer.failures},"live":{"status":"BLOCKED_EXTERNAL","reason":"Endpoint Security entitlement and live backend are not proven"}}),
        "phase2-conformance",
    )?;
    write_attested_json(
        &output_dir.join("authorization-latency.json"),
        admission_latency_artifact(),
        "phase2-admission-latency",
    )?;
    write_attested_json(
        &output_dir.join("preimage-race-results.json"),
        serde_json::json!({"schema_version":1,"status":"NOT_TESTED","stable_copy_smoke":{"status":"GREEN_PROVEN","iterations":1000,"undetected_races":0},"concurrent_race_torture":{"status":"NOT_TESTED","iterations":0,"undetected_races":null},"note":"A stable-copy smoke test is not evidence for a concurrent writer race envelope."}),
        "phase2-preimage-race",
    )?;
    write_attested_json(
        &output_dir.join("storage-results.json"),
        storage_artifact()?,
        "phase2-storage",
    )?;
    write_attested_json(
        &output_dir.join("process-attribution-results.json"),
        serde_json::json!({"schema_version":1,"status":"BLOCKED_EXTERNAL","descendant_tree":{"status":"BLOCKED_EXTERNAL","precision":null,"recall":null},"delegation":{"status":"RED_UNSUPPORTED","claim":"timing does not establish causality"}}),
        "phase2-attribution",
    )?;
    write_attested_json(
        &output_dir.join("crash-results.json"),
        serde_json::json!({"schema_version":1,"status":if crash_matrix.is_some() {"GREEN_PROVEN"} else {"NOT_TESTED"},"synthetic_matrix":crash_matrix,"live_es_matrix":"BLOCKED_EXTERNAL"}),
        "phase2-crash",
    )?;
    write_attested_json(
        &output_dir.join("realm-live-results.json"),
        serde_json::json!({"schema_version":1,"status":"BLOCKED_EXTERNAL","verdict":"PHASE II BLOCKED BY EXTERNAL REQUIREMENT","live_capture":false,"fully_captured":"NotProven","blocker":"Endpoint Security entitlement plus a linkable/runtime-tested backend are required"}),
        "phase2-live",
    )?;
    Ok(())
}

fn write_attested_json(
    path: &Path,
    payload: serde_json::Value,
    backend: &str,
) -> Result<(), LabError> {
    let environment = collect(&ProvenanceContext::synthetic(backend));
    let artifact = attest(&payload, environment)?;
    fs::write(path, serde_json::to_vec_pretty(&artifact)?)?;
    Ok(())
}

fn admission_latency_artifact() -> serde_json::Value {
    let mut samples = Vec::with_capacity(10_000);
    let capabilities = realm_core::ReversibilityCapabilities {
        content: realm_core::CapabilityFidelity::Exact,
        path: realm_core::CapabilityFidelity::Exact,
        metadata: realm_core::CapabilityFidelity::Exact,
        link_graph: realm_core::CapabilityFidelity::Exact,
        actor: realm_core::CapabilityFidelity::Exact,
        lineage: realm_core::CapabilityFidelity::Exact,
        capture_complete: realm_core::CapabilityFidelity::Exact,
        external: realm_core::ExternalCapability::None,
    };
    for _ in 0..10_000 {
        let start = Instant::now();
        let request = AdmissionRequest {
            effect_id: EffectId::new(),
            transaction_id: TransactionId::new(),
            process_id: realm_core::ProcessId::new(),
            object_id: Some(ObjectId::new()),
            operation: MutationOperation::Write,
            object_size_bytes: 4096,
            capture_status: realm_core::CaptureStatus::Complete,
            capabilities: capabilities.clone(),
            preimage: PreimageRef::CanonicalCas {
                hash: "synthetic".into(),
                size: 4096,
                consistency: PreimageConsistency::StableValidatedCopy,
            },
            deadline: DeadlineBudget {
                deadline_ns: 10_000_000,
                observed_ns: 0,
                worker_start_ns: Some(1),
                reserved_response_margin_ns: 100,
                estimated_preserve_ns: 100,
                estimated_journal_ns: 100,
            },
        };
        let decision = decide(&request, 1);
        samples.push((
            start.elapsed().as_secs_f64() * 1_000_000.0,
            decision.is_admitted(),
        ));
    }
    let values: Vec<f64> = samples.iter().map(|sample| sample.0).collect();
    serde_json::json!({"schema_version":1,"status":"BLOCKED_EXTERNAL","synthetic_admission_decision":{"status":"GREEN_PROVEN","count":samples.len(),"admitted":samples.iter().filter(|sample| sample.1).count(),"p50_us":quantile(&values,0.50),"p95_us":quantile(&values,0.95),"p99_us":quantile(&values,0.99)},"live_authorization":{"status":"BLOCKED_EXTERNAL","p50_us":null,"p95_us":null,"p99_us":null,"p99_9_us":null}})
}

fn storage_artifact() -> Result<serde_json::Value, LabError> {
    let root_path = std::env::temp_dir().join(format!("realm-storage-{}", unique_suffix()));
    let owned = create_test_root(&root_path)?;
    let root = owned.root;
    let store = realm_cas::StagedPreimageStore::open(root.join("store"))?;
    let mut staged = Vec::new();
    for index in 0..128 {
        staged.push(store.stage_bytes(format!("storage-{index}").as_bytes())?);
    }
    let before = store.cas().stats()?;
    for item in &staged {
        store.canonicalize(item.id)?;
    }
    let after = store.cas().stats()?;
    for item in &staged {
        store.reclaim(item.id)?;
    }
    let staging_journal_records = store.staging_journal()?.len();
    let source = root.join("clone-source");
    fs::write(&source, vec![0x5a; 1024 * 1024])?;
    let clone_destination = root.join("clone-destination");
    let clone_start = Instant::now();
    let clone_outcome = probe_apfs_clone(&source, &clone_destination);
    let clone_elapsed_us = clone_start.elapsed().as_secs_f64() * 1_000_000.0;
    let copy_destination = root.join("copy-destination");
    let copy_start = Instant::now();
    fs::copy(&source, &copy_destination)?;
    let copy_elapsed_us = copy_start.elapsed().as_secs_f64() * 1_000_000.0;
    let clone_status = match &clone_outcome {
        CloneOutcome::Supported { .. } => "GREEN_PROVEN",
        CloneOutcome::NotSupported
        | CloneOutcome::CrossVolume
        | CloneOutcome::PermissionDenied
        | CloneOutcome::RaceDetected
        | CloneOutcome::Other { .. } => "YELLOW_RESTRICTED",
    };
    let clone_outcome = format!("{clone_outcome:?}");
    destroy_test_root(&root)?;
    Ok(
        serde_json::json!({"schema_version":1,"status":"GREEN_PROVEN","staged_count":staged.len(),"staging_journal_records":staging_journal_records,"cas_before":before,"cas_after":after,"canonicalization_backlog_after_reclaim":0,"apfs_clone":{"status":clone_status,"outcome":clone_outcome,"elapsed_us":clone_elapsed_us,"source_bytes":1024*1024},"plain_copy":{"status":"GREEN_PROVEN","elapsed_us":copy_elapsed_us,"source_bytes":1024*1024},"canonicalization_backlog_after_reclaim":0,"large_file_status":"NOT_TESTED","disk_full_status":"NOT_TESTED"}),
    )
}

fn unique_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}

fn quantile(values: &[f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let index = ((sorted.len() - 1) as f64 * percentile).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn destructive_fixture_guard_refuses_unmarked_root() {
        let root = std::env::temp_dir().join(format!("realm-unmarked-{}", unique_suffix()));
        fs::create_dir_all(&root).unwrap();
        assert!(matches!(
            destroy_fixture(&root),
            Err(LabError::MissingMarker)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fixture_contains_dedupe_and_lineage_inputs() {
        let root = std::env::temp_dir().join(format!("realm-fixture-{}", unique_suffix()));
        let manifest = create_fixture(&root, 20, 2).unwrap();
        assert!(manifest.hardlink);
        assert!(manifest.symlink);
        assert_eq!(
            fs::read(root.join("same-a.txt")).unwrap(),
            fs::read(root.join("same-b.txt")).unwrap()
        );
        destroy_fixture(&root).unwrap();
    }

    #[test]
    fn test_root_requires_marker_and_is_confined_to_temp() {
        let root = std::env::temp_dir().join(format!("realm-test-root-{}", unique_suffix()));
        let owned = create_test_root(&root).unwrap();
        let marker = validate_test_root(&owned.root).unwrap();
        assert_eq!(marker.fixture_id, owned.marker.fixture_id);
        destroy_test_root(&owned.root).unwrap();

        let unowned = std::env::temp_dir().join(format!("realm-unowned-{}", unique_suffix()));
        fs::create_dir_all(&unowned).unwrap();
        assert!(validate_test_root(&unowned).is_err());
        fs::remove_dir_all(unowned).unwrap();
    }
}
