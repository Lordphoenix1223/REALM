//! Runtime execution-state recovery, never terminal closure or publication.
//! Broker-native lifecycle records are primary; pinned-object and SQLite reads
//! reconcile the world. Reopening an unsealed journal cannot mint launch authority.
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
};

const MAX_JOURNAL: u64 = 16 * 1024 * 1024;
const MAX_FILE: u64 = 1024 * 1024;
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, EffectError> {
    Ok(serde_json::to_vec(value)?)
}

#[derive(Debug, thiserror::Error)]
pub enum EffectError {
    #[error("REFUSE({0})")]
    Refuse(&'static str),
    #[error("UNKNOWN({0})")]
    Unknown(&'static str),
    #[error("runtime journal I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("runtime journal encoding: {0}")]
    Json(#[from] serde_json::Error),
    #[error("runtime SQLite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskFamily {
    File,
    Sqlite,
    Combined,
}
impl TaskFamily {
    pub fn operations(self) -> Vec<EffectOperation> {
        match self {
            Self::File => vec![EffectOperation::FileCreate {
                path: "output.txt".into(),
                bytes: b"ABC".to_vec(),
            }],
            Self::Sqlite => vec![EffectOperation::SqliteIncrement {
                database: "counter.sqlite".into(),
                before: 0,
                after: 1,
            }],
            Self::Combined => vec![
                EffectOperation::FileRead {
                    path: "input.txt".into(),
                    bytes: b"abc".to_vec(),
                },
                EffectOperation::FileCreate {
                    path: "output.txt".into(),
                    bytes: b"ABC".to_vec(),
                },
                EffectOperation::SqliteIncrement {
                    database: "counter.sqlite".into(),
                    before: 0,
                    after: 1,
                },
            ],
        }
    }
}

/// No arbitrary SQL, file deletion, overwrites, or shell semantics are offered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum EffectOperation {
    FileRead {
        path: String,
        bytes: Vec<u8>,
    },
    FileCreate {
        path: String,
        bytes: Vec<u8>,
    },
    SqliteIncrement {
        database: String,
        before: i64,
        after: i64,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRequest {
    pub effect_id: String,
    pub operation: EffectOperation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationState {
    Requested,
    Authorized,
    Dispatched,
    Committed,
    Acknowledged,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CallerState {
    Pending,
    ResultAvailable,
    Unknown,
    TimedOut,
    Cancelled,
    Acknowledged,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationOrigin {
    BrokerNative,
    RecoveryReconciliation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailurePoint {
    BeforeAuthorization,
    AfterAuthorization,
    AfterWorldCommit,
    AfterJournalCommit,
    AfterToolResult,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectIdentity {
    pub device: u64,
    pub inode: u64,
    pub birth_time_ns: u64,
    pub bytes: u64,
    pub content_blake3: String,
}
fn object(path: &Path) -> Result<ObjectIdentity, EffectError> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let before = f.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.len() > MAX_FILE {
        return Err(EffectError::Unknown("UNSUPPORTED_OBJECT"));
    }
    let mut bytes = Vec::new();
    (&mut f).take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    let after = f.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || bytes.len() as u64 != before.len()
    {
        return Err(EffectError::Unknown("OBJECT_CHANGED_DURING_OBSERVATION"));
    }
    let named = fs::symlink_metadata(path)?;
    if named.dev() != after.dev() || named.ino() != after.ino() || !named.is_file() {
        return Err(EffectError::Unknown("OBJECT_PATH_SUBSTITUTION"));
    }
    Ok(ObjectIdentity {
        device: before.dev(),
        inode: before.ino(),
        birth_time_ns: before
            .created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|d| u64::try_from(d.as_nanos()).ok())
            .ok_or(EffectError::Unknown("UNSUPPORTED_OBJECT_BIRTH_IDENTITY"))?,
        bytes: before.len(),
        content_blake3: digest(&bytes),
    })
}
fn private_dir(path: &Path) -> Result<(u64, u64), EffectError> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o022 != 0
    {
        return Err(EffectError::Refuse("UNTRUSTED_DIRECTORY"));
    }
    Ok((m.dev(), m.ino()))
}
fn private_file(path: &Path) -> Result<File, EffectError> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
    {
        return Err(EffectError::Refuse("UNTRUSTED_JOURNAL"));
    }
    Ok(f)
}
fn absent(path: &Path) -> Result<(), EffectError> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(EffectError::Unknown("EXPECTED_ABSENT_TARGET")),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSessionIdentity {
    pub run_id: String,
    pub call_id: String,
    pub execution_id: String,
    pub challenge: String,
    pub normalized_call_blake3: String,
    pub task_envelope_identity: String,
    pub contract_identity: String,
    pub policy_identity: String,
    pub prestart_launch_identity: String,
    pub vmm_process_identity: String,
    pub broker_session_identity: String,
    pub family: TaskFamily,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u16,
    session: RuntimeSessionIdentity,
    workspace: PathBuf,
    workspace_device: u64,
    workspace_inode: u64,
    input: ObjectIdentity,
    database: Option<ObjectIdentity>,
    database_schema: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum EffectObservation {
    File {
        object: ObjectIdentity,
    },
    Sqlite {
        database_device: u64,
        database_inode: u64,
        database_birth_time_ns: u64,
        schema_identity: String,
        effect_id: String,
        semantic_identity: String,
        before: i64,
        after: i64,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRecord {
    pub sequence: u64,
    pub session_identity: String,
    pub request: EffectRequest,
    pub semantic_identity: String,
    pub causal_parent: Option<String>,
    pub state: OperationState,
    pub before: Option<EffectObservation>,
    pub prepared: Option<ObjectIdentity>,
    pub after: Option<EffectObservation>,
    pub origin: ObservationOrigin,
    pub previous_hash: String,
    pub hash: String,
}
impl EffectRecord {
    fn calculate_hash(&self) -> Result<String, EffectError> {
        let mut r = self.clone();
        r.hash.clear();
        Ok(digest(&encode(&r)?))
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectFrontierIdentity {
    pub session_identity: String,
    pub journal: PathBuf,
    pub head: String,
    pub records: u64,
    pub journal_blake3: String,
}
/// Non-cloneable, non-deserializable runtime capability. It means the bounded
/// records were reconciled while this broker held its lock; it is NOT closure.
/// ```compile_fail
/// use realm_v6::runtime_effects::BrokerCompletion;
/// let _: BrokerCompletion = serde_json::from_str("{}").unwrap();
/// ```
pub struct BrokerCompletion {
    session: RuntimeSessionIdentity,
    frontier: EffectFrontierIdentity,
    effects: Vec<EffectRecord>,
}
impl BrokerCompletion {
    pub fn session(&self) -> &RuntimeSessionIdentity {
        &self.session
    }
    pub fn frontier(&self) -> &EffectFrontierIdentity {
        &self.frontier
    }
    pub fn effects(&self) -> &[EffectRecord] {
        &self.effects
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeDisposition {
    Pending,
    EffectsCommitted,
    Refused,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRefusal {
    session_identity: String,
    frontier_head: String,
    operation_id: String,
    request_blake3: String,
    reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReport {
    pub schema_version: u16,
    pub session: RuntimeSessionIdentity,
    pub frontier: EffectFrontierIdentity,
    pub operations: Vec<EffectRecord>,
    pub operation_states: BTreeMap<String, OperationState>,
    pub complete: bool,
    pub execution_disposition: RuntimeDisposition,
    pub caller_state: CallerState,
    pub authority: String,
    pub decision: String,
}

/// Created only by the runtime/broker path. The public reopen API recovers
/// existing state and cannot authorize a new guest or mint a launch capability.
pub struct RuntimeEffectBroker {
    dir: PathBuf,
    manifest: Manifest,
    lock: File,
    records: Vec<EffectRecord>,
}
impl RuntimeEffectBroker {
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn create(
        dir: &Path,
        workspace: &Path,
        session: RuntimeSessionIdentity,
    ) -> Result<Self, EffectError> {
        let (workspace_device, workspace_inode) = private_dir(workspace)?;
        let mut expected = vec!["input.txt".to_string()];
        if session.family != TaskFamily::File {
            expected.push("counter.sqlite".into());
        }
        check_names(workspace, expected)?;
        private_dir(dir)?;
        let input = object(&workspace.join("input.txt"))?;
        if session.family == TaskFamily::Combined && input.content_blake3 != digest(b"abc") {
            return Err(EffectError::Refuse("COMBINED_INPUT_CONTRACT"));
        }
        if session.family != TaskFamily::Sqlite {
            absent(&workspace.join("output.txt"))?;
        }
        let (database, database_schema) = if session.family != TaskFamily::File {
            let db = workspace.join("counter.sqlite");
            let id = object(&db)?;
            let c = open_db(&db, false)?;
            validate_schema(&c)?;
            if counter(&c)? != 0 || commit_count(&c)? != 0 {
                return Err(EffectError::Refuse("DATABASE_PRESTATE"));
            }
            (Some(id), Some(schema_identity(&c)?))
        } else {
            (None, None)
        };
        let manifest = Manifest {
            schema_version: 1,
            session,
            workspace: workspace.to_path_buf(),
            workspace_device,
            workspace_inode,
            input,
            database,
            database_schema,
        };
        write_new(&dir.join("runtime-session.json"), &encode(&manifest)?)?;
        write_new(&dir.join("runtime-effects.jsonl"), b"")?;
        write_new(&dir.join("runtime-callers.jsonl"), b"")?;
        Self::reopen(dir)
    }
    pub fn reopen(dir: &Path) -> Result<Self, EffectError> {
        private_dir(dir)?;
        let lock_path = dir.join("runtime-effects.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(lock_path)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(EffectError::Refuse("BROKER_BUSY"));
        }
        let m = lock.metadata()?;
        if m.nlink() != 1 || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err(EffectError::Refuse("LOCK_IDENTITY"));
        }
        let mut manifest_file = private_file(&dir.join("runtime-session.json"))?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut manifest_file)
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 64 * 1024 {
            return Err(EffectError::Unknown("MANIFEST_TOO_LARGE"));
        }
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        if manifest.schema_version != 1 {
            return Err(EffectError::Unknown("UNSUPPORTED_RUNTIME_JOURNAL_SCHEMA"));
        }
        let mut broker = Self {
            dir: dir.to_path_buf(),
            manifest,
            lock,
            records: vec![],
        };
        broker.check_root()?;
        broker.reload()?;
        broker.read_delivery()?;
        Ok(broker)
    }
    fn check_root(&self) -> Result<(), EffectError> {
        if private_dir(&self.manifest.workspace)?
            != (
                self.manifest.workspace_device,
                self.manifest.workspace_inode,
            )
        {
            return Err(EffectError::Unknown("WORKSPACE_SUBSTITUTION"));
        }
        if object(&self.manifest.workspace.join("input.txt"))? != self.manifest.input {
            return Err(EffectError::Unknown("INPUT_SUBSTITUTION"));
        }
        Ok(())
    }
    fn session_hash(&self) -> Result<String, EffectError> {
        Ok(digest(&encode(&self.manifest)?))
    }
    fn journal_bytes(&self) -> Result<Vec<u8>, EffectError> {
        let mut f = private_file(&self.dir.join("runtime-effects.jsonl"))?;
        if f.metadata()?.len() > MAX_JOURNAL {
            return Err(EffectError::Unknown("JOURNAL_TOO_LARGE"));
        }
        let mut b = Vec::new();
        f.read_to_end(&mut b)?;
        Ok(b)
    }
    fn reload(&mut self) -> Result<(), EffectError> {
        let b = self.journal_bytes()?;
        if !b.is_empty() && !b.ends_with(b"\n") {
            return Err(EffectError::Unknown("TORN_JOURNAL"));
        }
        let mut records = Vec::new();
        let mut last: BTreeMap<String, EffectRecord> = BTreeMap::new();
        let mut head = ZERO.to_string();
        for line in b.split(|c| *c == b'\n').filter(|l| !l.is_empty()) {
            let r: EffectRecord = serde_json::from_slice(line)?;
            if r.sequence != records.len() as u64
                || r.previous_hash != head
                || r.hash != r.calculate_hash()?
                || r.session_identity != self.session_hash()?
                || r.semantic_identity != self.semantic(&r.request)?
            {
                return Err(EffectError::Unknown("JOURNAL_CHAIN_OR_IDENTITY"));
            }
            let prior = last.get(&r.request.effect_id);
            let valid = match prior {
                None => {
                    r.state == OperationState::Requested
                        && r.after.is_none()
                        && r.prepared.is_none()
                }
                Some(p) => {
                    p.request == r.request
                        && p.semantic_identity == r.semantic_identity
                        && p.before == r.before
                        && p.causal_parent == r.causal_parent
                        && match (p.state, r.state) {
                            (OperationState::Requested, OperationState::Authorized) => {
                                r.after.is_none()
                            }
                            (OperationState::Authorized, OperationState::Dispatched) => {
                                p.prepared == r.prepared && r.after.is_none()
                            }
                            (OperationState::Dispatched, OperationState::Committed) => {
                                p.prepared == r.prepared && r.after.is_some()
                            }
                            _ => false,
                        }
                }
            };
            if !valid {
                return Err(EffectError::Unknown("INVALID_LIFECYCLE"));
            }
            head = r.hash.clone();
            last.insert(r.request.effect_id.clone(), r.clone());
            records.push(r);
        }
        // Contracts are replayed, not inferred from a count or a caller boolean.
        let allowed = self.manifest.session.family.operations();
        let mut committed = vec![];
        for r in &records {
            if r.state == OperationState::Authorized
                && (allowed.get(committed.len()) != Some(&r.request.operation)
                    || records.iter().any(|other: &EffectRecord| {
                        other.sequence < r.sequence
                            && other.state == OperationState::Authorized
                            && other.request.operation == r.request.operation
                            && other.request.effect_id != r.request.effect_id
                    })
                    || r.causal_parent != committed.last().cloned())
            {
                return Err(EffectError::Unknown("JOURNAL_CONTRACT_MISMATCH"));
            }
            if r.state == OperationState::Committed {
                committed.push(r.request.effect_id.clone());
            }
        }
        self.records = records;
        Ok(())
    }
    pub fn frontier(&self) -> Result<EffectFrontierIdentity, EffectError> {
        Ok(EffectFrontierIdentity {
            session_identity: self.session_hash()?,
            journal: self.dir.join("runtime-effects.jsonl"),
            head: self
                .records
                .last()
                .map_or(ZERO.to_owned(), |r| r.hash.clone()),
            records: self.records.len() as u64,
            journal_blake3: digest(&self.journal_bytes()?),
        })
    }
    fn semantic(&self, request: &EffectRequest) -> Result<String, EffectError> {
        Ok(digest(&encode(&(self.session_hash()?, request))?))
    }
    fn latest(&self) -> BTreeMap<String, EffectRecord> {
        let mut m = BTreeMap::new();
        for r in &self.records {
            m.insert(r.request.effect_id.clone(), r.clone());
        }
        m
    }
    fn append(&mut self, mut r: EffectRecord) -> Result<EffectRecord, EffectError> {
        r.sequence = self.records.len() as u64;
        r.previous_hash = self
            .records
            .last()
            .map_or(ZERO.to_owned(), |r| r.hash.clone());
        r.hash = r.calculate_hash()?;
        let mut b = encode(&r)?;
        b.push(b'\n');
        let mut f = OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.dir.join("runtime-effects.jsonl"))?;
        if f.metadata()?.len() + b.len() as u64 > MAX_JOURNAL {
            return Err(EffectError::Unknown("JOURNAL_TOO_LARGE"));
        }
        f.write_all(&b)?;
        f.sync_all()?;
        self.records.push(r.clone());
        Ok(r)
    }
    fn before(
        &self,
        operation: &EffectOperation,
    ) -> Result<Option<EffectObservation>, EffectError> {
        self.check_root()?;
        match operation {
            EffectOperation::FileRead { path, .. } if path == "input.txt" => {
                Ok(Some(EffectObservation::File {
                    object: self.manifest.input.clone(),
                }))
            }
            EffectOperation::FileCreate { path, .. } if path == "output.txt" => {
                absent(&self.manifest.workspace.join(path))?;
                Ok(None)
            }
            EffectOperation::SqliteIncrement {
                database,
                before,
                after,
            } if database == "counter.sqlite" && *before == 0 && *after == 1 => {
                self.check_db_pin()?;
                let c = open_db(&self.db_path(), false)?;
                if counter(&c)? != 0 || commit_count(&c)? != 0 {
                    return Err(EffectError::Unknown("DATABASE_PRESTATE_MISMATCH"));
                }
                Ok(Some(EffectObservation::Sqlite {
                    database_device: self.manifest.database.as_ref().unwrap().device,
                    database_inode: self.manifest.database.as_ref().unwrap().inode,
                    database_birth_time_ns: self.manifest.database.as_ref().unwrap().birth_time_ns,
                    schema_identity: schema_identity(&c)?,
                    effect_id: String::new(),
                    semantic_identity: String::new(),
                    before: 0,
                    after: 0,
                }))
            }
            _ => Err(EffectError::Refuse("UNSUPPORTED_OPERATION")),
        }
    }
    fn db_path(&self) -> PathBuf {
        self.manifest.workspace.join("counter.sqlite")
    }
    fn check_db_pin(&self) -> Result<(), EffectError> {
        let initial = self
            .manifest
            .database
            .as_ref()
            .ok_or(EffectError::Refuse("NO_DATABASE_CAPABILITY"))?;
        let p = object(&self.db_path())?;
        if (p.device, p.inode, p.birth_time_ns)
            != (initial.device, initial.inode, initial.birth_time_ns)
        {
            return Err(EffectError::Unknown("DATABASE_SUBSTITUTION"));
        }
        let c = open_db(&self.db_path(), false)?;
        validate_schema(&c)?;
        if Some(schema_identity(&c)?) != self.manifest.database_schema {
            return Err(EffectError::Unknown("DATABASE_SCHEMA_MISMATCH"));
        }
        Ok(())
    }
    fn stage_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("prepared-{}", digest(id.as_bytes())))
    }
    /// Host dispatch only, after canonical RPC has authenticated the session
    /// and checked the exact request. Same ID+semantics reconciles, never repeats.
    pub(crate) fn execute(
        &mut self,
        request: EffectRequest,
        failure: Option<FailurePoint>,
    ) -> Result<EffectRecord, EffectError> {
        if request.effect_id.is_empty()
            || request.effect_id.len() > 128
            || !request
                .effect_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_:-.".contains(&b))
        {
            return Err(EffectError::Refuse("INVALID_EFFECT_ID"));
        }
        self.check_root()?;
        if self.refusal()?.is_some() {
            return Err(EffectError::Refuse("SESSION_PREVIOUSLY_REFUSED"));
        }
        let mut recovering = false;
        let mut r = if let Some(mut r) = self.latest().get(&request.effect_id).cloned() {
            recovering = true;
            r.origin = ObservationOrigin::RecoveryReconciliation;
            if r.request != request || r.semantic_identity != self.semantic(&request)? {
                return Err(EffectError::Refuse("EFFECT_ID_SEMANTIC_CONFLICT"));
            }
            if r.state == OperationState::Committed {
                self.reconcile_committed(&r)?;
                return Ok(r);
            }
            r
        } else {
            let committed = self
                .records
                .iter()
                .filter(|r| r.state == OperationState::Committed)
                .collect::<Vec<_>>();
            let allowed = self.manifest.session.family.operations();
            if allowed.get(committed.len()) != Some(&request.operation)
                || self.records.iter().any(|r| {
                    r.state == OperationState::Authorized
                        && r.request.operation == request.operation
                })
            {
                return Err(EffectError::Refuse("EFFECT_CONTRACT_BUDGET_OR_ORDER"));
            }
            let before = self.before(&request.operation)?;
            let semantic_identity = self.semantic(&request)?;
            self.append(EffectRecord {
                sequence: 0,
                session_identity: self.session_hash()?,
                request,
                semantic_identity,
                causal_parent: committed.last().map(|r| r.request.effect_id.clone()),
                state: OperationState::Requested,
                before,
                prepared: None,
                after: None,
                origin: ObservationOrigin::BrokerNative,
                previous_hash: String::new(),
                hash: String::new(),
            })?
        };
        die_at(failure, FailurePoint::BeforeAuthorization);
        if r.state == OperationState::Requested {
            self.before(&r.request.operation)?;
            if let EffectOperation::FileCreate { bytes, .. } = &r.request.operation {
                let path = self.stage_path(&r.request.effect_id);
                match fs::symlink_metadata(&path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => write_new(&path, bytes)?,
                    Ok(_) => {
                        let o = object(&path)?;
                        if o.content_blake3 != digest(bytes) || o.bytes != bytes.len() as u64 {
                            return Err(EffectError::Unknown("PREPARED_OBJECT_MISMATCH"));
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
                r.prepared = Some(object(&path)?);
            }
            r.state = OperationState::Authorized;
            r = self.append(r)?;
        }
        die_at(failure, FailurePoint::AfterAuthorization);
        if r.state == OperationState::Authorized {
            r.state = OperationState::Dispatched;
            r = self.append(r)?;
        }
        if r.state != OperationState::Dispatched {
            return Err(EffectError::Unknown("UNSUPPORTED_RECOVERY_STATE"));
        }
        let after = self.commit_or_recover(&r)?;
        if recovering {
            r.origin = ObservationOrigin::RecoveryReconciliation;
        }
        die_at(failure, FailurePoint::AfterWorldCommit);
        r.state = OperationState::Committed;
        r.after = Some(after);
        r = self.append(r)?;
        die_at(failure, FailurePoint::AfterJournalCommit);
        Ok(r)
    }
    fn commit_or_recover(&self, r: &EffectRecord) -> Result<EffectObservation, EffectError> {
        match &r.request.operation {
            EffectOperation::FileRead { path, bytes } => {
                let o = object(&self.manifest.workspace.join(path))?;
                if o != self.manifest.input || o.content_blake3 != digest(bytes) {
                    return Err(EffectError::Unknown("READ_RECONCILIATION"));
                }
                Ok(EffectObservation::File { object: o })
            }
            EffectOperation::FileCreate { path, bytes } => {
                let dst = self.manifest.workspace.join(path);
                let staged = self.stage_path(&r.request.effect_id);
                let prepared = r
                    .prepared
                    .as_ref()
                    .ok_or(EffectError::Unknown("MISSING_PREPARED_INODE"))?;
                match fs::symlink_metadata(&dst) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        if object(&staged)? != *prepared {
                            return Err(EffectError::Unknown("PREPARED_INODE_SUBSTITUTION"));
                        }
                        // Atomic no-replace name installation; the pre-recorded inode
                        // is the witness across the world/journal crash window.
                        fs::hard_link(&staged, &dst)?;
                        File::open(&self.manifest.workspace)?.sync_all()?;
                    }
                    Ok(m) => {
                        if (m.dev(), m.ino()) != (prepared.device, prepared.inode)
                            || !m.is_file()
                            || m.file_type().is_symlink()
                        {
                            return Err(EffectError::Unknown("OUTPUT_RECONCILIATION_MISMATCH"));
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
                if fs::symlink_metadata(&staged).is_ok() {
                    let m = fs::symlink_metadata(&staged)?;
                    if (m.dev(), m.ino()) != (prepared.device, prepared.inode) {
                        return Err(EffectError::Unknown("STAGING_SUBSTITUTION"));
                    }
                    // Internal broker object cleanup; no user/world rollback.
                    fs::remove_file(&staged)?;
                    File::open(&self.dir)?.sync_all()?;
                }
                let o = object(&dst)?;
                if o != *prepared || o.content_blake3 != digest(bytes) {
                    return Err(EffectError::Unknown("OUTPUT_RECONCILIATION_MISMATCH"));
                }
                Ok(EffectObservation::File { object: o })
            }
            EffectOperation::SqliteIncrement { before, after, .. } => {
                self.check_db_pin()?;
                let mut c = open_db(&self.db_path(), true)?;
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let prior:Option<(String,String,i64,i64)>=tx.query_row(
                    "SELECT session,semantic,before_value,after_value FROM realm_effect_commits WHERE effect_id=?1",
                    [&r.request.effect_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional()?;
                if let Some((session, sem, b, a)) = prior {
                    if session != r.session_identity
                        || sem != r.semantic_identity
                        || b != *before
                        || a != *after
                        || counter(&tx)? != *after
                        || commit_count(&tx)? != 1
                    {
                        return Err(EffectError::Unknown("DATABASE_RECONCILIATION_MISMATCH"));
                    }
                } else {
                    if counter(&tx)? != *before || commit_count(&tx)? != 0 {
                        return Err(EffectError::Unknown("DATABASE_PRESTATE_MISMATCH"));
                    }
                    if tx.execute(
                        "UPDATE realm_counter SET value=?1 WHERE singleton=1 AND value=?2",
                        params![after, before],
                    )? != 1
                    {
                        return Err(EffectError::Unknown("DATABASE_COMPARE_AND_SWAP"));
                    }
                    tx.execute("INSERT INTO realm_effect_commits(effect_id,session,semantic,before_value,after_value) VALUES (?1,?2,?3,?4,?5)",
                        params![r.request.effect_id,r.session_identity,r.semantic_identity,before,after])?;
                }
                tx.commit()?;
                self.sqlite_observation(r)
            }
        }
    }
    fn sqlite_observation(&self, r: &EffectRecord) -> Result<EffectObservation, EffectError> {
        self.check_db_pin()?;
        // Independent read-only connection, not the mutation transaction handle.
        let c = open_db(&self.db_path(), false)?;
        let (session,semantic,before,after):(String,String,i64,i64)=c.query_row(
            "SELECT session,semantic,before_value,after_value FROM realm_effect_commits WHERE effect_id=?1",[&r.request.effect_id],
            |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
        if session != r.session_identity
            || semantic != r.semantic_identity
            || before != 0
            || after != 1
            || counter(&c)? != after
            || commit_count(&c)? != 1
        {
            return Err(EffectError::Unknown("DATABASE_RECONCILIATION_MISMATCH"));
        }
        let id = self.manifest.database.as_ref().unwrap();
        Ok(EffectObservation::Sqlite {
            database_device: id.device,
            database_inode: id.inode,
            database_birth_time_ns: id.birth_time_ns,
            schema_identity: schema_identity(&c)?,
            effect_id: r.request.effect_id.clone(),
            semantic_identity: semantic,
            before,
            after,
        })
    }
    fn reconcile_committed(&self, r: &EffectRecord) -> Result<(), EffectError> {
        self.check_root()?;
        let observed = match &r.request.operation {
            EffectOperation::FileRead { path, .. } | EffectOperation::FileCreate { path, .. } => {
                EffectObservation::File {
                    object: object(&self.manifest.workspace.join(path))?,
                }
            }
            EffectOperation::SqliteIncrement { .. } => self.sqlite_observation(r)?,
        };
        if r.after.as_ref() != Some(&observed) {
            return Err(EffectError::Unknown("JOURNAL_WORLD_MISMATCH"));
        }
        Ok(())
    }
    /// Reconcile every committed operation. Interrupted DISPATCHED operations
    /// are completed only by explicit same-ID retry, not by a read-only report.
    pub fn report(&self) -> Result<RecoveryReport, EffectError> {
        self.check_root()?;
        let mut ops = self.latest().into_values().collect::<Vec<_>>();
        ops.sort_by_key(|r| r.sequence);
        for r in &ops {
            if r.state == OperationState::Committed {
                self.reconcile_committed(r)?;
            } else if r.state == OperationState::Dispatched {
                match &r.request.operation {
                    EffectOperation::FileCreate { path, .. } => {
                        let destination = self.manifest.workspace.join(path);
                        if destination.exists() {
                            if Some(object(&destination)?) != r.prepared {
                                return Err(EffectError::Unknown("DISPATCHED_FILE_WORLD_MISMATCH"));
                            }
                        } else if Some(object(&self.stage_path(&r.request.effect_id))?)
                            != r.prepared
                        {
                            return Err(EffectError::Unknown(
                                "DISPATCHED_FILE_PREPARATION_MISMATCH",
                            ));
                        }
                    }
                    EffectOperation::SqliteIncrement { .. } => {
                        self.check_db_pin()?;
                        let c = open_db(&self.db_path(), false)?;
                        if counter(&c)? != 0 || commit_count(&c)? != 0 {
                            self.sqlite_observation(r)?;
                        }
                    }
                    EffectOperation::FileRead { .. } => {}
                }
            }
        }
        let mut expected = vec!["input.txt".to_string()];
        if self.manifest.session.family != TaskFamily::File {
            expected.push("counter.sqlite".into());
        }
        if ops.iter().any(|r| {
            matches!(r.request.operation, EffectOperation::FileCreate { .. })
                && matches!(
                    r.state,
                    OperationState::Dispatched | OperationState::Committed
                )
        }) && self.manifest.workspace.join("output.txt").exists()
        {
            expected.push("output.txt".into());
        }
        check_names(&self.manifest.workspace, expected)?;
        if self.manifest.database.is_some() {
            self.check_db_pin()?;
            if !ops.iter().any(|r| {
                matches!(r.request.operation, EffectOperation::SqliteIncrement { .. })
                    && matches!(
                        r.state,
                        OperationState::Dispatched | OperationState::Committed
                    )
            }) {
                let c = open_db(&self.db_path(), false)?;
                if counter(&c)? != 0 || commit_count(&c)? != 0 {
                    return Err(EffectError::Unknown("DATABASE_PRESTATE_MISMATCH"));
                }
            }
        }
        let complete = ops.len() == self.manifest.session.family.operations().len()
            && ops.iter().all(|r| r.state == OperationState::Committed);
        let caller_state = self
            .read_delivery()?
            .last()
            .map_or(CallerState::Pending, |r| r.state);
        // Delivery state is an overlay, never an edit to a hashed effect record.
        let operation_states = ops
            .iter()
            .map(|r| {
                (
                    r.request.effect_id.clone(),
                    if caller_state == CallerState::Acknowledged
                        && r.state == OperationState::Committed
                    {
                        OperationState::Acknowledged
                    } else {
                        r.state
                    },
                )
            })
            .collect();
        Ok(RecoveryReport {
            schema_version: 3,
            session: self.manifest.session.clone(),
            frontier: self.frontier()?,
            operations: ops,
            operation_states,
            complete,
            execution_disposition: if self.refusal()?.is_some() {
                RuntimeDisposition::Refused
            } else if complete {
                RuntimeDisposition::EffectsCommitted
            } else {
                RuntimeDisposition::Pending
            },
            caller_state,
            authority: "NON_AUTHORIZING".into(),
            decision: "REFUSE_UNVERIFIED_BOUNDARY".into(),
        })
    }
    /// Explicit host caller ACK after observing a reconciled result.
    pub fn acknowledge(&self) -> Result<RecoveryReport, EffectError> {
        if self.refusal()?.is_some() {
            return Err(EffectError::Refuse("ACK_OF_REFUSED_SESSION"));
        }
        self.delivery(CallerState::Acknowledged)?;
        self.report()
    }
    /// Reconcile/retry an already recorded ID only. No new operation is accepted
    /// through this recovery API, including an additional identical increment.
    pub fn recover_requested(
        &mut self,
        request: EffectRequest,
    ) -> Result<RecoveryReport, EffectError> {
        if !self.latest().contains_key(&request.effect_id) {
            return Err(EffectError::Refuse("EFFECT_CONTRACT_BUDGET_OR_UNKNOWN_ID"));
        }
        self.execute(request, None)?;
        self.report()
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn retry_all(&mut self) -> Result<RecoveryReport, EffectError> {
        let ops = self.latest().into_values().collect::<Vec<_>>();
        // Stable journal order, not lexicographic effect IDs.
        let mut ops = ops;
        ops.sort_by_key(|r| r.sequence);
        for r in ops {
            if r.state != OperationState::Committed {
                let mut original = r.clone();
                original.origin = ObservationOrigin::RecoveryReconciliation;
                // Origin is annotated on recovery transitions without changing preserved records.
                self.execute_recovery(original)?;
            }
        }
        self.report()
    }
    #[cfg(target_os = "linux")]
    fn execute_recovery(&mut self, r: EffectRecord) -> Result<(), EffectError> {
        self.execute(r.request.clone(), None)?;
        Ok(())
    }
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn completion(&self) -> Result<BrokerCompletion, EffectError> {
        let report = self.report()?;
        if !report.complete || report.execution_disposition != RuntimeDisposition::EffectsCommitted
        {
            return Err(EffectError::Unknown("INCOMPLETE_EFFECT_CONTRACT"));
        }
        Ok(BrokerCompletion {
            session: report.session,
            frontier: report.frontier,
            effects: report.operations,
        })
    }
    pub(crate) fn record_refusal(
        &self,
        operation_id: &str,
        request: &[u8],
        reason: &str,
    ) -> Result<(), EffectError> {
        if self.refusal()?.is_none() {
            let record = RuntimeRefusal {
                session_identity: self.session_hash()?,
                frontier_head: self.frontier()?.head,
                operation_id: operation_id.chars().take(128).collect(),
                request_blake3: digest(request),
                reason: reason.into(),
            };
            write_new(&self.dir.join("runtime-refusal.json"), &encode(&record)?)?;
        }
        Ok(())
    }
    fn refusal(&self) -> Result<Option<RuntimeRefusal>, EffectError> {
        let path = self.dir.join("runtime-refusal.json");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
            Ok(_) => {
                let f = private_file(&path)?;
                let mut bytes = Vec::new();
                f.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
                if bytes.len() > 64 * 1024 {
                    return Err(EffectError::Unknown("REFUSAL_RECORD_TOO_LARGE"));
                }
                let r: RuntimeRefusal = serde_json::from_slice(&bytes)?;
                if r.session_identity != self.session_hash()?
                    || (r.frontier_head != ZERO
                        && !self.records.iter().any(|e| e.hash == r.frontier_head))
                {
                    return Err(EffectError::Unknown("REFUSAL_RECORD_MISMATCH"));
                }
                Ok(Some(r))
            }
        }
    }
    fn stored_result_digest(&self) -> Result<Option<String>, EffectError> {
        let path = self.dir.join("runtime-tool-result.json");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
            Ok(_) => {
                let f = private_file(&path)?;
                let mut bytes = Vec::new();
                f.take(MAX_JOURNAL + 1).read_to_end(&mut bytes)?;
                if bytes.len() as u64 > MAX_JOURNAL {
                    return Err(EffectError::Unknown("STORED_RESULT_TOO_LARGE"));
                }
                Ok(Some(digest(&bytes)))
            }
        }
    }
    fn read_delivery(&self) -> Result<Vec<DeliveryRecord>, EffectError> {
        let mut f = private_file(&self.dir.join("runtime-callers.jsonl"))?;
        let mut b = Vec::new();
        std::io::Read::by_ref(&mut f)
            .take(MAX_JOURNAL + 1)
            .read_to_end(&mut b)?;
        if b.len() as u64 > MAX_JOURNAL || (!b.is_empty() && !b.ends_with(b"\n")) {
            return Err(EffectError::Unknown("TORN_DELIVERY_JOURNAL"));
        }
        let mut out = vec![];
        let mut previous = ZERO.to_string();
        for line in b.split(|c| *c == b'\n').filter(|l| !l.is_empty()) {
            let r: DeliveryRecord = serde_json::from_slice(line)?;
            let mut hashed = r.clone();
            hashed.hash.clear();
            if r.session != self.session_hash()?
                || r.sequence != out.len() as u64
                || r.previous_hash != previous
                || r.hash != digest(&encode(&hashed)?)
                || (r.frontier_head != ZERO
                    && !self.records.iter().any(|e| e.hash == r.frontier_head))
            {
                return Err(EffectError::Unknown("DELIVERY_CHAIN_MISMATCH"));
            }
            if r.tool_result_blake3.as_ref().is_some_and(|hash| {
                self.stored_result_digest().ok().flatten().as_ref() != Some(hash)
            }) {
                return Err(EffectError::Unknown("STORED_TOOL_RESULT_SUBSTITUTION"));
            }
            previous = r.hash.clone();
            out.push(r);
        }
        Ok(out)
    }
    pub(crate) fn delivery(&self, state: CallerState) -> Result<(), EffectError> {
        if state == CallerState::Acknowledged && !self.report()?.complete {
            return Err(EffectError::Refuse("ACK_WITHOUT_COMPLETED_CONTRACT"));
        }
        let records = self.read_delivery()?;
        let mut r = DeliveryRecord {
            sequence: records.len() as u64,
            session: self.session_hash()?,
            frontier_head: self.frontier()?.head,
            state,
            tool_result_blake3: self.stored_result_digest()?,
            previous_hash: records.last().map_or(ZERO.to_owned(), |r| r.hash.clone()),
            hash: String::new(),
        };
        r.hash = digest(&encode(&r)?);
        let mut b = encode(&r)?;
        b.push(b'\n');
        let mut f = OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.dir.join("runtime-callers.jsonl"))?;
        f.write_all(&b)?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn session(&self) -> &RuntimeSessionIdentity {
        &self.manifest.session
    }
    /// Crash a separate effect worker; canonical VMM ownership stays here.
    pub(crate) fn crash_worker(
        &mut self,
        request: EffectRequest,
        point: FailurePoint,
    ) -> Result<(), EffectError> {
        use std::process::{Command, Stdio};
        // The worker acquires its own flock. The canonical RPC already checked
        // peer/contract; the child receives no guest-controlled executable/SQL.
        if unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let result = (|| -> Result<std::process::ExitStatus, EffectError> {
            let mut child = Command::new(std::env::current_exe()?)
                .arg("--runtime-effect-worker")
                .arg(&self.dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?;
            let sent = child
                .stdin
                .take()
                .ok_or(EffectError::Unknown("WORKER_PIPE"))?
                .write_all(&encode(&(request, point))?);
            if sent.is_err() {
                let _ = child.kill();
            }
            let status = child.wait()?;
            sent?;
            Ok(status)
        })();
        if unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(EffectError::Unknown("WORKER_LOCK_REACQUIRE"));
        }
        let status = result?;
        self.reload()?;
        if status.code() != Some(86) {
            return Err(EffectError::Unknown("CRASH_POINT_NOT_REACHED"));
        }
        self.delivery(CallerState::Unknown)?;
        Err(EffectError::Unknown("EFFECT_WORKER_PROCESS_CRASH"))
    }
}
impl Drop for RuntimeEffectBroker {
    fn drop(&mut self) {
        unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN) };
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryRecord {
    sequence: u64,
    session: String,
    frontier_head: String,
    state: CallerState,
    tool_result_blake3: Option<String>,
    previous_hash: String,
    hash: String,
}
fn die_at(injected: Option<FailurePoint>, point: FailurePoint) {
    if injected == Some(point) {
        unsafe { libc::_exit(86) };
    }
}
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), EffectError> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    File::open(path.parent().ok_or(EffectError::Refuse("NO_PARENT"))?)?.sync_all()?;
    Ok(())
}
fn open_db(path: &Path, write: bool) -> Result<Connection, EffectError> {
    let flags = if write {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let c = Connection::open_with_flags(
        path,
        flags | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    c.busy_timeout(std::time::Duration::from_secs(5))?;
    c.pragma_update(None, "trusted_schema", false)?;
    if write {
        c.pragma_update(None, "journal_mode", "DELETE")?;
        c.pragma_update(None, "synchronous", "FULL")?;
    }
    Ok(c)
}
fn counter(c: &Connection) -> Result<i64, EffectError> {
    if c.query_row("SELECT count(*) FROM realm_counter", [], |r| {
        r.get::<_, i64>(0)
    })? != 1
    {
        return Err(EffectError::Unknown("COUNTER_CARDINALITY"));
    }
    Ok(c.query_row(
        "SELECT value FROM realm_counter WHERE singleton=1",
        [],
        |r| r.get(0),
    )?)
}
fn commit_count(c: &Connection) -> Result<i64, EffectError> {
    Ok(
        c.query_row("SELECT count(*) FROM realm_effect_commits", [], |r| {
            r.get(0)
        })?,
    )
}
fn schema_identity(c: &Connection) -> Result<String, EffectError> {
    let mut stmt =
        c.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(digest(&encode(&rows)?))
}
fn validate_schema(c: &Connection) -> Result<(), EffectError> {
    let rows = c
        .prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY type,name")?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected=vec![
        ("index".into(),"sqlite_autoindex_realm_effect_commits_1".into(),None),
        ("table".into(),"realm_counter".into(),Some("CREATE TABLE realm_counter(singleton INTEGER PRIMARY KEY CHECK(singleton=1),value INTEGER NOT NULL CHECK(value>=0))".into())),
        ("table".into(),"realm_effect_commits".into(),Some("CREATE TABLE realm_effect_commits(effect_id TEXT PRIMARY KEY,session TEXT NOT NULL,semantic TEXT NOT NULL,before_value INTEGER NOT NULL,after_value INTEGER NOT NULL)".into())),
    ];
    if rows != expected {
        return Err(EffectError::Refuse("UNSUPPORTED_DATABASE_SCHEMA"));
    }
    Ok(())
}
fn check_names(root: &Path, mut expected: Vec<String>) -> Result<(), EffectError> {
    let mut names = fs::read_dir(root)?
        .map(|e| e.map(|e| e.file_name().into_string().unwrap_or_default()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    expected.sort();
    if names != expected {
        return Err(EffectError::Unknown("UNDECLARED_WORKSPACE_ENTRY"));
    }
    Ok(())
}

/// Seed constructor for an empty, bounded world, not an effect capability.
pub fn initialize_counter(path: &Path) -> Result<(), EffectError> {
    write_new(path, b"")?;
    let c = open_db(path, true)?;
    c.execute_batch("BEGIN IMMEDIATE;
CREATE TABLE realm_counter(singleton INTEGER PRIMARY KEY CHECK(singleton=1),value INTEGER NOT NULL CHECK(value>=0));
INSERT INTO realm_counter VALUES(1,0);
CREATE TABLE realm_effect_commits(effect_id TEXT PRIMARY KEY,session TEXT NOT NULL,semantic TEXT NOT NULL,before_value INTEGER NOT NULL,after_value INTEGER NOT NULL);
COMMIT;")?;
    File::open(path)?.sync_all()?;
    Ok(())
}

/// Host control-process worker entry. Only an existing private session can be
/// used. This issues no launch/closure capability and is not a guest RPC API.
pub fn run_effect_worker(dir: &Path, input: &[u8]) -> Result<(), EffectError> {
    let (request, point): (EffectRequest, FailurePoint) = serde_json::from_slice(input)?;
    let mut broker = RuntimeEffectBroker::reopen(dir)?;
    broker.execute(request, Some(point))?;
    Err(EffectError::Unknown("CRASH_POINT_NOT_REACHED"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    struct Fixture {
        base: PathBuf,
        world: PathBuf,
        state: PathBuf,
    }
    impl Fixture {
        fn new(family: TaskFamily) -> Self {
            static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let base = std::env::temp_dir().join(format!(
                "realm-runtime-recovery-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&base).unwrap();
            fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
            let base = base.canonicalize().unwrap();
            let world = base.join("world");
            let state = base.join("state");
            fs::create_dir(&world).unwrap();
            fs::create_dir(&state).unwrap();
            write_new(&world.join("input.txt"), b"abc").unwrap();
            if family != TaskFamily::File {
                initialize_counter(&world.join("counter.sqlite")).unwrap();
            }
            Self { base, world, state }
        }
        fn broker(&self, family: TaskFamily) -> RuntimeEffectBroker {
            RuntimeEffectBroker::create(
                &self.state,
                &self.world,
                RuntimeSessionIdentity {
                    run_id: "run".into(),
                    call_id: "call".into(),
                    execution_id: "e".repeat(64),
                    challenge: "c".repeat(64),
                    normalized_call_blake3: "a".repeat(64),
                    task_envelope_identity: "b".repeat(64),
                    contract_identity: "d".repeat(64),
                    policy_identity: "f".repeat(64),
                    prestart_launch_identity: "1".repeat(64),
                    vmm_process_identity: "2".repeat(64),
                    broker_session_identity: "3".repeat(64),
                    family,
                },
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }
    fn request(family: TaskFamily, index: usize) -> EffectRequest {
        EffectRequest {
            effect_id: format!("effect-{index}"),
            operation: family.operations()[index].clone(),
        }
    }
    #[test]
    fn file_and_sqlite_retry_reopen_are_idempotent() {
        for family in [TaskFamily::File, TaskFamily::Sqlite, TaskFamily::Combined] {
            let f = Fixture::new(family);
            let mut b = f.broker(family);
            for i in 0..family.operations().len() {
                b.execute(request(family, i), None).unwrap();
            }
            let head = b.frontier().unwrap();
            drop(b);
            for _ in 0..3 {
                let mut b = RuntimeEffectBroker::reopen(&f.state).unwrap();
                for i in 0..family.operations().len() {
                    b.execute(request(family, i), None).unwrap();
                }
                assert_eq!(head, b.frontier().unwrap());
                assert!(b.report().unwrap().complete);
            }
            if family != TaskFamily::Sqlite {
                assert_eq!(fs::read(f.world.join("output.txt")).unwrap(), b"ABC");
            }
            if family != TaskFamily::File {
                assert_eq!(
                    counter(&open_db(&f.world.join("counter.sqlite"), false).unwrap()).unwrap(),
                    1
                );
            }
        }
    }
    #[test]
    fn semantic_conflict_new_id_and_third_effect_refuse() {
        for family in [TaskFamily::File, TaskFamily::Sqlite, TaskFamily::Combined] {
            let f = Fixture::new(family);
            let mut b = f.broker(family);
            for i in 0..family.operations().len() {
                b.execute(request(family, i), None).unwrap();
            }
            let original = b.frontier().unwrap();
            let mut changed = request(family, 0);
            changed.operation = EffectOperation::FileCreate {
                path: "elsewhere".into(),
                bytes: b"D".to_vec(),
            };
            assert!(matches!(
                b.execute(changed, None),
                Err(EffectError::Refuse("EFFECT_ID_SEMANTIC_CONFLICT"))
            ));
            let mut new_id = request(family, family.operations().len() - 1);
            new_id.effect_id = "second-effect".into();
            assert!(matches!(
                b.execute(new_id, None),
                Err(EffectError::Refuse("EFFECT_CONTRACT_BUDGET_OR_ORDER"))
            ));
            assert_eq!(original, b.frontier().unwrap());
        }
    }
    #[test]
    fn after_commit_file_and_database_mismatch_preserve_journal() {
        for family in [TaskFamily::File, TaskFamily::Sqlite] {
            let f = Fixture::new(family);
            let mut b = f.broker(family);
            b.execute(request(family, 0), None).unwrap();
            let bytes = b.journal_bytes().unwrap();
            drop(b);
            if family == TaskFamily::File {
                fs::write(f.world.join("output.txt"), b"WRONG").unwrap();
            } else {
                open_db(&f.world.join("counter.sqlite"), true)
                    .unwrap()
                    .execute("UPDATE realm_counter SET value=2", [])
                    .unwrap();
            }
            let mut b = RuntimeEffectBroker::reopen(&f.state).unwrap();
            assert!(b.report().is_err());
            assert!(b.execute(request(family, 0), None).is_err());
            assert_eq!(bytes, b.journal_bytes().unwrap());
        }
    }
    #[test]
    fn same_bytes_foreign_inode_input_substitution_and_escape_refuse() {
        let f = Fixture::new(TaskFamily::File);
        let mut b = f.broker(TaskFamily::File);
        b.execute(request(TaskFamily::File, 0), None).unwrap();
        let held = File::open(f.world.join("output.txt")).unwrap();
        fs::remove_file(f.world.join("output.txt")).unwrap();
        write_new(&f.world.join("output.txt"), b"ABC").unwrap();
        assert!(b.report().is_err());
        drop(held);
        drop(b);
        let f = Fixture::new(TaskFamily::File);
        let b = f.broker(TaskFamily::File);
        write_new(&f.world.join("third.txt"), b"x").unwrap();
        assert!(b.report().is_err());
        drop(b);
        let f = Fixture::new(TaskFamily::File);
        let b = f.broker(TaskFamily::File);
        drop(b);
        fs::write(f.world.join("input.txt"), b"changed").unwrap();
        assert!(RuntimeEffectBroker::reopen(&f.state).is_err());
    }
    #[test]
    fn journal_torn_tampered_and_reordered_refuse_without_truncation() {
        for mode in [0, 1, 2] {
            let f = Fixture::new(TaskFamily::File);
            let mut b = f.broker(TaskFamily::File);
            b.execute(request(TaskFamily::File, 0), None).unwrap();
            drop(b);
            let p = f.state.join("runtime-effects.jsonl");
            let mut bytes = fs::read(&p).unwrap();
            if mode == 0 {
                bytes.pop();
            } else if mode == 1 {
                let i = bytes.iter().position(|b| *b == b'4').unwrap();
                bytes[i] = b'9';
            } else {
                let mut lines = bytes
                    .split(|b| *b == b'\n')
                    .filter(|b| !b.is_empty())
                    .collect::<Vec<_>>();
                lines.swap(0, 1);
                bytes = lines.join(&b'\n');
                bytes.push(b'\n');
            }
            fs::write(&p, &bytes).unwrap();
            assert!(RuntimeEffectBroker::reopen(&f.state).is_err());
            assert_eq!(fs::read(&p).unwrap(), bytes);
        }
    }
    #[test]
    fn caller_timeout_cancel_and_ack_never_undo_commit() {
        let f = Fixture::new(TaskFamily::Sqlite);
        let mut b = f.broker(TaskFamily::Sqlite);
        b.execute(request(TaskFamily::Sqlite, 0), None).unwrap();
        let identity = b.frontier().unwrap();
        for state in [
            CallerState::Unknown,
            CallerState::TimedOut,
            CallerState::Cancelled,
            CallerState::Acknowledged,
        ] {
            b.delivery(state).unwrap();
            let r = b.report().unwrap();
            assert!(r.complete);
            assert_eq!(r.caller_state, state);
            assert_eq!(identity, r.frontier);
            assert_eq!(
                counter(&open_db(&f.world.join("counter.sqlite"), false).unwrap()).unwrap(),
                1
            );
        }
    }
    #[test]
    fn durable_refusal_survives_reopen_and_cannot_be_acked_or_retried_into_success() {
        let f = Fixture::new(TaskFamily::Sqlite);
        let mut b = f.broker(TaskFamily::Sqlite);
        b.execute(request(TaskFamily::Sqlite, 0), None).unwrap();
        b.record_refusal("extra", b"new effect ID", "EFFECT_CONTRACT_BUDGET_OR_ORDER")
            .unwrap();
        assert_eq!(
            b.report().unwrap().execution_disposition,
            RuntimeDisposition::Refused
        );
        assert!(b.completion().is_err());
        assert!(b.acknowledge().is_err());
        drop(b);
        let mut b = RuntimeEffectBroker::reopen(&f.state).unwrap();
        assert!(b.execute(request(TaskFamily::Sqlite, 0), None).is_err());
        assert_eq!(
            counter(&open_db(&f.world.join("counter.sqlite"), false).unwrap()).unwrap(),
            1
        );
    }
    #[test]
    fn stored_tool_result_is_bound_to_durable_delivery_chain() {
        let f = Fixture::new(TaskFamily::File);
        let mut b = f.broker(TaskFamily::File);
        b.execute(request(TaskFamily::File, 0), None).unwrap();
        let result = f.state.join("runtime-tool-result.json");
        write_new(&result, b"original bytes").unwrap();
        b.delivery(CallerState::ResultAvailable).unwrap();
        drop(b);
        fs::write(&result, b"substituted bytes").unwrap();
        assert!(RuntimeEffectBroker::reopen(&f.state).is_err());
    }
    #[test]
    fn dispatched_database_world_reconciliation_refuses_external_mismatch() {
        // Journal-prefix fixture only; actual process faults run in the Linux campaign.
        let f = Fixture::new(TaskFamily::Sqlite);
        let mut b = f.broker(TaskFamily::Sqlite);
        b.execute(request(TaskFamily::Sqlite, 0), None).unwrap();
        drop(b);
        let p = f.state.join("runtime-effects.jsonl");
        let data = fs::read_to_string(&p).unwrap();
        let prefix = data.lines().take(3).collect::<Vec<_>>().join("\n") + "\n";
        fs::write(&p, &prefix).unwrap();
        let b = RuntimeEffectBroker::reopen(&f.state).unwrap();
        assert!(!b.report().unwrap().complete);
        drop(b);
        open_db(&f.world.join("counter.sqlite"), true)
            .unwrap()
            .execute("UPDATE realm_counter SET value=2", [])
            .unwrap();
        let b = RuntimeEffectBroker::reopen(&f.state).unwrap();
        assert!(b.report().is_err());
        assert_eq!(fs::read_to_string(&p).unwrap(), prefix);
    }
    #[test]
    fn second_broker_and_database_schema_substitution_refuse() {
        let f = Fixture::new(TaskFamily::Sqlite);
        let b = f.broker(TaskFamily::Sqlite);
        assert!(matches!(
            RuntimeEffectBroker::reopen(&f.state),
            Err(EffectError::Refuse("BROKER_BUSY"))
        ));
        drop(b);
        let c = open_db(&f.world.join("counter.sqlite"), true).unwrap();
        c.execute("CREATE TABLE extra(x)", []).unwrap();
        drop(c);
        assert!(
            RuntimeEffectBroker::reopen(&f.state)
                .unwrap()
                .report()
                .is_err()
        );
    }
}
