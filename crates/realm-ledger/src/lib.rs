//! Durable append-only journal plus a rebuildable SQLite query index.
//!
//! The journal is authoritative in this foundation. SQLite is deliberately a
//! derived index: deleting or rebuilding it must not destroy historical truth.

use realm_core::{RealmEvent, TransactionMetadata};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"RLMJNL01";
const FORMAT_VERSION: u16 = 1;
const FIXED_HEADER: usize = 8 + 2 + 2 + 8 + 8;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JournalRecord {
    pub sequence: u64,
    pub record_type: String,
    pub payload: Vec<u8>,
    pub previous_hash: [u8; 32],
    pub record_hash: [u8; 32],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JournalScan {
    pub records: Vec<JournalRecord>,
    pub last_valid_offset: u64,
    pub tail_was_invalid: bool,
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("journal I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("journal frame is invalid: {0}")]
    InvalidFrame(String),
    #[error("journal payload serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("query index error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

pub struct JournalStore {
    path: PathBuf,
    file: File,
    next_sequence: u64,
    previous_hash: [u8; 32],
    repaired_tail: bool,
}

impl JournalStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let scan = scan_file(&path)?;
        if scan.tail_was_invalid {
            let file = OpenOptions::new().write(true).open(&path)?;
            file.set_len(scan.last_valid_offset)?;
            file.sync_all()?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        let (next_sequence, previous_hash) = scan
            .records
            .last()
            .map(|r| (r.sequence + 1, r.record_hash))
            .unwrap_or((1, [0; 32]));
        Ok(Self {
            path,
            file,
            next_sequence,
            previous_hash,
            repaired_tail: scan.tail_was_invalid,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn scan(&self) -> Result<JournalScan, JournalError> {
        scan_file(&self.path)
    }

    pub fn tail_was_repaired(&self) -> bool {
        self.repaired_tail
    }

    pub fn append(
        &mut self,
        record_type: impl Into<String>,
        payload: &[u8],
    ) -> Result<JournalRecord, JournalError> {
        let record_type = record_type.into();
        let record = encode_record(
            self.next_sequence,
            &record_type,
            payload,
            self.previous_hash,
        )?;
        self.file.write_all(&record.encoded)?;
        self.file.sync_all()?;
        sync_parent(&self.path)?;
        let result = JournalRecord {
            sequence: record.sequence,
            record_type,
            payload: payload.to_vec(),
            previous_hash: self.previous_hash,
            record_hash: record.record_hash,
        };
        self.next_sequence += 1;
        self.previous_hash = result.record_hash;
        Ok(result)
    }

    pub fn append_json<T: Serialize>(
        &mut self,
        record_type: impl Into<String>,
        value: &T,
    ) -> Result<JournalRecord, JournalError> {
        self.append(record_type, &serde_json::to_vec(value)?)
    }

    pub fn replay_json<T: DeserializeOwned>(
        &self,
        record_type: &str,
    ) -> Result<Vec<T>, JournalError> {
        Ok(self
            .scan()?
            .records
            .into_iter()
            .filter(|record| record.record_type == record_type)
            .map(|record| serde_json::from_slice(&record.payload))
            .collect::<Result<Vec<T>, serde_json::Error>>()?)
    }
}

struct EncodedRecord {
    sequence: u64,
    record_hash: [u8; 32],
    encoded: Vec<u8>,
}

fn encode_record(
    sequence: u64,
    record_type: &str,
    payload: &[u8],
    previous_hash: [u8; 32],
) -> Result<EncodedRecord, JournalError> {
    let type_bytes = record_type.as_bytes();
    if type_bytes.len() > u16::MAX as usize {
        return Err(JournalError::InvalidFrame("record type too long".into()));
    }
    let payload_len = u64::try_from(payload.len())
        .map_err(|_| JournalError::InvalidFrame("payload too large".into()))?;
    let mut canonical = Vec::with_capacity(FIXED_HEADER + type_bytes.len() + payload.len() + 32);
    canonical.extend_from_slice(MAGIC);
    canonical.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    canonical.extend_from_slice(&(type_bytes.len() as u16).to_le_bytes());
    canonical.extend_from_slice(&sequence.to_le_bytes());
    canonical.extend_from_slice(&payload_len.to_le_bytes());
    canonical.extend_from_slice(type_bytes);
    canonical.extend_from_slice(payload);
    canonical.extend_from_slice(&previous_hash);
    let record_hash = *blake3::hash(&canonical).as_bytes();
    let crc = crc32c::crc32c(&[canonical.as_slice(), &record_hash].concat());
    let mut encoded = canonical;
    encoded.extend_from_slice(&record_hash);
    encoded.extend_from_slice(&crc.to_le_bytes());
    Ok(EncodedRecord {
        sequence,
        record_hash,
        encoded,
    })
}

fn scan_file(path: &Path) -> Result<JournalScan, JournalError> {
    if !path.exists() {
        return Ok(JournalScan::default());
    }
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let mut offset = 0usize;
    let mut expected_sequence = 1u64;
    let mut previous_hash = [0u8; 32];
    let mut records = Vec::new();
    let mut tail_was_invalid = false;
    while offset < bytes.len() {
        let frame_start = offset;
        if bytes.len() - offset < FIXED_HEADER {
            tail_was_invalid = true;
            break;
        }
        if &bytes[offset..offset + 8] != MAGIC {
            tail_was_invalid = true;
            break;
        }
        let version = u16::from_le_bytes(bytes[offset + 8..offset + 10].try_into().unwrap());
        let type_len =
            u16::from_le_bytes(bytes[offset + 10..offset + 12].try_into().unwrap()) as usize;
        let sequence = u64::from_le_bytes(bytes[offset + 12..offset + 20].try_into().unwrap());
        let payload_len = u64::from_le_bytes(bytes[offset + 20..offset + 28].try_into().unwrap());
        if version != FORMAT_VERSION
            || sequence != expected_sequence
            || payload_len > usize::MAX as u64
        {
            tail_was_invalid = true;
            break;
        }
        let body_len = type_len
            .checked_add(payload_len as usize)
            .and_then(|n| n.checked_add(32))
            .and_then(|n| n.checked_add(32))
            .and_then(|n| n.checked_add(4));
        let Some(body_len) = body_len else {
            tail_was_invalid = true;
            break;
        };
        let frame_len = FIXED_HEADER.saturating_add(body_len);
        if bytes.len() - offset < frame_len {
            tail_was_invalid = true;
            break;
        }
        let end = offset + frame_len;
        let type_start = offset + FIXED_HEADER;
        let payload_start = type_start + type_len;
        let previous_start = payload_start + payload_len as usize;
        let hash_start = previous_start + 32;
        let crc_start = hash_start + 32;
        let record_type = match String::from_utf8(bytes[type_start..payload_start].to_vec()) {
            Ok(value) => value,
            Err(_) => {
                tail_was_invalid = true;
                break;
            }
        };
        let payload = bytes[payload_start..previous_start].to_vec();
        let previous: [u8; 32] = bytes[previous_start..hash_start].try_into().unwrap();
        let record_hash: [u8; 32] = bytes[hash_start..crc_start].try_into().unwrap();
        let crc = u32::from_le_bytes(bytes[crc_start..end].try_into().unwrap());
        let canonical = &bytes[frame_start..hash_start];
        if previous != previous_hash
            || *blake3::hash(canonical).as_bytes() != record_hash
            || crc32c::crc32c(&bytes[frame_start..crc_start]) != crc
        {
            tail_was_invalid = true;
            break;
        }
        records.push(JournalRecord {
            sequence,
            record_type,
            payload,
            previous_hash: previous,
            record_hash,
        });
        previous_hash = record_hash;
        expected_sequence += 1;
        offset = end;
    }
    Ok(JournalScan {
        records,
        last_valid_offset: offset as u64,
        tail_was_invalid,
    })
}

fn sync_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        {
            File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}

pub struct QueryIndex {
    connection: Connection,
}

impl QueryIndex {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        let index = Self { connection };
        index.initialize()?;
        Ok(index)
    }

    pub fn initialize(&self) -> Result<(), JournalError> {
        self.connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS transactions (
                 id TEXT PRIMARY KEY, parent_id TEXT, actor_kind TEXT NOT NULL,
                 actor_id TEXT NOT NULL, semantic_session_id TEXT, intent TEXT,
                 capture_backend TEXT NOT NULL, platform TEXT NOT NULL,
                 start_wall_time_ms INTEGER NOT NULL, end_wall_time_ms INTEGER,
                 state TEXT NOT NULL, capture_status TEXT NOT NULL,
                 recovery_capability TEXT NOT NULL, payload BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS processes (
                 id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL, payload BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS objects (
                 id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS object_paths (
                 object_id TEXT NOT NULL, raw_path BLOB NOT NULL,
                 valid_from_sequence INTEGER NOT NULL, valid_until_sequence INTEGER
             );
             CREATE TABLE IF NOT EXISTS object_versions (
                 id TEXT PRIMARY KEY, object_id TEXT NOT NULL, content_hash TEXT,
                 metadata_hash TEXT, blob_ref TEXT, fidelity TEXT NOT NULL,
                 preservation_method TEXT NOT NULL, payload BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS events (
                 sequence INTEGER PRIMARY KEY, transaction_id TEXT NOT NULL,
                 object_id TEXT, kind TEXT NOT NULL, payload BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS transaction_reads (
                 transaction_id TEXT NOT NULL, object_id TEXT NOT NULL,
                 first_sequence INTEGER NOT NULL, last_sequence INTEGER NOT NULL,
                 count INTEGER NOT NULL, PRIMARY KEY(transaction_id, object_id)
             );
             CREATE TABLE IF NOT EXISTS transaction_writes (
                 transaction_id TEXT NOT NULL, object_id TEXT NOT NULL,
                 first_sequence INTEGER NOT NULL, last_sequence INTEGER NOT NULL,
                 count INTEGER NOT NULL, PRIMARY KEY(transaction_id, object_id)
             );
             CREATE TABLE IF NOT EXISTS capture_gaps (
                 transaction_id TEXT NOT NULL, stream TEXT NOT NULL,
                 expected_sequence INTEGER NOT NULL, observed_sequence INTEGER NOT NULL,
                 payload BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS external_effects (
                 transaction_id TEXT NOT NULL, effect_id TEXT NOT NULL,
                 class TEXT NOT NULL, payload BLOB NOT NULL,
                 PRIMARY KEY(transaction_id, effect_id)
             );
             CREATE TABLE IF NOT EXISTS recovery_contracts (
                 transaction_id TEXT PRIMARY KEY, contract_version INTEGER NOT NULL,
                 payload BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS verification_runs (
                 id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL,
                 status TEXT NOT NULL, payload BLOB NOT NULL
             );",
        )?;
        Ok(())
    }

    pub fn upsert_transaction(
        &self,
        transaction: &TransactionMetadata,
    ) -> Result<(), JournalError> {
        let payload = serde_json::to_vec(transaction)?;
        self.connection.execute(
            "INSERT INTO transactions (id,parent_id,actor_kind,actor_id,semantic_session_id,intent,capture_backend,platform,start_wall_time_ms,end_wall_time_ms,state,capture_status,recovery_capability,payload)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
             ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,state=excluded.state,end_wall_time_ms=excluded.end_wall_time_ms,capture_status=excluded.capture_status,recovery_capability=excluded.recovery_capability",
            params![transaction.id.to_string(), transaction.parent_id.map(|v| v.to_string()), format!("{:?}", transaction.actor.kind), transaction.actor.actor_id, transaction.actor.semantic_session_id, transaction.actor.declared_intent, transaction.capture_backend, transaction.platform, transaction.start_wall_time_ms, transaction.end_wall_time_ms, format!("{:?}", transaction.state), format!("{:?}", transaction.capture_status), format!("{:?}", transaction.recovery_capability), payload],
        )?;
        Ok(())
    }

    pub fn insert_event(&self, event: &RealmEvent) -> Result<(), JournalError> {
        self.connection.execute(
            "INSERT OR REPLACE INTO events (sequence,transaction_id,object_id,kind,payload) VALUES (?1,?2,?3,?4,?5)",
            params![event.sequence as i64, event.transaction_id.to_string(), event.object_id.map(|v| v.to_string()), format!("{:?}", event.kind), serde_json::to_vec(event)?],
        )?;
        Ok(())
    }

    pub fn event_count(&self) -> Result<u64, JournalError> {
        Ok(self
            .connection
            .query_row("SELECT COUNT(*) FROM events", [], |row| {
                row.get::<_, i64>(0)
            })? as u64)
    }

    pub fn rebuild_from_journal(&self, journal: &JournalStore) -> Result<(), JournalError> {
        self.connection
            .execute_batch("DELETE FROM events; DELETE FROM transactions;")?;
        for record in journal.scan()?.records {
            match record.record_type.as_str() {
                "EVENT" => {
                    let event: RealmEvent = serde_json::from_slice(&record.payload)?;
                    self.insert_event(&event)?;
                }
                "TRANSACTION" => {
                    let transaction: TransactionMetadata = serde_json::from_slice(&record.payload)?;
                    self.upsert_transaction(&transaction)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "realm-ledger-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn journal_replays_and_repairs_partial_tail() {
        let path = temp_path("journal");
        let mut journal = JournalStore::open(&path).unwrap();
        journal.append("TEST", b"one").unwrap();
        journal.append("TEST", b"two").unwrap();
        drop(journal);
        let valid_len = fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"partial")
            .unwrap();
        let repaired = JournalStore::open(&path).unwrap();
        assert!(repaired.tail_was_repaired());
        assert_eq!(repaired.scan().unwrap().records.len(), 2);
        assert_eq!(fs::metadata(&path).unwrap().len(), valid_len);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn replay_is_idempotent() {
        let path = temp_path("idempotent");
        let mut journal = JournalStore::open(&path).unwrap();
        journal.append("TEST", b"one").unwrap();
        let once: Vec<Vec<u8>> = journal.replay_json("NOPE").unwrap();
        let twice: Vec<Vec<u8>> = journal.replay_json("NOPE").unwrap();
        assert_eq!(once, twice);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn query_index_rebuilds_from_authoritative_journal() {
        let root = temp_path("index");
        let journal_path = root.join("journal.log");
        let index_path = root.join("index.sqlite");
        fs::create_dir_all(&root).unwrap();
        let mut journal = JournalStore::open(&journal_path).unwrap();
        let event = RealmEvent {
            schema_version: 1,
            sequence: 1,
            transaction_id: realm_core::TransactionId::new(),
            actor_id: "test".into(),
            process_id: None,
            object_id: None,
            object_version_id: None,
            path: None,
            kind: realm_core::RealmEventKind::AgentSemanticEvent,
            evidence: realm_core::EvidenceStrength::AgentDeclared,
            wall_time_ms: 1,
            monotonic_ns: 1,
            pre_version: None,
            post_version: None,
            metadata: serde_json::json!({}),
        };
        journal.append_json("EVENT", &event).unwrap();
        let index = QueryIndex::open(&index_path).unwrap();
        index.rebuild_from_journal(&journal).unwrap();
        assert_eq!(index.event_count().unwrap(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hash_or_crc_corruption_is_detected_and_not_replayed() {
        let path = temp_path("corrupt");
        let mut journal = JournalStore::open(&path).unwrap();
        journal.append("TEST", b"one").unwrap();
        journal.append("TEST", b"two").unwrap();
        drop(journal);
        let mut bytes = fs::read(&path).unwrap();
        bytes[40] ^= 0x80;
        fs::write(&path, bytes).unwrap();
        let reopened = JournalStore::open(&path).unwrap();
        assert!(reopened.tail_was_repaired());
        assert_eq!(reopened.scan().unwrap().records.len(), 0);
        fs::remove_file(path).unwrap();
    }
}
