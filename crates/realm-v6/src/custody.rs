//! Independent, non-authorizing C0 output writer and durable write history.
//!
//! The launcher must give this process the only writable output descriptor and
//! keep its socket/journal inaccessible to the guest and broker. These local
//! checks cannot establish that host containment assumption by themselves.
use crate::frontier::{FrontierAudit, ObjectIdentity, RecordKind};
use crate::profile::SyncTrace as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const MAX_WRITE: usize = 1024 * 1024;
const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_FRAME: usize = 8 * 1024 * 1024;
const MAX_JOURNAL: u64 = 64 * 1024 * 1024;
const MAX_RECORDS: u64 = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CustodyError {
    Malformed,
    ResourceLimit,
    Refused,
    Ambiguous,
    Journal,
    Io,
    Mismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyCommand {
    Write,
    Seal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyWriteRequest {
    pub command: CustodyCommand,
    pub run_id: String,
    pub operation_id: String,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyWriteResponse {
    pub run_id: String,
    pub operation_id: String,
    pub completed: u64,
    pub after_digest: String,
    pub result_sequence: u64,
    pub result_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyResult {
    pub completed: usize,
    pub after_digest: String,
    pub sequence: u64,
    pub result_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Intent,
    Result,
    Seal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyRecord {
    schema: u8,
    run_id: String,
    sequence: u64,
    operation_id: String,
    kind: Kind,
    object: ObjectIdentity,
    offset: u64,
    requested: u64,
    completed: u64,
    bytes: Vec<u8>,
    before_digest: String,
    #[serde(deserialize_with = "crate::strict_json::present_option")]
    after_digest: Option<String>,
    previous_hash: String,
    hash: String,
}

fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_op(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'-')
}

fn validate_request(r: &CustodyWriteRequest) -> Result<(), CustodyError> {
    if !lower_hex_64(&r.run_id) || !valid_op(&r.operation_id) {
        return Err(CustodyError::Malformed);
    }
    if r.command == CustodyCommand::Seal {
        return if r.offset == 0 && r.bytes.is_empty() {
            Ok(())
        } else {
            Err(CustodyError::Malformed)
        };
    }
    if r.bytes.len() > MAX_WRITE
        || r.offset > MAX_OUTPUT as u64
        || r.offset
            .checked_add(r.bytes.len() as u64)
            .is_none_or(|end| end > MAX_OUTPUT as u64)
    {
        return Err(CustodyError::ResourceLimit);
    }
    Ok(())
}

fn read_frame<T: for<'de> Deserialize<'de>>(
    stream: &mut UnixStream,
) -> Result<Option<T>, CustodyError> {
    let mut prefix = [0u8; 4];
    match stream.read(&mut prefix[..1]) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        _ => return Err(CustodyError::Io),
    }
    stream
        .read_exact(&mut prefix[1..])
        .map_err(|_| CustodyError::Ambiguous)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(CustodyError::Malformed);
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|_| CustodyError::Ambiguous)?;
    let value = crate::strict_json::parse(&bytes).map_err(|_| CustodyError::Malformed)?;
    serde_json::from_value(value)
        .map(Some)
        .map_err(|_| CustodyError::Malformed)
}

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), CustodyError> {
    let bytes = serde_json::to_vec(value).map_err(|_| CustodyError::Malformed)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(CustodyError::ResourceLimit);
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .map_err(|_| CustodyError::Io)?;
    stream.write_all(&bytes).map_err(|_| CustodyError::Io)?;
    stream.flush().map_err(|_| CustodyError::Io)
}

fn object_identity(file: &File) -> Result<ObjectIdentity, CustodyError> {
    let metadata = file.metadata().map_err(|_| CustodyError::Refused)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(CustodyError::Refused);
    }
    Ok(ObjectIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn fd_flags(file: &File) -> Result<i32, CustodyError> {
    // SAFETY: AsRawFd yields a live descriptor for the duration of this call.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        Err(CustodyError::Refused)
    } else {
        Ok(flags)
    }
}

fn file_digest(file: &File) -> Result<String, CustodyError> {
    let before = file.metadata().map_err(|_| CustodyError::Ambiguous)?;
    if before.len() > MAX_OUTPUT as u64 {
        return Err(CustodyError::ResourceLimit);
    }
    let mut bytes = vec![0; before.len() as usize];
    let mut position = 0;
    while position < bytes.len() {
        let n = file
            .read_at(&mut bytes[position..], position as u64)
            .map_err(|_| CustodyError::Ambiguous)?;
        if n == 0 {
            return Err(CustodyError::Ambiguous);
        }
        position += n;
    }
    let after = file.metadata().map_err(|_| CustodyError::Ambiguous)?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(CustodyError::Ambiguous);
    }
    Ok(digest(&bytes))
}

fn record_hash(record: &CustodyRecord) -> Result<String, CustodyError> {
    let mut unsigned = record.clone();
    unsigned.hash.clear();
    Ok(digest(
        &serde_json::to_vec(&unsigned).map_err(|_| CustodyError::Journal)?,
    ))
}

/// The broker holds only the socket and an O_RDONLY output FD. Any response
/// ambiguity poisons the client; it cannot retry a write operation.
pub struct CustodyClient {
    stream: UnixStream,
    run_id: String,
    next_result_sequence: u64,
    poisoned: bool,
    sealed: bool,
}

impl CustodyClient {
    pub fn new(stream: UnixStream, run_id: String) -> Self {
        Self {
            stream,
            run_id,
            next_result_sequence: 1,
            poisoned: false,
            sealed: false,
        }
    }

    pub fn commit(
        &mut self,
        operation_id: &str,
        offset: u64,
        bytes: &[u8],
    ) -> Result<CustodyResult, CustodyError> {
        let request = CustodyWriteRequest {
            command: CustodyCommand::Write,
            run_id: self.run_id.clone(),
            operation_id: operation_id.into(),
            offset,
            bytes: bytes.to_vec(),
        };
        if self.poisoned || self.sealed {
            return Err(CustodyError::Ambiguous);
        }
        if let Err(error) = validate_request(&request) {
            self.poisoned = true;
            return Err(error);
        }
        let result = (|| {
            self.stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .map_err(|_| CustodyError::Io)?;
            self.stream
                .set_write_timeout(Some(Duration::from_secs(20)))
                .map_err(|_| CustodyError::Io)?;
            write_frame(&mut self.stream, &request)?;
            let reply: CustodyWriteResponse =
                read_frame(&mut self.stream)?.ok_or(CustodyError::Ambiguous)?;
            if reply.run_id != request.run_id
                || reply.operation_id != request.operation_id
                || reply.result_sequence != self.next_result_sequence
                || !lower_hex_64(&reply.after_digest)
                || !lower_hex_64(&reply.result_hash)
                || reply.completed > request.bytes.len() as u64
            {
                return Err(CustodyError::Mismatch);
            }
            self.next_result_sequence = self
                .next_result_sequence
                .checked_add(2)
                .ok_or(CustodyError::ResourceLimit)?;
            Ok(CustodyResult {
                completed: reply.completed as usize,
                after_digest: reply.after_digest,
                sequence: reply.result_sequence,
                result_hash: reply.result_hash,
            })
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// The caller must first establish a trusted post-VMM terminal barrier.
    /// A transport EOF cannot supply that evidence because a crash also closes
    /// the socket. The returned head is a diagnostic custody root only.
    pub fn seal_after_barrier(&mut self, barrier_id: &str) -> Result<String, CustodyError> {
        if self.poisoned || self.sealed || !valid_op(barrier_id) {
            self.poisoned = true;
            return Err(CustodyError::Refused);
        }
        let request = CustodyWriteRequest {
            command: CustodyCommand::Seal,
            run_id: self.run_id.clone(),
            operation_id: barrier_id.into(),
            offset: 0,
            bytes: Vec::new(),
        };
        let result = (|| {
            write_frame(&mut self.stream, &request)?;
            let reply: CustodyWriteResponse =
                read_frame(&mut self.stream)?.ok_or(CustodyError::Ambiguous)?;
            if reply.run_id != self.run_id
                || reply.operation_id != barrier_id
                || reply.completed != 0
                || reply.result_sequence != self.next_result_sequence - 1
                || !lower_hex_64(&reply.after_digest)
                || !lower_hex_64(&reply.result_hash)
            {
                return Err(CustodyError::Mismatch);
            }
            self.sealed = true;
            Ok(reply.result_hash)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

/// One-run custodian. Starting from any nonempty journal or output refuses;
/// recovery must audit the prior run instead of replaying its writes.
pub struct CustodyServer {
    output: File,
    journal: File,
    object: ObjectIdentity,
    run_id: String,
    content_digest: String,
    head: String,
    sequence: u64,
    used: BTreeSet<String>,
    poisoned: bool,
    sealed: bool,
}

impl CustodyServer {
    pub fn new(output: File, journal: File, run_id: String) -> Result<Self, CustodyError> {
        if !lower_hex_64(&run_id)
            || fd_flags(&output)? & libc::O_ACCMODE != libc::O_RDWR
            || fd_flags(&journal)? & libc::O_ACCMODE == libc::O_RDONLY
            || fd_flags(&journal)? & libc::O_APPEND == 0
            || output.metadata().map_err(|_| CustodyError::Refused)?.len() != 0
            || journal.metadata().map_err(|_| CustodyError::Refused)?.len() != 0
        {
            return Err(CustodyError::Refused);
        }
        let object = object_identity(&output)?;
        if object_identity(&journal)? == object {
            return Err(CustodyError::Refused);
        }
        output.sync_all_traced().map_err(|_| CustodyError::Io)?;
        journal.sync_all_traced().map_err(|_| CustodyError::Io)?;
        Ok(Self {
            output,
            journal,
            object,
            run_id,
            content_digest: digest(&[]),
            head: "0".repeat(64),
            sequence: 0,
            used: BTreeSet::new(),
            poisoned: false,
            sealed: false,
        })
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn append(&mut self, mut record: CustodyRecord) -> Result<(), CustodyError> {
        if self.sequence >= MAX_RECORDS {
            self.poisoned = true;
            return Err(CustodyError::ResourceLimit);
        }
        record.sequence = self.sequence;
        record.previous_hash = self.head.clone();
        record.hash = record_hash(&record)?;
        let mut bytes = serde_json::to_vec(&record).map_err(|_| CustodyError::Journal)?;
        bytes.push(b'\n');
        let journal_len = self
            .journal
            .metadata()
            .map_err(|_| CustodyError::Journal)?
            .len();
        if journal_len.saturating_add(bytes.len() as u64) > MAX_JOURNAL {
            self.poisoned = true;
            return Err(CustodyError::ResourceLimit);
        }
        if self.journal.write_all(&bytes).is_err() || self.journal.sync_all_traced().is_err() {
            self.poisoned = true;
            return Err(CustodyError::Journal);
        }
        self.sequence += 1;
        self.head = record.hash;
        Ok(())
    }

    fn record(&self, op: &str, kind: Kind, offset: u64, requested: u64) -> CustodyRecord {
        CustodyRecord {
            schema: 1,
            run_id: self.run_id.clone(),
            sequence: 0,
            operation_id: op.into(),
            kind,
            object: self.object.clone(),
            offset,
            requested,
            completed: 0,
            bytes: Vec::new(),
            before_digest: self.content_digest.clone(),
            after_digest: None,
            previous_hash: String::new(),
            hash: String::new(),
        }
    }

    fn commit_request(
        &mut self,
        request: CustodyWriteRequest,
    ) -> Result<CustodyWriteResponse, CustodyError> {
        let result = self.commit_request_inner(request);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn commit_request_inner(
        &mut self,
        request: CustodyWriteRequest,
    ) -> Result<CustodyWriteResponse, CustodyError> {
        if self.poisoned || self.sealed {
            return Err(CustodyError::Ambiguous);
        }
        if request.run_id != self.run_id
            || validate_request(&request).is_err()
            || self.used.contains(&request.operation_id)
        {
            self.poisoned = true;
            return Err(CustodyError::Refused);
        }
        if request.command == CustodyCommand::Seal {
            if self.used.is_empty() || file_digest(&self.output)? != self.content_digest {
                return Err(CustodyError::Ambiguous);
            }
            let mut seal = self.record(&request.operation_id, Kind::Seal, 0, 0);
            seal.after_digest = Some(self.content_digest.clone());
            self.append(seal)?;
            self.sealed = true;
            return Ok(CustodyWriteResponse {
                run_id: self.run_id.clone(),
                operation_id: request.operation_id,
                completed: 0,
                after_digest: self.content_digest.clone(),
                result_sequence: self.sequence - 1,
                result_hash: self.head.clone(),
            });
        }
        if file_digest(&self.output)? != self.content_digest {
            self.poisoned = true;
            return Err(CustodyError::Ambiguous);
        }
        let mut intent = self.record(
            &request.operation_id,
            Kind::Intent,
            request.offset,
            request.bytes.len() as u64,
        );
        intent.bytes = request.bytes.clone();
        self.append(intent)?;
        self.used.insert(request.operation_id.clone());
        let completed = match self.output.write_at(&request.bytes, request.offset) {
            Ok(n) => n,
            Err(_) => {
                self.poisoned = true;
                return Err(CustodyError::Ambiguous);
            }
        };
        if self.output.sync_all_traced().is_err() {
            self.poisoned = true;
            return Err(CustodyError::Ambiguous);
        }
        let after_digest = match file_digest(&self.output) {
            Ok(digest) => digest,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let mut result = self.record(
            &request.operation_id,
            Kind::Result,
            request.offset,
            request.bytes.len() as u64,
        );
        result.completed = completed as u64;
        result.bytes = request.bytes[..completed].to_vec();
        result.after_digest = Some(after_digest.clone());
        self.append(result)?;
        self.content_digest = after_digest.clone();
        Ok(CustodyWriteResponse {
            run_id: self.run_id.clone(),
            operation_id: request.operation_id,
            completed: completed as u64,
            after_digest,
            result_sequence: self.sequence - 1,
            result_hash: self.head.clone(),
        })
    }

    /// Returns false only for a clean EOF before the next frame. No success
    /// response is sent until both the object and result record are durable.
    pub fn serve_one(&mut self, stream: &mut UnixStream) -> Result<bool, CustodyError> {
        if self.poisoned {
            return Err(CustodyError::Ambiguous);
        }
        let request: CustodyWriteRequest = match read_frame(stream) {
            Ok(Some(request)) => request,
            Ok(None) if self.sealed => return Ok(false),
            Ok(None) => {
                self.poisoned = true;
                return Err(CustodyError::Ambiguous);
            }
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let response = self.commit_request(request)?;
        if let Err(error) = write_frame(stream, &response) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(true)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyAudit {
    pub head: String,
    pub final_output_digest: String,
    pub committed_write_count: u64,
}

/// Audits exact write history against a previously audited broker frontier.
/// The C0 output starts empty. This comparison detects extra writes, duplicate
/// same-byte writes, and write-then-restore histories even when final bytes
/// match. It does not authenticate journal custody or grant admission.
pub fn audit_custody_against_frontier(
    raw: &[u8],
    frontier: &FrontierAudit,
    output: &ObjectIdentity,
) -> Result<CustodyAudit, CustodyError> {
    if raw.is_empty() || raw.len() as u64 > MAX_JOURNAL || !raw.ends_with(b"\n") {
        return Err(CustodyError::Journal);
    }
    let expected_run = frontier
        .records()
        .first()
        .ok_or(CustodyError::Mismatch)?
        .run_id
        .as_str();
    let mut records = Vec::new();
    let mut head = "0".repeat(64);
    for line in raw[..raw.len() - 1].split(|b| *b == b'\n') {
        if line.is_empty() || line.contains(&b'\r') {
            return Err(CustodyError::Journal);
        }
        let value = crate::strict_json::parse(line).map_err(|_| CustodyError::Journal)?;
        let record: CustodyRecord =
            serde_json::from_value(value).map_err(|_| CustodyError::Journal)?;
        if records.len() as u64 >= MAX_RECORDS
            || record.schema != 1
            || record.run_id != expected_run
            || record.object != *output
            || record.sequence != records.len() as u64
            || record.previous_hash != head
            || record_hash(&record)? != record.hash
        {
            return Err(CustodyError::Journal);
        }
        head = record.hash.clone();
        records.push(record);
    }
    let seal = records.last().ok_or(CustodyError::Ambiguous)?;
    let frontier_seal = frontier.records().last().ok_or(CustodyError::Mismatch)?;
    if records.len() < 3
        || seal.kind != Kind::Seal
        || frontier_seal.kind != RecordKind::Seal
        || frontier_seal.freeze_epoch.as_deref() != Some(seal.operation_id.as_str())
        || !valid_op(&seal.operation_id)
        || seal.offset != 0
        || seal.requested != 0
        || seal.completed != 0
        || !seal.bytes.is_empty()
        || (records.len() - 1) % 2 != 0
    {
        return Err(CustodyError::Ambiguous);
    }
    let mut simulated = Vec::new();
    let mut used = BTreeSet::new();
    let mut effect_version = digest(
        format!(
            "output-v1:{}:{}:{}",
            output.device,
            output.inode,
            digest(&[])
        )
        .as_bytes(),
    );
    let mut positive_generation = 0u64;
    let mut frontier_writes = frontier.records().iter().filter(|record| {
        matches!(
            record.kind,
            RecordKind::IntentWrite | RecordKind::ResultWrite
        )
    });
    // The odd terminal seal was excluded above; each remaining pair is one
    // intent and its corresponding result.
    for pair in records[..records.len() - 1].as_chunks::<2>().0 {
        let intent = &pair[0];
        let result = &pair[1];
        if intent.kind != Kind::Intent
            || result.kind != Kind::Result
            || !valid_op(&intent.operation_id)
            || !used.insert(intent.operation_id.clone())
            || result.operation_id != intent.operation_id
            || intent.offset > MAX_OUTPUT as u64
            || intent.requested > MAX_WRITE as u64
            || intent
                .offset
                .checked_add(intent.requested)
                .is_none_or(|end| end > MAX_OUTPUT as u64)
            || intent.completed != 0
            || intent.bytes.len() as u64 != intent.requested
            || intent.before_digest != digest(&simulated)
            || intent.after_digest.is_some()
            || result.offset != intent.offset
            || result.requested != intent.requested
            || result.completed > intent.requested
            || result.bytes != intent.bytes[..result.completed as usize]
            || result.before_digest != intent.before_digest
        {
            return Err(CustodyError::Mismatch);
        }
        if result.completed > 0 {
            let start = intent.offset as usize;
            let end = start + result.completed as usize;
            simulated.resize(simulated.len().max(end), 0);
            simulated[start..end].copy_from_slice(&result.bytes);
            positive_generation += 1;
        }
        let after_digest = digest(&simulated);
        if result.after_digest.as_deref() != Some(after_digest.as_str()) {
            return Err(CustodyError::Mismatch);
        }
        let next_effect_version = if result.completed > 0 {
            digest(
                format!(
                    "output-write-v1:{}:{}:{}:{}",
                    effect_version, positive_generation, intent.operation_id, after_digest
                )
                .as_bytes(),
            )
        } else {
            effect_version.clone()
        };
        let broker_intent = frontier_writes.next().ok_or(CustodyError::Mismatch)?;
        let broker_result = frontier_writes.next().ok_or(CustodyError::Mismatch)?;
        if broker_intent.kind != RecordKind::IntentWrite
            || broker_result.kind != RecordKind::ResultWrite
            || broker_intent.run_id != expected_run
            || broker_result.run_id != expected_run
            || broker_intent.object.as_ref() != Some(output)
            || broker_result.object.as_ref() != Some(output)
            || broker_intent.operation_id != intent.operation_id
            || broker_result.operation_id != result.operation_id
            || broker_intent.offset != intent.offset
            || broker_result.offset != result.offset
            || broker_intent.requested != intent.requested
            || broker_result.requested != result.requested
            || broker_intent.completed != 0
            || broker_intent.bytes != intent.bytes
            || broker_result.completed != result.completed
            || broker_result.bytes != result.bytes
            || broker_intent.object_version_before.as_deref() != Some(effect_version.as_str())
            || broker_result.object_version_before.as_deref() != Some(effect_version.as_str())
            || broker_result.object_version_after.as_deref() != Some(next_effect_version.as_str())
        {
            return Err(CustodyError::Mismatch);
        }
        effect_version = next_effect_version;
    }
    if used.is_empty()
        || used.contains(&seal.operation_id)
        || frontier_writes.next().is_some()
        || frontier.committed_write_count != used.len() as u64
    {
        return Err(CustodyError::Mismatch);
    }
    if seal.before_digest != digest(&simulated)
        || seal.after_digest.as_deref() != Some(digest(&simulated).as_str())
    {
        return Err(CustodyError::Mismatch);
    }
    Ok(CustodyAudit {
        head,
        final_output_digest: digest(&simulated),
        committed_write_count: used.len() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontier::{EffectFrontier, audit_journal};
    use std::fs::{self, OpenOptions};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    const RUN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static NEXT_DIR: AtomicU64 = AtomicU64::new(1);

    fn test_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "realm-custody-test-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        dir
    }

    fn broker_history_with_epoch(
        writes: &[(&str, u64, &[u8])],
        epoch: &str,
    ) -> (PathBuf, FrontierAudit, ObjectIdentity) {
        let dir = test_dir();
        let input = dir.join("input");
        let output = dir.join("output");
        fs::write(&input, b"abc").unwrap();
        fs::write(&output, b"").unwrap();
        let mut broker = EffectFrontier::create(&dir, RUN, "broker", &input, &output).unwrap();
        broker
            .bind_topology(&"b".repeat(64), &"c".repeat(64), &"d".repeat(64))
            .unwrap();
        for (op, offset, bytes) in writes {
            assert_eq!(broker.write(op, *offset, bytes).unwrap(), bytes.len());
        }
        broker.seal(epoch).unwrap();
        let audit = audit_journal(broker.journal_path(), RUN, "broker").unwrap();
        let identity = audit
            .records()
            .iter()
            .find(|r| r.kind == RecordKind::IntentWrite)
            .unwrap()
            .object
            .clone()
            .unwrap();
        drop(broker);
        // The custodian separately replays the already audited broker history
        // against the same inode from the required empty C0 starting state.
        let reset = OpenOptions::new().write(true).open(&output).unwrap();
        reset.set_len(0).unwrap();
        reset.sync_all_traced().unwrap();
        (dir, audit, identity)
    }

    fn broker_history(writes: &[(&str, u64, &[u8])]) -> (PathBuf, FrontierAudit, ObjectIdentity) {
        broker_history_with_epoch(writes, "epoch-1")
    }

    fn server(dir: &Path, suffix: &str) -> CustodyServer {
        let output = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join("output"))
            .unwrap();
        let journal = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(dir.join(suffix))
            .unwrap();
        CustodyServer::new(output, journal, RUN.into()).unwrap()
    }

    fn request(op: &str, bytes: &[u8]) -> CustodyWriteRequest {
        CustodyWriteRequest {
            command: CustodyCommand::Write,
            run_id: RUN.into(),
            operation_id: op.into(),
            offset: 0,
            bytes: bytes.into(),
        }
    }

    fn seal_request() -> CustodyWriteRequest {
        CustodyWriteRequest {
            command: CustodyCommand::Seal,
            run_id: RUN.into(),
            operation_id: "epoch-1".into(),
            offset: 0,
            bytes: vec![],
        }
    }

    fn replay(dir: &Path, suffix: &str, writes: &[(&str, u64, &[u8])]) -> Vec<u8> {
        let mut service = server(dir, suffix);
        for (op, offset, bytes) in writes {
            let mut r = request(op, bytes);
            r.offset = *offset;
            let answer = service.commit_request(r).unwrap();
            assert_eq!(answer.completed as usize, bytes.len());
        }
        service.commit_request(seal_request()).unwrap();
        drop(service);
        fs::read(dir.join(suffix)).unwrap()
    }

    #[test]
    fn actual_socket_roundtrip_seals_only_after_explicit_barrier() {
        let writes = [("1:4", 0, b"A".as_slice())];
        let (dir, frontier, identity) = broker_history(&writes);
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let mut service = server(&dir, "custody.jsonl");
        let worker = std::thread::spawn(move || {
            while service.serve_one(&mut server_stream).unwrap() {}
            assert!(!service.is_poisoned());
        });
        let mut client = CustodyClient::new(client_stream, RUN.into());
        let result = client.commit("1:4", 0, b"A").unwrap();
        assert_eq!(result.completed, 1);
        assert_eq!(result.after_digest, digest(b"A"));
        assert!(lower_hex_64(&client.seal_after_barrier("epoch-1").unwrap()));
        assert_eq!(client.commit("1:5", 0, b"B"), Err(CustodyError::Ambiguous));
        drop(client);
        worker.join().unwrap();
        let audit = audit_custody_against_frontier(
            &fs::read(dir.join("custody.jsonl")).unwrap(),
            &frontier,
            &identity,
        )
        .unwrap();
        assert_eq!(audit.committed_write_count, 1);
        assert_eq!(audit.final_output_digest, digest(b"A"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn same_byte_and_restore_history_cannot_be_erased() {
        let writes = [
            ("1:4", 0, b"A".as_slice()),
            ("1:5", 0, b"A".as_slice()),
            ("1:6", 0, b"B".as_slice()),
            ("1:7", 0, b"A".as_slice()),
        ];
        let (dir, frontier, identity) = broker_history(&writes);
        let raw = replay(&dir, "custody.jsonl", &writes);
        let good = audit_custody_against_frontier(&raw, &frontier, &identity).unwrap();
        assert_eq!(good.committed_write_count, 4);
        assert_eq!(good.final_output_digest, digest(b"A"));
        // Remove the second (same-byte) write and rebuild a valid custody hash
        // chain. Equal final bytes cannot make the histories equivalent.
        let mut records: Vec<CustodyRecord> = raw[..raw.len() - 1]
            .split(|b| *b == b'\n')
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        records.drain(2..4);
        let mut head = "0".repeat(64);
        let mut shortened = Vec::new();
        for (sequence, record) in records.iter_mut().enumerate() {
            record.sequence = sequence as u64;
            record.previous_hash = head;
            record.hash = record_hash(record).unwrap();
            head = record.hash.clone();
            shortened.extend(serde_json::to_vec(record).unwrap());
            shortened.push(b'\n');
        }
        assert_eq!(
            audit_custody_against_frontier(&shortened, &frontier, &identity),
            Err(CustodyError::Mismatch)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn audit_rejects_seal_reusing_a_write_operation_id() {
        let writes = [("1:4", 0, b"A".as_slice())];
        let (dir, frontier, identity) = broker_history_with_epoch(&writes, "1:4");
        let raw = replay(&dir, "custody.jsonl", &writes);
        let mut records: Vec<CustodyRecord> = raw[..raw.len() - 1]
            .split(|b| *b == b'\n')
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        let last = records.last_mut().unwrap();
        last.operation_id = "1:4".into();
        last.hash = record_hash(last).unwrap();
        let mut forged = Vec::new();
        for record in records {
            forged.extend(serde_json::to_vec(&record).unwrap());
            forged.push(b'\n');
        }
        assert_eq!(
            audit_custody_against_frontier(&forged, &frontier, &identity),
            Err(CustodyError::Mismatch)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn duplicate_wrong_run_and_early_seal_poison() {
        let (dir, _, _) = broker_history(&[("1:4", 0, b"A".as_slice())]);
        let mut service = server(&dir, "one.jsonl");
        assert_eq!(
            service.commit_request(seal_request()),
            Err(CustodyError::Ambiguous)
        );
        assert!(service.is_poisoned());
        drop(service);
        let mut service = server(&dir, "two.jsonl");
        service.commit_request(request("1:4", b"A")).unwrap();
        assert_eq!(
            service.commit_request(request("1:4", b"A")),
            Err(CustodyError::Refused)
        );
        assert!(service.is_poisoned());
        drop(service);
        let reset = OpenOptions::new()
            .write(true)
            .open(dir.join("output"))
            .unwrap();
        reset.set_len(0).unwrap();
        reset.sync_all_traced().unwrap();
        let mut wrong = request("1:5", b"B");
        wrong.run_id = "f".repeat(64);
        let mut service = server(&dir, "three.jsonl");
        assert_eq!(service.commit_request(wrong), Err(CustodyError::Refused));
        assert!(service.is_poisoned());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn orphan_unsealed_and_blank_line_refuse() {
        let writes = [("1:4", 0, b"A".as_slice())];
        let (dir, frontier, identity) = broker_history(&writes);
        let raw = replay(&dir, "custody.jsonl", &writes);
        let lines: Vec<_> = raw.split_inclusive(|b| *b == b'\n').collect();
        assert_eq!(lines.len(), 3);
        assert!(audit_custody_against_frontier(lines[0], &frontier, &identity).is_err());
        assert!(
            audit_custody_against_frontier(
                &raw[..lines[0].len() + lines[1].len()],
                &frontier,
                &identity
            )
            .is_err()
        );
        let mut blank = Vec::new();
        blank.extend_from_slice(lines[0]);
        blank.push(b'\n');
        blank.extend_from_slice(lines[1]);
        blank.extend_from_slice(lines[2]);
        assert_eq!(
            audit_custody_against_frontier(&blank, &frontier, &identity),
            Err(CustodyError::Journal)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn forged_response_and_eof_before_seal_refuse() {
        let (client_stream, mut fake_server_stream) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            let _: CustodyWriteRequest = read_frame(&mut fake_server_stream).unwrap().unwrap();
            write_frame(
                &mut fake_server_stream,
                &CustodyWriteResponse {
                    run_id: "f".repeat(64),
                    operation_id: "1:4".into(),
                    completed: 1,
                    after_digest: "a".repeat(64),
                    result_sequence: 1,
                    result_hash: "b".repeat(64),
                },
            )
            .unwrap();
        });
        let mut client = CustodyClient::new(client_stream.try_clone().unwrap(), RUN.into());
        assert_eq!(client.commit("1:4", 0, b"A"), Err(CustodyError::Mismatch));
        assert_eq!(client.commit("1:5", 0, b"B"), Err(CustodyError::Ambiguous));
        drop(client);
        drop(client_stream);
        worker.join().unwrap();

        let (dir, _, _) = broker_history(&[("1:4", 0, b"A".as_slice())]);
        let mut service = server(&dir, "custody.jsonl");
        let (stream, mut server_stream) = UnixStream::pair().unwrap();
        drop(stream);
        assert_eq!(
            service.serve_one(&mut server_stream),
            Err(CustodyError::Ambiguous)
        );
        assert!(service.is_poisoned());
        fs::remove_dir_all(dir).unwrap();
    }
}
