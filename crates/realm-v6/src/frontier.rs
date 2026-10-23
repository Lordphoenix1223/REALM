//! Host-side broker prototype for the V6.2 single-input/single-output universe.
//!
//! This module establishes the ordering of brokered effects. It cannot establish
//! that an untrusted Linux task has no other path to the files. In particular,
//! its seal is not a process/FD quiescence proof or a FreezeToken.

use crate::custody::CustodyClient;
use crate::profile::SyncTrace as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

const MAX_OPERATION: usize = 1024 * 1024;
const MAX_RECORDS: u64 = 4096;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    IntentCreate,
    ResultCreate,
    IntentRead,
    ResultRead,
    IntentWrite,
    ResultWrite,
    ResultIdentify,
    ResultClose,
    /// Historical diagnostic control record with no Identify/Close distinction.
    /// Auditable for preservation, but never valid in a mediated journal.
    ResultControl,
    Seal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontierRecord {
    pub run_id: String,
    pub monitor_id: String,
    pub mediation_manifest_root: String,
    pub launch_identity: String,
    pub starting_generation: String,
    pub sequence: u64,
    pub operation_id: String,
    pub kind: RecordKind,
    #[serde(deserialize_with = "crate::strict_json::present_option")]
    pub object: Option<ObjectIdentity>,
    pub offset: u64,
    pub requested: u64,
    pub completed: u64,
    /// Exact returned bytes for a read; exact requested bytes for a write intent.
    pub bytes: Vec<u8>,
    #[serde(deserialize_with = "crate::strict_json::present_option")]
    pub object_version_before: Option<String>,
    #[serde(deserialize_with = "crate::strict_json::present_option")]
    pub object_version_after: Option<String>,
    #[serde(deserialize_with = "crate::strict_json::present_option")]
    pub freeze_epoch: Option<String>,
    pub previous_hash: String,
    pub hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadEvidence {
    pub sequence: u64,
    pub object: ObjectIdentity,
    pub offset: u64,
    pub returned_bytes: Vec<u8>,
    pub object_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrontierAudit {
    pub head: String,
    pub reads: Vec<ReadEvidence>,
    pub committed_write_count: u64,
    // Exact records from the same bounded read that was audited.
    pub(crate) records: Vec<FrontierRecord>,
}

impl FrontierAudit {
    pub fn records(&self) -> &[FrontierRecord] {
        &self.records
    }
}

/// A host-created copy bound to one broker seal. It is not a FreezeToken:
/// process/FD quiescence and immutable storage are not established here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCandidate {
    pub run_id: String,
    pub starting_generation: String,
    pub mediation_manifest_root: String,
    pub frontier_head: String,
    pub freeze_epoch: String,
    pub launch_root: String,
    pub policy_root: String,
    pub dependency_root: String,
    pub snapshot_dir: PathBuf,
    pub input_digest: String,
    pub output_digest: String,
    pub snapshot_root: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrontierFailure {
    InvalidInput,
    UnsupportedObject,
    OperationInFlight,
    JournalFailure,
    EffectAmbiguous,
    CorruptJournal,
    StaleRoot,
    NotSealed,
    AlreadySealed,
}

fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub(crate) fn absent_output_version() -> String {
    digest(b"realm.v6.c0.absent-output.v1")
}

fn output_effect_version(object: &ObjectIdentity, content_version: &str) -> String {
    digest(
        format!(
            "output-v1:{}:{}:{}",
            object.device, object.inode, content_version
        )
        .as_bytes(),
    )
}

fn identity(file: &File) -> Result<ObjectIdentity, FrontierFailure> {
    let meta = file
        .metadata()
        .map_err(|_| FrontierFailure::UnsupportedObject)?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(FrontierFailure::UnsupportedObject);
    }
    Ok(ObjectIdentity {
        device: meta.dev(),
        inode: meta.ino(),
    })
}

fn version(file: &File) -> Result<String, FrontierFailure> {
    let length = file
        .metadata()
        .map_err(|_| FrontierFailure::EffectAmbiguous)?
        .len();
    if length > MAX_OPERATION as u64 {
        return Err(FrontierFailure::UnsupportedObject);
    }
    let mut bytes = vec![0; length as usize];
    let mut pos = 0;
    while pos < bytes.len() {
        let read = file
            .read_at(&mut bytes[pos..], pos as u64)
            .map_err(|_| FrontierFailure::EffectAmbiguous)?;
        if read == 0 {
            return Err(FrontierFailure::EffectAmbiguous);
        }
        pos += read;
    }
    Ok(digest(&bytes))
}

fn record_hash(record: &FrontierRecord) -> Result<String, FrontierFailure> {
    let mut unsigned = record.clone();
    unsigned.hash.clear();
    let encoded = serde_json::to_vec(&unsigned).map_err(|_| FrontierFailure::JournalFailure)?;
    Ok(digest(&encoded))
}

/// Caller must own an isolated directory and keep task credentials away from it.
/// Each run creates a new journal; existing runs are never overwritten.
pub struct EffectFrontier {
    run_id: String,
    monitor_id: String,
    mediation_manifest_root: String,
    launch_identity: String,
    starting_generation: String,
    journal_path: PathBuf,
    journal: File,
    input: File,
    output: Option<File>,
    output_target: Option<PathBuf>,
    output_writer: OutputWriter,
    expected_input_version: String,
    expected_output_version: String,
    output_effect_version: String,
    positive_write_generation: u64,
    sequence: u64,
    head: String,
    poisoned: bool,
    sealed: bool,
    custody_terminal: bool,
    terminal_barrier_confirmed: bool,
    freeze_epoch: Option<String>,
    used_operations: BTreeSet<String>,
    runtime_completion: Option<crate::runtime_effects::BrokerCompletion>,
}

enum OutputWriter {
    Direct,
    Custodied(CustodyClient),
}

impl EffectFrontier {
    #[cfg(target_os = "linux")]
    pub(crate) fn attach_runtime_completion(
        &mut self,
        completion: crate::runtime_effects::BrokerCompletion,
    ) {
        self.runtime_completion = Some(completion);
    }
    /// The canonical ordered frontier for typed file/SQLite effects. The legacy
    /// range journal remains available for the preserved single-file profile.
    pub fn runtime_completion(&self) -> Option<&crate::runtime_effects::BrokerCompletion> {
        self.runtime_completion.as_ref()
    }

    pub fn create(
        host_owned_dir: &Path,
        run_id: &str,
        monitor_id: &str,
        input_path: &Path,
        output_path: &Path,
    ) -> Result<Self, FrontierFailure> {
        if !fs::symlink_metadata(output_path)
            .map_err(|_| FrontierFailure::UnsupportedObject)?
            .file_type()
            .is_file()
        {
            return Err(FrontierFailure::UnsupportedObject);
        }
        let output = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(output_path)
            .map_err(|_| FrontierFailure::UnsupportedObject)?;
        Self::create_with_output(
            host_owned_dir,
            run_id,
            monitor_id,
            input_path,
            Some(output),
            OutputWriter::Direct,
            None,
        )
    }

    /// The broker receives only a read-only handle to a separately owned
    /// output. The host launcher must enforce UID, directory, and inherited-FD
    /// separation; this local constructor alone is not a mediation claim.
    pub fn create_custodied(
        host_owned_dir: &Path,
        run_id: &str,
        monitor_id: &str,
        input_path: &Path,
        output: File,
        custodian: CustodyClient,
    ) -> Result<Self, FrontierFailure> {
        // SAFETY: F_GETFL only inspects this live file descriptor.
        let flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDONLY {
            return Err(FrontierFailure::UnsupportedObject);
        }
        Self::create_with_output(
            host_owned_dir,
            run_id,
            monitor_id,
            input_path,
            Some(output),
            OutputWriter::Custodied(custodian),
            None,
        )
    }

    /// Construct a C0 frontier whose declared output does not exist in the
    /// candidate world yet. The broker creates that exact path only after a
    /// guest `CreateOutput` request. The target must be a direct child of a
    /// host-owned candidate directory and must remain absent until then.
    pub fn create_with_absent_output(
        host_owned_dir: &Path,
        run_id: &str,
        monitor_id: &str,
        input_path: &Path,
        output_target: &Path,
    ) -> Result<Self, FrontierFailure> {
        let parent = output_target
            .parent()
            .ok_or(FrontierFailure::InvalidInput)?
            .canonicalize()
            .map_err(|_| FrontierFailure::UnsupportedObject)?;
        let name = output_target
            .file_name()
            .filter(|name| !name.is_empty() && *name != "." && *name != "..")
            .ok_or(FrontierFailure::InvalidInput)?;
        let target = parent.join(name);
        match fs::symlink_metadata(&target) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(FrontierFailure::UnsupportedObject),
        }
        let mut frontier = Self::create_with_output(
            host_owned_dir,
            run_id,
            monitor_id,
            input_path,
            None,
            OutputWriter::Direct,
            Some(target),
        )?;
        frontier.expected_output_version = absent_output_version();
        frontier.output_effect_version = frontier.expected_output_version.clone();
        Ok(frontier)
    }

    fn create_with_output(
        host_owned_dir: &Path,
        run_id: &str,
        monitor_id: &str,
        input_path: &Path,
        output: Option<File>,
        output_writer: OutputWriter,
        output_target: Option<PathBuf>,
    ) -> Result<Self, FrontierFailure> {
        if run_id.is_empty() || monitor_id.is_empty() || run_id.contains('/') {
            return Err(FrontierFailure::InvalidInput);
        }
        let dir = File::open(host_owned_dir).map_err(|_| FrontierFailure::JournalFailure)?;
        if !fs::symlink_metadata(input_path)
            .map_err(|_| FrontierFailure::UnsupportedObject)?
            .file_type()
            .is_file()
        {
            return Err(FrontierFailure::UnsupportedObject);
        }
        let journal_path = host_owned_dir.join(format!("{run_id}.frontier.jsonl"));
        let journal = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&journal_path)
            .map_err(|_| FrontierFailure::JournalFailure)?;
        dir.sync_all_traced()
            .map_err(|_| FrontierFailure::JournalFailure)?;
        let input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(input_path)
            .map_err(|_| FrontierFailure::UnsupportedObject)?;
        let expected_input_version = version(&input)?;
        let (expected_output_version, output_effect_version) = if let Some(output) = &output {
            if identity(&input)? == identity(output)? {
                return Err(FrontierFailure::UnsupportedObject);
            }
            let output_version = version(output)?;
            let output_identity = identity(output)?;
            let effect_version = output_effect_version(&output_identity, &output_version);
            (output_version, effect_version)
        } else {
            if output_target.is_none() || !matches!(output_writer, OutputWriter::Direct) {
                return Err(FrontierFailure::InvalidInput);
            }
            (absent_output_version(), absent_output_version())
        };
        Ok(Self {
            run_id: run_id.into(),
            monitor_id: monitor_id.into(),
            mediation_manifest_root: String::new(),
            launch_identity: String::new(),
            starting_generation: String::new(),
            journal_path,
            journal,
            input,
            output,
            output_target,
            output_writer,
            expected_input_version,
            expected_output_version,
            output_effect_version,
            positive_write_generation: 0,
            sequence: 0,
            head: "0".repeat(64),
            poisoned: false,
            sealed: false,
            custody_terminal: false,
            terminal_barrier_confirmed: false,
            freeze_epoch: None,
            used_operations: BTreeSet::new(),
            runtime_completion: None,
        })
    }

    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    /// Non-authorizing prototype binding. A production caller must first
    /// verify the manifest against a protected host measurement anchor.
    pub fn bind_topology(
        &mut self,
        mediation_manifest_root: &str,
        launch_identity: &str,
        starting_generation: &str,
    ) -> Result<(), FrontierFailure> {
        if self.sequence != 0
            || self.sealed
            || self.poisoned
            || [
                mediation_manifest_root,
                launch_identity,
                starting_generation,
            ]
            .iter()
            .any(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(FrontierFailure::InvalidInput);
        }
        self.mediation_manifest_root = mediation_manifest_root.into();
        self.launch_identity = launch_identity.into();
        self.starting_generation = starting_generation.into();
        Ok(())
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    pub fn monitor_id(&self) -> &str {
        &self.monitor_id
    }
    pub fn current_version(&self, output: bool) -> &str {
        if output {
            &self.output_effect_version
        } else {
            &self.expected_input_version
        }
    }
    pub fn current_content_digest(&self, output: bool) -> &str {
        if output {
            &self.expected_output_version
        } else {
            &self.expected_input_version
        }
    }
    pub fn evidence_sequence(&self) -> u64 {
        self.sequence
    }
    pub fn head(&self) -> &str {
        &self.head
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn is_sealed(&self) -> bool {
        self.sealed && !self.poisoned
    }
    pub fn is_custodied(&self) -> bool {
        matches!(&self.output_writer, OutputWriter::Custodied(_))
    }

    /// Create the configured absent output after a durable intent record. The
    /// file and containing directory are synced before the matching result is
    /// journaled, so a crash leaves either an in-flight create (REFUSE) or a
    /// complete result record.
    pub fn create_output(&mut self, op: &str) -> Result<String, FrontierFailure> {
        self.usable()?;
        if self.custody_terminal || self.output.is_some() || self.output_target.is_none() {
            return Err(FrontierFailure::UnsupportedObject);
        }
        if op.is_empty() || self.used_operations.contains(op) {
            self.poisoned = true;
            return Err(FrontierFailure::EffectAmbiguous);
        }
        self.check_versions()?;
        let mut intent = self.make_record(op, RecordKind::IntentCreate);
        intent.object_version_before = Some(self.expected_output_version.clone());
        self.append(intent)?;
        self.used_operations.insert(op.to_owned());

        let target = self
            .output_target
            .as_ref()
            .ok_or(FrontierFailure::InvalidInput)?;
        let output = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(target)
            .map_err(|_| {
                self.poisoned = true;
                FrontierFailure::EffectAmbiguous
            })?;
        output.sync_all().map_err(|_| {
            self.poisoned = true;
            FrontierFailure::EffectAmbiguous
        })?;
        File::open(target.parent().ok_or(FrontierFailure::InvalidInput)?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| {
                self.poisoned = true;
                FrontierFailure::JournalFailure
            })?;

        let object = identity(&output)?;
        let content_version = version(&output)?;
        let effect_version = output_effect_version(&object, &content_version);
        let mut result = self.make_record(op, RecordKind::ResultCreate);
        result.object = Some(object);
        result.object_version_before = Some(self.expected_output_version.clone());
        result.object_version_after = Some(effect_version.clone());
        self.append(result)?;
        self.expected_output_version = content_version;
        self.output_effect_version = effect_version.clone();
        self.output = Some(output);
        Ok(effect_version)
    }
    /// Records the custodian's own terminal head after a separately observed
    /// host barrier. This does not seal the broker journal or prove closure.
    pub fn seal_custodian_after_barrier(
        &mut self,
        barrier_id: &str,
    ) -> Result<String, FrontierFailure> {
        self.usable()?;
        if self.custody_terminal {
            return Err(FrontierFailure::AlreadySealed);
        }
        self.check_versions()?;
        let OutputWriter::Custodied(client) = &mut self.output_writer else {
            return Err(FrontierFailure::UnsupportedObject);
        };
        match client.seal_after_barrier(barrier_id) {
            Ok(head) => {
                self.custody_terminal = true;
                Ok(head)
            }
            Err(_) => {
                self.poisoned = true;
                Err(FrontierFailure::EffectAmbiguous)
            }
        }
    }
    pub fn terminal_barrier_confirmed(&self) -> bool {
        self.terminal_barrier_confirmed
    }
    pub(crate) fn confirm_terminal_barrier(&mut self) -> Result<(), FrontierFailure> {
        if self.sealed || self.poisoned || self.mediation_manifest_root.is_empty() {
            return Err(FrontierFailure::EffectAmbiguous);
        }
        self.terminal_barrier_confirmed = true;
        Ok(())
    }
    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Durable acknowledgment that the broker identified one logical object.
    pub fn record_identify(&mut self, op: &str, output: bool) -> Result<(), FrontierFailure> {
        self.record_control(op, output, RecordKind::ResultIdentify)
    }

    /// Durable acknowledgment that the broker closed task effect authority.
    pub fn record_close(&mut self, op: &str, output: bool) -> Result<(), FrontierFailure> {
        self.record_control(op, output, RecordKind::ResultClose)
    }

    fn record_control(
        &mut self,
        op: &str,
        output: bool,
        kind: RecordKind,
    ) -> Result<(), FrontierFailure> {
        self.usable()?;
        if self.custody_terminal {
            return Err(FrontierFailure::AlreadySealed);
        }
        if op.is_empty() || self.used_operations.contains(op) {
            self.poisoned = true;
            return Err(FrontierFailure::EffectAmbiguous);
        }
        self.check_versions()?;
        let mut r = self.make_record(op, kind);
        let file = if output {
            self.output
                .as_ref()
                .ok_or(FrontierFailure::UnsupportedObject)?
        } else {
            &self.input
        };
        r.object = Some(identity(file)?);
        r.object_version_before = Some(self.current_version(output).into());
        r.object_version_after = r.object_version_before.clone();
        self.append(r)?;
        self.used_operations.insert(op.into());
        Ok(())
    }

    fn append(&mut self, mut r: FrontierRecord) -> Result<(), FrontierFailure> {
        if self.sequence >= MAX_RECORDS {
            self.poisoned = true;
            return Err(FrontierFailure::JournalFailure);
        }
        r.sequence = self.sequence;
        r.previous_hash = self.head.clone();
        r.hash = match record_hash(&r) {
            Ok(hash) => hash,
            Err(e) => {
                self.poisoned = true;
                return Err(e);
            }
        };
        let mut encoded = match serde_json::to_vec(&r) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.poisoned = true;
                return Err(FrontierFailure::JournalFailure);
            }
        };
        encoded.push(b'\n');
        let current_len = match self.journal.metadata() {
            Ok(metadata) => metadata.len(),
            Err(_) => {
                self.poisoned = true;
                return Err(FrontierFailure::JournalFailure);
            }
        };
        if current_len.saturating_add(encoded.len() as u64) > MAX_JOURNAL_BYTES {
            self.poisoned = true;
            return Err(FrontierFailure::JournalFailure);
        }
        if self.journal.write_all(&encoded).is_err() || self.journal.sync_all_traced().is_err() {
            self.poisoned = true;
            return Err(FrontierFailure::JournalFailure);
        }
        self.sequence += 1;
        self.head = r.hash;
        Ok(())
    }

    fn make_record(&self, op: &str, kind: RecordKind) -> FrontierRecord {
        FrontierRecord {
            run_id: self.run_id.clone(),
            monitor_id: self.monitor_id.clone(),
            mediation_manifest_root: self.mediation_manifest_root.clone(),
            launch_identity: self.launch_identity.clone(),
            starting_generation: self.starting_generation.clone(),
            sequence: 0,
            operation_id: op.into(),
            kind,
            object: None,
            offset: 0,
            requested: 0,
            completed: 0,
            bytes: vec![],
            object_version_before: None,
            object_version_after: None,
            freeze_epoch: None,
            previous_hash: String::new(),
            hash: String::new(),
        }
    }

    fn usable(&self) -> Result<(), FrontierFailure> {
        if self.poisoned {
            Err(FrontierFailure::EffectAmbiguous)
        } else if self.sealed {
            Err(FrontierFailure::AlreadySealed)
        } else {
            Ok(())
        }
    }

    fn check_versions(&mut self) -> Result<(), FrontierFailure> {
        let input = version(&self.input);
        let output = match (&self.output, &self.output_target) {
            (Some(file), _) => version(file),
            (None, Some(target)) => match fs::symlink_metadata(target) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok(absent_output_version())
                }
                _ => Err(FrontierFailure::EffectAmbiguous),
            },
            (None, None) => Err(FrontierFailure::UnsupportedObject),
        };
        if input.as_ref() != Ok(&self.expected_input_version)
            || output.as_ref() != Ok(&self.expected_output_version)
        {
            self.poisoned = true;
            return Err(FrontierFailure::EffectAmbiguous);
        }
        Ok(())
    }

    /// Read bytes are journaled and synced before they are returned.
    pub fn read(
        &mut self,
        op: &str,
        output: bool,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, FrontierFailure> {
        self.usable()?;
        if self.custody_terminal {
            return Err(FrontierFailure::AlreadySealed);
        }
        if self.used_operations.contains(op) {
            self.poisoned = true;
            return Err(FrontierFailure::EffectAmbiguous);
        }
        if op.is_empty() || len > MAX_OPERATION {
            return Err(FrontierFailure::InvalidInput);
        }
        self.check_versions()?;
        let file = if output {
            self.output
                .as_ref()
                .ok_or(FrontierFailure::UnsupportedObject)?
        } else {
            &self.input
        };
        let object = identity(file)?;
        let before = version(file)?;
        let expected = if output {
            &self.expected_output_version
        } else {
            &self.expected_input_version
        };
        if &before != expected {
            self.poisoned = true;
            return Err(FrontierFailure::EffectAmbiguous);
        }
        let mut intent = self.make_record(op, RecordKind::IntentRead);
        let logical_version = self.current_version(output).to_owned();
        intent.object = Some(object.clone());
        intent.offset = offset;
        intent.requested = len as u64;
        intent.object_version_before = Some(logical_version.clone());
        self.append(intent)?;
        self.used_operations.insert(op.into());
        let mut bytes = vec![0; len];
        let n = match if output {
            self.output
                .as_ref()
                .ok_or(FrontierFailure::UnsupportedObject)?
                .read_at(&mut bytes, offset)
        } else {
            self.input.read_at(&mut bytes, offset)
        } {
            Ok(n) => n,
            Err(_) => {
                self.poisoned = true;
                return Err(FrontierFailure::EffectAmbiguous);
            }
        };
        bytes.truncate(n);
        let after = match if output {
            version(
                self.output
                    .as_ref()
                    .ok_or(FrontierFailure::UnsupportedObject)?,
            )
        } else {
            version(&self.input)
        } {
            Ok(v) => v,
            Err(e) => {
                self.poisoned = true;
                return Err(e);
            }
        };
        if after != before {
            self.poisoned = true;
            return Err(FrontierFailure::EffectAmbiguous);
        }
        let mut result = self.make_record(op, RecordKind::ResultRead);
        result.object = Some(object);
        result.offset = offset;
        result.requested = len as u64;
        result.completed = n as u64;
        result.bytes = bytes.clone();
        result.object_version_before = Some(logical_version.clone());
        result.object_version_after = Some(logical_version);
        self.append(result)?;
        Ok(bytes)
    }

    /// A short write is a committed partial write, not a full write.
    /// Any error after intent is ambiguous and permanently poisons this run.
    pub fn write(&mut self, op: &str, offset: u64, bytes: &[u8]) -> Result<usize, FrontierFailure> {
        self.usable()?;
        if self.custody_terminal {
            return Err(FrontierFailure::AlreadySealed);
        }
        if self.used_operations.contains(op) {
            self.poisoned = true;
            return Err(FrontierFailure::EffectAmbiguous);
        }
        if op.is_empty() || bytes.len() > MAX_OPERATION {
            return Err(FrontierFailure::InvalidInput);
        }
        self.check_versions()?;
        let output = self
            .output
            .as_ref()
            .ok_or(FrontierFailure::UnsupportedObject)?;
        let object = identity(output)?;
        let before = version(output)?;
        if before != self.expected_output_version {
            self.poisoned = true;
            return Err(FrontierFailure::EffectAmbiguous);
        }
        let mut intent = self.make_record(op, RecordKind::IntentWrite);
        let old_effect_version = self.output_effect_version.clone();
        intent.object = Some(object.clone());
        intent.offset = offset;
        intent.requested = bytes.len() as u64;
        intent.bytes = bytes.to_vec();
        intent.object_version_before = Some(old_effect_version.clone());
        self.append(intent)?;
        self.used_operations.insert(op.into());
        let (n, custody_digest) = match &mut self.output_writer {
            OutputWriter::Direct => match self.output.as_ref().unwrap().write_at(bytes, offset) {
                Ok(n) if self.output.as_ref().unwrap().sync_all_traced().is_ok() => (n, None),
                _ => {
                    self.poisoned = true;
                    return Err(FrontierFailure::EffectAmbiguous);
                }
            },
            OutputWriter::Custodied(client) => match client.commit(op, offset, bytes) {
                Ok(result) if result.completed <= bytes.len() => {
                    (result.completed, Some(result.after_digest))
                }
                _ => {
                    self.poisoned = true;
                    return Err(FrontierFailure::EffectAmbiguous);
                }
            },
        };
        let after = match version(self.output.as_ref().unwrap()) {
            Ok(v) => v,
            Err(e) => {
                self.poisoned = true;
                return Err(e);
            }
        };
        if custody_digest
            .as_ref()
            .is_some_and(|digest| digest != &after)
        {
            self.poisoned = true;
            return Err(FrontierFailure::EffectAmbiguous);
        }
        let next_generation = self.positive_write_generation + u64::from(n > 0);
        let new_effect_version = if n > 0 {
            digest(
                format!(
                    "output-write-v1:{}:{}:{}:{}",
                    old_effect_version, next_generation, op, after
                )
                .as_bytes(),
            )
        } else {
            old_effect_version.clone()
        };
        let mut result = self.make_record(op, RecordKind::ResultWrite);
        result.object = Some(object);
        result.offset = offset;
        result.requested = bytes.len() as u64;
        result.completed = n as u64;
        result.bytes = bytes[..n].to_vec();
        result.object_version_before = Some(old_effect_version);
        result.object_version_after = Some(new_effect_version.clone());
        self.append(result)?;
        self.expected_output_version = after;
        self.output_effect_version = new_effect_version;
        self.positive_write_generation = next_generation;
        Ok(n)
    }

    /// Seals broker operations only. A separate host process barrier and immutable
    /// snapshot must be established before a FreezeToken can be issued.
    pub fn seal(&mut self, freeze_epoch: &str) -> Result<String, FrontierFailure> {
        self.usable()?;
        if self.is_custodied() && !self.custody_terminal {
            return Err(FrontierFailure::NotSealed);
        }
        if freeze_epoch.is_empty() {
            return Err(FrontierFailure::InvalidInput);
        }
        self.check_versions()?;
        let mut record = self.make_record("terminal", RecordKind::Seal);
        record.freeze_epoch = Some(freeze_epoch.into());
        self.append(record)?;
        self.sealed = true;
        self.freeze_epoch = Some(freeze_epoch.into());
        Ok(self.head.clone())
    }

    /// Stages a byte-for-byte private copy after broker seal. The caller must
    /// supply a host-owned directory inaccessible to task credentials. This
    /// remains non-authorizing until a separate process barrier and immutable
    /// snapshot primitive bind the exact same object.
    pub fn stage_snapshot_candidate(
        &mut self,
        parent: &Path,
        starting_generation: &str,
        launch_root: &str,
        policy_root: &str,
        dependency_root: &str,
    ) -> Result<SnapshotCandidate, FrontierFailure> {
        if !self.sealed || self.poisoned {
            return Err(FrontierFailure::NotSealed);
        }
        if self.mediation_manifest_root.is_empty()
            || self.launch_identity != launch_root
            || self.starting_generation != starting_generation
        {
            return Err(FrontierFailure::StaleRoot);
        }
        if [
            starting_generation,
            launch_root,
            policy_root,
            dependency_root,
        ]
        .iter()
        .any(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(FrontierFailure::InvalidInput);
        }
        self.check_versions()?;
        let parent_fd = File::open(parent).map_err(|_| FrontierFailure::JournalFailure)?;
        let snapshot_dir = parent.join(format!("{}.snapshot", self.run_id));
        fs::create_dir(&snapshot_dir).map_err(|_| FrontierFailure::JournalFailure)?;
        parent_fd
            .sync_all_traced()
            .map_err(|_| FrontierFailure::JournalFailure)?;
        let input_digest = copy_snapshot_file(&self.input, &snapshot_dir.join("input"))?;
        let output_digest = copy_snapshot_file(
            self.output
                .as_ref()
                .ok_or(FrontierFailure::UnsupportedObject)?,
            &snapshot_dir.join("output"),
        )?;
        self.check_versions()?;
        if input_digest != self.expected_input_version
            || output_digest != self.expected_output_version
        {
            self.poisoned = true;
            return Err(FrontierFailure::EffectAmbiguous);
        }
        File::open(&snapshot_dir)
            .and_then(|dir| dir.sync_all_traced())
            .map_err(|_| FrontierFailure::JournalFailure)?;
        let mut candidate = SnapshotCandidate {
            run_id: self.run_id.clone(),
            starting_generation: starting_generation.into(),
            mediation_manifest_root: self.mediation_manifest_root.clone(),
            frontier_head: self.head.clone(),
            freeze_epoch: self
                .freeze_epoch
                .clone()
                .ok_or(FrontierFailure::NotSealed)?,
            launch_root: launch_root.into(),
            policy_root: policy_root.into(),
            dependency_root: dependency_root.into(),
            snapshot_dir,
            input_digest,
            output_digest,
            snapshot_root: String::new(),
        };
        candidate.snapshot_root =
            digest(&serde_json::to_vec(&candidate).map_err(|_| FrontierFailure::JournalFailure)?);
        Ok(candidate)
    }
}

fn copy_snapshot_file(source: &File, path: &Path) -> Result<String, FrontierFailure> {
    let length = source
        .metadata()
        .map_err(|_| FrontierFailure::EffectAmbiguous)?
        .len();
    if length > MAX_OPERATION as u64 {
        return Err(FrontierFailure::UnsupportedObject);
    }
    let mut bytes = vec![0; length as usize];
    let mut position = 0;
    while position < bytes.len() {
        let n = source
            .read_at(&mut bytes[position..], position as u64)
            .map_err(|_| FrontierFailure::EffectAmbiguous)?;
        if n == 0 {
            return Err(FrontierFailure::EffectAmbiguous);
        }
        position += n;
    }
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| FrontierFailure::JournalFailure)?;
    target
        .write_all(&bytes)
        .map_err(|_| FrontierFailure::JournalFailure)?;
    target
        .sync_all_traced()
        .map_err(|_| FrontierFailure::JournalFailure)?;
    Ok(digest(&bytes))
}

/// Diagnostic consistency check for staged bytes. It does not make the path
/// immutable and therefore cannot close scan-then-mutate-then-publish TOCTOU.
pub fn inspect_snapshot_candidate(candidate: &SnapshotCandidate) -> Result<(), FrontierFailure> {
    let mut unsigned = candidate.clone();
    unsigned.snapshot_root.clear();
    if digest(&serde_json::to_vec(&unsigned).map_err(|_| FrontierFailure::CorruptJournal)?)
        != candidate.snapshot_root
    {
        return Err(FrontierFailure::CorruptJournal);
    }
    let world =
        crate::scan_world(&candidate.snapshot_dir).map_err(|_| FrontierFailure::EffectAmbiguous)?;
    if world.len() != 2
        || world.get("input").and_then(|e| e.content_blake3.as_ref())
            != Some(&candidate.input_digest)
        || world.get("output").and_then(|e| e.content_blake3.as_ref())
            != Some(&candidate.output_digest)
    {
        return Err(FrontierFailure::EffectAmbiguous);
    }
    Ok(())
}

/// A strict local audit. A lost, truncated, reordered or in-flight operation
/// refuses; a valid hash chain alone does not prove mandatory mediation.
pub fn audit_journal(
    path: &Path,
    run_id: &str,
    monitor_id: &str,
) -> Result<FrontierAudit, FrontierFailure> {
    let file = File::open(path).map_err(|_| FrontierFailure::CorruptJournal)?;
    if file
        .metadata()
        .map_err(|_| FrontierFailure::CorruptJournal)?
        .len()
        > MAX_JOURNAL_BYTES
    {
        return Err(FrontierFailure::CorruptJournal);
    }
    let mut raw = Vec::new();
    file.take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|_| FrontierFailure::CorruptJournal)?;
    audit_bytes(&raw, run_id, monitor_id)
}

/// Audit a single immutable byte buffer, so parsing, roots and consumers cannot
/// observe different path generations. A hash chain alone is not authentication.
pub fn audit_bytes(
    raw: &[u8],
    run_id: &str,
    monitor_id: &str,
) -> Result<FrontierAudit, FrontierFailure> {
    if raw.len() > MAX_JOURNAL_BYTES as usize || !raw.ends_with(b"\n") {
        return Err(FrontierFailure::CorruptJournal);
    }
    let text = std::str::from_utf8(raw).map_err(|_| FrontierFailure::CorruptJournal)?;
    let mut records = Vec::new();
    let mut head = "0".repeat(64);
    let mut pending: Option<FrontierRecord> = None;
    let mut used = BTreeSet::new();
    let mut sealed = false;
    let mut count = 0u64;
    let mut reads = Vec::new();
    let mut committed_write_count = 0;
    let mut binding: Option<(String, String, String)> = None;
    let mut object_versions: BTreeMap<ObjectIdentity, String> = BTreeMap::new();
    for line in text.lines() {
        let value = crate::strict_json::parse(line.as_bytes())
            .map_err(|_| FrontierFailure::CorruptJournal)?;
        let r: FrontierRecord =
            serde_json::from_value(value).map_err(|_| FrontierFailure::CorruptJournal)?;
        if r.offset.checked_add(r.requested).is_none()
            || (r.kind != RecordKind::Seal && r.freeze_epoch.is_some())
            || (matches!(
                r.kind,
                RecordKind::IntentCreate | RecordKind::IntentRead | RecordKind::IntentWrite
            ) && r.object_version_after.is_some())
            || (matches!(
                r.kind,
                RecordKind::ResultIdentify
                    | RecordKind::ResultClose
                    | RecordKind::ResultControl
                    | RecordKind::IntentCreate
                    | RecordKind::ResultCreate
            ) && r.offset != 0)
            || (r.kind == RecordKind::Seal
                && (r.operation_id != "terminal"
                    || r.object.is_some()
                    || r.offset != 0
                    || r.requested != 0
                    || r.completed != 0
                    || !r.bytes.is_empty()
                    || r.object_version_before.is_some()
                    || r.object_version_after.is_some()))
        {
            return Err(FrontierFailure::CorruptJournal);
        }
        if sealed
            || r.run_id != run_id
            || r.monitor_id != monitor_id
            || r.sequence != count
            || r.previous_hash != head
            || record_hash(&r).map_err(|_| FrontierFailure::CorruptJournal)? != r.hash
        {
            return Err(FrontierFailure::CorruptJournal);
        }
        let current_binding = (
            r.mediation_manifest_root.clone(),
            r.launch_identity.clone(),
            r.starting_generation.clone(),
        );
        if binding.as_ref().is_some_and(|b| b != &current_binding) {
            return Err(FrontierFailure::CorruptJournal);
        }
        binding = Some(current_binding);
        match r.kind {
            RecordKind::IntentCreate
                if pending.is_none()
                    && !r.operation_id.is_empty()
                    && used.insert(r.operation_id.clone())
                    && r.object.is_none()
                    && r.object_version_before.as_deref()
                        == Some(absent_output_version().as_str())
                    && r.object_version_after.is_none()
                    && r.completed == 0
                    && r.requested == 0
                    && r.bytes.is_empty() =>
            {
                pending = Some(r.clone());
            }
            RecordKind::ResultCreate
                if pending.as_ref().is_some_and(|p| {
                    p.operation_id == r.operation_id && p.kind == RecordKind::IntentCreate
                }) =>
            {
                let p = pending.as_ref().ok_or(FrontierFailure::CorruptJournal)?;
                let object = r.object.clone().ok_or(FrontierFailure::CorruptJournal)?;
                let expected_effect = output_effect_version(&object, &digest(&[]));
                if r.offset != 0
                    || r.requested != 0
                    || r.completed != 0
                    || !r.bytes.is_empty()
                    || r.object_version_before != p.object_version_before
                    || r.object_version_after.as_deref() != Some(expected_effect.as_str())
                    || object_versions.contains_key(&object)
                {
                    return Err(FrontierFailure::CorruptJournal);
                }
                object_versions.insert(object, expected_effect);
                pending = None;
            }
            RecordKind::ResultIdentify | RecordKind::ResultClose | RecordKind::ResultControl
                if pending.is_none()
                    && !r.operation_id.is_empty()
                    && used.insert(r.operation_id.clone())
                    && r.object.is_some()
                    && r.object_version_before == r.object_version_after
                    && r.object_version_before.is_some()
                    && r.completed == 0
                    && r.requested == 0
                    && r.bytes.is_empty() =>
            {
                let object = r.object.clone().ok_or(FrontierFailure::CorruptJournal)?;
                let version = r
                    .object_version_before
                    .clone()
                    .ok_or(FrontierFailure::CorruptJournal)?;
                if object_versions
                    .get(&object)
                    .is_some_and(|known| known != &version)
                {
                    return Err(FrontierFailure::CorruptJournal);
                }
                object_versions.insert(object, version);
            }
            RecordKind::IntentRead | RecordKind::IntentWrite
                if pending.is_none() && used.insert(r.operation_id.clone()) =>
            {
                if r.operation_id.is_empty()
                    || r.object.is_none()
                    || r.object_version_before.is_none()
                    || r.requested > MAX_OPERATION as u64
                    || r.completed != 0
                    || (r.kind == RecordKind::IntentRead && !r.bytes.is_empty())
                    || (r.kind == RecordKind::IntentWrite && r.bytes.len() as u64 != r.requested)
                {
                    return Err(FrontierFailure::CorruptJournal);
                }
                let object = r.object.clone().ok_or(FrontierFailure::CorruptJournal)?;
                let version = r
                    .object_version_before
                    .clone()
                    .ok_or(FrontierFailure::CorruptJournal)?;
                if object_versions
                    .get(&object)
                    .is_some_and(|known| known != &version)
                {
                    return Err(FrontierFailure::CorruptJournal);
                }
                object_versions.insert(object, version);
                pending = Some(r.clone());
            }
            RecordKind::ResultRead
                if pending.as_ref().is_some_and(|p| {
                    p.operation_id == r.operation_id && p.kind == RecordKind::IntentRead
                }) =>
            {
                let p = pending.as_ref().unwrap();
                if r.object != p.object
                    || r.offset != p.offset
                    || r.requested != p.requested
                    || r.object_version_before != p.object_version_before
                    || r.object_version_after != p.object_version_before
                    || r.completed != r.bytes.len() as u64
                    || r.completed > r.requested
                {
                    return Err(FrontierFailure::CorruptJournal);
                }
                reads.push(ReadEvidence {
                    sequence: r.sequence,
                    object: r.object.clone().ok_or(FrontierFailure::CorruptJournal)?,
                    offset: r.offset,
                    returned_bytes: r.bytes.clone(),
                    object_version: r
                        .object_version_before
                        .clone()
                        .ok_or(FrontierFailure::CorruptJournal)?,
                });
                pending = None;
            }
            RecordKind::ResultWrite
                if pending.as_ref().is_some_and(|p| {
                    p.operation_id == r.operation_id && p.kind == RecordKind::IntentWrite
                }) =>
            {
                let p = pending.as_ref().unwrap();
                if r.object != p.object
                    || r.offset != p.offset
                    || r.requested != p.requested
                    || r.object_version_before != p.object_version_before
                    || r.object_version_after.is_none()
                    || r.completed != r.bytes.len() as u64
                    || r.completed > r.requested
                    || r.bytes != p.bytes[..r.completed as usize]
                    || (r.completed > 0 && r.object_version_after == r.object_version_before)
                    || (r.completed == 0 && r.object_version_after != r.object_version_before)
                {
                    return Err(FrontierFailure::CorruptJournal);
                }
                object_versions.insert(
                    r.object.clone().ok_or(FrontierFailure::CorruptJournal)?,
                    r.object_version_after
                        .clone()
                        .ok_or(FrontierFailure::CorruptJournal)?,
                );
                committed_write_count += 1;
                pending = None;
            }
            RecordKind::Seal
                if pending.is_none() && r.freeze_epoch.as_ref().is_some_and(|e| !e.is_empty()) =>
            {
                sealed = true
            }
            _ => return Err(FrontierFailure::OperationInFlight),
        }
        head = r.hash.clone();
        records.push(r);
        if object_versions.len() > 2 {
            return Err(FrontierFailure::CorruptJournal);
        }
        count += 1;
        if count > MAX_RECORDS {
            return Err(FrontierFailure::CorruptJournal);
        }
    }
    if pending.is_some() {
        return Err(FrontierFailure::OperationInFlight);
    }
    if !sealed {
        return Err(FrontierFailure::NotSealed);
    }
    Ok(FrontierAudit {
        head,
        reads,
        committed_write_count,
        records,
    })
}

/// The expected root must come from a protected host anchor. Passing a root
/// copied from the same task-controlled journal adds no authentication.
pub fn audit_journal_against(
    path: &Path,
    run_id: &str,
    monitor_id: &str,
    expected_head: &str,
) -> Result<FrontierAudit, FrontierFailure> {
    let audit = audit_journal(path, run_id, monitor_id)?;
    if audit.head != expected_head {
        return Err(FrontierFailure::StaleRoot);
    }
    Ok(audit)
}

/// Requires an independently protected expected topology root. The old audit
/// remains diagnostic and cannot authorize a V6 candidate.
pub fn audit_mediated_journal_against(
    path: &Path,
    run_id: &str,
    monitor_id: &str,
    expected_head: &str,
    manifest_root: &str,
    launch_identity: &str,
    starting_generation: &str,
) -> Result<FrontierAudit, FrontierFailure> {
    let audit = audit_journal_against(path, run_id, monitor_id, expected_head)?;
    let r = audit
        .records
        .first()
        .ok_or(FrontierFailure::CorruptJournal)?;
    if manifest_root.is_empty()
        || r.mediation_manifest_root != manifest_root
        || r.launch_identity != launch_identity
        || r.starting_generation != starting_generation
    {
        return Err(FrontierFailure::StaleRoot);
    }
    if audit
        .records
        .iter()
        .any(|record| record.kind == RecordKind::ResultControl)
        || audit
            .records
            .iter()
            .filter(|record| record.kind == RecordKind::ResultClose)
            .count()
            != 1
        || audit
            .records
            .iter()
            .rev()
            .nth(1)
            .is_none_or(|record| record.kind != RecordKind::ResultClose)
    {
        return Err(FrontierFailure::CorruptJournal);
    }
    Ok(audit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::{CustodyServer, audit_custody_against_frontier};
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn post_freeze_effect_cannot_enter_the_accepted_history() {
        let (dir, mut frontier) = setup();
        frontier
            .bind_topology(&"a".repeat(64), &"b".repeat(64), &"c".repeat(64))
            .unwrap();
        frontier.write("before-freeze", 0, b"ABC").unwrap();
        frontier.confirm_terminal_barrier().unwrap();
        let head = frontier.seal("frozen-test-epoch").unwrap();
        let before = fs::read(frontier.journal_path()).unwrap();
        let output = fs::read(dir.join("output")).unwrap();
        assert_eq!(
            frontier.write("post-freeze", 0, b"BAD"),
            Err(FrontierFailure::AlreadySealed)
        );
        assert_eq!(fs::read(frontier.journal_path()).unwrap(), before);
        assert_eq!(fs::read(dir.join("output")).unwrap(), output);
        let audited = audit_bytes(&before, "run-a", "host-broker-v1").unwrap();
        assert_eq!(audited.head, head);
        assert!(
            !audited
                .records()
                .iter()
                .any(|r| r.operation_id == "post-freeze")
        );
        fs::remove_dir_all(dir).unwrap();
    }

    fn setup() -> (PathBuf, EffectFrontier) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let serial = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "realm-v6-frontier-{}-{nonce}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("input"), b"abcdef").unwrap();
        fs::write(dir.join("output"), b"------").unwrap();
        let broker = EffectFrontier::create(
            &dir,
            "run-a",
            "host-broker-v1",
            &dir.join("input"),
            &dir.join("output"),
        )
        .unwrap();
        (dir, broker)
    }

    #[test]
    fn brokered_read_write_are_durable_before_success_and_auditable() {
        let (dir, mut broker) = setup();
        assert_eq!(broker.read("r1", false, 1, 3).unwrap(), b"bcd");
        assert_eq!(broker.write("w1", 2, b"XY").unwrap(), 2);
        assert_eq!(broker.read("r2", true, 1, 4).unwrap(), b"-XY-");
        let head = broker.seal("epoch-1").unwrap();
        let audit = audit_journal(broker.journal_path(), "run-a", "host-broker-v1").unwrap();
        assert_eq!(audit.head, head);
        assert_eq!(audit.committed_write_count, 1);
        assert_eq!(audit.reads.len(), 2);
        assert_eq!(audit.reads[0].returned_bytes, b"bcd");
        assert_eq!(audit.reads[0].offset, 1);
        assert_eq!(fs::read(dir.join("output")).unwrap(), b"--XY--");
        assert_eq!(
            broker.write("late", 0, b"!").unwrap_err(),
            FrontierFailure::AlreadySealed
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn absent_output_is_created_only_by_brokered_effect_and_audits_from_absence() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "realm-v6-frontier-create-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("input"), b"abc").unwrap();
        let output = dir.join("output");
        let run_id = format!("create-{}-{nonce}", std::process::id());
        let mut broker = EffectFrontier::create_with_absent_output(
            &dir,
            &run_id,
            "host-broker-v1",
            &dir.join("input"),
            &output,
        )
        .unwrap();
        assert!(!output.exists());
        let absent = broker.current_version(true).to_owned();
        let created = broker.create_output("create-output").unwrap();
        assert_ne!(absent, created);
        assert_eq!(fs::read(&output).unwrap(), b"");
        assert_eq!(broker.write("write-output", 0, b"ABC").unwrap(), 3);
        broker.record_close("close-output", true).unwrap();
        broker.seal("create-freeze").unwrap();

        let audit = audit_journal(
            &dir.join(format!("{run_id}.frontier.jsonl")),
            &run_id,
            "host-broker-v1",
        )
        .unwrap();
        assert!(matches!(audit.records[0].kind, RecordKind::IntentCreate));
        assert!(matches!(audit.records[1].kind, RecordKind::ResultCreate));
        assert_eq!(audit.committed_write_count, 1);
        assert_eq!(fs::read(&output).unwrap(), b"ABC");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn custodied_frontier_uses_read_only_output_and_agrees_on_write_history() {
        let (dir, old) = setup();
        drop(old);
        fs::remove_file(dir.join("run-a.frontier.jsonl")).unwrap();
        fs::write(dir.join("output"), b"").unwrap();
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let service_output = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join("output"))
            .unwrap();
        let service_journal = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(dir.join("custody.jsonl"))
            .unwrap();
        let mut service =
            CustodyServer::new(service_output, service_journal, "a".repeat(64)).unwrap();
        let worker = std::thread::spawn(
            move || {
                while service.serve_one(&mut server_stream).unwrap() {}
            },
        );
        let readonly_output = OpenOptions::new()
            .read(true)
            .open(dir.join("output"))
            .unwrap();
        let mut broker = EffectFrontier::create_custodied(
            &dir,
            &"a".repeat(64),
            "host-broker-v1",
            &dir.join("input"),
            readonly_output,
            CustodyClient::new(client_stream, "a".repeat(64)),
        )
        .unwrap();
        broker
            .bind_topology(&"b".repeat(64), &"c".repeat(64), &"d".repeat(64))
            .unwrap();
        assert!(broker.is_custodied());
        assert_eq!(broker.write("write-1", 0, b"ABC").unwrap(), 3);
        broker.record_close("close-1", true).unwrap();
        let custody_head = broker.seal_custodian_after_barrier("epoch-1").unwrap();
        assert_eq!(
            broker.write("late", 0, b"Z"),
            Err(FrontierFailure::AlreadySealed)
        );
        let frontier_head = broker.seal("epoch-1").unwrap();
        let journal = broker.journal_path().to_path_buf();
        drop(broker);
        worker.join().unwrap();
        let audit = audit_journal(&journal, &"a".repeat(64), "host-broker-v1").unwrap();
        assert_eq!(audit.head, frontier_head);
        let output = audit.records()[0].object.as_ref().unwrap();
        let custody = audit_custody_against_frontier(
            &fs::read(dir.join("custody.jsonl")).unwrap(),
            &audit,
            output,
        )
        .unwrap();
        assert_eq!(custody.head, custody_head);
        assert_eq!(custody.committed_write_count, 1);
        assert_eq!(fs::read(dir.join("output")).unwrap(), b"ABC");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ambiguous_intent_and_truncation_refuse() {
        let (dir, mut broker) = setup();
        broker.read("r1", false, 0, 1).unwrap();
        let path = broker.journal_path().to_path_buf();
        let lines = fs::read_to_string(&path).unwrap();
        let first = lines.lines().next().unwrap();
        fs::write(&path, format!("{first}\n")).unwrap();
        assert_eq!(
            audit_journal(&path, "run-a", "host-broker-v1"),
            Err(FrontierFailure::OperationInFlight)
        );
        fs::write(&path, format!("{first}\n{{bad\n")).unwrap();
        assert_eq!(
            audit_journal(&path, "run-a", "host-broker-v1"),
            Err(FrontierFailure::CorruptJournal)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wrong_run_replay_duplicate_operation_and_unsealed_refuse() {
        let (dir, mut broker) = setup();
        broker.read("r1", false, 0, 1).unwrap();
        assert_eq!(
            broker.read("r1", false, 0, 1).unwrap_err(),
            FrontierFailure::EffectAmbiguous
        );
        assert!(broker.is_poisoned());
        assert_eq!(
            audit_journal(broker.journal_path(), "run-b", "host-broker-v1"),
            Err(FrontierFailure::CorruptJournal)
        );
        assert_eq!(
            audit_journal(broker.journal_path(), "run-a", "host-broker-v1"),
            Err(FrontierFailure::NotSealed)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn mediated_audit_requires_one_terminal_close_record() {
        let manifest = "9".repeat(64);
        let launch = "b".repeat(64);
        let starting = "a".repeat(64);
        let (dir, mut broker) = setup();
        broker.bind_topology(&manifest, &launch, &starting).unwrap();
        broker.read("read", false, 0, 1).unwrap();
        let head = broker.seal("epoch").unwrap();
        assert_eq!(
            audit_mediated_journal_against(
                broker.journal_path(),
                "run-a",
                "host-broker-v1",
                &head,
                &manifest,
                &launch,
                &starting,
            ),
            Err(FrontierFailure::CorruptJournal)
        );
        fs::remove_dir_all(dir).unwrap();

        let (dir, mut broker) = setup();
        broker.bind_topology(&manifest, &launch, &starting).unwrap();
        broker.record_close("close", false).unwrap();
        broker.record_identify("late-identify", false).unwrap();
        let head = broker.seal("epoch").unwrap();
        assert_eq!(
            audit_mediated_journal_against(
                broker.journal_path(),
                "run-a",
                "host-broker-v1",
                &head,
                &manifest,
                &launch,
                &starting,
            ),
            Err(FrontierFailure::CorruptJournal)
        );
        fs::remove_dir_all(dir).unwrap();

        let (dir, mut broker) = setup();
        broker.bind_topology(&manifest, &launch, &starting).unwrap();
        broker.record_identify("identify", false).unwrap();
        broker.record_close("close", false).unwrap();
        broker.seal("epoch").unwrap();
        let path = broker.journal_path();
        let mut records: Vec<FrontierRecord> = fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        records[0].kind = RecordKind::ResultControl;
        let mut previous = "0".repeat(64);
        for record in &mut records {
            record.previous_hash = previous;
            record.hash = record_hash(record).unwrap();
            previous = record.hash.clone();
        }
        let legacy = records
            .iter()
            .map(|record| format!("{}\n", serde_json::to_string(record).unwrap()))
            .collect::<String>();
        fs::write(path, legacy).unwrap();
        assert!(audit_journal(path, "run-a", "host-broker-v1").is_ok());
        assert_eq!(
            audit_mediated_journal_against(
                path,
                "run-a",
                "host-broker-v1",
                &previous,
                &manifest,
                &launch,
                &starting,
            ),
            Err(FrontierFailure::CorruptJournal)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn equal_final_bytes_do_not_erase_write_history() {
        let (dir, mut broker) = setup();
        let original = fs::read(dir.join("output")).unwrap();
        let initial_effect_version = broker.current_version(true).to_owned();
        let initial_content = broker.current_content_digest(true).to_owned();
        broker.write("transient", 0, b"X").unwrap();
        broker.write("restore", 0, b"-").unwrap();
        assert_eq!(fs::read(dir.join("output")).unwrap(), original);
        assert_eq!(broker.current_content_digest(true), initial_content);
        assert_ne!(broker.current_version(true), initial_effect_version);
        broker.seal("epoch-1").unwrap();
        let journal = fs::read_to_string(broker.journal_path()).unwrap();
        assert!(journal.contains("transient"));
        assert!(journal.contains("restore"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn changed_read_version_is_visible_despite_equal_final_outputs() {
        let (dir_a, mut a) = setup();
        a.read("r", false, 0, 3).unwrap();
        a.write("w", 0, b"SAME").unwrap();
        a.seal("e1").unwrap();
        let audit_a = audit_journal(a.journal_path(), "run-a", "host-broker-v1").unwrap();

        let (dir_b, old) = setup();
        drop(old);
        fs::write(dir_b.join("input"), b"xyzdef").unwrap();
        let mut b = EffectFrontier::create(
            &dir_b,
            "run-b",
            "host-broker-v1",
            &dir_b.join("input"),
            &dir_b.join("output"),
        )
        .unwrap();
        b.read("r", false, 0, 3).unwrap();
        b.write("w", 0, b"SAME").unwrap();
        b.seal("e1").unwrap();
        let audit_b = audit_journal(b.journal_path(), "run-b", "host-broker-v1").unwrap();
        assert_eq!(
            fs::read(dir_a.join("output")).unwrap(),
            fs::read(dir_b.join("output")).unwrap()
        );
        assert_ne!(
            audit_a.reads[0].returned_bytes,
            audit_b.reads[0].returned_bytes
        );
        assert_ne!(
            audit_a.reads[0].object_version,
            audit_b.reads[0].object_version
        );
        fs::remove_dir_all(dir_a).unwrap();
        fs::remove_dir_all(dir_b).unwrap();
    }

    #[test]
    fn same_byte_write_advances_effect_version() {
        let (dir, mut broker) = setup();
        let old_content = broker.current_content_digest(true).to_owned();
        let old_effect = broker.current_version(true).to_owned();
        broker.write("same", 0, b"-").unwrap();
        assert_eq!(broker.current_content_digest(true), old_content);
        assert_ne!(broker.current_version(true), old_effect);
        let new_effect = broker.current_version(true).to_owned();
        assert_eq!(broker.read("observe-after-same", true, 0, 1).unwrap(), b"-");
        broker.seal("epoch-1").unwrap();
        let audit = audit_journal(broker.journal_path(), "run-a", "host-broker-v1").unwrap();
        assert_eq!(audit.reads[0].object_version, new_effect);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bypass_canary_shows_mandatory_mediation_is_still_unproven() {
        let (dir, mut broker) = setup();
        broker.read("r1", false, 0, 1).unwrap();
        let original = fs::read(dir.join("output")).unwrap();
        fs::write(dir.join("output"), b"BYPASS").unwrap();
        fs::write(dir.join("output"), &original).unwrap();
        assert_eq!(fs::read(dir.join("output")).unwrap(), original);
        let head = broker.seal("epoch-1").unwrap();
        assert_eq!(
            audit_journal(broker.journal_path(), "run-a", "host-broker-v1")
                .unwrap()
                .head,
            head
        );
        // The local broker cannot authorize admission: an unmediated transient
        // write leaves both the final bytes and journal apparently clean.
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn persistent_unmediated_mutation_poisoned_before_seal() {
        let (dir, mut broker) = setup();
        fs::write(dir.join("output"), b"BYPASS").unwrap();
        assert_eq!(
            broker.seal("epoch-1"),
            Err(FrontierFailure::EffectAmbiguous)
        );
        assert_eq!(
            broker.read("late", false, 0, 1),
            Err(FrontierFailure::EffectAmbiguous)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn staged_copy_binds_bytes_but_is_not_an_immutable_freeze_token() {
        let (dir, mut broker) = setup();
        broker
            .bind_topology(&"9".repeat(64), &"b".repeat(64), &"a".repeat(64))
            .unwrap();
        broker.read("r", false, 0, 1).unwrap();
        broker.seal("epoch-1").unwrap();
        let snapshots = dir.join("snapshots");
        fs::create_dir(&snapshots).unwrap();
        let candidate = broker
            .stage_snapshot_candidate(
                &snapshots,
                &"a".repeat(64),
                &"b".repeat(64),
                &"c".repeat(64),
                &"d".repeat(64),
            )
            .unwrap();
        inspect_snapshot_candidate(&candidate).unwrap();
        fs::write(dir.join("output"), b"AFTER!").unwrap();
        inspect_snapshot_candidate(&candidate).unwrap(); // source race leaves staged copy unchanged
        fs::write(candidate.snapshot_dir.join("output"), b"MUTATE").unwrap();
        assert_eq!(
            inspect_snapshot_candidate(&candidate),
            Err(FrontierFailure::EffectAmbiguous)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn symlink_input_and_hardlinked_output_are_rejected() {
        let (dir, broker) = setup();
        let link = dir.join("link");
        symlink(dir.join("input"), &link).unwrap();
        assert!(matches!(
            EffectFrontier::create(&dir, "run-b", "host-broker-v1", &link, &dir.join("output")),
            Err(FrontierFailure::UnsupportedObject)
        ));
        fs::hard_link(dir.join("output"), dir.join("other-link")).unwrap();
        assert!(matches!(
            EffectFrontier::create(
                &dir,
                "run-c",
                "host-broker-v1",
                &dir.join("input"),
                &dir.join("output")
            ),
            Err(FrontierFailure::UnsupportedObject)
        ));
        drop(broker);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reordered_records_and_stale_protected_root_refuse() {
        let (dir, mut broker) = setup();
        broker.read("r", false, 0, 1).unwrap();
        let head = broker.seal("e1").unwrap();
        let path = broker.journal_path().to_path_buf();
        assert_eq!(
            audit_journal_against(&path, "run-a", "host-broker-v1", &"0".repeat(64)),
            Err(FrontierFailure::StaleRoot)
        );
        assert_eq!(
            audit_journal_against(&path, "run-a", "host-broker-v1", &head)
                .unwrap()
                .head,
            head
        );
        let original = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<_> = original.lines().collect();
        lines.swap(0, 1);
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        assert_eq!(
            audit_journal(&path, "run-a", "host-broker-v1"),
            Err(FrontierFailure::CorruptJournal)
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
