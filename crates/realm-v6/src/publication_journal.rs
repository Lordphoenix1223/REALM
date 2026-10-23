//! Durable host-owned publication state.
//!
//! This journal records publication intent and outcome; it never grants
//! authority. An unfinished `publishing` record is ambiguous and must be
//! recovered explicitly rather than retried blindly.

use crate::profile::SyncTrace as _;
use crate::{generation::GenerationIdentity, publication::PublicationError};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicationState {
    Prepared,
    Publishing,
    Published,
    Failed,
    Conflict,
    Interrupted,
    GenerationPreparing,
    GenerationPrepared,
    CommitIntent,
    CommitInProgress,
    Committed,
    PublicationVerified,
    ReceiptPersisted,
    IntegrityFailure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationRecord {
    pub schema_version: u16,
    pub sequence: u64,
    pub publication_id: String,
    pub execution_id: String,
    pub run_id: String,
    pub decision_identity: String,
    pub destination_identity: String,
    pub accepted_final_root: String,
    pub accepted_delta_root: String,
    pub pre_publication_root: String,
    pub post_publication_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation_identity: Option<GenerationIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_digest: Option<String>,
    pub state: PublicationState,
    pub error: Option<String>,
}

/// Fields for one legacy publisher state transition. Keeping this as a typed
/// value avoids long positional calls that can silently swap world roots or
/// identity fields.
#[derive(Clone, Debug)]
pub struct PublicationStateUpdate {
    pub execution_id: String,
    pub destination_identity: String,
    pub accepted_final_root: String,
    pub accepted_delta_root: String,
    pub run_id: String,
    pub decision_identity: String,
    pub pre_publication_root: String,
    pub state: PublicationState,
    pub post_publication_root: Option<String>,
    pub error: Option<String>,
}

type PublicationKey = (String, String);

#[derive(Debug)]
pub enum PublicationJournalError {
    Io(io::Error),
    Scan(crate::filesystem_world::FilesystemScanError),
    Corrupt,
    Conflict(String),
    Publication(PublicationError),
}

impl std::fmt::Display for PublicationJournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "publication journal I/O: {error}"),
            Self::Scan(error) => write!(f, "publication journal scan: {error:?}"),
            Self::Corrupt => write!(f, "publication journal is corrupt"),
            Self::Conflict(reason) => write!(f, "publication conflict: {reason}"),
            Self::Publication(error) => write!(f, "publication failed: {error}"),
        }
    }
}

impl std::error::Error for PublicationJournalError {}
impl From<io::Error> for PublicationJournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<crate::filesystem_world::FilesystemScanError> for PublicationJournalError {
    fn from(error: crate::filesystem_world::FilesystemScanError) -> Self {
        Self::Scan(error)
    }
}
impl From<PublicationError> for PublicationJournalError {
    fn from(error: PublicationError) -> Self {
        Self::Publication(error)
    }
}

pub struct DestinationLock(File);

impl DestinationLock {
    pub fn acquire(destination: &Path) -> Result<Self, PublicationJournalError> {
        let name = destination
            .file_name()
            .ok_or_else(|| PublicationJournalError::Conflict("destination has no name".into()))?;
        let lock_path = destination
            .parent()
            .ok_or_else(|| PublicationJournalError::Conflict("destination has no parent".into()))?
            .join(format!(
                ".{}.realm-publication.lock",
                name.to_string_lossy()
            ));
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(lock_path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return Err(PublicationJournalError::Conflict(
                "publication lock has unsafe type, owner, or permissions".into(),
            ));
        }
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(PublicationJournalError::Conflict(
                "destination is locked by another publisher".into(),
            ));
        }
        Ok(Self(file))
    }
}

impl Drop for DestinationLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub struct PublicationJournal {
    path: PathBuf,
    next_sequence: u64,
    effective: BTreeMap<PublicationKey, PublicationRecord>,
}

impl PublicationJournal {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PublicationJournalError> {
        let path = path.into();
        let mut next_sequence = 1;
        let mut effective = BTreeMap::new();
        let mut history: BTreeMap<PublicationKey, Vec<PublicationRecord>> = BTreeMap::new();
        match fs::symlink_metadata(&path) {
            Ok(metadata) => validate_journal_metadata(&metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if fs::symlink_metadata(&path).is_ok() {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            validate_journal_metadata(&file.metadata()?)?;
            let mut previous = 0;
            for line in BufReader::new(file).lines() {
                let line = line?;
                let record: PublicationRecord =
                    serde_json::from_str(&line).map_err(|_| PublicationJournalError::Corrupt)?;
                if record.sequence != previous + 1 || !matches!(record.schema_version, 1 | 2) {
                    return Err(PublicationJournalError::Corrupt);
                }
                previous = record.sequence;
                next_sequence = previous + 1;
                let key = publication_key(&record);
                let prior_records = history.entry(key.clone()).or_default();
                if prior_records
                    .iter()
                    .any(|prior| same_lifecycle_record(prior, &record))
                {
                    continue;
                }
                validate_lifecycle_transition(effective.get(&key), &record)
                    .map_err(|_| PublicationJournalError::Corrupt)?;
                effective.insert(key, record.clone());
                prior_records.push(record);
            }
        }
        Ok(Self {
            path,
            next_sequence,
            effective,
        })
    }

    pub fn append(&mut self, mut record: PublicationRecord) -> Result<(), PublicationJournalError> {
        if !matches!(record.schema_version, 1 | 2) {
            return Err(PublicationJournalError::Corrupt);
        }
        record.sequence = self.next_sequence;
        let key = publication_key(&record);
        validate_lifecycle_transition(self.effective.get(&key), &record).map_err(|_| {
            PublicationJournalError::Conflict("invalid publication lifecycle transition".into())
        })?;
        let parent = self.path.parent().ok_or(PublicationJournalError::Corrupt)?;
        fs::create_dir_all(parent)?;
        let was_missing = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => {
                validate_journal_metadata(&metadata)?;
                false
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error.into()),
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)?;
        validate_journal_metadata(&file.metadata()?)?;
        let encoded = serde_json::to_vec(&record).map_err(|_| PublicationJournalError::Corrupt)?;
        crash_at(&record.state, "BEFORE_JOURNAL_FSYNC");
        file.write_all(&encoded)?;
        file.write_all(b"\n")?;
        file.sync_all_traced()?;
        if was_missing {
            sync_directory(parent)?;
        }
        crash_at(&record.state, "AFTER_JOURNAL_FSYNC");
        self.next_sequence += 1;
        self.effective.insert(key, record);
        Ok(())
    }

    pub fn record_state(
        &mut self,
        update: PublicationStateUpdate,
    ) -> Result<(), PublicationJournalError> {
        let PublicationStateUpdate {
            execution_id,
            destination_identity,
            accepted_final_root,
            accepted_delta_root,
            run_id,
            decision_identity,
            pre_publication_root,
            state,
            post_publication_root,
            error,
        } = update;
        if matches!(
            state,
            PublicationState::Prepared | PublicationState::Publishing
        ) {
            let key = (execution_id.clone(), destination_identity.clone());
            if let Some(current) = self.effective.get(&key) {
                match current.state {
                    PublicationState::Published => {
                        return Err(PublicationJournalError::Conflict(
                            "execution was already published to this destination".into(),
                        ));
                    }
                    PublicationState::Interrupted => {
                        return Err(PublicationJournalError::Conflict(
                            "an interrupted publication requires explicit operator reconciliation"
                                .into(),
                        ));
                    }
                    PublicationState::Prepared | PublicationState::Publishing
                        if state == PublicationState::Prepared =>
                    {
                        return Err(PublicationJournalError::Conflict(
                            "an unfinished publication exists for this execution and destination"
                                .into(),
                        ));
                    }
                    PublicationState::Failed | PublicationState::Conflict => {
                        return Err(PublicationJournalError::Conflict(
                            "a terminal publication cannot be reopened".into(),
                        ));
                    }
                    PublicationState::Prepared | PublicationState::Publishing => {}
                    PublicationState::GenerationPreparing
                    | PublicationState::GenerationPrepared
                    | PublicationState::CommitIntent
                    | PublicationState::CommitInProgress
                    | PublicationState::Committed
                    | PublicationState::PublicationVerified
                    | PublicationState::ReceiptPersisted
                    | PublicationState::IntegrityFailure => {
                        return Err(PublicationJournalError::Conflict(
                            "generation lifecycle cannot be reopened by the legacy publisher"
                                .into(),
                        ));
                    }
                }
            }
        }
        self.append(PublicationRecord {
            schema_version: 1,
            sequence: 0,
            publication_id: execution_id.clone(),
            execution_id,
            run_id,
            decision_identity,
            destination_identity,
            accepted_final_root,
            accepted_delta_root,
            pre_publication_root,
            post_publication_root,
            generation_identity: None,
            receipt_digest: None,
            state,
            error,
        })
    }

    pub fn record_generation_state(
        &mut self,
        identity: &GenerationIdentity,
        state: PublicationState,
        post_publication_root: Option<String>,
        receipt_digest: Option<String>,
        error: Option<String>,
    ) -> Result<(), PublicationJournalError> {
        if identity.validate_integrity().is_err()
            || !is_generation_state(state)
            || identity.workspace_identity().is_empty()
        {
            return Err(PublicationJournalError::Corrupt);
        }
        self.append(PublicationRecord {
            schema_version: 2,
            sequence: 0,
            publication_id: identity.publication_id().into(),
            execution_id: identity.execution_id().into(),
            run_id: identity.run_id().into(),
            decision_identity: identity.accepted_decision_identity().into(),
            destination_identity: identity.workspace_identity().into(),
            accepted_final_root: identity.accepted_final_root().into(),
            accepted_delta_root: identity.accepted_delta_root().into(),
            pre_publication_root: identity.accepted_start_root().into(),
            post_publication_root,
            generation_identity: Some(identity.clone()),
            receipt_digest,
            state,
            error,
        })
    }

    pub fn generation_records_for_workspace(
        &self,
        workspace_identity: &str,
    ) -> Vec<PublicationRecord> {
        let mut records = self
            .effective
            .values()
            .filter(|record| {
                record.schema_version == 2
                    && record.destination_identity == workspace_identity
                    && record.generation_identity.is_some()
            })
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by_key(|record| record.sequence);
        records
    }

    pub fn has_unfinished_generation_for_workspace(&self, workspace_identity: &str) -> bool {
        self.effective.values().any(|record| {
            record.schema_version == 2
                && record.destination_identity == workspace_identity
                && is_unfinished_record(record)
        })
    }

    pub fn has_unfinished(&self, execution_id: &str, destination_identity: &str) -> bool {
        self.effective
            .get(&(execution_id.into(), destination_identity.into()))
            .is_some_and(is_unfinished_record)
    }

    pub fn recover_unfinished(&mut self) -> Result<usize, PublicationJournalError> {
        if self
            .effective
            .values()
            .any(|record| record.schema_version == 2 && is_unfinished_record(record))
        {
            return Err(PublicationJournalError::Conflict(
                "generation publication requires world-aware recovery".into(),
            ));
        }
        let pending = self
            .effective
            .values()
            .filter(|record| {
                matches!(
                    record.state,
                    PublicationState::Prepared | PublicationState::Publishing
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let count = pending.len();
        for record in pending {
            self.append(PublicationRecord {
                schema_version: 1,
                sequence: 0,
                publication_id: record.publication_id,
                execution_id: record.execution_id,
                run_id: record.run_id,
                decision_identity: record.decision_identity,
                destination_identity: record.destination_identity,
                accepted_final_root: record.accepted_final_root,
                accepted_delta_root: record.accepted_delta_root,
                pre_publication_root: record.pre_publication_root,
                post_publication_root: None,
                generation_identity: record.generation_identity,
                receipt_digest: None,
                state: PublicationState::Interrupted,
                error: Some("publisher terminated before durable completion".into()),
            })?;
        }
        Ok(count)
    }
}

fn is_unfinished_record(record: &PublicationRecord) -> bool {
    match record.schema_version {
        1 => matches!(
            record.state,
            PublicationState::Prepared | PublicationState::Publishing
        ),
        2 => matches!(
            record.state,
            PublicationState::GenerationPreparing
                | PublicationState::GenerationPrepared
                | PublicationState::CommitIntent
                | PublicationState::CommitInProgress
                | PublicationState::Committed
                | PublicationState::PublicationVerified
                | PublicationState::ReceiptPersisted
        ),
        _ => false,
    }
}

fn publication_key(record: &PublicationRecord) -> PublicationKey {
    (
        record.execution_id.clone(),
        record.destination_identity.clone(),
    )
}

/// Returns true when `next` advances the lifecycle and false for an exact
/// duplicate historical record. Replay accepts exact duplicates so old
/// append-only journals remain readable, but new appends may not add them.
fn same_lifecycle_record(left: &PublicationRecord, right: &PublicationRecord) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left.sequence = 0;
    right.sequence = 0;
    left == right
}

fn validate_lifecycle_transition(
    current: Option<&PublicationRecord>,
    next: &PublicationRecord,
) -> Result<(), ()> {
    validate_record_shape(next)?;
    let Some(current) = current else {
        let first_state = match next.schema_version {
            1 => next.state == PublicationState::Prepared,
            2 => next.state == PublicationState::GenerationPreparing,
            _ => false,
        };
        return first_state.then_some(()).ok_or(());
    };

    if current.schema_version != next.schema_version
        || current.publication_id != next.publication_id
        || current.run_id != next.run_id
        || current.decision_identity != next.decision_identity
        || current.accepted_final_root != next.accepted_final_root
        || current.accepted_delta_root != next.accepted_delta_root
        || current.pre_publication_root != next.pre_publication_root
        || current.generation_identity != next.generation_identity
    {
        return Err(());
    }

    let valid = if current.schema_version == 1 {
        match current.state {
            PublicationState::Prepared => matches!(
                next.state,
                PublicationState::Publishing | PublicationState::Interrupted
            ),
            PublicationState::Publishing => matches!(
                next.state,
                PublicationState::Published
                    | PublicationState::Failed
                    | PublicationState::Conflict
                    | PublicationState::Interrupted
            ),
            _ => false,
        }
    } else {
        match current.state {
            PublicationState::GenerationPreparing => matches!(
                next.state,
                PublicationState::GenerationPrepared
                    | PublicationState::Failed
                    | PublicationState::Conflict
                    | PublicationState::Interrupted
                    | PublicationState::IntegrityFailure
            ),
            PublicationState::GenerationPrepared => matches!(
                next.state,
                PublicationState::CommitIntent
                    | PublicationState::Failed
                    | PublicationState::Conflict
                    | PublicationState::Interrupted
                    | PublicationState::IntegrityFailure
            ),
            PublicationState::CommitIntent => matches!(
                next.state,
                PublicationState::CommitInProgress
                    | PublicationState::Interrupted
                    | PublicationState::IntegrityFailure
            ),
            PublicationState::CommitInProgress => matches!(
                next.state,
                PublicationState::Committed
                    | PublicationState::Conflict
                    | PublicationState::Interrupted
                    | PublicationState::IntegrityFailure
            ),
            PublicationState::Committed => matches!(
                next.state,
                PublicationState::PublicationVerified | PublicationState::IntegrityFailure
            ),
            PublicationState::PublicationVerified => matches!(
                next.state,
                PublicationState::ReceiptPersisted | PublicationState::IntegrityFailure
            ),
            PublicationState::ReceiptPersisted => matches!(
                next.state,
                PublicationState::Published | PublicationState::IntegrityFailure
            ),
            _ => false,
        }
    };
    valid.then_some(()).ok_or(())
}

fn validate_record_shape(record: &PublicationRecord) -> Result<(), ()> {
    if record.schema_version == 1 {
        if record.generation_identity.is_some() || record.receipt_digest.is_some() {
            return Err(());
        }
        match record.state {
            PublicationState::Prepared | PublicationState::Publishing
                if record.post_publication_root.is_some() || record.error.is_some() =>
            {
                return Err(());
            }
            PublicationState::Published
                if record
                    .post_publication_root
                    .as_deref()
                    .is_none_or(str::is_empty)
                    || record.error.is_some() =>
            {
                return Err(());
            }
            PublicationState::Failed
            | PublicationState::Conflict
            | PublicationState::Interrupted
                if record.post_publication_root.is_some()
                    || record.error.as_deref().is_none_or(str::is_empty) =>
            {
                return Err(());
            }
            PublicationState::Prepared
            | PublicationState::Publishing
            | PublicationState::Published
            | PublicationState::Failed
            | PublicationState::Conflict
            | PublicationState::Interrupted => {}
            _ => return Err(()),
        }
        return Ok(());
    }
    if record.schema_version != 2 {
        return Err(());
    }
    let identity = record.generation_identity.as_ref().ok_or(())?;
    identity.validate_integrity().map_err(|_| ())?;
    if identity.execution_id() != record.execution_id
        || identity.run_id() != record.run_id
        || identity.publication_id() != record.publication_id
        || identity.accepted_decision_identity() != record.decision_identity
        || identity.workspace_identity() != record.destination_identity
        || identity.accepted_final_root() != record.accepted_final_root
        || identity.accepted_delta_root() != record.accepted_delta_root
        || identity.accepted_start_root() != record.pre_publication_root
    {
        return Err(());
    }
    match record.state {
        PublicationState::GenerationPreparing
        | PublicationState::GenerationPrepared
        | PublicationState::CommitIntent
        | PublicationState::CommitInProgress
        | PublicationState::Committed
            if record.post_publication_root.is_some()
                || record.receipt_digest.is_some()
                || record.error.is_some() =>
        {
            return Err(());
        }
        PublicationState::PublicationVerified
            if record.post_publication_root.as_deref() != Some(identity.accepted_final_root())
                || record.receipt_digest.is_some()
                || record.error.is_some() =>
        {
            return Err(());
        }
        PublicationState::ReceiptPersisted | PublicationState::Published
            if record.post_publication_root.as_deref() != Some(identity.accepted_final_root())
                || !record.receipt_digest.as_deref().is_some_and(valid_digest)
                || record.error.is_some() =>
        {
            return Err(());
        }
        PublicationState::Failed | PublicationState::Conflict | PublicationState::Interrupted
            if record.post_publication_root.is_some()
                || record.receipt_digest.is_some()
                || record.error.as_deref().is_none_or(str::is_empty) =>
        {
            return Err(());
        }
        PublicationState::IntegrityFailure
            if record.error.as_deref().is_none_or(str::is_empty)
                || record.receipt_digest.is_some() =>
        {
            return Err(());
        }
        PublicationState::GenerationPreparing
        | PublicationState::GenerationPrepared
        | PublicationState::CommitIntent
        | PublicationState::CommitInProgress
        | PublicationState::Committed
        | PublicationState::PublicationVerified
        | PublicationState::ReceiptPersisted
        | PublicationState::Published
        | PublicationState::Failed
        | PublicationState::Conflict
        | PublicationState::Interrupted
        | PublicationState::IntegrityFailure => {}
        _ => return Err(()),
    }
    Ok(())
}

fn is_generation_state(state: PublicationState) -> bool {
    matches!(
        state,
        PublicationState::GenerationPreparing
            | PublicationState::GenerationPrepared
            | PublicationState::CommitIntent
            | PublicationState::CommitInProgress
            | PublicationState::Committed
            | PublicationState::PublicationVerified
            | PublicationState::ReceiptPersisted
            | PublicationState::Published
            | PublicationState::Failed
            | PublicationState::Conflict
            | PublicationState::Interrupted
            | PublicationState::IntegrityFailure
    )
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_journal_metadata(metadata: &fs::Metadata) -> Result<(), PublicationJournalError> {
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(PublicationJournalError::Corrupt);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), PublicationJournalError> {
    File::open(path)?.sync_all_traced()?;
    Ok(())
}

fn crash_at(state: &PublicationState, point: &str) {
    let state_name = match state {
        PublicationState::Prepared => "PREPARED",
        PublicationState::Publishing => "PUBLISHING",
        PublicationState::Published => "PUBLISHED",
        PublicationState::Failed => "FAILED",
        PublicationState::Conflict => "CONFLICT",
        PublicationState::Interrupted => "INTERRUPTED",
        PublicationState::GenerationPreparing => "GENERATION_PREPARING",
        PublicationState::GenerationPrepared => "GENERATION_PREPARED",
        PublicationState::CommitIntent => "COMMIT_INTENT",
        PublicationState::CommitInProgress => "COMMIT_IN_PROGRESS",
        PublicationState::Committed => "COMMITTED",
        PublicationState::PublicationVerified => "PUBLICATION_VERIFIED",
        PublicationState::ReceiptPersisted => "RECEIPT_PERSISTED",
        PublicationState::IntegrityFailure => "INTEGRITY_FAILURE",
    };
    let configured = std::env::var("REALM_PUBLICATION_CRASH_AT").ok();
    if configured.as_deref() == Some(point)
        || configured.as_deref() == Some(&format!("{state_name}_{point}"))
    {
        std::process::abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generation::GenerationLayout;
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_PATH: AtomicU64 = AtomicU64::new(0);

    fn test_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "realm-publication-journal-test-{}-{}",
            std::process::id(),
            NEXT_TEST_PATH.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn generation_fixture() -> (PathBuf, GenerationIdentity) {
        let root = test_path().canonicalize().unwrap_or_else(|_| {
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "realm-generation-journal-fixture-{}-{}",
                std::process::id(),
                NEXT_TEST_PATH.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            path
        });
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let live = root.join("workspace");
        fs::create_dir(&live).unwrap();
        fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).unwrap();
        let checked = crate::execute::test_checked_execution(
            "journal-run",
            &"8".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
            &"3".repeat(64),
        );
        let layout = GenerationLayout::inspect(&live).unwrap();
        let identity = GenerationIdentity::from_publication_capability(&checked, &layout).unwrap();
        (root, identity)
    }

    fn record(
        execution_id: &str,
        destination_identity: &str,
        state: PublicationState,
        sequence: u64,
    ) -> PublicationRecord {
        PublicationRecord {
            schema_version: 1,
            sequence,
            publication_id: format!("publication-{execution_id}"),
            execution_id: execution_id.into(),
            run_id: format!("run-{execution_id}"),
            decision_identity: format!("decision-{execution_id}"),
            destination_identity: destination_identity.into(),
            accepted_final_root: format!("final-{execution_id}"),
            accepted_delta_root: format!("delta-{execution_id}"),
            pre_publication_root: format!("before-{execution_id}"),
            post_publication_root: (state == PublicationState::Published)
                .then(|| format!("after-{execution_id}")),
            generation_identity: None,
            receipt_digest: None,
            error: matches!(
                state,
                PublicationState::Failed
                    | PublicationState::Conflict
                    | PublicationState::Interrupted
            )
            .then(|| format!("{state:?}-{execution_id}")),
            state,
        }
    }

    fn append_state(
        journal: &mut PublicationJournal,
        execution_id: &str,
        destination_identity: &str,
        state: PublicationState,
    ) {
        journal
            .append(record(execution_id, destination_identity, state, 0))
            .unwrap();
    }

    fn read_records(path: &Path) -> Vec<PublicationRecord> {
        BufReader::new(File::open(path).unwrap())
            .lines()
            .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
            .collect()
    }

    fn write_journal_fixture(path: &Path, bytes: impl AsRef<[u8]>) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn interrupted_publication_is_durable_and_not_retryable() {
        let path = test_path();
        let mut journal = PublicationJournal::open(&path).unwrap();
        append_state(
            &mut journal,
            "execution-a",
            "destination-a",
            PublicationState::Prepared,
        );
        append_state(
            &mut journal,
            "execution-a",
            "destination-a",
            PublicationState::Publishing,
        );
        drop(journal);

        let mut recovered = PublicationJournal::open(&path).unwrap();
        assert_eq!(recovered.recover_unfinished().unwrap(), 1);
        assert_eq!(recovered.recover_unfinished().unwrap(), 0);
        let error = recovered
            .record_state(PublicationStateUpdate {
                execution_id: "execution-a".into(),
                destination_identity: "destination-a".into(),
                accepted_final_root: "final-a".into(),
                accepted_delta_root: "delta-a".into(),
                run_id: "run-a".into(),
                decision_identity: "decision-a".into(),
                pre_publication_root: "before-a".into(),
                state: PublicationState::Prepared,
                post_publication_root: None,
                error: None,
            })
            .unwrap_err();
        assert!(error.to_string().contains("operator reconciliation"));
        drop(recovered);

        let mut reopened = PublicationJournal::open(&path).unwrap();
        assert_eq!(reopened.recover_unfinished().unwrap(), 0);
        drop(reopened);
        let records = read_records(&path);
        assert_eq!(
            records
                .iter()
                .map(|record| record.state)
                .collect::<Vec<_>>(),
            vec![
                PublicationState::Prepared,
                PublicationState::Publishing,
                PublicationState::Interrupted,
            ]
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn published_failed_and_conflict_terminals_close_prior_history() {
        for terminal in [
            PublicationState::Published,
            PublicationState::Failed,
            PublicationState::Conflict,
        ] {
            let path = test_path();
            let mut journal = PublicationJournal::open(&path).unwrap();
            append_state(
                &mut journal,
                "execution-a",
                "destination-a",
                PublicationState::Prepared,
            );
            append_state(
                &mut journal,
                "execution-a",
                "destination-a",
                PublicationState::Publishing,
            );
            append_state(&mut journal, "execution-a", "destination-a", terminal);
            drop(journal);

            let mut reopened = PublicationJournal::open(&path).unwrap();
            assert!(!reopened.has_unfinished("execution-a", "destination-a"));
            assert_eq!(reopened.recover_unfinished().unwrap(), 0);
            let error = reopened
                .record_state(PublicationStateUpdate {
                    execution_id: "execution-a".into(),
                    destination_identity: "destination-a".into(),
                    accepted_final_root: "final-execution-a".into(),
                    accepted_delta_root: "delta-execution-a".into(),
                    run_id: "run-execution-a".into(),
                    decision_identity: "decision-execution-a".into(),
                    pre_publication_root: "before-execution-a".into(),
                    state: PublicationState::Prepared,
                    post_publication_root: None,
                    error: None,
                })
                .unwrap_err();
            match terminal {
                PublicationState::Published => {
                    assert!(error.to_string().contains("already published"));
                }
                PublicationState::Failed | PublicationState::Conflict => {
                    assert!(error.to_string().contains("terminal"));
                }
                _ => unreachable!(),
            }
            drop(reopened);

            let records = read_records(&path);
            assert_eq!(records.last().unwrap().state, terminal);
            assert_eq!(
                records
                    .iter()
                    .filter(|record| record.state == PublicationState::Interrupted)
                    .count(),
                0
            );
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn interleaved_unfinished_identities_recover_once_and_stay_terminal() {
        let path = test_path();
        let mut journal = PublicationJournal::open(&path).unwrap();
        append_state(
            &mut journal,
            "published",
            "destination-a",
            PublicationState::Prepared,
        );
        append_state(
            &mut journal,
            "unfinished",
            "destination-b",
            PublicationState::Prepared,
        );
        append_state(
            &mut journal,
            "published",
            "destination-a",
            PublicationState::Publishing,
        );
        append_state(
            &mut journal,
            "published",
            "destination-a",
            PublicationState::Published,
        );
        append_state(
            &mut journal,
            "unfinished",
            "destination-b",
            PublicationState::Publishing,
        );
        append_state(
            &mut journal,
            "prepared-only",
            "destination-c",
            PublicationState::Prepared,
        );
        drop(journal);

        let mut recovered = PublicationJournal::open(&path).unwrap();
        assert!(!recovered.has_unfinished("published", "destination-a"));
        assert!(recovered.has_unfinished("unfinished", "destination-b"));
        assert!(recovered.has_unfinished("prepared-only", "destination-c"));
        assert_eq!(recovered.recover_unfinished().unwrap(), 2);
        assert_eq!(recovered.recover_unfinished().unwrap(), 0);
        drop(recovered);

        let mut reopened = PublicationJournal::open(&path).unwrap();
        assert_eq!(reopened.recover_unfinished().unwrap(), 0);
        assert!(!reopened.has_unfinished("published", "destination-a"));
        assert!(!reopened.has_unfinished("unfinished", "destination-b"));
        assert!(!reopened.has_unfinished("prepared-only", "destination-c"));
        drop(reopened);

        let records = read_records(&path);
        assert_eq!(
            records
                .iter()
                .filter(|record| {
                    record.execution_id == "unfinished"
                        && record.state == PublicationState::Interrupted
                })
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| {
                    record.execution_id == "prepared-only"
                        && record.state == PublicationState::Interrupted
                })
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| {
                    record.execution_id == "published"
                        && record.state == PublicationState::Interrupted
                })
                .count(),
            0
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn exact_duplicate_history_is_idempotent_per_identity() {
        let path = test_path();
        let history = [
            record("published", "destination-a", PublicationState::Prepared, 1),
            record("pending", "destination-b", PublicationState::Prepared, 2),
            record("published", "destination-a", PublicationState::Prepared, 3),
            record(
                "published",
                "destination-a",
                PublicationState::Publishing,
                4,
            ),
            record(
                "published",
                "destination-a",
                PublicationState::Publishing,
                5,
            ),
            record("published", "destination-a", PublicationState::Published, 6),
            record("published", "destination-a", PublicationState::Published, 7),
            record("published", "destination-a", PublicationState::Prepared, 8),
            record("pending", "destination-b", PublicationState::Prepared, 9),
            record("pending", "destination-b", PublicationState::Publishing, 10),
            record("pending", "destination-b", PublicationState::Publishing, 11),
        ];
        let bytes = history
            .iter()
            .map(|record| format!("{}\n", serde_json::to_string(record).unwrap()))
            .collect::<String>();
        write_journal_fixture(&path, bytes);

        let mut replayed = PublicationJournal::open(&path).unwrap();
        assert!(!replayed.has_unfinished("published", "destination-a"));
        assert!(replayed.has_unfinished("pending", "destination-b"));
        assert_eq!(replayed.recover_unfinished().unwrap(), 1);
        assert_eq!(replayed.recover_unfinished().unwrap(), 0);
        drop(replayed);

        let mut reopened = PublicationJournal::open(&path).unwrap();
        assert_eq!(reopened.recover_unfinished().unwrap(), 0);
        drop(reopened);
        let records = read_records(&path);
        assert_eq!(records.len(), 12);
        assert_eq!(records.last().unwrap().state, PublicationState::Interrupted);
        assert_eq!(
            records
                .iter()
                .filter(|record| {
                    record.execution_id == "published"
                        && record.state == PublicationState::Interrupted
                })
                .count(),
            0
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn terminal_state_cannot_be_reopened_and_malformed_history_fails_closed() {
        let path = test_path();
        let mut journal = PublicationJournal::open(&path).unwrap();
        append_state(
            &mut journal,
            "execution-a",
            "destination-a",
            PublicationState::Prepared,
        );
        append_state(
            &mut journal,
            "execution-a",
            "destination-a",
            PublicationState::Publishing,
        );
        append_state(
            &mut journal,
            "execution-a",
            "destination-a",
            PublicationState::Published,
        );
        let error = journal
            .record_state(PublicationStateUpdate {
                execution_id: "execution-a".into(),
                destination_identity: "destination-a".into(),
                accepted_final_root: "final-execution-a".into(),
                accepted_delta_root: "delta-execution-a".into(),
                run_id: "run-execution-a".into(),
                decision_identity: "decision-execution-a".into(),
                pre_publication_root: "before-execution-a".into(),
                state: PublicationState::Publishing,
                post_publication_root: None,
                error: None,
            })
            .unwrap_err();
        assert!(error.to_string().contains("already published"));
        drop(journal);
        assert_eq!(read_records(&path).len(), 3);
        let _ = fs::remove_file(path);

        let illegal_path = test_path();
        let illegal_history = [
            record(
                "execution-a",
                "destination-a",
                PublicationState::Prepared,
                1,
            ),
            record(
                "execution-a",
                "destination-a",
                PublicationState::Publishing,
                2,
            ),
            record(
                "execution-a",
                "destination-a",
                PublicationState::Published,
                3,
            ),
            record(
                "execution-a",
                "destination-a",
                PublicationState::Interrupted,
                4,
            ),
        ];
        write_journal_fixture(
            &illegal_path,
            illegal_history
                .iter()
                .map(|record| format!("{}\n", serde_json::to_string(record).unwrap()))
                .collect::<String>(),
        );
        assert!(matches!(
            PublicationJournal::open(&illegal_path),
            Err(PublicationJournalError::Corrupt)
        ));
        let _ = fs::remove_file(illegal_path);

        let truncated_path = test_path();
        let valid = serde_json::to_string(&record(
            "execution-a",
            "destination-a",
            PublicationState::Prepared,
            1,
        ))
        .unwrap();
        write_journal_fixture(&truncated_path, format!("{valid}\n{{\"schema_version\":"));
        assert!(matches!(
            PublicationJournal::open(&truncated_path),
            Err(PublicationJournalError::Corrupt)
        ));
        let _ = fs::remove_file(truncated_path);
    }

    #[test]
    fn initial_skipped_and_mismatched_transitions_fail_closed() {
        let initial_path = test_path();
        let mut first = record(
            "execution-a",
            "destination-a",
            PublicationState::Publishing,
            1,
        );
        first.post_publication_root = None;
        first.error = None;
        write_journal_fixture(
            &initial_path,
            format!("{}\n", serde_json::to_string(&first).unwrap()),
        );
        assert!(matches!(
            PublicationJournal::open(&initial_path),
            Err(PublicationJournalError::Corrupt)
        ));
        let _ = fs::remove_file(initial_path);

        let skipped_path = test_path();
        let history = [
            record(
                "execution-a",
                "destination-a",
                PublicationState::Prepared,
                1,
            ),
            record(
                "execution-a",
                "destination-a",
                PublicationState::Published,
                2,
            ),
        ];
        write_journal_fixture(
            &skipped_path,
            history
                .iter()
                .map(|record| format!("{}\n", serde_json::to_string(record).unwrap()))
                .collect::<String>(),
        );
        assert!(matches!(
            PublicationJournal::open(&skipped_path),
            Err(PublicationJournalError::Corrupt)
        ));
        let _ = fs::remove_file(skipped_path);

        let mismatched_path = test_path();
        let mut publishing = record(
            "execution-a",
            "destination-a",
            PublicationState::Publishing,
            2,
        );
        publishing.post_publication_root = None;
        publishing.error = None;
        publishing.accepted_delta_root = "substituted-delta".into();
        let history = [
            record(
                "execution-a",
                "destination-a",
                PublicationState::Prepared,
                1,
            ),
            publishing,
        ];
        write_journal_fixture(
            &mismatched_path,
            history
                .iter()
                .map(|record| format!("{}\n", serde_json::to_string(record).unwrap()))
                .collect::<String>(),
        );
        assert!(matches!(
            PublicationJournal::open(&mismatched_path),
            Err(PublicationJournalError::Corrupt)
        ));
        let _ = fs::remove_file(mismatched_path);

        let malformed_terminal_path = test_path();
        let mut published = record(
            "execution-a",
            "destination-a",
            PublicationState::Published,
            3,
        );
        published.post_publication_root = None;
        let history = [
            record(
                "execution-a",
                "destination-a",
                PublicationState::Prepared,
                1,
            ),
            {
                let mut publishing = record(
                    "execution-a",
                    "destination-a",
                    PublicationState::Publishing,
                    2,
                );
                publishing.post_publication_root = None;
                publishing.error = None;
                publishing
            },
            published,
        ];
        write_journal_fixture(
            &malformed_terminal_path,
            history
                .iter()
                .map(|record| format!("{}\n", serde_json::to_string(record).unwrap()))
                .collect::<String>(),
        );
        assert!(matches!(
            PublicationJournal::open(&malformed_terminal_path),
            Err(PublicationJournalError::Corrupt)
        ));
        let _ = fs::remove_file(malformed_terminal_path);
    }

    #[test]
    fn generation_lifecycle_replays_and_terminal_state_cannot_reopen() {
        let (root, identity) = generation_fixture();
        let path = root.join("generation-publication.jsonl");
        let mut journal = PublicationJournal::open(&path).unwrap();
        for state in [
            PublicationState::GenerationPreparing,
            PublicationState::GenerationPrepared,
            PublicationState::CommitIntent,
            PublicationState::CommitInProgress,
            PublicationState::Committed,
        ] {
            journal
                .record_generation_state(&identity, state, None, None, None)
                .unwrap();
        }
        journal
            .record_generation_state(
                &identity,
                PublicationState::PublicationVerified,
                Some(identity.accepted_final_root().into()),
                None,
                None,
            )
            .unwrap();
        journal
            .record_generation_state(
                &identity,
                PublicationState::ReceiptPersisted,
                Some(identity.accepted_final_root().into()),
                Some("a".repeat(64)),
                None,
            )
            .unwrap();
        journal
            .record_generation_state(
                &identity,
                PublicationState::Published,
                Some(identity.accepted_final_root().into()),
                Some("a".repeat(64)),
                None,
            )
            .unwrap();
        drop(journal);

        let reopened = PublicationJournal::open(&path).unwrap();
        let records = reopened.generation_records_for_workspace(identity.workspace_identity());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, PublicationState::Published);
        let mut reopened = reopened;
        assert!(matches!(
            reopened.record_generation_state(
                &identity,
                PublicationState::CommitIntent,
                None,
                None,
                None
            ),
            Err(PublicationJournalError::Conflict(_))
        ));
        drop(reopened);
        let stable = PublicationJournal::open(&path).unwrap();
        assert_eq!(
            stable.generation_records_for_workspace(identity.workspace_identity())[0].state,
            PublicationState::Published
        );
        fs::remove_dir_all(root).unwrap();
    }
}
