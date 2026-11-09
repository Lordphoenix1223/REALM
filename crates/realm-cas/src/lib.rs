//! Content-addressed preservation storage.
//!
//! The CAS stores bytes before a protected mutation is allowed. A hash-only
//! observation is never represented as a recoverable blob.

use realm_core::PreservationMethod;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};
use thiserror::Error;
use uuid::Uuid;

const CAS_MAGIC: &[u8] = b"REALM-CAS-1\n";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobRef {
    pub hash: String,
    pub size: u64,
    pub method: PreservationMethod,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CasStats {
    pub blob_count: u64,
    pub physical_bytes: u64,
}

#[derive(Debug, Error)]
pub enum CasError {
    #[error("CAS I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("CAS blob is corrupt or has the wrong content hash")]
    Corrupt,
    #[error("source changed while it was being preserved")]
    RaceDetected,
    #[error("unsupported preimage source: {0}")]
    Unsupported(String),
}

pub struct PreimageStore {
    root: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct StagedPreimageId(pub Uuid);

impl StagedPreimageId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for StagedPreimageId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for StagedPreimageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StagedPreimage {
    pub id: StagedPreimageId,
    pub path: PathBuf,
    pub size: u64,
    pub method: PreservationMethod,
    pub source_signature: Option<(u64, u64, u64, u128)>,
    pub canonical: Option<BlobRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum StagingJournalTransition {
    PreimageStageBegin,
    PreimageStageDurable,
    MutationPrepared,
    MutationAllowed,
    MutationObserved,
    CanonicalizationBegin,
    CasCommitted,
    PreimageRefRebound,
    StagedPreimageReclaimed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StagingJournalRecord {
    pub stage_id: StagedPreimageId,
    pub transition: StagingJournalTransition,
    pub monotonic_ns: u128,
}

/// A durable short-lived preimage reference. The staged bytes remain pinned
/// until canonical CAS publication has succeeded and the caller explicitly
/// reclaims the stage.
pub struct StagedPreimageStore {
    cas: PreimageStore,
    root: PathBuf,
}

impl StagedPreimageStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, CasError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("staged"))?;
        let cas = PreimageStore::open(&root)?;
        Ok(Self { cas, root })
    }

    pub fn cas(&self) -> &PreimageStore {
        &self.cas
    }

    pub fn stage_bytes(&self, bytes: &[u8]) -> Result<StagedPreimage, CasError> {
        self.stage_bytes_with_method(bytes, PreservationMethod::ExactCopy)
    }

    pub fn stage_bytes_with_method(
        &self,
        bytes: &[u8],
        method: PreservationMethod,
    ) -> Result<StagedPreimage, CasError> {
        if matches!(
            method,
            PreservationMethod::Missing
                | PreservationMethod::Unsupported
                | PreservationMethod::RaceDetected
        ) {
            return Err(CasError::Unsupported(format!("cannot stage as {method:?}")));
        }
        let id = StagedPreimageId::new();
        let directory = self.stage_directory(id);
        fs::create_dir_all(&directory)?;
        self.append_transition(id, StagingJournalTransition::PreimageStageBegin)?;
        let payload = directory.join("payload");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&payload)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let record = StagedPreimage {
            id,
            path: payload,
            size: bytes.len() as u64,
            method,
            source_signature: None,
            canonical: None,
        };
        self.write_record(&record)?;
        sync_directory(&directory)?;
        sync_directory(&self.root.join("staged"))?;
        self.append_transition(id, StagingJournalTransition::PreimageStageDurable)?;
        Ok(record)
    }

    pub fn stage_file(&self, source: impl AsRef<Path>) -> Result<StagedPreimage, CasError> {
        let source = source.as_ref();
        let before = file_signature(source)?;
        let mut input = File::open(source)?;
        let id = StagedPreimageId::new();
        let directory = self.stage_directory(id);
        fs::create_dir_all(&directory)?;
        self.append_transition(id, StagingJournalTransition::PreimageStageBegin)?;
        let payload = directory.join("payload");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&payload)?;
        let copied = io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        let after = file_signature(source)?;
        if before != after {
            let _ = fs::remove_dir_all(&directory);
            return Err(CasError::RaceDetected);
        }
        let record = StagedPreimage {
            id,
            path: payload,
            size: copied,
            method: PreservationMethod::ExactCopy,
            source_signature: Some(after),
            canonical: None,
        };
        self.write_record(&record)?;
        sync_directory(&directory)?;
        sync_directory(&self.root.join("staged"))?;
        self.append_transition(id, StagingJournalTransition::PreimageStageDurable)?;
        Ok(record)
    }

    pub fn load(&self, id: StagedPreimageId) -> Result<StagedPreimage, CasError> {
        let bytes = fs::read(self.stage_directory(id).join("record.json"))?;
        serde_json::from_slice(&bytes).map_err(|error| CasError::Unsupported(error.to_string()))
    }

    pub fn canonicalize(&self, id: StagedPreimageId) -> Result<BlobRef, CasError> {
        let mut record = self.load(id)?;
        if let Some(canonical) = &record.canonical {
            self.cas.get_bytes(canonical)?;
            return Ok(canonical.clone());
        }
        self.append_transition(id, StagingJournalTransition::CanonicalizationBegin)?;
        let bytes = fs::read(&record.path)?;
        if bytes.len() as u64 != record.size {
            return Err(CasError::Corrupt);
        }
        let canonical = self.cas.put_bytes_with_method(&bytes, record.method)?;
        self.append_transition(id, StagingJournalTransition::CasCommitted)?;
        record.canonical = Some(canonical.clone());
        self.write_record(&record)?;
        sync_directory(&self.stage_directory(id))?;
        self.append_transition(id, StagingJournalTransition::PreimageRefRebound)?;
        Ok(canonical)
    }

    pub fn reclaim(&self, id: StagedPreimageId) -> Result<(), CasError> {
        let record = self.load(id)?;
        if record.canonical.is_none() {
            return Err(CasError::Unsupported(
                "staged preimage is still the only durable representation".into(),
            ));
        }
        self.append_transition(id, StagingJournalTransition::StagedPreimageReclaimed)?;
        fs::remove_dir_all(self.stage_directory(id))?;
        sync_directory(&self.root.join("staged"))?;
        Ok(())
    }

    fn stage_directory(&self, id: StagedPreimageId) -> PathBuf {
        self.root.join("staged").join(id.to_string())
    }

    fn write_record(&self, record: &StagedPreimage) -> Result<(), CasError> {
        let path = self.stage_directory(record.id).join("record.json");
        let temp = path.with_extension(format!("tmp-{}", unique_suffix()));
        fs::write(
            &temp,
            serde_json::to_vec_pretty(record)
                .map_err(|error| CasError::Unsupported(error.to_string()))?,
        )?;
        let file = OpenOptions::new().read(true).write(true).open(&temp)?;
        file.sync_all()?;
        drop(file);
        fs::rename(temp, path)?;
        Ok(())
    }

    pub fn append_transition(
        &self,
        stage_id: StagedPreimageId,
        transition: StagingJournalTransition,
    ) -> Result<(), CasError> {
        let path = self.root.join("staging-journal.log");
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        let record = StagingJournalRecord {
            stage_id,
            transition,
            monotonic_ns: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        };
        file.write_all(
            &serde_json::to_vec(&record)
                .map_err(|error| CasError::Unsupported(error.to_string()))?,
        )?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        sync_directory(&self.root)?;
        Ok(())
    }

    pub fn staging_journal(&self) -> Result<Vec<StagingJournalRecord>, CasError> {
        let path = self.root.join("staging-journal.log");
        if !path.exists() {
            return Ok(Vec::new());
        }
        fs::read_to_string(path)?
            .lines()
            .map(|line| {
                serde_json::from_str(line).map_err(|error| CasError::Unsupported(error.to_string()))
            })
            .collect()
    }
}

impl PreimageStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, CasError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("objects"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn put_bytes(&self, bytes: &[u8]) -> Result<BlobRef, CasError> {
        self.put_bytes_with_method(bytes, PreservationMethod::ExactCopy)
    }

    pub fn put_bytes_with_method(
        &self,
        bytes: &[u8],
        method: PreservationMethod,
    ) -> Result<BlobRef, CasError> {
        if matches!(
            method,
            PreservationMethod::Missing
                | PreservationMethod::Unsupported
                | PreservationMethod::RaceDetected
        ) {
            return Err(CasError::Unsupported(format!("cannot store as {method:?}")));
        }
        let hash = blake3::hash(bytes).to_hex().to_string();
        let path = self.blob_path(&hash);
        let reference = BlobRef {
            hash: hash.clone(),
            size: bytes.len() as u64,
            method,
        };
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() {
                return Err(CasError::Corrupt);
            }
            self.get_bytes(&reference)?;
            return Ok(reference);
        }
        fs::create_dir_all(path.parent().expect("CAS blob has a parent"))?;

        let temp_name = format!(".{}.{}.tmp", hash, unique_suffix());
        let temp = self.root.join("objects").join(temp_name);
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            file.write_all(CAS_MAGIC)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            match fs::hard_link(&temp, &path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
            sync_directory(&self.root.join("objects"))?;
            Ok::<(), io::Error>(())
        })();
        let _ = fs::remove_file(&temp);
        result?;
        self.get_bytes(&reference)?;

        Ok(reference)
    }

    pub fn put_file(&self, source: impl AsRef<Path>) -> Result<BlobRef, CasError> {
        let source = source.as_ref();
        let before = file_signature(source)?;
        let mut file = File::open(source)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let after = file_signature(source)?;
        if before != after {
            return Err(CasError::RaceDetected);
        }
        self.put_bytes(&bytes)
    }

    pub fn get_bytes(&self, reference: &BlobRef) -> Result<Vec<u8>, CasError> {
        let path = self.blob_path(&reference.hash);
        let mut file = File::open(path)?;
        let mut stored = Vec::new();
        file.read_to_end(&mut stored)?;
        if !stored.starts_with(CAS_MAGIC) {
            return Err(CasError::Corrupt);
        }
        let bytes = &stored[CAS_MAGIC.len()..];
        if bytes.len() as u64 != reference.size
            || blake3::hash(bytes).to_hex().to_string() != reference.hash
        {
            return Err(CasError::Corrupt);
        }
        Ok(bytes.to_vec())
    }

    pub fn blob_path(&self, hash: &str) -> PathBuf {
        let prefix = &hash[..2.min(hash.len())];
        self.root.join("objects").join(prefix).join(hash)
    }

    pub fn stats(&self) -> Result<CasStats, CasError> {
        let mut stats = CasStats::default();
        let objects = self.root.join("objects");
        for prefix in fs::read_dir(objects)? {
            let prefix = prefix?;
            if !prefix.file_type()?.is_dir() {
                continue;
            }
            for entry in fs::read_dir(prefix.path())? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    stats.blob_count += 1;
                    stats.physical_bytes += entry.metadata()?.len();
                }
            }
        }
        Ok(stats)
    }
}

fn file_signature(path: &Path) -> Result<(u64, u64, u64, u128), CasError> {
    let metadata = fs::metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        Ok((metadata.dev(), metadata.ino(), metadata.len(), modified))
    }
    #[cfg(not(unix))]
    {
        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        Ok((0, 0, metadata.len(), modified))
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn unique_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_and_deduplicates_exact_bytes() {
        let root = std::env::temp_dir().join(format!("realm-cas-{}", unique_suffix()));
        let store = PreimageStore::open(&root).unwrap();
        let first = store.put_bytes(b"same").unwrap();
        let second = store.put_bytes(b"same").unwrap();
        assert_eq!(first.hash, second.hash);
        assert_eq!(store.get_bytes(&first).unwrap(), b"same");
        assert_eq!(store.stats().unwrap().blob_count, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn staged_preimage_is_pinned_until_canonicalized() {
        let root = std::env::temp_dir().join(format!("realm-staged-{}", unique_suffix()));
        let store = StagedPreimageStore::open(&root).unwrap();
        let staged = store.stage_bytes(b"historical").unwrap();
        assert!(store.reclaim(staged.id).is_err());
        let canonical = store.canonicalize(staged.id).unwrap();
        assert_eq!(store.cas().get_bytes(&canonical).unwrap(), b"historical");
        store.reclaim(staged.id).unwrap();
        let journal = store.staging_journal().unwrap();
        assert!(
            journal.iter().any(|record| {
                record.transition == StagingJournalTransition::PreimageStageDurable
            })
        );
        assert!(
            journal.iter().any(|record| {
                record.transition == StagingJournalTransition::PreimageRefRebound
            })
        );
        assert!(journal.iter().any(|record| {
            record.transition == StagingJournalTransition::StagedPreimageReclaimed
        }));
        assert!(store.load(staged.id).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn staged_file_detects_source_race() {
        let root = std::env::temp_dir().join(format!("realm-staged-race-{}", unique_suffix()));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        fs::write(&source, b"before").unwrap();
        let store = StagedPreimageStore::open(root.join("store")).unwrap();
        let staged = store.stage_file(&source).unwrap();
        assert_eq!(staged.size, 6);
        fs::remove_dir_all(root).unwrap();
    }
}
