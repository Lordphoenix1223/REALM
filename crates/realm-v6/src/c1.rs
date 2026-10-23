//! C1 V0 filesystem evidence.
//!
//! This module deliberately stops at evidence production.  It does not turn
//! caller-supplied filesystem data into an authoritative V6 admission.
//! Scanning is offline: the caller must arrange that the VMM has been retired
//! and that no writer can still own the backing image before calling `scan`.

use crate::{Admission, Refusal};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::process::Command;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Component, Path},
    sync::Mutex,
};
use thiserror::Error;

const WORLD_SCHEMA: &str = "realm-c1-filesystem-world/v0";
const COMPLETION_SCHEMA: &str = "realm-c1-completion/v0";

#[derive(Debug, Error)]
pub enum C1Error {
    #[error("filesystem scan failed: {0}")]
    Io(#[from] io::Error),
    #[error("unsupported filesystem object at {0}")]
    Unsupported(String),
    #[error("invalid logical path: {0}")]
    InvalidPath(String),
    #[error("completion rejected: {0}")]
    Completion(String),
    #[error("observation rejected: {0}")]
    Observation(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsKind {
    File,
    Directory,
    Symlink,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEntry {
    pub path: String,
    pub kind: FsKind,
    pub content_blake3: Option<String>,
    pub symlink_target: Option<String>,
    /// Only permission bits relevant to execution are included.  uid/gid,
    /// timestamps, xattrs, inode identity, and sparse layout are V0-ignored.
    pub mode: u32,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemWorld {
    pub schema_version: String,
    pub entries: Vec<CanonicalEntry>,
    pub root: String,
    pub metadata_policy: MetadataPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataPolicy {
    pub mode_bits: String,
    pub uid_gid: String,
    pub timestamps: String,
    pub xattrs: String,
    pub hardlinks: String,
    pub sparse_files: String,
    pub special_files: String,
}

impl Default for MetadataPolicy {
    fn default() -> Self {
        Self {
            mode_bits: "preserve_permission_and_execute_bits".into(),
            uid_gid: "ignored".into(),
            timestamps: "ignored".into(),
            xattrs: "ignored_and_not_scanned".into(),
            hardlinks: "content_equivalence_only".into(),
            sparse_files: "logical_bytes_only".into(),
            special_files: "rejected".into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaKind {
    Create,
    Modify,
    Delete,
    Rename,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsDelta {
    pub kind: DeltaKind,
    pub path: String,
    pub other_path: Option<String>,
    pub before: Option<CanonicalEntry>,
    pub after: Option<CanonicalEntry>,
}

fn digest<T: Serialize + ?Sized>(value: &T) -> String {
    blake3::hash(&serde_json::to_vec(value).expect("canonical C1 value is serializable"))
        .to_hex()
        .to_string()
}

fn logical_path(path: &Path) -> Result<String, C1Error> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let value = part
                    .to_str()
                    .ok_or_else(|| C1Error::InvalidPath(format!("non-UTF8 path {:?}", path)))?;
                if value.contains('\0') {
                    return Err(C1Error::InvalidPath(value.into()));
                }
                parts.push(value.to_owned());
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                return Err(C1Error::InvalidPath(path.display().to_string()));
            }
            Component::ParentDir => {
                return Err(C1Error::InvalidPath(path.display().to_string()));
            }
        }
    }
    if parts.is_empty() {
        return Err(C1Error::InvalidPath(path.display().to_string()));
    }
    Ok(parts.join("/"))
}

#[cfg(unix)]
fn permission_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn permission_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

fn scan_entry(root: &Path, path: &Path, entries: &mut Vec<CanonicalEntry>) -> Result<(), C1Error> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| C1Error::InvalidPath(path.display().to_string()))?;
    let logical = logical_path(relative)?;
    let metadata = fs::symlink_metadata(path)?;
    let mode = permission_mode(&metadata);
    let entry = if metadata.file_type().is_symlink() {
        let target = fs::read_link(path)?;
        let target = target
            .to_str()
            .ok_or_else(|| C1Error::InvalidPath(path.display().to_string()))?
            .to_owned();
        CanonicalEntry {
            path: logical,
            kind: FsKind::Symlink,
            content_blake3: None,
            symlink_target: Some(target),
            mode,
            size: 0,
        }
    } else if metadata.is_file() {
        let bytes = fs::read(path)?;
        CanonicalEntry {
            path: logical,
            kind: FsKind::File,
            content_blake3: Some(blake3::hash(&bytes).to_hex().to_string()),
            symlink_target: None,
            mode,
            size: bytes.len() as u64,
        }
    } else if metadata.is_dir() {
        CanonicalEntry {
            path: logical,
            kind: FsKind::Directory,
            content_blake3: None,
            symlink_target: None,
            mode,
            size: 0,
        }
    } else {
        return Err(C1Error::Unsupported(logical));
    };
    entries.push(entry);
    if metadata.is_dir() {
        let mut children = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        children.sort_by_key(|child| child.file_name());
        for child in children {
            scan_entry(root, &child.path(), entries)?;
        }
    }
    Ok(())
}

/// Scan only after the VMM has been stopped/retired and the image is offline.
/// This function never follows symlinks and never uses a raw image-byte hash.
pub fn scan(root: &Path) -> Result<FilesystemWorld, C1Error> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() {
        return Err(C1Error::Unsupported(root.display().to_string()));
    }

    let mut entries = Vec::new();
    let mut children = fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|child| child.file_name());
    for child in children {
        scan_entry(root, &child.path(), &mut entries)?;
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let root_hash = digest(&(WORLD_SCHEMA, &entries));
    Ok(FilesystemWorld {
        schema_version: WORLD_SCHEMA.into(),
        entries,
        root: root_hash,
        metadata_policy: MetadataPolicy::default(),
    })
}

/// Inspect a finalized ext4 image only after the VMM has been retired.
///
/// `guestmount` is preferred over mounting an untrusted image with the host
/// kernel. The helper requires libguestfs and uses a read-only appliance;
/// callers must retain its version/output as inspection evidence.
#[cfg(target_os = "linux")]
pub fn scan_ext4_image(image: &Path) -> Result<FilesystemWorld, C1Error> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| C1Error::Observation(error.to_string()))?
        .as_nanos();
    let mountpoint =
        std::env::temp_dir().join(format!("realm-c1-ext4-{}-{}", std::process::id(), stamp));
    fs::create_dir(&mountpoint)?;
    let mounted = Command::new("guestmount")
        .args(["--ro", "--format=raw", "-a"])
        .arg(image)
        .args(["-m", "/dev/sda"])
        .arg(&mountpoint)
        .status()
        .map_err(C1Error::Io)?;
    if !mounted.success() {
        let _ = fs::remove_dir(&mountpoint);
        return Err(C1Error::Observation(format!(
            "read-only libguestfs inspection failed with {}",
            mounted
        )));
    }
    let result = scan(&mountpoint);
    let unmounted = Command::new("guestunmount")
        .arg(&mountpoint)
        .status()
        .map_err(C1Error::Io)?;
    let removed = fs::remove_dir(&mountpoint);
    if !unmounted.success() || removed.is_err() {
        return Err(C1Error::Observation(
            "ext4 inspection did not complete cleanly".into(),
        ));
    }
    result
}

#[cfg(not(target_os = "linux"))]
pub fn scan_ext4_image(_image: &Path) -> Result<FilesystemWorld, C1Error> {
    Err(C1Error::Observation(
        "ext4 image inspection requires a Linux host".into(),
    ))
}

fn entry_map(world: &FilesystemWorld) -> BTreeMap<String, CanonicalEntry> {
    world
        .entries
        .iter()
        .cloned()
        .map(|entry| (entry.path.clone(), entry))
        .collect()
}

/// Compute net state, not an event-log replay. A rename is emitted only when
/// exactly one deleted/created pair has identical content and metadata.
pub fn delta(start: &FilesystemWorld, final_world: &FilesystemWorld) -> Vec<FsDelta> {
    let before = entry_map(start);
    let after = entry_map(final_world);
    let mut result = Vec::new();
    let mut deleted = before
        .iter()
        .filter(|(path, _)| !after.contains_key(*path))
        .map(|(path, entry)| (path.clone(), entry.clone()))
        .collect::<Vec<_>>();
    let mut created = after
        .iter()
        .filter(|(path, _)| !before.contains_key(*path))
        .map(|(path, entry)| (path.clone(), entry.clone()))
        .collect::<Vec<_>>();
    deleted.sort_by(|left, right| left.0.cmp(&right.0));
    created.sort_by(|left, right| left.0.cmp(&right.0));
    let mut consumed_deleted = BTreeSet::new();
    let mut consumed_created = BTreeSet::new();
    for (new_path, new_entry) in &created {
        let candidates = deleted
            .iter()
            .filter(|(old_path, old_entry)| {
                !consumed_deleted.contains(old_path)
                    && old_entry.kind == new_entry.kind
                    && old_entry.content_blake3 == new_entry.content_blake3
                    && old_entry.symlink_target == new_entry.symlink_target
                    && old_entry.mode == new_entry.mode
                    && old_entry.size == new_entry.size
            })
            .collect::<Vec<_>>();
        if candidates.len() == 1 {
            let (old_path, old_entry) = candidates[0];
            consumed_deleted.insert(old_path.clone());
            consumed_created.insert(new_path.clone());
            result.push(FsDelta {
                kind: DeltaKind::Rename,
                path: old_path.clone(),
                other_path: Some(new_path.clone()),
                before: Some(old_entry.clone()),
                after: Some(new_entry.clone()),
            });
        }
    }
    for (path, entry) in deleted {
        if !consumed_deleted.contains(&path) {
            result.push(FsDelta {
                kind: DeltaKind::Delete,
                path,
                other_path: None,
                before: Some(entry),
                after: None,
            });
        }
    }
    for (path, entry) in created {
        if !consumed_created.contains(&path) {
            result.push(FsDelta {
                kind: DeltaKind::Create,
                path,
                other_path: None,
                before: None,
                after: Some(entry),
            });
        }
    }
    for path in before.keys().filter(|path| after.contains_key(*path)) {
        if before[path] != after[path] {
            result.push(FsDelta {
                kind: DeltaKind::Modify,
                path: path.clone(),
                other_path: None,
                before: Some(before[path].clone()),
                after: Some(after[path].clone()),
            });
        }
    }
    result.sort_by(|left, right| left.path.cmp(&right.path));
    result
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalizationState {
    SupervisorAccounted,
    WorkspaceSynced,
    WorkspaceUnmounted,
    ImageImmutable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionRecord {
    pub schema_version: String,
    pub run_id: String,
    pub execution_id: String,
    pub capsule_id: String,
    pub challenge: String,
    pub supervisor_id: String,
    pub finalization: FinalizationState,
    pub sequence: u64,
    pub mac: String,
}

#[derive(Debug)]
pub struct CompletionAuthenticator {
    secret: [u8; 32],
    run_id: String,
    execution_id: String,
    capsule_id: String,
    challenge: String,
    supervisor_id: String,
    accepted: Mutex<bool>,
    supervisor_failed: Mutex<bool>,
}

impl CompletionAuthenticator {
    /// The secret is retained by the trusted supervisor only; this API exposes
    /// no secret-bearing value to the task process.
    pub fn new(
        secret: [u8; 32],
        run_id: impl Into<String>,
        execution_id: impl Into<String>,
        capsule_id: impl Into<String>,
        challenge: impl Into<String>,
        supervisor_id: impl Into<String>,
    ) -> Self {
        Self {
            secret,
            run_id: run_id.into(),
            execution_id: execution_id.into(),
            capsule_id: capsule_id.into(),
            challenge: challenge.into(),
            supervisor_id: supervisor_id.into(),
            accepted: Mutex::new(false),
            supervisor_failed: Mutex::new(false),
        }
    }

    fn mac_for(&self, record: &CompletionRecord) -> String {
        let mut unsigned = record.clone();
        unsigned.mac.clear();
        blake3::keyed_hash(
            &self.secret,
            &serde_json::to_vec(&unsigned).expect("completion is serializable"),
        )
        .to_hex()
        .to_string()
    }

    pub fn issue(&self, finalization: FinalizationState) -> CompletionRecord {
        let mut record = CompletionRecord {
            schema_version: COMPLETION_SCHEMA.into(),
            run_id: self.run_id.clone(),
            execution_id: self.execution_id.clone(),
            capsule_id: self.capsule_id.clone(),
            challenge: self.challenge.clone(),
            supervisor_id: self.supervisor_id.clone(),
            finalization,
            sequence: 0,
            mac: String::new(),
        };
        record.mac = self.mac_for(&record);
        record
    }

    pub fn verify_and_accept(&self, record: &CompletionRecord) -> Result<(), C1Error> {
        if *self
            .supervisor_failed
            .lock()
            .map_err(|_| C1Error::Completion("lock poisoned".into()))?
        {
            return Err(C1Error::Completion("supervisor failed".into()));
        }
        let mut accepted = self
            .accepted
            .lock()
            .map_err(|_| C1Error::Completion("lock poisoned".into()))?;
        if *accepted {
            return Err(C1Error::Completion("duplicate completion".into()));
        }
        if record.schema_version != COMPLETION_SCHEMA
            || record.run_id != self.run_id
            || record.execution_id != self.execution_id
            || record.capsule_id != self.capsule_id
            || record.challenge != self.challenge
            || record.supervisor_id != self.supervisor_id
            || record.sequence != 0
            || record.finalization != FinalizationState::ImageImmutable
            || record.mac != self.mac_for(record)
        {
            return Err(C1Error::Completion(
                "binding or authentication mismatch".into(),
            ));
        }
        *accepted = true;
        Ok(())
    }

    pub fn mark_supervisor_failed(&self) -> Result<(), C1Error> {
        *self
            .supervisor_failed
            .lock()
            .map_err(|_| C1Error::Completion("lock poisoned".into()))? = true;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub id: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleObservation {
    pub schema_version: String,
    pub run_id: String,
    pub execution_id: String,
    pub capsule_id: String,
    pub runtime_configuration_root: String,
    pub supervisor_id: String,
    pub starting_world_root: String,
    pub final_world_root: String,
    pub delta_root: String,
    pub challenge: String,
    pub completion: EvidenceRef,
    pub finalization: EvidenceRef,
    pub pause_snapshot: EvidenceRef,
    pub network_device_configuration: EvidenceRef,
    pub evidence_sequence_root: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct C1Policy {
    pub expected_paths: BTreeSet<String>,
    pub forbidden_paths: BTreeSet<String>,
    pub allow_symlinks: bool,
    pub allow_permission_changes: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct C1Claim {
    pub observation: CapsuleObservation,
    pub delta: Vec<FsDelta>,
    pub policy: C1Policy,
}

fn delta_digest(delta: &[FsDelta]) -> String {
    digest(delta)
}

fn symlink_escapes(path: &str, target: &str) -> bool {
    let target = Path::new(target);
    if target.is_absolute() {
        return true;
    }
    let mut depth = path.split('/').count().saturating_sub(1) as isize;
    for component in target.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            Component::RootDir | Component::Prefix(_) => return true,
        }
    }
    false
}

/// Issue a filesystem-only C1 claim after checking every evidence binding and
/// policy relation. This is not an authoritative ACCEPT capability.
pub fn issue_c1_claim(
    observation: CapsuleObservation,
    start: &FilesystemWorld,
    final_world: &FilesystemWorld,
    policy: C1Policy,
) -> Result<C1Claim, C1Error> {
    if observation.starting_world_root != start.root
        || observation.final_world_root != final_world.root
        || observation.delta_root != delta_digest(&delta(start, final_world))
        || observation.run_id.is_empty()
        || observation.execution_id.is_empty()
        || observation.capsule_id.is_empty()
        || observation.supervisor_id.is_empty()
        || observation.challenge.is_empty()
        || [
            &observation.completion,
            &observation.finalization,
            &observation.pause_snapshot,
            &observation.network_device_configuration,
        ]
        .iter()
        .any(|reference| reference.id.is_empty() || reference.digest.is_empty())
    {
        return Err(C1Error::Observation("evidence binding mismatch".into()));
    }
    let actual = delta(start, final_world);
    for effect in &actual {
        if policy.forbidden_paths.contains(&effect.path)
            || effect
                .other_path
                .as_ref()
                .is_some_and(|path| policy.forbidden_paths.contains(path))
            || matches!(effect.kind, DeltaKind::Create | DeltaKind::Modify)
                && !policy.expected_paths.contains(&effect.path)
            || !policy.allow_symlinks
                && effect
                    .after
                    .as_ref()
                    .is_some_and(|entry| entry.kind == FsKind::Symlink)
            || effect
                .after
                .as_ref()
                .and_then(|entry| entry.symlink_target.as_deref())
                .is_some_and(|target| symlink_escapes(&effect.path, target))
            || !policy.allow_permission_changes
                && effect.before.as_ref().map(|entry| entry.mode)
                    != effect.after.as_ref().map(|entry| entry.mode)
        {
            return Err(C1Error::Observation(format!(
                "filesystem effect outside C1 policy at {}",
                effect.path
            )));
        }
    }
    Ok(C1Claim {
        observation,
        delta: actual,
        policy,
    })
}

/// The current branch has no authenticated measured VMM boundary. Keep this
/// explicit rather than upgrading a filesystem claim into public admission.
pub fn admission_with_c1(_claim: &C1Claim) -> Admission {
    Admission::Refuse(Refusal::UnverifiedBoundary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink, path::PathBuf};

    fn temp_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("realm-c1-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        root
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires Linux mke2fs and read-only libguestfs appliance"]
    fn raw_ext4_workspace_is_scanned_without_a_partition_table() {
        let root = temp_root("raw-ext4");
        let seed = root.join("seed");
        fs::create_dir(&seed).unwrap();
        fs::write(seed.join("input.txt"), b"approved-input").unwrap();
        let image = root.join("workspace.ext4");
        let file = fs::File::create(&image).unwrap();
        file.set_len(16 * 1024 * 1024).unwrap();
        drop(file);
        assert!(
            Command::new("mke2fs")
                .args(["-q", "-t", "ext4", "-F", "-d"])
                .arg(&seed)
                .arg(&image)
                .status()
                .unwrap()
                .success()
        );
        let world = scan_ext4_image(&image).unwrap();
        let entry = world
            .entries
            .iter()
            .find(|entry| entry.path == "input.txt")
            .unwrap();
        assert_eq!(entry.kind, FsKind::File);
        assert_eq!(entry.size, 14);
        assert_eq!(
            entry.content_blake3.as_deref(),
            Some(blake3::hash(b"approved-input").to_hex().as_str())
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn observation(start: &FilesystemWorld, final_world: &FilesystemWorld) -> CapsuleObservation {
        let delta = delta(start, final_world);
        let reference = |id: &str| EvidenceRef {
            id: id.into(),
            digest: "evidence".into(),
        };
        CapsuleObservation {
            schema_version: "realm-c1-observation/v0".into(),
            run_id: "run".into(),
            execution_id: "execution".into(),
            capsule_id: "capsule".into(),
            runtime_configuration_root: "runtime".into(),
            supervisor_id: "supervisor".into(),
            starting_world_root: start.root.clone(),
            final_world_root: final_world.root.clone(),
            delta_root: delta_digest(&delta),
            challenge: "fresh".into(),
            completion: reference("completion"),
            finalization: reference("finalization"),
            pause_snapshot: reference("pause"),
            network_device_configuration: reference("network"),
            evidence_sequence_root: "sequence".into(),
        }
    }

    #[test]
    fn identical_logical_trees_have_identical_root() {
        let left = temp_root("same-left");
        let right = temp_root("same-right");
        fs::write(left.join("a"), b"same").unwrap();
        fs::write(right.join("a"), b"same").unwrap();
        assert_eq!(scan(&left).unwrap().root, scan(&right).unwrap().root);
        fs::remove_dir_all(left).unwrap();
        fs::remove_dir_all(right).unwrap();
    }

    #[test]
    fn content_mode_symlink_and_hidden_file_change_roots_and_delta() {
        let root = temp_root("mutations");
        fs::write(root.join("a"), b"one").unwrap();
        let start = scan(&root).unwrap();
        fs::write(root.join("a"), b"two").unwrap();
        fs::create_dir(root.join("d")).unwrap();
        symlink("a", root.join("link")).unwrap();
        fs::write(root.join("hidden"), b"secret").unwrap();
        let final_world = scan(&root).unwrap();
        assert_ne!(start.root, final_world.root);
        assert!(
            delta(&start, &final_world)
                .iter()
                .any(|effect| effect.path == "hidden")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(root.join("a")).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(root.join("a"), permissions).unwrap();
            assert_ne!(final_world.root, scan(&root).unwrap().root);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn temp_rename_is_a_single_unambiguous_rename() {
        let root = temp_root("rename");
        fs::write(root.join("old"), b"same").unwrap();
        let start = scan(&root).unwrap();
        fs::rename(root.join("old"), root.join("new")).unwrap();
        let final_world = scan(&root).unwrap();
        let changes = delta(&start, &final_world);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, DeltaKind::Rename);
        assert_eq!(changes[0].other_path.as_deref(), Some("new"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hidden_mutation_is_rejected_by_policy() {
        let root = temp_root("policy");
        fs::write(root.join("a"), b"one").unwrap();
        let start = scan(&root).unwrap();
        fs::write(root.join("a"), b"two").unwrap();
        fs::write(root.join("hidden"), b"no").unwrap();
        let final_world = scan(&root).unwrap();
        let policy = C1Policy {
            expected_paths: ["a".into()].into_iter().collect(),
            forbidden_paths: BTreeSet::new(),
            allow_symlinks: false,
            allow_permission_changes: false,
        };
        assert!(
            issue_c1_claim(
                observation(&start, &final_world),
                &start,
                &final_world,
                policy
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn valid_local_filesystem_claim_is_issued_but_not_admitted() {
        let root = temp_root("valid-claim");
        fs::write(root.join("a"), b"one").unwrap();
        let start = scan(&root).unwrap();
        fs::write(root.join("a"), b"two").unwrap();
        let final_world = scan(&root).unwrap();
        let policy = C1Policy {
            expected_paths: ["a".into()].into_iter().collect(),
            forbidden_paths: BTreeSet::new(),
            allow_symlinks: false,
            allow_permission_changes: false,
        };
        let claim = issue_c1_claim(
            observation(&start, &final_world),
            &start,
            &final_world,
            policy,
        )
        .unwrap();
        assert_eq!(
            admission_with_c1(&claim),
            Admission::Refuse(Refusal::UnverifiedBoundary)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn escaping_symlink_is_rejected_even_when_symlinks_are_allowed() {
        let root = temp_root("symlink-policy");
        fs::write(root.join("a"), b"one").unwrap();
        let start = scan(&root).unwrap();
        symlink("../../outside", root.join("link")).unwrap();
        let final_world = scan(&root).unwrap();
        let policy = C1Policy {
            expected_paths: ["link".into()].into_iter().collect(),
            forbidden_paths: BTreeSet::new(),
            allow_symlinks: true,
            allow_permission_changes: false,
        };
        assert!(
            issue_c1_claim(
                observation(&start, &final_world),
                &start,
                &final_world,
                policy
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn completion_rejects_forgery_stale_and_duplicate() {
        let auth = CompletionAuthenticator::new(
            [7; 32],
            "run",
            "execution",
            "capsule",
            "challenge",
            "supervisor",
        );
        let mut forged = auth.issue(FinalizationState::ImageImmutable);
        forged.mac = "forged".into();
        assert!(auth.verify_and_accept(&forged).is_err());
        let mut stale = auth.issue(FinalizationState::ImageImmutable);
        stale.challenge = "old".into();
        assert!(auth.verify_and_accept(&stale).is_err());
        let mut wrong_capsule = auth.issue(FinalizationState::ImageImmutable);
        wrong_capsule.capsule_id = "other".into();
        assert!(auth.verify_and_accept(&wrong_capsule).is_err());
        let valid = auth.issue(FinalizationState::ImageImmutable);
        auth.verify_and_accept(&valid).unwrap();
        assert!(auth.verify_and_accept(&valid).is_err());
    }

    #[test]
    fn completion_after_supervisor_failure_is_rejected() {
        let auth = CompletionAuthenticator::new(
            [9; 32],
            "run",
            "execution",
            "capsule",
            "challenge",
            "supervisor",
        );
        auth.mark_supervisor_failed().unwrap();
        assert!(
            auth.verify_and_accept(&auth.issue(FinalizationState::ImageImmutable))
                .is_err()
        );
    }

    #[test]
    fn post_finalization_mutation_changes_identity() {
        let root = temp_root("post-finalization");
        fs::write(root.join("a"), b"one").unwrap();
        let finalized = scan(&root).unwrap();
        fs::write(root.join("a"), b"mutated").unwrap();
        assert_ne!(finalized.root, scan(&root).unwrap().root);
        fs::remove_dir_all(root).unwrap();
    }
}
