//! Legacy C1 publisher API, quarantined pending terminal authority.
//!
//! No current public path mutates a destination. Caller data and filesystem
//! roots cannot substitute for the private terminal capability.

use crate::filesystem_world::{
    FilesystemChange, FilesystemObject, FilesystemScanError, FilesystemWorld, delta, scan_directory,
};
use crate::profile::SyncTrace as _;
use crate::{Admission, execute::ExecuteResult};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationRequest {
    pub execution_id: String,
    pub accepted_final_root: String,
    pub accepted_delta_root: String,
    pub before: FilesystemWorld,
    pub after: FilesystemWorld,
    pub source_root: PathBuf,
    pub destination_root: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    pub schema_version: u16,
    pub publication_id: String,
    pub execution_id: String,
    pub verifier_decision: Admission,
    pub publication_sequence: u64,
    pub destination_identity: String,
    pub accepted_final_root: String,
    pub accepted_delta_root: String,
    pub destination_root: String,
    pub pre_publication_root: String,
    pub post_publication_root: String,
    pub published_changes: Vec<FilesystemChange>,
}

/// Publish only the measured workspace produced by the same authoritative
/// execution result. The images are rescanned independently; serialized roots
/// and paths cannot manufacture an accepted publication.
/// Legacy caller-result publication is disabled. A serialized decision is
/// ordinary data and cannot substitute for the private terminal capability.
pub fn publish_accepted(
    _execution: &ExecuteResult,
    _destination_root: &Path,
) -> Result<PublicationReceipt, PublicationError> {
    Err(PublicationError::Quarantined)
}

#[derive(Debug)]
pub enum PublicationError {
    Quarantined,
    Invalid(String),
    Io(io::Error),
    Scan(FilesystemScanError),
    DestinationChanged,
    SourceChanged,
    Unsupported(String),
}

impl std::fmt::Display for PublicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quarantined => write!(
                f,
                "legacy publication is quarantined until the private terminal-authority join exists"
            ),
            Self::Invalid(reason) | Self::Unsupported(reason) => write!(f, "{reason}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::Scan(error) => write!(f, "filesystem scan failed: {error:?}"),
            Self::DestinationChanged => write!(f, "destination changed after acceptance"),
            Self::SourceChanged => write!(f, "accepted source world is no longer present"),
        }
    }
}

impl std::error::Error for PublicationError {}

impl From<io::Error> for PublicationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<FilesystemScanError> for PublicationError {
    fn from(error: FilesystemScanError) -> Self {
        Self::Scan(error)
    }
}

/// Public root comparison is not publication authority. This entry point is
/// retained for wire/API compatibility and always refuses.
pub fn publish(_request: &PublicationRequest) -> Result<PublicationReceipt, PublicationError> {
    Err(PublicationError::Quarantined)
}

#[allow(dead_code)]
fn publish_legacy(request: &PublicationRequest) -> Result<PublicationReceipt, PublicationError> {
    if request.execution_id.is_empty()
        || request.accepted_final_root.is_empty()
        || request.accepted_delta_root.is_empty()
    {
        return Err(PublicationError::Invalid(
            "publication identity and accepted roots are required".into(),
        ));
    }
    let source = request
        .source_root
        .canonicalize()
        .map_err(PublicationError::Io)?;
    let destination = request
        .destination_root
        .canonicalize()
        .map_err(PublicationError::Io)?;
    if !source.is_dir() || !destination.is_dir() {
        return Err(PublicationError::Invalid(
            "publication roots must be directories".into(),
        ));
    }
    if request.accepted_final_root != request.after.root {
        return Err(PublicationError::Invalid(
            "accepted final root does not match the accepted world".into(),
        ));
    }
    let changes = delta(&request.before, &request.after);
    let delta_root = digest(&changes)?;
    if request.accepted_delta_root != delta_root {
        return Err(PublicationError::Invalid(
            "accepted delta root does not match the accepted delta".into(),
        ));
    }
    if scan_directory(&source)?.root != request.accepted_final_root {
        return Err(PublicationError::SourceChanged);
    }
    if scan_directory(&destination)?.root != request.before.root {
        return Err(PublicationError::DestinationChanged);
    }

    for change in &changes {
        validate_change(&destination, change)?;
    }
    crash_injection("BEFORE_FIRST_REPLACEMENT");
    for change in &changes {
        apply_change(&source, &destination, change)?;
        crash_injection("AFTER_PATH_MUTATION");
    }

    crash_injection("BEFORE_POST_SCAN");
    let post = scan_directory(&destination)?;
    crash_injection("AFTER_POST_SCAN");
    if post.root != request.after.root {
        return Err(PublicationError::DestinationChanged);
    }
    Ok(PublicationReceipt {
        schema_version: 1,
        publication_id: publication_id(&request.execution_id),
        execution_id: request.execution_id.clone(),
        // This legacy helper is not an authority source and is unreachable
        // from public entry points. It must never emit an ACCEPT decision.
        verifier_decision: Admission::Refuse(crate::Refusal::UnverifiedBoundary),
        publication_sequence: 1,
        destination_identity: digest(&destination.display().to_string())?,
        accepted_final_root: request.accepted_final_root.clone(),
        accepted_delta_root: request.accepted_delta_root.clone(),
        destination_root: destination.display().to_string(),
        pre_publication_root: request.before.root.clone(),
        post_publication_root: post.root,
        published_changes: changes,
    })
}

#[cfg(target_os = "linux")]
#[allow(dead_code)] // legacy helper; generation publication owns the production path
pub(crate) fn mount_image(image: &Path, mountpoint: &Path) -> Result<(), PublicationError> {
    if !image.is_file() || image.is_symlink() {
        return Err(PublicationError::Invalid(
            "publication image must be a regular non-symlink file".into(),
        ));
    }
    let mounted = std::process::Command::new("guestmount")
        .args(["--ro", "--format=raw", "-a"])
        .arg(image)
        .args(["-m", "/dev/sda"])
        .arg(mountpoint)
        .status()?
        .success();
    if !mounted {
        return Err(PublicationError::Unsupported(
            "guestmount could not mount accepted workspace image".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(dead_code)] // legacy helper; generation publication owns the production path
pub(crate) fn unmount_image(mountpoint: &Path) -> Result<(), io::Error> {
    let status = std::process::Command::new("guestunmount")
        .arg(mountpoint)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("guestunmount failed"))
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub(crate) fn mount_image(_image: &Path, _mountpoint: &Path) -> Result<(), PublicationError> {
    Err(PublicationError::Unsupported(
        "workspace image publication requires Linux".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub(crate) fn unmount_image(_mountpoint: &Path) -> Result<(), io::Error> {
    Err(io::Error::other(
        "workspace image publication requires Linux",
    ))
}

fn validate_change(destination: &Path, change: &FilesystemChange) -> Result<(), PublicationError> {
    let (path, expected_before) = match change {
        FilesystemChange::Create { path, .. } => (path, None),
        FilesystemChange::Modify { path, before, .. } => (path, Some(before)),
        FilesystemChange::Delete { path, object } => (path, Some(object)),
    };
    let relative = safe_relative(path)?;
    let target = confined(destination, &relative)?;
    match expected_before {
        None if fs::symlink_metadata(&target).is_ok() => Err(PublicationError::DestinationChanged),
        None => Ok(()),
        Some(expected) if read_object(destination, &relative)? == *expected => Ok(()),
        Some(_) => Err(PublicationError::DestinationChanged),
    }
}

fn apply_change(
    source: &Path,
    destination: &Path,
    change: &FilesystemChange,
) -> Result<(), PublicationError> {
    let (path, expected_before, expected_after) = match change {
        FilesystemChange::Create { path, object } => (path, None, Some(object)),
        FilesystemChange::Modify {
            path,
            before,
            after,
        } => (path, Some(before), Some(after)),
        FilesystemChange::Delete { path, object } => (path, Some(object), None),
    };
    let relative = safe_relative(path)?;
    let target = confined(destination, &relative)?;
    if let Some(expected) = expected_before {
        if read_object(destination, &relative)? != *expected {
            return Err(PublicationError::DestinationChanged);
        }
    } else if fs::symlink_metadata(&target).is_ok() {
        return Err(PublicationError::DestinationChanged);
    }

    match expected_after {
        None => {
            remove_existing(&target)?;
            sync_parent(&target)?;
            Ok(())
        }
        Some(FilesystemObject::File { mode, .. }) => {
            let source_path = confined(source, &relative)?;
            let metadata = fs::symlink_metadata(&source_path)?;
            if !metadata.is_file() {
                return Err(PublicationError::SourceChanged);
            }
            let temp = temporary_sibling(&target);
            fs::copy(source_path, &temp)?;
            set_mode(&temp, *mode)?;
            fs::File::open(&temp)?.sync_all_traced()?;
            crash_injection("BEFORE_ATOMIC_REPLACEMENT");
            fs::rename(temp, &target)?;
            sync_parent(&target)?;
            crash_injection("AFTER_ATOMIC_REPLACEMENT");
            Ok(())
        }
        Some(FilesystemObject::Directory { mode }) => {
            if let Some(parent) = target.parent() {
                ensure_directory_chain(destination, parent)?;
            }
            if fs::symlink_metadata(&target).is_err() {
                fs::create_dir(&target)?;
            }
            set_mode(&target, *mode)?;
            sync_parent(&target)?;
            Ok(())
        }
        Some(FilesystemObject::Symlink { target: link, mode }) => {
            validate_symlink_target(link)?;
            if let Some(parent) = target.parent() {
                ensure_directory_chain(destination, parent)?;
            }
            let temp = temporary_sibling(&target);
            #[cfg(unix)]
            std::os::unix::fs::symlink(link, &temp)?;
            #[cfg(not(unix))]
            return Err(PublicationError::Unsupported(
                "symlink publication is unavailable".into(),
            ));
            set_mode(&temp, *mode)?;
            fs::File::open(&temp)?.sync_all_traced()?;
            crash_injection("BEFORE_ATOMIC_REPLACEMENT");
            fs::rename(temp, &target)?;
            sync_parent(&target)?;
            crash_injection("AFTER_ATOMIC_REPLACEMENT");
            Ok(())
        }
    }
}

fn sync_parent(path: &Path) -> Result<(), PublicationError> {
    let parent = path
        .parent()
        .ok_or_else(|| PublicationError::Invalid("publication path has no parent".into()))?;
    fs::File::open(parent)?.sync_all_traced()?;
    Ok(())
}

fn crash_injection(point: &str) {
    if std::env::var("REALM_PUBLICATION_CRASH_AT").ok().as_deref() == Some(point) {
        std::process::abort();
    }
}

fn read_object(root: &Path, relative: &Path) -> Result<FilesystemObject, PublicationError> {
    let world = scan_directory(root)?;
    let key = relative
        .to_str()
        .ok_or_else(|| PublicationError::Invalid("non-UTF8 publication path".into()))?
        .replace('\\', "/");
    world
        .entries
        .get(&key)
        .cloned()
        .ok_or(PublicationError::DestinationChanged)
}

fn remove_existing(path: &Path) -> Result<(), PublicationError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        if fs::read_dir(path)?.next().is_some() {
            return Err(PublicationError::Unsupported(
                "non-empty directory deletion is unsupported".into(),
            ));
        }
        fs::remove_dir(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn confined(root: &Path, relative: &Path) -> Result<PathBuf, PublicationError> {
    ensure_directory_chain(root, root)?;
    let path = root.join(relative);
    if path.parent().is_none() {
        return Err(PublicationError::Invalid("invalid publication path".into()));
    }
    Ok(path)
}

fn ensure_directory_chain(root: &Path, path: &Path) -> Result<(), PublicationError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| PublicationError::Invalid("path escaped root".into()))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(PublicationError::Invalid("path escaped root".into()));
        };
        current.push(name);
        if let Ok(metadata) = fs::symlink_metadata(&current) {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(PublicationError::DestinationChanged);
            }
        } else if current != path {
            fs::create_dir(&current)?;
        }
    }
    Ok(())
}

fn safe_relative(path: &str) -> Result<PathBuf, PublicationError> {
    let mut output = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(value) => output.push(value),
            _ => {
                return Err(PublicationError::Invalid(
                    "publication path escaped root".into(),
                ));
            }
        }
    }
    if output.as_os_str().is_empty() {
        return Err(PublicationError::Invalid("empty publication path".into()));
    }
    Ok(output)
}

fn validate_symlink_target(target: &str) -> Result<(), PublicationError> {
    if Path::new(target).is_absolute()
        || Path::new(target)
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(PublicationError::Unsupported(
            "escaping symlink publication is unsupported".into(),
        ));
    }
    Ok(())
}

fn temporary_sibling(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        ".realm-publish-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

fn set_mode(path: &Path, mode: u32) -> Result<(), PublicationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

fn digest<T: Serialize>(value: &T) -> Result<String, PublicationError> {
    Ok(blake3::hash(
        &serde_json::to_vec(value)
            .map_err(|_| PublicationError::Invalid("cannot encode publication delta".into()))?,
    )
    .to_hex()
    .to_string())
}

fn publication_id(execution_id: &str) -> String {
    blake3::hash(
        format!(
            "{execution_id}:{}:{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
        .as_bytes(),
    )
    .to_hex()
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn roots(name: &str) -> (PathBuf, PathBuf) {
        let base =
            std::env::temp_dir().join(format!("realm-publication-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let source = base.join("source");
        let destination = base.join("destination");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&destination).unwrap();
        (source, destination)
    }

    fn request(
        source: &Path,
        destination: &Path,
        before: FilesystemWorld,
        after: FilesystemWorld,
    ) -> PublicationRequest {
        let changes = delta(&before, &after);
        PublicationRequest {
            execution_id: "execution-1".into(),
            accepted_final_root: after.root.clone(),
            accepted_delta_root: digest(&changes).unwrap(),
            before,
            after,
            source_root: source.into(),
            destination_root: destination.into(),
        }
    }

    #[test]
    fn caller_supplied_matching_roots_cannot_publish() {
        let (source, destination) = roots("delta");
        fs::write(destination.join("keep"), b"unchanged").unwrap();
        fs::write(source.join("keep"), b"unchanged").unwrap();
        fs::write(source.join("new"), b"published").unwrap();
        let before = scan_directory(&destination).unwrap();
        let after = scan_directory(&source).unwrap();
        let error = publish(&request(
            &source,
            &destination,
            before.clone(),
            after.clone(),
        ))
        .unwrap_err();
        assert!(matches!(error, PublicationError::Quarantined));
        assert!(!destination.join("new").exists());
        assert_eq!(fs::read(destination.join("keep")).unwrap(), b"unchanged");
        assert_eq!(scan_directory(&destination).unwrap().root, before.root);
        assert_ne!(scan_directory(&destination).unwrap().root, after.root);
    }

    #[test]
    fn changed_destination_refuses_before_writing() {
        let (source, destination) = roots("stale");
        fs::write(destination.join("old"), b"one").unwrap();
        fs::write(source.join("old"), b"two").unwrap();
        let before = scan_directory(&destination).unwrap();
        let after = scan_directory(&source).unwrap();
        fs::write(destination.join("old"), b"attacker").unwrap();
        let error = publish(&request(&source, &destination, before, after)).unwrap_err();
        assert!(matches!(error, PublicationError::Quarantined));
        assert_eq!(fs::read(destination.join("old")).unwrap(), b"attacker");
    }

    #[cfg(unix)]
    #[test]
    fn escaping_symlink_is_not_published() {
        let (source, destination) = roots("symlink");
        std::os::unix::fs::symlink("../outside", source.join("escape")).unwrap();
        let before = scan_directory(&destination).unwrap();
        let after = scan_directory(&source).unwrap();
        let error = publish(&request(&source, &destination, before, after)).unwrap_err();
        assert!(matches!(error, PublicationError::Quarantined));
    }

    #[test]
    fn result_claim_cannot_open_the_legacy_publisher() {
        let (_source, destination) = roots("result-gate");
        let result = ExecuteResult {
            schema_version: 1,
            run_id: "run".into(),
            execution_id: "execution".into(),
            guest_exit_code: None,
            guest_crashed: None,
            vmm_pid: None,
            vmm_start_time_ticks: None,
            starting_world_commitment: "start".into(),
            final_world_commitment: Some("final".into()),
            delta_root: Some("delta".into()),
            starting_workspace_image: None,
            final_workspace_image: None,
            observed_effects: vec![],
            proposed_effects: vec![],
            evidence_root: None,
            receipt_path: None,
            verifier_decision: Admission::Refuse(crate::Refusal::UnverifiedBoundary),
            reason_code: "UNVERIFIED".into(),
            task_success: true,
            unsupported_effects: vec![],
            runtime_ms: 1,
            overhead_ms: 1,
        };
        for decision in ["ACCEPT", "REUSE", "RECOMPUTE"] {
            let mut json = serde_json::to_value(&result).unwrap();
            json["verifier_decision"] = serde_json::json!({"decision": decision});
            assert!(serde_json::from_value::<ExecuteResult>(json).is_err());
        }
        let error = publish_accepted(&result, &destination).unwrap_err();
        assert!(matches!(error, PublicationError::Quarantined));
    }
}
