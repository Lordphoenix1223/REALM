//! Disposable Recovery Workspace abstraction and Level-1 exact inverse helpers.

use realm_cas::{CasError, PreimageStore};
use realm_contract::{ExactRestore, ExactRestoreAction, RecoveryContract};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const WORKSPACE_MARKER: &[u8] = b"REALM-RECOVERY-WORKSPACE-v1\n";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceManifest {
    pub root: PathBuf,
    pub base_root: PathBuf,
    pub isolated: bool,
    pub file_count: u64,
}

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("recovery workspace I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("CAS error: {0}")]
    Cas(#[from] CasError),
    #[error("unsafe recovery path: {0}")]
    UnsafePath(String),
    #[error("the requested workspace is not marked as a Realm recovery workspace")]
    MissingMarker,
    #[error("recovery operation is unsupported for this object or fidelity")]
    Unsupported,
}

pub trait RecoveryWorkspace {
    fn materialize(&self, base: &Path) -> Result<WorkspaceManifest, RecoveryError>;
    fn root(&self) -> &Path;
    fn apply_exact_restore(
        &self,
        restore: &ExactRestore,
        store: &PreimageStore,
    ) -> Result<(), RecoveryError>;
}

#[derive(Clone, Debug)]
pub struct DisposableRecoveryWorkspace {
    root: PathBuf,
}

impl DisposableRecoveryWorkspace {
    pub fn create(root: impl AsRef<Path>) -> Result<Self, RecoveryError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let marker = root.join(".realm-recovery-marker");
        if marker.exists() {
            if fs::read(&marker)? != WORKSPACE_MARKER {
                return Err(RecoveryError::MissingMarker);
            }
        } else {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&marker)?;
            use std::io::Write;
            file.write_all(WORKSPACE_MARKER)?;
            file.sync_all()?;
        }
        Ok(Self { root })
    }

    pub fn unique() -> Result<Self, RecoveryError> {
        let root = std::env::temp_dir().join(format!(
            "realm-recovery-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        Self::create(root)
    }

    pub fn cleanup(self) -> Result<(), RecoveryError> {
        if self.root.join(".realm-recovery-marker").exists() {
            fs::remove_dir_all(self.root)?;
        }
        Ok(())
    }
}

impl RecoveryWorkspace for DisposableRecoveryWorkspace {
    fn materialize(&self, base: &Path) -> Result<WorkspaceManifest, RecoveryError> {
        ensure_marker(&self.root)?;
        if self.root == base {
            return Err(RecoveryError::UnsafePath(
                "recovery root must differ from live/base root".into(),
            ));
        }
        let mut file_count = 0;
        copy_tree(base, &self.root, &mut file_count)?;
        Ok(WorkspaceManifest {
            root: self.root.clone(),
            base_root: base.to_path_buf(),
            isolated: true,
            file_count,
        })
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn apply_exact_restore(
        &self,
        restore: &ExactRestore,
        store: &PreimageStore,
    ) -> Result<(), RecoveryError> {
        ensure_marker(&self.root)?;
        match &restore.action {
            ExactRestoreAction::RemoveCreatedPath => {
                let relative = safe_relative_path(&restore.target_path.as_path())?;
                let destination = self.root.join(relative);
                if let Ok(metadata) = fs::symlink_metadata(&destination) {
                    if metadata.file_type().is_dir() {
                        fs::remove_dir(&destination)?;
                    } else {
                        fs::remove_file(&destination)?;
                    }
                }
                return Ok(());
            }
            ExactRestoreAction::RenameBack { from, to } => {
                let source = self.root.join(safe_relative_path(&from.as_path())?);
                let destination = self.root.join(safe_relative_path(&to.as_path())?);
                if fs::symlink_metadata(&destination).is_ok() {
                    return Err(RecoveryError::Unsupported);
                }
                fs::rename(source, destination)?;
                return Ok(());
            }
            ExactRestoreAction::RestoreBytes => {}
        }
        let blob = restore
            .source_blob
            .as_ref()
            .ok_or(RecoveryError::Unsupported)?;
        let reference = realm_cas::BlobRef {
            hash: blob.clone(),
            size: 0,
            method: realm_core::PreservationMethod::ExactCopy,
        };
        let bytes = match store.get_bytes(&reference) {
            Ok(bytes) => bytes,
            Err(CasError::Corrupt) => {
                // The contract may omit size; recover it from the CAS envelope.
                let path = store.blob_path(blob);
                let stored = fs::read(path)?;
                let header = b"REALM-CAS-1\n";
                let payload = stored
                    .strip_prefix(header)
                    .ok_or(RecoveryError::Unsupported)?;
                if blake3::hash(payload).to_hex().to_string() != *blob {
                    return Err(RecoveryError::Cas(CasError::Corrupt));
                }
                payload.to_vec()
            }
            Err(other) => return Err(RecoveryError::Cas(other)),
        };
        let relative = safe_relative_path(&restore.target_path.as_path())?;
        let destination = self.root.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp = destination.with_extension(format!("realm-restore-{}", std::process::id()));
        fs::write(&temp, &bytes)?;
        File::open(&temp)?.sync_all()?;
        fs::rename(temp, destination)?;
        Ok(())
    }
}

pub fn materialize_contract<W: RecoveryWorkspace>(
    workspace: &W,
    base: &Path,
    contract: &RecoveryContract,
    store: &PreimageStore,
) -> Result<WorkspaceManifest, RecoveryError> {
    let manifest = workspace.materialize(base)?;
    for restore in &contract.exact_restores {
        workspace.apply_exact_restore(restore, store)?;
    }
    Ok(manifest)
}

fn ensure_marker(root: &Path) -> Result<(), RecoveryError> {
    let marker = root.join(".realm-recovery-marker");
    if !marker.exists() || fs::read(marker)? != WORKSPACE_MARKER {
        return Err(RecoveryError::MissingMarker);
    }
    Ok(())
}

fn safe_relative_path(path: &Path) -> Result<PathBuf, RecoveryError> {
    if path.is_absolute() {
        return Err(RecoveryError::UnsafePath(path.display().to_string()));
    }
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => output.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(RecoveryError::UnsafePath(path.display().to_string()));
            }
        }
    }
    if output.as_os_str().is_empty() {
        return Err(RecoveryError::UnsafePath("empty path".into()));
    }
    Ok(output)
}

fn copy_tree(source: &Path, destination: &Path, count: &mut u64) -> Result<(), RecoveryError> {
    if !source.exists() {
        return Err(RecoveryError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("base root does not exist: {}", source.display()),
        )));
    }
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        if source_path
            .file_name()
            .is_some_and(|name| name == ".realm-recovery-marker")
        {
            continue;
        }
        let destination_path = destination.join(entry.file_name());
        let file_type = fs::symlink_metadata(&source_path)?.file_type();
        if file_type.is_symlink() {
            let target = fs::read_link(&source_path)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, destination_path)?;
            #[cfg(not(unix))]
            {
                let _ = target;
                return Err(RecoveryError::Unsupported);
            }
        } else if file_type.is_dir() {
            fs::create_dir_all(&destination_path)?;
            copy_tree(&source_path, &destination_path, count)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path)?;
            *count += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use realm_cas::PreimageStore;
    use realm_contract::{ExactRestore, ExactRestoreAction, RecoveryContract};
    use realm_core::{Fidelity, ObjectId, ObjectVersionId, PathBytes, TransactionId};

    #[test]
    fn recovery_workspace_is_isolated_and_exact_restore_works() {
        let base = std::env::temp_dir().join(format!("realm-base-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("x"), b"new").unwrap();
        let cas = PreimageStore::open(base.join("cas")).unwrap();
        let blob = cas.put_bytes(b"old").unwrap();
        let workspace = DisposableRecoveryWorkspace::unique().unwrap();
        let contract = RecoveryContract {
            contract_version: 1,
            target_transaction: TransactionId::new(),
            objective: "test".into(),
            exact_restores: vec![ExactRestore {
                object_id: ObjectId::new(),
                target_path: PathBytes(b"x".to_vec()),
                historical_version: ObjectVersionId::new(),
                source_blob: Some(blob.hash),
                fidelity: Fidelity::ContentExact,
                action: ExactRestoreAction::RestoreBytes,
                event_sequence: 1,
            }],
            direct_effects_to_remove: vec![],
            must_preserve: vec![],
            may_modify: vec![],
            must_not_modify: vec![],
            overlaps: vec![],
            known_dependencies: vec![],
            candidate_dependencies: vec![],
            known_unknowns: vec![],
            capture_quality: realm_contract::CaptureQuality {
                status: realm_core::CaptureStatus::Complete,
                exact_preimages: 1,
                missing_preimages: 0,
                race_detected_preimages: 0,
                unresolved_gap_count: 0,
            },
            invariants: vec![],
            external_effects: vec![],
            required_adapters: vec![],
        };
        materialize_contract(&workspace, &base, &contract, &cas).unwrap();
        assert_eq!(fs::read(workspace.root().join("x")).unwrap(), b"old");
        assert_eq!(fs::read(base.join("x")).unwrap(), b"new");
        workspace.cleanup().unwrap();
        fs::remove_dir_all(base).unwrap();
    }
}
