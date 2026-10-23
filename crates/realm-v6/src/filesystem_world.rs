//! Deterministic semantic filesystem commitments for C1.
//!
//! This scans an already detached directory tree. It intentionally does not
//! parse filesystem images; the Linux supervisor must mount a detached image
//! read-only before calling it. Unsupported object kinds fail closed.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs, io,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum FilesystemObject {
    File { content_blake3: String, mode: u32 },
    Directory { mode: u32 },
    Symlink { target: String, mode: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemWorld {
    pub entries: BTreeMap<String, FilesystemObject>,
    pub root: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum FilesystemChange {
    Create {
        path: String,
        object: FilesystemObject,
    },
    Modify {
        path: String,
        before: FilesystemObject,
        after: FilesystemObject,
    },
    Delete {
        path: String,
        object: FilesystemObject,
    },
}

pub fn scan_directory(root: &Path) -> Result<FilesystemWorld, FilesystemScanError> {
    let root = root.canonicalize().map_err(FilesystemScanError::Io)?;
    let mut entries = BTreeMap::new();
    scan_recursive(&root, &root, &mut entries)?;
    let bytes = serde_json::to_vec(&entries).map_err(|_| FilesystemScanError::Encoding)?;
    Ok(FilesystemWorld {
        entries,
        root: blake3::hash(&bytes).to_hex().to_string(),
    })
}

pub fn delta(before: &FilesystemWorld, after: &FilesystemWorld) -> Vec<FilesystemChange> {
    let mut changes = Vec::new();
    for (path, object) in &before.entries {
        match after.entries.get(path) {
            None => changes.push(FilesystemChange::Delete {
                path: path.clone(),
                object: object.clone(),
            }),
            Some(next) if next != object => changes.push(FilesystemChange::Modify {
                path: path.clone(),
                before: object.clone(),
                after: next.clone(),
            }),
            Some(_) => {}
        }
    }
    for (path, object) in &after.entries {
        if !before.entries.contains_key(path) {
            changes.push(FilesystemChange::Create {
                path: path.clone(),
                object: object.clone(),
            });
        }
    }
    changes
}

#[derive(Debug)]
pub enum FilesystemScanError {
    Io(io::Error),
    Unsupported(String),
    Escape,
    Encoding,
}

fn scan_recursive(
    root: &Path,
    current: &Path,
    entries: &mut BTreeMap<String, FilesystemObject>,
) -> Result<(), FilesystemScanError> {
    let mut children = fs::read_dir(current)
        .map_err(FilesystemScanError::Io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(FilesystemScanError::Io)?;
    children.sort_by_key(|entry| entry.file_name());
    for entry in children {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| FilesystemScanError::Escape)?;
        let relative = normalize_relative(relative)?;
        let metadata = fs::symlink_metadata(&path).map_err(FilesystemScanError::Io)?;
        let mode = metadata.mode() & 0o7777;
        let object = if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)
                .map_err(FilesystemScanError::Io)?
                .to_string_lossy()
                .into_owned();
            FilesystemObject::Symlink { target, mode }
        } else if metadata.is_dir() {
            FilesystemObject::Directory { mode }
        } else if metadata.is_file() {
            let mut hasher = Hasher::new();
            let mut file = fs::File::open(&path).map_err(FilesystemScanError::Io)?;
            io::copy(&mut file, &mut hasher).map_err(FilesystemScanError::Io)?;
            FilesystemObject::File {
                content_blake3: hasher.finalize().to_hex().to_string(),
                mode,
            }
        } else {
            return Err(FilesystemScanError::Unsupported(relative));
        };
        entries.insert(relative, object);
        if metadata.is_dir() {
            scan_recursive(root, &path, entries)?;
        }
    }
    Ok(())
}

fn normalize_relative(path: &Path) -> Result<String, FilesystemScanError> {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => output.push(value),
            _ => return Err(FilesystemScanError::Escape),
        }
    }
    Ok(output.to_string_lossy().replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("realm-world-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn identical_logical_trees_have_identical_roots() {
        let a = root("a");
        let b = root("b");
        fs::write(a.join("x"), b"same").unwrap();
        fs::write(b.join("x"), b"same").unwrap();
        assert_eq!(
            scan_directory(&a).unwrap().root,
            scan_directory(&b).unwrap().root
        );
    }

    #[test]
    fn content_symlink_and_mode_changes_are_detected() {
        let path = root("changes");
        fs::write(path.join("x"), b"one").unwrap();
        let before = scan_directory(&path).unwrap();
        fs::write(path.join("x"), b"two").unwrap();
        symlink("x", path.join("link")).unwrap();
        let after = scan_directory(&path).unwrap();
        assert!(!delta(&before, &after).is_empty());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn unsupported_objects_fail_closed() {
        let path = root("unsupported");
        #[cfg(unix)]
        std::os::unix::net::UnixListener::bind(path.join("socket")).unwrap();
        assert!(matches!(
            scan_directory(&path),
            Err(FilesystemScanError::Unsupported(_))
        ));
        fs::remove_dir_all(path).unwrap();
    }
}
