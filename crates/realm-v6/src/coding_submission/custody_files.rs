//! Held-original file checks shared by native custody and physical local controls.
//! These functions are not authority issuers or complete-history observers.
use crate::{execute::ExecuteError, frontier::ObjectIdentity};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
fn bad(s: impl std::fmt::Debug) -> ExecuteError {
    ExecuteError::Supervisor(format!("{s:?}"))
}
pub(crate) fn object(file: &File) -> Result<ObjectIdentity, ExecuteError> {
    let m = file.metadata()?;
    Ok(ObjectIdentity {
        device: m.dev(),
        inode: m.ino(),
    })
}

// Keep original descriptor identity across seal and child retirement.
pub(crate) fn open_snapshot(path: &Path) -> Result<File, ExecuteError> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?)
}
pub(crate) fn read_original(
    file: &mut File,
    path: &Path,
    expected: &ObjectIdentity,
    owner: (u32, u32),
    limit: usize,
) -> Result<Vec<u8>, ExecuteError> {
    let before = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if object(file)? != *expected
        || named.dev() != expected.device
        || named.ino() != expected.inode
        || !named.is_file()
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || (before.uid(), before.gid()) != owner
        || before.len() > limit as u64
    {
        return Err(bad(
            "original native custody file identity/permissions/size differ",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    (&mut *file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mode(),
            before.uid(),
            before.gid(),
            before.nlink(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mode(),
            after.uid(),
            after.gid(),
            after.nlink(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err(bad(
            "original native custody file changed during bounded read",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn actual_held_object_rejects_replacement_alias_permissions_and_bounds() {
        let root = std::env::temp_dir().join(format!(
            "r7-owned-files-{}",
            &crate::mediation::MediationChallenge::fresh()
                .unwrap()
                .root()[..12]
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("output");
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut held = open_snapshot(&path).unwrap();
        let id = object(&held).unwrap();
        let meta = held.metadata().unwrap();
        let owner = (meta.uid(), meta.gid());
        for _ in 0..2 {
            assert_eq!(
                read_original(&mut held, &path, &id, owner, 8).unwrap(),
                b"original"
            );
        }
        assert!(read_original(&mut held, &path, &id, owner, 7).is_err());
        let alias = root.join("alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(read_original(&mut held, &path, &id, owner, 8).is_err());
        fs::remove_file(alias).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_original(&mut held, &path, &id, owner, 8).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let saved = root.join("saved");
        fs::rename(&path, &saved).unwrap();
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_original(&mut held, &path, &id, owner, 8).is_err());
        fs::remove_file(&path).unwrap();
        symlink(&saved, &path).unwrap();
        assert!(read_original(&mut held, &path, &id, owner, 8).is_err());
        drop(held);
        fs::remove_dir_all(root).unwrap();
    }
}
