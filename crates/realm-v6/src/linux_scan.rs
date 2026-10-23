//! Linux final-state scan using descriptor-relative `openat2`.
//! The caller must first establish VM/process quiescence and freeze the image.

use crate::{EntryKind, FsEntry, Refusal, World};
use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const MAX_FILE_BYTES: u64 = 1 << 30;
const MAX_TOTAL_BYTES: u64 = 4 << 30;
const MAX_DEPTH: usize = 64;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn open_root(root: &Path) -> Result<OwnedFd, Refusal> {
    let path = CString::new(root.as_os_str().as_bytes()).map_err(|_| Refusal::ScanFailure)?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Refusal::ScanFailure);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_child(parent: RawFd, name: &OsString) -> Result<OwnedFd, Refusal> {
    let name = CString::new(name.as_bytes()).map_err(|_| Refusal::ScanFailure)?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) as u64,
        mode: 0,
        resolve: RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent,
            name.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(libc::ELOOP | libc::EXDEV | libc::ENXIO | libc::ENODEV) => {
                Refusal::UnsupportedEffect
            }
            _ => Refusal::ScanFailure,
        });
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn stat(fd: RawFd) -> Result<libc::stat, Refusal> {
    let mut value = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut value) } != 0 {
        return Err(Refusal::ScanFailure);
    }
    Ok(value)
}

fn stable(before: &libc::stat, after: &libc::stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_nlink == after.st_nlink
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn names(dir: RawFd) -> Result<Vec<OsString>, Refusal> {
    let proc_path = format!("/proc/self/fd/{dir}");
    let mut result = fs::read_dir(proc_path)
        .map_err(|_| Refusal::ScanFailure)?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|_| Refusal::ScanFailure)
        })
        .collect::<Result<Vec<_>, _>>()?;
    result.sort();
    Ok(result)
}

fn walk(
    dir: RawFd,
    relative: &str,
    root_device: libc::dev_t,
    world: &mut World,
    remaining_bytes: &mut u64,
    depth: usize,
) -> Result<(), Refusal> {
    if depth > MAX_DEPTH {
        return Err(Refusal::ResourceLimit);
    }
    let before_dir = stat(dir)?;
    let initial_names = names(dir)?;
    for name in &initial_names {
        let name = name.to_str().ok_or(Refusal::UnsupportedEffect)?;
        if matches!(name, "" | "." | "..") || name.contains('/') || name.contains('\\') {
            return Err(Refusal::UnsupportedEffect);
        }
        let path = if relative.is_empty() {
            name.to_owned()
        } else {
            format!("{relative}/{name}")
        };
        if world.len() >= 1_000_000 || path.len() > 4096 {
            return Err(Refusal::ResourceLimit);
        }
        let fd = open_child(dir, &OsString::from(name))?;
        let before = stat(fd.as_raw_fd())?;
        if before.st_dev != root_device {
            return Err(Refusal::UnsupportedEffect);
        }
        let mode = before.st_mode & 0o7777;
        let kind = before.st_mode & libc::S_IFMT;
        let entry = if kind == libc::S_IFDIR {
            walk(
                fd.as_raw_fd(),
                &path,
                root_device,
                world,
                remaining_bytes,
                depth + 1,
            )?;
            FsEntry {
                kind: EntryKind::Directory,
                content_blake3: None,
                size: 0,
                mode,
            }
        } else if kind == libc::S_IFREG && before.st_nlink == 1 {
            if before.st_size < 0
                || before.st_size as u64 > MAX_FILE_BYTES
                || before.st_size as u64 > *remaining_bytes
            {
                return Err(Refusal::ResourceLimit);
            }
            let file = File::from(fd.try_clone().map_err(|_| Refusal::ScanFailure)?);
            let mut bytes = Vec::new();
            file.take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| Refusal::ScanFailure)?;
            if bytes.len() as u64 != before.st_size as u64 {
                return Err(Refusal::ScanFailure);
            }
            *remaining_bytes -= bytes.len() as u64;
            FsEntry {
                kind: EntryKind::File,
                content_blake3: Some(blake3::hash(&bytes).to_hex().to_string()),
                size: bytes.len() as u64,
                mode,
            }
        } else {
            return Err(Refusal::UnsupportedEffect);
        };
        let after = stat(fd.as_raw_fd())?;
        if !stable(&before, &after) {
            return Err(Refusal::ScanFailure);
        }
        world.insert(path, entry);
    }
    if names(dir)? != initial_names || !stable(&before_dir, &stat(dir)?) {
        return Err(Refusal::ScanFailure);
    }
    Ok(())
}

/// The root must be a frozen, private filesystem tree. This scan alone cannot
/// establish quiescence or reveal transient effects.
pub fn scan_world_linux(root: &Path) -> Result<World, Refusal> {
    let root_fd = open_root(root)?;
    let root_stat = stat(root_fd.as_raw_fd())?;
    let mut world = World::new();
    let mut remaining_bytes = MAX_TOTAL_BYTES;
    walk(
        root_fd.as_raw_fd(),
        "",
        root_stat.st_dev,
        &mut world,
        &mut remaining_bytes,
        0,
    )?;
    Ok(world)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn descriptor_scan_matches_simple_tree_and_refuses_aliases() {
        let dir = std::env::temp_dir().join(format!("realm-v6-openat2-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("file"), b"bytes").unwrap();
        assert_eq!(scan_world_linux(&dir), crate::scan_world(&dir));
        symlink("file", dir.join("alias")).unwrap();
        assert!(matches!(
            scan_world_linux(&dir),
            Err(Refusal::UnsupportedEffect)
        ));
        fs::remove_file(dir.join("alias")).unwrap();
        fs::hard_link(dir.join("file"), dir.join("alias")).unwrap();
        assert!(matches!(
            scan_world_linux(&dir),
            Err(Refusal::UnsupportedEffect)
        ));
        fs::remove_dir_all(dir).unwrap();
    }
}
