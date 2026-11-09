//! Linux pipe-only controller syscall boundary. This is not a coding authority
//! issuer: vDSO, hardware counters and preloaded process memory are outside this
//! filter. Arbitrary native/Python controllers remain unqualified.
use std::{
    io::{self, Read},
    mem,
};

pub const POLICY: &str = "realm.controller.pipe-only-seccomp/v1";

/// Install only in a freshly exec'd single-threaded helper. Every descriptor
/// above stderr is closed before installing the filter. Path syscalls are
/// rejected before VFS lookup; no errno normalization wrapper is involved.
/// Trusted startup must keep the task and mapping tables stable until the
/// filter is installed: no asynchronous thread creation or mapping mutation.
/// The procfs checks are snapshots, not locks or thread-synchronized seccomp.
/// This preflight closes one effect channel, not all unmediated observations.
pub fn install() -> io::Result<String> {
    require_single_task(std::fs::read_dir("/proc/self/task")?)?;
    for fd in 0..=2 {
        let mut st = mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { st.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFIFO {
            return Err(io::Error::other("controller stdio must be three pipes"));
        }
    }
    // Closing descriptors does not revoke existing MAP_SHARED mappings: an
    // ordinary memory store can still change their backing object. Inspect
    // before close_range/filter installation, while procfs remains available.
    let mut maps = String::new();
    std::fs::File::open("/proc/self/maps")?
        .take(1024 * 1024 + 1)
        .read_to_string(&mut maps)?;
    reject_writable_shared_maps(&maps)?;
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut filter = instructions();
    let root = policy_root();
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(root)
}

/// Hash of the exact installed filter, not a child-supplied policy label.
pub fn policy_root() -> String {
    let filter = instructions();
    let raw = filter
        .iter()
        .flat_map(|i| {
            let mut bytes = i.code.to_le_bytes().to_vec();
            bytes.extend([i.jt, i.jf]);
            bytes.extend(i.k.to_le_bytes());
            bytes
        })
        .collect::<Vec<_>>();
    blake3::hash(&raw).to_hex().to_string()
}

fn require_single_task<T>(mut tasks: impl Iterator<Item = io::Result<T>>) -> io::Result<()> {
    let count = tasks.try_fold(0usize, |count, entry| entry.map(|_| count + 1))?;
    if count != 1 {
        return Err(io::Error::other("controller must have exactly one thread"));
    }
    Ok(())
}

fn reject_writable_shared_maps(maps: &str) -> io::Result<()> {
    let invalid = || io::Error::other("invalid or oversized controller mapping inventory");
    if maps.is_empty() || maps.len() > 1024 * 1024 || !maps.ends_with('\n') {
        return Err(invalid());
    }
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let address = fields.next().ok_or_else(invalid)?;
        let permissions = fields.next().ok_or_else(invalid)?.as_bytes();
        let offset = fields.next().ok_or_else(invalid)?;
        let device = fields.next().ok_or_else(invalid)?;
        let inode = fields.next().ok_or_else(invalid)?;
        let hex_pair = |text: &str, separator: char| {
            text.split_once(separator).and_then(|(a, b)| {
                Some((
                    u64::from_str_radix(a, 16).ok()?,
                    u64::from_str_radix(b, 16).ok()?,
                ))
            })
        };
        if !matches!(hex_pair(address, '-'), Some((start, end)) if start < end)
            || permissions.len() != 4
            || !matches!(permissions[0], b'r' | b'-')
            || !matches!(permissions[1], b'w' | b'-')
            || !matches!(permissions[2], b'x' | b'-')
            || !matches!(permissions[3], b'p' | b's')
            || u64::from_str_radix(offset, 16).is_err()
            || hex_pair(device, ':').is_none()
            || inode.parse::<u64>().is_err()
        {
            return Err(invalid());
        }
        // Includes deleted files, memfd, and anonymous shared mappings. A
        // pathname or nonzero inode is not required for shared-memory effects.
        if permissions[1] == b'w' && permissions[3] == b's' {
            return Err(io::Error::other("controller has a writable shared mapping"));
        }
    }
    Ok(())
}

fn ins(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}
fn instructions() -> Vec<libc::sock_filter> {
    const LD: u16 = 0x20;
    const JEQ: u16 = 0x15;
    const RET: u16 = 0x06;
    const ALLOW: u32 = 0x7fff0000;
    const DENY: u32 = 0x00050000 | libc::EPERM as u32;
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    let mut f = vec![
        ins(LD, 0, 0, 4),
        ins(JEQ, 1, 0, ARCH),
        ins(RET, 0, 0, 0x80000000), // kill foreign ABI
        ins(LD, 0, 0, 0),
    ];
    // Syscall and descriptor direction both matter. No readv, recvmsg, splice,
    // io_uring, descriptor duplication, path operation, process creation or
    // network syscall is present in the allowlist.
    for (nr, descriptors) in [
        (libc::SYS_read, &[0u32][..]),
        (libc::SYS_write, &[1u32, 2u32][..]),
    ] {
        let block_len = 3 + 2 * descriptors.len();
        f.push(ins(JEQ, 0, block_len as u8, nr as u32));
        f.push(ins(LD, 0, 0, 16));
        for fd in descriptors {
            f.push(ins(JEQ, 0, 1, *fd));
            f.push(ins(RET, 0, 0, ALLOW));
        }
        f.push(ins(RET, 0, 0, DENY));
        f.push(ins(LD, 0, 0, 0));
    }
    // Allocation may only create anonymous mappings, never file mappings.
    f.extend([
        ins(JEQ, 0, 4, libc::SYS_mmap as u32),
        ins(LD, 0, 0, 16 + 3 * 8),
        ins(0x45, 0, 1, libc::MAP_ANONYMOUS as u32), // JSET
        ins(RET, 0, 0, ALLOW),
        ins(RET, 0, 0, DENY),
        ins(LD, 0, 0, 0),
    ]);
    for nr in [
        libc::SYS_brk,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_sigaltstack,
        libc::SYS_futex,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        f.push(ins(JEQ, 0, 1, nr as u32));
        f.push(ins(RET, 0, 0, ALLOW));
    }
    f.push(ins(RET, 0, 0, DENY));
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn task_inventory_errors_never_count_as_a_verified_thread() {
        assert!(require_single_task([Ok(())].into_iter()).is_ok());
        assert!(require_single_task(std::iter::empty::<io::Result<()>>()).is_err());
        assert!(require_single_task([Ok(()), Ok(())].into_iter()).is_err());
        let error = || io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(
            require_single_task([Err::<(), _>(error())].into_iter())
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(require_single_task([Ok(()), Err(error())].into_iter()).is_err());
    }
    #[test]
    fn mapping_preflight_rejects_effect_channels_and_incomplete_inventories() {
        for name in [
            "/tmp/backing",
            "/memfd:fixture (deleted)",
            "/dev/zero (deleted)",
            "",
        ] {
            let row = format!("1000-2000 rw-s 00000000 00:00 0 {name}\n");
            assert!(reject_writable_shared_maps(&row).is_err());
        }
        let safe = "1000-2000 rw-p 00000000 00:00 0 [heap]\n2000-3000 r--s 00000000 00:01 1 /tmp/read-only\n3000-4000 r-xp 00001000 00:01 1 /bin/helper\n";
        assert!(reject_writable_shared_maps(safe).is_ok());
        for invalid in [
            "",
            "1000-2000 rw-p 0 00:00 0",
            "1000-2000 rw-p\n",
            "2000-1000 rw-p 0 00:00 0\n",
            "1000-2000 rw-? 0 00:00 0\n",
            "1000-2000 rw-p nope 00:00 0\n",
        ] {
            assert!(reject_writable_shared_maps(invalid).is_err(), "{invalid:?}");
        }
        assert!(reject_writable_shared_maps(&"x".repeat(1024 * 1024 + 1)).is_err());
    }
    #[test]
    fn allowlist_has_no_path_network_clock_entropy_or_process_creation() {
        let f = instructions();
        // Evaluate this exact cBPF subset against syscall/argument inputs. Real
        // process tests additionally exercise the installed kernel filter.
        fn eval(f: &[libc::sock_filter], nr: i64, arg0: u32, flags: u32) -> u32 {
            let mut a = 0;
            let mut pc = 3; // native architecture already checked
            while pc < f.len() {
                let i = &f[pc];
                match i.code {
                    0x20 => {
                        a = match i.k {
                            0 => nr as u32,
                            16 => arg0,
                            40 => flags,
                            _ => panic!(),
                        }
                    }
                    0x15 | 0x45 => {
                        let yes = if i.code == 0x15 {
                            a == i.k
                        } else {
                            a & i.k != 0
                        };
                        pc += if yes { i.jt } else { i.jf } as usize;
                    }
                    0x06 => return i.k,
                    _ => panic!(),
                }
                pc += 1;
            }
            panic!("filter fell through")
        }
        for nr in [
            libc::SYS_openat,
            libc::SYS_getdents64,
            libc::SYS_readlinkat,
            libc::SYS_statx,
            libc::SYS_socket,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_execve,
            libc::SYS_mprotect,
            libc::SYS_prctl,
            libc::SYS_seccomp,
            libc::SYS_getrandom,
            libc::SYS_clock_gettime,
            libc::SYS_io_uring_setup,
            libc::SYS_dup,
            libc::SYS_recvmsg,
            libc::SYS_sendmsg,
        ] {
            assert_eq!(eval(&f, nr, 0, 0), 0x00050001);
        }
        for fd in 0..=8 {
            assert_eq!(eval(&f, libc::SYS_read, fd, 0) == 0x7fff0000, fd == 0);
            assert_eq!(
                eval(&f, libc::SYS_write, fd, 0) == 0x7fff0000,
                fd == 1 || fd == 2
            );
        }
        assert_eq!(eval(&f, libc::SYS_mmap, 0, 0), 0x00050001);
        assert_eq!(
            eval(&f, libc::SYS_mmap, 0, libc::MAP_ANONYMOUS as u32),
            0x7fff0000
        );
        // Runtime remapping remains allowed; it is not a permission-upgrade
        // mechanism or proof of observation completeness. Protection changes
        // and new threads cannot be enabled through this allowlist.
        assert_eq!(eval(&f, libc::SYS_mremap, 0, 0), 0x7fff0000);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(eval(&f, libc::SYS_pkey_mprotect, 0, 0), 0x00050001);
    }
}
