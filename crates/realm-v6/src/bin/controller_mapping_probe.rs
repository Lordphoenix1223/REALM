//! Independent Linux guard canary, not an executor or authority issuer.
//! Creates only a new caller-owned fixture; parent must inspect actual bytes.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    use std::{fs::OpenOptions, io::Write, os::fd::AsRawFd, os::unix::fs::OpenOptionsExt};
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || !matches!(args[1].as_str(), "shared" | "private" | "none") {
        eprintln!("requires shared|private|none NEW_FIXTURE");
        std::process::exit(2);
    }
    let path = std::path::Path::new(&args[2]);
    assert!(path.is_absolute());
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .unwrap();
    file.set_len(4096).unwrap();
    file.write_all(b"A").unwrap();
    file.sync_all().unwrap();
    let fd = file.as_raw_fd();
    let mapping = if args[1] == "none" {
        std::ptr::null_mut()
    } else {
        let flags = if args[1] == "shared" {
            libc::MAP_SHARED
        } else {
            libc::MAP_PRIVATE
        };
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                fd,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        p
    };
    match realm_v6::controller_guard::install() {
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({"guard_installed":false,
                "error":error.to_string(),"mode":args[1],"authority":"NONE",
                "complete_observation_admission":"REFUSE"})
            );
        }
        Ok(policy_root) => {
            let denied_write = unsafe { libc::write(fd, b"Z".as_ptr().cast(), 1) };
            let denied_errno = std::io::Error::last_os_error().raw_os_error();
            if !mapping.is_null() {
                // A memory store is not a syscall. No msync, descriptor or path
                // operation is needed for parent-visible MAP_SHARED mutation.
                unsafe { std::ptr::write_volatile(mapping.cast::<u8>(), b'B') };
            }
            println!(
                "{}",
                serde_json::json!({"guard_installed":true,
                "policy_root":policy_root,"mode":args[1],"write_return":denied_write,
                "write_errno":denied_errno,"authority":"NONE",
                "complete_observation_admission":"REFUSE"})
            );
        }
    }
    if !mapping.is_null() {
        assert_eq!(unsafe { libc::munmap(mapping, 4096) }, 0);
    }
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn main() {
    eprintln!("REFUSE: actual Linux kernel required; no controller experiment ran");
    std::process::exit(2);
}
