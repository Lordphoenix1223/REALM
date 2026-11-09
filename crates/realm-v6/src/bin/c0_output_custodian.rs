//! C0 diagnostic output custodian. Its distinct UID and private journal are
//! launcher obligations; this binary cannot issue admission or mediation.
use realm_v6::custody::CustodyServer;
use realm_v6::profile::SyncTrace as _;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;

const LAUNCH_READY: &[u8] = b"REALM-C0-CUSTODIAN-READY-V1\n";
const LAUNCH_START: &[u8] = b"REALM-C0-CUSTODIAN-START-V1\n";

fn check_stdin_socket() -> io::Result<()> {
    let mut kind = 0i32;
    let mut kind_len = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: both output pointers address initialized writable stack values.
    let status = unsafe {
        libc::getsockopt(
            0,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut i32).cast(),
            &mut kind_len,
        )
    };
    if status != 0 || kind_len as usize != std::mem::size_of::<i32>() || kind != libc::SOCK_STREAM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stdin is not a stream socket",
        ));
    }
    // SAFETY: storage and size are valid writable buffers for getsockname.
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut address_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let status = unsafe {
        libc::getsockname(
            0,
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut address_len,
        )
    };
    if status != 0 || address.ss_family as i32 != libc::AF_UNIX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stdin is not AF_UNIX",
        ));
    }
    Ok(())
}

fn absolute_clean(path: &Path) -> bool {
    path.is_absolute()
        && !path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}

fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(args.len(), 4 | 5) {
        return Err(
            "usage: c0_output_custodian OUTPUT_PATH JOURNAL_PATH RUN_ID (AF_UNIX stream on stdin)"
                .into(),
        );
    }
    let budget_ms = if args.len() == 5 {
        args[4].parse::<u64>()?
    } else {
        30_000
    };
    if !(1..=300_000).contains(&budget_ms) {
        return Err("invalid bounded custody session deadline".into());
    }
    check_stdin_socket()?;
    let output_path = Path::new(&args[1]);
    let journal_path = Path::new(&args[2]);
    let birth_cwd_paths =
        output_path == Path::new("output") && journal_path == Path::new("custody.jsonl");
    if (!birth_cwd_paths && (!absolute_clean(output_path) || !absolute_clean(journal_path)))
        || output_path == journal_path
        || output_path.parent() != journal_path.parent()
    {
        return Err("invalid output or journal path".into());
    }
    // Relative basenames use the private cwd granted before credential drop.
    // They require no permission to traverse the root-private run ancestors.
    let parent = if birth_cwd_paths {
        Path::new(".")
    } else {
        journal_path.parent().ok_or("journal parent missing")?
    };
    let parent_stat = fs::symlink_metadata(parent)?;
    // A private directory rules out replacement by the separately credentialed
    // broker. The launcher must also protect all ancestor path components.
    if !parent_stat.is_dir()
        || parent_stat.uid() != unsafe { libc::geteuid() }
        || parent_stat.mode() & 0o7777 != 0o700
    {
        return Err("journal directory is not custodian-owned mode 0700".into());
    }
    let output_stat = fs::symlink_metadata(output_path)?;
    if !output_stat.is_file()
        || output_stat.nlink() != 1
        || output_stat.uid() != unsafe { libc::geteuid() }
        || output_stat.mode() & 0o7777 != 0o600
    {
        return Err("output is not custodian-owned regular mode 0600 file".into());
    }
    let output = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output_path)?;
    let opened_output = output.metadata()?;
    if (opened_output.dev(), opened_output.ino()) != (output_stat.dev(), output_stat.ino()) {
        return Err("output pathname changed during open".into());
    }
    let journal = OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(journal_path)?;
    if journal.metadata()?.mode() & 0o7777 != 0o600 {
        return Err("custody journal mode is not 0600".into());
    }
    File::open(parent)?.sync_all_traced()?;
    let mut server = CustodyServer::new(output, journal, args[3].clone())
        .map_err(|e| format!("custodian start refused: {e:?}"))?;
    // SAFETY: the launcher arranges one connected AF_UNIX descriptor at fd 0.
    // check_stdin_socket validated its family and stream type above.
    let mut stream = unsafe { UnixStream::from_raw_fd(0) };
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    // Keep the child alive after its private output/journal binding is ready,
    // but before the launcher trusts a numeric PID enough to open a pidfd.
    // Without this two-way gate, a fast startup refusal or EOF can make
    // pidfd_open race process exit and report ESRCH without the real reason.
    stream.write_all(LAUNCH_READY)?;
    stream.flush()?;
    let mut start = [0_u8; LAUNCH_START.len()];
    stream.read_exact(&mut start)?;
    if start != *LAUNCH_START {
        return Err("custodian launch gate refused".into());
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(budget_ms);
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or("custody session deadline expired")?;
        stream.set_read_timeout(Some(remaining))?;
        stream.set_write_timeout(Some(remaining))?;
        match server.serve_one(&mut stream) {
            Ok(true) => {}
            Ok(false) => return Ok(()),
            Err(error) => return Err(format!("custodian refused: {error:?}").into()),
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if let Err(error) = run(&args) {
        eprintln!("C0 output custodian refused: {error}");
        std::process::exit(2);
    }
}
