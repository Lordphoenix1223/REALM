//! Coding-only enforcement execution chain. No public qualification producer.
//! The trusted static stage is build-embedded, not selected by caller metadata.
use crate::measured_launch::{FileIdentity, VmmIncarnation};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};
const STAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/coding-fence"));
const OFFICIAL: &str = "realm-vmm";
pub(crate) fn stage_digest() -> String {
    blake3::hash(STAGE).to_hex().to_string()
}

/// This is actual observed installation control flow, not kernel policy
/// readback or registered publication qualification. Kept inside the live
/// launch owner, never deserialized or reconstructed from its JSON export.
pub(crate) struct EnforcedCodingLaunch {
    pid: u32,
    start: u64,
    stage: FileIdentity,
    official: FileIdentity,
    net: (u64, u64),
    ipc: (u64, u64),
    jail: PathBuf,
    origin: serde_json::Value,
    _root_pin: File,
    stage_pin: File,
    official_pin: File,
    _net_pin: File,
    _ipc_pin: File,
    _pidfd: File,
    journal_pin: File,
    journal_identity: FileIdentity,
}
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct ExecStopExpectation {
    pub cgroup_relative: PathBuf,
    pub memory_max: u64,
    pub pids_max: u32,
    pub uid: u32,
    pub gid: u32,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
}
#[cfg(test)]
#[derive(Clone)]
struct ExecStopProbe {
    result: std::sync::Arc<std::sync::Mutex<Option<serde_json::Value>>>,
    expected: Option<ExecStopExpectation>,
}
pub(crate) struct PreparedCodingFence {
    pub(crate) executable: PathBuf,
    official: FileIdentity,
    jail: PathBuf,
    journal: File,
    journal_path: PathBuf,
    root_pin: File,
    uid: u32,
    gid: u32,
    userfaultfd_minor: Option<u32>,
    // Compiled out of every production binary. No runtime policy/test flag.
    #[cfg(test)]
    stop_probe: Option<ExecStopProbe>,
}
fn err(s: &str) -> io::Error {
    io::Error::other(s)
}
// Diagnostic context only: retain the actual I/O cause and errno without
// changing the refusal or attempting another operation.
#[derive(Debug)]
struct OperationError {
    operation: String,
    cause: io::Error,
}
impl std::fmt::Display for OperationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} [raw_os_error={:?}]",
            self.operation,
            self.cause,
            self.cause.raw_os_error()
        )
    }
}
impl std::error::Error for OperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
fn operation_error(operation: impl Into<String>, cause: io::Error) -> io::Error {
    io::Error::new(
        cause.kind(),
        OperationError {
            operation: operation.into(),
            cause,
        },
    )
}
fn ns(pid: u32, name: &str) -> io::Result<(u64, u64)> {
    let m = fs::metadata(format!("/proc/{pid}/ns/{name}"))?;
    Ok((m.dev(), m.ino()))
}
fn protect(path: &Path, mode: u32) -> io::Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if unsafe { libc::fchown(f.as_raw_fd(), 0, 0) } != 0
        || unsafe { libc::fchmod(f.as_raw_fd(), mode) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    f.sync_all()
}
fn process_start_ticks(pid: u32) -> io::Result<u64> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    raw.rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| err("original process start identity absent"))
}
fn verify_pidfd(pid: u32, pin: &File) -> io::Result<()> {
    let raw = fs::read_to_string(format!("/proc/self/fdinfo/{}", pin.as_raw_fd()))?;
    let values: Vec<_> = raw.lines().filter_map(|s| s.strip_prefix("Pid:")).collect();
    if values.len() != 1 || values[0].trim().parse::<u32>().ok() != Some(pid) {
        return Err(err("retained pidfd does not name original process"));
    }
    Ok(())
}
// Supplemental diagnostic evidence, not the canonical qualification receipt
// schema. Only the actual wait on the original kernel handle produces this.
fn wait_original_terminal(
    pid: u32,
    pin: &File,
    start: u64,
    timeout: Duration,
    peek: bool,
) -> io::Result<serde_json::Value> {
    verify_pidfd(pid, pin)?;
    if process_start_ticks(pid)? != start {
        return Err(err("original process incarnation substituted"));
    }
    let deadline = Instant::now() + timeout;
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let flags =
            libc::WEXITED | libc::WNOHANG | libc::__WALL | if peek { libc::WNOWAIT } else { 0 };
        if unsafe { libc::waitid(libc::P_PIDFD, pin.as_raw_fd() as u32, &mut info, flags) } != 0 {
            return Err(operation_error(
                "original pidfd terminal wait",
                io::Error::last_os_error(),
            ));
        }
        if unsafe { info.si_pid() } != 0 {
            if unsafe { info.si_pid() } != pid as i32
                || ![libc::CLD_EXITED, libc::CLD_KILLED, libc::CLD_DUMPED].contains(&info.si_code)
            {
                return Err(err("original terminal identity/status unavailable"));
            }
            return Ok(serde_json::json!({"pid":pid,"start_time_ticks":start,
                "boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
                "handle":"original_pidfd","wait":"waitid(P_PIDFD,__WALL)",
                "si_code":info.si_code,"si_status":unsafe {info.si_status()},
                "signal":unsafe {info.si_status()},"reaped":!peek}));
        }
        if Instant::now() >= deadline {
            return Err(err("original pidfd terminal deadline"));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn terminate_original(
    pid: u32,
    pin: &File,
    start: u64,
    timeout: Duration,
) -> io::Result<serde_json::Value> {
    verify_pidfd(pid, pin)?;
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pin.as_raw_fd(),
            libc::SIGKILL,
            0,
            0,
        )
    } < 0
    {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ESRCH) {
            return Err(operation_error("original pidfd SIGKILL", e));
        }
    }
    wait_original_terminal(pid, pin, start, timeout, false)
}

fn diagnostic_terminal_bundle(
    discovered: &BTreeSet<u32>,
    rows: &BTreeMap<u32, serde_json::Value>,
    unresolved: bool,
) -> serde_json::Value {
    let receipts: Vec<_> = discovered.iter().map(|pid| rows.get(pid).cloned().unwrap_or_else(||
        serde_json::json!({"pid":pid,"status":"INCOMPLETE","reaped":null,"error":"original handle or terminal observation absent"}))).collect();
    let complete = !unresolved
        && rows.len() == discovered.len()
        && discovered.iter().zip(&receipts).all(|(pid, r)| {
            r["pid"].as_u64() == Some(*pid as u64)
                && r["start_time_ticks"].as_u64().is_some_and(|n| n > 0)
                && r["boot_id"].as_str().is_some_and(|b| !b.is_empty())
                && r["si_code"].as_i64().is_some_and(|c| {
                    [
                        libc::CLD_EXITED as i64,
                        libc::CLD_KILLED as i64,
                        libc::CLD_DUMPED as i64,
                    ]
                    .contains(&c)
                })
                && r["si_status"].as_u64().is_some()
                && r["reaped"] == true
                && r["handle"] == "original_pidfd"
                && r["wait"] == "waitid(P_PIDFD,__WALL)"
        });
    serde_json::json!({"schema":"realm.exec-stop-diagnostic-terminal.v1","authority":"NONE",
        "required_original_pids":discovered,"unresolved_descendant_discovery":unresolved,"receipts":receipts,"complete":complete})
}
// Only for a just-discovered, never-reaped original trace child when pidfd
// acquisition fails. A bounded numeric wait may clean up; it cannot establish
// an original-pidfd receipt or turn INCOMPLETE custody into complete custody.
fn fallback_unpinned_descendant(pid: u32) -> serde_json::Value {
    let signal_result = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    let signal_errno = if signal_result < 0 {
        io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut raw = None;
    let mut wait_error = None;
    while Instant::now() < deadline {
        let mut status = 0;
        let got = unsafe { libc::waitpid(pid as i32, &mut status, libc::__WALL | libc::WNOHANG) };
        if got == pid as i32 {
            raw = Some(status);
            break;
        }
        if got < 0 {
            wait_error = io::Error::last_os_error().raw_os_error();
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    serde_json::json!({"pid":pid,"status":"INCOMPLETE","reaped":null,"handle":null,
        "error":"original pidfd not acquired","fallback_signal_errno":signal_errno,
        "fallback_waitpid_raw_status":raw,"fallback_wait_errno":wait_error})
}

// Vendor v1.17.0 creates this optional node from /proc/misc before clone/exec.
// It is not an admitted CodingTools capability. Recognition below authorizes
// only removal while the authenticated original stage is still EXEC-stopped.
fn parse_userfaultfd_minor(text: &str) -> io::Result<Option<u32>> {
    let mut found = None;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.get(1) == Some(&"userfaultfd") {
            let minor = fields[0]
                .parse::<u32>()
                .map_err(|_| err("invalid userfaultfd minor"))?;
            if fields.len() != 2
                || minor > 0xfffff
                || [200, 232].contains(&minor)
                || found.is_some()
            {
                return Err(err("ambiguous userfaultfd device registration"));
            }
            found = Some(minor);
        }
    }
    Ok(found)
}
fn open_dir(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}
fn open_at(parent: &File, name: &std::ffi::CStr, flags: i32) -> io::Result<File> {
    use std::os::fd::FromRawFd;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn same_node(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.mode(),
        a.uid(),
        a.gid(),
        a.rdev(),
        a.nlink(),
    ) == (
        b.dev(),
        b.ino(),
        b.mode(),
        b.uid(),
        b.gid(),
        b.rdev(),
        b.nlink(),
    )
}
fn node_record(m: &fs::Metadata) -> serde_json::Value {
    serde_json::json!({"device":m.dev(),"inode":m.ino(),"mode":m.mode(),"uid":m.uid(),"gid":m.gid(),"rdev":m.rdev(),"links":m.nlink()})
}
fn validate_vendor_node(m: &fs::Metadata, minor: u32, uid: u32, gid: u32) -> io::Result<()> {
    if uid == 0
        || gid == 0
        || !m.file_type().is_char_device()
        || m.mode() != libc::S_IFCHR | 0o600
        || (
            m.uid(),
            m.gid(),
            m.nlink(),
            libc::major(m.rdev()),
            libc::minor(m.rdev()),
        ) != (uid, gid, 1, 10, minor)
    {
        return Err(err(
            "vendor userfaultfd object type/identity/permissions differ",
        ));
    }
    Ok(())
}
fn verify_root(jail: &Path, pin: &File, pid: u32) -> io::Result<()> {
    verify_root_identity(jail, pin, pid)?;
    let held = pin.metadata()?;
    if (held.uid(), held.gid()) != (0, 0) || held.mode() & 0o022 != 0 {
        return Err(err("original jail root is not protected"));
    }
    Ok(())
}
fn verify_root_identity(jail: &Path, pin: &File, pid: u32) -> io::Result<()> {
    let held = pin.metadata()?;
    let named = fs::symlink_metadata(jail)?;
    if !held.is_dir() || (held.dev(), held.ino()) != (named.dev(), named.ino()) || !named.is_dir() {
        return Err(err("original protected jail root substituted"));
    }
    for leaf in ["root", "cwd"] {
        let actual = fs::metadata(format!("/proc/{pid}/{leaf}"))?;
        if (actual.dev(), actual.ino()) != (held.dev(), held.ino()) {
            return Err(err("stopped stage root/cwd differs"));
        }
    }
    Ok(())
}
fn verify_no_userfaultfd_fds(
    pid: u32,
    pin: &File,
    minor: Option<u32>,
) -> io::Result<Vec<serde_json::Value>> {
    verify_pidfd(pid, pin)?;
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    if !status.lines().any(|s| s.starts_with("State:\tt"))
        || !status.lines().any(|s| s == "Threads:\t1")
    {
        return Err(err("original stage not single-thread trace-stopped"));
    }
    let mut records = Vec::new();
    let mut count = 0;
    for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
        count += 1;
        if count > 256 {
            return Err(err("unbounded inherited descriptor census"));
        }
        let entry = entry?;
        let number = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
            .ok_or_else(|| err("invalid original descriptor"))?;
        use std::os::fd::FromRawFd;
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pin.as_raw_fd(), number, 0) };
        if fd < 0 {
            return Err(operation_error(
                "stage original descriptor duplication",
                io::Error::last_os_error(),
            ));
        }
        let held = unsafe { File::from_raw_fd(fd as i32) };
        let m = held.metadata()?;
        let link = fs::read_link(entry.path())?;
        if (m.file_type().is_char_device()
            && minor.is_some_and(|n| m.rdev() == libc::makedev(10, n)))
            || [
                Path::new("anon_inode:[userfaultfd]"),
                Path::new("anon_inode:userfaultfd"),
            ]
            .contains(&link.as_path())
        {
            return Err(err("inherited userfaultfd capability"));
        }
        records.push(serde_json::json!({"fd":number,"metadata":node_record(&m),"target":link}));
    }
    Ok(records)
}
struct UserfaultfdExclusion {
    dev: File,
    dev_metadata: fs::Metadata,
    node: File, // O_PATH: never opens the device driver or calls its ioctl.
    node_metadata: fs::Metadata,
}
impl UserfaultfdExclusion {
    fn prepare(
        jail: &Path,
        root: &File,
        uid: u32,
        gid: u32,
        expected: Option<u32>,
        pid: u32,
    ) -> io::Result<Option<Self>> {
        verify_root(jail, root, pid)?;
        if parse_userfaultfd_minor(&fs::read_to_string("/proc/misc")?)? != expected {
            return Err(err("host userfaultfd registration changed during launch"));
        }
        let dev = open_at(root, c"dev", libc::O_RDONLY | libc::O_DIRECTORY)?;
        let dev_metadata = dev.metadata()?;
        if (dev_metadata.uid(), dev_metadata.gid(), dev_metadata.mode())
            != (uid, gid, libc::S_IFDIR | 0o700)
        {
            return Err(err("vendor dev directory ownership/permissions differ"));
        }
        let node = match open_at(&dev, c"userfaultfd", libc::O_PATH) {
            Ok(node) => node,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) && expected.is_none() => {
                return Ok(None);
            }
            Err(e) => return Err(operation_error("expected vendor userfaultfd node", e)),
        };
        let node_metadata = node.metadata()?;
        validate_vendor_node(
            &node_metadata,
            expected.ok_or_else(|| err("unregistered userfaultfd object"))?,
            uid,
            gid,
        )?;
        Ok(Some(Self {
            dev,
            dev_metadata,
            node,
            node_metadata,
        }))
    }
    fn remove(self, jail: &Path, root: &File, pid: u32) -> io::Result<serde_json::Value> {
        verify_root(jail, root, pid)?;
        let mut receipt = self.remove_pinned(root)?;
        verify_root(jail, root, pid)?;
        receipt["pid"] = serde_json::json!(pid);
        Ok(receipt)
    }
    fn remove_pinned(self, root: &File) -> io::Result<serde_json::Value> {
        let named_dev = open_at(root, c"dev", libc::O_RDONLY | libc::O_DIRECTORY)?;
        if !same_node(&self.dev_metadata, &self.dev.metadata()?)
            || !same_node(&self.dev_metadata, &named_dev.metadata()?)
        {
            return Err(err("original dev directory substituted"));
        }
        let named = open_at(&self.dev, c"userfaultfd", libc::O_PATH)?;
        if !same_node(&self.node_metadata, &self.node.metadata()?)
            || !same_node(&self.node_metadata, &named.metadata()?)
        {
            return Err(err("original userfaultfd node substituted"));
        }
        // Freeze the vendor directory against the jailed UID before removal.
        if unsafe { libc::fchown(self.dev.as_raw_fd(), 0, 0) } != 0
            || unsafe { libc::fchmod(self.dev.as_raw_fd(), 0o755) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let frozen_name = open_at(&self.dev, c"userfaultfd", libc::O_PATH)?;
        if !same_node(&self.node_metadata, &frozen_name.metadata()?) {
            return Err(err("userfaultfd name substituted before exclusion"));
        }
        if unsafe { libc::unlinkat(self.dev.as_raw_fd(), c"userfaultfd".as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        match open_at(&self.dev, c"userfaultfd", libc::O_PATH) {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => (),
            _ => return Err(err("userfaultfd absence not established")),
        }
        let after = self.node.metadata()?;
        if (after.dev(), after.ino(), after.nlink())
            != (self.node_metadata.dev(), self.node_metadata.ino(), 0)
        {
            return Err(err("held original userfaultfd inode was not unlinked"));
        }
        let dev_after = self.dev.metadata()?;
        if (dev_after.uid(), dev_after.gid(), dev_after.mode()) != (0, 0, libc::S_IFDIR | 0o755)
            || (dev_after.dev(), dev_after.ino())
                != (self.dev_metadata.dev(), self.dev_metadata.ino())
        {
            return Err(err("protected dev directory readback differs"));
        }
        Ok(
            serde_json::json!({"phase":"DEVICE_EXCLUSION_COMPLETE", "authority":"NONE",
            "before":node_record(&self.node_metadata),"held_after":node_record(&after),
            "dev_before":node_record(&self.dev_metadata),"dev_after":node_record(&dev_after),
            "path":"dev/userfaultfd","path_absent":true,"original_inode_unlinked":true,
            "policy":"excluded before original stage CONT; never an admitted device"}),
        )
    }
}

fn census_origin(jail: &Path, pid: u32) -> io::Result<serde_json::Value> {
    census_origin_before_exclusion(jail, pid, None)
}
fn census_origin_before_exclusion(
    jail: &Path,
    pid: u32,
    excluded: Option<&fs::Metadata>,
) -> io::Result<serde_json::Value> {
    let root = fs::symlink_metadata(jail)
        .map_err(|e| operation_error(format!("census symlink_metadata {}", jail.display()), e))?;
    for name in ["root", "cwd"] {
        let path = format!("/proc/{pid}/{name}");
        let actual = fs::metadata(&path)
            .map_err(|e| operation_error(format!("census metadata {path}"), e))?;
        if (actual.dev(), actual.ino()) != (root.dev(), root.ino()) {
            return Err(err("stage root/cwd is outside the owned jail"));
        }
    }
    let records = census_entries(jail, excluded)?;
    Ok(
        serde_json::json!({"root":{"dev":root.dev(),"ino":root.ino()},"entries":records,"reachable_sockets":[],"phase":"native stage exec-stop before policy installation"}),
    )
}
fn census_entries(
    jail: &Path,
    excluded: Option<&fs::Metadata>,
) -> io::Result<BTreeMap<String, serde_json::Value>> {
    let mut queue = vec![PathBuf::new()];
    let mut records = std::collections::BTreeMap::new();
    while let Some(relative) = queue.pop() {
        let directory = jail.join(&relative);
        let entries = fs::read_dir(&directory)
            .map_err(|e| operation_error(format!("census read_dir {}", directory.display()), e))?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                operation_error(format!("census read_dir entry {}", directory.display()), e)
            })?;
            let path = relative.join(entry.file_name());
            let m = fs::symlink_metadata(entry.path()).map_err(|e| {
                operation_error(
                    format!("census symlink_metadata {}", entry.path().display()),
                    e,
                )
            })?;
            let name = path.to_str().ok_or_else(|| err("non-UTF8 jail entry"))?;
            let kind = m.file_type();
            if kind.is_symlink() || kind.is_socket() {
                return Err(err("preexisting jail alias or socket"));
            }
            let allowed = if kind.is_dir() {
                matches!(name, "run" | "dev" | "dev/net")
            } else if kind.is_file() {
                matches!(
                    name,
                    "firecracker" | "realm-vmm" | "kernel" | "rootfs.ext4" | "firecracker.pid"
                ) && m.nlink() == 1
            } else if kind.is_char_device() {
                matches!(
                    (name, libc::major(m.rdev()), libc::minor(m.rdev())),
                    ("dev/kvm", 10, 232) | ("dev/net/tun", 10, 200) | ("dev/urandom", 1, 9)
                ) || (name == "dev/userfaultfd" && excluded.is_some_and(|held| same_node(&m, held)))
            } else {
                false
            };
            if !allowed || records.len() >= 64 {
                return Err(err(&format!("unexpected reachable jail object: {name}")));
            }
            records.insert(name.to_owned(),serde_json::json!({"dev":m.dev(),"ino":m.ino(),"mode":m.mode(),"uid":m.uid(),"gid":m.gid(),"rdev":m.rdev()}));
            if kind.is_dir() {
                queue.push(path);
            }
        }
    }
    for name in [
        "firecracker",
        "realm-vmm",
        "kernel",
        "rootfs.ext4",
        "dev/kvm",
        "run",
    ] {
        if !records.contains_key(name) {
            return Err(err("required jail resource absent"));
        }
    }
    Ok(records)
}
// Called only for a stopped, originally traced process whose pidfd is held.
// A proc exe magic link may have no pathname in the observer's mount namespace.
// Measure the opened kernel object, preserving the regular/single-link/version
// requirements; the caller still checks expected inode, digest and incarnation.
fn measure_actual_exec(pid: u32) -> io::Result<(FileIdentity, File)> {
    let path = PathBuf::from(format!("/proc/{pid}/exe"));
    let file = File::open(&path)
        .map_err(|error| operation_error(format!("actual exec open {}", path.display()), error))?;
    let identity = FileIdentity::measure_open_file_detailed(&path, &file)
        .map_err(|error| operation_error("actual exec object", io::Error::other(error)))?;
    Ok((identity, file))
}

impl PreparedCodingFence {
    pub(crate) fn create(
        state: &Path,
        jail: &Path,
        source: &Path,
        uid: u32,
        gid: u32,
    ) -> io::Result<Self> {
        if STAGE.is_empty() {
            return Err(err("static coding fence unavailable for this build"));
        }
        if uid == 0 || gid == 0 {
            return Err(err("dedicated non-root jail identity required"));
        }
        let root_pin = open_dir(jail)?;
        let userfaultfd_minor = parse_userfaultfd_minor(&fs::read_to_string("/proc/misc")?)?;
        match jail.join("dev/userfaultfd").symlink_metadata() {
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
            Ok(_) => return Err(err("preexisting userfaultfd object before official jailer")),
        }
        let directory = state.join("coding-fence");
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let executable = directory.join("firecracker");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&executable)?;
        f.write_all(STAGE)?;
        f.sync_all()?;
        let target = jail.join(OFFICIAL);
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(source)?;
        let original =
            FileIdentity::measure(source).map_err(|_| err("official source identity"))?;
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o555)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&target)?;
        io::copy(&mut input, &mut out)?;
        out.set_permissions(fs::Permissions::from_mode(0o555))?;
        out.sync_all()?;
        drop(out);
        let official = FileIdentity::measure(&target).map_err(|_| err("official copy identity"))?;
        if original.blake3() != official.blake3()
            || FileIdentity::measure(source).map_err(|_| err("official changed"))? != original
        {
            return Err(err("official copy differs"));
        }
        File::open(&directory)?.sync_all()?;
        File::open(jail)?.sync_all()?;
        Ok(Self {
            executable,
            official,
            jail: jail.to_owned(),
            journal: OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(directory.join("exec.jsonl"))?,
            journal_path: directory.join("exec.jsonl"),
            root_pin,
            uid,
            gid,
            userfaultfd_minor,
            #[cfg(test)]
            stop_probe: None,
        })
    }
    fn event(&mut self, value: serde_json::Value) -> io::Result<()> {
        self.journal.write_all(&serde_json::to_vec(&value)?)?;
        self.journal.write_all(b"\n")?;
        self.journal.sync_all()
    }
    /// Test-only diagnostic. Shares all normal exec-chain validation, but
    /// succeeds only after the stopped target and original jailer are reaped.
    /// Returns ordinary diagnostic data, never an EnforcedCodingLaunch.
    #[cfg(test)]
    pub(crate) fn spawn_exec_stop_probe(
        mut self,
        command: &mut Command,
        timeout: Duration,
        expected: Option<ExecStopExpectation>,
    ) -> io::Result<serde_json::Value> {
        let result = std::sync::Arc::new(std::sync::Mutex::new(None));
        self.stop_probe = Some(ExecStopProbe {
            result: result.clone(),
            expected,
        });
        match self.spawn(command, timeout) {
            Err(error) if error.to_string() == "test-only stopped exec diagnostic complete" => {
                result
                    .lock()
                    .map_err(|_| err("stop probe lock poisoned"))?
                    .take()
                    .ok_or_else(|| err("stop probe completion absent"))
            }
            Err(error) => Err(error),
            Ok((mut child, _, owner)) => {
                // Defensive cleanup if a future refactor ever ignores the probe.
                // Never export the running fence owner through this API.
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        owner._pidfd.as_raw_fd(),
                        libc::SIGKILL,
                        0,
                        0,
                    );
                }
                let _ = child.kill();
                let deadline = Instant::now() + Duration::from_secs(2);
                while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(err("stop probe unexpectedly returned a running owner"))
            }
        }
    }
    pub(crate) fn spawn(
        mut self,
        command: &mut Command,
        timeout: Duration,
    ) -> io::Result<(Child, VmmIncarnation, EnforcedCodingLaunch)> {
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            command.pre_exec(|| {
                // Creation precedes the official jailer and stage. Failure is a
                // launch refusal, never a shared-namespace fallback.
                if libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWIPC) != 0
                    || libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        self.event(serde_json::json!({"phase":"SPAWN_ATTEMPT","stage_blake3":stage_digest(),"profile":blake3::hash(crate::coding_submission::NATIVE_EXECUTION_PROFILE.as_bytes()).to_hex().to_string()}))?;
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                self.event(serde_json::json!({"phase":"SPAWN_REFUSED","error":error.to_string()}))?;
                return Err(error);
            }
        };
        let parent = child.id();
        let mut tracked = BTreeSet::from([parent]);
        fn pin(pid: u32) -> io::Result<File> {
            use std::os::fd::FromRawFd;
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { File::from_raw_fd(fd as i32) })
        }
        let parent_pin = match pin(parent) {
            Ok(pin) => pin,
            Err(error) => {
                let fallback = fallback_unpinned_descendant(parent);
                let mut record = diagnostic_terminal_bundle(
                    &BTreeSet::from([parent]),
                    &BTreeMap::from([(parent, fallback)]),
                    false,
                );
                record["phase"] = serde_json::json!("REFUSAL_TERMINAL_RECEIPTS");
                self.event(record)?;
                return Err(error);
            }
        };
        let mut pins = BTreeMap::from([(parent, parent_pin)]);
        let mut discovered = BTreeSet::from([parent]);
        let mut unresolved_discovery = false;
        let mut starts = BTreeMap::new();
        let mut terminal_receipts = BTreeMap::new();
        let result = (|| {
            starts.insert(parent, process_start_ticks(parent)?);
            let mut status = 0;
            let deadline = Instant::now() + timeout;
            loop {
                let got = unsafe { libc::waitpid(parent as i32, &mut status, libc::WNOHANG) };
                if got < 0 {
                    return Err(io::Error::last_os_error());
                }
                if got == parent as i32 {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(err("bounded initial exec-stop deadline"));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            self.event(
                serde_json::json!({"phase":"JAILER_EXEC_WAIT","pid":parent,"raw_status":status}),
            )?;
            if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGTRAP {
                return Err(err("jailer initial exec stop"));
            }
            let jailer =
                VmmIncarnation::capture_linux(parent).map_err(|_| err("jailer exec identity"))?;
            let original_jailer_pin = {
                let (actual, pin) = measure_actual_exec(parent)?;
                let declared = FileIdentity::measure(Path::new(command.get_program()))
                    .map_err(|e| err(&format!("stop probe jailer declared object: {e:?}")))?;
                if actual.device_inode() != declared.device_inode()
                    || actual.blake3() != declared.blake3()
                    || actual.owner() != declared.owner()
                    || actual.mode() != declared.mode()
                    || jailer.executable_identity().device_inode() != actual.device_inode()
                    || jailer.executable_identity().blake3() != actual.blake3()
                {
                    return Err(err(
                        "stop probe original jailer differs from declared pinned object",
                    ));
                }
                self.event(serde_json::json!({"phase":"ORIGINAL_JAILER_EXEC_PINNED","jailer":jailer,"actual_exec":actual}))?;
                (actual, pin)
            };
            let net = ns(parent, "net")?;
            let ipc = ns(parent, "ipc")?;
            if net == ns(std::process::id(), "net")? || ipc == ns(std::process::id(), "ipc")? {
                return Err(err("private endpoint namespaces absent"));
            }
            let options = libc::PTRACE_O_TRACEFORK
                | libc::PTRACE_O_TRACECLONE
                | libc::PTRACE_O_TRACEVFORK
                | libc::PTRACE_O_TRACEEXEC
                | libc::PTRACE_O_EXITKILL;
            if unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, parent, 0, options) } == -1
                || unsafe { libc::ptrace(libc::PTRACE_CONT, parent, 0, 0) } == -1
            {
                return Err(io::Error::last_os_error());
            }
            let mut stage_seen = None;
            #[cfg(test)]
            let mut device_exclusion_receipt = None;
            loop {
                for pid in tracked.clone() {
                    // Preserve the original Child's exit status for its owner.
                    if pid == parent {
                        let mut peek: libc::siginfo_t = unsafe { std::mem::zeroed() };
                        if unsafe {
                            libc::waitid(
                                libc::P_PID,
                                pid,
                                &mut peek,
                                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                            )
                        } != 0
                        {
                            return Err(io::Error::last_os_error());
                        }
                        if unsafe { peek.si_pid() } != 0 {
                            self.event(serde_json::json!({"phase":"JAILER_WAIT_PEEK","pid":pid,"si_code":peek.si_code}))?;
                            if [libc::CLD_EXITED, libc::CLD_KILLED, libc::CLD_DUMPED]
                                .contains(&peek.si_code)
                            {
                                tracked.remove(&pid);
                                continue;
                            }
                        }
                    }
                    let got = unsafe {
                        libc::waitpid(pid as i32, &mut status, libc::__WALL | libc::WNOHANG)
                    };
                    if got == 0 {
                        continue;
                    }
                    if got < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    self.event(serde_json::json!({"phase":"TRACE_WAIT","pid":pid,"raw_status":status,"event":status>>16}))?;
                    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                        return Err(err("execution chain exited before official VMM exec"));
                    }
                    if !libc::WIFSTOPPED(status) {
                        return Err(err("unexpected execution-chain wait state"));
                    }
                    let event = status >> 16;
                    if [
                        libc::PTRACE_EVENT_FORK,
                        libc::PTRACE_EVENT_CLONE,
                        libc::PTRACE_EVENT_VFORK,
                    ]
                    .contains(&event)
                    {
                        let mut next: libc::c_ulong = 0;
                        if unsafe { libc::ptrace(libc::PTRACE_GETEVENTMSG, pid, 0, &mut next) }
                            == -1
                        {
                            unresolved_discovery = true;
                            return Err(io::Error::last_os_error());
                        }
                        if next == 0
                            || next > i32::MAX as libc::c_ulong
                            || !discovered.insert(next as u32)
                        {
                            unresolved_discovery = true;
                            return Err(err("invalid or duplicate original descendant discovery"));
                        }
                        self.event(serde_json::json!({"phase":"ORIGINAL_DESCENDANT_DISCOVERED","parent":pid,"pid":next}))?;
                        let next_pin = match pin(next as u32) {
                            Ok(pin) => pin,
                            Err(error) => {
                                terminal_receipts
                                    .insert(next as u32, fallback_unpinned_descendant(next as u32));
                                return Err(error);
                            }
                        };
                        pins.insert(next as u32, next_pin);
                        starts.insert(next as u32, process_start_ticks(next as u32)?);
                        if tracked.len() != 1 || stage_seen.is_some() {
                            return Err(err("unexpected execution-chain descendant"));
                        }
                        tracked.insert(next as u32);
                    } else if event == libc::PTRACE_EVENT_EXEC {
                        let (actual, _actual_exec_pin) = measure_actual_exec(pid)?;
                        if stage_seen.is_none() {
                            let expected = FileIdentity::measure(&self.jail.join("firecracker"))
                                .map_err(|error| err(&format!("actual stage copy: {error:?}")))?;
                            if pid == parent
                                || actual.device_inode() != expected.device_inode()
                                || fs::read(format!("/proc/{pid}/exe")).map_err(|e| {
                                    operation_error(format!("stage exec read /proc/{pid}/exe"), e)
                                })? != STAGE
                            {
                                return Err(err("stage exec differs"));
                            }
                            verify_pidfd(pid, &pins[&pid])?;
                            if process_start_ticks(pid)? != starts[&pid] {
                                return Err(err("original stage incarnation differs"));
                            }
                            verify_root_identity(&self.jail, &self.root_pin, pid)?;
                            // The child is stopped BEFORE trusted stage startup.
                            // The official jailer has finished its chowns.
                            protect(&self.jail, 0o755)?;
                            protect(&self.jail.join("firecracker"), 0o555)?;
                            protect(&self.jail.join(OFFICIAL), 0o555)?;
                            let stage = FileIdentity::measure(&self.jail.join("firecracker"))
                                .map_err(|error| err(&format!("protected stage: {error:?}")))?;
                            let birth = VmmIncarnation::capture_linux(pid)
                                .map_err(|error| err(&format!("stage birth: {error:?}")))?;
                            // Vendor device creation is finished and no original
                            // jailer writer remains alive before we mutate its jail.
                            let peek = wait_original_terminal(
                                parent,
                                &pins[&parent],
                                starts[&parent],
                                Duration::from_secs(2),
                                true,
                            )?;
                            if peek["si_code"] != libc::CLD_EXITED || peek["si_status"] != 0 {
                                return Err(err(
                                    "original jailer did not normally finish before stage release",
                                ));
                            }
                            self.event(serde_json::json!({"phase":"ORIGINAL_JAILER_TERMINAL_PEEK","receipt":peek}))?;
                            let root_pin = self.root_pin.try_clone()?;
                            let descriptors = verify_no_userfaultfd_fds(
                                pid,
                                pins.get(&pid)
                                    .ok_or_else(|| err("original stage pidfd absent"))?,
                                self.userfaultfd_minor,
                            )?;
                            self.event(serde_json::json!({"phase":"STAGE_FD_CENSUS","pid":pid,
                                "start_time_ticks":birth.start_time_ticks(),"descriptors":descriptors,"userfaultfd_inherited":false}))?;
                            let exclusion = UserfaultfdExclusion::prepare(
                                &self.jail,
                                &root_pin,
                                self.uid,
                                self.gid,
                                self.userfaultfd_minor,
                                pid,
                            )?;
                            let temporary = exclusion.as_ref().map(|e| &e.node_metadata);
                            let before =
                                census_origin_before_exclusion(&self.jail, pid, temporary)?;
                            self.event(serde_json::json!({"phase":"DEVICE_EXCLUSION_BEFORE", "pid":pid,
                                "stage_start_ticks":birth.start_time_ticks(), "census":before,
                                "expected_userfaultfd_minor":self.userfaultfd_minor,
                                "original_jailer":original_jailer_pin.0, "actual_stage":stage, "authority":"NONE"}))?;
                            if let Some(exclusion) = exclusion {
                                let receipt = exclusion.remove(&self.jail, &root_pin, pid)?;
                                self.event(receipt.clone())?;
                                #[cfg(test)]
                                {
                                    device_exclusion_receipt = Some(receipt);
                                }
                            }
                            let origin = census_origin(&self.jail, pid)?;
                            stage_seen = Some((pid, birth.start_time_ticks(), stage, origin));
                        } else {
                            let (expected_pid, start, stage, origin) =
                                stage_seen.take().ok_or_else(|| err("stage absent"))?;
                            let final_process = VmmIncarnation::capture_linux(pid)
                                .map_err(|error| err(&format!("VMM birth: {error:?}")))?;
                            if pid != expected_pid
                                || start != final_process.start_time_ticks()
                                || actual.device_inode() != self.official.device_inode()
                                || actual.blake3() != self.official.blake3()
                                || ns(pid, "net")? != net
                                || ns(pid, "ipc")? != ipc
                            {
                                return Err(err("stage-to-VMM identity differs"));
                            }
                            let text = fs::read_to_string(format!("/proc/{pid}/status"))?;
                            for (key, value) in [
                                ("NoNewPrivs:", "1"),
                                ("Seccomp:", "2"),
                                ("CapEff:", "0000000000000000"),
                                ("CapPrm:", "0000000000000000"),
                                ("CapInh:", "0000000000000000"),
                                ("CapAmb:", "0000000000000000"),
                            ] {
                                if !text.lines().any(|line| {
                                    line.strip_prefix(key).is_some_and(|s| s.trim() == value)
                                }) {
                                    return Err(err("VMM enforcement state differs"));
                                }
                            }
                            self.event(serde_json::json!({"phase":"OFFICIAL_EXEC_STOP","pid":pid,"start":start,"net":net,"ipc":ipc,"stage":stage,"actual_official":actual}))?;
                            #[cfg(test)]
                            if let Some(probe) = self.stop_probe.clone() {
                                // No DETACH/CONT has occurred since the final
                                // validated EXEC event. The VMM has executed
                                // zero userspace instructions. Kill through
                                // its original pidfd before minting any owner.
                                let (jailer_object, jailer_pin) = &original_jailer_pin;
                                let retained = FileIdentity::measure_open_file_detailed(
                                    Path::new(jailer_object.path()),
                                    jailer_pin,
                                )
                                .map_err(|e| {
                                    operation_error(
                                        "stop probe jailer remeasurement",
                                        io::Error::other(e),
                                    )
                                })?;
                                if retained.device_inode() != jailer_object.device_inode()
                                    || retained.blake3() != jailer_object.blake3()
                                    || retained.owner() != jailer_object.owner()
                                    || retained.mode() != jailer_object.mode()
                                {
                                    return Err(err("stop probe held jailer object changed"));
                                }
                                let observed = probe
                                    .expected
                                    .as_ref()
                                    .map(|expected| {
                                        observe_exec_stop(pid, parent, &self.jail, expected)
                                    })
                                    .transpose()?;
                                if let Some(observed) = &observed {
                                    self.event(serde_json::json!({"phase":"TEST_ONLY_LIVE_STOP_OBSERVED","observations":observed.record}))?;
                                }
                                let target = pins
                                    .get(&pid)
                                    .ok_or_else(|| err("stop probe pidfd absent"))?;
                                let jailer_terminal = terminate_original(
                                    parent,
                                    &pins[&parent],
                                    starts[&parent],
                                    Duration::from_secs(2),
                                )?;
                                terminal_receipts.insert(parent, jailer_terminal.clone());
                                if !((jailer_terminal["si_code"] == libc::CLD_EXITED
                                    && jailer_terminal["si_status"] == 0)
                                    || (jailer_terminal["si_code"] == libc::CLD_KILLED
                                        && jailer_terminal["si_status"] == libc::SIGKILL))
                                {
                                    return Err(err("stop probe jailer terminal status differs"));
                                }
                                // Parent receipt is consumed first; original clone
                                // is now adopted by this scoped subreaper.
                                let terminal = terminate_original(
                                    pid,
                                    target,
                                    starts[&pid],
                                    Duration::from_secs(2),
                                )?;
                                terminal_receipts.insert(pid, terminal.clone());
                                if terminal["si_code"] != libc::CLD_KILLED
                                    || terminal["si_status"] != libc::SIGKILL
                                {
                                    return Err(err("stop probe target terminal status differs"));
                                }
                                let observations =
                                    observed.map(ExecStopObservation::after_reap).transpose()?;
                                let custody = diagnostic_terminal_bundle(
                                    &discovered,
                                    &terminal_receipts,
                                    unresolved_discovery,
                                );
                                if custody["complete"] != true
                                    || discovered != BTreeSet::from([parent, pid])
                                {
                                    return Err(err("original inner custody remains incomplete"));
                                }
                                let record = serde_json::json!({
                                    "phase":"TEST_ONLY_EXEC_STOP_REAPED", "authority":"NONE",
                                    "vmm_userspace_executed":false, "pid":pid,"start":start,
                                    "stage":stage,"actual_official":actual,"net":net,"ipc":ipc,
                                    "origin":origin,"target_terminal":terminal,
                                    "original_jailer":jailer,"jailer_exec_stop_identity":jailer_object,
                                    "jailer_object_revalidated":true,
                                    "jailer_exit_status":jailer_terminal,
                                    "terminal_receipts":custody,
                                    "excluded_optional_userfaultfd":device_exclusion_receipt,
                                    "host_userfaultfd_minor":self.userfaultfd_minor,
                                    "jailer_reaped":true,"qualification":"NOT_REGISTERED",
                                    "live_stop_observations":observations
                                });
                                self.event(record.clone())?;
                                *probe
                                    .result
                                    .lock()
                                    .map_err(|_| err("stop probe lock poisoned"))? = Some(record);
                                return Err(err("test-only stopped exec diagnostic complete"));
                            }
                            let journal_pin = File::open(&self.journal_path)?;
                            let journal_identity =
                                FileIdentity::measure_open_file(&self.journal_path, &journal_pin)
                                    .map_err(|_| err("original exec journal unavailable"))?;
                            let owner = EnforcedCodingLaunch {
                                pid,
                                start,
                                stage,
                                official: self.official.clone(),
                                net,
                                ipc,
                                jail: self.jail.clone(),
                                origin,
                                journal_pin,
                                journal_identity,
                                _root_pin: File::open(&self.jail)?,
                                stage_pin: File::open(self.jail.join("firecracker"))?,
                                official_pin: File::open(self.jail.join(OFFICIAL))?,
                                _net_pin: File::open(format!("/proc/{pid}/ns/net"))?,
                                _ipc_pin: File::open(format!("/proc/{pid}/ns/ipc"))?,
                                _pidfd: pins
                                    .get(&pid)
                                    .ok_or_else(|| err("original pidfd absent"))?
                                    .try_clone()?,
                            };
                            if unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) } == -1 {
                                return Err(io::Error::last_os_error());
                            }
                            tracked.remove(&pid);
                            // The short-lived original jailer may still be
                            // running; its owner consumes its normal exit with
                            // Child::wait. No trace stop is silently discarded.
                            for other in &tracked {
                                if *other != parent {
                                    return Err(err("unexpected traced process"));
                                }
                            }
                            return Ok((jailer, owner));
                        }
                    } else if libc::WSTOPSIG(status) != libc::SIGSTOP
                        && libc::WSTOPSIG(status) != libc::SIGTRAP
                    {
                        return Err(err("execution-chain signal"));
                    }
                    if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) } == -1 {
                        return Err(io::Error::last_os_error());
                    }
                }
                if Instant::now() >= deadline {
                    return Err(err("bounded execution-chain deadline"));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        })();
        match result {
            Ok((jailer, owner)) => Ok((child, jailer, owner)),
            Err(error) => {
                #[cfg(test)]
                if self.stop_probe.is_some()
                    && error.to_string() == "test-only stopped exec diagnostic complete"
                {
                    return Err(error);
                }
                let _=self.event(serde_json::json!({"phase":"CHAIN_REFUSED","error":error.to_string(),"tracked":tracked}));
                // Kill through every retained handle even when birth capture
                // failed. Missing identity prevents a complete receipt, never
                // permits an unowned survivor or a PID-based substitute.
                for pin in pins.values() {
                    unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            pin.as_raw_fd(),
                            libc::SIGKILL,
                            0,
                            0,
                        );
                    }
                }
                // Reap parent first so original clone descendants are adopted.
                for pid in std::iter::once(parent)
                    .chain(discovered.iter().copied().filter(|p| *p != parent))
                {
                    if terminal_receipts.contains_key(&pid) {
                        continue;
                    }
                    let observed = starts
                        .get(&pid)
                        .ok_or_else(|| err("original birth identity not captured"))
                        .and_then(|start| {
                            pins.get(&pid)
                                .ok_or_else(|| err("original pidfd not acquired"))
                                .and_then(|pin| {
                                    terminate_original(pid, pin, *start, Duration::from_secs(2))
                                })
                        });
                    terminal_receipts.insert(pid, match observed {
                        Ok(receipt)=>receipt,
                        Err(e)=>serde_json::json!({"pid":pid,"status":"INCOMPLETE","error":e.to_string(),"reaped":null}),
                    });
                }
                let mut custody = diagnostic_terminal_bundle(
                    &discovered,
                    &terminal_receipts,
                    unresolved_discovery,
                );
                custody["phase"] = serde_json::json!("REFUSAL_TERMINAL_RECEIPTS");
                self.event(custody)?;
                Err(error)
            }
        }
    }
}
#[cfg(test)]
fn stop_status(text: &str, uid: u32, gid: u32) -> io::Result<()> {
    fn values<'a>(text: &'a str, key: &str) -> io::Result<Vec<&'a str>> {
        let mut rows = text.lines().filter_map(|line| line.strip_prefix(key));
        let row = rows.next().ok_or_else(|| err("stop status field absent"))?;
        if rows.next().is_some() {
            return Err(err("duplicate stop status field"));
        }
        Ok(row.split_whitespace().collect())
    }
    for (key, expected) in [("Uid:", uid), ("Gid:", gid)] {
        let fields = values(text, key)?;
        if fields.len() != 4
            || !fields
                .iter()
                .all(|s| s.parse::<u32>().ok() == Some(expected))
        {
            return Err(err("stop credentials differ from production plan"));
        }
    }
    if uid == 0
        || gid == 0
        || !values(text, "Groups:")?.is_empty()
        || values(text, "NSpid:")?.last() != Some(&"1")
        || values(text, "Threads:")? != ["1"]
    {
        return Err(err("stop identity is not dedicated PID init"));
    }
    for (key, expected) in [
        ("NoNewPrivs:", "1"),
        ("Seccomp:", "2"),
        ("CapEff:", "0000000000000000"),
        ("CapPrm:", "0000000000000000"),
        ("CapInh:", "0000000000000000"),
        ("CapAmb:", "0000000000000000"),
    ] {
        if values(text, key)? != [expected] {
            return Err(err("stop privilege enforcement differs"));
        }
    }
    Ok(())
}
#[cfg(test)]
fn cgroup_leaf(root: &File, name: &str) -> io::Result<String> {
    use std::{io::Read, os::fd::FromRawFd};
    let name = std::ffi::CString::new(name).map_err(|_| err("invalid cgroup leaf"))?;
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(operation_error(
            "read held cgroup leaf",
            io::Error::last_os_error(),
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut text = String::new();
    file.take(65537).read_to_string(&mut text)?;
    if text.len() > 65536 {
        return Err(err("oversized cgroup observation"));
    }
    Ok(text)
}
#[cfg(test)]
struct StopCgroupReadout {
    membership: String,
    procs: String,
    limits: [String; 3],
}
#[cfg(test)]
impl StopCgroupReadout {
    fn validate(&self, expected: &ExecStopExpectation, pid: u32, parent: u32) -> io::Result<()> {
        let unified: Vec<_> = self
            .membership
            .lines()
            .filter_map(|line| line.strip_prefix("0::"))
            .collect();
        if unified.len() != 1
            || Path::new(unified[0]) != Path::new("/").join(&expected.cgroup_relative)
        {
            return Err(err("stopped child belongs to different cgroup"));
        }
        let members = self
            .procs
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| err("invalid live cgroup members"))?;
        if !members.contains(&pid)
            || members
                .iter()
                .any(|member| *member != pid && *member != parent)
        {
            return Err(err(
                "live cgroup lacks original child or contains foreign process",
            ));
        }
        if self.limits[0].trim().parse::<u64>().ok() != Some(expected.memory_max)
            || self.limits[1].trim().parse::<u32>().ok() != Some(expected.pids_max)
            || self.limits[2].split_whitespace().collect::<Vec<_>>() != ["100000", "100000"]
        {
            return Err(err("live cgroup limits differ from production plan"));
        }
        Ok(())
    }
}
#[cfg(test)]
struct ExecStopObservation {
    record: serde_json::Value,
    group: File,
    path: PathBuf,
    identity: (u64, u64),
    limits: [String; 3],
    namespace_pins: Vec<File>,
}
#[cfg(test)]
impl ExecStopObservation {
    fn after_reap(mut self) -> io::Result<serde_json::Value> {
        let named = fs::symlink_metadata(&self.path)?;
        let held = self.group.metadata()?;
        if !named.is_dir()
            || (named.dev(), named.ino()) != self.identity
            || (held.dev(), held.ino()) != self.identity
        {
            return Err(err("original cgroup object changed"));
        }
        for (i, name) in ["memory.max", "pids.max", "cpu.max"].iter().enumerate() {
            if cgroup_leaf(&self.group, name)? != self.limits[i] {
                return Err(err("cgroup limits changed during cleanup"));
            }
        }
        let procs = cgroup_leaf(&self.group, "cgroup.procs")?;
        let events = cgroup_leaf(&self.group, "cgroup.events")?;
        if !procs.trim().is_empty()
            || !events
                .lines()
                .any(|line| line.split_whitespace().collect::<Vec<_>>() == ["populated", "0"])
        {
            return Err(err("original cgroup remains populated"));
        }
        for pin in &self.namespace_pins {
            pin.metadata()?;
        }
        self.record["terminal"] = serde_json::json!({"same_cgroup_inode":true,"procs_raw":procs,"events_raw":events,"empty":true,"limits_unchanged":true});
        Ok(self.record)
    }
}
#[cfg(test)]
fn observe_exec_stop(
    pid: u32,
    parent: u32,
    jail: &Path,
    expected: &ExecStopExpectation,
) -> io::Result<ExecStopObservation> {
    use std::path::Component;
    if expected.cgroup_relative.as_os_str().is_empty()
        || !expected
            .cgroup_relative
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
    {
        return Err(err("non-relative expected cgroup"));
    }
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    stop_status(&status, expected.uid, expected.gid)?;
    let root = fs::metadata(jail)?;
    let mut roots = serde_json::Map::new();
    for name in ["root", "cwd"] {
        let actual = fs::metadata(format!("/proc/{pid}/{name}"))?;
        if (actual.dev(), actual.ino()) != (root.dev(), root.ino()) {
            return Err(err("stopped root/cwd differs from original jail"));
        }
        roots.insert(
            name.into(),
            serde_json::json!({"dev":actual.dev(),"ino":actual.ino()}),
        );
    }
    let mut namespace_pins = Vec::new();
    let mut namespaces = serde_json::Map::new();
    for name in ["net", "ipc", "mnt", "pid"] {
        let pin = File::open(format!("/proc/{pid}/ns/{name}"))?;
        let actual = pin.metadata()?;
        let owner = ns(std::process::id(), name)?;
        if (actual.dev(), actual.ino()) == owner {
            return Err(err("stopped namespace shared with host owner"));
        }
        namespaces.insert(
            name.into(),
            serde_json::json!({"dev":actual.dev(),"ino":actual.ino(),"owner":owner,"private":true}),
        );
        namespace_pins.push(pin);
    }
    let mut fds = fs::read_dir(format!("/proc/{pid}/fd"))?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    fds.sort();
    if fds != ["0", "1", "2"].map(std::ffi::OsString::from) {
        return Err(err("unexpected descriptor at VMM exec stop"));
    }
    let mut stdio = Vec::new();
    for (fd, path) in [(1, &expected.stdout), (2, &expected.stderr)] {
        let actual = fs::metadata(format!("/proc/{pid}/fd/{fd}"))?;
        let named = fs::symlink_metadata(path)?;
        if !actual.is_file()
            || actual.nlink() != 1
            || actual.uid() != 0
            || actual.gid() != 0
            || (actual.dev(), actual.ino()) != (named.dev(), named.ino())
            || !named.is_file()
        {
            return Err(err("stopped stdio differs from original native log"));
        }
        stdio.push(serde_json::json!({"fd":fd,"dev":actual.dev(),"ino":actual.ino(),"uid":actual.uid(),"gid":actual.gid(),"nlink":actual.nlink(),"path":path}));
    }
    let stdin = fs::metadata(format!("/proc/{pid}/fd/0"))?;
    if !stdin.file_type().is_char_device()
        || libc::major(stdin.rdev()) != 1
        || libc::minor(stdin.rdev()) != 3
    {
        return Err(err("stopped stdin is not null"));
    }
    let path = Path::new("/sys/fs/cgroup").join(&expected.cgroup_relative);
    let group = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let meta = group.metadata()?;
    let readout = StopCgroupReadout {
        membership: fs::read_to_string(format!("/proc/{pid}/cgroup"))?,
        procs: cgroup_leaf(&group, "cgroup.procs")?,
        limits: [
            cgroup_leaf(&group, "memory.max")?,
            cgroup_leaf(&group, "pids.max")?,
            cgroup_leaf(&group, "cpu.max")?,
        ],
    };
    readout.validate(expected, pid, parent)?;
    let record = serde_json::json!({"status_raw":status,"roots":roots,"namespaces":namespaces,"stdio":stdio,"descriptors":[0,1,2],
        "cgroup":{"path":path,"dev":meta.dev(),"ino":meta.ino(),"membership_raw":readout.membership,"procs_raw":readout.procs,
        "memory_max_raw":readout.limits[0],"pids_max_raw":readout.limits[1],"cpu_max_raw":readout.limits[2],
        "expected_memory_max":expected.memory_max,"expected_pids_max":expected.pids_max,"membership_checked":true,"limits_checked":true}});
    Ok(ExecStopObservation {
        record,
        group,
        path,
        identity: (meta.dev(), meta.ino()),
        limits: readout.limits,
        namespace_pins,
    })
}

/// Only callable with the original pidfd of an observed ptrace EXEC stop.
/// No ptrace CONT/DETACH and no PID-based signal is used here.
#[cfg(test)]
fn kill_and_reap_exec_stop(
    pid: u32,
    pidfd: &File,
    timeout: Duration,
) -> io::Result<serde_json::Value> {
    let receipt = terminate_original(pid, pidfd, process_start_ticks(pid)?, timeout)?;
    if receipt["si_code"] != libc::CLD_KILLED || receipt["si_status"] != libc::SIGKILL {
        return Err(err("exec-stop unexpected terminal status"));
    }
    Ok(receipt)
}

impl EnforcedCodingLaunch {
    pub(crate) fn executable(&self) -> PathBuf {
        self.jail.join(OFFICIAL)
    }
    pub(crate) fn revalidate_objects(&self) -> io::Result<()> {
        for (file, expected) in [
            (&self.stage_pin, &self.stage),
            (&self.official_pin, &self.official),
            (&self.journal_pin, &self.journal_identity),
        ] {
            let actual = FileIdentity::measure_open_file(Path::new(expected.path()), file)
                .map_err(|_| err("fence object pin changed"))?;
            if actual.device_inode() != expected.device_inode()
                || actual.blake3() != expected.blake3()
                || actual.owner() != expected.owner()
                || actual.mode() != expected.mode()
            {
                return Err(err("fence consumed object changed"));
            }
        }
        Ok(())
    }
    pub(crate) fn matches_terminal(
        &self,
        measured: &crate::measured_launch::MeasuredLaunchSession,
    ) -> bool {
        let pinned_ns = |file: &File, expected: (u64, u64)| {
            file.metadata()
                .is_ok_and(|m| (m.dev(), m.ino()) == expected)
        };
        self.revalidate_objects().is_ok()
            && self.pid == measured.vmm().pid()
            && self.start == measured.vmm().start_time_ticks()
            && self.official.device_inode() == measured.firecracker_identity().device_inode()
            && self.official.blake3() == measured.firecracker_identity().blake3()
            && self.stage.blake3() == stage_digest()
            && pinned_ns(&self._net_pin, self.net)
            && pinned_ns(&self._ipc_pin, self.ipc)
    }
    pub(crate) fn revalidate_live(
        &self,
        measured: &crate::measured_launch::MeasuredLaunchSession,
    ) -> io::Result<()> {
        self.revalidate_objects()?;
        let actual =
            VmmIncarnation::capture_linux(self.pid).map_err(|_| err("fenced process absent"))?;
        if self.pid != measured.vmm().pid()
            || self.start != actual.start_time_ticks()
            || !actual.same_process(measured.vmm())
            || ns(self.pid, "net")? != self.net
            || ns(self.pid, "ipc")? != self.ipc
        {
            return Err(err("fenced process identity changed"));
        }
        Ok(())
    }
    pub(crate) fn record(&self) -> serde_json::Value {
        serde_json::json!({"policy":"realm.coding-fence/v1","prelaunch_profile_blake3":blake3::hash(crate::coding_submission::NATIVE_EXECUTION_PROFILE.as_bytes()).to_hex().to_string(),"origin":self.origin,"original_exec_journal":self.journal_identity,"pid":self.pid,"start_ticks":self.start,"stage":self.stage,"official":self.official,"net_namespace":self.net,"ipc_namespace":self.ipc,"qualification":"NOT_REGISTERED","policy_basis":"native-observed fixed-stage exec control flow; not kernel policy readback"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        os::{
            linux::net::SocketAddrExt,
            unix::net::{SocketAddr, UnixListener},
        },
        process::Stdio,
    };
    fn compile(path: &Path, source: &[u8]) -> PathBuf {
        fs::write(path.with_extension("c"), source).unwrap();
        let out = Command::new("cc")
            .args([
                "-static",
                "-std=gnu11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pthread",
            ])
            .arg(path.with_extension("c"))
            .arg("-o")
            .arg(path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        path.to_owned()
    }
    fn setup(base: &Path, name: &str, worker: &Path) -> (PreparedCodingFence, PathBuf) {
        let state = base.join(name);
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let jail = state.join("root");
        fs::create_dir(&jail).unwrap();
        for dir in ["run", "dev"] {
            fs::create_dir(jail.join(dir)).unwrap();
        }
        fs::set_permissions(jail.join("dev"), fs::Permissions::from_mode(0o755)).unwrap();
        let run = File::open(jail.join("run")).unwrap();
        assert_eq!(unsafe { libc::fchown(run.as_raw_fd(), 65534, 65534) }, 0);
        fs::set_permissions(jail.join("run"), fs::Permissions::from_mode(0o700)).unwrap();
        for leaf in ["kernel", "rootfs.ext4"] {
            fs::write(jail.join(leaf), b"K").unwrap();
            fs::set_permissions(jail.join(leaf), fs::Permissions::from_mode(0o444)).unwrap();
        }
        let kvm =
            std::ffi::CString::new(jail.join("dev/kvm").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mknod(kvm.as_ptr(), libc::S_IFCHR | 0o666, libc::makedev(10, 232)) },
            0
        );
        let prepared = PreparedCodingFence::create(&state, &jail, worker, 65534, 65534).unwrap();
        // TEST_ONLY fixture for documented official-jailer directory/node setup.
        let dev = open_dir(&jail.join("dev")).unwrap();
        assert_eq!(unsafe { libc::fchown(dev.as_raw_fd(), 65534, 65534) }, 0);
        assert_eq!(unsafe { libc::fchmod(dev.as_raw_fd(), 0o700) }, 0);
        if let Some(minor) = prepared.userfaultfd_minor {
            let path =
                std::ffi::CString::new(jail.join("dev/userfaultfd").as_os_str().as_encoded_bytes())
                    .unwrap();
            assert_eq!(
                unsafe {
                    libc::mknod(
                        path.as_ptr(),
                        libc::S_IFCHR | 0o600,
                        libc::makedev(10, minor),
                    )
                },
                0
            );
            assert_eq!(unsafe { libc::chown(path.as_ptr(), 65534, 65534) }, 0);
        }
        fs::copy(&prepared.executable, jail.join("firecracker")).unwrap();
        (prepared, jail)
    }
    fn command(shim: &Path, jail: &Path, mode: &str, backing: &File) -> Command {
        let mut command = Command::new(shim);
        command.arg(jail).arg(mode).env_clear().stdin(Stdio::null());
        command
            .stdout(File::create(jail.parent().unwrap().join("stdout")).unwrap())
            .stderr(File::create(jail.parent().unwrap().join("stderr")).unwrap());
        let fd = backing.as_raw_fd();
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(fd, 200) != 200 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
    }
    #[test]
    #[ignore = "execute only in the explicit unavailable-static-toolchain build campaign"]
    fn unavailable_stage_refuses_before_preparation() {
        assert!(STAGE.is_empty(), "requires actual unavailable-static build");
        let state =
            std::env::temp_dir().join(format!("realm-unavailable-stage-{}", std::process::id()));
        assert!(!state.exists());
        let error = PreparedCodingFence::create(
            &state,
            &state.join("root"),
            &state.join("absent-vmm"),
            65534,
            65534,
        )
        .err()
        .expect("unavailable fence must refuse");
        assert_eq!(
            error.to_string(),
            "static coding fence unavailable for this build"
        );
        assert!(
            !state.exists(),
            "refusal must precede filesystem preparation"
        );
        println!(
            "UNAVAILABLE_FENCE actual_build_stage_bytes=0 CodingTools=REFUSE filesystem_effects=NONE"
        );
    }
    #[test]
    fn stop_measurement_checks_refuse_wrong_identity_membership_and_limits() {
        // Parser/refusal controls only, not physical containment evidence.
        let status = "Uid:\t1001 1001 1001 1001\nGid:\t1002 1002 1002 1002\nGroups:\nNSpid:\t999 1\nThreads:\t1\nNoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000\nCapInh:\t0000000000000000\nCapAmb:\t0000000000000000\n";
        stop_status(status, 1001, 1002).unwrap();
        for (from, to) in [
            ("1001 1001 1001 1001", "1001 0 1001 1001"),
            ("Groups:\n", "Groups: 0\n"),
            ("999 1", "999 2"),
            ("Threads:\t1", "Threads:\t2"),
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            ("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
        ] {
            assert!(
                stop_status(&status.replace(from, to), 1001, 1002).is_err(),
                "{from}"
            );
        }
        assert!(stop_status(&format!("{status}Uid: 1001 1001 1001 1001\n"), 1001, 1002).is_err());
        let expected = ExecStopExpectation {
            cgroup_relative: "realm/run".into(),
            memory_max: 536870912,
            pids_max: 32,
            uid: 1001,
            gid: 1002,
            stdout: "unused".into(),
            stderr: "unused".into(),
        };
        let make = || StopCgroupReadout {
            membership: "0::/realm/run\n".into(),
            procs: "999\n998\n".into(),
            limits: [
                "536870912\n".into(),
                "32\n".into(),
                "100000 100000\n".into(),
            ],
        };
        make().validate(&expected, 999, 998).unwrap();
        for case in 0..7 {
            let mut changed = make();
            match case {
                0 => changed.membership = "0::/realm/foreign\n".into(),
                1 => changed.membership.push_str("0::/realm/run\n"),
                2 => changed.procs = "998\n".into(),
                3 => changed.procs.push_str("123\n"),
                4 => changed.limits[0] = "max".into(),
                5 => changed.limits[1] = "64".into(),
                _ => changed.limits[2] = "200000 100000".into(),
            }
            assert!(
                changed.validate(&expected, 999, 998).is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn stopped_exec_is_pidfd_killed_and_reaped_before_userspace() {
        use std::os::fd::FromRawFd;
        let base = std::env::temp_dir().join(format!(
            "realm-stop-before-userspace-{}",
            std::process::id()
        ));
        fs::create_dir(&base).unwrap();
        let marker = base.join("executed");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "printf executed > \"$1\"", "exec-stop-control"])
            .arg(&marker);
        // Positive control: the same command/environment can create the marker.
        assert!(command.status().unwrap().success());
        assert_eq!(fs::read(&marker).unwrap(), b"executed");
        fs::remove_file(&marker).unwrap();
        unsafe {
            command.pre_exec(|| {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
        assert!(fd >= 0);
        let pin = unsafe { File::from_raw_fd(fd as i32) };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut status = 0;
            loop {
                let got = unsafe { libc::waitpid(child.id() as i32, &mut status, libc::WNOHANG) };
                assert!(got >= 0);
                if got != 0 {
                    break;
                }
                assert!(Instant::now() < deadline, "exec stop deadline");
                std::thread::sleep(Duration::from_millis(2));
            }
            assert!(libc::WIFSTOPPED(status));
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
            let report = kill_and_reap_exec_stop(child.id(), &pin, Duration::from_secs(2)).unwrap();
            assert_eq!(report["reaped"], true);
            println!(
                "EXEC_STOP_CONTROL euid={} reaped=true marker_absent={}",
                unsafe { libc::geteuid() },
                !marker.exists()
            );
            assert!(
                !marker.exists(),
                "the executable must not reach its side effect"
            );
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe {
                    libc::waitid(
                        libc::P_PIDFD,
                        pin.as_raw_fd() as u32,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::__WALL,
                    )
                },
                -1
            );
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
        }));
        // Original pidfd remains safe even after reaping; never kill a reused PID.
        if result.is_err() {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pin.as_raw_fd(),
                    libc::SIGKILL,
                    0,
                    0,
                );
            }
        }
        // Successful pidfd waitid already consumed the child (ECHILD here).
        // On failure this completes cleanup after the pidfd SIGKILL above.
        let _ = child.wait();
        fs::remove_dir_all(base).unwrap();
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    }

    #[test]
    #[ignore = "root Linux SYS_ADMIN/SYS_PTRACE static compiler; shim only, no KVM"]
    fn actual_stage_exec_stop_probe_returns_no_running_owner() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let base = std::env::temp_dir().join(format!("realm-stop-chain-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
        let worker = compile(
            &base.join("worker"),
            include_bytes!("../tests/fixtures/coding_fence_worker.c"),
        );
        let shim = compile(
            &base.join("jailer-shim"),
            include_bytes!("../tests/fixtures/coding_fence_jailer.c"),
        );
        let backing = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(base.join("backing"))
            .unwrap();
        backing.set_len(4096).unwrap();
        let (prepared, jail) = setup(&base, "stopped", &worker);
        let report = prepared
            .spawn_exec_stop_probe(
                &mut command(&shim, &jail, "normal", &backing),
                Duration::from_secs(8),
                None,
            )
            .unwrap();
        assert_eq!(report["vmm_userspace_executed"], false);
        assert_eq!(report["target_terminal"]["reaped"], true);
        assert_eq!(report["jailer_reaped"], true);
        assert_eq!(report["authority"], "NONE");
        assert!(
            fs::read(jail.parent().unwrap().join("stdout"))
                .unwrap()
                .is_empty()
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn exec_open_and_census_errors_preserve_operation_errno_and_cause() {
        // PID zero cannot name a real process. This exercises the production
        // helper rather than asserting only the formatting of a fabricated error.
        let error = measure_actual_exec(0).expect_err("missing process refuses");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("actual exec open /proc/0/exe"));
        assert!(error.to_string().contains("raw_os_error=Some(2)"));
        let context = error
            .get_ref()
            .unwrap()
            .downcast_ref::<OperationError>()
            .unwrap();
        assert_eq!(context.cause.raw_os_error(), Some(libc::ENOENT));
        let cause = std::error::Error::source(context).unwrap();
        assert_eq!(
            cause.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(libc::ENOENT)
        );
        let missing = Path::new("/proc/0/realm-missing-jail");
        let error = census_origin(missing, 0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(
            error
                .to_string()
                .contains("census symlink_metadata /proc/0/realm-missing-jail")
        );
        let context = error
            .get_ref()
            .unwrap()
            .downcast_ref::<OperationError>()
            .unwrap();
        assert_eq!(context.cause.raw_os_error(), Some(libc::ENOENT));
    }
    #[test]
    fn proc_exec_held_object_survives_unreachable_name_and_refuses_aliases() {
        let base = std::env::temp_dir().join(format!("realm-proc-exec-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        let executable = base.join("sleep");
        let retained = base.join("retained");
        fs::copy("/bin/sleep", &executable).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).unwrap();
        fs::hard_link(&executable, &retained).unwrap();
        let mut child = Command::new(&executable).arg("30").spawn().unwrap();
        let result = std::panic::catch_unwind(|| {
            fs::remove_file(&executable).unwrap();
            let proc_path = PathBuf::from(format!("/proc/{}/exe", child.id()));
            assert!(
                fs::read_link(&proc_path)
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(" (deleted)")
            );
            assert!(
                FileIdentity::measure(&proc_path).is_err(),
                "old pathname measurement must reproduce refusal"
            );
            let expected = FileIdentity::measure(&retained).unwrap();
            let (actual, pin) = measure_actual_exec(child.id()).unwrap();
            assert_eq!(actual.device_inode(), expected.device_inode());
            assert_eq!(actual.blake3(), expected.blake3());
            assert_eq!(pin.metadata().unwrap().nlink(), 1);
            fs::hard_link(&retained, base.join("unapproved-alias")).unwrap();
            assert!(
                measure_actual_exec(child.id()).is_err(),
                "held-object measurement must preserve single-link refusal"
            );
        });
        let _ = child.kill();
        child.wait().unwrap();
        fs::remove_dir_all(&base).unwrap();
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    }

    #[test]
    #[ignore = "root local Linux with SYS_ADMIN/SYS_PTRACE, static C compiler; component only, no KVM"]
    fn actual_stage_exec_chain_and_origin_refusals() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let base = std::env::temp_dir().join(format!("realm-fence-native-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
        let worker = compile(
            &base.join("worker"),
            include_bytes!("../tests/fixtures/coding_fence_worker.c"),
        );
        let shim = compile(
            &base.join("jailer-shim"),
            include_bytes!("../tests/fixtures/coding_fence_jailer.c"),
        );
        fs::write(base.join("backing"), vec![b'0'; 4096]).unwrap();
        let backing = OpenOptions::new()
            .read(true)
            .write(true)
            .open(base.join("backing"))
            .unwrap();
        // Kernel endpoints exist outside the new NET namespace and chroot.
        let outside_path = Path::new("/tmp/realm-fence-component-outside.sock");
        let outside = UnixListener::bind(outside_path).unwrap();
        outside.set_nonblocking(true).unwrap();
        let abstract_listener = UnixListener::bind_addr(
            &SocketAddr::from_abstract_name(b"realm-fence-component-outside").unwrap(),
        )
        .unwrap();
        abstract_listener.set_nonblocking(true).unwrap();
        let (prepared, jail) = setup(&base, "allowed", &worker);
        let launch_result = prepared.spawn(
            &mut command(&shim, &jail, "normal", &backing),
            Duration::from_secs(8),
        );
        let (mut original_jailer, _, owner) = match launch_result {
            Ok(value) => value,
            Err(error) => panic!(
                "native chain: {error}; stderr: {}; original journal: {}",
                fs::read_to_string(jail.parent().unwrap().join("stderr")).unwrap_or_default(),
                fs::read_to_string(jail.parent().unwrap().join("coding-fence/exec.jsonl"))
                    .unwrap_or_default()
            ),
        };
        // Test-only negative injection by the unfenced parent. This object was
        // absent from the admitted origin; it must not gain write capability.
        fs::write(jail.join("run/late-unapproved"), b"0").unwrap();
        fs::set_permissions(
            jail.join("run/late-unapproved"),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        let endpoint = jail.join("run/realm.task_9001");
        let listener = UnixListener::bind(&endpoint).unwrap();
        fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o666)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint_before = fs::symlink_metadata(&endpoint).unwrap();
        let deadline = Instant::now() + Duration::from_secs(6);
        let mut peer = loop {
            match listener.accept() {
                Ok((peer, _)) => break peer,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(e) => panic!("native endpoint accept: {e}"),
            }
        };
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of_val(&cred) as libc::socklen_t;
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    peer.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut cred as *mut libc::ucred).cast(),
                    &mut size,
                )
            },
            0
        );
        assert_eq!(
            (cred.pid as u32, cred.uid, cred.gid),
            (owner.pid, 65534, 65534)
        );
        let mut ready = [0];
        peer.read_exact(&mut ready).unwrap();
        assert_eq!(ready, [b'R']);
        let mut byte = *b"F";
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control =
            vec![
                0usize;
                unsafe { libc::CMSG_SPACE(4) } as usize / std::mem::size_of::<usize>() + 1
            ];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as usize;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&msg);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(4) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), backing.as_raw_fd());
            assert_eq!(libc::sendmsg(peer.as_raw_fd(), &msg, libc::MSG_NOSIGNAL), 1);
        }
        drop(peer);
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut done: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            let result = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    owner._pidfd.as_raw_fd() as u32,
                    &mut done,
                    libc::WEXITED | libc::WNOHANG,
                )
            };
            assert_eq!(result, 0, "{}", io::Error::last_os_error());
            if unsafe { done.si_pid() } != 0 {
                break;
            }
            if Instant::now() >= deadline {
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        owner._pidfd.as_raw_fd(),
                        libc::SIGKILL,
                        0,
                        0,
                    );
                }
                panic!("bounded worker exit");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(done.si_code, libc::CLD_EXITED);
        assert_eq!(unsafe { done.si_status() }, 0);
        assert!(original_jailer.wait().unwrap().success());
        owner.revalidate_objects().unwrap();
        let output = fs::read_to_string(jail.parent().unwrap().join("stdout")).unwrap();
        let errors = fs::read_to_string(jail.parent().unwrap().join("stderr")).unwrap();
        assert!(errors.is_empty(), "{errors}");
        let values = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 3, "{output}");
        assert_eq!(values[0]["pid_namespace_init"], 1);
        assert_eq!(values[0]["vcpu_kick"], 35);
        assert_eq!(values[0]["other_signal_errno"], libc::EPERM);
        for (key, expected) in [
            ("approved_read", 1),
            ("inherited_fd_errno", libc::EBADF),
            ("fresh_mapping", 1),
            ("memfd_errno", libc::EPERM),
            ("internet_socket_errno", libc::EPERM),
            ("unix_connect", 0),
            ("recvmsg_errno", libc::EPERM),
            ("pthread_error", 0),
            ("thread_value", 42),
            ("fork_errno", libc::EPERM),
        ] {
            assert_eq!(values[1][key], expected, "{key}: {output}");
        }
        for (key, expected) in [
            ("unlink_errno", libc::EPERM),
            ("symlink_errno", libc::EPERM),
            ("rebind_errno", libc::EADDRINUSE),
            ("outside_path_errno", libc::ENOENT),
            ("outside_abstract_errno", libc::ECONNREFUSED),
            ("private_self_peer", 1),
            ("self_peer_uid", 65534),
            ("recvmmsg_errno", libc::EPERM),
            ("readonly_alias_write_errno", libc::EBADF),
            ("late_unapproved_write_errno", libc::EACCES),
        ] {
            assert_eq!(values[2][key], expected, "{key}: {output}");
        }
        assert_eq!(fs::read(base.join("backing")).unwrap(), vec![b'0'; 4096]);
        assert_eq!(fs::read(jail.join("kernel")).unwrap(), b"K");
        assert_eq!(fs::read(jail.join("run/late-unapproved")).unwrap(), b"0");
        let after = fs::symlink_metadata(&endpoint).unwrap();
        assert_eq!(
            (after.dev(), after.ino()),
            (endpoint_before.dev(), endpoint_before.ino())
        );
        assert_eq!(
            outside.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            abstract_listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        println!(
            "NATIVE_COMPONENT_ONLY authority=NONE KVM=NOT_RUN original_peer={}:65534 retained_objects=PASS effects={output}",
            owner.pid
        );
        println!("NATIVE_EXEC_OWNER {}", owner.record());
        println!(
            "NATIVE_EXEC_ORIGINAL_JOURNAL {}",
            fs::read_to_string(jail.parent().unwrap().join("coding-fence/exec.jsonl")).unwrap()
        );
        // Same native production observer refuses wrong exec and origin aliases
        // BEFORE stage startup; these test-shim paths never register authority.
        for mode in ["bypass", "socket", "symlink"] {
            let (prepared, jail) = setup(&base, mode, &worker);
            let error = prepared
                .spawn(
                    &mut command(&shim, &jail, mode, &backing),
                    Duration::from_secs(5),
                )
                .err()
                .expect("unsafe origin or bypass must refuse");
            println!(
                "ORIGIN_REFUSAL {mode}: {error}; journal {}",
                fs::read_to_string(jail.parent().unwrap().join("coding-fence/exec.jsonl")).unwrap()
            );
            assert!(
                fs::read(jail.parent().unwrap().join("stdout"))
                    .unwrap()
                    .is_empty()
            );
        }
        let (prepared, jail) = setup(&base, "interrupted", &worker);
        let began = Instant::now();
        let error = prepared
            .spawn(
                &mut command(&shim, &jail, "hang", &backing),
                Duration::from_millis(150),
            )
            .err()
            .expect("interrupted initialization must refuse");
        assert!(began.elapsed() < Duration::from_secs(4));
        let journal =
            fs::read_to_string(jail.parent().unwrap().join("coding-fence/exec.jsonl")).unwrap();
        let refusal = journal
            .lines()
            .filter_map(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            .find(|v| v["phase"] == "CHAIN_REFUSED")
            .unwrap();
        for pid in refusal["tracked"].as_array().unwrap() {
            assert!(!Path::new(&format!("/proc/{}", pid.as_u64().unwrap())).exists());
        }
        println!("INTERRUPTED_LAUNCH_REFUSAL {error}; original journal {journal}");
        let (prepared, jail) = setup(&base, "unsupported", &worker);
        let mut denied = command(&shim, &jail, "normal", &backing);
        denied.uid(65534).gid(65534);
        assert!(prepared.spawn(&mut denied, Duration::from_secs(1)).is_err());
        fs::remove_file(outside_path).unwrap();
        drop(owner);
        drop(listener);
        drop(outside);
        drop(abstract_listener);
        fs::remove_dir_all(base).unwrap();
    }
    // Controlled component fixtures. These are real local Linux metadata and
    // held-FD operations, never a vendor launch or qualification assertion.
    fn device_fixture(label: &str) -> (PathBuf, File, UserfaultfdExclusion) {
        let base = std::env::temp_dir().join(format!("realm-uffd-{label}-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        fs::create_dir(base.join("dev")).unwrap();
        let dev = open_dir(&base.join("dev")).unwrap();
        assert_eq!(unsafe { libc::fchown(dev.as_raw_fd(), 65534, 65534) }, 0);
        assert_eq!(unsafe { libc::fchmod(dev.as_raw_fd(), 0o700) }, 0);
        let path =
            std::ffi::CString::new(base.join("dev/userfaultfd").as_os_str().as_encoded_bytes())
                .unwrap();
        assert_eq!(
            unsafe { libc::mknod(path.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(10, 257)) },
            0,
            "{}",
            io::Error::last_os_error()
        );
        assert_eq!(unsafe { libc::chown(path.as_ptr(), 65534, 65534) }, 0);
        let node = open_at(&dev, c"userfaultfd", libc::O_PATH).unwrap();
        let node_metadata = node.metadata().unwrap();
        validate_vendor_node(&node_metadata, 257, 65534, 65534).unwrap();
        let dev_metadata = dev.metadata().unwrap();
        let root = open_dir(&base).unwrap();
        (
            base,
            root,
            UserfaultfdExclusion {
                dev,
                dev_metadata,
                node,
                node_metadata,
            },
        )
    }
    #[test]
    fn vendor_minor_registration_is_exact_and_unique() {
        assert_eq!(
            parse_userfaultfd_minor("232 kvm\n257 userfaultfd\n").unwrap(),
            Some(257)
        );
        assert_eq!(parse_userfaultfd_minor("232 kvm\n").unwrap(), None);
        for bad in [
            "257 userfaultfd\n258 userfaultfd",
            "oops userfaultfd",
            "257 userfaultfd extra",
            "232 userfaultfd",
            "1048576 userfaultfd",
        ] {
            assert!(parse_userfaultfd_minor(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn optional_device_is_removed_by_held_inode_and_never_admitted() {
        let (base, root, pending) = device_fixture("remove");
        let result = pending.remove_pinned(&root).unwrap();
        assert_eq!(result["path_absent"], true);
        assert_eq!(result["held_after"]["links"], 0);
        assert!(!base.join("dev/userfaultfd").exists());
        assert_eq!(
            open_dir(&base.join("dev"))
                .unwrap()
                .metadata()
                .unwrap()
                .uid(),
            0
        );
        fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn altered_vendor_device_metadata_refuses() {
        for case in 0..7 {
            let (base, _root, pending) = device_fixture(&format!("metadata{case}"));
            let path = base.join("dev/userfaultfd");
            match case {
                0 => assert!(
                    validate_vendor_node(&pending.node_metadata, 258, 65534, 65534).is_err()
                ),
                1 => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
                2 => {
                    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                    assert_eq!(unsafe { libc::chown(c.as_ptr(), 65533, 65534) }, 0);
                }
                3 => {
                    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                    assert_eq!(unsafe { libc::chown(c.as_ptr(), 65534, 65533) }, 0);
                }
                4 => fs::hard_link(&path, base.join("alias")).unwrap(),
                5 => {
                    fs::remove_file(&path).unwrap();
                    fs::write(&path, b"not a device").unwrap();
                }
                _ => {
                    fs::remove_file(&path).unwrap();
                    std::os::unix::fs::symlink("/dev/null", &path).unwrap();
                }
            }
            if case != 0 {
                assert!(
                    validate_vendor_node(&fs::symlink_metadata(&path).unwrap(), 257, 65534, 65534)
                        .is_err()
                );
            }
            assert!(fs::symlink_metadata(&path).is_ok());
            fs::remove_dir_all(base).unwrap();
        }
    }
    #[test]
    fn held_device_directory_and_inode_substitutions_refuse() {
        for case in 0..3 {
            let (base, root, pending) = device_fixture(&format!("swap{case}"));
            let path = base.join("dev/userfaultfd");
            match case {
                0 => {
                    fs::rename(base.join("dev"), base.join("displaced")).unwrap();
                    fs::create_dir(base.join("dev")).unwrap();
                }
                1 => {
                    fs::rename(&path, base.join("dev/original")).unwrap();
                    fs::write(&path, b"substitution").unwrap();
                }
                _ => fs::remove_file(&path).unwrap(),
            }
            assert!(pending.remove_pinned(&root).is_err());
            if case == 1 {
                assert_eq!(fs::read(path).unwrap(), b"substitution");
            }
            fs::remove_dir_all(base).unwrap();
        }
    }
    #[test]
    fn extra_reachable_objects_refuse_before_optional_device_removal() {
        let (base, _root, pending) = device_fixture("extra");
        for d in ["run", "dev/net"] {
            fs::create_dir(base.join(d)).unwrap();
        }
        for leaf in ["firecracker", "realm-vmm", "kernel", "rootfs.ext4"] {
            fs::write(base.join(leaf), b"TEST_ONLY").unwrap();
        }
        let kvm =
            std::ffi::CString::new(base.join("dev/kvm").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mknod(kvm.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(10, 232)) },
            0
        );
        assert!(census_entries(&base, None).is_err()); // Never added to admission table.
        census_entries(&base, Some(&pending.node_metadata)).unwrap(); // Pre-removal census only.
        fs::write(base.join("unexpected"), b"forbidden").unwrap();
        assert!(census_entries(&base, Some(&pending.node_metadata)).is_err());
        assert!(base.join("dev/userfaultfd").symlink_metadata().is_ok());
        fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn original_pidfd_and_incarnation_substitution_refuse_without_signalling() {
        use std::os::fd::FromRawFd;
        let pid = std::process::id();
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0);
        let pin = unsafe { File::from_raw_fd(fd as i32) };
        verify_pidfd(pid, &pin).unwrap();
        assert!(verify_pidfd(pid + 1, &pin).is_err());
        assert!(
            wait_original_terminal(
                pid,
                &pin,
                process_start_ticks(pid).unwrap() + 1,
                Duration::ZERO,
                false
            )
            .is_err()
        );
    }
    #[test]
    fn discovered_processes_without_original_receipts_are_never_complete() {
        // TEST_ONLY supplemental contract fixtures, not native terminal claims.
        let required = BTreeSet::from([10, 11]);
        let row = |pid| serde_json::json!({"pid":pid,"start_time_ticks":1,"boot_id":"TEST_ONLY","si_code":libc::CLD_KILLED,"si_status":9,"reaped":true,"handle":"original_pidfd","wait":"waitid(P_PIDFD,__WALL)"});
        let complete = BTreeMap::from([(10, row(10)), (11, row(11))]);
        assert_eq!(
            diagnostic_terminal_bundle(&required, &complete, false)["complete"],
            true
        );
        for rows in [
            BTreeMap::from([(10, row(10))]),
            BTreeMap::from([
                (10, row(10)),
                (
                    11,
                    serde_json::json!({"pid":11,"reaped":null,"status":"INCOMPLETE"}),
                ),
            ]),
        ] {
            let result = diagnostic_terminal_bundle(&required, &rows, false);
            assert_eq!(result["complete"], false);
            assert_eq!(result["receipts"].as_array().unwrap().len(), 2);
        }
        assert_eq!(
            diagnostic_terminal_bundle(&required, &complete, true)["complete"],
            false
        );
        let mut substituted = complete.clone();
        substituted.get_mut(&11).unwrap()["pid"] = serde_json::json!(999);
        assert_eq!(
            diagnostic_terminal_bundle(&required, &substituted, false)["complete"],
            false
        );
        let extra = BTreeSet::from([10, 11, 12]);
        assert_eq!(
            diagnostic_terminal_bundle(&extra, &complete, false)["complete"],
            false
        );
    }
    #[test]
    fn original_clone_without_sigchld_has_a_consumed_pidfd_receipt() {
        use std::os::fd::FromRawFd;
        // Actual local clone child, no namespace/VM/guest and no SIGCHLD.
        // Mirrors the jailer's non-SIGCHLD child wait semantics only.
        let child = unsafe {
            libc::syscall(
                libc::SYS_clone,
                0,
                std::ptr::null::<libc::c_void>(),
                0,
                0,
                0,
            )
        };
        assert!(child >= 0, "{}", io::Error::last_os_error());
        if child == 0 {
            unsafe {
                // Independent local test safety if the parent loses progress
                // or an assertion fails. SIGALRM can never satisfy SIGKILL PASS.
                let mut alarms: libc::sigset_t = std::mem::zeroed();
                if libc::signal(libc::SIGALRM, libc::SIG_DFL) == libc::SIG_ERR
                    || libc::sigemptyset(&mut alarms) != 0
                    || libc::sigaddset(&mut alarms, libc::SIGALRM) != 0
                    || libc::sigprocmask(libc::SIG_UNBLOCK, &alarms, std::ptr::null_mut()) != 0
                {
                    libc::_exit(126);
                }
                libc::alarm(3);
                loop {
                    libc::pause();
                }
            }
        }
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) };
        assert!(fd >= 0);
        let pin = unsafe { File::from_raw_fd(fd as i32) };
        let row = terminate_original(
            child as u32,
            &pin,
            process_start_ticks(child as u32).unwrap(),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(row["si_code"], libc::CLD_KILLED);
        assert_eq!(row["si_status"], libc::SIGKILL);
        assert_eq!(row["reaped"], true);
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    pin.as_raw_fd() as u32,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::__WALL,
                )
            },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}
