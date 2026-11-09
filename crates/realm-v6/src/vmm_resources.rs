//! Kernel-owned descriptor evidence for the fixed CodingTools VMM. No caller
//! inventory, pathname digest or JSON can construct this proof. The official
//! pinned VMM/jailer remain trusted; this is not a hostile-VMM sandbox monitor.
use crate::measured_launch::{FileIdentity, MeasuredLaunchSession};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
fn bad(s: &str) -> io::Error {
    io::Error::other(format!("REFUSE_VMM_RESOURCE_BOUNDARY: {s}"))
}
#[derive(Serialize)]
struct Descriptor {
    fd: i32,
    device: u64,
    inode: u64,
    mode: u32,
    flags: i32,
    target: String,
}
#[derive(Serialize)]
struct Snapshot {
    pid: u32,
    start_ticks: u64,
    descriptors: Vec<Descriptor>,
    maps: String,
}
/// Check the required kernel inspection operations without creating a VM.
/// This is only API/access feasibility, never a VMM resource proof.
pub(crate) fn inspection_preflight() -> io::Result<()> {
    let file = File::open("/dev/null")?;
    let pid = std::process::id();
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(bad("pidfd_open unavailable"));
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let copied = unsafe {
        libc::syscall(
            libc::SYS_pidfd_getfd,
            pidfd.as_raw_fd(),
            file.as_raw_fd(),
            0,
        )
    };
    if copied < 0 {
        return Err(bad(&format!(
            "pidfd_getfd unavailable: {}",
            io::Error::last_os_error()
        )));
    }
    let copied = unsafe { OwnedFd::from_raw_fd(copied as i32) };
    if unsafe {
        libc::syscall(
            libc::SYS_kcmp,
            pid,
            pid,
            0,
            file.as_raw_fd(),
            copied.as_raw_fd(),
        )
    } != 0
    {
        return Err(bad(&format!(
            "kcmp open-description identity unavailable: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}
/// Owned group-stop, never PID-number signaling or a foreign existing stop.
/// A stop makes one inventory coherent; it is not continuous history coverage.
struct StoppedVmm {
    pidfd: OwnedFd,
    pid: u32,
    active: bool,
    tasks: BTreeSet<u32>,
}
impl StoppedVmm {
    fn states(pid: u32) -> io::Result<BTreeSet<(u32, char)>> {
        fs::read_dir(format!("/proc/{pid}/task"))?
            .map(|entry| {
                let entry = entry?;
                let tid = entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| bad("invalid task ID"))?;
                let status = fs::read_to_string(entry.path().join("status"))?;
                let state = status
                    .lines()
                    .find_map(|s| s.strip_prefix("State:"))
                    .and_then(|s| s.trim().chars().next())
                    .ok_or_else(|| bad("task state unavailable"))?;
                Ok((tid, state))
            })
            .collect()
    }
    fn stop(pidfd: &OwnedFd, pid: u32) -> io::Result<Self> {
        if pid == std::process::id() {
            return Err(bad("cannot stop the native owner"));
        }
        let states = Self::states(pid)?;
        if states.is_empty()
            || states
                .iter()
                .any(|(_, s)| matches!(s, 'T' | 't' | 'Z' | 'X'))
        {
            return Err(bad("VMM already stopped, traced or exited"));
        }
        let mut this = Self {
            pidfd: pidfd.try_clone()?,
            pid,
            active: false,
            tasks: BTreeSet::new(),
        };
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                this.pidfd.as_raw_fd(),
                libc::SIGSTOP,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        this.active = true;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    this.pidfd.as_raw_fd() as u32,
                    &mut info,
                    libc::WSTOPPED | libc::WNOWAIT | libc::WNOHANG,
                )
            } != 0
            {
                return Err(bad("native owner cannot wait for its VMM stop"));
            }
            if unsafe { info.si_pid() } == pid as i32
                && info.si_code == libc::CLD_STOPPED
                && unsafe { info.si_status() } == libc::SIGSTOP
            {
                let states = Self::states(pid)?;
                if !states.is_empty() && states.iter().all(|(_, s)| *s == 'T') {
                    this.tasks = states.into_iter().map(|(tid, _)| tid).collect();
                    return Ok(this);
                }
            }
            if Instant::now() >= deadline {
                return Err(bad("all-thread VMM stop deadline"));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn check(&self) -> io::Result<()> {
        let states = Self::states(self.pid)?;
        if states.iter().any(|(_, s)| *s != 'T')
            || states
                .into_iter()
                .map(|(tid, _)| tid)
                .collect::<BTreeSet<_>>()
                != self.tasks
        {
            return Err(bad("VMM stop/task census changed"));
        }
        Ok(())
    }
    fn resume(mut self) -> io::Result<()> {
        self.check()?;
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGCONT,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } != 0
        {
            return Err(bad("owned VMM resume failed"));
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    self.pidfd.as_raw_fd() as u32,
                    &mut info,
                    libc::WCONTINUED | libc::WNOWAIT | libc::WNOHANG,
                )
            } != 0
            {
                return Err(bad("owned VMM continuation wait failed"));
            }
            if unsafe { info.si_pid() } == self.pid as i32
                && info.si_code == libc::CLD_CONTINUED
                && Self::states(self.pid)?
                    .iter()
                    .all(|(_, s)| !matches!(s, 'T' | 't'))
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(bad("owned VMM continuation deadline"));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for StoppedVmm {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGCONT,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
        }
    }
}
/// Retains the original pidfd and duplicated approved resource descriptions.
/// Only a same-incarnation prestart+initialized census can advance this owner.
pub(crate) struct VmmResources {
    pidfd: OwnedFd,
    audit: File,
    pid: u32,
    ticks: u64,
    prepared: String,
    kernel: FileIdentity,
    rootfs: FileIdentity,
    stdout: (u64, u64),
    stderr: (u64, u64),
    api: Vec<u8>,
    vsock: Vec<u8>,
    peer_endpoints: [Vec<u8>; 3],
    driver: u32,
    pins: Vec<OwnedFd>,
    snapshots: Vec<Snapshot>,
    initialized: bool,
}
impl VmmResources {
    pub(crate) fn prepare(
        m: &MeasuredLaunchSession,
        state: &Path,
        api: &Path,
        vsock: &Path,
        peer_endpoints: [&Path; 3],
    ) -> io::Result<Self> {
        if !m.supports_coding_packet_profile() || !m.consumable_input_binding() {
            return Err(bad("unsupported or unbound launch"));
        }
        let pid = m.vmm().pid();
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let object = |name: &str| -> io::Result<(u64, u64)> {
            let s = fs::symlink_metadata(state.join(name))?;
            if !s.is_file() || s.nlink() != 1 || s.uid() != 0 || s.mode() & 0o022 != 0 {
                return Err(bad("unprotected VMM log"));
            }
            Ok((s.dev(), s.ino()))
        };
        let audit = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(state.join("native-resource-observations.jsonl"))?;
        audit.set_permissions(fs::Permissions::from_mode(0o600))?;
        File::open(state)?.sync_all()?;
        let mut this = Self {
            pidfd,
            audit,
            pid,
            ticks: m.vmm().start_time_ticks(),
            prepared: m.canonical_hash_blake3().into(),
            kernel: m.kernel_identity().clone(),
            rootfs: m.rootfs_identity().clone(),
            stdout: object("jailer.stdout")?,
            stderr: object("jailer.stderr")?,
            api: api.as_os_str().as_encoded_bytes().to_vec(),
            vsock: vsock.as_os_str().as_encoded_bytes().to_vec(),
            peer_endpoints: peer_endpoints.map(|p| p.as_os_str().as_encoded_bytes().to_vec()),
            driver: unsafe { libc::getppid() } as u32,
            pins: vec![],
            snapshots: vec![],
            initialized: false,
        };
        this.capture(m, true)?;
        Ok(this)
    }
    fn observe(&mut self, value: serde_json::Value) -> io::Result<()> {
        serde_json::to_writer(&mut self.audit, &value)?;
        self.audit.write_all(b"\n")?;
        self.audit.sync_all()
    }
    fn alive(&self, m: &MeasuredLaunchSession) -> io::Result<()> {
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 0) } != 0
            || m.vmm().pid() != self.pid
            || m.vmm().start_time_ticks() != self.ticks
            || m.prepared_measurement_root() != self.prepared
        {
            return Err(bad("VMM incarnation changed or exited"));
        }
        let actual = crate::measured_launch::VmmIncarnation::capture_linux(self.pid)
            .map_err(|_| bad("live VMM birth unavailable"))?;
        if actual.start_time_ticks() != self.ticks
            || actual.executable_identity().device_inode()
                != m.vmm().executable_identity().device_inode()
        {
            return Err(bad("actual VMM identity changed"));
        }
        Ok(())
    }
    fn fd_numbers(&self) -> io::Result<BTreeSet<i32>> {
        let entries = fs::read_dir(format!("/proc/{}/fd", self.pid))?;
        let fds = entries
            .map(|e| {
                e.and_then(|e| {
                    e.file_name()
                        .to_str()
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| bad("invalid descriptor entry"))
                })
            })
            .collect::<io::Result<BTreeSet<_>>>()?;
        if fds.len() > 256 {
            return Err(bad("descriptor census bound"));
        }
        Ok(fds)
    }
    fn capture(&mut self, m: &MeasuredLaunchSession, prestart: bool) -> io::Result<()> {
        self.alive(m)?;
        let stopped = StoppedVmm::stop(&self.pidfd, self.pid)?;
        self.observe(serde_json::json!({"authority":"NONE","phase":self.snapshots.len(),"stopped_tasks":stopped.tasks}))?;
        let before = self.fd_numbers()?;
        let mut rows = Vec::new();
        let mut resources = BTreeSet::new();
        for fd in &before {
            // pidfd_getfd duplicates the ACTUAL open file description; opening
            // the proc symlink would lose access-mode/socket identity evidence.
            let copied =
                unsafe { libc::syscall(libc::SYS_pidfd_getfd, self.pidfd.as_raw_fd(), *fd, 0) };
            if copied < 0 {
                return Err(bad(&format!(
                    "pidfd_getfd({fd}) unavailable: {}",
                    io::Error::last_os_error()
                )));
            }
            let held = unsafe { OwnedFd::from_raw_fd(copied as i32) };
            let file = File::from(held.try_clone()?);
            let st = file.metadata()?;
            let flags = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            let path = PathBuf::from(format!("/proc/{}/fd/{fd}", self.pid));
            let target = fs::read_link(&path)?.to_string_lossy().into_owned();
            self.observe(serde_json::json!({"authority":"NONE","measurement":self.prepared,
                "phase":self.snapshots.len(),"pid":self.pid,"start_ticks":self.ticks,
                "fd":fd,"device":st.dev(),"inode":st.ino(),"mode":st.mode(),"flags":flags,"target":target}))?;
            let id = (st.dev(), st.ino());
            if st.is_file() {
                if *fd == 1 && id == self.stdout || *fd == 2 && id == self.stderr {
                    if flags & libc::O_ACCMODE == libc::O_RDONLY {
                        return Err(bad("VMM log not writable"));
                    }
                } else {
                    let approved = if id == self.kernel.device_inode() {
                        resources.insert("kernel");
                        &self.kernel
                    } else if id == self.rootfs.device_inode() {
                        resources.insert("rootfs");
                        &self.rootfs
                    } else {
                        return Err(bad("unapproved regular-file descriptor/alias"));
                    };
                    if flags & libc::O_ACCMODE != libc::O_RDONLY
                        || st.nlink() != 1
                        || st.uid() != 0
                        || st.mode() & 0o022 != 0
                    {
                        return Err(bad("approved resource is writable or aliased"));
                    }
                    let actual = FileIdentity::measure_open_file(&path, &file)
                        .map_err(|_| bad("consumed resource measurement failed"))?;
                    if !actual.same_pinned_resource(approved) {
                        return Err(bad("consumed resource differs from launch commitment"));
                    }
                    self.pins.push(held.try_clone()?);
                }
            } else if st.mode() & libc::S_IFMT == libc::S_IFSOCK {
                self.socket(held.as_raw_fd())?;
            } else if st.mode() & libc::S_IFMT == libc::S_IFCHR {
                let expected = if *fd == 0 { "/dev/null" } else { "/dev/kvm" };
                let device = fs::metadata(expected)?;
                if st.rdev() != device.rdev() {
                    return Err(bad("unapproved character-device descriptor"));
                }
            } else if !matches!(
                target.as_str(),
                "anon_inode:[eventfd]"
                    | "anon_inode:[eventpoll]"
                    | "anon_inode:[timerfd]"
                    | "anon_inode:kvm-vm"
                    | "anon_inode:kvm-vcpu"
                    | "anon_inode:[kvm-vm]"
                    | "anon_inode:[kvm-vcpu]"
            ) {
                return Err(bad("unaccounted descriptor kind"));
            }
            rows.push(Descriptor {
                fd: *fd,
                device: st.dev(),
                inode: st.ino(),
                mode: st.mode(),
                flags,
                target,
            });
            if unsafe {
                libc::syscall(
                    libc::SYS_kcmp,
                    self.pid,
                    std::process::id(),
                    0,
                    *fd,
                    held.as_raw_fd(),
                )
            } != 0
            {
                return Err(bad(
                    "actual open description changed or kcmp inspection denied",
                ));
            }
            // Recheck the original descriptor still names the same object.
            let current = fs::metadata(&path)?;
            if (current.dev(), current.ino()) != id {
                return Err(bad("descriptor changed during census"));
            }
        }
        if self.fd_numbers()? != before {
            return Err(bad("descriptor table changed during census"));
        }
        if prestart && (!resources.contains("kernel") || !resources.contains("rootfs")) {
            return Err(bad(
                "actual prestart kernel/rootfs open descriptions not observed",
            ));
        }
        let mut maps = String::new();
        File::open(format!("/proc/{}/maps", self.pid))?
            .take(1024 * 1024 + 1)
            .read_to_string(&mut maps)?;
        self.observe(
            serde_json::json!({"authority":"NONE","phase":self.snapshots.len(),"maps":maps}),
        )?;
        // KVM vCPU run mappings are kernel interfaces. File-backed shared writes
        // to storage, including deleted/memfd aliases, are never admitted.
        for line in maps.lines() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 5 {
                return Err(bad("invalid map census"));
            }
            if fields[1].as_bytes().get(1) == Some(&b'w')
                && fields[1].as_bytes().get(3) == Some(&b's')
                && fields[4] != "0"
            {
                let (major, minor) = fields[3]
                    .split_once(':')
                    .ok_or_else(|| bad("invalid map device"))?;
                let major =
                    u64::from_str_radix(major, 16).map_err(|_| bad("invalid map device"))?;
                let minor =
                    u64::from_str_radix(minor, 16).map_err(|_| bad("invalid map device"))?;
                let inode = fields[4]
                    .parse::<u64>()
                    .map_err(|_| bad("invalid map inode"))?;
                let cpu = rows.iter().any(|row| {
                    matches!(
                        row.target.as_str(),
                        "anon_inode:kvm-vcpu" | "anon_inode:[kvm-vcpu]"
                    ) && row.inode == inode
                        && libc::major(row.device) as u64 == major
                        && libc::minor(row.device) as u64 == minor
                });
                if !cpu {
                    return Err(bad("unapproved writable shared mapping"));
                }
            }
        }
        if maps.is_empty() || maps.len() > 1024 * 1024 || !maps.ends_with('\n') {
            return Err(bad("incomplete or oversized map census"));
        }

        self.alive(m)?;
        stopped.check()?;
        stopped.resume()?;
        self.alive(m)?;
        self.snapshots.push(Snapshot {
            pid: self.pid,
            start_ticks: self.ticks,
            descriptors: rows,
            maps,
        });
        Ok(())
    }
    fn socket(&self, fd: i32) -> io::Result<()> {
        let option = |key| -> io::Result<i32> {
            let mut value = 0;
            let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    key,
                    (&mut value as *mut i32).cast(),
                    &mut len,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(value)
        };
        if option(libc::SO_DOMAIN)? != libc::AF_UNIX || option(libc::SO_TYPE)? != libc::SOCK_STREAM
        {
            return Err(bad("VMM has non-Unix-stream socket"));
        }
        validate_socket_role(
            fd,
            &self.api,
            &self.vsock,
            &self.peer_endpoints,
            std::process::id(),
            self.driver,
        )
    }
    pub(crate) fn initialized(&mut self, m: &MeasuredLaunchSession) -> io::Result<()> {
        self.capture(m, false)?;
        self.initialized = true;
        Ok(())
    }
    pub(crate) fn observe_before_close(&mut self, m: &MeasuredLaunchSession) -> io::Result<()> {
        if !self.initialized {
            return Err(bad("no post-initialization census"));
        }
        self.capture(m, false)
    }
    pub(crate) fn finish_after_retirement(
        self,
        retired: &crate::supervisor::RetiredCodingVmm,
    ) -> io::Result<ObservedVmmResources> {
        let m = &retired.production;
        let mut exited = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if !retired.has_closed_coding_channels()
            || self.snapshots.len() != 3
            || self.pid != m.vmm().pid()
            || self.ticks != m.vmm().start_time_ticks()
            || self.prepared != m.prepared_measurement_root()
            || unsafe { libc::poll(&mut exited, 1, 0) } != 1
            || exited.revents & libc::POLLIN == 0
        {
            return Err(bad(
                "original resource owner lacks same-run closed channels/retirement",
            ));
        }
        let custody = retired
            .owned_custody
            .as_ref()
            .ok_or_else(|| bad("original custody absent"))?;
        custody
            .validate_retired(m)
            .map_err(|_| bad("retired custody differs"))?;
        for pin in &self.pins {
            let file = File::from(pin.try_clone()?);
            let meta = file.metadata()?;
            let expected = if (meta.dev(), meta.ino()) == self.kernel.device_inode() {
                &self.kernel
            } else if (meta.dev(), meta.ino()) == self.rootfs.device_inode() {
                &self.rootfs
            } else {
                return Err(bad("held resource identity changed"));
            };
            let actual = FileIdentity::measure_open_file(Path::new("/proc/self/fd"), &file)
                .map_err(|_| bad("held retired resource unreadable"))?;
            if !actual.same_pinned_resource(expected) {
                return Err(bad("original resource changed through retirement"));
            }
        }
        let raw = serde_json::to_vec(&(
            "realm.actual-vmm-resources/v1",
            &self.prepared,
            &self.kernel,
            &self.rootfs,
            &self.snapshots,
        ))?;
        let root = blake3::hash(&raw).to_hex().to_string();
        Ok(ObservedVmmResources {
            root,
            raw,
            pid: self.pid,
            ticks: self.ticks,
            prepared: self.prepared,
        })
    }
}
fn socket_name(fd: i32, peer: bool) -> io::Result<Vec<u8>> {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
    let result = unsafe {
        if peer {
            libc::getpeername(fd, (&mut addr as *mut libc::sockaddr_un).cast(), &mut len)
        } else {
            libc::getsockname(fd, (&mut addr as *mut libc::sockaddr_un).cast(), &mut len)
        }
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if addr.sun_family != libc::AF_UNIX as libc::sa_family_t {
        return Err(bad("non-Unix endpoint"));
    }
    Ok(addr
        .sun_path
        .iter()
        .map(|c| c.to_ne_bytes()[0])
        .take_while(|b| *b != 0)
        .collect())
}
fn validate_socket_role(
    fd: i32,
    api: &[u8],
    vsock: &[u8],
    endpoints: &[Vec<u8>; 3],
    native: u32,
    driver: u32,
) -> io::Result<()> {
    let local = socket_name(fd, false)?;
    let mut listening = 0;
    let mut len = std::mem::size_of_val(&listening) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut listening as *mut i32).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if listening != 0 {
        return if local == api || local == vsock {
            Ok(())
        } else {
            Err(bad("unapproved VMM listener"))
        };
    }
    let remote = socket_name(fd, true)?;
    let mut c: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&c) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut c as *mut libc::ucred).cast(),
            &mut len,
        )
    } != 0
        || c.uid != 0
    {
        return Err(bad("unapproved VMM socket peer"));
    }
    let api_client = local == api && remote.is_empty() && c.pid as u32 == native;
    let guest_channel = local.is_empty()
        && endpoints.iter().enumerate().any(|(role, path)| {
            remote == *path && c.pid as u32 == if role == 2 { driver } else { native }
        });
    if !api_client && !guest_channel {
        return Err(bad(
            "same-peer socket is not an approved API/submission/control/raw role",
        ));
    }
    Ok(())
}
pub(crate) struct ObservedVmmResources {
    root: String,
    raw: Vec<u8>,
    pid: u32,
    ticks: u64,
    prepared: String,
}
impl ObservedVmmResources {
    pub(crate) fn identity_bytes(&self) -> &[u8] {
        &self.raw
    }
    pub(crate) fn diagnostic(&self) -> serde_json::Value {
        serde_json::json!({"authority":"NONE", "root":self.root,
            "observations":serde_json::from_slice::<serde_json::Value>(&self.raw).expect("native serialized observations")})
    }
    pub(crate) fn matches(&self, m: &MeasuredLaunchSession) -> bool {
        self.pid == m.vmm().pid()
            && self.ticks == m.vmm().start_time_ticks()
            && self.prepared == m.prepared_measurement_root()
    }
    pub(crate) fn root(&self) -> &str {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};
    #[test]
    fn owned_stop_resume_and_existing_stop_refusal() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let child = Child(
            std::process::Command::new("/bin/sleep")
                .arg("10")
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id();
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(raw >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let stopped = StoppedVmm::stop(&fd, pid).unwrap();
        stopped.check().unwrap();
        assert!(StoppedVmm::stop(&fd, pid).is_err());
        stopped.check().unwrap();
        stopped.resume().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while StoppedVmm::states(pid)
            .unwrap()
            .iter()
            .any(|(_, s)| *s == 'T')
        {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        let stopped = StoppedVmm::stop(&fd, pid).unwrap();
        drop(stopped);
        while StoppedVmm::states(pid)
            .unwrap()
            .iter()
            .any(|(_, s)| *s == 'T')
        {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    #[test]
    fn actual_same_peer_unapproved_channel_refuses() {
        let root = std::env::temp_dir().join(format!("realm-socket-roles-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let approved = root.join("control");
        let unknown = root.join("unknown");
        let yes = UnixListener::bind(&approved).unwrap();
        let no = UnixListener::bind(&unknown).unwrap();
        let client_yes = UnixStream::connect(&approved).unwrap();
        let (_accepted, _) = yes.accept().unwrap();
        let client_no = UnixStream::connect(&unknown).unwrap();
        let (_other, _) = no.accept().unwrap();
        let paths = [
            approved.as_os_str().as_encoded_bytes().to_vec(),
            b"unused-control".to_vec(),
            b"unused-raw".to_vec(),
        ];
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            assert!(
                validate_socket_role(
                    client_yes.as_raw_fd(),
                    b"api",
                    b"vsock",
                    &paths,
                    std::process::id(),
                    0
                )
                .is_ok()
            );
        }
        assert!(
            validate_socket_role(
                client_no.as_raw_fd(),
                b"api",
                b"vsock",
                &paths,
                std::process::id(),
                0
            )
            .is_err()
        );
        drop((client_yes, client_no, yes, no));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn identical_endpoint_snapshots_do_not_prove_temporal_alias_absence() {
        // Isolate the actual kernel observation from unrelated parallel-test
        // descriptor activity. The subprocess still executes this exact test.
        const CHILD: &str = "REALM_TEMPORAL_HISTORY_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "vmm_resources::tests::identical_endpoint_snapshots_do_not_prove_temporal_alias_absence", "--nocapture"])
                .env(CHILD, "1")
                .output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) },
            0
        );
        // Controlled host-process counterexample, NOT a guest escape or a
        // production evidence constructor. An independent reopen sees a write
        // that identical endpoint FD inventories cannot distinguish.
        let root =
            std::env::temp_dir().join(format!("realm-alias-interval-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let file = root.join("subject");
        fs::write(&file, b"before").unwrap();
        let inventory = || {
            fs::read_dir("/proc/self/fd")
                .unwrap()
                .map(|e| {
                    let e = e.unwrap();
                    (e.file_name(), fs::read_link(e.path()).unwrap())
                })
                .collect::<BTreeSet<_>>()
        };
        // History A: no write. Independent reopen observes the original state.
        let quiet = (inventory(), inventory());
        let quiet_result = fs::read(&file).unwrap();
        // History B starts with the same subject and has an actual transient
        // write between censuses. Endpoint observations cannot distinguish it.
        let before = inventory();
        {
            let mut transient = OpenOptions::new().write(true).open(&file).unwrap();
            transient.write_all(b"after!").unwrap();
            transient.sync_all().unwrap();
        }
        let after = inventory();
        assert_eq!(quiet.0, quiet.1);
        assert_eq!(quiet, (before, after));
        let changed_result = fs::read(&file).unwrap();
        assert_eq!(quiet_result, b"before");
        assert_eq!(changed_result, b"after!");
        assert_ne!(quiet_result, changed_result);
        fs::remove_dir_all(root).unwrap();
    }
}
