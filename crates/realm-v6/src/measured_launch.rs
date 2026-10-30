//! Host-created measurement of the Firecracker launch topology.
//!
//! `DirectMeasuredLaunch` remains diagnostic. `ProductionContainedLaunch` is
//! minted only by the official-jailer path after observing its VMM, namespaces,
//! cgroup, seccomp, jail root, and unchanged materialized resources. Neither
//! type authorizes admission or terminal publication.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::profile::SyncTrace as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::{
        fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt},
        io::AsRawFd,
        net::UnixListener,
    },
    path::{Path, PathBuf},
    process::Command,
};

pub const MEASURED_LAUNCH_HASH_DOMAIN: &str = "REALM::DirectMeasuredLaunch";
pub const MEASURED_LAUNCH_HASH_VERSION: u16 = 1;
const CONFIG_HASH_DOMAIN: &str = "REALM::FirecrackerFullVmConfiguration";
const GUEST_TASK_PORT: u32 = 7000;
pub(crate) const EXPECTED_BOOT_ARGS: &str =
    "console=ttyS0 root=/dev/vda rw init=/sbin/realm-guest-supervisor";

pub(crate) const BROKER_BOOT_ARGS: &str =
    "console=ttyS0 root=/dev/vda rootfstype=ext4 ro init=/c0 panic=1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaunchProfile {
    Workspace,
    RootfsBroker,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaunchRefusal {
    MalformedConfiguration,
    UnsupportedConfiguration,
    TopologyMismatch,
    InputMeasurementFailed,
    InputChanged,
    EndpointMismatch,
    ProcessIncarnationMismatch,
    InputBindingMismatch,
    UnsupportedHost,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileIdentity {
    path: String,
    blake3: String,
    device: u64,
    inode: u64,
    size: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    trusted_parent_chain: bool,
}

impl FileIdentity {
    pub fn measure(path: &Path) -> Result<Self, LaunchRefusal> {
        let _profile = crate::profile::Span::new("resource_hash_verification");
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| LaunchRefusal::InputMeasurementFailed)?
                .join(path)
        };
        let parent_chain_trusted = trusted_parent_chain(&absolute);
        let canonical = absolute
            .canonicalize()
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&canonical)
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        let before = file
            .metadata()
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        if !before.is_file() || before.nlink() != 1 {
            return Err(LaunchRefusal::InputMeasurementFailed);
        }
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0_u8; 1024 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            crate::profile::bytes("resource_hash_verification", "hashed", count as u64);
        }
        let after = file
            .metadata()
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        if !same_file_version(&before, &after) {
            return Err(LaunchRefusal::InputChanged);
        }
        Ok(Self {
            path: canonical.to_string_lossy().into_owned(),
            blake3: hasher.finalize().to_hex().to_string(),
            device: before.dev(),
            inode: before.ino(),
            size: before.len(),
            owner_uid: before.uid(),
            owner_gid: before.gid(),
            mode: before.mode() & 0o7777,
            trusted_parent_chain: parent_chain_trusted,
        })
    }

    fn measure_open_file(path: &Path, file: &File) -> Result<Self, LaunchRefusal> {
        let _profile = crate::profile::Span::new("resource_hash_verification");
        let before = file
            .metadata()
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        if !before.is_file() || before.nlink() != 1 {
            return Err(LaunchRefusal::InputMeasurementFailed);
        }
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0_u8; 1024 * 1024];
        let mut offset = 0u64;
        loop {
            let count = file
                .read_at(&mut buffer, offset)
                .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            crate::profile::bytes("resource_hash_verification", "hashed", count as u64);
            offset = offset
                .checked_add(count as u64)
                .ok_or(LaunchRefusal::InputMeasurementFailed)?;
        }
        let after = file
            .metadata()
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        if !same_file_version(&before, &after) || offset != after.len() {
            return Err(LaunchRefusal::InputChanged);
        }
        Ok(Self {
            path: path.to_string_lossy().into_owned(),
            blake3: hasher.finalize().to_hex().to_string(),
            device: before.dev(),
            inode: before.ino(),
            size: before.len(),
            owner_uid: before.uid(),
            owner_gid: before.gid(),
            mode: before.mode() & 0o7777,
            trusted_parent_chain: trusted_parent_chain(path),
        })
    }

    fn measure_opened_executable(pid: u32) -> Result<Self, LaunchRefusal> {
        let _profile = crate::profile::Span::new("resource_hash_verification");
        let path = format!("/proc/{pid}/exe");
        let mut file = File::open(&path).map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        let before = file
            .metadata()
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        if !before.is_file() {
            return Err(LaunchRefusal::InputMeasurementFailed);
        }
        let mut hasher = blake3::Hasher::new();
        let hashed = io::copy(&mut file, &mut HashWriter(&mut hasher))
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        crate::profile::bytes("resource_hash_verification", "hashed", hashed);
        let after = file
            .metadata()
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        if !same_file_version(&before, &after) {
            return Err(LaunchRefusal::InputChanged);
        }
        Ok(Self {
            path,
            blake3: hasher.finalize().to_hex().to_string(),
            device: before.dev(),
            inode: before.ino(),
            size: before.len(),
            owner_uid: before.uid(),
            owner_gid: before.gid(),
            mode: before.mode() & 0o7777,
            trusted_parent_chain: false,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn blake3(&self) -> &str {
        &self.blake3
    }

    pub fn device_inode(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

    fn same_pinned_resource(&self, other: &Self) -> bool {
        self.blake3 == other.blake3
            && self.device == other.device
            && self.inode == other.inode
            && self.size == other.size
            && self.owner_uid == other.owner_uid
            && self.owner_gid == other.owner_gid
            && self.mode == other.mode
    }

    fn same_object_identity(&self, other: &Self) -> bool {
        self.path == other.path
            && self.device == other.device
            && self.inode == other.inode
            && self.size == other.size
            && self.owner_uid == other.owner_uid
            && self.owner_gid == other.owner_gid
            && self.mode == other.mode
    }

    pub fn trusted_parent_chain(&self) -> bool {
        self.trusted_parent_chain
    }

    pub fn owner(&self) -> (u32, u32) {
        (self.owner_uid, self.owner_gid)
    }

    pub fn mode(&self) -> u32 {
        self.mode
    }

    pub fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    pub fn owner_gid(&self) -> u32 {
        self.owner_gid
    }
}

#[derive(Debug)]
struct PinnedInput {
    file: File,
    identity: FileIdentity,
}

impl PinnedInput {
    fn open(path: &Path, writable: bool) -> Result<Self, LaunchRefusal> {
        let canonical = path
            .canonicalize()
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(writable)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(&canonical)
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        let identity = FileIdentity::measure_open_file(&canonical, &file)?;
        if identity.owner_uid != unsafe { libc::geteuid() } {
            return Err(LaunchRefusal::InputMeasurementFailed);
        }
        Ok(Self { file, identity })
    }

    fn fd_path(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.file.as_raw_fd()
        ))
    }

    fn revalidate(&self) -> Result<(), LaunchRefusal> {
        self.revalidate_object_identity()?;
        if FileIdentity::measure_open_file(Path::new(&self.identity.path), &self.file)?
            != self.identity
        {
            return Err(LaunchRefusal::InputChanged);
        }
        Ok(())
    }

    fn revalidate_object_identity(&self) -> Result<(), LaunchRefusal> {
        let metadata = self
            .file
            .metadata()
            .map_err(|_| LaunchRefusal::InputChanged)?;
        let object_unchanged = metadata.is_file()
            && metadata.nlink() == 1
            && metadata.dev() == self.identity.device
            && metadata.ino() == self.identity.inode
            && metadata.uid() == self.identity.owner_uid
            && metadata.gid() == self.identity.owner_gid
            && metadata.mode() & 0o7777 == self.identity.mode;
        let path_metadata =
            fs::symlink_metadata(&self.identity.path).map_err(|_| LaunchRefusal::InputChanged)?;
        let path_is_same_object = path_metadata.is_file()
            && path_metadata.nlink() == 1
            && path_metadata.dev() == metadata.dev()
            && path_metadata.ino() == metadata.ino()
            && path_metadata.uid() == metadata.uid()
            && path_metadata.gid() == metadata.gid()
            && path_metadata.mode() & 0o7777 == metadata.mode() & 0o7777;
        if !object_unchanged || !path_is_same_object {
            return Err(LaunchRefusal::InputChanged);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PinnedDirectory {
    file: File,
    device: u64,
    inode: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
}

impl PinnedDirectory {
    fn open(path: &Path) -> Result<Self, LaunchRefusal> {
        let canonical = path
            .canonicalize()
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(canonical)
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        let metadata = file
            .metadata()
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return Err(LaunchRefusal::InputMeasurementFailed);
        }
        Ok(Self {
            file,
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
            owner_gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
        })
    }

    fn revalidate(&self) -> Result<(), LaunchRefusal> {
        let metadata = self
            .file
            .metadata()
            .map_err(|_| LaunchRefusal::InputChanged)?;
        if !metadata.is_dir()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.owner_uid
            || metadata.gid() != self.owner_gid
            || metadata.mode() & 0o7777 != self.mode
        {
            return Err(LaunchRefusal::InputChanged);
        }
        Ok(())
    }
}

/// Validated host-owned inputs. It is deliberately in-process only and cannot
/// be cloned, serialized, or reconstructed from the diagnostic identities.
#[derive(Debug)]
pub(crate) struct PreparedExecutionInputs {
    profile: LaunchProfile,
    firecracker: PinnedInput,
    kernel: PinnedInput,
    rootfs: PinnedInput,
    base_workspace: PinnedInput,
    guest_supervisor: PinnedInput,
    starting_workspace: PinnedInput,
    working_workspace: PinnedInput,
    state_dir: PinnedDirectory,
    run_state_dir: PinnedDirectory,
}

/// Jail-local copies made from the already-opened input descriptors. The
/// descriptor pins remain authoritative until each copy is hashed and synced.
#[derive(Clone, Debug)]
pub(crate) struct JailedResourcePaths {
    pub(crate) input_binding_root: String,
    pub(crate) firecracker_exec_source: PathBuf,
    pub(crate) kernel_host_path: PathBuf,
    pub(crate) rootfs_host_path: PathBuf,
    pub(crate) workspace_host_path: PathBuf,
    firecracker_identity: FileIdentity,
    kernel_identity: FileIdentity,
    rootfs_identity: FileIdentity,
    workspace_identity: FileIdentity,
}

impl JailedResourcePaths {
    pub(crate) fn verify_before_instance_start(&self) -> Result<(), LaunchRefusal> {
        for expected in [
            &self.firecracker_identity,
            &self.kernel_identity,
            &self.rootfs_identity,
            &self.workspace_identity,
        ] {
            if FileIdentity::measure(Path::new(expected.path()))? != *expected {
                return Err(LaunchRefusal::InputChanged);
            }
        }
        Ok(())
    }

    pub(crate) fn verify_after_guest(&self) -> Result<(), LaunchRefusal> {
        for expected in [
            &self.firecracker_identity,
            &self.kernel_identity,
            &self.rootfs_identity,
        ] {
            if FileIdentity::measure(Path::new(expected.path()))? != *expected {
                return Err(LaunchRefusal::InputChanged);
            }
        }
        let actual = FileIdentity::measure(&self.workspace_host_path)?;
        if !self.workspace_identity.same_object_identity(&actual) {
            return Err(LaunchRefusal::InputChanged);
        }
        Ok(())
    }
}

impl PreparedExecutionInputs {
    pub(crate) fn prepare(
        backend: &crate::execute::C1BackendInputPaths,
        starting_workspace: &Path,
        working_workspace: &Path,
        run_state_dir: &Path,
    ) -> Result<Self, LaunchRefusal> {
        Self::prepare_profile(
            backend,
            starting_workspace,
            working_workspace,
            run_state_dir,
            LaunchProfile::Workspace,
        )
    }

    pub(crate) fn prepare_profile(
        backend: &crate::execute::C1BackendInputPaths,
        starting_workspace: &Path,
        working_workspace: &Path,
        run_state_dir: &Path,
        profile: LaunchProfile,
    ) -> Result<Self, LaunchRefusal> {
        let prepared = Self {
            profile,
            firecracker: PinnedInput::open(&backend.firecracker, false)?,
            kernel: PinnedInput::open(&backend.kernel, false)?,
            rootfs: PinnedInput::open(&backend.rootfs, false)?,
            base_workspace: PinnedInput::open(&backend.workspace_device, false)?,
            guest_supervisor: PinnedInput::open(&backend.guest_supervisor, false)?,
            starting_workspace: PinnedInput::open(starting_workspace, false)?,
            working_workspace: PinnedInput::open(working_workspace, true)?,
            state_dir: PinnedDirectory::open(&backend.state_dir)?,
            run_state_dir: PinnedDirectory::open(run_state_dir)?,
        };
        validate_workspace_image_identity(
            &prepared.base_workspace,
            &prepared.starting_workspace,
            &prepared.working_workspace,
        )?;
        let rootfs_fd = unsafe { libc::fcntl(prepared.rootfs.file.as_raw_fd(), libc::F_DUPFD, 64) };
        if rootfs_fd < 0 {
            return Err(LaunchRefusal::InputMeasurementFailed);
        }
        let embedded_result = Command::new("debugfs")
            .arg("-R")
            .arg(match profile {
                LaunchProfile::Workspace => "cat /sbin/realm-guest-supervisor",
                LaunchProfile::RootfsBroker => "cat /c0",
            })
            .arg(format!("/proc/self/fd/{rootfs_fd}"))
            .output();
        unsafe {
            libc::close(rootfs_fd);
        }
        let embedded = embedded_result.map_err(|_| LaunchRefusal::InputBindingMismatch)?;
        if !embedded.status.success()
            || blake3::hash(&embedded.stdout).to_hex().as_str()
                != prepared.guest_supervisor.identity.blake3
        {
            return Err(LaunchRefusal::InputBindingMismatch);
        }
        Ok(prepared)
    }

    pub(crate) fn bind(
        self,
        run_id: String,
        execution_id: String,
        challenge: String,
        s0_root: String,
        policy: PolicyIdentity,
    ) -> Result<ConsumableInputBinding, LaunchRefusal> {
        if run_id.is_empty()
            || execution_id.is_empty()
            || challenge.len() != 64
            || s0_root.len() != 64
            || !challenge.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !s0_root.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(LaunchRefusal::InputBindingMismatch);
        }
        #[derive(Serialize)]
        struct Seed<'a> {
            run_id: &'a str,
            execution_id: &'a str,
            challenge: &'a str,
            s0_root: &'a str,
            firecracker: &'a FileIdentity,
            kernel: &'a FileIdentity,
            rootfs: &'a FileIdentity,
            rootfs_fd_access: &'static str,
            base_workspace: &'a FileIdentity,
            guest_supervisor: &'a FileIdentity,
            guest_supervisor_fd_access: &'static str,
            starting_workspace: &'a FileIdentity,
            working_workspace: &'a FileIdentity,
            working_workspace_fd_access: &'static str,
            firecracker_fd_access: &'static str,
            kernel_fd_access: &'static str,
            rootfs_access: &'static str,
            workspace_access: &'static str,
            state_dir_device: u64,
            state_dir_inode: u64,
            state_dir_owner_uid: u32,
            state_dir_owner_gid: u32,
            state_dir_mode: u32,
            run_state_device: u64,
            run_state_inode: u64,
            run_state_owner_uid: u32,
            run_state_owner_gid: u32,
            run_state_mode: u32,
            profile: &'static str,
            policy: &'a PolicyIdentity,
        }
        let seed = Seed {
            run_id: &run_id,
            execution_id: &execution_id,
            challenge: &challenge,
            s0_root: &s0_root,
            firecracker: &self.firecracker.identity,
            kernel: &self.kernel.identity,
            rootfs: &self.rootfs.identity,
            rootfs_fd_access: "read-only",
            base_workspace: &self.base_workspace.identity,
            guest_supervisor: &self.guest_supervisor.identity,
            guest_supervisor_fd_access: "read-only",
            starting_workspace: &self.starting_workspace.identity,
            working_workspace: &self.working_workspace.identity,
            working_workspace_fd_access: "read-write",
            firecracker_fd_access: "execute-through-pinned-read-only-fd",
            kernel_fd_access: "read-only",
            rootfs_access: "read-only-drive",
            workspace_access: match self.profile {
                LaunchProfile::Workspace => "read-write-drive",
                LaunchProfile::RootfsBroker => "host-only-staging-not-a-drive",
            },
            state_dir_device: self.state_dir.device,
            state_dir_inode: self.state_dir.inode,
            state_dir_owner_uid: self.state_dir.owner_uid,
            state_dir_owner_gid: self.state_dir.owner_gid,
            state_dir_mode: self.state_dir.mode,
            run_state_device: self.run_state_dir.device,
            run_state_inode: self.run_state_dir.inode,
            run_state_owner_uid: self.run_state_dir.owner_uid,
            run_state_owner_gid: self.run_state_dir.owner_gid,
            run_state_mode: self.run_state_dir.mode,
            profile: match self.profile {
                LaunchProfile::Workspace => "v6-c0-positive-minimal-v1",
                LaunchProfile::RootfsBroker => "v6-rootfs-broker-create-v1",
            },
            policy: &policy,
        };
        let bytes = serde_json::to_vec(&seed).map_err(|_| LaunchRefusal::InputBindingMismatch)?;
        let root = domain_hash("REALM::ConsumableInputBinding", 1, &bytes);
        Ok(ConsumableInputBinding {
            run_id,
            execution_id,
            challenge,
            s0_root,
            policy,
            root,
            inputs: self,
        })
    }

    pub(crate) fn starting_workspace_path(&self) -> PathBuf {
        self.starting_workspace.fd_path()
    }

    /// Copy the exact bound files into a freshly created jail root. This does
    /// not use hard links: the writable workspace must have a unique inode.
    /// The caller must create and protect `jail_root` and must refuse a stale
    /// jail identity before calling this method.
    pub(crate) fn materialize_for_jailer(
        &self,
        jail_root: &Path,
        execution_state: &Path,
        uid: u32,
        gid: u32,
        input_binding_root: &str,
    ) -> Result<JailedResourcePaths, LaunchRefusal> {
        let _profile = crate::profile::Span::new("jail_creation_materialization");
        self.revalidate()?;
        if !jail_root.is_absolute() || !execution_state.is_absolute() || uid == 0 || gid == 0 {
            return Err(LaunchRefusal::InputBindingMismatch);
        }
        let firecracker_exec_source = execution_state.join("jailer-input").join("firecracker");
        fs::create_dir(firecracker_exec_source.parent().unwrap())
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        let kernel_host_path = jail_root.join("kernel");
        let rootfs_host_path = jail_root.join("rootfs.ext4");
        let workspace_host_path = match self.profile {
            LaunchProfile::Workspace => jail_root.join("workspace.ext4"),
            LaunchProfile::RootfsBroker => execution_state.join("unattached-s0.ext4"),
        };
        copy_pinned_input(&self.firecracker, &firecracker_exec_source, 0, 0, 0o500)?;
        copy_pinned_input(&self.kernel, &kernel_host_path, 0, 0, 0o444)?;
        copy_pinned_input(&self.rootfs, &rootfs_host_path, 0, 0, 0o444)?;
        copy_pinned_input(
            &self.working_workspace,
            &workspace_host_path,
            if self.profile == LaunchProfile::Workspace {
                uid
            } else {
                0
            },
            if self.profile == LaunchProfile::Workspace {
                gid
            } else {
                0
            },
            if self.profile == LaunchProfile::Workspace {
                0o600
            } else {
                0o444
            },
        )?;
        self.revalidate()?;
        let firecracker_identity = FileIdentity::measure(&firecracker_exec_source)?;
        let kernel_identity = FileIdentity::measure(&kernel_host_path)?;
        let rootfs_identity = FileIdentity::measure(&rootfs_host_path)?;
        let workspace_identity = FileIdentity::measure(&workspace_host_path)?;
        if firecracker_identity.blake3() != self.firecracker.identity.blake3()
            || kernel_identity.blake3() != self.kernel.identity.blake3()
            || rootfs_identity.blake3() != self.rootfs.identity.blake3()
            || workspace_identity.blake3() != self.working_workspace.identity.blake3()
        {
            return Err(LaunchRefusal::InputBindingMismatch);
        }
        Ok(JailedResourcePaths {
            input_binding_root: input_binding_root.into(),
            firecracker_exec_source,
            kernel_host_path,
            rootfs_host_path,
            workspace_host_path,
            firecracker_identity,
            kernel_identity,
            rootfs_identity,
            workspace_identity,
        })
    }
}

fn copy_pinned_input(
    source: &PinnedInput,
    destination: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), LaunchRefusal> {
    let _profile = crate::profile::Span::new("jail_resource_materialization");
    let before = source
        .file
        .metadata()
        .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
    let mut cleanup = RemoveOnDrop {
        path: destination.to_path_buf(),
        keep: false,
    };
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(destination)
        .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
    let mut offset = 0u64;
    let mut hasher = blake3::Hasher::new();
    // Keep the copy buffer off the small default Rust test-thread stack. The
    // same helper runs in production, where large input files are expected.
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let count = source
            .file
            .read_at(&mut buffer, offset)
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        if count == 0 {
            break;
        }
        if buffer[..count].iter().any(|byte| *byte != 0) {
            crate::profile::bytes(
                "jail_resource_materialization",
                "copied_physical",
                count as u64,
            );
            output
                .write_all(&buffer[..count])
                .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        } else {
            output
                .seek(SeekFrom::Current(count as i64))
                .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
        }
        hasher.update(&buffer[..count]);
        crate::profile::bytes("resource_hash_verification", "hashed", count as u64);
        offset = offset
            .checked_add(count as u64)
            .ok_or(LaunchRefusal::InputMeasurementFailed)?;
    }
    output
        .set_len(offset)
        .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
    output
        .sync_all_traced()
        .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
    if unsafe { libc::fchown(output.as_raw_fd(), uid, gid) } != 0
        || unsafe { libc::fchmod(output.as_raw_fd(), mode as libc::mode_t) } != 0
    {
        return Err(LaunchRefusal::InputMeasurementFailed);
    }
    output
        .sync_all_traced()
        .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
    let after = source
        .file
        .metadata()
        .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
    if !same_file_version(&before, &after)
        || offset != source.identity.size
        || hasher.finalize().to_hex().as_str() != source.identity.blake3
    {
        return Err(LaunchRefusal::InputChanged);
    }
    let copied = FileIdentity::measure(destination)?;
    if copied.blake3 != source.identity.blake3
        || copied.size != source.identity.size
        || copied.owner() != (uid, gid)
        || copied.mode() & 0o7777 != mode
    {
        return Err(LaunchRefusal::InputBindingMismatch);
    }
    cleanup.keep = true;
    Ok(())
}

struct RemoveOnDrop {
    path: PathBuf,
    keep: bool,
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn validate_workspace_image_identity(
    base: &PinnedInput,
    starting: &PinnedInput,
    working: &PinnedInput,
) -> Result<(), LaunchRefusal> {
    let same_object = |left: &PinnedInput, right: &PinnedInput| {
        left.identity.device == right.identity.device && left.identity.inode == right.identity.inode
    };
    if base.identity.blake3 != starting.identity.blake3
        || starting.identity.blake3 != working.identity.blake3
        || same_object(base, starting)
        || same_object(starting, working)
        || same_object(base, working)
    {
        return Err(LaunchRefusal::InputBindingMismatch);
    }
    Ok(())
}

/// Opaque one-shot capability. Launch consumes it by value; no serializer,
/// public constructor, or `Clone` implementation exists. A downstream caller
/// cannot construct, clone, deserialize, or replay this capability:
/// ```compile_fail
/// use realm_v6::measured_launch::ConsumableInputBinding;
/// fn clone_capability(binding: ConsumableInputBinding) {
///     let _again = binding.clone();
/// }
/// ```
/// ```compile_fail
/// use realm_v6::measured_launch::ConsumableInputBinding;
/// let _: ConsumableInputBinding = serde_json::from_str("{}").unwrap();
/// ```
pub(crate) struct ConsumableInputBinding {
    run_id: String,
    execution_id: String,
    challenge: String,
    s0_root: String,
    policy: PolicyIdentity,
    root: String,
    inputs: PreparedExecutionInputs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct VmmInputFdBindings {
    firecracker: i32,
    kernel: i32,
    rootfs: i32,
    workspace: i32,
}

impl VmmInputFdBindings {
    fn executable_path(self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.firecracker))
    }

    fn resource_path(self, pid: u32, fd: i32) -> PathBuf {
        PathBuf::from(format!("/proc/{pid}/fd/{fd}"))
    }

    fn identities(self, pid: u32) -> [PathBuf; 4] {
        [
            self.resource_path(pid, self.firecracker),
            self.resource_path(pid, self.kernel),
            self.resource_path(pid, self.rootfs),
            self.resource_path(pid, self.workspace),
        ]
    }

    fn diagnostic_bindings(self) -> Vec<String> {
        vec![
            format!("firecracker:{}", self.firecracker),
            format!("kernel:{}", self.kernel),
            format!("rootfs:{}", self.rootfs),
            format!("workspace:{}", self.workspace),
        ]
    }
}

pub(crate) struct DuplicatedVmmInputFds {
    bindings: VmmInputFdBindings,
    descriptors: Vec<i32>,
}

impl DuplicatedVmmInputFds {
    fn duplicate(binding: &ConsumableInputBinding) -> Result<Self, LaunchRefusal> {
        let mut descriptors = Vec::new();
        for file in [
            &binding.inputs.firecracker.file,
            &binding.inputs.kernel.file,
            &binding.inputs.rootfs.file,
            &binding.inputs.working_workspace.file,
        ] {
            // F_DUPFD deliberately clears CLOEXEC on these dedicated copies;
            // the originals remain CLOEXEC and stay owned by the parent.
            let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 64) };
            if fd < 0 {
                return Err(LaunchRefusal::InputMeasurementFailed);
            }
            descriptors.push(fd);
        }
        let bindings = VmmInputFdBindings {
            firecracker: descriptors[0],
            kernel: descriptors[1],
            rootfs: descriptors[2],
            workspace: descriptors[3],
        };
        Ok(Self {
            bindings,
            descriptors,
        })
    }

    pub(crate) fn bindings(self) -> VmmInputFdBindings {
        self.bindings
    }

    pub(crate) fn bindings_executable_path(&self) -> PathBuf {
        self.bindings.executable_path()
    }

    pub(crate) fn bindings_paths(&self, pid: u32) -> [PathBuf; 4] {
        self.bindings.identities(pid)
    }
}

impl Drop for DuplicatedVmmInputFds {
    fn drop(&mut self) {
        for fd in &self.descriptors {
            unsafe {
                libc::close(*fd);
            }
        }
    }
}

pub(crate) struct LaunchedInputResources {
    binding: ConsumableInputBinding,
    vmm_fd_bindings: VmmInputFdBindings,
}

/// Jailer-path binding. It proves the exact copied resources configured by
/// Firecracker without relying on inherited descriptors, which the official
/// jailer closes before executing the VMM.
pub(crate) struct LaunchedJailerInputBinding {
    binding: ConsumableInputBinding,
    resources: JailedResourcePaths,
}

impl ConsumableInputBinding {
    pub(crate) fn duplicate_vmm_inputs(&self) -> Result<DuplicatedVmmInputFds, LaunchRefusal> {
        DuplicatedVmmInputFds::duplicate(self)
    }
    pub(crate) fn guest_supervisor_path(&self) -> PathBuf {
        self.inputs.guest_supervisor.fd_path()
    }
    pub(crate) fn materialize_for_jailer(
        &self,
        jail_root: &Path,
        execution_state: &Path,
        uid: u32,
        gid: u32,
    ) -> Result<JailedResourcePaths, LaunchRefusal> {
        self.inputs
            .materialize_for_jailer(jail_root, execution_state, uid, gid, &self.root)
    }

    fn matches_context(&self, context: &CaptureContext) -> bool {
        let identity_matches = self.matches_identity(
            &context.run_id,
            &context.execution_id,
            &context.challenge,
            &context.s0_root,
            &context.policy,
        );
        let descriptors_match = context.vmm_input_fds.is_some_and(|bindings| {
            let pid = context.vmm.pid();
            let paths = bindings.identities(pid);
            let expected = [
                &self.inputs.firecracker.identity,
                &self.inputs.kernel.identity,
                &self.inputs.rootfs.identity,
                &self.inputs.working_workspace.identity,
            ];
            let contexts = [
                &context.firecracker_path,
                &context.kernel_path,
                &context.rootfs_path,
                &context.workspace_path,
            ];
            paths.iter().zip(contexts).zip(expected).all(
                |((path, expected_context_path), expected_identity)| {
                    path == expected_context_path
                        && FileIdentity::measure(path)
                            .is_ok_and(|actual| actual.same_pinned_resource(expected_identity))
                },
            )
        });
        identity_matches
            && self.inputs.profile == context.profile
            && descriptors_match
            && self.guest_supervisor_path() == context.guest_policy_path
            && FileIdentity::measure(&context.guest_policy_path).is_ok_and(|actual| {
                actual.same_pinned_resource(&self.inputs.guest_supervisor.identity)
            })
    }

    fn matches_identity(
        &self,
        run_id: &str,
        execution_id: &str,
        challenge: &str,
        s0_root: &str,
        policy: &PolicyIdentity,
    ) -> bool {
        self.run_id == run_id
            && self.execution_id == execution_id
            && self.challenge == challenge
            && self.s0_root == s0_root
            && &self.policy == policy
    }

    fn into_measured(
        self,
        vmm_fd_bindings: VmmInputFdBindings,
        vm_config_root: String,
        endpoint: &UnixEndpointIdentity,
        vmm: &VmmIncarnation,
    ) -> Result<(ConsumableInputBindingProof, PreparedExecutionInputs), LaunchRefusal> {
        self.inputs.revalidate()?;
        #[derive(Serialize)]
        struct FinalRoot<'a> {
            input_root: &'a str,
            vm_config_root: &'a str,
            endpoint: &'a UnixEndpointIdentity,
            vmm: &'a VmmIncarnation,
            consumption: &'a ConsumableInputConsumption,
            policy: &'a PolicyIdentity,
        }
        let consumption = ConsumableInputConsumption::Direct {
            vmm_fd_bindings: vmm_fd_bindings.diagnostic_bindings(),
        };
        let final_root = FinalRoot {
            input_root: &self.root,
            vm_config_root: &vm_config_root,
            endpoint,
            vmm,
            consumption: &consumption,
            policy: &self.policy,
        };
        let bytes =
            serde_json::to_vec(&final_root).map_err(|_| LaunchRefusal::InputBindingMismatch)?;
        let proof = ConsumableInputBindingProof {
            run_id: self.run_id,
            execution_id: self.execution_id,
            challenge: self.challenge,
            s0_root: self.s0_root,
            resource_root: self.root,
            consumption,
            vm_config_root,
            vmm_identity_root: domain_hash(
                "REALM::VmmIncarnation",
                1,
                &serde_json::to_vec(vmm).map_err(|_| LaunchRefusal::InputBindingMismatch)?,
            ),
            policy_root: self.policy.blake3().into(),
            root: domain_hash("REALM::ConsumedInputBinding", 1, &bytes),
        };
        Ok((proof, self.inputs))
    }
}

impl LaunchedInputResources {
    pub(crate) fn from_consumed_binding(
        binding: ConsumableInputBinding,
        vmm_fd_bindings: VmmInputFdBindings,
    ) -> Self {
        Self {
            binding,
            vmm_fd_bindings,
        }
    }

    pub(crate) fn vmm_input_fds(&self) -> VmmInputFdBindings {
        self.vmm_fd_bindings
    }

    fn matches_context(&self, context: &CaptureContext) -> bool {
        self.binding.matches_context(context) && Some(self.vmm_fd_bindings) == context.vmm_input_fds
    }

    pub(crate) fn firecracker_path(&self, pid: u32) -> PathBuf {
        self.vmm_fd_bindings
            .resource_path(pid, self.vmm_fd_bindings.firecracker)
    }
    pub(crate) fn kernel_path(&self, pid: u32) -> PathBuf {
        self.vmm_fd_bindings
            .resource_path(pid, self.vmm_fd_bindings.kernel)
    }
    pub(crate) fn rootfs_path(&self, pid: u32) -> PathBuf {
        self.vmm_fd_bindings
            .resource_path(pid, self.vmm_fd_bindings.rootfs)
    }
    pub(crate) fn workspace_path(&self, pid: u32) -> PathBuf {
        self.vmm_fd_bindings
            .resource_path(pid, self.vmm_fd_bindings.workspace)
    }
    pub(crate) fn guest_supervisor_path(&self) -> PathBuf {
        self.binding.guest_supervisor_path()
    }

    fn into_measured(
        self,
        vm_config_root: String,
        endpoint: &UnixEndpointIdentity,
        vmm: &VmmIncarnation,
    ) -> Result<(ConsumableInputBindingProof, PreparedExecutionInputs), LaunchRefusal> {
        self.binding
            .into_measured(self.vmm_fd_bindings, vm_config_root, endpoint, vmm)
    }
}

impl LaunchedJailerInputBinding {
    pub(crate) fn new(binding: ConsumableInputBinding, resources: JailedResourcePaths) -> Self {
        Self { binding, resources }
    }

    fn matches_context(&self, context: &CaptureContext) -> bool {
        let resources = &self.resources;
        self.binding.matches_identity(
            &context.run_id,
            &context.execution_id,
            &context.challenge,
            &context.s0_root,
            &context.policy,
        ) && self.binding.inputs.profile == context.profile
            && context.vmm_input_fds.is_none()
            && context.jail_root_host.is_some()
            && resources.input_binding_root == self.binding.root
            && resources.verify_before_instance_start().is_ok()
            && FileIdentity::measure(&context.firecracker_path)
                .is_ok_and(|actual| actual.blake3() == resources.firecracker_identity.blake3())
            && FileIdentity::measure(&context.kernel_path)
                .is_ok_and(|actual| actual == resources.kernel_identity)
            && FileIdentity::measure(&context.rootfs_path)
                .is_ok_and(|actual| actual == resources.rootfs_identity)
            && FileIdentity::measure(&context.workspace_path)
                .is_ok_and(|actual| actual == resources.workspace_identity)
            && FileIdentity::measure(&context.guest_policy_path).is_ok_and(|actual| {
                actual.same_pinned_resource(&self.binding.inputs.guest_supervisor.identity)
            })
            && self.binding.inputs.firecracker.identity.blake3()
                == resources.firecracker_identity.blake3()
            && self.binding.inputs.kernel.identity.blake3() == resources.kernel_identity.blake3()
            && self.binding.inputs.rootfs.identity.blake3() == resources.rootfs_identity.blake3()
            && self.binding.inputs.working_workspace.identity.blake3()
                == resources.workspace_identity.blake3()
    }

    fn into_measured(
        self,
        vm_config_root: String,
        endpoint: &UnixEndpointIdentity,
        vmm: &VmmIncarnation,
    ) -> Result<(ConsumableInputBindingProof, PreparedExecutionInputs), LaunchRefusal> {
        self.binding.inputs.revalidate()?;
        self.resources.verify_before_instance_start()?;
        #[derive(Serialize)]
        struct FinalRoot<'a> {
            input_root: &'a str,
            vm_config_root: &'a str,
            endpoint: &'a UnixEndpointIdentity,
            vmm: &'a VmmIncarnation,
            jailer_resources: [&'a FileIdentity; 4],
            policy: &'a PolicyIdentity,
        }
        let jailer_resources = [
            &self.resources.firecracker_identity,
            &self.resources.kernel_identity,
            &self.resources.rootfs_identity,
            &self.resources.workspace_identity,
        ];
        let final_root = FinalRoot {
            input_root: &self.binding.root,
            vm_config_root: &vm_config_root,
            endpoint,
            vmm,
            jailer_resources,
            policy: &self.binding.policy,
        };
        let bytes =
            serde_json::to_vec(&final_root).map_err(|_| LaunchRefusal::InputBindingMismatch)?;
        let proof = ConsumableInputBindingProof {
            run_id: self.binding.run_id,
            execution_id: self.binding.execution_id,
            challenge: self.binding.challenge,
            s0_root: self.binding.s0_root,
            resource_root: self.binding.root,
            consumption: ConsumableInputConsumption::OfficialJailer {
                resources: jailer_resources.into_iter().cloned().collect(),
            },
            vm_config_root,
            vmm_identity_root: domain_hash(
                "REALM::VmmIncarnation",
                1,
                &serde_json::to_vec(vmm).map_err(|_| LaunchRefusal::InputBindingMismatch)?,
            ),
            policy_root: self.binding.policy.blake3().into(),
            root: domain_hash("REALM::ConsumedInputBinding", 1, &bytes),
        };
        Ok((proof, self.binding.inputs))
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ConsumableInputBindingProof {
    run_id: String,
    execution_id: String,
    challenge: String,
    s0_root: String,
    resource_root: String,
    consumption: ConsumableInputConsumption,
    vm_config_root: String,
    vmm_identity_root: String,
    policy_root: String,
    root: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum ConsumableInputConsumption {
    Direct { vmm_fd_bindings: Vec<String> },
    OfficialJailer { resources: Vec<FileIdentity> },
}

fn consumed_workspace_path(
    proof: Option<&ConsumableInputBindingProof>,
    inputs: Option<&PreparedExecutionInputs>,
    drives: &[MeasuredDrive],
) -> Option<PathBuf> {
    let attached_path = || {
        drives
            .iter()
            .find(|drive| drive.id == "workspace")
            .map(|drive| PathBuf::from(drive.identity.path()))
    };
    // The jailer consumes a new jail-local inode. The host pin is only an
    // input to materialization and must never be scanned as the final state.
    if proof.is_some_and(|proof| {
        matches!(
            proof.consumption,
            ConsumableInputConsumption::OfficialJailer { .. }
        )
    }) {
        attached_path()
    } else {
        inputs
            .map(|inputs| inputs.working_workspace.fd_path())
            .or_else(attached_path)
    }
}

impl PreparedExecutionInputs {
    fn revalidate(&self) -> Result<(), LaunchRefusal> {
        self.firecracker.revalidate()?;
        self.kernel.revalidate()?;
        self.rootfs.revalidate()?;
        self.base_workspace.revalidate()?;
        self.guest_supervisor.revalidate()?;
        self.starting_workspace.revalidate()?;
        self.working_workspace.revalidate()?;
        self.state_dir.revalidate()?;
        self.run_state_dir.revalidate()
    }

    fn revalidate_after_guest(&self) -> Result<(), LaunchRefusal> {
        self.firecracker.revalidate()?;
        self.kernel.revalidate()?;
        self.rootfs.revalidate()?;
        self.base_workspace.revalidate()?;
        self.guest_supervisor.revalidate()?;
        self.starting_workspace.revalidate()?;
        // The guest is expected to write this image. After InstanceStart, bind
        // its pathname and inode while allowing the content hash to change.
        self.working_workspace.revalidate_object_identity()?;
        self.state_dir.revalidate()?;
        self.run_state_dir.revalidate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UnixEndpointIdentity {
    path: String,
    device: u64,
    inode: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    parent_device: u64,
    parent_inode: u64,
}

impl UnixEndpointIdentity {
    #[cfg(target_os = "linux")]
    pub fn capture_for_vmm_group(
        listener: &UnixListener,
        path: &Path,
        gid: u32,
    ) -> Result<Self, LaunchRefusal> {
        Self::capture_with_owner(listener, path, unsafe { libc::geteuid() }, Some(gid))
    }
    pub fn capture(listener: &UnixListener, path: &Path) -> Result<Self, LaunchRefusal> {
        Self::capture_with_owner(listener, path, unsafe { libc::geteuid() }, None)
    }

    pub(crate) fn capture_with_owner(
        listener: &UnixListener,
        path: &Path,
        expected_uid: u32,
        expected_gid: Option<u32>,
    ) -> Result<Self, LaunchRefusal> {
        let metadata = fs::symlink_metadata(path).map_err(|_| LaunchRefusal::EndpointMismatch)?;
        let parent = path.parent().ok_or(LaunchRefusal::EndpointMismatch)?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(|_| LaunchRefusal::EndpointMismatch)?;
        if !metadata.file_type().is_socket()
            || !parent_metadata.is_dir()
            || metadata.uid() != expected_uid
            || expected_gid.is_some_and(|gid| metadata.gid() != gid)
            || metadata.mode() & 0o077 != 0
        {
            return Err(LaunchRefusal::EndpointMismatch);
        }
        let local = listener
            .local_addr()
            .map_err(|_| LaunchRefusal::EndpointMismatch)?;
        if local.as_pathname() != Some(path) {
            return Err(LaunchRefusal::EndpointMismatch);
        }
        Ok(Self {
            path: path.to_string_lossy().into_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
            owner_gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
            parent_device: parent_metadata.dev(),
            parent_inode: parent_metadata.ino(),
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn device_inode(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

    pub fn owner(&self) -> (u32, u32) {
        (self.owner_uid, self.owner_gid)
    }

    pub fn revalidate(&self) -> Result<(), LaunchRefusal> {
        let path = Path::new(&self.path);
        let metadata = fs::symlink_metadata(path).map_err(|_| LaunchRefusal::EndpointMismatch)?;
        let parent = path.parent().ok_or(LaunchRefusal::EndpointMismatch)?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(|_| LaunchRefusal::EndpointMismatch)?;
        if !metadata.file_type().is_socket()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.owner_uid
            || metadata.gid() != self.owner_gid
            || metadata.mode() & 0o7777 != self.mode
            || parent_metadata.dev() != self.parent_device
            || parent_metadata.ino() != self.parent_inode
        {
            return Err(LaunchRefusal::EndpointMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VmmIncarnation {
    pid: u32,
    boot_id: String,
    start_time_ticks: u64,
    owner_uid: u32,
    owner_gid: u32,
    executable: FileIdentity,
}

impl VmmIncarnation {
    #[cfg(target_os = "linux")]
    pub(crate) fn capture_linux(pid: u32) -> Result<Self, LaunchRefusal> {
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|_| LaunchRefusal::UnsupportedHost)?
            .trim()
            .to_owned();
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| LaunchRefusal::ProcessIncarnationMismatch)?;
        let fields = stat
            .rsplit_once(") ")
            .ok_or(LaunchRefusal::ProcessIncarnationMismatch)?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        let start_time_ticks = fields
            .get(19)
            .ok_or(LaunchRefusal::ProcessIncarnationMismatch)?
            .parse()
            .map_err(|_| LaunchRefusal::ProcessIncarnationMismatch)?;
        let metadata = fs::metadata(format!("/proc/{pid}"))
            .map_err(|_| LaunchRefusal::ProcessIncarnationMismatch)?;
        Ok(Self {
            pid,
            boot_id,
            start_time_ticks,
            owner_uid: metadata.uid(),
            owner_gid: metadata.gid(),
            executable: FileIdentity::measure_opened_executable(pid)?,
        })
    }

    pub fn start_time_ticks(&self) -> u64 {
        self.start_time_ticks
    }
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub(crate) fn executable_identity(&self) -> &FileIdentity {
        &self.executable
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn owner(&self) -> (u32, u32) {
        (self.owner_uid, self.owner_gid)
    }

    pub fn same_process(&self, other: &Self) -> bool {
        self.pid == other.pid
            && self.boot_id == other.boot_id
            && self.start_time_ticks == other.start_time_ticks
            && self.owner_uid == other.owner_uid
            && self.owner_gid == other.owner_gid
            && self.executable.device_inode() == other.executable.device_inode()
            && self.executable.blake3 == other.executable.blake3
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyIdentity {
    identifier: String,
    version: String,
    blake3: String,
    task_blake3: String,
}

impl PolicyIdentity {
    pub(crate) fn new(
        identifier: String,
        version: String,
        bytes: &[u8],
        task_bytes: &[u8],
    ) -> Self {
        let blake3 = domain_hash("REALM::EffectivePolicy", 1, bytes);
        let task_blake3 = domain_hash("REALM::TaskInvocation", 1, task_bytes);
        Self {
            identifier,
            version,
            blake3,
            task_blake3,
        }
    }

    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn blake3(&self) -> &str {
        &self.blake3
    }

    pub fn task_blake3(&self) -> &str {
        &self.task_blake3
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeasuredDrive {
    id: String,
    identity: FileIdentity,
    read_only: bool,
    root_device: bool,
    io_engine: String,
}

impl MeasuredDrive {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    pub fn root_device(&self) -> bool {
        self.root_device
    }

    pub fn io_engine(&self) -> &str {
        &self.io_engine
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct JailerMeasurement {
    mode: &'static str,
    executable: Option<FileIdentity>,
    uid: Option<u32>,
    gid: Option<u32>,
    configuration_blake3: Option<String>,
}

/// Assurance carried by a launch measurement. Direct launches are useful for
/// testing input binding and guest execution, but are never production
/// containment evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LaunchAssuranceGrade {
    DirectFunctional,
    ProductionContained,
}

#[derive(Debug)]
pub struct MeasuredLaunchSession {
    assurance_grade: LaunchAssuranceGrade,
    run_id: String,
    execution_id: String,
    firecracker_version: String,
    firecracker: FileIdentity,
    jailer: JailerMeasurement,
    kernel: FileIdentity,
    rootfs: FileIdentity,
    guest_policy: FileIdentity,
    drives: Vec<MeasuredDrive>,
    machine_config: Value,
    guest_cid: u32,
    uds_path: String,
    broker_endpoint: UnixEndpointIdentity,
    network_interfaces: Vec<Value>,
    policy: PolicyIdentity,
    vmm: VmmIncarnation,
    vmm_birth_identity_root: Option<String>,
    prepared_measurement_root: String,
    vm_config_blake3: String,
    canonical_hash_domain: &'static str,
    canonical_hash_version: u16,
    canonical_hash_blake3: String,
    full_config: Value,
    boot_args: String,
    input_binding_proof: Option<ConsumableInputBindingProof>,
    _pinned_inputs: Option<PreparedExecutionInputs>,
}

/// A measured direct Firecracker run. This proves only functional launch and
/// input/configuration binding; its type cannot satisfy the production
/// terminal-authority boundary.
#[derive(Debug)]
pub struct DirectMeasuredLaunch {
    session: MeasuredLaunchSession,
    evidence_dir: PathBuf,
}

impl DirectMeasuredLaunch {
    pub(crate) fn from_direct_session(
        session: MeasuredLaunchSession,
        evidence_dir: PathBuf,
    ) -> Self {
        debug_assert_eq!(
            session.assurance_grade,
            LaunchAssuranceGrade::DirectFunctional
        );
        debug_assert!(!session.jailer_used());
        Self {
            session,
            evidence_dir,
        }
    }

    pub fn assurance_grade(&self) -> LaunchAssuranceGrade {
        LaunchAssuranceGrade::DirectFunctional
    }

    pub fn evidence_dir(&self) -> &Path {
        &self.evidence_dir
    }
}

impl std::ops::Deref for DirectMeasuredLaunch {
    type Target = MeasuredLaunchSession;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

impl std::ops::Deref for ProductionContainedLaunch {
    type Target = MeasuredLaunchSession;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

#[derive(Debug)]
pub enum LaunchEvidence {
    Direct(Box<DirectMeasuredLaunch>),
    Production(Box<ProductionContainedLaunch>),
}

impl LaunchEvidence {
    pub fn assurance_grade(&self) -> LaunchAssuranceGrade {
        match self {
            Self::Direct(launch) => launch.assurance_grade(),
            Self::Production(launch) => launch.assurance_grade(),
        }
    }

    pub fn direct_evidence_dir(&self) -> Option<&Path> {
        match self {
            Self::Direct(launch) => Some(launch.evidence_dir()),
            Self::Production(_) => None,
        }
    }

    pub fn production_launch_root(&self) -> Option<String> {
        match self {
            Self::Direct(_) => None,
            Self::Production(launch) => Some(launch.production_launch_root()),
        }
    }
}

impl std::ops::Deref for LaunchEvidence {
    type Target = MeasuredLaunchSession;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Direct(launch) => &launch.session,
            Self::Production(launch) => &launch.session,
        }
    }
}

/// Production launch evidence. Its fields and constructors are private; only
/// a strict launcher that has verified jailer containment may create it.
#[derive(Debug)]
pub struct ProductionContainedLaunch {
    session: MeasuredLaunchSession,
    containment: ProductionContainmentEvidence,
}

/// Live containment observation, deliberately ineligible for publication.
/// Only a successful, reaped VMM exit can finish this private intermediate.
pub(crate) struct ObservedContainedLaunch {
    session: MeasuredLaunchSession,
    containment: ProductionContainmentEvidence,
    resources: JailedResourcePaths,
}

impl std::ops::Deref for ObservedContainedLaunch {
    type Target = MeasuredLaunchSession;
    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

impl ObservedContainedLaunch {
    pub(crate) fn observation_record(&self) -> Value {
        serde_json::to_value(&self.containment).expect("containment serialization is infallible")
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn finish_after_exit(
        mut self,
        pid: u32,
        wait_status: i32,
    ) -> Result<ProductionContainedLaunch, LaunchRefusal> {
        let cgroup =
            Path::new("/sys/fs/cgroup").join(self.containment.cgroup.path.trim_start_matches('/'));
        if pid != self.session.vmm.pid()
            || !libc::WIFEXITED(wait_status)
            || libc::WEXITSTATUS(wait_status) != 0
            || Path::new(&format!("/proc/{pid}")).exists()
            || !fs::read_to_string(cgroup.join("cgroup.procs"))
                .is_ok_and(|pids| pids.trim().is_empty())
        {
            return Err(LaunchRefusal::ProcessIncarnationMismatch);
        }
        self.resources.verify_after_guest()?;
        self.containment.vmm_exit_status = Some(wait_status);
        self.session.assurance_grade = LaunchAssuranceGrade::ProductionContained;
        self.session.canonical_hash_blake3 = domain_hash_value(
            "REALM::MeasuredLaunchProductionContained",
            1,
            &serde_json::json!({
                "direct_measurement_root": self.session.canonical_hash_blake3,
                "jailer": &self.session.jailer,
                "containment": &self.containment,
            }),
        )
        .map_err(|_| LaunchRefusal::MalformedConfiguration)?;
        Ok(ProductionContainedLaunch {
            session: self.session,
            containment: self.containment,
        })
    }
}

#[derive(Debug, Serialize)]
struct ProductionContainmentEvidence {
    prestart_measurement_root: String,
    jail_id: String,
    jailer_pid: u32,
    jailer_process: VmmIncarnation,
    jailer_exit_code: i32,
    vmm_exit_status: Option<i32>,
    firecracker_pid: u32,
    firecracker_pid_namespace: u32,
    input_binding_root: String,
    materialized_resources: Vec<FileIdentity>,
    jailer: FileIdentity,
    uid: u32,
    gid: u32,
    user_name: String,
    group_name: String,
    jail_root: DirectoryIdentity,
    cgroup: CgroupIdentity,
    cgroup_parent: CgroupParentIdentity,
    namespaces: NamespaceIdentity,
    seccomp: SeccompEvidence,
}

#[derive(Debug, Serialize)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
}

#[derive(Debug, Serialize)]
struct CgroupIdentity {
    path: String,
    device: u64,
    inode: u64,
    memory_max_bytes: u64,
    pids_max: u32,
    cpu_max: String,
}

#[derive(Debug, Serialize)]
struct CgroupParentIdentity {
    path: String,
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
    subtree_control: Vec<String>,
}

#[derive(Debug, Serialize)]
struct NamespaceIdentity {
    mount: (u64, u64),
    pid: (u64, u64),
    network: (u64, u64),
}

#[derive(Debug, Serialize)]
struct SeccompEvidence {
    mode: u8,
    filter_count: u32,
    release_binary_sha256: String,
}

impl ProductionContainedLaunch {
    /// Measurement consumed before guest start, joined by the private containment producer.
    pub fn prestart_measurement_identity(&self) -> &str {
        &self.containment.prestart_measurement_root
    }
    pub fn assurance_grade(&self) -> LaunchAssuranceGrade {
        LaunchAssuranceGrade::ProductionContained
    }

    pub fn run_id(&self) -> &str {
        self.session.run_id()
    }

    pub fn execution_id(&self) -> &str {
        self.session.execution_id()
    }

    pub fn policy_identity(&self) -> &PolicyIdentity {
        self.session.policy_identity()
    }

    pub fn measured_launch_identity(&self) -> &str {
        self.session.canonical_hash_blake3()
    }

    pub fn vm_config_blake3(&self) -> &str {
        self.session.vm_config_blake3()
    }

    pub fn vmm(&self) -> &VmmIncarnation {
        self.session.vmm()
    }

    /// Root over the exact VMM configuration and typed containment identities.
    /// It is evidence only; publication still requires the private terminal join.
    pub(crate) fn owned_cgroup_device_inode(&self) -> (u64, u64) {
        (
            self.containment.cgroup.device,
            self.containment.cgroup.inode,
        )
    }
    pub(crate) fn owned_pid_namespace_inode(&self) -> u64 {
        self.containment.namespaces.pid.1
    }
    pub fn production_launch_root(&self) -> String {
        let measured_launch = self.session.canonical_hash_blake3();
        let payload = serde_json::json!({
            "assurance_grade": "PRODUCTION_CONTAINED",
            "measured_launch_blake3": measured_launch,
            "containment": &self.containment,
        });
        domain_hash_value("REALM::ProductionContainedLaunch", 1, &payload)
            .expect("production launch evidence serialization is infallible")
    }

    pub(crate) fn containment_record(&self) -> Value {
        serde_json::to_value(&self.containment)
            .expect("production containment evidence serialization is infallible")
    }

    pub(crate) fn cgroup_controllers_record(&self) -> Value {
        let path =
            Path::new("/sys/fs/cgroup").join(self.containment.cgroup.path.trim_start_matches('/'));
        let parent_enabled = fs::read_to_string(
            path.parent()
                .unwrap_or_else(|| Path::new("/sys/fs/cgroup"))
                .join("cgroup.subtree_control"),
        )
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let available = fs::read_to_string(path.join("cgroup.controllers"))
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        serde_json::json!({
            "enabled_for_jailer_cgroup": parent_enabled,
            "available_to_children": available,
            "delegated_limits_observed": {
                "cpu.max": self.containment.cgroup.cpu_max,
                "memory.max": self.containment.cgroup.memory_max_bytes,
                "pids.max": self.containment.cgroup.pids_max,
            }
        })
    }
}

impl ObservedContainedLaunch {
    /// Observe live confinement. This does not mint production authority;
    /// `finish_after_exit` additionally requires a successful VMM exit.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_jailer(
        mut session: MeasuredLaunchSession,
        jail_id: &str,
        jailer_pid: u32,
        jailer_process: VmmIncarnation,
        firecracker_pid: u32,
        firecracker_pid_namespace: u32,
        jailer_path: &Path,
        jailer_sha256: &str,
        firecracker_sha256: &str,
        uid: u32,
        gid: u32,
        jail_root: &Path,
        cgroup_parent: &Path,
        memory_max_bytes: u64,
        pids_max: u32,
        materialized: &JailedResourcePaths,
    ) -> Result<Self, LaunchRefusal> {
        const JAILER_SHA256: &str =
            "65ef226e96f0ceda55ba643f445801ef2cc0ea667ef67cad8ac4f406c9c8434f";
        const FIRECRACKER_SHA256: &str =
            "99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5";
        let (user_name, group_name) =
            require_realm_fc_identity(uid, gid).map_err(|_| LaunchRefusal::UnsupportedHost)?;
        if session.assurance_grade != LaunchAssuranceGrade::DirectFunctional
            || jail_id.is_empty()
            || jail_id.len() > 64
            || !jail_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || jailer_pid == 0
            || firecracker_pid == 0
            || jailer_pid == firecracker_pid
            || uid == 0
            || gid == 0
            || jailer_sha256 != JAILER_SHA256
            || firecracker_sha256 != FIRECRACKER_SHA256
            || !session.network_is_explicitly_empty()
            || materialized.input_binding_root.len() != 64
        {
            return Err(LaunchRefusal::UnsupportedHost);
        }
        materialized.verify_after_guest()?;
        let binding_proof = session
            .input_binding_proof
            .as_ref()
            .ok_or(LaunchRefusal::InputBindingMismatch)?;
        let jail_identity_material = format!(
            "{}:{}:{}",
            binding_proof.run_id, binding_proof.execution_id, binding_proof.challenge
        );
        let expected_jail_id = format!(
            "realm-{}",
            &blake3::hash(jail_identity_material.as_bytes())
                .to_hex()
                .to_string()[..32]
        );
        if binding_proof.run_id != session.run_id
            || binding_proof.execution_id != session.execution_id
            || binding_proof.resource_root != materialized.input_binding_root
            || jail_id != expected_jail_id
        {
            return Err(LaunchRefusal::InputBindingMismatch);
        }
        let workspace_matches = if session.supports_measured_brokered_c0_profile() {
            !session.drives.iter().any(|drive| !drive.read_only)
                && materialized.workspace_identity.owner() == (0, 0)
                && materialized.workspace_identity.mode() == 0o444
                && !materialized.workspace_host_path.starts_with(jail_root)
        } else {
            session
                .drives
                .iter()
                .find(|drive| drive.id == "workspace")
                .is_some_and(|drive| {
                    drive.identity == materialized.workspace_identity && !drive.read_only
                })
        };
        if session.firecracker.blake3() != materialized.firecracker_identity.blake3()
            || session.kernel != materialized.kernel_identity
            || session.rootfs != materialized.rootfs_identity
            || !workspace_matches
        {
            return Err(LaunchRefusal::InputBindingMismatch);
        }
        if session.vmm.pid() != firecracker_pid {
            return Err(LaunchRefusal::ProcessIncarnationMismatch);
        }

        let status_path = format!("/proc/{firecracker_pid}/status");
        let status = fs::read_to_string(status_path).map_err(|_| LaunchRefusal::UnsupportedHost)?;
        let parent_pid = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(LaunchRefusal::ProcessIncarnationMismatch)?;
        // The official --new-pid-ns jailer exits after clone. The supervisor
        // is a child subreaper and must now own the measured VMM directly.
        if parent_pid != std::process::id() || jailer_process.pid() != jailer_pid {
            return Err(LaunchRefusal::ProcessIncarnationMismatch);
        }
        let read_status_number = |key: &str| -> Result<u64, LaunchRefusal> {
            status
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{key}:")))
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse().ok())
                .ok_or(LaunchRefusal::UnsupportedHost)
        };
        let effective_uid = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|value| value.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(LaunchRefusal::UnsupportedHost)?;
        let effective_gid = status
            .lines()
            .find_map(|line| line.strip_prefix("Gid:"))
            .and_then(|value| value.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(LaunchRefusal::UnsupportedHost)?;
        let seccomp_mode = read_status_number("Seccomp")? as u8;
        let seccomp_filters = read_status_number("Seccomp_filters")? as u32;
        if effective_uid != uid || effective_gid != gid || seccomp_mode != 2 || seccomp_filters == 0
        {
            return Err(LaunchRefusal::UnsupportedHost);
        }

        let jail_root_meta =
            fs::symlink_metadata(jail_root).map_err(|_| LaunchRefusal::UnsupportedHost)?;
        if !jail_root_meta.is_dir()
            || jail_root_meta.uid() != 0
            || jail_root_meta.gid() != 0
            || jail_root_meta.mode() & 0o777 != 0o755
        {
            return Err(LaunchRefusal::UnsupportedHost);
        }
        let observed_namespace_pid = status
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:"))
            .and_then(|value| value.split_whitespace().last())
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(LaunchRefusal::UnsupportedHost)?;
        if observed_namespace_pid != firecracker_pid_namespace || observed_namespace_pid != 1 {
            return Err(LaunchRefusal::ProcessIncarnationMismatch);
        }
        let process_root = fs::metadata(format!("/proc/{firecracker_pid}/root"))
            .map_err(|_| LaunchRefusal::UnsupportedHost)?;
        if process_root.dev() != jail_root_meta.dev() || process_root.ino() != jail_root_meta.ino()
        {
            return Err(LaunchRefusal::UnsupportedHost);
        }

        let cgroup_text = fs::read_to_string(format!("/proc/{firecracker_pid}/cgroup"))
            .map_err(|_| LaunchRefusal::UnsupportedHost)?;
        let cgroup_relative = cgroup_text
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or(LaunchRefusal::UnsupportedHost)?;
        let cgroup_path = Path::new("/sys/fs/cgroup").join(cgroup_relative.trim_start_matches('/'));
        let expected_cgroup = Path::new("/").join(cgroup_parent).join(jail_id);
        if Path::new(cgroup_relative) != expected_cgroup {
            return Err(LaunchRefusal::UnsupportedHost);
        }
        let cgroup_members = fs::read_to_string(cgroup_path.join("cgroup.procs"))
            .map_err(|_| LaunchRefusal::UnsupportedHost)?;
        if !cgroup_members
            .lines()
            .any(|pid| pid.parse::<u32>().ok() == Some(firecracker_pid))
        {
            return Err(LaunchRefusal::UnsupportedHost);
        }
        let cgroup_parent_path = Path::new("/sys/fs/cgroup").join(cgroup_parent);
        let cgroup_parent_meta = fs::symlink_metadata(&cgroup_parent_path)
            .map_err(|_| LaunchRefusal::UnsupportedHost)?;
        if !cgroup_parent_meta.is_dir()
            || cgroup_parent_meta.uid() != 0
            || cgroup_parent_meta.mode() & 0o022 != 0
        {
            return Err(LaunchRefusal::UnsupportedHost);
        }
        let subtree_control = fs::read_to_string(cgroup_parent_path.join("cgroup.subtree_control"))
            .map_err(|_| LaunchRefusal::UnsupportedHost)?
            .split_whitespace()
            .map(|controller| controller.trim_start_matches('+').to_owned())
            .collect::<Vec<_>>();
        if !["cpu", "memory", "pids"]
            .into_iter()
            .all(|controller| subtree_control.iter().any(|enabled| enabled == controller))
        {
            return Err(LaunchRefusal::UnsupportedHost);
        }
        let actual_memory = fs::read_to_string(cgroup_path.join("memory.max"))
            .map_err(|_| LaunchRefusal::UnsupportedHost)?
            .trim()
            .parse::<u64>()
            .map_err(|_| LaunchRefusal::UnsupportedHost)?;
        let actual_pids = fs::read_to_string(cgroup_path.join("pids.max"))
            .map_err(|_| LaunchRefusal::UnsupportedHost)?
            .trim()
            .parse::<u32>()
            .map_err(|_| LaunchRefusal::UnsupportedHost)?;
        let actual_cpu = fs::read_to_string(cgroup_path.join("cpu.max"))
            .map_err(|_| LaunchRefusal::UnsupportedHost)?
            .trim()
            .to_owned();
        if actual_memory != memory_max_bytes
            || actual_pids != pids_max
            || actual_cpu != "100000 100000"
        {
            return Err(LaunchRefusal::UnsupportedHost);
        }
        let cgroup_meta = fs::metadata(&cgroup_path).map_err(|_| LaunchRefusal::UnsupportedHost)?;

        let namespace_identity = |name: &str| -> Result<(u64, u64), LaunchRefusal> {
            let metadata = fs::metadata(format!("/proc/{firecracker_pid}/ns/{name}"))
                .map_err(|_| LaunchRefusal::UnsupportedHost)?;
            Ok((metadata.dev(), metadata.ino()))
        };
        let namespaces = NamespaceIdentity {
            mount: namespace_identity("mnt")?,
            pid: namespace_identity("pid")?,
            network: namespace_identity("net")?,
        };
        let supervisor_pid_ns =
            fs::metadata("/proc/self/ns/pid").map_err(|_| LaunchRefusal::UnsupportedHost)?;
        let supervisor_mount_ns =
            fs::metadata("/proc/self/ns/mnt").map_err(|_| LaunchRefusal::UnsupportedHost)?;
        let supervisor_network_ns =
            fs::metadata("/proc/self/ns/net").map_err(|_| LaunchRefusal::UnsupportedHost)?;
        if namespaces.pid == (supervisor_pid_ns.dev(), supervisor_pid_ns.ino()) {
            return Err(LaunchRefusal::UnsupportedHost);
        }
        if namespaces.mount == (supervisor_mount_ns.dev(), supervisor_mount_ns.ino()) {
            return Err(LaunchRefusal::UnsupportedHost);
        }
        if namespaces.network != (supervisor_network_ns.dev(), supervisor_network_ns.ino()) {
            return Err(LaunchRefusal::UnsupportedHost);
        }

        let materialized_resources = [
            &materialized.kernel_host_path,
            &materialized.rootfs_host_path,
            &materialized.workspace_host_path,
        ]
        .into_iter()
        .map(|path| FileIdentity::measure(path))
        .collect::<Result<Vec<_>, _>>()?;
        let jailer = FileIdentity::measure(jailer_path)?;
        if !jailer.trusted_parent_chain()
            || jailer.owner() != (0, 0)
            || jailer.mode() & 0o022 != 0
            || jailer.mode() & 0o100 == 0
            || jailer_process.owner() != (0, 0)
            || jailer_process.executable.blake3() != jailer.blake3()
            || jailer_process.executable.device_inode() != jailer.device_inode()
            || !materialized.firecracker_identity.trusted_parent_chain()
            || materialized.firecracker_identity.owner() != (0, 0)
            || materialized.firecracker_identity.mode() & 0o022 != 0
            || materialized.firecracker_identity.mode() & 0o100 == 0
        {
            return Err(LaunchRefusal::InputMeasurementFailed);
        }
        let jailer_config_bytes = serde_json::to_vec(&serde_json::json!({
            "jail_id": jail_id,
            "uid": uid,
            "gid": gid,
            "cgroup_parent": cgroup_parent,
            "memory.max": memory_max_bytes,
            "pids.max": pids_max,
            "cpu.max": "100000 100000",
            "new_pid_ns": true,
            "guest_network": false,
            "seccomp": "firecracker-default",
        }))
        .map_err(|_| LaunchRefusal::MalformedConfiguration)?;
        let jailer_config_blake3 = blake3::hash(&jailer_config_bytes).to_hex().to_string();
        let jail_root_identity = DirectoryIdentity {
            device: jail_root_meta.dev(),
            inode: jail_root_meta.ino(),
            owner: jail_root_meta.uid(),
            group: jail_root_meta.gid(),
            mode: jail_root_meta.mode() & 0o7777,
        };
        let containment = ProductionContainmentEvidence {
            prestart_measurement_root: session.canonical_hash_blake3().to_owned(),
            jail_id: jail_id.into(),
            jailer_pid,
            jailer_process,
            jailer_exit_code: 0,
            vmm_exit_status: None,
            firecracker_pid,
            firecracker_pid_namespace,
            input_binding_root: materialized.input_binding_root.clone(),
            materialized_resources,
            jailer: jailer.clone(),
            uid,
            gid,
            user_name,
            group_name,
            jail_root: jail_root_identity,
            cgroup: CgroupIdentity {
                path: cgroup_relative.into(),
                device: cgroup_meta.dev(),
                inode: cgroup_meta.ino(),
                memory_max_bytes: actual_memory,
                pids_max: actual_pids,
                cpu_max: actual_cpu,
            },
            cgroup_parent: CgroupParentIdentity {
                path: cgroup_parent.to_string_lossy().into_owned(),
                device: cgroup_parent_meta.dev(),
                inode: cgroup_parent_meta.ino(),
                owner: cgroup_parent_meta.uid(),
                group: cgroup_parent_meta.gid(),
                mode: cgroup_parent_meta.mode() & 0o7777,
                subtree_control,
            },
            namespaces,
            seccomp: SeccompEvidence {
                mode: seccomp_mode,
                filter_count: seccomp_filters,
                release_binary_sha256: firecracker_sha256.into(),
            },
        };
        session.jailer = JailerMeasurement {
            mode: "official-firecracker-jailer-v1.17.0",
            executable: Some(jailer),
            uid: Some(uid),
            gid: Some(gid),
            configuration_blake3: Some(jailer_config_blake3),
        };
        Ok(Self {
            session,
            containment,
            resources: materialized.clone(),
        })
    }
}

/// Require the host's dedicated Firecracker account, rather than accepting an
/// arbitrary non-root UID/GID supplied by the request configuration.
pub(crate) fn require_realm_fc_identity(
    uid: u32,
    gid: u32,
) -> Result<(String, String), LaunchRefusal> {
    let passwd = fs::read_to_string("/etc/passwd").map_err(|_| LaunchRefusal::UnsupportedHost)?;
    let group = fs::read_to_string("/etc/group").map_err(|_| LaunchRefusal::UnsupportedHost)?;
    parse_realm_fc_identity(&passwd, &group, uid, gid)
}

fn parse_realm_fc_identity(
    passwd: &str,
    group: &str,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(String, String), LaunchRefusal> {
    let mut users = Vec::new();
    for line in passwd
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 4 {
            return Err(LaunchRefusal::UnsupportedHost);
        }
        let uid = fields[2]
            .parse::<u32>()
            .map_err(|_| LaunchRefusal::UnsupportedHost)?;
        let gid = fields[3]
            .parse::<u32>()
            .map_err(|_| LaunchRefusal::UnsupportedHost)?;
        users.push((fields[0], uid, gid));
    }
    let named_users = users
        .iter()
        .filter(|(name, _, _)| *name == "realm-fc")
        .count();
    let uid_aliases = users
        .iter()
        .filter(|(_, uid, _)| *uid == expected_uid)
        .count();
    let Some((user_name, _, primary_gid)) = users.iter().find(|(name, uid, gid)| {
        *name == "realm-fc" && *uid == expected_uid && *gid == expected_gid
    }) else {
        return Err(LaunchRefusal::UnsupportedHost);
    };
    if named_users != 1 || uid_aliases != 1 || *primary_gid != expected_gid {
        return Err(LaunchRefusal::UnsupportedHost);
    }

    let mut groups = Vec::new();
    for line in group
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 3 {
            return Err(LaunchRefusal::UnsupportedHost);
        }
        let gid = fields[2]
            .parse::<u32>()
            .map_err(|_| LaunchRefusal::UnsupportedHost)?;
        groups.push((fields[0], gid));
    }
    let named_groups = groups
        .iter()
        .filter(|(name, _)| *name == "realm-fc")
        .count();
    let gid_aliases = groups
        .iter()
        .filter(|(_, gid)| *gid == expected_gid)
        .count();
    let Some((group_name, _)) = groups
        .iter()
        .find(|(name, gid)| *name == "realm-fc" && *gid == expected_gid)
    else {
        return Err(LaunchRefusal::UnsupportedHost);
    };
    if named_groups != 1 || gid_aliases != 1 {
        return Err(LaunchRefusal::UnsupportedHost);
    }
    Ok(((*user_name).to_owned(), (*group_name).to_owned()))
}

pub(crate) struct CaptureContext {
    pub profile: LaunchProfile,
    pub vmm_birth_identity_root: Option<String>,
    pub run_id: String,
    pub execution_id: String,
    pub challenge: String,
    pub s0_root: String,
    pub firecracker_version: String,
    pub firecracker_path: PathBuf,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub workspace_path: PathBuf,
    pub guest_policy_path: PathBuf,
    pub uds_path: PathBuf,
    /// Host-visible directory backing `/` in the jailer's chroot. API paths
    /// stay jail-relative and are resolved through this directory for file
    /// identity checks.
    pub jail_root_host: Option<PathBuf>,
    pub broker_endpoint: UnixEndpointIdentity,
    pub policy: PolicyIdentity,
    pub vmm: VmmIncarnation,
    pub vmm_input_fds: Option<VmmInputFdBindings>,
    pub input_binding: Option<LaunchedInputResources>,
    pub jailer_input_binding: Option<LaunchedJailerInputBinding>,
}

pub struct C0DiagnosticCaptureContext {
    pub run_id: String,
    pub execution_id: String,
    pub challenge: String,
    pub s0_root: String,
    pub expected_vmm_start_ticks: u64,
    pub expected_vmm_gid: u32,
    pub firecracker_version: String,
    pub firecracker_path: PathBuf,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub guest_policy_path: PathBuf,
    pub uds_path: PathBuf,
    pub broker_endpoint: UnixEndpointIdentity,
    pub policy_identifier: String,
    pub policy_version: String,
    pub policy_bytes: Vec<u8>,
    pub task_bytes: Vec<u8>,
    pub vmm_pid: u32,
}

impl MeasuredLaunchSession {
    #[cfg(target_os = "linux")]
    pub fn capture_c0_diagnostic(
        bytes: &[u8],
        c: C0DiagnosticCaptureContext,
    ) -> Result<Self, LaunchRefusal> {
        let vmm = VmmIncarnation::capture_linux(c.vmm_pid)?;
        if vmm.start_time_ticks() != c.expected_vmm_start_ticks
            || vmm.owner().1 != c.expected_vmm_gid
            || c.broker_endpoint.owner().1 != c.expected_vmm_gid
        {
            return Err(LaunchRefusal::ProcessIncarnationMismatch);
        }
        Self::capture(
            bytes,
            CaptureContext {
                profile: LaunchProfile::RootfsBroker,
                vmm_birth_identity_root: None,
                run_id: c.run_id,
                execution_id: c.execution_id,
                challenge: c.challenge,
                s0_root: c.s0_root,
                firecracker_version: c.firecracker_version,
                firecracker_path: c.firecracker_path,
                kernel_path: c.kernel_path,
                rootfs_path: c.rootfs_path,
                workspace_path: PathBuf::new(),
                guest_policy_path: c.guest_policy_path,
                uds_path: c.uds_path,
                jail_root_host: None,
                broker_endpoint: c.broker_endpoint,
                policy: PolicyIdentity::new(
                    c.policy_identifier,
                    c.policy_version,
                    &c.policy_bytes,
                    &c.task_bytes,
                ),
                vmm,
                vmm_input_fds: None,
                input_binding: None,
                jailer_input_binding: None,
            },
        )
    }
    #[cfg(target_os = "linux")]
    pub fn revalidate_c0_diagnostic(&self, bytes: &[u8]) -> Result<(), LaunchRefusal> {
        self.revalidate_inputs()?;
        self.verify_same_config(bytes)?;
        if !self
            .vmm
            .same_process(&VmmIncarnation::capture_linux(self.vmm.pid())?)
        {
            return Err(LaunchRefusal::ProcessIncarnationMismatch);
        }
        Ok(())
    }

    pub(crate) fn capture(
        actual_full_config: &[u8],
        mut context: CaptureContext,
    ) -> Result<Self, LaunchRefusal> {
        if context.run_id.is_empty() || context.execution_id.is_empty() {
            return Err(LaunchRefusal::MalformedConfiguration);
        }
        let full_config: Value = serde_json::from_slice(actual_full_config)
            .map_err(|_| LaunchRefusal::MalformedConfiguration)?;
        let full_config = canonicalize_json(full_config);
        let root = full_config
            .as_object()
            .ok_or(LaunchRefusal::MalformedConfiguration)?;
        reject_unknown_top_level(root)?;

        let boot_source = object_field(root, "boot-source")?;
        let configured_kernel = path_field(boot_source, "kernel_image_path")?;
        let kernel = FileIdentity::measure(&resolve_configured_path(
            configured_kernel,
            context.jail_root_host.as_deref(),
        )?)?;
        let expected_kernel = FileIdentity::measure(&context.kernel_path)?;
        if kernel != expected_kernel {
            return Err(LaunchRefusal::TopologyMismatch);
        }
        let boot_args = string_field(boot_source, "boot_args")?.to_owned();
        if boot_args
            != match context.profile {
                LaunchProfile::Workspace => EXPECTED_BOOT_ARGS,
                LaunchProfile::RootfsBroker => BROKER_BOOT_ARGS,
            }
        {
            return Err(LaunchRefusal::TopologyMismatch);
        }

        let drives_value = root
            .get("drives")
            .and_then(Value::as_array)
            .ok_or(LaunchRefusal::MalformedConfiguration)?;
        let mut drives = Vec::with_capacity(drives_value.len());
        let mut seen = std::collections::BTreeSet::new();
        for value in drives_value {
            let drive = value
                .as_object()
                .ok_or(LaunchRefusal::MalformedConfiguration)?;
            let id = string_field(drive, "drive_id")?.to_owned();
            if !seen.insert(id.clone()) {
                return Err(LaunchRefusal::TopologyMismatch);
            }
            let configured_path = path_field(drive, "path_on_host")?;
            let expected_path = match id.as_str() {
                "rootfs" => &context.rootfs_path,
                "workspace" => &context.workspace_path,
                _ => return Err(LaunchRefusal::UnsupportedConfiguration),
            };
            let identity = FileIdentity::measure(&resolve_configured_path(
                configured_path,
                context.jail_root_host.as_deref(),
            )?)?;
            let expected_identity = FileIdentity::measure(expected_path)?;
            let expected_read_only = id == "rootfs";
            let expected_root = id == "rootfs";
            if identity != expected_identity
                || bool_field(drive, "is_read_only")? != expected_read_only
                || bool_field(drive, "is_root_device")? != expected_root
                || string_field(drive, "io_engine")? != "Sync"
            {
                return Err(LaunchRefusal::TopologyMismatch);
            }
            drives.push(MeasuredDrive {
                id,
                identity,
                read_only: expected_read_only,
                root_device: expected_root,
                io_engine: "Sync".into(),
            });
        }
        drives.sort_by(|left, right| left.id.cmp(&right.id));
        let expected_drives = match context.profile {
            LaunchProfile::Workspace => 2,
            LaunchProfile::RootfsBroker => 1,
        };
        if seen.len() != expected_drives
            || !seen.contains("rootfs")
            || (context.profile == LaunchProfile::Workspace && !seen.contains("workspace"))
        {
            return Err(LaunchRefusal::TopologyMismatch);
        }
        if context.profile == LaunchProfile::RootfsBroker
            && context.jailer_input_binding.is_some()
            && context.vmm_birth_identity_root.is_none()
        {
            return Err(LaunchRefusal::ProcessIncarnationMismatch);
        }
        let rootfs = drives
            .iter()
            .find(|drive| drive.id == "rootfs")
            .ok_or(LaunchRefusal::TopologyMismatch)?
            .identity
            .clone();

        let machine_config = root
            .get("machine-config")
            .cloned()
            .ok_or(LaunchRefusal::MalformedConfiguration)?;
        if machine_config.get("vcpu_count").and_then(Value::as_u64) != Some(1)
            || machine_config.get("mem_size_mib").and_then(Value::as_u64) != Some(256)
            || machine_config.get("smt").and_then(Value::as_bool) != Some(false)
        {
            return Err(LaunchRefusal::TopologyMismatch);
        }

        let network_interfaces = root
            .get("network-interfaces")
            .and_then(Value::as_array)
            .cloned()
            .ok_or(LaunchRefusal::MalformedConfiguration)?;
        if !network_interfaces.is_empty() {
            return Err(LaunchRefusal::UnsupportedConfiguration);
        }
        reject_unsupported_devices(root)?;

        let vsock = object_field(root, "vsock")?;
        let guest_cid = number_field(vsock, "guest_cid")?;
        let uds_path = path_field(vsock, "uds_path")?.to_owned();
        if guest_cid != 3
            || canonical_socket_prefix(Path::new(&uds_path))?
                != canonical_socket_prefix(Path::new(&context.uds_path))?
        {
            return Err(LaunchRefusal::TopologyMismatch);
        }
        context.broker_endpoint.revalidate()?;
        let endpoint_prefix = canonical_socket_prefix(Path::new(&uds_path))?;
        let endpoint_prefix = resolve_configured_path(
            &endpoint_prefix.to_string_lossy(),
            context.jail_root_host.as_deref(),
        )?;
        let expected_endpoint =
            PathBuf::from(format!("{}_{}", endpoint_prefix.display(), GUEST_TASK_PORT));
        if fs::canonicalize(&context.broker_endpoint.path).ok()
            != fs::canonicalize(&expected_endpoint).ok()
        {
            return Err(LaunchRefusal::EndpointMismatch);
        }

        let firecracker = FileIdentity::measure(&context.firecracker_path)?;
        if firecracker.device_inode() != context.vmm.executable.device_inode()
            || firecracker.blake3 != context.vmm.executable.blake3
        {
            return Err(LaunchRefusal::ProcessIncarnationMismatch);
        }
        let guest_policy = FileIdentity::measure(&context.guest_policy_path)?;
        let vm_config_blake3 = domain_hash_value(CONFIG_HASH_DOMAIN, 1, &full_config)?;
        if context.input_binding.is_some() && context.jailer_input_binding.is_some() {
            return Err(LaunchRefusal::InputBindingMismatch);
        }
        let (input_binding_proof, pinned_inputs) =
            if let Some(binding) = context.input_binding.take() {
                if !binding.matches_context(&context) {
                    return Err(LaunchRefusal::InputBindingMismatch);
                }
                let (proof, pins) = binding.into_measured(
                    vm_config_blake3.clone(),
                    &context.broker_endpoint,
                    &context.vmm,
                )?;
                (Some(proof), Some(pins))
            } else if let Some(binding) = context.jailer_input_binding.take() {
                if !binding.matches_context(&context) {
                    return Err(LaunchRefusal::InputBindingMismatch);
                }
                let (proof, pins) = binding.into_measured(
                    vm_config_blake3.clone(),
                    &context.broker_endpoint,
                    &context.vmm,
                )?;
                (Some(proof), Some(pins))
            } else {
                (None, None)
            };
        let jailer = JailerMeasurement {
            mode: "direct-firecracker-no-jailer",
            executable: None,
            uid: None,
            gid: None,
            configuration_blake3: None,
        };

        #[derive(Serialize)]
        struct SessionPayload<'a> {
            assurance_grade: LaunchAssuranceGrade,
            run_id: &'a str,
            execution_id: &'a str,
            firecracker_version: &'a str,
            firecracker: &'a FileIdentity,
            jailer: &'a JailerMeasurement,
            inherited_fds_status: &'static str,
            kernel: &'a FileIdentity,
            rootfs: &'a FileIdentity,
            guest_policy: &'a FileIdentity,
            drives: &'a [MeasuredDrive],
            machine_config: &'a Value,
            guest_cid: u32,
            uds_path: &'a str,
            broker_endpoint: &'a UnixEndpointIdentity,
            network_interfaces: &'a [Value],
            policy: &'a PolicyIdentity,
            vmm: &'a VmmIncarnation,
            vmm_birth_identity_root: Option<&'a str>,
            vm_config_blake3: &'a str,
            boot_args: &'a str,
            input_binding_proof: Option<&'a ConsumableInputBindingProof>,
            full_config: &'a Value,
        }
        let payload = SessionPayload {
            assurance_grade: LaunchAssuranceGrade::DirectFunctional,
            run_id: &context.run_id,
            execution_id: &context.execution_id,
            firecracker_version: &context.firecracker_version,
            firecracker: &firecracker,
            jailer: &jailer,
            inherited_fds_status: if context.vmm_input_fds.is_some() {
                "BACKEND_INPUT_FDS_INHERITED_AND_BOUND"
            } else {
                "UNMEASURED"
            },
            kernel: &kernel,
            rootfs: &rootfs,
            guest_policy: &guest_policy,
            drives: &drives,
            machine_config: &machine_config,
            guest_cid,
            uds_path: &uds_path,
            broker_endpoint: &context.broker_endpoint,
            network_interfaces: &network_interfaces,
            policy: &context.policy,
            vmm: &context.vmm,
            vmm_birth_identity_root: context.vmm_birth_identity_root.as_deref(),
            vm_config_blake3: &vm_config_blake3,
            boot_args: &boot_args,
            input_binding_proof: input_binding_proof.as_ref(),
            full_config: &full_config,
        };
        let payload_bytes =
            serde_json::to_vec(&payload).map_err(|_| LaunchRefusal::MalformedConfiguration)?;
        let canonical_hash_blake3 = domain_hash(
            MEASURED_LAUNCH_HASH_DOMAIN,
            MEASURED_LAUNCH_HASH_VERSION,
            &payload_bytes,
        );

        Ok(Self {
            assurance_grade: LaunchAssuranceGrade::DirectFunctional,
            run_id: context.run_id,
            execution_id: context.execution_id,
            firecracker_version: context.firecracker_version,
            firecracker,
            jailer,
            kernel,
            rootfs,
            guest_policy,
            drives,
            machine_config,
            guest_cid,
            uds_path,
            broker_endpoint: context.broker_endpoint,
            network_interfaces,
            policy: context.policy,
            vmm: context.vmm,
            vmm_birth_identity_root: context.vmm_birth_identity_root,
            prepared_measurement_root: canonical_hash_blake3.clone(),
            vm_config_blake3,
            canonical_hash_domain: MEASURED_LAUNCH_HASH_DOMAIN,
            canonical_hash_version: MEASURED_LAUNCH_HASH_VERSION,
            canonical_hash_blake3,
            full_config,
            boot_args,
            input_binding_proof,
            _pinned_inputs: pinned_inputs,
        })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub fn firecracker_version(&self) -> &str {
        &self.firecracker_version
    }

    pub fn firecracker_identity(&self) -> &FileIdentity {
        &self.firecracker
    }

    fn jailer_used(&self) -> bool {
        self.jailer.executable.is_some()
    }

    pub fn assurance_grade(&self) -> LaunchAssuranceGrade {
        self.assurance_grade
    }

    /// Durably records the exact API configuration read immediately before
    /// `InstanceStart`, together with the consumed input and VMM identities.
    /// This record is direct functional evidence and carries no production
    /// containment authority.
    pub(crate) fn write_direct_prestart_evidence(
        &self,
        api_configuration_bytes: &[u8],
        destination: &Path,
    ) -> Result<(), LaunchRefusal> {
        let api_configuration: Value = serde_json::from_slice(api_configuration_bytes)
            .map_err(|_| LaunchRefusal::MalformedConfiguration)?;
        let record = serde_json::json!({
            "schema_version": 1,
            "source_commit": option_env!("REALM_SOURCE_COMMIT"),
            "assurance_grade": "DIRECT_FUNCTIONAL",
            "run_id": &self.run_id,
            "execution_id": &self.execution_id,
            "consumable_input_binding_proof": &self.input_binding_proof,
            "firecracker_version": &self.firecracker_version,
            "firecracker_identity": &self.firecracker,
            "kernel_identity": &self.kernel,
            "rootfs_identity": &self.rootfs,
            "guest_supervisor_identity": &self.guest_policy,
            "drives": &self.drives,
            "machine_config": &self.machine_config,
            "guest_cid": self.guest_cid,
            "boot_args": &self.boot_args,
            "network_interfaces": &self.network_interfaces,
            "broker_endpoint": &self.broker_endpoint,
            "vmm_incarnation": &self.vmm,
            "vm_config_blake3": &self.vm_config_blake3,
            "measured_launch_domain": self.canonical_hash_domain,
            "measured_launch_version": self.canonical_hash_version,
            "measured_launch_blake3": &self.canonical_hash_blake3,
            "actual_api_configuration": api_configuration,
            "actual_api_configuration_bytes_blake3": blake3::hash(api_configuration_bytes).to_hex().to_string(),
            "observation_point": "read_and_verified_immediately_before_InstanceStart"
        });
        write_new_json_record(destination, &record)
    }

    pub fn kernel_identity(&self) -> &FileIdentity {
        &self.kernel
    }

    pub fn rootfs_identity(&self) -> &FileIdentity {
        &self.rootfs
    }

    pub fn guest_policy_identity(&self) -> &FileIdentity {
        &self.guest_policy
    }

    pub fn machine_config(&self) -> &Value {
        &self.machine_config
    }

    pub fn guest_cid(&self) -> u32 {
        self.guest_cid
    }

    pub fn uds_path(&self) -> &str {
        &self.uds_path
    }

    pub fn policy_identity(&self) -> &PolicyIdentity {
        &self.policy
    }

    pub fn boot_args(&self) -> &str {
        &self.boot_args
    }

    pub fn full_config(&self) -> &Value {
        &self.full_config
    }

    pub fn vm_config_blake3(&self) -> &str {
        &self.vm_config_blake3
    }

    pub fn canonical_hash_domain(&self) -> &str {
        self.canonical_hash_domain
    }

    pub fn canonical_hash_version(&self) -> u16 {
        self.canonical_hash_version
    }

    pub fn canonical_hash_blake3(&self) -> &str {
        &self.canonical_hash_blake3
    }

    pub fn drives(&self) -> &[MeasuredDrive] {
        &self.drives
    }

    pub fn network_is_explicitly_empty(&self) -> bool {
        self.network_interfaces.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn consumable_input_binding_proof(&self) -> Option<&ConsumableInputBindingProof> {
        self.input_binding_proof.as_ref()
    }

    pub(crate) fn workspace_resource_path(&self) -> Option<PathBuf> {
        consumed_workspace_path(
            self.input_binding_proof.as_ref(),
            self._pinned_inputs.as_ref(),
            &self.drives,
        )
    }

    pub fn consumable_input_binding(&self) -> bool {
        self.input_binding_proof.is_some()
    }
    pub(crate) fn supports_measured_brokered_c0_profile(&self) -> bool {
        self.boot_args == BROKER_BOOT_ARGS
            && self.drives.len() == 1
            && self.drives[0].id == "rootfs"
            && self.drives[0].read_only
            && self.drives[0].root_device
    }
    pub(crate) fn semantic_invocation_matches(&self, argv: &[String]) -> bool {
        serde_json::to_vec(argv).is_ok_and(|bytes| {
            domain_hash("REALM::TaskInvocation", 1, &bytes) == self.policy.task_blake3
        })
    }
    pub(crate) fn vmm_birth_identity_root(&self) -> Option<&str> {
        self.vmm_birth_identity_root.as_deref()
    }
    pub(crate) fn bound_challenge(&self) -> Option<&str> {
        self.input_binding_proof
            .as_ref()
            .map(|p| p.challenge.as_str())
    }
    pub(crate) fn prepared_measurement_root(&self) -> &str {
        &self.prepared_measurement_root
    }

    pub fn vmm(&self) -> &VmmIncarnation {
        &self.vmm
    }

    pub fn broker_endpoint(&self) -> &UnixEndpointIdentity {
        &self.broker_endpoint
    }

    pub fn broker_endpoint_blake3(&self) -> String {
        let bytes = serde_json::to_vec(&self.broker_endpoint)
            .expect("endpoint identity serialization is infallible");
        domain_hash("REALM::FirecrackerBrokerEndpoint", 1, &bytes)
    }

    pub fn seccomp_policy_blake3(&self) -> String {
        let value = serde_json::json!({
            "policy": "firecracker-default-seccomp",
            "firecracker_version": self.firecracker_version,
            "binary_blake3": self.firecracker.blake3,
            "measured_filter_bytes": false
        });
        domain_hash_value("REALM::FirecrackerSeccompIdentity", 1, &value)
            .expect("seccomp identity serialization is infallible")
    }

    pub fn network_policy_blake3(&self) -> String {
        let value = serde_json::json!({
            "network_interfaces": self.network_interfaces,
            "explicitly_empty": self.network_interfaces.is_empty()
        });
        domain_hash_value("REALM::FirecrackerNetworkTopology", 1, &value)
            .expect("network topology serialization is infallible")
    }

    pub(crate) fn runtime_identity(&self) -> &str {
        &self.canonical_hash_blake3
    }

    pub(crate) fn verify_same_config(&self, bytes: &[u8]) -> Result<(), LaunchRefusal> {
        let actual: Value =
            serde_json::from_slice(bytes).map_err(|_| LaunchRefusal::MalformedConfiguration)?;
        let actual = canonicalize_json(actual);
        let hash = domain_hash_value(CONFIG_HASH_DOMAIN, 1, &actual)?;
        if hash != self.vm_config_blake3 {
            return Err(LaunchRefusal::InputChanged);
        }
        Ok(())
    }

    pub(crate) fn revalidate_inputs(&self) -> Result<(), LaunchRefusal> {
        if let Some(pinned) = &self._pinned_inputs {
            pinned.revalidate()?;
        } else {
            for expected in [
                &self.firecracker,
                &self.kernel,
                &self.rootfs,
                &self.guest_policy,
            ] {
                if FileIdentity::measure(Path::new(&expected.path))? != *expected {
                    return Err(LaunchRefusal::InputChanged);
                }
            }
            for expected in self.drives.iter().map(|drive| &drive.identity) {
                if FileIdentity::measure(Path::new(&expected.path))? != *expected {
                    return Err(LaunchRefusal::InputChanged);
                }
            }
        }
        self.broker_endpoint.revalidate()
    }

    pub(crate) fn revalidate_inputs_after_guest(&self) -> Result<(), LaunchRefusal> {
        if let Some(pinned) = &self._pinned_inputs {
            pinned.revalidate_after_guest()?;
        } else {
            for expected in [
                &self.firecracker,
                &self.kernel,
                &self.rootfs,
                &self.guest_policy,
            ] {
                if FileIdentity::measure(Path::new(&expected.path))? != *expected {
                    return Err(LaunchRefusal::InputChanged);
                }
            }
            for drive in &self.drives {
                let actual = FileIdentity::measure(Path::new(&drive.identity.path))?;
                if drive.read_only {
                    if actual != drive.identity {
                        return Err(LaunchRefusal::InputChanged);
                    }
                } else if actual.device_inode() != drive.identity.device_inode()
                    || actual.size != drive.identity.size
                    || actual.owner() != drive.identity.owner()
                    || actual.mode() != drive.identity.mode()
                {
                    return Err(LaunchRefusal::InputChanged);
                }
            }
        }
        self.broker_endpoint.revalidate()
    }

    pub(crate) fn matches_manifest(&self, manifest: &crate::mediation::MediationManifest) -> bool {
        let mut expected_devices = self
            .drives
            .iter()
            .map(|drive| crate::mediation::AttachedDevice {
                kind: drive.id.clone(),
                identity: drive.identity.blake3.clone(),
                read_only: drive.read_only,
            })
            .collect::<Vec<_>>();
        expected_devices.push(crate::mediation::AttachedDevice {
            kind: "broker_vsock".into(),
            identity: "vsock:host:7000".into(),
            read_only: true,
        });
        let expected_writable = self
            .drives
            .iter()
            .filter(|drive| !drive.read_only)
            .map(|drive| format!("drive:{}:rw", drive.id))
            .collect::<Vec<_>>();
        let expected_network = self
            .network_interfaces
            .iter()
            .filter_map(|device| device.get("iface_id").and_then(Value::as_str))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        manifest.run_id == self.run_id
            && manifest.launch_identity == self.execution_id
            && manifest.broker_endpoint == format!("vsock:host:{GUEST_TASK_PORT}")
            && manifest.vm_config_blake3 == self.vm_config_blake3
            && manifest.guest_kernel_blake3 == self.kernel.blake3
            && manifest.rootfs_blake3 == self.rootfs.blake3
            && manifest.guest_policy_blake3 == self.guest_policy.blake3
            && manifest.task_blake3 == self.policy.task_blake3
            && manifest.host_policy_identifier == self.policy.identifier
            && manifest.host_policy_version == self.policy.version
            && manifest.host_policy_blake3 == self.policy.blake3
            && manifest.runtime_identity == self.canonical_hash_blake3
            && manifest.measured_launch_hash_domain == self.canonical_hash_domain
            && manifest.measured_launch_hash_version == self.canonical_hash_version
            && manifest.measured_launch_blake3 == self.canonical_hash_blake3
            && manifest.broker_identity == self.firecracker.blake3
            && manifest.broker_endpoint_identity == self.broker_endpoint_blake3()
            && manifest.network_policy_identity == self.network_policy_blake3()
            && manifest.seccomp_blake3 == self.seccomp_policy_blake3()
            && manifest.devices == expected_devices
            && manifest.network_devices == expected_network
            && manifest.writable_mappings == expected_writable
            && manifest.shared_mounts.is_empty()
            && if self.supports_measured_brokered_c0_profile() {
                manifest.inherited_fds.is_empty()
            } else {
                manifest.inherited_fds.as_slice() == ["UNMEASURED"]
            }
            && manifest.other_storage_aliases.is_empty()
    }
}

fn write_new_json_record(path: &Path, value: &Value) -> Result<(), LaunchRefusal> {
    let bytes =
        serde_json::to_vec_pretty(value).map_err(|_| LaunchRefusal::MalformedConfiguration)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all_traced())
        .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all_traced())
            .map_err(|_| LaunchRefusal::InputMeasurementFailed)?;
    }
    Ok(())
}

fn reject_unknown_top_level(root: &Map<String, Value>) -> Result<(), LaunchRefusal> {
    const KNOWN: &[&str] = &[
        "balloon",
        "drives",
        "boot-source",
        "cpu-config",
        "logger",
        "machine-config",
        "metrics",
        "memory-hotplug",
        "mmds-config",
        "network-interfaces",
        "pmem",
        "vsock",
        "entropy",
    ];
    if root.keys().any(|key| !KNOWN.contains(&key.as_str())) {
        return Err(LaunchRefusal::UnsupportedConfiguration);
    }
    Ok(())
}

fn reject_unsupported_devices(root: &Map<String, Value>) -> Result<(), LaunchRefusal> {
    for key in [
        "balloon",
        "memory-hotplug",
        "mmds-config",
        "pmem",
        "entropy",
    ] {
        let Some(value) = root.get(key) else {
            continue;
        };
        if !value.is_null() && !value.as_array().is_some_and(Vec::is_empty) {
            return Err(LaunchRefusal::UnsupportedConfiguration);
        }
    }
    Ok(())
}

fn object_field<'a>(
    root: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, LaunchRefusal> {
    root.get(key)
        .and_then(Value::as_object)
        .ok_or(LaunchRefusal::MalformedConfiguration)
}

fn string_field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, LaunchRefusal> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(LaunchRefusal::MalformedConfiguration)
}

fn path_field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, LaunchRefusal> {
    string_field(object, key)
}

fn resolve_configured_path(
    configured: &str,
    jail_root_host: Option<&Path>,
) -> Result<PathBuf, LaunchRefusal> {
    let path = Path::new(configured);
    match jail_root_host {
        None => Ok(path.to_path_buf()),
        Some(root) => {
            let relative = path
                .strip_prefix("/")
                .map_err(|_| LaunchRefusal::TopologyMismatch)?;
            if relative
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            {
                return Err(LaunchRefusal::TopologyMismatch);
            }
            Ok(root.join(relative))
        }
    }
}

fn canonical_socket_prefix(path: &Path) -> Result<PathBuf, LaunchRefusal> {
    let parent = path.parent().ok_or(LaunchRefusal::EndpointMismatch)?;
    let name = path.file_name().ok_or(LaunchRefusal::EndpointMismatch)?;
    Ok(parent
        .canonicalize()
        .map_err(|_| LaunchRefusal::EndpointMismatch)?
        .join(name))
}

fn bool_field(object: &Map<String, Value>, key: &str) -> Result<bool, LaunchRefusal> {
    object
        .get(key)
        .and_then(Value::as_bool)
        .ok_or(LaunchRefusal::MalformedConfiguration)
}

fn number_field(object: &Map<String, Value>, key: &str) -> Result<u32, LaunchRefusal> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(LaunchRefusal::MalformedConfiguration)
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        Value::Object(object) => {
            let mut entries = object.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut canonical = Map::new();
            for (key, value) in entries {
                canonical.insert(key, canonicalize_json(value));
            }
            if let Some(Value::Array(drives)) = canonical.get_mut("drives") {
                drives.sort_by(|left, right| {
                    left.get("drive_id")
                        .and_then(Value::as_str)
                        .cmp(&right.get("drive_id").and_then(Value::as_str))
                });
            }
            Value::Object(canonical)
        }
        other => other,
    }
}

fn domain_hash_value(domain: &str, version: u16, value: &Value) -> Result<String, LaunchRefusal> {
    let bytes = serde_json::to_vec(value).map_err(|_| LaunchRefusal::MalformedConfiguration)?;
    Ok(domain_hash(domain, version, &bytes))
}

pub(crate) fn domain_hash(domain: &str, version: u16, bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher.update(&version.to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

fn trusted_parent_chain(path: &Path) -> bool {
    let mut current = path.parent();
    while let Some(parent) = current {
        let Ok(metadata) = fs::symlink_metadata(parent) else {
            return false;
        };
        if !metadata.is_dir() || metadata.mode() & 0o022 != 0 || metadata.uid() != 0 {
            return false;
        }
        current = parent.parent();
    }
    true
}

fn same_file_version(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

struct HashWriter<'a>(&'a mut blake3::Hasher);

impl io::Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mediation::{
        AttachedDevice, MediationFailure, MediationManifest, check_manifest_claim_shape,
    };
    use serde_json::json;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn dedicated_realm_fc_account_requires_unique_matching_uid_gid() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\nrealm-fc:x:991:992:Firecracker:/nonexistent:/usr/sbin/nologin\n";
        let group = "root:x:0:\nrealm-fc:x:992:\n";
        assert_eq!(
            parse_realm_fc_identity(passwd, group, 991, 992),
            Ok(("realm-fc".into(), "realm-fc".into()))
        );
        assert_eq!(
            parse_realm_fc_identity(passwd, group, 1001, 992),
            Err(LaunchRefusal::UnsupportedHost)
        );
        assert_eq!(
            parse_realm_fc_identity(
                &format!("{passwd}other:x:991:992:alias:/nonexistent:/bin/false\n"),
                group,
                991,
                992,
            ),
            Err(LaunchRefusal::UnsupportedHost)
        );
        assert_eq!(
            parse_realm_fc_identity(passwd, "root:x:0:\nrealm-fc:x:993:\n", 991, 992),
            Err(LaunchRefusal::UnsupportedHost)
        );
    }

    pub(crate) struct Fixture {
        root: PathBuf,
        firecracker: PathBuf,
        kernel: PathBuf,
        rootfs: PathBuf,
        workspace: PathBuf,
        guest_policy: PathBuf,
        uds_path: PathBuf,
        endpoint_path: PathBuf,
        _listener: UnixListener,
        endpoint: UnixEndpointIdentity,
        vmm: VmmIncarnation,
        config: Value,
    }

    impl Fixture {
        pub(crate) fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let fixture_id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("rml-{}-{unique}-{fixture_id}", std::process::id()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let firecracker = write_file(&root, "firecracker", b"firecracker-fixture");
            let kernel = write_file(&root, "kernel", b"kernel-fixture");
            let rootfs = write_file(&root, "rootfs", b"rootfs-fixture");
            let workspace = write_file(&root, "workspace", b"workspace-fixture");
            let guest_policy = write_file(&root, "guest-policy", b"guest-policy-fixture");
            let uds_path = root.join("task");
            let endpoint_path = PathBuf::from(format!("{}_7000", uds_path.display()));
            let listener = UnixListener::bind(&endpoint_path).unwrap();
            fs::set_permissions(&endpoint_path, fs::Permissions::from_mode(0o600)).unwrap();
            let endpoint = UnixEndpointIdentity::capture(&listener, &endpoint_path).unwrap();
            let firecracker_identity = FileIdentity::measure(&firecracker).unwrap();
            let vmm = VmmIncarnation {
                pid: 1234,
                boot_id: "fixture-boot-id".into(),
                start_time_ticks: 100,
                owner_uid: unsafe { libc::geteuid() },
                owner_gid: unsafe { libc::getegid() },
                executable: firecracker_identity,
            };
            let config = json!({
                "boot-source": {
                    "kernel_image_path": kernel,
                    "boot_args": EXPECTED_BOOT_ARGS
                },
                "drives": [
                    {
                        "drive_id": "rootfs",
                        "path_on_host": rootfs,
                        "is_read_only": true,
                        "is_root_device": true,
                        "io_engine": "Sync"
                    },
                    {
                        "drive_id": "workspace",
                        "path_on_host": workspace,
                        "is_read_only": false,
                        "is_root_device": false,
                        "io_engine": "Sync"
                    }
                ],
                "machine-config": {
                    "vcpu_count": 1,
                    "mem_size_mib": 256,
                    "smt": false
                },
                "network-interfaces": [],
                "vsock": {
                    "guest_cid": 3,
                    "uds_path": uds_path
                }
            });
            Self {
                root,
                firecracker,
                kernel,
                rootfs,
                workspace,
                guest_policy,
                uds_path,
                endpoint_path,
                _listener: listener,
                endpoint,
                vmm,
                config,
            }
        }

        fn context(&self) -> CaptureContext {
            CaptureContext {
                profile: LaunchProfile::Workspace,
                vmm_birth_identity_root: None,
                run_id: "run-measured-fixture".into(),
                execution_id: "e".repeat(64),
                challenge: "c".repeat(64),
                s0_root: "d".repeat(64),
                firecracker_version: "fixture-version".into(),
                firecracker_path: self.firecracker.clone(),
                kernel_path: self.kernel.clone(),
                rootfs_path: self.rootfs.clone(),
                workspace_path: self.workspace.clone(),
                guest_policy_path: self.guest_policy.clone(),
                uds_path: self.uds_path.clone(),
                jail_root_host: None,
                broker_endpoint: self.endpoint.clone(),
                policy: PolicyIdentity::new(
                    "fixture-policy".into(),
                    "1".into(),
                    b"policy-fixture",
                    b"task-fixture",
                ),
                vmm: self.vmm.clone(),
                vmm_input_fds: None,
                input_binding: None,
                jailer_input_binding: None,
            }
        }

        pub(crate) fn capture_c0_diagnostic_profile(
            &self,
        ) -> Result<MeasuredLaunchSession, LaunchRefusal> {
            let mut c = self.context();
            c.profile = LaunchProfile::RootfsBroker;
            c.run_id = blake3::hash(b"run-measured-fixture").to_hex().to_string();
            c.vmm_birth_identity_root = Some(blake3::hash(b"test-vmm-birth").to_hex().to_string());
            c.policy = PolicyIdentity::new(
                "fixture-policy".into(),
                "2".into(),
                b"policy-fixture",
                &serde_json::to_vec(&vec!["test-task"]).unwrap(),
            );
            let mut config = self.config.clone();
            config["boot-source"]["boot_args"] = BROKER_BOOT_ARGS.into();
            config["drives"]
                .as_array_mut()
                .unwrap()
                .retain(|d| d["drive_id"] == "rootfs");
            MeasuredLaunchSession::capture(&serde_json::to_vec(&config).unwrap(), c)
        }
        pub(crate) fn capture(&self) -> Result<MeasuredLaunchSession, LaunchRefusal> {
            MeasuredLaunchSession::capture(
                &serde_json::to_vec(&self.config).unwrap(),
                self.context(),
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn write_file(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = root.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    pub(crate) fn matching_manifest(launch: &MeasuredLaunchSession) -> MediationManifest {
        let mut devices = launch
            .drives()
            .iter()
            .map(|drive| AttachedDevice {
                kind: drive.id().to_owned(),
                identity: drive.identity().blake3().to_owned(),
                read_only: drive.read_only(),
            })
            .collect::<Vec<_>>();
        devices.push(AttachedDevice {
            kind: "broker_vsock".into(),
            identity: "vsock:host:7000".into(),
            read_only: true,
        });
        MediationManifest {
            schema: 2,
            run_id: launch.run_id().into(),
            vm_config_blake3: launch.vm_config_blake3().into(),
            guest_kernel_blake3: launch.kernel_identity().blake3().into(),
            rootfs_blake3: launch.rootfs_identity().blake3().into(),
            task_blake3: launch.policy_identity().task_blake3().into(),
            guest_policy_blake3: launch.guest_policy_identity().blake3().into(),
            seccomp_blake3: launch.seccomp_policy_blake3(),
            measured_launch_hash_domain: launch.canonical_hash_domain().into(),
            measured_launch_hash_version: launch.canonical_hash_version(),
            measured_launch_blake3: launch.canonical_hash_blake3().into(),
            broker_endpoint_identity: launch.broker_endpoint_blake3(),
            host_policy_identifier: launch.policy_identity().identifier().into(),
            host_policy_version: launch.policy_identity().version().into(),
            host_policy_blake3: launch.policy_identity().blake3().into(),
            launch_identity: launch.execution_id().into(),
            starting_generation: "a".repeat(64),
            final_world: "b".repeat(64),
            delta_root: "c".repeat(64),
            runtime_identity: launch.runtime_identity().into(),
            network_policy_identity: launch.network_policy_blake3(),
            broker_identity: launch.firecracker_identity().blake3().into(),
            broker_endpoint: "vsock:host:7000".into(),
            devices,
            network_devices: Vec::new(),
            shared_mounts: Vec::new(),
            inherited_fds: if launch.supports_measured_brokered_c0_profile() {
                Vec::new()
            } else {
                vec!["UNMEASURED".into()]
            },
            writable_mappings: launch
                .drives()
                .iter()
                .filter(|d| !d.read_only())
                .map(|d| format!("drive:{}:rw", d.id()))
                .collect(),
            other_storage_aliases: Vec::new(),
            max_task_processes: 1,
        }
    }

    #[test]
    fn actual_coding_boot_profile_cannot_borrow_v6_measured_launch_authority() {
        // Exact run016 boot args, from its externally pinned raw archive.
        // Host paths use the existing fixture; this is an admission regression,
        // never a claim that a fixture is a qualified measured coding run.
        let mut fixture = Fixture::new();
        fixture.config["boot-source"]["boot_args"] =
            "console=ttyS0 root=/dev/vda rootfstype=ext4 ro init=/coding-init panic=1 devtmpfs.mount=0".into();
        assert!(matches!(
            fixture.capture(),
            Err(LaunchRefusal::TopologyMismatch)
        ));
        let mut context = fixture.context();
        context.profile = LaunchProfile::RootfsBroker;
        let captured =
            MeasuredLaunchSession::capture(&serde_json::to_vec(&fixture.config).unwrap(), context);
        assert!(matches!(captured, Err(LaunchRefusal::TopologyMismatch)));
        // Restoring the original fixture profile continues to work.
        fixture.config["boot-source"]["boot_args"] = EXPECTED_BOOT_ARGS.into();
        assert!(fixture.capture().is_ok());
    }

    #[test]
    fn captures_actual_workspace_topology_but_never_authorizes_consumption() {
        let fixture = Fixture::new();
        let launch = fixture.capture().unwrap();
        assert_eq!(launch.drives().len(), 2);
        assert!(launch.drives().iter().any(|drive| {
            drive.id() == "workspace" && !drive.read_only() && !drive.root_device()
        }));
        assert!(launch.network_is_explicitly_empty());
        assert_eq!(
            launch.assurance_grade(),
            LaunchAssuranceGrade::DirectFunctional
        );
        assert!(launch.consumable_input_binding_proof().is_none());
    }

    #[test]
    fn refuses_omitted_extra_or_mode_changed_drives_and_unsupported_attachments() {
        let mutations: [fn(&mut Value); 6] = [
            |config| {
                config["drives"].as_array_mut().unwrap().pop();
            },
            |config| {
                config["drives"].as_array_mut().unwrap().push(json!({
                    "drive_id": "extra",
                    "path_on_host": "/unmeasured/extra",
                    "is_read_only": true,
                    "is_root_device": false,
                    "io_engine": "Sync"
                }));
            },
            |config| config["drives"][1]["is_read_only"] = Value::Bool(true),
            |config| config["drives"][0]["is_read_only"] = Value::Bool(false),
            |config| config["network-interfaces"] = json!([{"iface_id":"eth0"}]),
            |config| config["unexpected-device"] = json!({"enabled":true}),
        ];
        for mutate in mutations {
            let mut fixture = Fixture::new();
            mutate(&mut fixture.config);
            assert!(fixture.capture().is_err());
        }
    }

    #[test]
    fn changed_vm_config_after_measurement_is_detected() {
        let fixture = Fixture::new();
        let launch = fixture.capture().unwrap();
        let mut changed = fixture.config.clone();
        changed["machine-config"]["mem_size_mib"] = json!(512);
        assert!(
            launch
                .verify_same_config(&serde_json::to_vec(&changed).unwrap())
                .is_err()
        );
    }

    #[test]
    fn kernel_and_rootfs_replacements_are_detected_on_revalidation() {
        let fixture = Fixture::new();
        let launch = fixture.capture().unwrap();
        let replacement = fixture.root.join("replacement");
        fs::write(&replacement, b"replaced-rootfs-bytes").unwrap();
        fs::rename(&replacement, &fixture.rootfs).unwrap();
        assert_eq!(launch.revalidate_inputs(), Err(LaunchRefusal::InputChanged));
    }

    #[test]
    fn kernel_replacement_is_detected_on_revalidation() {
        let fixture = Fixture::new();
        let launch = fixture.capture().unwrap();
        let replacement = fixture.root.join("replacement-kernel");
        fs::write(&replacement, b"replacement-kernel-bytes").unwrap();
        fs::rename(&replacement, &fixture.kernel).unwrap();
        assert_eq!(launch.revalidate_inputs(), Err(LaunchRefusal::InputChanged));
    }

    #[test]
    fn host_uds_path_replacement_is_detected() {
        let fixture = Fixture::new();
        let launch = fixture.capture().unwrap();
        fs::remove_file(&fixture.endpoint_path).unwrap();
        let replacement = UnixListener::bind(&fixture.endpoint_path).unwrap();
        fs::set_permissions(&fixture.endpoint_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            launch.broker_endpoint().revalidate(),
            Err(LaunchRefusal::EndpointMismatch)
        );
        drop(replacement);
    }

    #[test]
    fn stale_vmm_incarnation_with_reused_pid_is_not_equal() {
        let fixture = Fixture::new();
        let mut stale = fixture.vmm.clone();
        stale.start_time_ticks += 1;
        assert!(!fixture.vmm.same_process(&stale));
    }

    #[test]
    fn manifest_must_match_every_measured_drive_and_endpoint() {
        let fixture = Fixture::new();
        let launch = fixture.capture().unwrap();
        let manifest = matching_manifest(&launch);
        assert!(launch.matches_manifest(&manifest));
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_root = blake3::hash(&bytes).to_hex().to_string();
        assert_eq!(
            check_manifest_claim_shape(&bytes, &manifest_root),
            Err(MediationFailure::AlternatePath)
        );
        let mut missing_workspace = manifest.clone();
        missing_workspace
            .devices
            .retain(|device| device.kind != "workspace");
        assert!(!launch.matches_manifest(&missing_workspace));
        let mut wrong_endpoint = manifest;
        wrong_endpoint.broker_endpoint_identity = "0".repeat(64);
        assert!(!launch.matches_manifest(&wrong_endpoint));
        let mut claimed_empty_fds = matching_manifest(&launch);
        claimed_empty_fds.inherited_fds.clear();
        assert!(!launch.matches_manifest(&claimed_empty_fds));
    }

    #[test]
    fn config_hash_is_independent_of_json_object_key_order() {
        let left: Value = serde_json::from_str(r#"{"b":{"y":2,"x":1},"a":0}"#).unwrap();
        let right: Value = serde_json::from_str(r#"{"a":0,"b":{"x":1,"y":2}}"#).unwrap();
        assert_eq!(canonicalize_json(left), canonicalize_json(right));
    }

    fn pinned_test_file(root: &Path, name: &str, bytes: &[u8], writable: bool) -> PinnedInput {
        let path = root.join(name);
        fs::write(&path, bytes).unwrap();
        PinnedInput::open(&path, writable).unwrap()
    }

    fn test_prepared_inputs(rootfs_bytes: &[u8]) -> (PathBuf, PreparedExecutionInputs) {
        let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("realm-v6-binding-{}-{id}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.join("state");
        let run_state = state.join("run");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&run_state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&run_state, fs::Permissions::from_mode(0o700)).unwrap();
        let base_bytes = b"initial workspace bytes";
        let base_workspace = pinned_test_file(&root, "base", base_bytes, false);
        let starting_workspace = pinned_test_file(&root, "starting", base_bytes, false);
        let working_workspace = pinned_test_file(&root, "working", base_bytes, true);
        let prepared = PreparedExecutionInputs {
            profile: LaunchProfile::Workspace,
            firecracker: pinned_test_file(&root, "firecracker", b"fc", false),
            kernel: pinned_test_file(&root, "kernel", b"kernel", false),
            rootfs: pinned_test_file(&root, "rootfs", rootfs_bytes, false),
            base_workspace,
            guest_supervisor: pinned_test_file(&root, "guest-supervisor", b"supervisor", false),
            starting_workspace,
            working_workspace,
            state_dir: PinnedDirectory::open(&state).unwrap(),
            run_state_dir: PinnedDirectory::open(&run_state).unwrap(),
        };
        (root, prepared)
    }

    #[test]
    fn official_jailer_capture_binds_materialized_resources_without_inherited_fds() {
        let (root, prepared) = test_prepared_inputs(b"rootfs-for-jailer-binding");
        let jail_root = root.join("jailer-root");
        let execution_state = root.join("execution-state");
        let run_dir = jail_root.join("tmp");
        fs::create_dir(&jail_root).unwrap();
        fs::create_dir(&run_dir).unwrap();
        fs::create_dir(&execution_state).unwrap();

        let run_id = "run-jailer-binding-fixture".to_owned();
        let execution_id = "e".repeat(64);
        let challenge = "c".repeat(64);
        let s0_root = "d".repeat(64);
        let policy = PolicyIdentity::new(
            "fixture-policy".into(),
            "1".into(),
            b"policy-fixture",
            b"task-fixture",
        );
        let guest_policy_path = PathBuf::from(prepared.guest_supervisor.identity.path());
        let binding = prepared
            .bind(
                run_id.clone(),
                execution_id.clone(),
                challenge.clone(),
                s0_root.clone(),
                policy.clone(),
            )
            .unwrap();

        let firecracker_exec_source = execution_state.join("firecracker-source");
        let firecracker_path = jail_root.join("firecracker");
        let kernel_host_path = jail_root.join("kernel");
        let rootfs_host_path = jail_root.join("rootfs.ext4");
        let workspace_host_path = jail_root.join("workspace.ext4");
        fs::copy(
            &binding.inputs.firecracker.identity.path,
            &firecracker_exec_source,
        )
        .unwrap();
        fs::copy(&firecracker_exec_source, &firecracker_path).unwrap();
        fs::copy(&binding.inputs.kernel.identity.path, &kernel_host_path).unwrap();
        fs::copy(&binding.inputs.rootfs.identity.path, &rootfs_host_path).unwrap();
        fs::copy(
            &binding.inputs.working_workspace.identity.path,
            &workspace_host_path,
        )
        .unwrap();
        fs::set_permissions(&firecracker_path, fs::Permissions::from_mode(0o500)).unwrap();
        fs::set_permissions(&kernel_host_path, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&rootfs_host_path, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&workspace_host_path, fs::Permissions::from_mode(0o600)).unwrap();
        let expected_resource_root = binding.root.clone();
        let jailed_resources = JailedResourcePaths {
            input_binding_root: binding.root.clone(),
            firecracker_exec_source,
            kernel_host_path: kernel_host_path.clone(),
            rootfs_host_path: rootfs_host_path.clone(),
            workspace_host_path: workspace_host_path.clone(),
            firecracker_identity: FileIdentity::measure(
                &execution_state.join("firecracker-source"),
            )
            .unwrap(),
            kernel_identity: FileIdentity::measure(&kernel_host_path).unwrap(),
            rootfs_identity: FileIdentity::measure(&rootfs_host_path).unwrap(),
            workspace_identity: FileIdentity::measure(&workspace_host_path).unwrap(),
        };

        let uds_path = PathBuf::from("/tmp/task");
        let endpoint_path = run_dir.join("task_7000");
        let endpoint = UnixEndpointIdentity {
            path: endpoint_path.to_string_lossy().into_owned(),
            device: 1,
            inode: 2,
            owner_uid: unsafe { libc::geteuid() },
            owner_gid: unsafe { libc::getegid() },
            mode: 0o600,
            parent_device: 1,
            parent_inode: 3,
        };
        let firecracker_identity = FileIdentity::measure(&firecracker_path).unwrap();
        let vmm = VmmIncarnation {
            pid: 1234,
            boot_id: "fixture-boot-id".into(),
            start_time_ticks: 100,
            owner_uid: unsafe { libc::geteuid() },
            owner_gid: unsafe { libc::getegid() },
            executable: firecracker_identity,
        };
        let mut context = CaptureContext {
            profile: LaunchProfile::Workspace,
            vmm_birth_identity_root: None,
            run_id,
            execution_id,
            challenge,
            s0_root,
            firecracker_version: "v1.17.0".into(),
            firecracker_path,
            kernel_path: kernel_host_path,
            rootfs_path: rootfs_host_path,
            workspace_path: workspace_host_path,
            guest_policy_path,
            uds_path,
            jail_root_host: Some(jail_root.clone()),
            broker_endpoint: endpoint,
            policy,
            vmm,
            vmm_input_fds: None,
            input_binding: None,
            jailer_input_binding: Some(LaunchedJailerInputBinding::new(binding, jailed_resources)),
        };

        let jailer_binding = context.jailer_input_binding.take().unwrap();
        assert!(jailer_binding.matches_context(&context));
        context.profile = LaunchProfile::RootfsBroker;
        assert!(!jailer_binding.matches_context(&context));
        context.profile = LaunchProfile::Workspace;
        assert!(jailer_binding.matches_context(&context));
        let expected_challenge = context.challenge.clone();
        context.challenge = "f".repeat(64);
        assert!(!jailer_binding.matches_context(&context));
        context.challenge = expected_challenge;

        let expected_workspace_path = context.workspace_path.clone();
        context.workspace_path = root.join("foreign-workspace.ext4");
        assert!(!jailer_binding.matches_context(&context));
        context.workspace_path = expected_workspace_path;

        let expected_kernel_path = context.kernel_path.clone();
        let parked_kernel_path = root.join("parked-kernel");
        fs::rename(&expected_kernel_path, &parked_kernel_path).unwrap();
        fs::write(&expected_kernel_path, b"substituted-kernel").unwrap();
        assert!(!jailer_binding.matches_context(&context));
        fs::remove_file(&expected_kernel_path).unwrap();
        fs::rename(&parked_kernel_path, &expected_kernel_path).unwrap();
        assert!(jailer_binding.matches_context(&context));

        let (proof, pinned_inputs) = jailer_binding
            .into_measured("f".repeat(64), &context.broker_endpoint, &context.vmm)
            .unwrap();
        assert!(matches!(
            proof.consumption,
            ConsumableInputConsumption::OfficialJailer { ref resources } if resources.len() == 4
        ));
        assert!(!proof.root.is_empty());
        assert_eq!(proof.resource_root, expected_resource_root);
        assert_ne!(proof.root, expected_resource_root);
        let host_working = PathBuf::from(pinned_inputs.working_workspace.identity.path());
        let drives = vec![MeasuredDrive {
            id: "workspace".into(),
            identity: FileIdentity::measure(&context.workspace_path).unwrap(),
            read_only: false,
            root_device: false,
            io_engine: "Sync".into(),
        }];
        let selected =
            consumed_workspace_path(Some(&proof), Some(&pinned_inputs), &drives).unwrap();
        assert_eq!(selected, context.workspace_path.canonicalize().unwrap());
        fs::write(&context.workspace_path, b"guest-mutated-workspace").unwrap();
        fs::copy(selected, &host_working).unwrap();
        assert_eq!(fs::read(&host_working).unwrap(), b"guest-mutated-workspace");
        drop(pinned_inputs);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires root/CAP_CHOWN; NOT_RUN in ordinary public checks"]
    fn jailer_materialization_copies_bound_resources_with_isolated_write_access() {
        // Ownership assertions need CAP_CHOWN; the qualified VM runs this test
        // as root as part of the production launch preparation check.
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "explicit root ownership-test authorization required"
        );
        let (root, prepared) = test_prepared_inputs(b"rootfs-for-jailer");
        let jail_root = root.join("jailer-root");
        let execution_state = root.join("execution-state");
        fs::create_dir(&jail_root).unwrap();
        fs::create_dir(&execution_state).unwrap();
        let binding_root = "a".repeat(64);
        let resources = prepared
            .materialize_for_jailer(&jail_root, &execution_state, 1001, 1001, &binding_root)
            .unwrap();
        resources.verify_before_instance_start().unwrap();
        resources.verify_after_guest().unwrap();
        for (path, expected) in [
            (
                &resources.firecracker_exec_source,
                &prepared.firecracker.identity,
            ),
            (&resources.kernel_host_path, &prepared.kernel.identity),
            (&resources.rootfs_host_path, &prepared.rootfs.identity),
            (
                &resources.workspace_host_path,
                &prepared.working_workspace.identity,
            ),
        ] {
            let actual = FileIdentity::measure(path).unwrap();
            assert_eq!(actual.blake3, expected.blake3);
            assert_eq!(actual.size, expected.size);
            assert_ne!(actual.device_inode(), expected.device_inode());
        }
        assert_eq!(
            FileIdentity::measure(&resources.kernel_host_path)
                .unwrap()
                .mode(),
            0o444
        );
        assert_eq!(
            FileIdentity::measure(&resources.rootfs_host_path)
                .unwrap()
                .mode(),
            0o444
        );
        let workspace = FileIdentity::measure(&resources.workspace_host_path).unwrap();
        assert_eq!(workspace.owner(), (1001, 1001));
        assert_eq!(workspace.mode(), 0o600);
        assert_ne!(
            fs::metadata(&resources.workspace_host_path).unwrap().ino(),
            prepared.working_workspace.identity.inode
        );
        drop(prepared);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires root/CAP_CHOWN; NOT_RUN in ordinary public checks"]
    fn jailer_materialized_replacement_is_refused_before_instance_start() {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "explicit root ownership-test authorization required"
        );
        let (root, prepared) = test_prepared_inputs(b"rootfs-for-jailer");
        let jail_root = root.join("jailer-root");
        let execution_state = root.join("execution-state");
        fs::create_dir(&jail_root).unwrap();
        fs::create_dir(&execution_state).unwrap();
        let resources = prepared
            .materialize_for_jailer(&jail_root, &execution_state, 1001, 1001, &"a".repeat(64))
            .unwrap();
        let parked = root.join("parked-kernel");
        fs::rename(&resources.kernel_host_path, &parked).unwrap();
        fs::write(&resources.kernel_host_path, b"substituted-kernel").unwrap();
        assert_eq!(
            resources.verify_before_instance_start(),
            Err(LaunchRefusal::InputChanged)
        );
        drop(prepared);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires root/CAP_CHOWN; NOT_RUN in ordinary public checks"]
    fn jailer_workspace_write_is_allowed_but_workspace_replacement_is_refused() {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "explicit root ownership-test authorization required"
        );
        let (root, prepared) = test_prepared_inputs(b"rootfs-for-jailer");
        let jail_root = root.join("jailer-root");
        let execution_state = root.join("execution-state");
        fs::create_dir(&jail_root).unwrap();
        fs::create_dir(&execution_state).unwrap();
        let resources = prepared
            .materialize_for_jailer(&jail_root, &execution_state, 1001, 1001, &"a".repeat(64))
            .unwrap();
        let mut workspace = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&resources.workspace_host_path)
            .unwrap();
        workspace.seek(SeekFrom::Start(0)).unwrap();
        workspace.write_all(b"guest-mutated").unwrap();
        workspace.sync_all_traced().unwrap();
        drop(workspace);
        resources.verify_after_guest().unwrap();
        let parked = root.join("parked-workspace");
        fs::rename(&resources.workspace_host_path, &parked).unwrap();
        fs::copy(&parked, &resources.workspace_host_path).unwrap();
        assert_eq!(
            resources.verify_after_guest(),
            Err(LaunchRefusal::InputChanged)
        );
        drop(prepared);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn descriptor_pin_survives_path_substitution() {
        let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("realm-v6-pin-{}-{id}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("rootfs");
        fs::write(&path, b"approved-rootfs").unwrap();
        let pin = PinnedInput::open(&path, false).unwrap();
        let approved = pin.file.metadata().unwrap();
        let approved_identity = (approved.dev(), approved.ino());
        let parked = root.join("parked-rootfs");
        fs::rename(&path, &parked).unwrap();
        fs::write(&path, b"substituted-rootfs").unwrap();

        // Invariant A: the held descriptor still names and reads the approved
        // object after the canonical pathname has been replaced.
        let held = pin.file.metadata().unwrap();
        assert_eq!((held.dev(), held.ino()), approved_identity);
        let mut held_bytes = [0_u8; b"approved-rootfs".len()];
        assert_eq!(
            pin.file.read_at(&mut held_bytes, 0).unwrap(),
            held_bytes.len()
        );
        assert_eq!(&held_bytes, b"approved-rootfs");

        // Invariant B: the canonical path now resolves to a different object.
        let substituted = fs::symlink_metadata(&path).unwrap();
        assert!(substituted.is_file());
        assert_ne!((substituted.dev(), substituted.ino()), approved_identity);

        // Invariants B/C: revalidation detects the path substitution and will
        // not consume the substitute as the previously approved input.
        assert_eq!(
            pin.revalidate_object_identity(),
            Err(LaunchRefusal::InputChanged)
        );
        assert_eq!(pin.revalidate(), Err(LaunchRefusal::InputChanged));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn binding_refuses_run_nonce_s0_and_policy_substitution() {
        let (root, prepared) = test_prepared_inputs(b"rootfs");
        let policy = PolicyIdentity::new("p".into(), "1".into(), b"policy", b"task");
        let binding = prepared
            .bind(
                "run-A".into(),
                "execution-A".into(),
                "a".repeat(64),
                "b".repeat(64),
                policy.clone(),
            )
            .unwrap();
        assert!(binding.matches_identity(
            "run-A",
            "execution-A",
            &"a".repeat(64),
            &"b".repeat(64),
            &policy
        ));
        assert!(!binding.matches_identity(
            "run-B",
            "execution-A",
            &"a".repeat(64),
            &"b".repeat(64),
            &policy
        ));
        assert!(!binding.matches_identity(
            "run-A",
            "execution-A",
            &"c".repeat(64),
            &"b".repeat(64),
            &policy
        ));
        assert!(!binding.matches_identity(
            "run-A",
            "execution-A",
            &"a".repeat(64),
            &"d".repeat(64),
            &policy
        ));
        let foreign_policy = PolicyIdentity::new("p".into(), "2".into(), b"other", b"task");
        assert!(!binding.matches_identity(
            "run-A",
            "execution-A",
            &"a".repeat(64),
            &"b".repeat(64),
            &foreign_policy
        ));
        drop(binding);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn binding_root_changes_when_a_pinned_resource_changes() {
        let (root_a, prepared_a) = test_prepared_inputs(b"rootfs-A");
        let (root_b, prepared_b) = test_prepared_inputs(b"rootfs-B");
        let policy = PolicyIdentity::new("p".into(), "1".into(), b"policy", b"task");
        let cap_a = prepared_a
            .bind(
                "run-A".into(),
                "execution-A".into(),
                "a".repeat(64),
                "b".repeat(64),
                policy.clone(),
            )
            .unwrap();
        let cap_b = prepared_b
            .bind(
                "run-A".into(),
                "execution-A".into(),
                "a".repeat(64),
                "b".repeat(64),
                policy,
            )
            .unwrap();
        assert_ne!(cap_a.root, cap_b.root);
        drop((cap_a, cap_b));
        fs::remove_dir_all(root_a).unwrap();
        fs::remove_dir_all(root_b).unwrap();
    }

    #[test]
    fn mismatched_workspace_copy_refuses_binding() {
        let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("realm-v6-s0-{}-{id}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let base = pinned_test_file(&root, "base", b"s0", false);
        let starting = pinned_test_file(&root, "starting", b"s0", false);
        let working = pinned_test_file(&root, "working", b"stale-s1", true);
        assert_eq!(
            validate_workspace_image_identity(&base, &starting, &working),
            Err(LaunchRefusal::InputBindingMismatch)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn aliased_s0_and_working_image_refuses_binding() {
        let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("realm-v6-alias-{}-{id}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let shared = pinned_test_file(&root, "shared", b"s0", false);
        let base = pinned_test_file(&root, "base", b"s0", false);
        assert_eq!(
            validate_workspace_image_identity(&base, &shared, &shared),
            Err(LaunchRefusal::InputBindingMismatch)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn binding_revalidation_refuses_prelaunch_working_image_mutation() {
        let (root, prepared) = test_prepared_inputs(b"rootfs");
        let working_path = PathBuf::from(&prepared.working_workspace.identity.path);
        let binding = prepared
            .bind(
                "run-A".into(),
                "execution-A".into(),
                "a".repeat(64),
                "b".repeat(64),
                PolicyIdentity::new("p".into(), "1".into(), b"policy", b"task"),
            )
            .unwrap();
        fs::write(working_path, b"substituted before InstanceStart").unwrap();
        assert_eq!(
            binding.inputs.revalidate(),
            Err(LaunchRefusal::InputChanged)
        );
        drop(binding);
        fs::remove_dir_all(root).unwrap();
    }
}
