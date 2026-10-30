//! Restricted C0 client. External exact-head trust plus explicit destination
//! approval are required; artifact structure never grants host authority.
pub mod coding_development;
pub mod ordered_create;

use crate::{
    ArtifactBundle, ValidationLevel,
    lifecycle::{self, GenesisAnchor, LifecycleSnapshot, LifecycleTrust, VerificationState},
};
use realm_v6::{
    c0_contract::C0FileContract,
    execute::CheckedC1Evidence,
    filesystem_world::{FilesystemObject, FilesystemWorld},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::{File, Metadata},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};
use thiserror::Error;

pub const MAX_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("REFUSE: {0}")]
    Refuse(String),
    #[error("UNKNOWN: filesystem operation failed: {0}; inspect journal before retrying")]
    Io(#[from] io::Error),
    #[error("REFUSE: invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("REFUSE: invalid artifact: {0}")]
    Artifact(#[from] crate::ArtifactError),
}
pub type Result<T> = std::result::Result<T, ApplyError>;
fn refuse<T>(s: &str) -> Result<T> {
    Err(ApplyError::Refuse(s.into()))
}

/// Evidence sidecar. These serialized assertions do not authenticate a worker.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferProof {
    pub schema_version: u16,
    pub genesis: GenesisAnchor,
    pub snapshot: LifecycleSnapshot,
}
/// Must be obtained outside the agent/transfer through an authenticated worker
/// channel or checked by the operator. Never create this from received claims.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPermit {
    pub schema_version: u16,
    pub artifact_blake3: String,
    pub genesis_root: String,
    pub exact_head_root: String,
    pub contract: C0FileContract,
}

/// Opaque verified state delta, distinct from a live V6 ACCEPT capability.
/// ```compile_fail
/// use realm_artifact::host_apply::VerifiedDelta;
/// let forged = VerifiedDelta { contract: todo!(), artifact_blake3: String::new(), run_id: String::new(), head_root: String::new() };
/// ```
#[derive(Debug)]
pub struct VerifiedDelta {
    contract: C0FileContract,
    artifact_blake3: String,
    run_id: String,
    head_root: String,
}
impl VerifiedDelta {
    pub fn contract(&self) -> &C0FileContract {
        &self.contract
    }
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
}
fn digest(b: &[u8]) -> String {
    blake3::hash(b).to_hex().to_string()
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
}
pub fn verify_transfer(
    artifact: &[u8],
    proof: &TransferProof,
    permit: &ArtifactPermit,
) -> Result<VerifiedDelta> {
    if artifact.len() as u64 > MAX_TRANSFER_BYTES
        || permit.schema_version != 1
        || proof.schema_version != 1
        || !valid_digest(&permit.artifact_blake3)
        || !valid_digest(&permit.genesis_root)
        || !valid_digest(&permit.exact_head_root)
        || digest(artifact) != permit.artifact_blake3
    {
        return refuse("artifact does not match external permit");
    }
    permit
        .contract
        .validate()
        .map_err(|s| ApplyError::Refuse(s.into()))?;
    let trust = LifecycleTrust {
        genesis_root: permit.genesis_root.clone(),
        previously_trusted_head_root: permit.exact_head_root.clone(),
    };
    if proof.snapshot.head.authority_root != permit.exact_head_root {
        return refuse("worker head differs from external exact-head pin");
    }
    let verification = lifecycle::verify_chain(&trust, &proof.genesis, &proof.snapshot);
    if verification.state != VerificationState::Valid || verification.verified_transitions == 0 {
        return refuse("incomplete, corrupt or untrusted genesis-to-head evidence");
    }
    let bundle = ArtifactBundle::unpack(artifact)?;
    bundle.validate_at(ValidationLevel::ContentComplete)?;
    let transition = proof
        .snapshot
        .transitions
        .iter()
        .max_by_key(|t| t.sequence)
        .ok_or_else(|| ApplyError::Refuse("no published transition".into()))?;
    if crate::hash("realm.v6-lifecycle-artifact", artifact) != transition.artifact_digest
        || proof
            .snapshot
            .artifacts
            .get(&transition.artifact_digest.value)
            .map(Vec::as_slice)
            != Some(artifact)
    {
        return refuse("artifact is not the externally pinned head's publication");
    }
    let reference = bundle
        .run
        .evidence
        .iter()
        .find(|x| x.id == "v6-checked-c1")
        .ok_or_else(|| ApplyError::Refuse("no checked execution evidence".into()))?;
    let bytes = bundle
        .blobs
        .get(&reference.digest.value)
        .ok_or_else(|| ApplyError::Refuse("missing checked evidence".into()))?;
    let checked: CheckedC1Evidence = serde_json::from_slice(bytes)?;
    // This client admits only the production C0 family, never legacy structural
    // C1 evidence or a diagnostic runtime result.
    if !matches!(checked.schema_version, 7 | 8)
        || checked.verifier_decision != "CHECKED_FOR_PUBLICATION"
        || checked
            .file_contract
            .clone()
            .unwrap_or_else(C0FileContract::frozen)
            != permit.contract
        || !realm_v6::execute::validate_checked_c1_evidence(&checked)
    {
        return refuse("not a supported production C0 task matching the authorized contract");
    }
    let (before, after, delta) = permit.contract.commitments()?;
    if (
        checked.accepted_start_root,
        checked.accepted_final_root,
        checked.accepted_delta_root,
    ) != (before, after, delta)
    {
        return refuse("verified worlds do not match the approved task");
    }
    Ok(VerifiedDelta {
        contract: permit.contract.clone(),
        artifact_blake3: permit.artifact_blake3.clone(),
        run_id: checked.run_id,
        head_root: permit.exact_head_root.clone(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyPlan {
    pub schema_version: u16,
    pub artifact_blake3: String,
    pub run_id: String,
    pub authority_head_root: String,
    pub destination: DirectoryIdentity,
    pub starting_world: String,
    pub final_world: String,
    pub create_path: String,
    pub create_bytes: u64,
    pub create_mode: u32,
}
impl ApplyPlan {
    pub fn approval_id(&self) -> Result<String> {
        Ok(crate::hash(
            "realm.host-application-approval.v1",
            &serde_json::to_vec(self)?,
        )
        .value)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicationState {
    Authorized,
    Staged,
    Linked,
    Complete,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageIdentity {
    device: u64,
    inode: u64,
    content: String,
    mode: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEntry {
    sequence: u64,
    plan: ApplyPlan,
    approval_id: String,
    phase: ApplicationState,
    stage: Option<StageIdentity>,
    previous: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostReceipt {
    pub schema_version: u16,
    pub approval_id: String,
    pub artifact_blake3: String,
    pub run_id: String,
    pub destination: DirectoryIdentity,
    pub operation: String,
    pub state: ApplicationState,
    pub independently_observed_world: String,
    pub expected_world: String,
    pub verified: bool,
    pub history_complete: bool,
    pub scope: String,
}

/// Directory FDs, not canonicalized pathnames, are the mutation authority.
struct Directory(File);
impl Directory {
    fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return refuse("absolute path required (no symlink components)");
        }
        let mut d = Self(unsafe {
            File::from_raw_fd(checked_fd(libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            ))?)
        });
        for part in path.components() {
            match part {
                Component::RootDir => {}
                Component::Normal(name) => {
                    let n = CString::new(name.as_bytes())
                        .map_err(|_| ApplyError::Refuse("NUL path".into()))?;
                    let f =
                        d.open_at(&n, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW, 0)?;
                    let m = f.metadata()?;
                    let uid = unsafe { libc::geteuid() };
                    if m.uid() != uid && m.uid() != 0 {
                        return refuse("directory chain has an untrusted owner");
                    }
                    if m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0) {
                        return refuse("directory chain permits untrusted rename");
                    }
                    d = Self(f);
                }
                _ => return refuse("dot/parent path component forbidden"),
            }
        }
        d.private()?;
        Ok(d)
    }
    fn private(&self) -> Result<()> {
        let m = self.0.metadata()?;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7777 != 0o700 {
            return refuse(
                "destination and state directories must be owned by this user, mode 0700",
            );
        }
        Ok(())
    }
    fn identity(&self) -> Result<DirectoryIdentity> {
        let m = self.0.metadata()?;
        Ok(DirectoryIdentity {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
        })
    }
    fn open_at(&self, n: &CStr, flags: i32, mode: u32) -> Result<File> {
        // SAFETY: live directory FD and NUL-terminated name. The returned FD is
        // checked and transferred to exactly one File owner.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                n.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NONBLOCK,
                mode as libc::c_uint,
            )
        };
        Ok(unsafe { File::from_raw_fd(checked_fd(fd)?) })
    }
    fn file(&self, name: &str) -> Result<File> {
        let n = CString::new(name).map_err(|_| ApplyError::Refuse("NUL filename".into()))?;
        self.open_at(&n, libc::O_RDONLY | libc::O_NOFOLLOW, 0)
    }
    fn names(&self) -> Result<Vec<String>> {
        // dup shares a directory offset; openat(".") obtains a fresh offset.
        let fd = self.open_at(
            c".",
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        )?;
        let raw = std::os::fd::IntoRawFd::into_raw_fd(fd);
        let dir = unsafe { libc::fdopendir(raw) };
        if dir.is_null() {
            unsafe {
                libc::close(raw);
            }
            return Err(io::Error::last_os_error().into());
        }
        let result = (|| {
            let mut out = Vec::new();
            loop {
                // errno distinguishes end-of-directory from an I/O failure.
                #[cfg(target_os = "linux")]
                unsafe {
                    *libc::__errno_location() = 0;
                }
                #[cfg(target_os = "macos")]
                unsafe {
                    *libc::__error() = 0;
                }
                let e = unsafe { libc::readdir(dir) };
                if e.is_null() {
                    let errno = io::Error::last_os_error();
                    if errno.raw_os_error() != Some(0) {
                        return Err(errno.into());
                    }
                    break;
                }
                let name = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) }
                    .to_str()
                    .map_err(|_| ApplyError::Refuse("non-UTF8 filename".into()))?;
                if name != "." && name != ".." {
                    out.push(name.into());
                }
                if out.len() > 16 {
                    return refuse("too many files for C0 workspace/state");
                }
            }
            out.sort();
            Ok(out)
        })();
        unsafe {
            libc::closedir(dir);
        }
        result
    }
    fn sync(&self) -> Result<()> {
        self.0.sync_all()?;
        Ok(())
    }
    fn unlink(&self, name: &CStr) -> Result<()> {
        if unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        self.sync()
    }
}
fn checked_fd(fd: i32) -> io::Result<i32> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}
fn stable_meta(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.nlink() == b.nlink()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
fn read_file(mut f: File, max: u64, links: u64) -> Result<(Vec<u8>, Metadata)> {
    let m = f.metadata()?;
    if !m.is_file() || m.nlink() != links || m.uid() != unsafe { libc::geteuid() } || m.len() > max
    {
        return refuse("unsupported file kind, owner, hard link or size");
    }
    let mut bytes = Vec::new();
    (&mut f).take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max || !stable_meta(&m, &f.metadata()?) {
        return refuse("file changed during validation");
    }
    Ok((bytes, m))
}
fn scan(
    d: &Directory,
    c: &C0FileContract,
    final_state: bool,
    stage: Option<&StageIdentity>,
) -> Result<FilesystemWorld> {
    d.private()?;
    let mut expected = vec!["input.txt".to_owned()];
    if final_state {
        expected.push(c.output_path.clone());
    }
    expected.sort();
    if d.names()? != expected {
        return refuse("unexpected file, missing input or already-existing output");
    }
    let mut entries = BTreeMap::new();
    for n in &expected {
        let links = if n == &c.output_path && stage.is_some() {
            2
        } else {
            1
        };
        let (b, m) = read_file(d.file(n)?, 128, links)?;
        if let Some(s) = stage.filter(|_| n == &c.output_path)
            && (s.device != m.dev()
                || s.inode != m.ino()
                || s.content != digest(&b)
                || s.mode != m.mode() & 0o7777)
        {
            return refuse("output is not the journal-owned staged inode");
        }
        entries.insert(
            n.clone(),
            FilesystemObject::File {
                content_blake3: digest(&b),
                mode: m.mode() & 0o7777,
            },
        );
    }
    if d.names()? != expected {
        return refuse("workspace changed during scan");
    }
    Ok(FilesystemWorld {
        root: digest(&serde_json::to_vec(&entries)?),
        entries,
    })
}
fn plan_for(v: &VerifiedDelta, d: &Directory) -> Result<ApplyPlan> {
    let (before, after, _) = v.contract.commitments()?;
    Ok(ApplyPlan {
        schema_version: 1,
        artifact_blake3: v.artifact_blake3.clone(),
        run_id: v.run_id.clone(),
        authority_head_root: v.head_root.clone(),
        destination: d.identity()?,
        starting_world: before,
        final_world: after,
        create_path: v.contract.output_path.clone(),
        create_bytes: v.contract.output_bytes.len() as u64,
        create_mode: v.contract.output_mode,
    })
}
pub fn preflight(v: &VerifiedDelta, destination: &Path) -> Result<ApplyPlan> {
    let d = Directory::open(destination)?;
    let p = plan_for(v, &d)?;
    if scan(&d, &v.contract, false, None)?.root != p.starting_world {
        return refuse("destination baseline differs from verified task input");
    }
    Ok(p)
}
struct State {
    dir: Directory,
    journal: File,
}
impl State {
    fn open(path: &Path, destination: &Directory, create: bool) -> Result<Self> {
        let dir = Directory::open(path)?;
        if dir.identity()? == destination.identity()?
            || dir.identity()?.device != destination.identity()?.device
        {
            return refuse("state must be separate from destination on the same filesystem");
        }
        if dir
            .names()?
            .iter()
            .any(|n| !["journal.jsonl", "stage", "receipt.json"].contains(&n.as_str()))
        {
            return refuse("state directory contains unknown files");
        }
        let journal = dir.open_at(
            c"journal.jsonl",
            libc::O_RDWR
                | if create { libc::O_CREAT } else { 0 }
                | libc::O_NOFOLLOW
                | libc::O_APPEND,
            0o600,
        )?;
        let m = journal.metadata()?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o7777 != 0o600
        {
            return refuse("untrusted journal file");
        }
        if unsafe { libc::flock(journal.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return refuse("another application holds this journal");
        }
        dir.sync()?;
        Ok(Self { dir, journal })
    }
    fn load(&self) -> Result<Vec<JournalEntry>> {
        // read through a fresh FD, not the shared append FD's changing offset.
        let (bytes, _) = read_file(self.dir.file("journal.jsonl")?, 1024 * 1024, 1)?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        if !bytes.ends_with(b"\n") {
            return refuse("torn journal; mutation status UNKNOWN, manual reconciliation required");
        }
        let mut rows = Vec::<JournalEntry>::new();
        let mut previous = "0".repeat(64);
        for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            let r: JournalEntry = serde_json::from_slice(line)?;
            if r.sequence != rows.len() as u64
                || r.previous != previous
                || r.approval_id != r.plan.approval_id()?
            {
                return refuse("journal binding/sequence/hash mismatch");
            }
            let expected_phase = match rows.len() {
                0 => ApplicationState::Authorized,
                1 => ApplicationState::Staged,
                2 => ApplicationState::Linked,
                3 => ApplicationState::Complete,
                _ => return refuse("journal has extra operations"),
            };
            if r.phase != expected_phase
                || (rows.is_empty() && r.stage.is_some())
                || (!rows.is_empty() && r.stage.is_none())
            {
                return refuse("invalid journal phase or stage identity");
            }
            if let Some(prior) = rows.last()
                && (r.plan != prior.plan
                    || r.approval_id != prior.approval_id
                    || (rows.len() > 1 && r.stage != prior.stage))
            {
                return refuse("journal operation identity changed");
            }
            previous = digest(line);
            rows.push(r);
        }
        Ok(rows)
    }
    fn append(
        &mut self,
        rows: &mut Vec<JournalEntry>,
        plan: &ApplyPlan,
        phase: ApplicationState,
        stage: Option<StageIdentity>,
    ) -> Result<()> {
        let previous = rows
            .last()
            .map(|r| serde_json::to_vec(r).map(|b| digest(&b)))
            .transpose()?
            .unwrap_or_else(|| "0".repeat(64));
        let r = JournalEntry {
            sequence: rows.len() as u64,
            plan: plan.clone(),
            approval_id: plan.approval_id()?,
            phase,
            stage,
            previous,
        };
        let mut b = serde_json::to_vec(&r)?;
        b.push(b'\n');
        self.journal.write_all(&b)?;
        self.journal.sync_all()?;
        self.dir.sync()?;
        rows.push(r);
        Ok(())
    }
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
enum Stop {
    None,
    #[cfg(test)]
    AfterAuthorized,
    #[cfg(test)]
    AfterStaged,
    #[cfg(test)]
    AfterLink,
    #[cfg(test)]
    AfterLinked,
    #[cfg(test)]
    AfterUnlink,
}
#[cfg(test)]
fn stop(_at: Stop, _here: Stop) -> Result<()> {
    #[cfg(test)]
    if std::mem::discriminant(&_at) == std::mem::discriminant(&_here) && !matches!(_at, Stop::None)
    {
        return refuse("test interruption");
    }
    Ok(())
}
/// Apply one create-only effect, after a separate, destination-bound approval.
/// A journal is required even for the first operation. Resume never infers
/// ownership from matching bytes: it requires the staged inode recorded before
/// publication. A same-content preexisting file cannot be adopted.
pub fn apply(
    v: &VerifiedDelta,
    destination: &Path,
    state: &Path,
    approval: &str,
) -> Result<HostReceipt> {
    apply_inner(v, destination, state, approval, Stop::None)
}
fn apply_inner(
    v: &VerifiedDelta,
    destination: &Path,
    state: &Path,
    approval: &str,
    fault: Stop,
) -> Result<HostReceipt> {
    let _ = fault;
    if state.starts_with(destination) || destination.starts_with(state) {
        return refuse("state and destination must be separate sibling trees");
    }
    let d = Directory::open(destination)?;
    let plan = plan_for(v, &d)?;
    if approval != plan.approval_id()? {
        return refuse("explicit approval does not match this artifact and destination");
    }
    // State is outside the task world: nested state directories appear in scans
    // and cannot pass the exact C0 baseline or postcondition.
    let mut st = State::open(state, &d, true)?;
    let mut rows = st.load()?;
    if let Some(r) = rows.last() {
        if r.plan != plan || r.approval_id != approval {
            return refuse("journal belongs to another task/destination");
        }
    } else {
        if st.dir.names()? != ["journal.jsonl"] {
            return refuse("nonempty state without durable authorization");
        }
        if scan(&d, &v.contract, false, None)?.root != plan.starting_world {
            return refuse("baseline changed before authorization");
        }
        st.append(&mut rows, &plan, ApplicationState::Authorized, None)?;
        #[cfg(test)]
        stop(fault, Stop::AfterAuthorized)?;
    }
    if rows.last().unwrap().phase == ApplicationState::Authorized {
        if scan(&d, &v.contract, false, None)?.root != plan.starting_world {
            return refuse("baseline changed before staging");
        }
        // If a crash left a stage before its identity was durable, refuse. It is
        // not safe to turn an unjournaled inode into execution authority.
        let mut f = st.dir.open_at(
            c"stage",
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )?;
        f.write_all(&v.contract.output_bytes)?;
        if unsafe { libc::fchmod(f.as_raw_fd(), v.contract.output_mode as libc::mode_t) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        f.sync_all()?;
        st.dir.sync()?;
        let m = f.metadata()?;
        let s = StageIdentity {
            device: m.dev(),
            inode: m.ino(),
            content: digest(&v.contract.output_bytes),
            mode: v.contract.output_mode,
        };
        st.append(&mut rows, &plan, ApplicationState::Staged, Some(s))?;
        #[cfg(test)]
        stop(fault, Stop::AfterStaged)?;
    }
    let stage = rows
        .last()
        .unwrap()
        .stage
        .clone()
        .ok_or_else(|| ApplyError::Refuse("missing stage identity".into()))?;
    if rows.last().unwrap().phase == ApplicationState::Staged {
        let names = d.names()?;
        if names.iter().any(|n| n == &v.contract.output_path) {
            if scan(&d, &v.contract, true, Some(&stage))?.root != plan.final_world {
                return refuse("post-link recovery world mismatch");
            }
        } else {
            if scan(&d, &v.contract, false, None)?.root != plan.starting_world {
                return refuse("baseline changed before application");
            }
            let (b, m) = read_file(st.dir.file("stage")?, 128, 1)?;
            if m.dev() != stage.device
                || m.ino() != stage.inode
                || digest(&b) != stage.content
                || m.mode() & 0o7777 != stage.mode
            {
                return refuse("staged payload differs from durable identity");
            }
            let out = CString::new(v.contract.output_path.as_str())
                .map_err(|_| ApplyError::Refuse("NUL output path".into()))?;
            // linkat is atomic no-replace. Unlike rename, a concurrent target is
            // never overwritten. No intermediate partial output is visible.
            if unsafe {
                libc::linkat(
                    st.dir.0.as_raw_fd(),
                    c"stage".as_ptr(),
                    d.0.as_raw_fd(),
                    out.as_ptr(),
                    0,
                )
            } != 0
            {
                return Err(io::Error::last_os_error().into());
            }
            d.sync()?;
            #[cfg(test)]
            stop(fault, Stop::AfterLink)?;
            if scan(&d, &v.contract, true, Some(&stage))?.root != plan.final_world {
                return refuse(
                    "world changed at effect application; partial result requires reconciliation",
                );
            }
        }
        st.append(
            &mut rows,
            &plan,
            ApplicationState::Linked,
            Some(stage.clone()),
        )?;
        #[cfg(test)]
        stop(fault, Stop::AfterLinked)?;
    }
    if rows.last().unwrap().phase == ApplicationState::Linked {
        if st.dir.names()?.iter().any(|n| n == "stage") {
            if scan(&d, &v.contract, true, Some(&stage))?.root != plan.final_world {
                return refuse("linked output changed before stage retirement");
            }
            st.dir.unlink(c"stage")?;
            #[cfg(test)]
            stop(fault, Stop::AfterUnlink)?;
        }
        // A reopened checker derives the world independently of executor logs.
        let observed = inspect_destination(v, destination, Some(&stage))?;
        if observed != plan.final_world {
            return refuse("final independent host verification failed");
        }
        st.append(
            &mut rows,
            &plan,
            ApplicationState::Complete,
            Some(stage.clone()),
        )?;
    }
    let receipt = receipt(v, &plan, inspect_destination(v, destination, Some(&stage))?);
    if !receipt.verified {
        return refuse("completed journal no longer matches host state");
    }
    let bytes = serde_json::to_vec_pretty(&receipt)?;
    match st.dir.open_at(
        c"receipt.json",
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
        0o600,
    ) {
        Ok(mut f) => {
            f.write_all(&bytes)?;
            f.sync_all()?;
            st.dir.sync()?;
        }
        Err(ApplyError::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => {
            let (old, _) = read_file(st.dir.file("receipt.json")?, 1024 * 1024, 1)?;
            if old != bytes {
                return refuse("existing receipt differs; preserve it and reconcile");
            }
        }
        Err(e) => return Err(e),
    }
    // Last read after receipt durability; a changed world can never return a
    // successful current observation merely because a historical receipt exists.
    drop(st);
    verify_host(v, destination, state)
}
fn inspect_destination(
    v: &VerifiedDelta,
    path: &Path,
    owned: Option<&StageIdentity>,
) -> Result<String> {
    let d = Directory::open(path)?;
    let world = scan(&d, &v.contract, true, None)?;
    if let Some(s) = owned {
        let (_, m) = read_file(d.file(&v.contract.output_path)?, 128, 1)?;
        if m.dev() != s.device || m.ino() != s.inode {
            return refuse("final output inode is not the applied operation");
        }
    }
    Ok(world.root)
}
fn receipt(v: &VerifiedDelta, p: &ApplyPlan, observed: String) -> HostReceipt {
    HostReceipt { schema_version: 1, approval_id: p.approval_id().expect("serializable plan"), artifact_blake3: v.artifact_blake3.clone(), run_id: v.run_id.clone(), destination: p.destination.clone(), operation: format!("create {} ({} bytes, mode {:04o})", p.create_path, p.create_bytes, p.create_mode), state: ApplicationState::Complete, verified: observed == p.final_world, independently_observed_world: observed, expected_world: p.final_world.clone(), history_complete: false, scope: "C0 destination final content/mode and journal-owned create; trusted OS, exclusive user control; no proof of unobserved external history".into() }
}
/// Independent fresh final-state inspection. Receipt contents alone never pass
/// this check, and no host execution or mutation is performed by this API.
pub fn verify_host(v: &VerifiedDelta, destination: &Path, state: &Path) -> Result<HostReceipt> {
    let d = Directory::open(destination)?;
    let plan = plan_for(v, &d)?;
    let st = State::open(state, &d, false)?;
    let rows = st.load()?;
    let r = rows
        .last()
        .ok_or_else(|| ApplyError::Refuse("no applied operation journal".into()))?;
    if r.plan != plan
        || r.phase != ApplicationState::Complete
        || st.dir.names()? != ["journal.jsonl", "receipt.json"]
    {
        return refuse("application journal is incomplete or belongs to another destination");
    }
    let observed = inspect_destination(v, destination, r.stage.as_ref())?;
    let result = receipt(v, &plan, observed);
    let (bytes, _) = read_file(st.dir.file("receipt.json")?, 1024 * 1024, 1)?;
    let saved: HostReceipt = serde_json::from_slice(&bytes)?;
    if !result.verified || saved != result {
        return refuse("receipt and independently observed host state disagree");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static ID: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        root: PathBuf,
        dest: PathBuf,
        state: PathBuf,
        v: VerifiedDelta,
    }
    impl Fixture {
        fn new() -> Self {
            #[cfg(target_os = "macos")]
            let prefix = "/private/tmp";
            #[cfg(not(target_os = "macos"))]
            let prefix = "/tmp";
            let root = PathBuf::from(format!(
                "{prefix}/realm-v7-{}-{}",
                std::process::id(),
                ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let dest = root.join("dest");
            let state = root.join("state");
            for p in [&dest, &state] {
                fs::create_dir(p).unwrap();
                fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
            }
            fs::write(dest.join("input.txt"), b"abc").unwrap();
            fs::set_permissions(dest.join("input.txt"), fs::Permissions::from_mode(0o644)).unwrap();
            // Synthetic mechanics-only fixture. Cannot create ACCEPT or .realm.
            let v = VerifiedDelta {
                contract: C0FileContract::frozen(),
                artifact_blake3: "a".repeat(64),
                run_id: "synthetic-applier-unit-fixture".into(),
                head_root: "b".repeat(64),
            };
            Self {
                root,
                dest,
                state,
                v,
            }
        }
        fn approval(&self) -> String {
            preflight(&self.v, &self.dest)
                .unwrap()
                .approval_id()
                .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
    #[test]
    fn create_apply_reopen_repeat_preserves_inode_and_journal() {
        let f = Fixture::new();
        let a = f.approval();
        let r = apply(&f.v, &f.dest, &f.state, &a).unwrap();
        assert!(r.verified);
        assert!(!r.history_complete);
        assert_eq!(fs::read(f.dest.join("output.txt")).unwrap(), b"ABC");
        let ino = fs::metadata(f.dest.join("output.txt")).unwrap().ino();
        assert_eq!(verify_host(&f.v, &f.dest, &f.state).unwrap(), r);
        assert_eq!(apply(&f.v, &f.dest, &f.state, &a).unwrap(), r);
        assert_eq!(fs::metadata(f.dest.join("output.txt")).unwrap().ino(), ino);
        assert_eq!(
            fs::read_to_string(f.state.join("journal.jsonl"))
                .unwrap()
                .lines()
                .count(),
            4
        );
    }
    #[test]
    fn durable_interruption_boundaries_recover_without_repeating_effects() {
        for stop_at in [
            Stop::AfterAuthorized,
            Stop::AfterStaged,
            Stop::AfterLink,
            Stop::AfterLinked,
            Stop::AfterUnlink,
        ] {
            let f = Fixture::new();
            let a = f.approval();
            assert!(apply_inner(&f.v, &f.dest, &f.state, &a, stop_at).is_err());
            let prior = fs::metadata(f.dest.join("output.txt"))
                .ok()
                .map(|m| m.ino());
            assert!(apply(&f.v, &f.dest, &f.state, &a).unwrap().verified);
            if let Some(ino) = prior {
                assert_eq!(fs::metadata(f.dest.join("output.txt")).unwrap().ino(), ino);
            }
        }
    }
    #[test]
    fn mismatched_approval_writes_nothing() {
        let f = Fixture::new();
        assert!(apply(&f.v, &f.dest, &f.state, "forged").is_err());
        assert_eq!(fs::read_dir(&f.state).unwrap().count(), 0);
        assert!(!f.dest.join("output.txt").exists());
    }
    #[test]
    fn approval_is_bound_to_destination_and_artifact() {
        let mut f = Fixture::new();
        let a = f.approval();
        let other = f.root.join("other");
        fs::create_dir(&other).unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(other.join("input.txt"), b"abc").unwrap();
        assert!(apply(&f.v, &other, &f.state, &a).is_err());
        f.v.artifact_blake3 = "c".repeat(64);
        assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
    }
    #[test]
    fn existing_matching_output_cannot_be_adopted() {
        let f = Fixture::new();
        let a = f.approval();
        fs::write(f.dest.join("output.txt"), b"ABC").unwrap();
        let ino = fs::metadata(f.dest.join("output.txt")).unwrap().ino();
        assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
        assert_eq!(fs::metadata(f.dest.join("output.txt")).unwrap().ino(), ino);
    }
    #[test]
    fn baseline_content_mode_extra_files_and_links_fail_closed() {
        for case in 0..5 {
            let f = Fixture::new();
            let a = f.approval();
            match case {
                0 => fs::write(f.dest.join("input.txt"), b"changed").unwrap(),
                1 => {
                    fs::set_permissions(f.dest.join("input.txt"), fs::Permissions::from_mode(0o600))
                        .unwrap()
                }
                2 => fs::write(f.dest.join("extra"), b"x").unwrap(),
                3 => symlink("input.txt", f.dest.join("alias")).unwrap(),
                _ => fs::hard_link(f.dest.join("input.txt"), f.root.join("outside")).unwrap(),
            }
            assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
            assert!(!f.dest.join("output.txt").exists());
        }
    }
    #[test]
    fn symlink_target_and_parent_refused_without_following() {
        let f = Fixture::new();
        let a = f.approval();
        fs::write(f.root.join("outside"), b"sentinel").unwrap();
        symlink(f.root.join("outside"), f.dest.join("output.txt")).unwrap();
        assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
        symlink(&f.dest, f.root.join("alias")).unwrap();
        assert!(preflight(&f.v, &f.root.join("alias")).is_err());
        assert_eq!(fs::read(f.root.join("outside")).unwrap(), b"sentinel");
    }
    #[test]
    fn fresh_journal_cannot_duplicate_completed_application() {
        let f = Fixture::new();
        let a = f.approval();
        apply(&f.v, &f.dest, &f.state, &a).unwrap();
        let second = f.root.join("state2");
        fs::create_dir(&second).unwrap();
        fs::set_permissions(&second, fs::Permissions::from_mode(0o700)).unwrap();
        let ino = fs::metadata(f.dest.join("output.txt")).unwrap().ino();
        assert!(apply(&f.v, &f.dest, &second, &a).is_err());
        assert_eq!(fs::metadata(f.dest.join("output.txt")).unwrap().ino(), ino);
    }
    #[test]
    fn matching_bytes_on_unowned_inode_cannot_recover_link() {
        let f = Fixture::new();
        let a = f.approval();
        assert!(apply_inner(&f.v, &f.dest, &f.state, &a, Stop::AfterStaged).is_err());
        fs::write(f.dest.join("output.txt"), b"ABC").unwrap();
        fs::set_permissions(f.dest.join("output.txt"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
    }
    #[test]
    fn torn_journal_and_unjournaled_stage_preserve_unknown() {
        for torn in [false, true] {
            let f = Fixture::new();
            let a = f.approval();
            assert!(apply_inner(&f.v, &f.dest, &f.state, &a, Stop::AfterAuthorized).is_err());
            if torn {
                let mut b = fs::read(f.state.join("journal.jsonl")).unwrap();
                b.pop();
                fs::write(f.state.join("journal.jsonl"), b).unwrap();
            } else {
                fs::write(f.state.join("stage"), b"ABC").unwrap();
            }
            assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
            assert!(!f.dest.join("output.txt").exists());
        }
    }
    #[test]
    fn input_invalidation_after_staging_prevents_publication() {
        let f = Fixture::new();
        let a = f.approval();
        assert!(apply_inner(&f.v, &f.dest, &f.state, &a, Stop::AfterStaged).is_err());
        fs::write(f.dest.join("input.txt"), b"XYZ").unwrap();
        assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
        assert!(!f.dest.join("output.txt").exists());
    }
    #[test]
    fn independent_verification_rejects_receipt_state_tampering() {
        for case in 0..4 {
            let f = Fixture::new();
            let a = f.approval();
            apply(&f.v, &f.dest, &f.state, &a).unwrap();
            match case {
                0 => fs::write(f.dest.join("output.txt"), b"BAD").unwrap(),
                1 => fs::set_permissions(
                    f.dest.join("output.txt"),
                    fs::Permissions::from_mode(0o644),
                )
                .unwrap(),
                2 => {
                    let b = fs::read(f.dest.join("output.txt")).unwrap();
                    fs::remove_file(f.dest.join("output.txt")).unwrap();
                    fs::write(f.dest.join("output.txt"), b).unwrap();
                }
                _ => fs::write(f.state.join("receipt.json"), b"{}").unwrap(),
            }
            assert!(verify_host(&f.v, &f.dest, &f.state).is_err());
            assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
        }
    }
    #[test]
    fn read_only_verifier_does_not_create_journal() {
        let f = Fixture::new();
        assert!(verify_host(&f.v, &f.dest, &f.state).is_err());
        assert_eq!(fs::read_dir(&f.state).unwrap().count(), 0);
    }
    #[test]
    fn unsafe_state_permissions_journal_links_and_foreign_files_refuse() {
        for case in 0..4 {
            let f = Fixture::new();
            let a = f.approval();
            match case {
                0 => fs::set_permissions(&f.state, fs::Permissions::from_mode(0o755)).unwrap(),
                1 => {
                    fs::write(f.state.join("journal.jsonl"), b"").unwrap();
                    fs::hard_link(f.state.join("journal.jsonl"), f.root.join("alias-journal"))
                        .unwrap();
                }
                2 => {
                    fs::write(f.root.join("outside"), b"sentinel").unwrap();
                    symlink(f.root.join("outside"), f.state.join("journal.jsonl")).unwrap();
                }
                _ => fs::write(f.state.join("unknown"), b"x").unwrap(),
            }
            assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
            assert!(!f.dest.join("output.txt").exists());
        }
    }
    #[test]
    fn simultaneous_journal_lock_refuses_without_host_effect() {
        let f = Fixture::new();
        let a = f.approval();
        let d = Directory::open(&f.dest).unwrap();
        let _held = State::open(&f.state, &d, true).unwrap();
        assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
        assert!(!f.dest.join("output.txt").exists());
    }

    #[test]
    fn concurrent_distinct_journals_publish_exactly_one_create() {
        let f = Fixture::new();
        let a = f.approval();
        let second = f.root.join("state2");
        fs::create_dir(&second).unwrap();
        fs::set_permissions(&second, fs::Permissions::from_mode(0o700)).unwrap();
        let barrier = std::sync::Barrier::new(3);
        let outcomes = std::thread::scope(|scope| {
            let one = scope.spawn(|| {
                barrier.wait();
                apply(&f.v, &f.dest, &f.state, &a)
            });
            let two = scope.spawn(|| {
                barrier.wait();
                apply(&f.v, &f.dest, &second, &a)
            });
            barrier.wait();
            [one.join().unwrap(), two.join().unwrap()]
        });
        assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(fs::read(f.dest.join("output.txt")).unwrap(), b"ABC");
        assert_eq!(fs::metadata(f.dest.join("output.txt")).unwrap().nlink(), 1);
        assert_eq!(fs::read(f.dest.join("input.txt")).unwrap(), b"abc");
    }

    #[test]
    fn fifo_input_refuses_before_any_read_or_host_effect() {
        let f = Fixture::new();
        fs::remove_file(f.dest.join("input.txt")).unwrap();
        let n = CString::new(f.dest.join("input.txt").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(n.as_ptr(), 0o644) }, 0);
        assert!(preflight(&f.v, &f.dest).is_err());
        assert!(!f.dest.join("output.txt").exists());
    }
}
