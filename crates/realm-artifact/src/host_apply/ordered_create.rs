//! Ordered three-file host mechanics. There is deliberately NO production
//! constructor for VerifiedCreateBatch until a qualified coding verifier exists.
//! C0 transfers cannot obtain this type. Tests exercise filesystem mechanics,
//! not execution authority, containment, publication or coding qualification.
use super::*;

const PATHS: [&str; 3] = ["totals.py", "report.py", "test_totals.py"];
const MAX_FILE: u64 = 32 * 1024;

/// Future verified coding delta. No deserializer or public constructor exists.
/// ```compile_fail
/// use realm_artifact::host_apply::ordered_create::VerifiedCreateBatch;
/// let forged: VerifiedCreateBatch = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug)]
pub struct VerifiedCreateBatch {
    artifact: String,
    run: String,
    head: String,
    semantic: String,
    files: [Vec<u8>; 3],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOperation {
    pub index: usize,
    pub path: String,
    pub content_blake3: String,
    pub bytes: u64,
    pub mode: u32,
    /// Every preceding operation must be durably complete.
    pub requires_completed: usize,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderedPlan {
    pub schema: String,
    pub artifact: String,
    pub run: String,
    pub head: String,
    pub semantic: String,
    pub destination: DirectoryIdentity,
    pub before: String,
    pub after: String,
    pub operations: Vec<CreateOperation>,
}
impl OrderedPlan {
    pub fn approval_id(&self) -> Result<String> {
        Ok(crate::hash(
            "realm.host-ordered-create-approval.v1",
            &serde_json::to_vec(self)?,
        )
        .value)
    }
}
impl VerifiedCreateBatch {
    fn plan(&self, d: &Directory) -> Result<OrderedPlan> {
        if [&self.artifact, &self.run, &self.head, &self.semantic]
            .iter()
            .any(|s| !valid_digest(s))
            || self.files.iter().any(|b| b.len() as u64 > MAX_FILE)
        {
            return refuse("unsupported coding batch identity or size");
        }
        let operations = PATHS
            .iter()
            .enumerate()
            .map(|(i, p)| CreateOperation {
                index: i,
                path: (*p).into(),
                content_blake3: digest(&self.files[i]),
                bytes: self.files[i].len() as u64,
                mode: 0o600,
                requires_completed: i,
            })
            .collect();
        Ok(OrderedPlan {
            schema: "realm.host-ordered-create.v1".into(),
            artifact: self.artifact.clone(),
            run: self.run.clone(),
            head: self.head.clone(),
            semantic: self.semantic.clone(),
            destination: d.identity()?,
            before: expected_world(self, 0)?,
            after: expected_world(self, 3)?,
            operations,
        })
    }
}
fn expected_world(v: &VerifiedCreateBatch, count: usize) -> Result<String> {
    let entries = (0..count)
        .map(|i| {
            (
                PATHS[i].to_owned(),
                FilesystemObject::File {
                    content_blake3: digest(&v.files[i]),
                    mode: 0o600,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    Ok(digest(&serde_json::to_vec(&entries)?))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Phase {
    Authorized,
    Staged,
    Linked,
    Complete,
    Finished,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    sequence: usize,
    plan: OrderedPlan,
    approval: String,
    operation: Option<usize>,
    phase: Phase,
    stage: Option<StageIdentity>,
    previous: String,
}
fn step(n: usize) -> Result<(Phase, Option<usize>)> {
    match n {
        0 => Ok((Phase::Authorized, None)),
        1..=9 => Ok((
            match (n - 1) % 3 {
                0 => Phase::Staged,
                1 => Phase::Linked,
                _ => Phase::Complete,
            },
            Some((n - 1) / 3),
        )),
        10 => Ok((Phase::Finished, None)),
        _ => refuse("extra ordered operations"),
    }
}
struct Journal {
    dir: Directory,
    file: OwnedJournalLock,
    rows: Vec<Row>,
}
// flock is shared by dup/fork aliases of the open-file description. Closing
// just the owner's descriptor need not release it if another thread forked
// before CLOEXEC took effect. End the lock explicitly with the owning scope.
struct OwnedJournalLock(File);
impl std::ops::Deref for OwnedJournalLock {
    type Target = File;
    fn deref(&self) -> &File {
        &self.0
    }
}
impl std::ops::DerefMut for OwnedJournalLock {
    fn deref_mut(&mut self) -> &mut File {
        &mut self.0
    }
}
impl Drop for OwnedJournalLock {
    fn drop(&mut self) {
        while unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) } != 0 {
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
    }
}
impl Journal {
    fn open(path: &Path, d: &Directory, create: bool, plan: &OrderedPlan) -> Result<Self> {
        let dir = Directory::open(path)?;
        if dir.identity()?.device != d.identity()?.device || dir.identity()? == d.identity()? {
            return refuse("ordered state must be separate on the same filesystem");
        }
        if dir.names()?.iter().any(|s| {
            ![
                "journal.jsonl",
                "stage-0",
                "stage-1",
                "stage-2",
                "receipt.json",
            ]
            .contains(&s.as_str())
        }) {
            return refuse("unknown file in ordered state");
        }
        let file = dir.open_at(
            c"journal.jsonl",
            libc::O_RDWR
                | libc::O_APPEND
                | libc::O_NOFOLLOW
                | if create { libc::O_CREAT } else { 0 },
            0o600,
        )?;
        let m = file.metadata()?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o7777 != 0o600
        {
            return refuse("untrusted ordered journal");
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return refuse("another application holds the ordered journal");
        }
        let file = OwnedJournalLock(file);
        dir.sync()?;
        let (bytes, _) = read_file(dir.file("journal.jsonl")?, 1024 * 1024, 1)?;
        let mut rows = Vec::<Row>::new();
        let mut previous = "0".repeat(64);
        if !bytes.is_empty() {
            if !bytes.ends_with(b"\n") {
                return refuse("torn ordered journal: mutation status UNKNOWN");
            }
            for line in bytes[..bytes.len() - 1].split(|b| *b == b'\n') {
                let r: Row = serde_json::from_slice(line)?;
                let (phase, operation) = step(rows.len())?;
                if r.sequence != rows.len()
                    || r.plan != *plan
                    || r.approval != plan.approval_id()?
                    || r.previous != previous
                    || r.phase != phase
                    || r.operation != operation
                    || r.stage.is_some() != operation.is_some()
                {
                    return refuse("ordered journal binding, phase or sequence mismatch");
                }
                if let Some(i) = operation {
                    let s = r.stage.as_ref().unwrap();
                    if s.content != plan.operations[i].content_blake3
                        || s.mode != 0o600
                        || s.device != plan.destination.device
                        || (phase != Phase::Staged
                            && rows.last().and_then(|p| p.stage.as_ref()) != Some(s))
                    {
                        return refuse("ordered stage identity changed");
                    }
                    // A fresh operation cannot reuse an earlier operation's inode.
                    if phase == Phase::Staged
                        && rows
                            .iter()
                            .filter_map(|p| p.stage.as_ref())
                            .any(|p| p.device == s.device && p.inode == s.inode)
                    {
                        return refuse("ordered operations share a staged inode");
                    }
                }
                previous = digest(line);
                rows.push(r);
            }
        }
        Ok(Self { dir, file, rows })
    }
    fn append(&mut self, plan: &OrderedPlan, stage: Option<StageIdentity>) -> Result<()> {
        let (phase, operation) = step(self.rows.len())?;
        let previous = self
            .rows
            .last()
            .map(|r| serde_json::to_vec(r).map(|b| digest(&b)))
            .transpose()?
            .unwrap_or_else(|| "0".repeat(64));
        let row = Row {
            sequence: self.rows.len(),
            plan: plan.clone(),
            approval: plan.approval_id()?,
            phase,
            operation,
            stage,
            previous,
        };
        let mut bytes = serde_json::to_vec(&row)?;
        bytes.push(b'\n');
        self.file.write_all(&bytes)?;
        self.file.sync_all()?;
        self.dir.sync()?;
        self.rows.push(row);
        Ok(())
    }
    fn identities(&self) -> Vec<StageIdentity> {
        self.rows
            .iter()
            .filter(|r| r.phase == Phase::Complete)
            .map(|r| r.stage.clone().unwrap())
            .collect()
    }
    fn state_names(&self, stage: Option<usize>, receipt: bool) -> Result<()> {
        let mut expected = vec!["journal.jsonl".to_string()];
        if let Some(i) = stage {
            expected.push(format!("stage-{i}"));
        }
        if receipt {
            expected.push("receipt.json".into());
        }
        expected.sort();
        if self.dir.names()? != expected {
            return refuse("unexplained ordered state; preserve and reconcile");
        }
        Ok(())
    }
}

fn scan_prefix(
    v: &VerifiedCreateBatch,
    d: &Directory,
    identities: &[StageIdentity],
    linked_stage: bool,
) -> Result<String> {
    d.private()?;
    let count = identities.len();
    if count > 3 {
        return refuse("invalid ordered prefix");
    }
    let mut names = PATHS[..count]
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    names.sort();
    if d.names()? != names {
        return refuse("destination is not the exact approved operation prefix");
    }
    for (i, s) in identities.iter().enumerate() {
        let links = if linked_stage && i + 1 == count { 2 } else { 1 };
        let (bytes, m) = read_file(d.file(PATHS[i])?, MAX_FILE, links)?;
        if bytes != v.files[i]
            || m.mode() & 0o7777 != 0o600
            || m.dev() != s.device
            || m.ino() != s.inode
        {
            return refuse("destination bytes, mode or operation-owned inode changed");
        }
        // Check the directory name still points to the held inode.
        let named = d.file(PATHS[i])?.metadata()?;
        if !stable_meta(&m, &named) {
            return refuse("destination file replaced during scan");
        }
    }
    if d.names()? != names {
        return refuse("destination changed during ordered scan");
    }
    expected_world(v, count)
}
pub fn preflight(v: &VerifiedCreateBatch, destination: &Path) -> Result<OrderedPlan> {
    let d = Directory::open(destination)?;
    let plan = v.plan(&d)?;
    scan_prefix(v, &d, &[], false)?;
    Ok(plan)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderedReceipt {
    pub schema: String,
    pub plan: OrderedPlan,
    pub approval: String,
    pub completed_operations: usize,
    pub journal_head: String,
    pub observed_world: String,
    pub verified: bool,
    pub history_complete: bool,
    pub scope: String,
}
fn receipt(
    v: &VerifiedCreateBatch,
    plan: &OrderedPlan,
    j: &Journal,
    d: &Directory,
) -> Result<OrderedReceipt> {
    let identities = j.identities();
    if j.rows.len() != 11 || identities.len() != 3 {
        return refuse("ordered application incomplete");
    }
    let observed = scan_prefix(v, d, &identities, false)?;
    if observed != plan.after {
        return refuse("independent final world mismatch");
    }
    Ok(OrderedReceipt { schema: "realm.host-ordered-receipt.v1".into(), plan: plan.clone(),
        approval: plan.approval_id()?, completed_operations: 3,
        journal_head: digest(&serde_json::to_vec(j.rows.last().unwrap())?), observed_world: observed,
        verified: true, history_complete: false,
        scope: "three ordered create-only operations; actual current content/mode and journal-owned inodes; trusted OS and exclusive operator control; power-loss behavior unqualified".into() })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Fault {
    None,
    Boundary(usize, u8),
}
fn fault(at: Fault, operation: usize, boundary: u8) -> Result<()> {
    #[cfg(test)]
    if std::env::var("REALM_ORDERED_TEST_CRASH").ok() == Some(format!("{operation}:{boundary}")) {
        // Only the isolated child test below enables this hook. Production
        // builds never inspect this variable or expose a crash control.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
        unreachable!("SIGKILL returned");
    }
    if at == Fault::Boundary(operation, boundary) {
        return refuse("test-only ordered interruption");
    }
    Ok(())
}
pub fn apply(
    v: &VerifiedCreateBatch,
    destination: &Path,
    state: &Path,
    approval: &str,
) -> Result<OrderedReceipt> {
    apply_inner(v, destination, state, approval, Fault::None)
}
fn apply_inner(
    v: &VerifiedCreateBatch,
    destination: &Path,
    state: &Path,
    approval: &str,
    at: Fault,
) -> Result<OrderedReceipt> {
    if state.starts_with(destination) || destination.starts_with(state) {
        return refuse("ordered state and destination must be separate sibling trees");
    }
    let d = Directory::open(destination)?;
    let plan = v.plan(&d)?;
    if plan.approval_id()? != approval {
        return refuse("ordered approval does not bind this exact task and destination");
    }
    let mut j = Journal::open(state, &d, true, &plan)?;
    if j.rows.is_empty() {
        j.state_names(None, false)?;
        scan_prefix(v, &d, &[], false)?;
        j.append(&plan, None)?;
        fault(at, 0, 0)?;
    }
    for (i, path) in PATHS.iter().enumerate() {
        let complete = j.identities();
        if complete.len() > i {
            continue;
        }
        if complete.len() != i {
            return refuse("ordered dependency not durably complete");
        }
        let name = CString::new(format!("stage-{i}")).unwrap();
        let n = 1 + 3 * i;
        if j.rows.len() == n {
            j.state_names(None, false)?;
            scan_prefix(v, &d, &complete, false)?;
            let mut f = j.dir.open_at(
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                0o600,
            )?;
            f.write_all(&v.files[i])?;
            if unsafe { libc::fchmod(f.as_raw_fd(), 0o600) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            f.sync_all()?;
            j.dir.sync()?;
            // An interruption here leaves an unjournaled stage: never adopt it.
            fault(at, i, 1)?;
            let m = f.metadata()?;
            let stage = StageIdentity {
                device: m.dev(),
                inode: m.ino(),
                content: digest(&v.files[i]),
                mode: 0o600,
            };
            j.append(&plan, Some(stage))?;
            fault(at, i, 2)?;
        }
        let stage = j
            .rows
            .get(n)
            .and_then(|r| r.stage.clone())
            .ok_or_else(|| ApplyError::Refuse("ordered stage missing".into()))?;
        let mut with_current = complete.clone();
        with_current.push(stage.clone());
        if j.rows.len() == n + 1 {
            j.state_names(Some(i), false)?;
            let (bytes, m) = read_file(
                j.dir.file(name.to_str().unwrap())?,
                MAX_FILE,
                if d.names()?.iter().any(|p| p == path) {
                    2
                } else {
                    1
                },
            )?;
            if m.dev() != stage.device
                || m.ino() != stage.inode
                || bytes != v.files[i]
                || m.mode() & 0o7777 != 0o600
            {
                return refuse("ordered stage does not match durable identity");
            }
            if d.names()?.iter().any(|p| p == path) {
                scan_prefix(v, &d, &with_current, true)?;
            } else {
                scan_prefix(v, &d, &complete, false)?;
                let out = CString::new(*path).unwrap();
                if unsafe {
                    libc::linkat(
                        j.dir.0.as_raw_fd(),
                        name.as_ptr(),
                        d.0.as_raw_fd(),
                        out.as_ptr(),
                        0,
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error().into());
                }
                d.sync()?;
                fault(at, i, 3)?;
                scan_prefix(v, &d, &with_current, true)?;
            }
            j.append(&plan, Some(stage.clone()))?;
            fault(at, i, 4)?;
        }
        if j.rows.len() == n + 2 {
            let has_stage = j.dir.names()?.iter().any(|p| p == name.to_str().unwrap());
            j.state_names(if has_stage { Some(i) } else { None }, false)?;
            scan_prefix(v, &d, &with_current, has_stage)?;
            if has_stage {
                let (bytes, m) = read_file(j.dir.file(name.to_str().unwrap())?, MAX_FILE, 2)?;
                if m.dev() != stage.device
                    || m.ino() != stage.inode
                    || bytes != v.files[i]
                    || m.mode() & 0o7777 != 0o600
                {
                    return refuse("ordered linked stage changed before retirement");
                }
                j.dir.unlink(&name)?;
                fault(at, i, 5)?;
            }
            scan_prefix(v, &d, &with_current, false)?;
            j.append(&plan, Some(stage))?;
            fault(at, i, 6)?;
        }
    }
    if j.rows.len() == 10 {
        j.state_names(None, false)?;
        scan_prefix(v, &d, &j.identities(), false)?;
        j.append(&plan, None)?;
        fault(at, 3, 0)?;
    }
    let r = receipt(v, &plan, &j, &d)?;
    let bytes = serde_json::to_vec_pretty(&r)?;
    if j.dir.names()?.iter().any(|n| n == "receipt.json") {
        j.state_names(None, true)?;
        let (old, _) = read_file(j.dir.file("receipt.json")?, 1024 * 1024, 1)?;
        if old != bytes {
            return refuse("ordered saved receipt differs; preserve and reconcile");
        }
    } else {
        j.state_names(None, false)?;
        let mut f = j.dir.open_at(
            c"receipt.json",
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        j.dir.sync()?;
    }
    drop(j);
    verify_host(v, destination, state)
}
/// Fresh read-only world inspection; saved success fields never act as an oracle.
pub fn verify_host(
    v: &VerifiedCreateBatch,
    destination: &Path,
    state: &Path,
) -> Result<OrderedReceipt> {
    let d = Directory::open(destination)?;
    let plan = v.plan(&d)?;
    let j = Journal::open(state, &d, false, &plan)?;
    j.state_names(None, true)?;
    let r = receipt(v, &plan, &j, &d)?;
    let (bytes, _) = read_file(j.dir.file("receipt.json")?, 1024 * 1024, 1)?;
    let saved: OrderedReceipt = serde_json::from_slice(&bytes)?;
    if saved != r {
        return refuse("ordered receipt differs from independent physical state");
    }
    Ok(r)
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
        v: VerifiedCreateBatch,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "realm-ordered-{}-{}",
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
            // Mechanics fixture ONLY. No production issuer exists for this type.
            let v = VerifiedCreateBatch {
                artifact: "a".repeat(64),
                run: "b".repeat(64),
                head: "c".repeat(64),
                semantic: "d".repeat(64),
                files: [
                    b"def summarize(x): return x\n".to_vec(),
                    b"from totals import summarize\n".to_vec(),
                    b"assert True\n".to_vec(),
                ],
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
        fn snapshot(&self) -> Vec<(Vec<u8>, u64, u32)> {
            PATHS
                .iter()
                .filter(|p| self.dest.join(p).exists())
                .map(|p| {
                    let m = fs::metadata(self.dest.join(p)).unwrap();
                    (
                        fs::read(self.dest.join(p)).unwrap(),
                        m.ino(),
                        m.mode() & 0o7777,
                    )
                })
                .collect()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
    #[test]
    fn three_creates_separately_reopen_and_resume_without_duplicates() {
        let f = Fixture::new();
        let a = f.approval();
        let r = apply(&f.v, &f.dest, &f.state, &a).unwrap();
        assert!(r.verified);
        assert!(!r.history_complete);
        assert_eq!(r.completed_operations, 3);
        let old = f.snapshot();
        assert_eq!(verify_host(&f.v, &f.dest, &f.state).unwrap(), r);
        assert_eq!(apply(&f.v, &f.dest, &f.state, &a).unwrap(), r);
        assert_eq!(f.snapshot(), old);
        for (i, (bytes, _, mode)) in old.iter().enumerate() {
            assert_eq!(bytes, &f.v.files[i]);
            assert_eq!(*mode, 0o600);
        }
    }
    #[test]
    fn interrupted_each_operation_resumes_only_owned_prefix() {
        for i in 0..3 {
            for boundary in [2, 3, 4, 5, 6] {
                let f = Fixture::new();
                let a = f.approval();
                assert!(
                    apply_inner(&f.v, &f.dest, &f.state, &a, Fault::Boundary(i, boundary)).is_err()
                );
                assert!(verify_host(&f.v, &f.dest, &f.state).is_err());
                let old = f.snapshot();
                assert!(apply(&f.v, &f.dest, &f.state, &a).unwrap().verified);
                assert_eq!(&f.snapshot()[..old.len()], old.as_slice());
            }
        }
        for (i, b) in [(0, 0), (3, 0)] {
            let f = Fixture::new();
            let a = f.approval();
            assert!(apply_inner(&f.v, &f.dest, &f.state, &a, Fault::Boundary(i, b)).is_err());
            assert!(apply(&f.v, &f.dest, &f.state, &a).unwrap().verified);
        }
    }
    #[test]
    fn journal_owner_releases_lock_even_if_an_inherited_description_survives() {
        let f = Fixture::new();
        let destination = Directory::open(&f.dest).unwrap();
        let plan = f.v.plan(&destination).unwrap();
        let owner = Journal::open(&f.state, &destination, true, &plan).unwrap();
        // dup/fork aliases share the kernel open-file description. CLOEXEC
        // closes a forked alias only at exec, which can lag another thread's
        // completion and immediate resume. Keep a real alias open here.
        let inherited = owner.file.try_clone().unwrap();
        assert!(Journal::open(&f.state, &destination, false, &plan).is_err());
        drop(owner);
        let resumed = Journal::open(&f.state, &destination, false, &plan)
            .expect("finished owner must release its advisory lock before all aliases close");
        drop(resumed);
        drop(inherited);
    }
    #[test]
    fn unjournaled_stages_and_torn_journals_cannot_be_adopted() {
        for i in 0..3 {
            let f = Fixture::new();
            let a = f.approval();
            assert!(apply_inner(&f.v, &f.dest, &f.state, &a, Fault::Boundary(i, 1)).is_err());
            let before = f.snapshot();
            assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
            assert_eq!(f.snapshot(), before);
        }
        let f = Fixture::new();
        let a = f.approval();
        assert!(apply_inner(&f.v, &f.dest, &f.state, &a, Fault::Boundary(1, 3)).is_err());
        let mut b = fs::read(f.state.join("journal.jsonl")).unwrap();
        b.pop();
        fs::write(f.state.join("journal.jsonl"), b).unwrap();
        let before = f.snapshot();
        assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
        assert_eq!(f.snapshot(), before);
    }
    #[test]
    fn stale_destinations_and_unauthorized_intermediate_files_stop_next_effect() {
        for kind in 0..4 {
            let f = Fixture::new();
            let a = f.approval();
            assert!(apply_inner(&f.v, &f.dest, &f.state, &a, Fault::Boundary(0, 6)).is_err());
            match kind {
                0 => fs::write(f.dest.join("extra"), b"unauthorized").unwrap(),
                1 => fs::write(f.dest.join(PATHS[0]), b"stale").unwrap(),
                2 => fs::write(f.dest.join(PATHS[1]), &f.v.files[1]).unwrap(),
                _ => symlink(f.root.join("outside"), f.dest.join(PATHS[1])).unwrap(),
            }
            let before = f.snapshot();
            let names = fs::read_dir(&f.dest)
                .unwrap()
                .map(|p| p.unwrap().file_name())
                .collect::<std::collections::BTreeSet<_>>();
            let journal = fs::read(f.state.join("journal.jsonl")).unwrap();
            assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
            assert_eq!(f.snapshot(), before);
            assert_eq!(fs::read(f.state.join("journal.jsonl")).unwrap(), journal);
            assert_eq!(
                fs::read_dir(&f.dest)
                    .unwrap()
                    .map(|p| p.unwrap().file_name())
                    .collect::<std::collections::BTreeSet<_>>(),
                names
            );
            assert!(!f.dest.join(PATHS[2]).exists());
        }
    }
    #[test]
    fn artifact_run_semantic_order_and_destination_are_approval_bound() {
        for kind in 0..6 {
            let mut f = Fixture::new();
            let a = f.approval();
            match kind {
                0 => f.v.artifact = "e".repeat(64),
                1 => f.v.run = "e".repeat(64),
                2 => f.v.head = "e".repeat(64),
                3 => f.v.semantic = "e".repeat(64),
                4 => f.v.files.swap(0, 1),
                _ => {
                    fs::rename(&f.dest, f.root.join("old-dest")).unwrap();
                    fs::create_dir(&f.dest).unwrap();
                    fs::set_permissions(&f.dest, fs::Permissions::from_mode(0o700)).unwrap();
                }
            }
            assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
            assert_eq!(fs::read_dir(&f.state).unwrap().count(), 0);
        }
        for kind in 0..2 {
            let mut f = Fixture::new();
            let a = f.approval();
            assert!(apply_inner(&f.v, &f.dest, &f.state, &a, Fault::Boundary(0, 6)).is_err());
            let before = f.snapshot();
            let journal = fs::read(f.state.join("journal.jsonl")).unwrap();
            if kind == 0 {
                f.v.artifact = "e".repeat(64);
            } else {
                f.v.run = "e".repeat(64);
            }
            assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
            assert_eq!(f.snapshot(), before);
            assert_eq!(fs::read(f.state.join("journal.jsonl")).unwrap(), journal);
        }
    }
    #[test]
    fn matching_unowned_output_is_not_recovered_and_prior_inode_changes_refuse() {
        let f = Fixture::new();
        let a = f.approval();
        assert!(apply_inner(&f.v, &f.dest, &f.state, &a, Fault::Boundary(1, 2)).is_err());
        fs::write(f.dest.join(PATHS[1]), &f.v.files[1]).unwrap();
        fs::set_permissions(f.dest.join(PATHS[1]), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
        assert!(!f.dest.join(PATHS[2]).exists());
        let f = Fixture::new();
        let a = f.approval();
        apply(&f.v, &f.dest, &f.state, &a).unwrap();
        fs::rename(f.dest.join(PATHS[0]), f.root.join("old-inode")).unwrap();
        fs::write(f.dest.join(PATHS[0]), &f.v.files[0]).unwrap();
        fs::set_permissions(f.dest.join(PATHS[0]), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(verify_host(&f.v, &f.dest, &f.state).is_err());
        assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
    }
    #[test]
    fn reordered_journal_and_unknown_state_refuse_before_more_creates() {
        for kind in 0..2 {
            let f = Fixture::new();
            let a = f.approval();
            assert!(apply_inner(&f.v, &f.dest, &f.state, &a, Fault::Boundary(1, 2)).is_err());
            if kind == 0 {
                let text = fs::read_to_string(f.state.join("journal.jsonl")).unwrap();
                let mut lines = text.lines().collect::<Vec<_>>();
                lines.swap(1, 4);
                fs::write(f.state.join("journal.jsonl"), lines.join("\n") + "\n").unwrap();
            } else {
                fs::write(f.state.join("agent-success"), b"ACCEPT").unwrap();
            }
            let before = f.snapshot();
            assert!(apply(&f.v, &f.dest, &f.state, &a).is_err());
            assert_eq!(f.snapshot(), before);
        }
    }
    #[test]
    #[ignore = "isolated subprocess helper; executed by abrupt_process_death_recovers_owned_prefix"]
    fn crash_child() {
        let root = PathBuf::from(std::env::var("REALM_ORDERED_TEST_ROOT").unwrap());
        let v = VerifiedCreateBatch {
            artifact: "a".repeat(64),
            run: "b".repeat(64),
            head: "c".repeat(64),
            semantic: "d".repeat(64),
            files: [
                b"def summarize(x): return x\n".to_vec(),
                b"from totals import summarize\n".to_vec(),
                b"assert True\n".to_vec(),
            ],
        };
        let dest = root.join("dest");
        let state = root.join("state");
        let a = preflight(&v, &dest).unwrap().approval_id().unwrap();
        let _ = apply(&v, &dest, &state, &a);
        panic!("crash hook was not reached");
    }
    #[test]
    fn abrupt_process_death_recovers_owned_prefix() {
        use std::os::unix::process::ExitStatusExt;
        for boundary in [2, 3, 4, 5, 6] {
            let f = Fixture::new();
            let a = f.approval();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "host_apply::ordered_create::tests::crash_child",
                    "--ignored",
                ])
                .env("REALM_ORDERED_TEST_ROOT", &f.root)
                .env("REALM_ORDERED_TEST_CRASH", format!("1:{boundary}"))
                .status()
                .unwrap();
            assert_eq!(status.signal(), Some(libc::SIGKILL));
            assert!(verify_host(&f.v, &f.dest, &f.state).is_err());
            let before = f.snapshot();
            assert!(apply(&f.v, &f.dest, &f.state, &a).unwrap().verified);
            assert_eq!(&f.snapshot()[..before.len()], before.as_slice());
        }
    }
}
