//! Native ownership of the finite planner/tool exchange. External proposals are
//! advisory. Only bytes read, validated, dispatched and durably recorded here
//! contribute to this capture; hidden planner inputs remain outside its scope.
use crate::{
    coding_submission::{CodingExecutionScope, SubmissionContract},
    measured_launch::FileIdentity,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};
const LIMIT: usize = 128 * 1024;
fn refuse(s: &str) -> io::Error {
    io::Error::other(s)
}
fn hash(v: &impl Serialize) -> io::Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(v)?).to_hex().to_string())
}
/// Configuration is a request, never a provenance capability. The native owner
/// verifies the executable object and the actual kernel peer before dispatch.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelayConfig {
    pub planner_socket: PathBuf,
    pub guest_hello: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    run_id: String,
    challenge: String,
    request_id: String,
    action: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    run_id: String,
    challenge: String,
    request_id: String,
    sequence: u64,
    authority: String,
    result: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    #[serde(default)]
    task_inputs_blake3: Option<String>,
    schema: String,
    authority: String,
    run_id: String,
    challenge: String,
    worker_sha256: String,
    protocol_sha256: String,
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn peer(s: &UnixStream) -> io::Result<(u32, u32, u32)> {
    let mut c: libc::ucred = unsafe { std::mem::zeroed() };
    let mut n = std::mem::size_of_val(&c) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut c as *mut libc::ucred).cast(),
            &mut n,
        )
    } != 0
        || n as usize != std::mem::size_of_val(&c)
        || c.pid <= 0
    {
        return Err(refuse("kernel peer unavailable"));
    }
    Ok((c.pid as u32, c.uid, c.gid))
}
fn poll_ready(fd: i32, event: i16, deadline: Instant) -> io::Result<()> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| refuse("native relay absolute deadline"))?;
    let mut p = libc::pollfd {
        fd,
        events: event,
        revents: 0,
    };
    if unsafe {
        libc::poll(
            &mut p,
            1,
            left.as_millis().max(1).min(i32::MAX as u128) as i32,
        )
    } <= 0
    {
        return Err(refuse("native relay absolute deadline or interrupted poll"));
    }
    Ok(())
}
fn nonblocking(fd: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn read_some(fd: i32, b: &mut [u8], deadline: Instant) -> io::Result<usize> {
    loop {
        poll_ready(fd, libc::POLLIN, deadline)?;
        let n = unsafe { libc::read(fd, b.as_mut_ptr().cast(), b.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if !matches!(
            e.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        ) {
            return Err(e);
        }
    }
}
fn exact(fd: i32, mut b: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !b.is_empty() {
        let n = read_some(fd, b, deadline)?;
        if n == 0 {
            return Err(refuse("short tool frame; dispatched outcome UNKNOWN"));
        }
        b = &mut b[n..];
    }
    Ok(())
}
fn write_all(fd: i32, mut b: &[u8], deadline: Instant) -> io::Result<()> {
    while !b.is_empty() {
        poll_ready(fd, libc::POLLOUT, deadline)?;
        let n = unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) };
        if n > 0 {
            b = &b[n as usize..];
        } else if n == 0 {
            return Err(refuse("zero native transport write"));
        } else {
            let e = io::Error::last_os_error();
            if !matches!(
                e.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                return Err(e);
            }
        }
    }
    Ok(())
}
fn bounded_line(fd: i32, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut block = [0; 4096];
    loop {
        let n = read_some(fd, &mut block, deadline)?;
        if n == 0 {
            return Err(refuse("relay EOF before complete response"));
        }
        line.extend_from_slice(&block[..n]);
        if line.len() > LIMIT {
            return Err(refuse("relay line bound"));
        }
        if let Some(at) = line.iter().position(|b| *b == b'\n') {
            if at + 1 != line.len() {
                return Err(refuse("unsolicited relay output"));
            }
            return Ok(line);
        }
    }
}
fn receive_captured(s: &mut UnixStream, deadline: Instant) -> io::Result<(Value, String)> {
    nonblocking(s.as_raw_fd())?;
    let mut n = [0; 4];
    exact(s.as_raw_fd(), &mut n, deadline)?;
    let n = u32::from_be_bytes(n) as usize;
    if n == 0 || n > LIMIT {
        return Err(refuse("tool frame bound"));
    }
    let mut b = vec![0; n];
    exact(s.as_raw_fd(), &mut b, deadline)?;
    let value = crate::strict_json::parse(&b).map_err(|_| refuse("strict tool JSON required"))?;
    Ok((
        value,
        String::from_utf8(b).map_err(|_| refuse("UTF-8 tool JSON required"))?,
    ))
}
fn send_deadline(s: &mut UnixStream, v: &Value, deadline: Instant) -> io::Result<()> {
    nonblocking(s.as_raw_fd())?;
    let b = serde_json::to_vec(v)?;
    if b.is_empty() || b.len() > LIMIT {
        return Err(refuse("tool frame bound"));
    }
    write_all(s.as_raw_fd(), &(b.len() as u32).to_be_bytes(), deadline)?;
    write_all(s.as_raw_fd(), &b, deadline)
}
#[cfg(test)]
fn receive(s: &mut UnixStream) -> io::Result<Value> {
    receive_captured(s, Instant::now() + Duration::from_secs(10)).map(|(v, _)| v)
}
#[cfg(test)]
fn send(s: &mut UnixStream, v: &Value) -> io::Result<()> {
    send_deadline(s, v, Instant::now() + Duration::from_secs(10))
}
fn accept(l: &UnixListener, deadline: Instant) -> io::Result<UnixStream> {
    l.set_nonblocking(true)?;
    loop {
        poll_ready(l.as_raw_fd(), libc::POLLIN, deadline)?;
        match l.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(true)?;
                return Ok(s);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
}
struct Controller {
    child: Child,
    input: Option<ChildStdin>,
    output: io::BufReader<ChildStdout>,
    binary: File,
    identity: FileIdentity,
}
impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Controller {
    fn start(b: &SubmissionContract) -> io::Result<Self> {
        // Open the kernel magic link directly: canonical pathname lookup could
        // select a replacement rather than this running native executable.
        let (binary, identity) =
            crate::runtime_admission::protected_running_supervisor().map_err(io::Error::other)?;
        Self::start_held(binary, Path::new(identity.path()), b)
    }
    fn start_held(binary: File, path: &Path, b: &SubmissionContract) -> io::Result<Self> {
        let identity = FileIdentity::measure_open_file(path, &binary)
            .map_err(|_| refuse("running native executable measurement"))?;
        let m = binary.metadata()?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 || m.mode() & 0o100 == 0 || m.nlink() != 1 {
            return Err(refuse("unprotected or unpinned relay executable"));
        }
        // Exec the held object, with no caller environment or inherited control FD.
        let mut child = Command::new(format!("/proc/self/fd/{}", binary.as_raw_fd()))
            .args(["--internal-coding-relay", &serde_json::to_string(b)?])
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let actual = FileIdentity::measure(&PathBuf::from(format!("/proc/{}/exe", child.id())))
            .map_err(|_| refuse("actual controller exec unavailable"));
        let actual = match actual {
            Ok(actual) => actual,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        if actual.device_inode() != identity.device_inode() || actual.blake3() != identity.blake3()
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse("actual relay executable differs"));
        }
        Ok(Self {
            input: child.stdin.take(),
            output: io::BufReader::new(child.stdout.take().ok_or_else(|| refuse("relay stdout"))?),
            child,
            binary,
            identity,
        })
    }
    fn dispatch(
        &mut self,
        b: &SubmissionContract,
        sequence: u64,
        action: &Value,
        deadline: Instant,
    ) -> io::Result<(Value, String, String)> {
        let bytes = serde_json::to_vec(&json!({"binding":b,"sequence":sequence,"request":action}))?;
        if bytes.len() + 1 > LIMIT {
            return Err(refuse("relay line bound"));
        }
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| refuse("relay already closed"))?;
        nonblocking(input.as_raw_fd())?;
        nonblocking(self.output.get_ref().as_raw_fd())?;
        write_all(input.as_raw_fd(), &bytes, deadline)?;
        write_all(input.as_raw_fd(), b"\n", deadline)?;
        let line = bounded_line(self.output.get_ref().as_raw_fd(), deadline)?;
        let value = crate::strict_json::parse(&line).map_err(|_| refuse("strict relay result"))?;
        let expected = json!({"binding":b,"sequence":sequence,"request":action,"policy":crate::controller_guard::POLICY,"policy_root":crate::controller_guard::policy_root(),"authority":"NONE","complete_observation_admission":"REFUSE"});
        if value != expected {
            return Err(refuse("relay result/binding/policy differs"));
        }
        Ok((
            value,
            String::from_utf8(bytes).map_err(|_| refuse("relay input UTF-8"))?,
            String::from_utf8(line).map_err(|_| refuse("relay result UTF-8"))?,
        ))
    }
    fn finish(&mut self, deadline: Instant) -> io::Result<()> {
        self.input.take();
        loop {
            if let Some(s) = self.child.try_wait()? {
                if !s.success() {
                    return Err(refuse("relay did not exit cleanly"));
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err(refuse("relay retirement deadline"));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let mut extra = [0; 1];
        if self.output.read(&mut extra)? != 0 {
            return Err(refuse("relay output after finish"));
        }
        let m = self.binary.metadata()?;
        if (m.dev(), m.ino()) != self.identity.device_inode() {
            return Err(refuse("relay object changed"));
        }
        Ok(())
    }
}
/// Native owner created before InstanceStart. No deserialization or detached
/// transcript can construct the completed capture.
pub(crate) struct NativeRelay {
    task_inputs: Option<crate::runtime_admission::inputs::OwnedTaskInputs>,
    config: RelayConfig,
    controller: Option<Controller>,
    measurement: String,
    scope: CodingExecutionScope,
    guest: UnixListener,
    local: UnixListener,
    journal: File,
    journal_path: PathBuf,
    vmm: (u32, u32, u32),
    deadline: Instant,
}
pub(crate) struct CapturedRelay {
    pub listener: UnixListener,
    pub stream: UnixStream,
    pub capture: RelayCapture,
}
pub(crate) struct RelayCapture {
    task_inputs: Option<crate::runtime_admission::inputs::OwnedTaskInputs>,
    measurement: String,
    vmm: (u32, u32, u32),
    scope: CodingExecutionScope,
    root: String,
    journal: File,
    path: PathBuf,
    object: (u64, u64),
    hello: Value,
    final_files: Value,
    controller: FileIdentity,
}
impl NativeRelay {
    pub(crate) fn prepare(
        c: RelayConfig,
        scope: &CodingExecutionScope,
        guest_path: &Path,
        state: &Path,
        measured: &crate::measured_launch::MeasuredLaunchSession,
        timeout: Duration,
    ) -> io::Result<Self> {
        let m = measured;
        if scope.submission.run_id != m.run_id()
            || scope.submission.execution_id != m.execution_id()
            || m.bound_challenge() != Some(scope.submission.challenge_root.as_str())
            || scope
                .policy_identity()
                .map_err(|_| refuse("prelaunch policy"))?
                != *m.policy_identity()
        {
            return Err(refuse(
                "native relay scope differs from actual measured launch",
            ));
        }
        Self::prepare_bound(
            c,
            scope,
            guest_path,
            state,
            (m.vmm().pid(), m.vmm().owner().0, m.vmm().owner().1),
            m.canonical_hash_blake3().into(),
            timeout,
            Controller::start(&scope.submission)?,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_bound(
        c: RelayConfig,
        scope: &CodingExecutionScope,
        guest_path: &Path,
        state: &Path,
        vmm: (u32, u32, u32),
        measurement: String,
        timeout: Duration,
        controller: Controller,
    ) -> io::Result<Self> {
        let hello: Hello = serde_json::from_value(c.guest_hello.clone())?;
        if hello.task_inputs_blake3 != scope.task_inputs_blake3
            || hello.schema != "realm.host-planned-coding-development.v1"
            || hello.authority != "NONE"
            || hello.worker_sha256 != scope.submission.worker_sha256
            || ![&hello.run_id, &hello.challenge, &hello.protocol_sha256]
                .into_iter()
                .all(|s| digest(s))
        {
            return Err(refuse("prelaunch tool hello differs"));
        }
        // The trusted root driver commits the guest protocol labels before VM
        // start. They cannot substitute for kernel peer or native run identity.
        if c.planner_socket.parent() != Some(state)
            || c.planner_socket.file_name() != Some(std::ffi::OsStr::new("planner.sock"))
        {
            return Err(refuse("planner socket outside private native state"));
        }
        let guest = UnixListener::bind(guest_path)?;
        let p = std::ffi::CString::new(guest_path.as_os_str().as_encoded_bytes())?;
        if unsafe { libc::chown(p.as_ptr(), vmm.1, vmm.2) } != 0 {
            return Err(io::Error::last_os_error());
        }
        fs::set_permissions(guest_path, fs::Permissions::from_mode(0o600))?;
        let local = UnixListener::bind(&c.planner_socket)?;
        fs::set_permissions(&c.planner_socket, fs::Permissions::from_mode(0o600))?;
        let journal_path = state.join("native-relay.jsonl");
        let journal = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&journal_path)?;
        journal.set_permissions(fs::Permissions::from_mode(0o600))?;
        File::open(state)?.sync_all()?;
        let mut this = Self {
            task_inputs: None,
            config: c,
            controller: Some(controller),
            measurement,
            scope: scope.clone(),
            guest,
            local,
            journal,
            journal_path,
            vmm,
            deadline: Instant::now() + timeout,
        };
        this.event(
            json!({"phase":"RELAY_PREPARED","measurement":this.measurement,"scope":this.scope,
            "vmm":this.vmm,"controller":this.controller.as_ref().unwrap().identity}),
        )?;
        Ok(this)
    }
    pub(crate) fn with_task_inputs(
        mut self,
        inputs: Option<crate::runtime_admission::inputs::OwnedTaskInputs>,
    ) -> io::Result<Self> {
        match (&inputs, &self.scope.task_inputs_blake3) {
            (None, None) => {}
            (Some(owner), Some(_)) if owner.data().matches_scope(&self.scope) => {
                owner.revalidate().map_err(|e| refuse(&e))?;
            }
            _ => return Err(refuse("relay lacks original task input descriptor")),
        }
        self.task_inputs = inputs;
        Ok(self)
    }
    fn event(&mut self, value: Value) -> io::Result<()> {
        self.journal.write_all(&serde_json::to_vec(&value)?)?;
        self.journal.write_all(b"\n")?;
        self.journal.sync_all()
    }
    pub(crate) fn run(mut self) -> io::Result<CapturedRelay> {
        let mut controller = self
            .controller
            .take()
            .ok_or_else(|| refuse("native controller already consumed"))?;
        let mut guest = accept(&self.guest, self.deadline)?;
        if peer(&guest)? != self.vmm {
            return Err(refuse("tool socket not connected by actual measured VMM"));
        }
        if let Some(inputs) = &self.task_inputs {
            inputs.revalidate().map_err(|e| refuse(&e))?;
            let bootstrap = json!({"root":inputs.root(),"inputs":inputs.data()});
            send_deadline(&mut guest, &bootstrap, self.deadline)?;
            self.event(json!({"phase":"TASK_INPUTS_SENT","bootstrap":bootstrap}))?;
        } else if self.scope.task_inputs_blake3.is_some() {
            return Err(refuse("missing original task input owner"));
        }
        let (hello, hello_raw) = receive_captured(&mut guest, self.deadline)?;
        if hello != self.config.guest_hello {
            return Err(refuse("actual guest hello differs"));
        }
        self.event(json!({"phase":"CONNECTED","scope":self.scope,"peer":self.vmm,"hello":hello,"hello_raw_json":hello_raw,"controller":controller.identity}))?;
        let mut seen = BTreeSet::new();
        for sequence in 1..=128u64 {
            let mut local = accept(&self.local, self.deadline)?;
            if peer(&local)?.1 != 0 {
                return Err(refuse("planner client must be root"));
            }
            let (proposal, proposal_raw) = receive_captured(&mut local, self.deadline)?;
            self.event(json!({"phase":"PROPOSAL_RECEIVED","raw_json":proposal_raw}))?;
            let p: Proposal = serde_json::from_value(proposal.clone())?;
            if p.run_id != hello["run_id"]
                || p.challenge != hello["challenge"]
                || !digest(&p.request_id)
                || !seen.insert(p.request_id.clone())
            {
                return Err(refuse("planner identity or replay differs"));
            }
            if self
                .scope
                .native_subtask
                .as_ref()
                .is_some_and(|s| !s.allows_action(&p.action))
            {
                return Err(refuse("action violates registered native subtask effects"));
            }
            // The actual restricted executable validates this action. No guest
            // dispatch happens if its child exits or refuses an intermediate tool.
            let (relay, relay_input, relay_output) = controller.dispatch(
                &self.scope.submission,
                sequence - 1,
                &p.action,
                self.deadline,
            )?;
            let message = json!({"run_id":p.run_id,"challenge":p.challenge,"request_id":p.request_id,"sequence":sequence,"action":relay["request"]});
            self.event(json!({"phase":"DISPATCH_INTENT","proposal":proposal,"relay":relay,"relay_input_json":relay_input,"relay_output_json":relay_output,"message":message}))?;
            send_deadline(&mut guest, &message, self.deadline)?;
            // Any error after intent is an ambiguous effect and yields no seal.
            let (reply, reply_raw) = receive_captured(&mut guest, self.deadline)?;
            self.event(json!({"phase":"RESULT_RECEIVED","raw_json":reply_raw}))?;
            let r: Reply = serde_json::from_value(reply.clone())?;
            if r.run_id != p.run_id
                || r.challenge != p.challenge
                || r.request_id != p.request_id
                || r.sequence != sequence
                || r.authority != "NONE"
            {
                return Err(refuse("actual guest reply binding differs; effect UNKNOWN"));
            }
            self.event(json!({"phase":"GUEST_REPLY","reply":reply,"raw_json":reply_raw}))?;
            send_deadline(&mut local, &reply, self.deadline)?;
            if p.action["tool"] == "finish" {
                if r.result["status"] != "DEVELOPMENT_TASK_CHECKED" {
                    return Err(refuse("finish did not complete"));
                }
                controller.finish(self.deadline)?;
                // Require actual peer EOF before handing ownership to the
                // existing channel revoker (which independently checks EOF).
                let mut extra = [0; 1];
                if read_some(guest.as_raw_fd(), &mut extra, self.deadline)? != 0 {
                    return Err(refuse("tool traffic after finish"));
                }
                self.event(json!({"phase":"RELAY_CLOSED","controller":controller.identity}))?;
                drop(self.local);
                fs::remove_file(&self.config.planner_socket)?;
                File::open(self.journal_path.parent().unwrap())?.sync_all()?;
                let m = self.journal.metadata()?;
                let root = journal_digest(&self.journal)?;
                return Ok(CapturedRelay {
                    listener: self.guest,
                    stream: guest,
                    capture: RelayCapture {
                        task_inputs: self.task_inputs,
                        measurement: self.measurement,
                        vmm: self.vmm,
                        scope: self.scope,
                        root,
                        journal: self.journal,
                        path: self.journal_path,
                        object: (m.dev(), m.ino()),
                        hello,
                        final_files: r.result["files"].clone(),
                        controller: controller.identity.clone(),
                    },
                });
            }
        }
        Err(refuse("tool request count exhausted"))
    }
}
fn journal_digest(file: &File) -> io::Result<String> {
    use std::os::unix::fs::FileExt;
    let mut at = 0;
    let mut h = blake3::Hasher::new();
    let mut b = [0; 8192];
    loop {
        let n = file.read_at(&mut b, at)?;
        if n == 0 {
            break;
        }
        at += n as u64;
        if at > 40 * 1024 * 1024 {
            return Err(refuse("relay journal bound"));
        }
        h.update(&b[..n]);
    }
    Ok(h.finalize().to_hex().to_string())
}
impl RelayCapture {
    pub(crate) fn controller_identity(&self) -> &FileIdentity {
        &self.controller
    }
    pub(crate) fn matches_native(&self, m: &crate::measured_launch::MeasuredLaunchSession) -> bool {
        self.measurement == m.prepared_measurement_root()
            && self.vmm == (m.vmm().pid(), m.vmm().owner().0, m.vmm().owner().1)
    }
    pub(crate) fn revalidate(&self) -> io::Result<()> {
        if let Some(inputs) = &self.task_inputs {
            inputs.revalidate().map_err(|e| refuse(&e))?;
        }

        let m = self.journal.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        if (m.dev(), m.ino()) != self.object
            || (named.dev(), named.ino()) != self.object
            || m.nlink() != 1
            || m.uid() != 0
            || m.mode() & 0o7777 != 0o600
            || journal_digest(&self.journal)? != self.root
        {
            return Err(refuse("original relay journal changed"));
        }
        Ok(())
    }
    pub(crate) fn verify(
        &self,
        scope: &CodingExecutionScope,
        packet: &[u8],
        referee: &(impl crate::coding_referee::NativeRefereeEvidence + ?Sized),
    ) -> io::Result<String> {
        self.verify_subject(scope, packet, &referee.diagnostic()["result"]["subject"])
    }
    pub(crate) fn verify_refusal(
        &self,
        scope: &CodingExecutionScope,
        packet: &[u8],
        referee: &crate::coding_referee::OwnedCodingTaskRefusal,
    ) -> io::Result<String> {
        self.verify_subject(scope, packet, &referee.diagnostic()["result"]["subject"])
    }
    fn verify_subject(
        &self,
        scope: &CodingExecutionScope,
        packet: &[u8],
        subject: &Value,
    ) -> io::Result<String> {
        if let Some(inputs) = &self.task_inputs {
            inputs.revalidate().map_err(|e| refuse(&e))?;
        }
        let m = self.journal.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        if self.scope != *scope
            || (m.dev(), m.ino()) != self.object
            || (named.dev(), named.ino()) != self.object
            || m.nlink() != 1
            || m.uid() != 0
            || m.mode() & 0o7777 != 0o600
            || journal_digest(&self.journal)? != self.root
        {
            return Err(refuse("original relay journal/scope changed"));
        }
        let packet = scope.submission.decode(packet).map_err(refuse)?;
        let expected: serde_json::Map<String, Value> = packet
            .files
            .iter()
            .map(|f| (f.path.clone(), subject[&f.path]["sha256"].clone()))
            .collect();
        if self.final_files != Value::Object(expected) {
            return Err(refuse(
                "observed finish files differ from native custody packet",
            ));
        }
        hash(&(
            "realm.native-tool-capture/v1",
            &self.scope,
            &self.measurement,
            &self.vmm,
            &self.root,
            &self.hello,
            &self.controller,
            &self.final_files,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_input_frame_roundtrip_preserves_original_sealed_bundle() {
        let owner = crate::runtime_admission::inputs::tests::local_owner();
        let (mut tx, mut rx) = UnixStream::pair().unwrap();
        let sent = json!({"root":owner.root(),"inputs":owner.data()});
        send_deadline(&mut tx, &sent, Instant::now() + Duration::from_secs(1)).unwrap();
        let (received, raw) =
            receive_captured(&mut rx, Instant::now() + Duration::from_secs(1)).unwrap();
        assert_eq!(received, sent);
        assert!(!raw.is_empty());
        owner.revalidate().unwrap();
        let parsed: crate::runtime_admission::inputs::NativeTaskInputs =
            serde_json::from_value(received["inputs"].clone()).unwrap();
        assert_eq!(parsed.root().unwrap(), owner.root());
        let mut changed = received;
        changed["inputs"]["submission"]["run_id"] = json!("f".repeat(64));
        let parsed: crate::runtime_admission::inputs::NativeTaskInputs =
            serde_json::from_value(changed["inputs"].clone()).unwrap();
        assert_ne!(parsed.root().unwrap(), owner.root());
    }
    #[test]
    fn partial_frames_lines_and_full_pipe_obey_absolute_deadline() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(&20u32.to_be_bytes()).unwrap();
        writer.write_all(b"{").unwrap();
        let start = Instant::now();
        assert!(receive_captured(&mut reader, start + Duration::from_millis(60)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        let mut raw = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(raw.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) },
            0
        );
        use std::os::fd::{FromRawFd, OwnedFd};
        let rd = unsafe { OwnedFd::from_raw_fd(raw[0]) };
        let wr = unsafe { OwnedFd::from_raw_fd(raw[1]) };
        assert_eq!(
            unsafe { libc::write(wr.as_raw_fd(), b"{".as_ptr().cast(), 1) },
            1
        );
        let start = Instant::now();
        assert!(bounded_line(rd.as_raw_fd(), start + Duration::from_millis(60)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        let b = [0u8; 4096];
        loop {
            let n = unsafe { libc::write(wr.as_raw_fd(), b.as_ptr().cast(), b.len()) };
            if n < 0 {
                assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
                break;
            }
        }
        let start = Instant::now();
        assert!(write_all(wr.as_raw_fd(), b"x", start + Duration::from_millis(60)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    /// Actual seccomp relay child + Unix streams. These are host-process
    /// mechanics, not a VM run or a production provenance constructor.
    #[test]
    #[ignore = "requires root Linux and REALM_TEST_CONTROLLER actual built binary"]
    fn actual_controller_and_native_socket_owner() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let source = PathBuf::from(
            std::env::var("REALM_TEST_CONTROLLER").expect("build the real controller first"),
        );
        for case in [
            "complete",
            "path-replacement",
            "unauthorized",
            "reply-substitution",
            "replay",
            "trailing",
        ] {
            let root = PathBuf::from(format!(
                "/root/realm-native-relay-{}-{case}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let binary = root.join("controller");
            fs::copy(&source, &binary).unwrap();
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o500)).unwrap();
            assert!(
                FileIdentity::measure(&binary)
                    .unwrap()
                    .trusted_parent_chain()
            );
            let held = File::open(&binary).unwrap();
            if case == "path-replacement" {
                fs::rename(&binary, root.join("original-native-elf")).unwrap();
                fs::write(&binary, b"unapproved replacement, never executable").unwrap();
                fs::set_permissions(&binary, fs::Permissions::from_mode(0o500)).unwrap();
            }
            let binding = SubmissionContract {
                run_id: "a".repeat(64),
                execution_id: "b".repeat(64),
                challenge_root: "c".repeat(64),
                task_sha256: "d".repeat(64),
                worker_sha256: "e".repeat(64),
            };
            let scope = CodingExecutionScope {
                submission: binding,
                source_commit: "f".repeat(40),
                checker_sha256: "1".repeat(64),
                checker_scope_sha256: "2".repeat(64),
                runtime_admission_id: None,
                native_subtask: None,
                task_inputs_blake3: None,
            };
            let hello = json!({"schema":"realm.host-planned-coding-development.v1","authority":"NONE","run_id":"3".repeat(64),"challenge":"4".repeat(64),"worker_sha256":scope.submission.worker_sha256,"protocol_sha256":"5".repeat(64)});
            let local = root.join("planner.sock");
            let guest_path = root.join("guest.sock");
            let relay = NativeRelay::prepare_bound(
                RelayConfig {
                    planner_socket: local.clone(),
                    guest_hello: hello.clone(),
                },
                &scope,
                &guest_path,
                &root,
                (std::process::id(), 0, 0),
                "test-host-process-not-vmm".into(),
                Duration::from_secs(10),
                Controller::start_held(held, &binary, &scope.submission).unwrap(),
            )
            .unwrap();
            let handle = std::thread::spawn(move || relay.run());
            let mut guest = UnixStream::connect(&guest_path).unwrap();
            guest
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            send(&mut guest, &hello).unwrap();
            let mut count = 0;
            let ok = loop {
                count += 1;
                let tool = if case == "unauthorized" && count == 2 {
                    json!({"tool":"read","path":"/etc/passwd"})
                } else if matches!(case, "complete" | "path-replacement" | "trailing") {
                    json!({"tool":"finish"})
                } else {
                    json!({"tool":"list"})
                };
                let request_id = if case == "replay" {
                    "6".repeat(64)
                } else {
                    format!("{count:064x}")
                };
                let mut client = UnixStream::connect(&local).unwrap();
                client
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                send(&mut client,&json!({"run_id":hello["run_id"],"challenge":hello["challenge"],"request_id":request_id,"action":tool})).unwrap();
                if (case == "unauthorized" || case == "replay") && count == 2 {
                    assert!(
                        receive(&mut guest).is_err(),
                        "unauthorized/replayed action reached guest"
                    );
                    break false;
                }
                let message = receive(&mut guest).unwrap();
                assert_eq!(message["action"], tool);
                let result = if tool["tool"] == "finish" {
                    json!({"status":"DEVELOPMENT_TASK_CHECKED","files":{}})
                } else {
                    json!({"status":"LISTED"})
                };
                let mut reply = json!({"run_id":hello["run_id"],"challenge":hello["challenge"],"request_id":request_id,"sequence":count,"authority":"NONE","result":result});
                if case == "reply-substitution" {
                    reply["request_id"] = json!("7".repeat(64));
                }
                send(&mut guest, &reply).unwrap();
                if case == "reply-substitution" {
                    assert!(receive(&mut client).is_err());
                    break false;
                }
                assert_eq!(receive(&mut client).unwrap(), reply);
                if tool["tool"] == "finish" {
                    if case == "trailing" {
                        guest.write_all(b"x").unwrap();
                    }
                    guest.shutdown(std::net::Shutdown::Write).unwrap();
                    break matches!(case, "complete" | "path-replacement");
                }
            };
            let completed = handle.join().unwrap();
            assert_eq!(completed.is_ok(), ok, "{case}");
            if let Ok(captured) = completed {
                captured.capture.revalidate().unwrap();
                OpenOptions::new()
                    .append(true)
                    .open(root.join("native-relay.jsonl"))
                    .unwrap()
                    .write_all(b"{}\n")
                    .unwrap();
                assert!(
                    captured.capture.revalidate().is_err(),
                    "changed original journal accepted"
                );
            } else {
                let journal = fs::read_to_string(root.join("native-relay.jsonl")).unwrap();
                assert!(!journal.contains("RELAY_CLOSED"));
                if case == "unauthorized" || case == "replay" {
                    assert_eq!(journal.matches("DISPATCH_INTENT").count(), 1);
                }
            }
            fs::remove_dir_all(root).unwrap();
        }
    }
}
