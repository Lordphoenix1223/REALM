//! Owned finite-task checker evidence. Only actual closed native custody and an
//! owned checker child can construct this value. It is NOT same-run authority:
//! host runtime qualification, coding mediation and controller scope remain gates.
use crate::{coding_submission::SubmissionContract, execute::CheckedC1Evidence};

/// Exact sources materialized for the independently owned referee. This is
/// public source data, never an execution or admission capability. Keep the
/// verifier materialization and runtime tuple validation on the same catalog.
pub const COMPILED_SOURCES: [(&str, &[u8]); 4] = [
    (
        "coding_task_verifier.py",
        include_bytes!("../../../scripts/v7/coding_task_verifier.py"),
    ),
    (
        "coding_worker.py",
        include_bytes!("../../../scripts/v7/coding_worker.py"),
    ),
    (
        "candidate_channel_guard.py",
        include_bytes!("../../../scripts/v7/candidate_channel_guard.py"),
    ),
    (
        "development_task_oracles.py",
        include_bytes!("../../../scripts/v7/development_task_oracles.py"),
    ),
];

/// No public constructor, Clone or deserializer; a standalone PASS JSON is not
/// this value. Its constructor requires actual Linux/x86 run-owned custody and
/// cgroup child birth; full runtime/controller profile qualification is separate.
/// ```compile_fail
/// let check: realm_v6::coding_referee::OwnedCodingTaskCheck =
///     serde_json::from_str("{}").unwrap();
/// ```
pub struct OwnedCodingTaskCheck {
    binding: SubmissionContract,
    packet_root: String,
    source_commit: String,
    custody_root: String,
    broker_completion_root: String,
    request_root: String,
    root: String,
    identity_record: serde_json::Value,
    diagnostic: serde_json::Value,
}
/// A real owned referee's semantic rejection after a normal exit and original
/// request/subject revalidation. No constructor, deserializer or conversion to
/// OwnedCodingTaskCheck. This is not admission, success or retry permission.
/// ```compile_fail
/// let _: realm_v6::coding_referee::OwnedCodingTaskRefusal = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// fn promote(x: realm_v6::coding_referee::OwnedCodingTaskRefusal)
///     -> realm_v6::coding_referee::OwnedCodingTaskCheck { x }
/// ```
pub struct OwnedCodingTaskRefusal {
    binding: SubmissionContract,
    packet_root: String,
    source_commit: String,
    custody_root: String,
    broker_completion_root: String,
    root: String,
    identity_record: serde_json::Value,
    diagnostic: serde_json::Value,
    #[cfg(target_os = "linux")]
    closed_process: crate::run_closure::linux::RunOwnedChildExit,
}
/// Original native API-child success, deliberately not a whole-task owner.
/// ```compile_fail
/// fn promote(x: realm_v6::coding_referee::OwnedNativeApiCheck)
///     -> realm_v6::coding_referee::OwnedCodingTaskCheck { x.inner }
/// ```
pub struct OwnedNativeApiCheck {
    inner: OwnedCodingTaskCheck,
}
impl OwnedNativeApiCheck {
    #[cfg(target_os = "linux")]
    pub(crate) fn view(&self) -> &OwnedCodingTaskCheck {
        &self.inner
    }
    pub fn root(&self) -> &str {
        self.inner.root()
    }
    pub fn diagnostic(&self) -> &serde_json::Value {
        self.inner.diagnostic()
    }
    pub fn identity_record(&self) -> &serde_json::Value {
        self.inner.identity_record()
    }
}
/// An observation must come from the original native child, never decoded data.
/// ```compile_fail
/// let _: realm_v6::coding_referee::OwnedCodingTaskOutcome = serde_json::from_str("{}").unwrap();
/// ```
pub enum OwnedCodingTaskOutcome {
    Passed(OwnedCodingTaskCheck),
    ApiPassed(OwnedNativeApiCheck),
    Refused(OwnedCodingTaskRefusal),
}
impl OwnedCodingTaskRefusal {
    pub fn binding(&self) -> &SubmissionContract {
        &self.binding
    }
    pub fn packet_root(&self) -> &str {
        &self.packet_root
    }
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }
    pub fn custody_root(&self) -> &str {
        &self.custody_root
    }
    pub fn broker_completion_root(&self) -> &str {
        &self.broker_completion_root
    }
    pub fn root(&self) -> &str {
        &self.root
    }
    pub fn diagnostic(&self) -> &serde_json::Value {
        &self.diagnostic
    }
    pub fn identity_record(&self) -> &serde_json::Value {
        &self.identity_record
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn native_binding(
        &self,
        scope: &crate::coding_submission::CodingExecutionScope,
        packet: &[u8],
        custody: &str,
        broker: &str,
    ) -> bool {
        serde_json::to_vec(&self.identity_record)
            .is_ok_and(|bytes| blake3::hash(&bytes).to_hex().as_str() == self.root)
            && self.closed_process.exit_code() == 2
            && self.binding == scope.submission
            && self.source_commit == scope.source_commit
            && self.packet_root == blake3::hash(packet).to_hex().as_str()
            && self.custody_root == custody
            && self.broker_completion_root == broker
            && self.diagnostic["result"]["scope_sha256"] == scope.checker_scope_sha256
    }
}

impl OwnedCodingTaskCheck {
    pub fn root(&self) -> &str {
        &self.root
    }
    pub fn diagnostic(&self) -> &serde_json::Value {
        &self.diagnostic
    }
    /// Original native-generated commitment material, retained for independent
    /// inspection. Exporting it does not reconstruct this opaque owner.
    pub fn identity_record(&self) -> &serde_json::Value {
        &self.identity_record
    }
    fn identity_record_matches(&self) -> bool {
        serde_json::to_vec(&self.identity_record)
            .is_ok_and(|bytes| blake3::hash(&bytes).to_hex().as_str() == self.root)
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn native_binding(
        &self,
        scope: &crate::coding_submission::CodingExecutionScope,
        packet: &[u8],
        custody: &str,
        broker: &str,
    ) -> bool {
        self.identity_record_matches()
            && self.binding == scope.submission
            && self.source_commit == scope.source_commit
            && self.packet_root == blake3::hash(packet).to_hex().as_str()
            && self.custody_root == custody
            && self.broker_completion_root == broker
            && self.diagnostic["result"]["scope_sha256"] == scope.checker_scope_sha256
            && self.diagnostic["result"]["scope"]["checker_sha256"] == scope.checker_sha256
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn request_root(&self) -> &str {
        &self.request_root
    }
    pub(crate) fn matches(&self, evidence: &CheckedC1Evidence) -> bool {
        evidence.coding.as_ref().is_some_and(|c| {
            self.identity_record_matches()
                && self.binding == c.contract.submission
                && self.source_commit == c.contract.source_commit
                && self.packet_root == blake3::hash(&c.submission).to_hex().to_string()
                && c.semantic_evidence.as_ref().is_some_and(|semantic| {
                    semantic.matches_data(c)
                        && semantic.referee_identity_record.as_ref() == Some(&self.identity_record)
                        && semantic.referee_root == self.root
                        && semantic.custody_root == self.custody_root
                        && semantic.broker_completion_root == self.broker_completion_root
                        && semantic.consumed_request_blake3 == self.request_root
                })
        })
    }
}

// Read-only internal view of an ORIGINAL owned referee; never a constructor.
// Whole-task finalization still consumes OwnedCodingTaskCheck by value.
#[cfg(target_os = "linux")]
pub(crate) trait NativeRefereeEvidence {
    fn root(&self) -> &str;
    fn request_root(&self) -> &str;
    fn identity_record(&self) -> &serde_json::Value;
    fn diagnostic(&self) -> &serde_json::Value;
    fn native_binding(
        &self,
        scope: &crate::coding_submission::CodingExecutionScope,
        packet: &[u8],
        custody: &str,
        broker: &str,
    ) -> bool;
}
#[cfg(target_os = "linux")]
impl NativeRefereeEvidence for OwnedCodingTaskCheck {
    fn root(&self) -> &str {
        self.root()
    }
    fn request_root(&self) -> &str {
        self.request_root()
    }
    fn identity_record(&self) -> &serde_json::Value {
        self.identity_record()
    }
    fn diagnostic(&self) -> &serde_json::Value {
        self.diagnostic()
    }
    fn native_binding(
        &self,
        s: &crate::coding_submission::CodingExecutionScope,
        p: &[u8],
        c: &str,
        b: &str,
    ) -> bool {
        self.native_binding(s, p, c, b)
    }
}
#[cfg(target_os = "linux")]
impl NativeRefereeEvidence for OwnedNativeApiCheck {
    fn root(&self) -> &str {
        self.root()
    }
    fn request_root(&self) -> &str {
        self.identity_record()["request_blake3"]
            .as_str()
            .unwrap_or("")
    }
    fn identity_record(&self) -> &serde_json::Value {
        self.identity_record()
    }
    fn diagnostic(&self) -> &serde_json::Value {
        self.diagnostic()
    }
    fn native_binding(
        &self,
        s: &crate::coding_submission::CodingExecutionScope,
        p: &[u8],
        c: &str,
        b: &str,
    ) -> bool {
        self.inner.native_binding(s, p, c, b)
    }
}
#[cfg(target_os = "linux")]
impl NativeRefereeEvidence for OwnedCodingTaskRefusal {
    fn root(&self) -> &str {
        self.root()
    }
    fn request_root(&self) -> &str {
        self.identity_record()["request_blake3"]
            .as_str()
            .unwrap_or("")
    }
    fn identity_record(&self) -> &serde_json::Value {
        self.identity_record()
    }
    fn diagnostic(&self) -> &serde_json::Value {
        self.diagnostic()
    }
    fn native_binding(
        &self,
        s: &crate::coding_submission::CodingExecutionScope,
        p: &[u8],
        c: &str,
        b: &str,
    ) -> bool {
        self.native_binding(s, p, c, b)
    }
}

// Content validation is only one prerequisite after actual owned child exit.
// These bytes can never construct OwnedCodingTaskCheck on their own.
#[cfg(any(target_os = "linux", test))]
fn response_result<'a>(
    v: &'a serde_json::Value,
    request: &[u8],
) -> Result<&'a serde_json::Value, &'static str> {
    let fields = v.as_object().ok_or("response must be an object")?;
    let expected_hex: String = request.iter().map(|b| format!("{b:02x}")).collect();
    if fields.len() != 3
        || v["schema"] != "realm.owned-coding-referee-response.v1"
        || v["request_hex"] != expected_hex
        || !fields.contains_key("result")
    {
        return Err("response shape or exact consumed request differs");
    }
    Ok(&v["result"])
}
#[cfg(target_os = "linux")]
pub(crate) mod native {
    use super::*;
    use crate::{
        coding_custody::ClosedCodingCustody, execute::ExecuteError, measured_launch::FileIdentity,
        run_closure::linux::ChildLaunch, supervisor::CodingAuxiliaryClosed,
    };
    use std::{
        ffi::OsStr,
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        time::Duration,
    };

    fn bad(s: impl std::fmt::Debug) -> ExecuteError {
        ExecuteError::Supervisor(format!("owned coding referee refused: {s:?}"))
    }
    fn protected(path: &Path) -> Result<FileIdentity, ExecuteError> {
        let identity = FileIdentity::measure(path).map_err(bad)?;
        if identity.owner() != (0, 0)
            || !identity.trusted_parent_chain()
            || identity.mode() & 0o022 != 0
        {
            return Err(bad("checker runtime/source is not root protected"));
        }
        Ok(identity)
    }
    fn create(path: &Path, bytes: &[u8]) -> Result<File, ExecuteError> {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(bytes)?;
        f.sync_all()?;
        f.seek(SeekFrom::Start(0))?;
        Ok(f)
    }
    const DRIVER: &str = r#"import json,sys,pathlib,shutil,os
os.environ.clear();os.environ.update(PATH='/usr/bin:/bin',LC_ALL='C')
root=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(root/'source'))
import coding_task_verifier as r
import coding_worker as w
raw=sys.stdin.buffer.read(1024*1024+1)
q=r.owned_request(raw,root/'candidate')
if str(pathlib.Path(shutil.which('bwrap')).resolve()) != sys.argv[2]: raise ValueError('bwrap identity differs')
api=q['scope'].get('native_subtask',{}).get('role')=='api'
scope=w.digest(w.encoded(r.native_api_scope() if api else r.describe()))
v=r.verify_native_api(root/'candidate',root/'observations',scope,q['seed'],packet_bytes=len(bytes.fromhex(q['packet_hex']))) if api else r.verify(root/'candidate',root/'observations',scope,q['seed'])
print(w.encoded({'schema':'realm.owned-coding-referee-response.v1','request_hex':raw.hex(),'result':v}).decode())
if v['status'] not in ('PASS_BOUNDED_PROPERTIES','PASS_API_SUBTASK'):sys.exit(2)
"#;

    pub(crate) fn verify(
        closed: &CodingAuxiliaryClosed,
        custody: &ClosedCodingCustody,
        python: &Path,
    ) -> Result<OwnedCodingTaskCheck, ExecuteError> {
        match observe(closed, custody, python)? {
            OwnedCodingTaskOutcome::Passed(check) => Ok(check),
            OwnedCodingTaskOutcome::ApiPassed(_) => {
                Err(bad("API-only ownership cannot satisfy a whole-task check"))
            }
            OwnedCodingTaskOutcome::Refused(_) => {
                Err(bad("owned referee rejected finite predicate"))
            }
        }
    }

    pub(crate) fn observe(
        closed: &CodingAuxiliaryClosed,
        custody: &ClosedCodingCustody,
        python: &Path,
    ) -> Result<OwnedCodingTaskOutcome, ExecuteError> {
        if std::env::consts::ARCH != "x86_64" || unsafe { libc::geteuid() } != 0 {
            return Err(bad(
                "requires root Linux x86_64 and actual delegated run cgroup",
            ));
        }
        let (scope, packet, custody_root, broker_completion_root) =
            custody.referee_inputs(closed).map_err(bad)?;
        scope.validate().map_err(bad)?;
        let binding = scope.submission.clone();
        let submission = binding.decode(&packet).map_err(bad)?;
        let python = python.canonicalize()?;
        let python_id = protected(&python)?;
        let bwrap = Path::new("/usr/bin/bwrap").canonicalize()?;
        let bwrap_id = protected(&bwrap)?;
        let live = closed.rootfs_launch();
        let root = live.state().join("owned-coding-referee");
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        if !crate::supervisor::directory_is_trusted(&root).map_err(bad)? {
            return Err(bad("checker directory/parent chain is not protected"));
        }
        let source = root.join("source");
        fs::create_dir(&source)?;
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700))?;
        let mut pins: Vec<(PathBuf, FileIdentity)> = Vec::new();
        for (name, bytes) in super::COMPILED_SOURCES {
            let path = source.join(name);
            drop(create(&path, bytes)?);
            pins.push((path.clone(), protected(&path)?));
        }
        File::open(&source)?.sync_all()?;
        // Parent creates and retains every original subject descriptor before
        // the helper exists. Neither child PASS nor its reported hashes decide
        // whether it checked the bytes from this actual closed custody packet.
        let candidate = root.join("candidate");
        fs::create_dir(&candidate)?;
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))?;
        let mut subjects = Vec::new();
        for item in &submission.files {
            let path = candidate.join(&item.path);
            let held = create(&path, item.text.as_bytes())?;
            let identity = crate::coding_submission::custody_files::object(&held)?;
            subjects.push((path, held, identity, item.text.as_bytes()));
        }
        File::open(&candidate)?.sync_all()?;
        let mut entropy = [0u8; 8];
        File::open("/dev/urandom")?.read_exact(&mut entropy)?;
        let seed = u64::from_le_bytes(entropy);
        // A fresh u64 seed is represented exactly by both JSON implementations.
        let packet_hex = packet
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let request = format!(
            "{{\"schema\":\"realm.owned-coding-referee-request.v2\",\"scope\":{},\"binding\":{},\"packet_hex\":{},\"seed\":{seed}}}",
            serde_json::to_string(&scope).map_err(bad)?,
            serde_json::to_string(&binding).map_err(bad)?,
            serde_json::to_string(&packet_hex).map_err(bad)?
        );
        let mut stdin = create(&root.join("request.json"), request.as_bytes())?;
        let input_id = crate::coding_submission::custody_files::object(&stdin)?;
        let mut stdout = create(&root.join("stdout.json"), b"")?;
        let stderr = create(&root.join("stderr.txt"), b"")?;
        File::open(&root)?.sync_all()?;
        let args = [
            OsStr::new("-I"),
            OsStr::new("-S"),
            OsStr::new("-B"),
            OsStr::new("-c"),
            OsStr::new(DRIVER),
            root.as_os_str(),
            bwrap.as_os_str(),
        ];
        let child = live
            .cgroup()
            .spawn_owned_with_fds(
                ChildLaunch {
                    program: &python,
                    arguments: &args,
                    working_directory: &root,
                    stdin: &stdin,
                    stdout: &stdout,
                    stderr: &stderr,
                },
                &[],
            )
            .map_err(bad)?;
        let incarnation_valid = crate::measured_launch::VmmIncarnation::capture_linux(
            child.pid() as u32
        )
        .is_ok_and(|incarnation| {
            incarnation.start_time_ticks() == child.identity().start_ticks()
                && incarnation.owner() == (0, 0)
                && incarnation.executable_identity().blake3() == python_id.blake3()
        });
        // Observe normal nonzero exit only as potential refusal. Timeout,
        // signal or unknown wait is still an error, never a completed attempt.
        let child_exit = child.wait_observed(Duration::from_secs(120)).map_err(bad)?;
        let process = child_exit.identity();
        if !incarnation_valid {
            return Err(bad("checker child birth/runtime identity differs"));
        }
        closed.revalidate().map_err(bad)?;
        for (path, before) in pins
            .iter()
            .map(|(p, i)| (p.as_path(), i))
            .chain([(python.as_path(), &python_id), (bwrap.as_path(), &bwrap_id)])
        {
            if protected(path)? != *before {
                return Err(bad("checker runtime/source changed"));
            }
        }
        let id = crate::coding_submission::custody_files::object(&stdout)?;
        let raw = crate::coding_submission::custody_files::read_original(
            &mut stdout,
            &root.join("stdout.json"),
            &id,
            (0, 0),
            1024 * 1024,
        )?;
        let input_after = crate::coding_submission::custody_files::read_original(
            &mut stdin,
            &root.join("request.json"),
            &input_id,
            (0, 0),
            1024 * 1024,
        )?;
        if input_after != request.as_bytes() {
            return Err(bad("checker request changed"));
        }
        for (path, held, identity, expected) in &mut subjects {
            let actual = crate::coding_submission::custody_files::read_original(
                held,
                path,
                identity,
                (0, 0),
                crate::coding_submission::MAX_FILE,
            )?;
            if actual != *expected {
                return Err(bad("checker subject differs from original closed packet"));
            }
        }
        let envelope = crate::strict_json::parse(&raw).map_err(bad)?;
        let result = super::response_result(&envelope, request.as_bytes()).map_err(bad)?;
        if result["seed"].as_u64() != Some(seed)
            || result["scope"]["checker_sha256"] != scope.checker_sha256
            || result["scope_sha256"] != scope.checker_scope_sha256
        {
            return Err(bad("task/source/seed identity differs"));
        }
        let api = scope
            .native_subtask
            .as_ref()
            .is_some_and(|s| s.role == crate::native_workflow::NativeTaskRole::Api);
        let outcome = if api {
            classify_api_result(result, &binding, child_exit.exit_code())
        } else {
            classify_observed_result(result, &binding, child_exit.exit_code())
        }
        .ok_or_else(|| bad("exit/result mismatch or incomplete owned observation"))?;
        let packet_root = blake3::hash(&packet).to_hex().to_string();
        let mut identity_record = serde_json::json!({
            "domain":if outcome { if api { "realm.owned-native-api-check/v1" } else { "realm.owned-coding-task-check/v2" } } else { "realm.owned-coding-task-refusal/v1" },"prelaunch_scope":scope,"binding":binding,"packet":packet_root,
            "native_custody":custody_root,"broker_completion":broker_completion_root,"measurement":closed.measurement().canonical_hash_blake3(),
            "barrier":closed.barrier_root().map_err(bad)?,"process":process,
            "python":python_id,"bwrap":bwrap_id,"sources":pins,
            "request_blake3":blake3::hash(request.as_bytes()).to_hex().to_string(),
            "subject_packet_blake3":packet_root, "seed":seed.to_string(),"result_blake3":blake3::hash(&raw).to_hex().to_string()
        });
        if !outcome {
            identity_record["child_exit_code"] = child_exit.exit_code().into();
        }
        let root_hash = blake3::hash(&serde_json::to_vec(&identity_record).map_err(bad)?)
            .to_hex()
            .to_string();
        if !outcome {
            return Ok(OwnedCodingTaskOutcome::Refused(OwnedCodingTaskRefusal {
                binding,
                packet_root,
                source_commit: scope.source_commit,
                custody_root,
                broker_completion_root,
                root: root_hash,
                identity_record,
                diagnostic: serde_json::json!({"finite_check":"OWNED_CHILD_REFUSED_SEMANTIC_PREDICATE", "process":process,
                    "result":result,"authority":"NONE","retry_authorization":"NONE"}),
                closed_process: child_exit,
            }));
        }
        let check = OwnedCodingTaskCheck {
            binding,
            packet_root,
            source_commit: scope.source_commit,
            custody_root,
            broker_completion_root,
            request_root: blake3::hash(request.as_bytes()).to_hex().to_string(),
            root: root_hash,
            identity_record,
            diagnostic: serde_json::json!({
            "finite_check":if api {"OWNED_API_CHILD_FINISHED"} else {"OWNED_CHILD_FINISHED"},"process":process,"result":result,
            "authority":"NONE","runtime_scope":"root-protected host runtime; full coding profile qualification remains required"}),
        };
        if api {
            Ok(OwnedCodingTaskOutcome::ApiPassed(OwnedNativeApiCheck {
                inner: check,
            }))
        } else {
            Ok(OwnedCodingTaskOutcome::Passed(check))
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn finite_result(v: &serde_json::Value, b: &SubmissionContract) -> bool {
    v["schema"] == "realm.coding-task-referee-result.v1"
        && v["authority"] == "NONE"
        && v["realm_artifact"].is_null()
        && v["same_run_native_join"] == "NOT_ESTABLISHED"
        && v["status"] == "PASS_BOUNDED_PROPERTIES"
        && v["subject_unchanged"] == true
        && v["scope"]["original_task_sha256"] == b.task_sha256
        && v["scope"]["oracle_worker_sha256"] == b.worker_sha256
        && v["baseline_discrimination"]["passed"] == true
        && v["report_checks"]["passed"] == true
        && [
            &v["report_checks"]["independent_cases"],
            &v["api_driver_checks"],
        ]
        .into_iter()
        .all(|r| {
            r.as_array()
                .is_some_and(|rows| rows.len() == 17 && rows.iter().all(|x| x["passed"] == true))
        })
}

// Content classification only. Called after actual owned child closure and
// same-run request/source/subject readbacks; never creates an owner itself.
#[cfg(any(target_os = "linux", test))]
fn classify_observed_result(
    v: &serde_json::Value,
    b: &SubmissionContract,
    exit: i32,
) -> Option<bool> {
    if exit == 0 && finite_result(v, b) {
        return Some(true);
    }
    if exit == 2
        && v["schema"] == "realm.coding-task-referee-result.v1"
        && v["authority"] == "NONE"
        && v["realm_artifact"].is_null()
        && v["same_run_native_join"] == "NOT_ESTABLISHED"
        && v["status"] == "REFUSE_BOUNDED_PROPERTIES"
        && v["subject_unchanged"] == true
        && v["scope"]["original_task_sha256"] == b.task_sha256
        && v["scope"]["oracle_worker_sha256"] == b.worker_sha256
    {
        return Some(false);
    }
    None
}

#[cfg(any(target_os = "linux", test))]
fn classify_api_result(v: &serde_json::Value, b: &SubmissionContract, exit: i32) -> Option<bool> {
    if v["schema"] != "realm.native-api-subtask-result.v1"
        || v["authority"] != "NONE"
        || !v["realm_artifact"].is_null()
        || v["same_run_native_join"] != "NOT_ESTABLISHED"
        || v["subject_unchanged"] != true
        || v["scope"]["native_subtask"] != "api"
        || v["scope"]["original_task_sha256"] != b.task_sha256
        || v["scope"]["oracle_worker_sha256"] != b.worker_sha256
        || v["report_checks"] != "NOT_RUN_API_ONLY"
    {
        return None;
    }
    if exit == 2 && v["status"] == "REFUSE_API_SUBTASK" {
        return Some(false);
    }
    if exit == 0
        && v["status"] == "PASS_API_SUBTASK"
        && v["baseline_discrimination"]["passed"] == true
        && v["candidate_tests"]["exit"] == 0
        && v["api_driver_checks"]
            .as_array()
            .is_some_and(|r| r.len() == 17 && r.iter().all(|x| x["passed"] == true))
    {
        Some(true)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::response_result;
    fn content_case() -> (
        crate::coding_submission::SubmissionContract,
        serde_json::Value,
    ) {
        let binding = crate::coding_submission::SubmissionContract {
            run_id: "a".repeat(64),
            execution_id: "b".repeat(64),
            challenge_root: "c".repeat(64),
            task_sha256: "d".repeat(64),
            worker_sha256: "e".repeat(64),
        };
        let row = serde_json::json!({"passed":true});
        let result = serde_json::json!({"schema":"realm.coding-task-referee-result.v1",
            "authority":"NONE","realm_artifact":null,"same_run_native_join":"NOT_ESTABLISHED",
            "status":"PASS_BOUNDED_PROPERTIES","subject_unchanged":true,
            "scope":{"original_task_sha256":binding.task_sha256,"oracle_worker_sha256":binding.worker_sha256},
            "baseline_discrimination":{"passed":true},
            "report_checks":{"passed":true,"independent_cases":vec![row.clone();17]},
            "api_driver_checks":vec![row;17]});
        (binding, result)
    }
    #[test]
    fn content_classifier_does_not_promote_refusal_or_exit_status_to_success() {
        let (binding, pass) = content_case();
        assert_eq!(
            super::classify_observed_result(&pass, &binding, 0),
            Some(true)
        );
        assert_eq!(super::classify_observed_result(&pass, &binding, 2), None);
        let mut refused = pass.clone();
        refused["status"] = "REFUSE_BOUNDED_PROPERTIES".into();
        refused["report_checks"]["passed"] = false.into();
        assert_eq!(
            super::classify_observed_result(&refused, &binding, 2),
            Some(false)
        );
        for exit in [0, 1, 3, 127, -9] {
            assert_eq!(
                super::classify_observed_result(&refused, &binding, exit),
                None
            );
        }
        // This tests detached content only, not a child or either opaque owner.
        for (field, value) in [
            ("authority", serde_json::json!("ACCEPT")),
            ("subject_unchanged", serde_json::json!(false)),
            ("schema", serde_json::json!("unknown")),
            ("same_run_native_join", serde_json::json!("QUALIFIED")),
        ] {
            let mut bad = refused.clone();
            bad[field] = value;
            assert_eq!(super::classify_observed_result(&bad, &binding, 2), None);
        }
        let mut foreign = binding.clone();
        foreign.run_id = "f".repeat(64);
        // Run identity is validated against the original request/packet by the
        // owner constructor, not asserted by this metadata predicate.
        foreign.task_sha256 = "f".repeat(64);
        assert_eq!(super::classify_observed_result(&refused, &foreign, 2), None);
        assert_eq!(
            super::classify_observed_result(
                &serde_json::json!({"status":"REFUSE_BOUNDED_PROPERTIES"}),
                &binding,
                2
            ),
            None
        );
    }
    #[test]
    fn content_success_keeps_all_original_finite_obligations() {
        let (binding, pass) = content_case();
        for field in [
            "api_driver_checks",
            "report_checks",
            "baseline_discrimination",
            "scope",
        ] {
            let mut missing = pass.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert_eq!(super::classify_observed_result(&missing, &binding, 0), None);
        }
        let mut short = pass.clone();
        short["api_driver_checks"] = serde_json::json!([{"passed":true}]);
        assert_eq!(super::classify_observed_result(&short, &binding, 0), None);
        let mut bad = pass;
        bad["api_driver_checks"][0]["passed"] = false.into();
        assert_eq!(super::classify_observed_result(&bad, &binding, 0), None);
    }
    #[test]
    fn materialized_native_sources_can_describe_the_referee_without_repository_imports() {
        use std::{
            fs,
            process::Command,
            time::{SystemTime, UNIX_EPOCH},
        };
        let root = std::env::temp_dir().join(format!(
            "realm-referee-catalog-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let complete = root.join("complete");
        let old = root.join("missing-oracle");
        fs::create_dir(&complete).unwrap();
        fs::create_dir(&old).unwrap();
        for (name, bytes) in super::COMPILED_SOURCES {
            fs::write(complete.join(name), bytes).unwrap();
            if name != "development_task_oracles.py" {
                fs::write(old.join(name), bytes).unwrap();
            }
        }
        let program = "import sys,pathlib,json;sys.path.insert(0,sys.argv[1]);import coding_task_verifier as r;v=r.describe();assert len(v['functional_oracle_sha256'])==64;print(json.dumps(v,sort_keys=True))";
        let invoke = |path: &std::path::Path| {
            Command::new("python3")
                .args(["-I", "-B", "-c", program])
                .arg(path)
                .current_dir(&root)
                .output()
                .unwrap()
        };
        let pass = invoke(&complete);
        assert!(
            pass.status.success(),
            "{}",
            String::from_utf8_lossy(&pass.stderr)
        );
        let scope: serde_json::Value = serde_json::from_slice(&pass.stdout).unwrap();
        assert_eq!(scope["authority"], "NONE");
        let failure = invoke(&old);
        assert!(!failure.status.success());
        assert!(String::from_utf8_lossy(&failure.stderr).contains("development_task_oracles.py"));
        // Retain both materialized trees for diagnosis; no qualification is issued.
    }
    #[test]
    fn content_envelope_rejects_replay_cross_input_and_unknown_fields() {
        let mut v = serde_json::json!({"schema":"realm.owned-coding-referee-response.v1",
            "request_hex":"7b7d", "result":{"authority":"NONE"}});
        assert!(response_result(&v, b"{}").is_ok());
        assert!(response_result(&v, b"{ }").is_err());
        v["extra"] = true.into();
        assert!(response_result(&v, b"{}").is_err());
        v.as_object_mut().unwrap().remove("extra");
        v["schema"] = "realm.coding-task-referee-result.v1".into();
        assert!(response_result(&v, b"{}").is_err());
        assert!(response_result(&serde_json::json!({"status":"PASS"}), b"{}").is_err());
    }
    #[test]
    fn api_success_cannot_be_used_as_whole_task_or_refusal_success() {
        let (binding, mut data) = content_case();
        data["schema"] = "realm.native-api-subtask-result.v1".into();
        data["status"] = "PASS_API_SUBTASK".into();
        data["scope"]["native_subtask"] = "api".into();
        data["report_checks"] = "NOT_RUN_API_ONLY".into();
        data["candidate_tests"] = serde_json::json!({"exit":0});
        assert_eq!(super::classify_api_result(&data, &binding, 0), Some(true));
        assert_eq!(super::classify_observed_result(&data, &binding, 0), None);
        assert_eq!(super::classify_api_result(&data, &binding, 2), None);
        data["status"] = "REFUSE_API_SUBTASK".into();
        assert_eq!(super::classify_api_result(&data, &binding, 2), Some(false));
        assert_eq!(super::classify_api_result(&data, &binding, 0), None);
    }
}
