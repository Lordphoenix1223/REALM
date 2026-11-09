//! Live retention of ORIGINAL native attempt owners. The fsynced journal is
//! audit data, never a way to recover an owner after this process dies.
//!
//! Qualification and canonical publication remain in the existing native issuer
//! and publisher; this module supplies their original retained owner set.
use super::{NativeCodingAttempt, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenNativeTask {
    pub task_sha256: String,
    pub worker_sha256: String,
    pub source_commit: String,
    pub checker_sha256: String,
    pub checker_scope_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<crate::native_workflow::NativeTaskRole>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub installed_admission: bool,
}
impl FrozenNativeTask {
    pub(super) fn permits(&self, scope: &crate::coding_submission::CodingExecutionScope) -> bool {
        self.task_sha256 == scope.submission.task_sha256
            && self.worker_sha256 == scope.submission.worker_sha256
            && self.source_commit == scope.source_commit
            && self.checker_sha256 == scope.checker_sha256
            && self.checker_scope_sha256 == scope.checker_scope_sha256
            && self.role == scope.native_subtask.as_ref().map(|s| s.role)
    }
}

struct Slot {
    task: usize,
    owner: Option<NativeCodingAttempt>,
    outcome: &'static str,
}

/// Persistent in-process ownership. No Clone, Deserialize, file importer,
/// reassignment API, removal API, or conversion from Session JSON exists.
/// Dropping/killing this owner cannot leave a successful workflow capability.
/// ```compile_fail
/// let _: realm_v6::coding_runtime::attempt_history::NativeAttemptHistory =
///     serde_json::from_str("{}").unwrap();
/// ```
pub struct NativeAttemptHistory {
    journal: File,
    path: PathBuf,
    object: (u64, u64),
    bytes: Vec<u8>,
    head: String,
    nonce: String,
    workflow: String,
    tasks: Vec<FrozenNativeTask>,
    slots: Vec<Slot>,
    runs: BTreeSet<String>,
    poisoned: bool,
}

impl NativeAttemptHistory {
    pub fn create(root: &Path, workflow: &str, tasks: Vec<FrozenNativeTask>) -> Result<Self> {
        let hex = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        };
        if !hex(workflow)
            || tasks.len() != 2
            || tasks.iter().any(|t| {
                !hex(&t.task_sha256)
                    || !hex(&t.worker_sha256)
                    || !hex(&t.checker_sha256)
                    || !hex(&t.checker_scope_sha256)
                    || t.source_commit.len() != 40
                    || !t
                        .source_commit
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            || tasks[0].source_commit != tasks[1].source_commit
            || tasks[0].role.is_some()
                && (tasks[0].task_sha256 != tasks[1].task_sha256
                    || tasks[0].worker_sha256 != tasks[1].worker_sha256
                    || tasks[0].checker_sha256 != tasks[1].checker_sha256
                    || tasks[0].checker_scope_sha256 == tasks[1].checker_scope_sha256)
            || !matches!(
                (tasks[0].role, tasks[1].role),
                (None, None)
                    | (
                        Some(crate::native_workflow::NativeTaskRole::Api),
                        Some(crate::native_workflow::NativeTaskRole::Cli)
                    )
            )
        {
            return Err("frozen two-task native workflow required".into());
        }
        let m = fs::symlink_metadata(root)?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7777 != 0o700 {
            return Err("private original native history directory required".into());
        }
        let path = root.join("native-attempts.jsonl");
        let journal = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let m = journal.metadata()?;
        let mut s = Self {
            journal,
            path,
            object: (m.dev(), m.ino()),
            bytes: Vec::new(),
            head: "0".repeat(64),
            nonce: crate::mediation::MediationChallenge::fresh()?.root().into(),
            workflow: workflow.into(),
            tasks,
            slots: Vec::new(),
            runs: BTreeSet::new(),
            poisoned: false,
        };
        s.append(
            "OPEN",
            json!({"tasks":s.tasks,"owner_pid":std::process::id(),
            "qualification":"NOT_ESTABLISHED","authority":"NONE"}),
        )?;
        File::open(root)?.sync_all()?;
        Ok(s)
    }

    fn append(&mut self, phase: &str, data: Value) -> Result<()> {
        // Any storage/identity failure is sticky, including failures before a
        // complete BEGIN can reach disk. A caller catching Err cannot resume.
        self.poisoned = true;
        self.verify_journal()?;
        let body = json!({"schema":"realm.native-attempt-history.v1","workflow":self.workflow,
            "owner_nonce":self.nonce,"previous":self.head,"phase":phase,"data":data,"authority":"NONE"});
        let head = blake3::hash(&serde_json::to_vec(&body)?)
            .to_hex()
            .to_string();
        let mut encoded = serde_json::to_vec(&json!({"body":body,"blake3":head}))?;
        encoded.push(b'\n');
        self.journal.seek(SeekFrom::End(0))?;
        self.journal.write_all(&encoded)?;
        self.journal.sync_all()?;
        self.bytes.extend(encoded);
        self.head = head;
        self.poisoned = false;
        Ok(())
    }

    fn verify_journal(&self) -> Result<()> {
        let a = self.journal.metadata()?;
        let b = fs::symlink_metadata(&self.path)?;
        if !b.is_file()
            || b.file_type().is_symlink()
            || a.nlink() != 1
            || b.nlink() != 1
            || (a.dev(), a.ino()) != self.object
            || (b.dev(), b.ino()) != self.object
            || a.mode() & 0o7777 != 0o600
            || a.uid() != unsafe { libc::geteuid() }
            || a.len() != self.bytes.len() as u64
        {
            return Err("original native history object replaced/changed".into());
        }
        use std::os::unix::fs::FileExt;
        let mut raw = vec![0; self.bytes.len()];
        let mut at = 0;
        while at < raw.len() {
            let n = self.journal.read_at(&mut raw[at..], at as u64)?;
            if n == 0 {
                break;
            }
            at += n;
        }
        raw.truncate(at);
        if raw != self.bytes {
            return Err("original native history bytes changed".into());
        }
        Ok(())
    }

    fn reserve(&mut self, task: usize, args: &[String]) -> Result<usize> {
        if self.poisoned || self.slots.iter().any(|s| s.owner.is_none()) {
            return Err("native ownership/closure incomplete; cannot retry or finish".into());
        }
        let valid = self.tasks.get(task).is_some_and(|expected| {
            args.len() == 10
                && args[1] == "--native-referee-launch"
                && args[3] == expected.task_sha256
                && args[4] == expected.worker_sha256
                && self.slots.iter().filter(|s| s.task == task).count() < 2
                && !self
                    .slots
                    .iter()
                    .any(|s| s.task == task && s.outcome == "PASS")
                && (task == 0
                    || self
                        .slots
                        .iter()
                        .any(|s| s.task == 0 && s.outcome == "PASS"))
        });
        let index = self.slots.len();
        self.slots.push(Slot {
            task,
            owner: None,
            outcome: "INCOMPLETE",
        });
        self.append("BEGIN", json!({"attempt":index,"task":task,"argv":args}))?;
        if !valid {
            self.append(
                "REJECTED",
                json!({"attempt":index,"task":task,
                "reason":"task pin, dependency, retry budget or source differs"}),
            )?;
            self.poisoned = true;
            return Err("native task pin, dependency, retry budget or source differs".into());
        }
        Ok(index)
    }

    fn subtask(&self, index: usize) -> Result<Option<crate::native_workflow::NativeSubtask>> {
        let role = match self.tasks[self.slots[index].task].role {
            Some(v) => v,
            None => return Ok(None),
        };
        let predecessor = if role == crate::native_workflow::NativeTaskRole::Cli {
            let api = self.slots[..index]
                .iter()
                .rev()
                .find_map(|s| match s.owner.as_ref() {
                    Some(NativeCodingAttempt::ApiRetired(api)) if s.outcome == "PASS" => Some(api),
                    _ => None,
                })
                .ok_or("CLI requires original successful native API owner")?;
            let custody = api
                .retired
                .owned_custody
                .as_ref()
                .ok_or("API custody absent")?;
            custody.validate_retired(&api.retired.production)?;
            let (scope, packet, _, _, _) = custody.publication_inputs();
            Some(crate::native_workflow::NativeApiPredecessor {
                submission: scope.submission.clone(),
                packet_blake3: blake3::hash(packet).to_hex().to_string(),
                packet_hex: packet.iter().map(|b| format!("{b:02x}")).collect(),
                referee_root: api.referee.root().into(),
            })
        } else {
            None
        };
        let scope = crate::native_workflow::NativeSubtask {
            workflow: self.workflow.clone(),
            role,
            attempt: index,
            history_prefix_blake3: self.head.clone(),
            predecessor,
        };
        scope.validate()?;
        Ok(Some(scope))
    }
    /// The launch itself executes in THIS process. No process-exit record or
    /// Python-owned result can be passed as the returned native owner.
    pub fn execute(
        &mut self,
        task: usize,
        args: &[String],
        admission: Option<crate::runtime_admission::ReviewedRuntimeAdmission>,
        input: &mut impl std::io::BufRead,
    ) -> Result<Value> {
        let index = self.reserve(task, args)?;
        let launched = self.subtask(index).and_then(|step| {
            super::run_native_attempt_stream(
                args,
                admission,
                input,
                None,
                Some(&self.tasks[task]),
                step.as_ref(),
            )
        });
        self.retain_result(index, launched)
    }

    fn retain_result(
        &mut self,
        index: usize,
        launched: Result<NativeCodingAttempt>,
    ) -> Result<Value> {
        let task = self.slots[index].task;
        match launched {
            Ok(owner) => {
                // Move the owner into its permanent slot BEFORE validation or
                // persistence can fail. An error never discards or reassigns it.
                self.slots[index].owner = Some(owner);
                let checked = self.owner_summary(index);
                match checked {
                    Ok((run, outcome, diagnostic)) => {
                        if !self.runs.insert(run) {
                            self.poisoned = true;
                            return Err("native run reused by another attempt".into());
                        }
                        self.append(
                            "RETAINED",
                            json!({"attempt":index,"task":task,
                            "outcome":outcome,"original":diagnostic}),
                        )?;
                        self.slots[index].outcome = outcome;
                        let binding = match self.slots[index].owner.as_ref().unwrap() {
                            NativeCodingAttempt::Retired(run) => &run.binding,
                            NativeCodingAttempt::ApiRetired(run) => &run.binding,
                            NativeCodingAttempt::Refused(run) => run.referee.binding(),
                        };
                        Ok(
                            json!({"phase":"ATTEMPT_RETAINED","attempt":index,"task":task,
                            "outcome":outcome,"binding":binding,"history_head":self.head,"owner_nonce":self.nonce,
                            "owner_alive":true,"authority":"NONE"}),
                        )
                    }
                    Err(error) => {
                        self.poisoned = true;
                        Err(error)
                    }
                }
            }
            Err(error) => {
                // No terminal owner: preserve the failed intent and exact error,
                // and latch INCOMPLETE. A later successful run cannot heal it.
                let persisted = self.append(
                    "INCOMPLETE",
                    json!({"attempt":index,"task":task,
                    "error":error.to_string(),"retry_authorization":"NONE"}),
                );
                self.poisoned = true;
                persisted?;
                Err(error)
            }
        }
    }

    fn owner_summary(&self, index: usize) -> Result<(String, &'static str, Value)> {
        match self.slots[index]
            .owner
            .as_ref()
            .ok_or("native attempt has no original owner")?
        {
            NativeCodingAttempt::Refused(run) => {
                run.revalidate()?;
                let custody = run
                    .retired
                    .owned_custody
                    .as_ref()
                    .ok_or("missing refused custody")?;
                if !self.tasks[self.slots[index].task].permits(custody.publication_inputs().0) {
                    return Err("refused owner belongs to a different frozen workflow task".into());
                }
                Ok((
                    run.referee.binding().run_id.clone(),
                    "REFUSED",
                    run.diagnostic(),
                ))
            }
            NativeCodingAttempt::ApiRetired(run) => self.successful_summary(
                &run.retired,
                run.referee.view(),
                &run.binding,
                Some(&run.capture_root),
                index,
            ),
            NativeCodingAttempt::Retired(run) => self.successful_summary(
                &run.retired,
                run.referee.as_ref().ok_or("missing owned referee")?,
                &run.binding,
                run.relay_capture_root.as_deref(),
                index,
            ),
        }
    }
    fn successful_summary(
        &self,
        retired: &crate::supervisor::RetiredCodingVmm,
        referee: &crate::coding_referee::OwnedCodingTaskCheck,
        binding: &crate::coding_submission::SubmissionContract,
        capture_root: Option<&str>,
        index: usize,
    ) -> Result<(String, &'static str, Value)> {
        let custody = retired
            .owned_custody
            .as_ref()
            .ok_or("missing original custody")?;
        custody.validate_retired(&retired.production)?;
        let (scope, packet, native, frozen, _) = custody.publication_inputs();

        let fence = retired
            .coding_fence
            .as_ref()
            .ok_or("missing original fence")?;
        fence.revalidate_objects()?;
        if !self.tasks[self.slots[index].task].permits(scope)
            || !retired.has_closed_coding_channels()
            || !fence.matches_terminal(&retired.production)
            || !referee.native_binding(scope, packet, &native.root, frozen.completion.root())
            || scope.submission != *binding
            || !retired.owned_provenance.as_ref().is_some_and(|p| {
                capture_root == Some(p.root())
                    && p.matches_native(
                        &retired.production,
                        scope,
                        frozen.completion.frontier_root(),
                        &frozen.barrier,
                    )
            })
        {
            return Err("native original owner/capture/closure mismatch".into());
        }
        Ok((
            binding.run_id.clone(),
            "PASS",
            json!({"retirement":retired.record(),
                    "referee":referee.identity_record(),"custody":custody.record(),"capture_root":capture_root}),
        ))
    }

    fn attempt_receipt(
        &self,
        index: usize,
    ) -> Result<crate::native_workflow::NativeAttemptReceipt> {
        use crate::coding_semantics::{API_SCOPE, REFUSAL_SCOPE, SCOPE};
        use crate::native_workflow::{AttemptOutcome, NativeAttemptReceipt};
        self.owner_summary(index)?;
        let role = self.tasks[self.slots[index].task]
            .role
            .ok_or("registered native role required")?;
        let (retired, referee, kind): (
            &crate::supervisor::RetiredCodingVmm,
            &dyn crate::coding_referee::NativeRefereeEvidence,
            &str,
        ) = match self.slots[index]
            .owner
            .as_ref()
            .ok_or("missing original attempt owner")?
        {
            NativeCodingAttempt::Retired(r) => (
                &r.retired,
                r.referee.as_ref().ok_or("missing original referee")?,
                SCOPE,
            ),
            NativeCodingAttempt::ApiRetired(r) => (&r.retired, &r.referee, API_SCOPE),
            NativeCodingAttempt::Refused(r) => (&r.retired, &r.referee, REFUSAL_SCOPE),
        };
        let custody = retired
            .owned_custody
            .as_ref()
            .ok_or("missing original custody")?;
        let provenance = retired
            .owned_provenance
            .as_ref()
            .ok_or("missing original runtime observations")?;
        let evidence = crate::integration::coding::receipt_from_owners(
            custody,
            referee,
            provenance,
            &retired.production,
            kind,
        )?;
        let packet = custody.publication_inputs().1;
        Ok(NativeAttemptReceipt {
            role,
            outcome: if kind == REFUSAL_SCOPE {
                AttemptOutcome::Refused
            } else {
                AttemptOutcome::Pass
            },
            evidence: Box::new(evidence),
            packet_hex: packet.iter().map(|b| format!("{b:02x}")).collect(),
        })
    }
    /// Original-owner DATA export; absence of qualification remains visible and
    /// cannot authorize publication. The canonical join below consumes owners.
    pub fn stage7_history(&self) -> Result<crate::native_workflow::NativeWorkflowReceipt> {
        self.verify_journal()?;
        if self.poisoned
            || self.slots.is_empty()
            || self.tasks[0].role != Some(crate::native_workflow::NativeTaskRole::Api)
            || self.tasks[1].role != Some(crate::native_workflow::NativeTaskRole::Cli)
            || self
                .slots
                .last()
                .is_none_or(|s| s.task != 1 || s.outcome != "PASS")
        {
            return Err("native workflow incomplete/unregistered".into());
        }
        let last = self.slots.len() - 1;
        let current = self.attempt_receipt(last)?;
        let prior = (0..last)
            .map(|i| self.attempt_receipt(i))
            .collect::<Result<Vec<_>>>()?;
        let record = crate::native_workflow::NativeWorkflowReceipt {
            schema: "realm.native-two-subtask-history/v1".into(),
            workflow: self.workflow.clone(),
            ledger: String::from_utf8(self.bytes.clone())?,
            prior,
        };
        record.validate(&current.evidence)?;
        Ok(record)
    }
    /// Consume the entire live owner set. The returned opaque prefix must be
    /// carried by the existing Stage7 capability through actual publication.
    pub fn into_stage7(mut self) -> Result<(super::NativeCodingRetirement, OwnedNativeWorkflow)> {
        let record = self.stage7_history()?;
        for slot in &self.slots {
            let retired = match slot.owner.as_ref().ok_or("missing original attempt")? {
                NativeCodingAttempt::Retired(r) => &r.retired,
                NativeCodingAttempt::ApiRetired(r) => &r.retired,
                NativeCodingAttempt::Refused(r) => &r.retired,
            };
            if !retired
                .owned_provenance
                .as_ref()
                .is_some_and(|p| p.has_verified_vmm_fd_boundary())
            {
                return Err(
                    "INCOMPLETE: every original native attempt needs qualified runtime provenance"
                        .into(),
                );
            }
        }
        let last = self.slots.len() - 1;
        let owner = self.slots[last]
            .owner
            .take()
            .ok_or("missing final native owner")?;
        let NativeCodingAttempt::Retired(final_run) = owner else {
            return Err("final CLI is not a whole-task owner".into());
        };
        Ok((
            *final_run,
            OwnedNativeWorkflow {
                history: self,
                record,
            },
        ))
    }
    /// Non-authorizing audit snapshot checked against the STILL-LIVE original
    /// owners. It is deliberately not a workflow qualification or publication.
    pub fn inspect(&mut self) -> Result<Value> {
        self.verify_journal()
            .inspect_err(|_| self.poisoned = true)?;
        let mut attempts = Vec::new();
        for i in 0..self.slots.len() {
            if self.slots[i].owner.is_some() {
                let result = self
                    .owner_summary(i)
                    .inspect_err(|_| self.poisoned = true)?;
                // Keep bounded control replies independent of the size of
                // original kernel/custody evidence. The complete original
                // diagnostic was fsynced in RETAINED and remains live-owned.
                let evidence_root = blake3::hash(&serde_json::to_vec(&result.2)?)
                    .to_hex()
                    .to_string();
                let binding = match self.slots[i].owner.as_ref().unwrap() {
                    NativeCodingAttempt::Retired(run) => &run.binding,
                    NativeCodingAttempt::ApiRetired(run) => &run.binding,
                    NativeCodingAttempt::Refused(run) => run.referee.binding(),
                };
                attempts.push(json!({"attempt":i,"task":self.slots[i].task,
                    "outcome":self.slots[i].outcome,"run_id":result.0,"binding":binding,
                    "original_evidence_blake3":evidence_root,"original_owner_retained":true}));
            } else {
                attempts
                    .push(json!({"attempt":i,"task":self.slots[i].task,"outcome":"INCOMPLETE"}));
            }
        }
        let complete = !self.poisoned
            && (0..self.tasks.len()).all(|t| {
                self.slots
                    .iter()
                    .any(|s| s.task == t && s.outcome == "PASS")
            });
        Ok(
            json!({"schema":"realm.retained-native-attempts.v1","workflow":self.workflow,
            "owner_nonce":self.nonce,"history_head":self.head,"attempts":attempts,
            "ownership_status":if complete {"ALL_ORIGINAL_OWNERS_RETAINED"} else {"INCOMPLETE"},
            "qualification":"NOT_ESTABLISHED","authority":"NONE","publication_authority":false}),
        )
    }
}

/// Only original native keeper ownership can construct this publication input.
/// ```compile_fail
/// let _:realm_v6::coding_runtime::attempt_history::OwnedNativeWorkflow=serde_json::from_str("{}").unwrap();
/// ```
pub struct OwnedNativeWorkflow {
    history: NativeAttemptHistory,
    record: crate::native_workflow::NativeWorkflowReceipt,
}
impl OwnedNativeWorkflow {
    pub(crate) fn revalidate(
        &self,
        current: &crate::coding_semantics::CodingSemanticEvidence,
    ) -> Result<()> {
        self.history.verify_journal()?;
        for i in 0..self.history.slots.len() - 1 {
            self.history.owner_summary(i)?;
        }
        if current.workflow.as_deref() != Some(&self.record) {
            return Err("retained original workflow differs from publication receipt".into());
        }
        self.record.validate(current).map_err(Into::into)
    }
    pub(crate) fn attach(
        &self,
        current: &mut crate::coding_semantics::CodingSemanticEvidence,
    ) -> Result<()> {
        self.history.verify_journal()?;
        for i in 0..self.history.slots.len() - 1 {
            self.history.owner_summary(i)?;
        }
        self.record.validate(current)?;
        current.workflow = Some(Box::new(self.record.clone()));
        current.validate_shape()?;
        Ok(())
    }
}

/// Persistent mode of the EXISTING native probe. All attempts use the original
/// launch/referee/retirement implementation in this same process. This mode
/// diagnostic probe has no publisher; the existing realm-cli entrypoint supplies
/// its canonical publisher callback, consuming the entire original owner set.
///
/// Arguments: --retain-native-attempts ROOT WORKFLOW_SHA TASKS_JSON AUX_FD.
/// Control: ATTEMPT {task, args} (native argv, slot8 replaced with an owned dup),
/// INSPECT, RELEASE, PUBLISH. Configuration/start/retirement frames remain unchanged.
pub fn run_retained(args: &[String]) -> Result<()> {
    run_retained_with_publisher(args, |_| {
        Err("canonical workflow publisher is not linked into diagnostic probe".into())
    })
}
pub fn run_retained_with_publisher(
    args: &[String],
    publish: impl FnOnce(crate::execute::CheckedExecutionForPublication) -> Result<Value>,
) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if args.len() != 6 {
        return Err("--retain-native-attempts ROOT WORKFLOW_SHA TASKS_JSON AUX_FD".into());
    }
    let tasks: Vec<FrozenNativeTask> = serde_json::from_value(
        crate::strict_json::parse(args[4].as_bytes())
            .map_err(|_| "strict frozen tasks required")?,
    )?;
    // Own the existing private descriptor once; each launch consumes a fresh
    // descriptor alias, while this process retains the handoff endpoint.
    let fd: i32 = args[5].parse()?;
    if fd <= 2
        || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0
        || unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
    {
        return Err("private retained handoff descriptor required".into());
    }
    // SAFETY: this CLI transfers the descriptor exactly once. Merely retaining
    // it establishes NO trust. Each actual launch calls the original
    // auxiliary_channel root-parent/SO_PEERCRED check before using any handoff.
    let auxiliary = unsafe { File::from_raw_fd(fd) };
    let mut history = NativeAttemptHistory::create(Path::new(&args[2]), &args[3], tasks)?;
    let mut input = std::io::BufReader::new(std::io::stdin());
    super::emit(
        json!({"phase":"HISTORY_OPEN","owner_pid":std::process::id(),
        "owner_nonce":history.nonce,"workflow":history.workflow,"authority":"NONE"}),
    )?;
    #[derive(Deserialize)]
    #[serde(tag = "phase", deny_unknown_fields)]
    enum Command {
        #[serde(rename = "ATTEMPT")]
        Attempt { task: usize, args: Vec<String> },
        #[serde(rename = "INSPECT")]
        Inspect,
        #[serde(rename = "RELEASE")]
        Release,
        #[serde(rename = "ABORT")]
        Abort { reason: String },
        #[serde(rename = "PUBLISH")]
        Publish,
    }
    loop {
        let command: Command = serde_json::from_value(super::line(&mut input)?)?;
        match command {
            Command::Attempt { task, mut args } => {
                // Reject unknown task/profile before transferring a descriptor.
                // reserve() persists intent before the original launch guard.
                let held = auxiliary.try_clone()?;
                if args.len() == 10 {
                    args[8] = held.as_raw_fd().to_string();
                }
                let index = history.reserve(task, &args)?;
                // RAII ownership crosses the function call, including every
                // prelaunch refusal. No raw FD can leak on an early error.
                let outcome = (|| -> Result<NativeCodingAttempt> {
                    let step = history.subtask(index)?;
                    super::run_native_attempt_stream(
                        &args,
                        None,
                        &mut input,
                        Some(held),
                        Some(&history.tasks[task]),
                        step.as_ref(),
                    )
                })();
                match history.retain_result(index, outcome) {
                    Ok(row) => {
                        match history.slots[index].owner.as_ref().unwrap() {
                            NativeCodingAttempt::Retired(run) => {
                                super::emit_native_retirement(run)?
                            }
                            NativeCodingAttempt::ApiRetired(run) => {
                                let custody = &run.custody_record;
                                super::emit(
                                    json!({"phase":"RETIRED_API_DIAGNOSTIC","authority":"NONE","native_state":run.state,
                                    "publication_authority":false,"realm_artifact":null,"binding":run.binding,
                                    "retirement":run.retired.record(),"owned_custody":custody,
                                    "owned_referee":{"root":run.referee.root(),"check":run.referee.diagnostic()},
                                    "output_object":custody["output_object"],"custody_head":custody["custody_head"],
                                    "frontier_head":custody["frontier_head"],"packet_blake3":custody["packet_blake3"],
                                    "transcript_head":custody["transcript_head"]}),
                                )?;
                            }
                            NativeCodingAttempt::Refused(run) => {
                                let custody = run
                                    .retired
                                    .owned_custody
                                    .as_ref()
                                    .ok_or("missing refused custody")?
                                    .record();
                                super::emit(json!({"phase":"RETIRED_REFUSED_DIAGNOSTIC",
                                    "authority":"NONE","publication_authority":false,"realm_artifact":null,
                                    "binding":run.referee.binding(),"retirement":run.retired.record(),
                                    "owned_custody":custody,"owned_referee":{"root":run.referee.root(),"check":run.referee.diagnostic()},
                                    "output_object":custody["output_object"],"custody_head":custody["custody_head"],
                                    "frontier_head":custody["frontier_head"],"packet_blake3":custody["packet_blake3"],
                                    "transcript_head":custody["transcript_head"]}))?;
                            }
                        }
                        super::emit(row)?;
                    }
                    Err(error) => super::emit(json!({"phase":"ATTEMPT_INCOMPLETE",
                        "error":error.to_string(),"retained":history.inspect()?,"authority":"NONE"}))?,
                }
            }
            Command::Abort { reason } => {
                if reason.len() > 1024 {
                    return Err("bounded abort reason required".into());
                }
                history.append("ABORT", json!({"reason":reason}))?;
                history.poisoned = true;
                super::emit(history.inspect()?)?;
            }
            Command::Publish => {
                let (mut final_run, workflow) = history.into_stage7()?;
                let provenance = final_run.retired.require_coding_provenance()?;
                let referee = final_run
                    .referee
                    .take()
                    .ok_or("missing final CLI referee")?;
                let capability = final_run
                    .retired
                    .finalize_coding_workflow(referee, provenance, workflow)?;
                let publication = publish(capability)?;
                super::emit(
                    json!({"phase":"WORKFLOW_PUBLISHED","publication":publication,"authority":"NONE"}),
                )?;
                return Ok(());
            }
            Command::Inspect => super::emit(history.inspect()?)?,
            Command::Release => {
                let result = history.inspect()?;
                // RELEASE means the originals are about to be dropped; this is
                // NEVER called a live ownership or publication transfer.
                history.append(
                    "RELEASE",
                    json!({"status":result["ownership_status"],
                    "qualification":"NOT_ESTABLISHED","authority":"NONE"}),
                )?;
                super::emit(json!({"phase":"OWNERS_RELEASED","audit":result,
                    "owner_retention":"ENDED","authority":"NONE"}))?;
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn setup() -> (PathBuf, NativeAttemptHistory) {
        let root = std::env::temp_dir().join(format!(
            "realm-retained-native-{}",
            crate::mediation::MediationChallenge::fresh()
                .unwrap()
                .root()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let tasks = vec![
            FrozenNativeTask {
                task_sha256: "a".repeat(64),
                worker_sha256: "b".repeat(64),
                source_commit: "d".repeat(40),
                checker_sha256: "e".repeat(64),
                checker_scope_sha256: "f".repeat(64),
                role: None,
                installed_admission: false
            };
            2
        ];
        let history = NativeAttemptHistory::create(&root, &"c".repeat(64), tasks).unwrap();
        (root, history)
    }
    fn args() -> Vec<String> {
        [
            "original",
            "--native-referee-launch",
            "/never-launched",
            &"a".repeat(64),
            &"b".repeat(64),
            "/custodian",
            "996",
            "980",
            "-1",
            "/python",
        ]
        .iter()
        .map(|x| x.to_string())
        .collect()
    }
    #[test]
    fn prelaunch_source_and_criteria_are_frozen_not_accepted_from_session_json() {
        let (_root, history) = setup();
        let mut scope: crate::coding_submission::CodingExecutionScope = serde_json::from_value(json!({
            "submission":{"run_id":"1".repeat(64),"execution_id":"2".repeat(64),"challenge_root":"3".repeat(64),
                "task_sha256":"a".repeat(64),"worker_sha256":"b".repeat(64)},
            "source_commit":"d".repeat(40),"checker_sha256":"e".repeat(64),"checker_scope_sha256":"f".repeat(64)
        })).unwrap();
        assert!(history.tasks[0].permits(&scope));
        scope.checker_scope_sha256 = "9".repeat(64);
        assert!(!history.tasks[0].permits(&scope));
        scope.checker_scope_sha256 = "f".repeat(64);
        scope.source_commit = "8".repeat(40);
        assert!(!history.tasks[0].permits(&scope));
    }
    #[test]
    fn incomplete_original_intent_blocks_retry_and_finish() {
        let (_root, mut history) = setup();
        let index = history.reserve(0, &args()).unwrap();
        assert!(
            history
                .retain_result(index, Err("interrupted original closure".into()))
                .is_err()
        );
        assert!(history.reserve(0, &args()).is_err());
        assert!(history.reserve(1, &args()).is_err());
        let result = history.inspect().unwrap();
        assert_eq!(result["ownership_status"], "INCOMPLETE");
        assert_eq!(result["attempts"].as_array().unwrap().len(), 1);
        assert_eq!(result["attempts"][0]["outcome"], "INCOMPLETE");
        let raw = String::from_utf8(history.bytes.clone()).unwrap();
        assert!(raw.contains("interrupted original closure"));
    }
    #[test]
    fn cross_task_pin_rejection_is_not_erased() {
        let (_root, mut history) = setup();
        let mut a = args();
        a[3] = "d".repeat(64);
        assert!(history.reserve(0, &a).is_err());
        assert!(
            String::from_utf8(history.bytes.clone())
                .unwrap()
                .contains("REJECTED")
        );
        assert_eq!(history.slots.len(), 1);
        assert!(history.reserve(0, &args()).is_err());
    }
    #[test]
    fn dependency_rejection_retains_original_request() {
        let (_root, mut history) = setup();
        assert!(history.reserve(1, &args()).is_err());
        assert_eq!(history.slots[0].task, 1);
        assert_eq!(history.inspect().unwrap()["ownership_status"], "INCOMPLETE");
    }
    #[test]
    fn process_restart_cannot_import_previous_history() {
        let (root, mut history) = setup();
        history.reserve(0, &args()).unwrap();
        drop(history);
        let tasks = vec![
            FrozenNativeTask {
                task_sha256: "a".repeat(64),
                worker_sha256: "b".repeat(64),
                source_commit: "d".repeat(40),
                checker_sha256: "e".repeat(64),
                checker_scope_sha256: "f".repeat(64),
                role: None,
                installed_admission: false
            };
            2
        ];
        assert!(NativeAttemptHistory::create(&root, &"c".repeat(64), tasks).is_err());
        assert!(
            fs::read_to_string(root.join("native-attempts.jsonl"))
                .unwrap()
                .contains("BEGIN")
        );
    }
    #[test]
    fn replaced_journal_does_not_replace_held_ownership() {
        let (root, mut history) = setup();
        fs::rename(&history.path, root.join("preserved-original.jsonl")).unwrap();
        fs::write(&history.path, &history.bytes).unwrap();
        assert!(history.inspect().is_err());
        assert!(history.reserve(0, &args()).is_err());
    }
    #[test]
    fn changed_journal_is_sticky_failure() {
        let (_root, mut history) = setup();
        let original = history.bytes.clone();
        history.journal.write_all(b"x").unwrap();
        history.journal.sync_all().unwrap();
        assert!(history.inspect().is_err());
        history.journal.set_len(0).unwrap();
        history.journal.seek(SeekFrom::Start(0)).unwrap();
        history.journal.write_all(&original).unwrap();
        history.journal.sync_all().unwrap();
        assert!(history.reserve(0, &args()).is_err());
    }
}
