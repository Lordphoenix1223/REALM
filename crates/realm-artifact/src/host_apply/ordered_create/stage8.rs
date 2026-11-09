//! Stage 8 trusted broker over the existing ordered-create engine.
//!
//! A Session is private policy state, never an executor-side deserializable
//! capability. The controller MUST isolate an untrusted executor before routing
//! its bounded requests here. This API alone does not contain a process.
use super::*;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

pub const PROFILE: &str = "realm.stage8.ordered-create.v1";
pub const MAX_FRAME: usize = 4096;
#[cfg(target_os = "macos")]
pub const RUNTIME_PROFILE: &str = "realm.stage8.macos-seatbelt-stdio.v1";
#[cfg(not(target_os = "macos"))]
pub const RUNTIME_PROFILE: &str = "realm.stage8.linux-bwrap-seccomp-stdio.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub schema: String,
    pub approval: String,
    pub artifact_blake3: String,
    pub task_sha256: String,
    pub destination: DirectoryIdentity,
    pub state: DirectoryIdentity,
    pub expires_at_unix: u64,
    pub max_requests: usize,
    pub network: Vec<String>,
    pub shell: bool,
    pub runtime_profile: String,
    pub child_cpu_seconds: u64,
    pub child_wall_millis: u64,
    pub child_output_bytes: usize,
    pub broker_wall_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub approval: String,
    pub operation: CreateOperation,
}

#[derive(Debug, Serialize)]
pub struct Disposition {
    pub status: &'static str,
    pub authority: &'static str,
    pub completed: usize,
    pub terminal: bool,
    pub error: Option<String>,
    pub receipt: Option<OrderedReceipt>,
}

/// Not Clone, Deserialize, or constructible by an untrusted request.
/// On refusal the session is permanently poisoned; recovery requires an
/// independent operator decision through the existing reconciliation API.
pub struct Session {
    batch: VerifiedCreateBatch,
    plan: OrderedPlan,
    destination: PathBuf,
    state: PathBuf,
    state_identity: DirectoryIdentity,
    task: String,
    development: bool,
    expires: u64,
    started: Instant,
    granted: bool,
    terminal: bool,
    failed: bool,
    completed: usize,
}

impl Session {
    /// Reuses the sole native/publication/destination verifier. Raw candidate
    /// inspection and development dispositions cannot satisfy this API.
    pub fn verified_transfer(
        bytes: &[u8],
        proof: &TransferProof,
        policy: &coding_transfer::CodingTransferPolicy,
        destination: &Path,
        state: &Path,
    ) -> Result<Self> {
        let batch = coding_transfer::verify_transfer(bytes, proof, policy)?;
        let task = &policy.contract.submission.task_sha256;
        if batch.authorization.is_none() {
            return refuse("Stage 8 production authorization missing");
        }
        Self::prepare(batch, destination, state, task, false)
    }

    fn prepare(
        batch: VerifiedCreateBatch,
        destination: &Path,
        state: &Path,
        task: &str,
        development: bool,
    ) -> Result<Self> {
        if !cfg!(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )) {
            return refuse("UNSUPPORTED: strict Stage8 kernel/architecture profile");
        }
        if !valid_digest(task) || state.starts_with(destination) || destination.starts_with(state) {
            return refuse("Stage 8 task/state binding invalid");
        }
        let plan = preflight(&batch, destination)?;
        let s = Directory::open(state)?;
        supported_filesystem(&s)?;
        if !s.names()?.is_empty() || s.identity()?.device != plan.destination.device {
            return refuse("Stage 8 requires fresh separate same-filesystem state");
        }
        Ok(Self {
            batch,
            plan,
            destination: destination.into(),
            state: state.into(),
            state_identity: s.identity()?,
            task: task.into(),
            development,
            expires: 0,
            started: Instant::now(),
            granted: false,
            terminal: false,
            failed: false,
            completed: 0,
        })
    }

    pub fn plan(&self) -> &OrderedPlan {
        &self.plan
    }
    pub fn destination(&self) -> &Path {
        &self.destination
    }
    pub fn state(&self) -> &Path {
        &self.state
    }
    /// Proposal only. The TRUSTED controller must independently compare these
    /// bindings with its own operator/task/destination pins before supplying it.
    pub fn grant_proposal(&self) -> Result<Grant> {
        Ok(Grant {
            schema: PROFILE.into(),
            approval: self.plan.approval_id()?,
            artifact_blake3: self.batch.artifact.clone(),
            task_sha256: self.task.clone(),
            destination: self.plan.destination.clone(),
            state: self.state_identity.clone(),
            expires_at_unix: coding_transfer::now_unix()? + 30,
            max_requests: 3,
            network: vec![],
            shell: false,
            runtime_profile: RUNTIME_PROFILE.into(),
            child_cpu_seconds: 2,
            child_wall_millis: 3000,
            child_output_bytes: 32768,
            broker_wall_seconds: 10,
        })
    }
    pub fn activate(&mut self, grant: Grant) -> Result<()> {
        let valid = self.check_grant(&grant);
        if valid.is_err() {
            self.terminal = true;
            self.failed = true;
        }
        valid?;
        self.expires = grant.expires_at_unix;
        self.started = Instant::now();
        self.granted = true;
        Ok(())
    }
    fn check_grant(&self, g: &Grant) -> Result<()> {
        let now = coding_transfer::now_unix()?;
        if self.terminal
            || self.granted
            || g.schema != PROFILE
            || g.approval != self.plan.approval_id()?
            || g.artifact_blake3 != self.batch.artifact
            || g.task_sha256 != self.task
            || g.destination != self.plan.destination
            || g.state != self.state_identity
            || g.expires_at_unix <= now
            || g.expires_at_unix > now + 30
            || g.max_requests != 3
            || !g.network.is_empty()
            || g.shell
            || g.runtime_profile != RUNTIME_PROFILE
            || g.child_cpu_seconds != 2
            || g.child_wall_millis != 3000
            || g.child_output_bytes != 32768
            || g.broker_wall_seconds != 10
        {
            return refuse("Stage 8 independent grant/budget differs");
        }
        Ok(())
    }
    /// Strict bounded protocol. Unknown operations/fields, replay, reordered or
    /// changed arguments fail before mutation. Bytes always come from the frozen
    /// verified artifact, never from the requesting executor.
    pub fn dispatch(&mut self, bytes: &[u8]) -> Disposition {
        let result = self.step(bytes);
        if result.is_err() {
            self.terminal = true;
            self.failed = true;
        }
        let (status, error, receipt) = match result {
            Ok(r) => (
                if r.is_some() {
                    "COMPLETE_PENDING_INDEPENDENT_VERIFICATION"
                } else {
                    "STEP_COMPLETE"
                },
                None,
                r,
            ),
            Err(e) => ("REFUSE", Some(e.to_string()), None),
        };
        Disposition {
            status,
            authority: if self.development {
                "NONE"
            } else {
                "EXTERNAL_VERIFIED_POLICY"
            },
            completed: self.completed,
            terminal: self.terminal,
            error,
            receipt,
        }
    }
    fn step(&mut self, bytes: &[u8]) -> Result<Option<OrderedReceipt>> {
        if self.terminal
            || !self.granted
            || self.completed >= 3
            || bytes.is_empty()
            || bytes.len() > MAX_FRAME
        {
            return refuse("Stage 8 terminal, ungranted or oversized request");
        }
        if coding_transfer::now_unix()? >= self.expires
            || self.started.elapsed() > Duration::from_secs(10)
        {
            return refuse("Stage 8 time budget exhausted");
        }
        let request: Request = coding_transfer::strict_json(bytes)?;
        if request.approval != self.plan.approval_id()?
            || request.operation != self.plan.operations[self.completed]
        {
            return refuse("Stage 8 exact operation/order/count/arguments differ");
        }
        if Directory::open(&self.destination)?.identity()? != self.plan.destination
            || Directory::open(&self.state)?.identity()? != self.state_identity
        {
            return refuse("Stage 8 destination or state replaced");
        }
        let r = run_until(
            &self.batch,
            &self.destination,
            &self.state,
            &request.approval,
            Fault::None,
            self.completed + 1,
        )?;
        self.completed += 1;
        if self.completed == 3 {
            self.terminal = true;
        }
        Ok(r)
    }
    /// Separate read-only physical verification; never trusts executor verdicts.
    pub fn verify(&self) -> Result<Disposition> {
        if self.failed || !self.granted || self.completed != 3 {
            return refuse("Stage 8 incomplete session");
        }
        if Directory::open(&self.destination)?.identity()? != self.plan.destination
            || Directory::open(&self.state)?.identity()? != self.state_identity
        {
            return refuse("Stage 8 final destination or state identity changed");
        }
        let r = verify_host(&self.batch, &self.destination, &self.state)?;
        Ok(Disposition {
            status: "VERIFIED_FINAL_STATE",
            authority: if self.development {
                "NONE"
            } else {
                "EXTERNAL_VERIFIED_POLICY"
            },
            completed: 3,
            terminal: true,
            error: None,
            receipt: Some(r),
        })
    }

    /// Explicit, feature-gated disposable test permission. No VerifiedCreateBatch
    /// escapes. Creates a NEW private child; can never select an existing
    /// protected destination. Does not weaken the native production verifier.
    #[cfg(feature = "receiver-fixtures")]
    pub fn disposable_capture(
        bytes: &[u8],
        pin: &str,
        expectations: &[u8],
        expectations_pin: &str,
        parent: &Path,
    ) -> Result<Self> {
        let disposition =
            coding_development::inspect_capture(bytes, pin, expectations, expectations_pin)?;
        if disposition.status != "INCOMPLETE" || disposition.authority != "NONE" {
            return refuse("development classification differs");
        }
        let b = ArtifactBundle::unpack(bytes)?;
        let expected: serde_json::Value = coding_transfer::strict_json(expectations)?;
        let task = expected["task_sha256"]
            .as_str()
            .ok_or_else(|| ApplyError::Refuse("missing development task".into()))?;
        // Stored in a separate digest domain; never a native head or capability.
        let batch = VerifiedCreateBatch {
            artifact: pin.into(),
            run: digest(b.run.run.run_id.as_bytes()),
            head: digest(b.run.run.execution_id.as_bytes()),
            semantic: b.semantic_identity()?.value,
            files: std::array::from_fn(|i| b.blobs[&b.run.outputs[i].digest.value].clone()),
            authorization: None,
        };
        Self::disposable_verified(batch, parent, task)
    }

    /// Adapter over the existing Stage 7 procedure verifier. The finalized
    /// archive, task/expectation pins and typed successful procedure are all
    /// checked before a disposable destination or Stage 8 session is created.
    #[cfg(feature = "receiver-fixtures")]
    pub fn disposable_procedure(
        bytes: &[u8],
        pin: &str,
        expectations: &[u8],
        expectations_pin: &str,
        procedure_pin: &str,
        parent: &Path,
    ) -> Result<Self> {
        let verified = super::fixtures::verify_development_procedure(
            bytes,
            pin,
            expectations,
            expectations_pin,
            procedure_pin,
        )?;
        let expected: serde_json::Value = coding_transfer::strict_json(expectations)?;
        let task = expected["task_sha256"]
            .as_str()
            .ok_or_else(|| ApplyError::Refuse("missing task pin".into()))?;
        verified.into_stage8(parent, task)
    }

    #[cfg(feature = "receiver-fixtures")]
    pub(super) fn disposable_verified(
        batch: VerifiedCreateBatch,
        parent: &Path,
        task: &str,
    ) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let p = Directory::open(parent)?;
        let mut random = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let root = parent.join(format!("stage8-{}", digest(&random)));
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        // Parent identity is checked around creation. Same-UID/root hostile
        // concurrent writers remain outside this exclusive-operator profile.
        if Directory::open(parent)?.identity()? != p.identity()? {
            return refuse("disposable parent replaced");
        }
        let destination = root.join("destination");
        let state = root.join("state");
        for path in [&destination, &state] {
            std::fs::DirBuilder::new().mode(0o700).create(path)?;
        }
        Self::prepare(batch, &destination, &state, task, true)
    }
}

#[cfg(all(
    test,
    feature = "receiver-fixtures",
    any(target_os = "macos", target_os = "linux")
))]
mod tests {
    use super::*;

    fn session(f: &super::super::tests::Fixture) -> Session {
        let batch = VerifiedCreateBatch {
            artifact: "a".repeat(64),
            run: "b".repeat(64),
            head: "c".repeat(64),
            semantic: "d".repeat(64),
            files: [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
            authorization: None,
        };
        Session::prepare(batch, &f.dest, &f.state, &"e".repeat(64), true).unwrap()
    }
    fn request(s: &Session, i: usize) -> Vec<u8> {
        serde_json::to_vec(&Request {
            approval: s.plan.approval_id().unwrap(),
            operation: s.plan.operations[i].clone(),
        })
        .unwrap()
    }
    #[test]
    fn exact_steps_use_shared_engine_and_only_finish_after_three() {
        let f = super::super::tests::Fixture::new();
        let mut s = session(&f);
        s.activate(s.grant_proposal().unwrap()).unwrap();
        for i in 0..3 {
            let bytes = request(&s, i);
            assert_ne!(s.dispatch(&bytes).status, "REFUSE");
            assert_eq!(std::fs::read_dir(&f.dest).unwrap().count(), i + 1);
            if i < 2 {
                assert!(s.verify().is_err());
            }
        }
        assert_eq!(s.verify().unwrap().status, "VERIFIED_FINAL_STATE");
        // A subsequent violation cannot be hidden behind earlier completion.
        let extra = request(&s, 0);
        assert_eq!(s.dispatch(&extra).status, "REFUSE");
        assert!(s.verify().is_err());
    }
    #[test]
    fn replacing_completed_state_with_identical_bytes_cannot_change_its_binding() {
        use std::os::unix::fs::PermissionsExt;
        let f = super::super::tests::Fixture::new();
        let mut s = session(&f);
        s.activate(s.grant_proposal().unwrap()).unwrap();
        for i in 0..3 {
            let bytes = request(&s, i);
            assert_ne!(s.dispatch(&bytes).status, "REFUSE");
        }
        assert!(s.verify().is_ok());
        let old = f.root.join("old-state");
        std::fs::rename(&f.state, &old).unwrap();
        std::fs::create_dir(&f.state).unwrap();
        std::fs::set_permissions(&f.state, std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["journal.jsonl", "receipt.json"] {
            std::fs::copy(old.join(name), f.state.join(name)).unwrap();
        }
        assert!(s.verify().is_err());
    }
    #[test]
    fn grant_task_destination_budget_and_expiry_are_not_self_granted() {
        for kind in 0..7 {
            let f = super::super::tests::Fixture::new();
            let mut s = session(&f);
            let mut grant = s.grant_proposal().unwrap();
            match kind {
                0 => grant.task_sha256 = "0".repeat(64),
                1 => grant.destination.inode += 1,
                2 => grant.network.push("127.0.0.1".into()),
                3 => grant.shell = true,
                4 => grant.max_requests += 1,
                5 => grant.expires_at_unix = 0,
                _ => grant.state.inode += 1,
            }
            assert!(s.activate(grant).is_err());
            assert!(s.activate(s.grant_proposal().unwrap()).is_err());
            let bytes = request(&s, 0);
            assert_eq!(s.dispatch(&bytes).status, "REFUSE");
            assert!(std::fs::read_dir(&f.dest).unwrap().next().is_none());
        }
    }
    #[test]
    fn parser_order_timeout_and_state_replacement_poison_before_further_effects() {
        for kind in 0..6 {
            let f = super::super::tests::Fixture::new();
            let mut s = session(&f);
            s.activate(s.grant_proposal().unwrap()).unwrap();
            let mut bytes = request(&s, 0);
            match kind {
                0 => bytes = request(&s, 1),
                1 => bytes = br#"{"approval":"x","approval":"y"}"#.to_vec(),
                2 => bytes = vec![b'x'; MAX_FRAME + 1],
                3 => s.started = Instant::now() - Duration::from_secs(11),
                4 => {
                    std::fs::rename(&f.state, f.root.join("old-state")).unwrap();
                    std::fs::create_dir(&f.state).unwrap();
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&f.state, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                }
                _ => bytes = br#"{"verify":true}"#.to_vec(),
            }
            assert_eq!(s.dispatch(&bytes).status, "REFUSE");
            let valid = request(&s, 0);
            assert_eq!(s.dispatch(&valid).status, "REFUSE");
            assert!(std::fs::read_dir(&f.dest).unwrap().next().is_none());
        }
    }
}

#[cfg(all(
    test,
    not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))
))]
mod unsupported_tests {
    use super::*;
    #[test]
    fn strict_profile_refuses_before_destination_access() {
        let v = VerifiedCreateBatch {
            artifact: "a".repeat(64),
            run: "b".repeat(64),
            head: "c".repeat(64),
            semantic: "d".repeat(64),
            files: [vec![], vec![], vec![]],
            authorization: None,
        };
        let result = Session::prepare(
            v,
            Path::new("/nonexistent-destination"),
            Path::new("/nonexistent-state"),
            &"e".repeat(64),
            true,
        );
        assert!(
            matches!(result, Err(ApplyError::Refuse(message)) if message.contains("UNSUPPORTED"))
        );
    }
}
