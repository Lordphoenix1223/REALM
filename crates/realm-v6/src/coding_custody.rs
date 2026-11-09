//! Native coding custodian ownership using the existing production child launcher.
//! This closes a process/custody boundary only, never coding publication authority.
use crate::coding_submission::custody_files::{object, open_snapshot, read_original};
use crate::{
    broker_rpc::{BrokerRpc, FrozenCodingBroker},
    coding_submission::{CodingExecutionScope, MAX_SUBMISSION, SubmissionContract},
    custody::{CustodyClient, audit_custody_against_frontier},
    execute::ExecuteError,
    frontier::{self, EffectFrontier, ObjectIdentity, RecordKind},
    measured_launch::{FileIdentity, MeasuredLaunchSession},
    production_session::ClosedCustodian,
    run_closure::linux::RunOwnedChild,
    supervisor::{CodingAuxiliaryClosed, CodingToolsLaunch, SupervisorError},
};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
fn bad(s: impl std::fmt::Debug) -> ExecuteError {
    ExecuteError::Supervisor(format!("{s:?}"))
}
fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
/// Live native-owned process and exact output descriptor. Private fields and no
/// deserializer prevent caller JSON from inventing child birth or custody I/O.
pub struct CodingCustody {
    binding: SubmissionContract,
    measurement_root: String,
    starting_world: String,
    session_root: String,
    monitor: String,
    child: RunOwnedChild,
    binary: FileIdentity,
    journal: PathBuf,
    snapshot: File,
    journal_snapshot: File,
    journal_identity: ObjectIdentity,
    frontier_snapshot: File,
    frontier_identity: ObjectIdentity,
    owner: (u32, u32),
    output_identity: ObjectIdentity,
    broker: BrokerRpc,
}
impl CodingCustody {
    /// Reuse C0's protected binary, explicit-FD/cgroup child birth, dedicated
    /// credentials, executable identity and READY/START checks unchanged.
    pub fn start(
        launch: &CodingToolsLaunch,
        scope: &CodingExecutionScope,
        challenge: &crate::mediation::MediationChallenge,
        starting_world: &str,
        binary: &Path,
        uid: u32,
        gid: u32,
    ) -> Result<Self, ExecuteError> {
        scope.validate().map_err(bad)?;
        let binding = &scope.submission;
        let measured = launch.measurement();
        let session = crate::mediation::MediationSessionBinding::from_measured_coding_launch(
            measured,
            scope,
            starting_world,
            challenge,
        )
        .map_err(bad)?;
        let session_root = session.root().to_owned();
        let monitor = measured.firecracker_identity().blake3().to_owned();
        if binding.run_id != measured.run_id()
            || binding.execution_id != measured.execution_id()
            || measured.bound_challenge() != Some(binding.challenge_root.as_str())
            || (uid, gid) == measured.vmm().owner()
            || uid == 0
            || gid == 0
            || starting_world.len() != 64
            || !starting_world
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(bad("native custody launch/scope/credentials differ"));
        }
        let (child, stream, output, journal, binary) = crate::production_session::open_custodian(
            launch.rootfs_launch(),
            binary,
            uid,
            gid,
            &binding.run_id,
            120_000,
        )?;
        let meta = output.metadata()?;
        if meta.len() != 0
            || meta.nlink() != 1
            || meta.uid() != uid
            || meta.gid() != gid
            || meta.mode() & 0o7777 != 0o600
        {
            return Err(bad(
                "native custody output is not original empty private object",
            ));
        }
        let before = std::collections::BTreeMap::from([(
            "output".to_string(),
            crate::filesystem_world::FilesystemObject::File {
                content_blake3: digest(b""),
                mode: 0o600,
            },
        )]);
        if digest(&serde_json::to_vec(&before).map_err(bad)?) != starting_world {
            return Err(bad(
                "native S0 must be exactly the actual empty packet output at0600",
            ));
        }
        let output_identity = object(&output)?;
        let snapshot = output.try_clone()?;
        let input = launch.state().join("coding-empty-input");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&input)?;
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
        file.sync_all()?;
        drop(file);
        let frontier = EffectFrontier::create_custodied(
            launch.state(),
            &binding.run_id,
            &monitor,
            &input,
            output,
            CustodyClient::new(stream, binding.run_id.clone()),
        )
        .map_err(bad)?;
        let broker = BrokerRpc::new_for_measured_session(frontier, session).map_err(bad)?;
        let journal_snapshot = open_snapshot(&journal)?;
        let journal_identity = object(&journal_snapshot)?;
        let frontier_snapshot = open_snapshot(broker.journal_path())?;
        let frontier_identity = object(&frontier_snapshot)?;
        Ok(Self {
            binding: binding.clone(),
            measurement_root: measured.canonical_hash_blake3().into(),
            starting_world: starting_world.into(),
            session_root,
            monitor,
            child,
            binary,
            journal,
            snapshot,
            output_identity,
            journal_snapshot,
            journal_identity,
            frontier_snapshot,
            frontier_identity,
            owner: (uid, gid),
            broker,
        })
    }
    pub fn birth_record(&self) -> serde_json::Value {
        serde_json::json!({"pid":self.child.pid(),"process":self.child.identity(),
            "output_object":self.output_identity,"journal":self.journal,"binary":self.binary,
            "frontier_state":self.journal.parent().and_then(|p|p.parent()),
            "broker_monitor":self.monitor,"broker_session_root":self.session_root,
            "authority":"NONE"})
    }
    pub fn broker(&mut self) -> &mut BrokerRpc {
        &mut self.broker
    }
    pub fn output_identity(&self) -> &ObjectIdentity {
        &self.output_identity
    }
    /// Actual submission/control/raw revocation must precede native seal, audit
    /// and clean child wait. Retirement follows this transition, never before it.
    pub fn seal_and_wait(
        mut self,
        closed: &CodingAuxiliaryClosed,
    ) -> Result<ClosedCodingCustody, ExecuteError> {
        let m = closed.measurement();
        if self.measurement_root != m.canonical_hash_blake3()
            || self.binding.run_id != m.run_id()
            || self.binding.execution_id != m.execution_id()
            || m.bound_challenge() != Some(self.binding.challenge_root.as_str())
        {
            return Err(bad("foreign coding closure/custodian"));
        }
        let barrier = closed.barrier_root().map_err(bad)?;
        let custody_head = self
            .broker
            .seal_custodian_after_barrier(&barrier)
            .map_err(bad)?;
        let frontier_path = self.broker.journal_path().to_path_buf();
        let expected_packet_digest = self.broker.output_content_digest().to_owned();
        let frozen = self
            .broker
            .freeze_coding_effects(closed, &barrier)
            .map_err(bad)?;
        let frontier_head = frozen.completion.frontier_root().to_owned();
        let raw_frontier = read_original(
            &mut self.frontier_snapshot,
            &frontier_path,
            &self.frontier_identity,
            (0, 0),
            4 * 1024 * 1024,
        )?;
        let audit = frontier::audit_bytes(&raw_frontier, &self.binding.run_id, &self.monitor)
            .map_err(bad)?;
        if audit.head != frontier_head
            || audit.committed_write_count != 1
            || audit.records().len() != 4
            || !audit.records().iter().map(|r| r.kind.clone()).eq([
                RecordKind::IntentWrite,
                RecordKind::ResultWrite,
                RecordKind::ResultClose,
                RecordKind::Seal,
            ])
            || audit.records().iter().any(|r| {
                r.mediation_manifest_root != self.session_root
                    || r.launch_identity != self.binding.execution_id
                    || r.starting_generation != self.starting_world
            })
        {
            return Err(bad(
                "native coding frontier differs from exact one-write/close profile",
            ));
        }
        let raw_custody = read_original(
            &mut self.journal_snapshot,
            &self.journal,
            &self.journal_identity,
            self.owner,
            4 * 1024 * 1024,
        )?;
        let custody = audit_custody_against_frontier(&raw_custody, &audit, &self.output_identity)
            .map_err(bad)?;
        let metadata = self.snapshot.metadata()?;
        if object(&self.snapshot)? != self.output_identity
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() == 0
            || metadata.len() > MAX_SUBMISSION as u64
        {
            return Err(bad("native output descriptor/size/permissions changed"));
        }
        let packet = read_original(
            &mut self.snapshot,
            &self
                .journal
                .parent()
                .ok_or_else(|| bad("custody parent missing"))?
                .join("output"),
            &self.output_identity,
            self.owner,
            MAX_SUBMISSION,
        )?;
        let submitted = self.binding.decode(&packet).map_err(bad)?;
        if packet.len() as u64 != metadata.len()
            || custody.head != custody_head
            || custody.committed_write_count != 1
            || custody.final_output_digest != digest(&packet)
            || expected_packet_digest != digest(&packet)
        {
            return Err(bad("native output/custody/packet agreement refused"));
        }
        let process = self
            .child
            .wait_clean(Duration::from_secs(10))
            .map_err(bad)?;
        if read_original(
            &mut self.frontier_snapshot,
            &frontier_path,
            &self.frontier_identity,
            (0, 0),
            4 * 1024 * 1024,
        )? != raw_frontier
            || read_original(
                &mut self.journal_snapshot,
                &self.journal,
                &self.journal_identity,
                self.owner,
                4 * 1024 * 1024,
            )? != raw_custody
            || read_original(
                &mut self.snapshot,
                &self
                    .journal
                    .parent()
                    .ok_or_else(|| bad("custody parent missing"))?
                    .join("output"),
                &self.output_identity,
                self.owner,
                MAX_SUBMISSION,
            )? != packet
        {
            return Err(bad("native files changed after clean custodian retirement"));
        }
        closed.revalidate().map_err(bad)?;
        let root = digest(
            &serde_json::to_vec(&(
                "realm.closed-coding-custody/v1",
                &self.binding,
                &self.measurement_root,
                &barrier,
                frozen.completion.root(),
                frozen.frozen_boottime_ns,
                &process,
                &self.binary,
                &custody_head,
                digest(&raw_custody),
                &frontier_head,
                digest(&raw_frontier),
                &self.output_identity,
                digest(&packet),
            ))
            .map_err(bad)?,
        );
        Ok(ClosedCodingCustody {
            native: ClosedCustodian {
                run_id: self.binding.run_id.clone(),
                process,
                frontier_root: frontier_head,
                journal_root: custody_head,
                root,
            },
            binding: self.binding,
            starting_world: self.starting_world,
            measurement_root: self.measurement_root,
            barrier,
            packet,
            output: self.output_identity,
            transcript_head: submitted.transcript_head,
            binary: self.binary,
            frontier_record_blake3: digest(&raw_frontier),
            custody_record_blake3: digest(&raw_custody),
            frozen,
        })
    }
}

/// Real native-owned custody closure, not a coding same-run publication token.
/// It retains the packet and original object plus the existing closed child
/// capability, so the next join need not reconstruct authority from a report.
pub struct ClosedCodingCustody {
    starting_world: String,
    native: ClosedCustodian,
    binding: SubmissionContract,
    measurement_root: String,
    barrier: String,
    packet: Vec<u8>,
    output: ObjectIdentity,
    transcript_head: String,
    binary: FileIdentity,
    frontier_record_blake3: String,
    custody_record_blake3: String,
    frozen: FrozenCodingBroker,
}
impl ClosedCodingCustody {
    pub(crate) fn publication_inputs(
        &self,
    ) -> (
        &CodingExecutionScope,
        &[u8],
        &ClosedCustodian,
        &FrozenCodingBroker,
        &str,
    ) {
        (
            &self.frozen.scope,
            &self.packet,
            &self.native,
            &self.frozen,
            &self.starting_world,
        )
    }
    pub(crate) fn validate_retired(
        &self,
        launch: &crate::measured_launch::MeasuredLaunchSession,
    ) -> Result<(), SupervisorError> {
        self.matches(launch, &self.barrier)
    }
    /// Run the build-pinned independent predicate through this actual run's
    /// owned helper launcher. This does not grant coding mediation or ACCEPT.
    pub fn verify_finite_task(
        &self,
        closed: &CodingAuxiliaryClosed,
        python: &Path,
    ) -> Result<crate::coding_referee::OwnedCodingTaskCheck, ExecuteError> {
        crate::coding_referee::native::verify(closed, self, python)
    }
    /// Observe semantic refusal as a distinct opaque owner; unknown child or
    /// input/subject/closure failure still returns an error, not a retry token.
    pub fn observe_finite_task(
        &self,
        closed: &CodingAuxiliaryClosed,
        python: &Path,
    ) -> Result<crate::coding_referee::OwnedCodingTaskOutcome, ExecuteError> {
        crate::coding_referee::native::observe(closed, self, python)
    }
    pub(crate) fn referee_inputs(
        &self,
        closed: &CodingAuxiliaryClosed,
    ) -> Result<(CodingExecutionScope, Vec<u8>, String, String), SupervisorError> {
        self.matches(closed.measurement(), &closed.barrier_root()?)?;
        Ok((
            self.frozen.scope.clone(),
            self.packet.clone(),
            self.native.root.clone(),
            self.frozen.completion.root().to_owned(),
        ))
    }
    pub(crate) fn matches(
        &self,
        measured: &MeasuredLaunchSession,
        barrier: &str,
    ) -> Result<(), SupervisorError> {
        if self.measurement_root != measured.prepared_measurement_root()
            || self.binding.run_id != measured.run_id()
            || self.binding.execution_id != measured.execution_id()
            || measured.bound_challenge() != Some(self.binding.challenge_root.as_str())
            || self.barrier != barrier
            || self.frozen.barrier != barrier
            || self.frozen.scope.submission != self.binding
            || self
                .frozen
                .scope
                .policy_identity()
                .map_err(|e| SupervisorError::Protocol(e.to_string()))?
                != *measured.policy_identity()
            || self.frozen.completion.challenge_root() != self.binding.challenge_root
            || self.frozen.completion.run_id() != measured.run_id()
            || self.frozen.completion.execution_id() != measured.execution_id()
            || self.frozen.completion.frontier_root() != self.native.frontier_root
        {
            return Err(SupervisorError::Protocol(
                "coding custody/closure binding differs".into(),
            ));
        }
        Ok(())
    }
    pub fn record(&self) -> serde_json::Value {
        serde_json::json!({"schema":"realm.native-owned-coding-custody/v1","binding":self.binding,
            "custodian_root":self.native.root,"process":self.native.process,"binary":self.binary,
            "frontier_record_blake3":self.frontier_record_blake3,"custody_record_blake3":self.custody_record_blake3,
            "frontier_head":self.native.frontier_root,
            "custody_head":self.native.journal_root,"barrier":self.barrier,"measurement_root":self.measurement_root,
            "packet_blake3":digest(&self.packet),"transcript_head":self.transcript_head,"output_object":self.output,"authority":"NONE",
            "native_wait_verified":true,"child_exit_status":0,"measured_broker_freeze":true,"broker_completion_root":self.frozen.completion.root(),
            "broker_session_root":self.frozen.completion.session_binding_root(),"prelaunch_scope":self.frozen.scope,
            "frozen_boottime_ns":self.frozen.frozen_boottime_ns,"independent_coding_semantics":false,"publication_capability":false})
    }
}
