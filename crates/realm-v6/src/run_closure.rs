//! Host-owned, non-authorizing REALM V6 run-closure evidence.
//!
//! This module deliberately separates the kernel observation from the terminal
//! receipts it must be joined with.  A cgroup becoming empty is necessary, but
//! it is not enough to establish that a broker drained, that endpoints were
//! revoked, or that a writable descriptor was never transferred elsewhere.
use serde::Serialize;
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::fmt;

pub const RUN_CLOSURE_SCHEMA: &str = "realm.run-closure-proof/v4";
pub const RUN_CLOSURE_ALGORITHM: &str = "cgroup-v2-kill-populated-pidfd-v4";

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RunTerminalIdentity {
    run_id: String,
    execution_id: String,
    capsule_id: String,
    process_identity: String,
    challenge_root: String,
    launch_root: String,
    vmm_identity_root: String,
    endpoint_root: String,
}

#[cfg(test)]
pub(crate) struct RunTerminalIdentityFields {
    pub(crate) run_id: String,
    pub(crate) execution_id: String,
    pub(crate) capsule_id: String,
    pub(crate) process_identity: String,
    pub(crate) challenge_root: String,
    pub(crate) launch_root: String,
    pub(crate) vmm_identity_root: String,
    pub(crate) endpoint_root: String,
}

#[cfg(test)]
impl RunTerminalIdentity {
    pub(crate) fn measured(fields: RunTerminalIdentityFields) -> Result<Self, ClosureRefusal> {
        let RunTerminalIdentityFields {
            run_id,
            execution_id,
            capsule_id,
            process_identity,
            challenge_root,
            launch_root,
            vmm_identity_root,
            endpoint_root,
        } = fields;
        if run_id.is_empty()
            || execution_id.is_empty()
            || !digest(&capsule_id)
            || !digest(&process_identity)
            || !digest(&challenge_root)
            || !digest(&launch_root)
            || !digest(&vmm_identity_root)
            || !digest(&endpoint_root)
        {
            return Err(ClosureRefusal::MalformedBinding);
        }
        Ok(Self {
            run_id,
            execution_id,
            capsule_id,
            process_identity,
            challenge_root,
            launch_root,
            vmm_identity_root,
            endpoint_root,
        })
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostRunBinding {
    identity: RunTerminalIdentity,
    vmm_identity: VmmIdentity,
    cgroup: CgroupIdentity,
}

#[cfg(test)]
impl HostRunBinding {
    /// This constructor is crate-private by design. The measured-launch adapter
    /// must be the only production caller; guest, runner, and broker inputs are
    /// not accepted as lifecycle authority.
    pub(crate) fn measured(
        identity: RunTerminalIdentity,
        vmm_identity: VmmIdentity,
        cgroup: CgroupIdentity,
    ) -> Result<Self, ClosureRefusal> {
        if vmm_identity.pid == 0
            || vmm_identity.start_ticks == 0
            || vmm_identity.pid_namespace_inode == 0
            || vmm_identity.cgroup_namespace_inode == 0
            || !digest(&vmm_identity.root)
            || vmm_identity.root != identity.vmm_identity_root
            || vmm_identity.cgroup != cgroup
            || cgroup.mount_id == 0
            || cgroup.inode == 0
        {
            return Err(ClosureRefusal::MalformedBinding);
        }
        Ok(Self {
            identity,
            vmm_identity,
            cgroup,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct VmmIdentity {
    pid: u32,
    start_ticks: u64,
    pid_namespace_inode: u64,
    cgroup_namespace_inode: u64,
    boot_id: String,
    cgroup: CgroupIdentity,
    birth_identity_root: String,
    root: String,
}

impl VmmIdentity {
    #[cfg(any(target_os = "linux", test))]
    fn measured(
        pid: u32,
        start_ticks: u64,
        pid_namespace_inode: u64,
        cgroup_namespace_inode: u64,
        boot_id: String,
        cgroup: &CgroupIdentity,
        birth_identity_root: String,
    ) -> Self {
        let mut hash = blake3::Hasher::new();
        hash.update(b"realm.vmm.pidfd.identity.v2\0");
        hash.update(&pid.to_le_bytes());
        hash.update(&start_ticks.to_le_bytes());
        hash.update(&pid_namespace_inode.to_le_bytes());
        hash.update(&cgroup_namespace_inode.to_le_bytes());
        hash.update(&(boot_id.len() as u64).to_le_bytes());
        hash.update(boot_id.as_bytes());
        hash.update(&cgroup.mount_id.to_le_bytes());
        hash.update(&cgroup.device.to_le_bytes());
        hash.update(&cgroup.inode.to_le_bytes());
        hash.update(birth_identity_root.as_bytes());
        let root = hash.finalize().to_hex().to_string();
        Self {
            pid,
            start_ticks,
            pid_namespace_inode,
            cgroup_namespace_inode,
            boot_id,
            cgroup: cgroup.clone(),
            birth_identity_root,
            root,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct CgroupIdentity {
    mount_id: u64,
    device: u64,
    inode: u64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum TerminalRootKind {
    CapabilityBoundary,
    EffectChannel,
    BrokerFrontier,
    CustodianEvidence,
    SemanticReceipt,
    VmmSubsystem,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TerminalBinding {
    identity: RunTerminalIdentity,
    terminal_epoch: u64,
    recovery_generation: u64,
}

#[cfg(test)]
impl TerminalBinding {
    pub(crate) fn measured(
        identity: RunTerminalIdentity,
        terminal_epoch: u64,
        recovery_generation: u64,
    ) -> Result<Self, ClosureRefusal> {
        if terminal_epoch == 0 {
            return Err(ClosureRefusal::MalformedTerminalRoot);
        }
        Ok(Self {
            identity,
            terminal_epoch,
            recovery_generation,
        })
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostTerminalRoot {
    binding: TerminalBinding,
    kind: TerminalRootKind,
    root: String,
}

#[cfg(test)]
impl HostTerminalRoot {
    /// Host adapters call this only after independently collecting and durably
    /// sealing the source subsystem's terminal record.
    pub(crate) fn measured(
        binding: TerminalBinding,
        kind: TerminalRootKind,
        root: String,
    ) -> Result<Self, ClosureRefusal> {
        if !digest(&root) {
            return Err(ClosureRefusal::MalformedTerminalRoot);
        }
        Ok(Self {
            binding,
            kind,
            root,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct KernelClosureObservation {
    cgroup: CgroupIdentity,
    vmm_identity: VmmIdentity,
    terminal_epoch: u64,
    recovery_generation: u64,
    kill_requested_boottime_ns: u64,
    populated_zero_boottime_ns: u64,
    vmm_pidfd_exit_observed: bool,
    raw_evidence_root: String,
    raw_cgroup_events: String,
    raw_cgroup_procs: String,
    raw_cgroup_threads: String,
    pidfd_poll_revents: i16,
}

impl KernelClosureObservation {
    #[cfg(target_os = "linux")]
    pub(crate) fn raw_evidence_root(&self) -> &str {
        &self.raw_evidence_root
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ClosureRefusal {
    MalformedBinding,
    MalformedTerminalRoot,
    WrongRun,
    WrongExecution,
    WrongCapsuleIdentity,
    WrongProcessIdentity,
    WrongChallenge,
    WrongLaunch,
    WrongVmmIncarnation,
    WrongEndpointSet,
    WrongTerminalEpoch,
    WrongRecoveryGeneration,
    DuplicateTerminalRoot,
    DuplicateKernelObservation,
    MissingTerminalRoot,
    KernelCgroupMismatch,
    KernelKillMissing,
    CgroupNotEmpty,
    VmmStillAlive,
    InvalidTimestamps,
}

#[cfg(test)]
impl fmt::Display for ClosureRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
impl std::error::Error for ClosureRefusal {}

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct ClosureJoin {
    binding: HostRunBinding,
    recovery_generation: u64,
    terminal_epoch: Option<u64>,
    roots: BTreeMap<TerminalRootKind, HostTerminalRoot>,
    kernel: Option<KernelClosureObservation>,
    poisoned: bool,
}

#[cfg(test)]
impl ClosureJoin {
    pub(crate) fn new(binding: HostRunBinding, recovery_generation: u64) -> Self {
        Self {
            binding,
            recovery_generation,
            terminal_epoch: None,
            roots: BTreeMap::new(),
            kernel: None,
            poisoned: false,
        }
    }

    pub(crate) fn attach_terminal_root(
        &mut self,
        root: HostTerminalRoot,
    ) -> Result<(), ClosureRefusal> {
        self.check_binding(&root)?;
        if let Some(epoch) = self.terminal_epoch {
            if root.binding.terminal_epoch != epoch {
                return self.poison(ClosureRefusal::WrongTerminalEpoch);
            }
        } else {
            self.terminal_epoch = Some(root.binding.terminal_epoch);
        }
        if self.roots.insert(root.kind, root).is_some() {
            return self.poison(ClosureRefusal::DuplicateTerminalRoot);
        }
        Ok(())
    }

    pub(crate) fn attach_kernel_observation(
        &mut self,
        observation: KernelClosureObservation,
    ) -> Result<(), ClosureRefusal> {
        if self.poisoned {
            return Err(ClosureRefusal::KernelCgroupMismatch);
        }
        if observation.cgroup != self.binding.cgroup {
            return self.poison(ClosureRefusal::KernelCgroupMismatch);
        }
        if observation.vmm_identity.cgroup != observation.cgroup {
            return self.poison(ClosureRefusal::KernelCgroupMismatch);
        }
        if observation.vmm_identity != self.binding.vmm_identity {
            return self.poison(ClosureRefusal::WrongVmmIncarnation);
        }
        if self.terminal_epoch != Some(observation.terminal_epoch) {
            return self.poison(ClosureRefusal::WrongTerminalEpoch);
        }
        if observation.recovery_generation != self.recovery_generation {
            return self.poison(ClosureRefusal::WrongRecoveryGeneration);
        }
        if self.kernel.is_some() {
            return self.poison(ClosureRefusal::DuplicateKernelObservation);
        }
        if observation.kill_requested_boottime_ns == 0
            || observation.populated_zero_boottime_ns < observation.kill_requested_boottime_ns
        {
            return self.poison(ClosureRefusal::InvalidTimestamps);
        }
        if parse_populated_snapshot(&observation.raw_cgroup_events) != Some(0)
            || !observation.raw_cgroup_procs.trim().is_empty()
            || !observation.raw_cgroup_threads.trim().is_empty()
        {
            return self.poison(ClosureRefusal::CgroupNotEmpty);
        }
        if !observation.vmm_pidfd_exit_observed
            || observation.pidfd_poll_revents & libc::POLLIN == 0
        {
            return self.poison(ClosureRefusal::VmmStillAlive);
        }
        if observation.raw_evidence_root != kernel_raw_root(&observation) {
            return self.poison(ClosureRefusal::InvalidTimestamps);
        }
        self.kernel = Some(observation);
        Ok(())
    }

    fn check_binding(&mut self, root: &HostTerminalRoot) -> Result<(), ClosureRefusal> {
        if self.poisoned {
            return Err(ClosureRefusal::WrongRun);
        }
        if root.binding.identity.run_id != self.binding.identity.run_id {
            return self.poison(ClosureRefusal::WrongRun);
        }
        if root.binding.identity.execution_id != self.binding.identity.execution_id {
            return self.poison(ClosureRefusal::WrongExecution);
        }
        if root.binding.identity.capsule_id != self.binding.identity.capsule_id {
            return self.poison(ClosureRefusal::WrongCapsuleIdentity);
        }
        if root.binding.identity.process_identity != self.binding.identity.process_identity {
            return self.poison(ClosureRefusal::WrongProcessIdentity);
        }
        if root.binding.identity.challenge_root != self.binding.identity.challenge_root {
            return self.poison(ClosureRefusal::WrongChallenge);
        }
        if root.binding.identity.launch_root != self.binding.identity.launch_root {
            return self.poison(ClosureRefusal::WrongLaunch);
        }
        if root.binding.identity.vmm_identity_root != self.binding.vmm_identity.root {
            return self.poison(ClosureRefusal::WrongVmmIncarnation);
        }
        if root.binding.identity.endpoint_root != self.binding.identity.endpoint_root {
            return self.poison(ClosureRefusal::WrongEndpointSet);
        }
        if root.binding.recovery_generation != self.recovery_generation {
            return self.poison(ClosureRefusal::WrongRecoveryGeneration);
        }
        Ok(())
    }

    fn poison<T>(&mut self, reason: ClosureRefusal) -> Result<T, ClosureRefusal> {
        self.poisoned = true;
        Err(reason)
    }

    pub(crate) fn seal(self) -> Result<RunClosureProofV3, ClosureRefusal> {
        if self.poisoned {
            return Err(ClosureRefusal::MissingTerminalRoot);
        }
        let required = [
            TerminalRootKind::CapabilityBoundary,
            TerminalRootKind::EffectChannel,
            TerminalRootKind::BrokerFrontier,
            TerminalRootKind::CustodianEvidence,
            TerminalRootKind::SemanticReceipt,
            TerminalRootKind::VmmSubsystem,
        ];
        if required.iter().any(|kind| !self.roots.contains_key(kind)) {
            return Err(ClosureRefusal::MissingTerminalRoot);
        }
        let Some(kernel) = self.kernel else {
            return Err(ClosureRefusal::KernelKillMissing);
        };
        if !kernel.vmm_pidfd_exit_observed {
            return Err(ClosureRefusal::VmmStillAlive);
        }
        if kernel.kill_requested_boottime_ns == 0
            || kernel.populated_zero_boottime_ns < kernel.kill_requested_boottime_ns
        {
            return Err(ClosureRefusal::CgroupNotEmpty);
        }
        let epoch = self
            .terminal_epoch
            .ok_or(ClosureRefusal::MissingTerminalRoot)?;
        let root = |kind| {
            self.roots
                .get(&kind)
                .map(|record| record.root.clone())
                .ok_or(ClosureRefusal::MissingTerminalRoot)
        };
        Ok(RunClosureProofV3 {
            schema: RUN_CLOSURE_SCHEMA,
            algorithm: RUN_CLOSURE_ALGORITHM,
            run_id: self.binding.identity.run_id,
            execution_id: self.binding.identity.execution_id,
            process_identity: self.binding.identity.process_identity,
            capsule_id: self.binding.identity.capsule_id,
            challenge_root: self.binding.identity.challenge_root,
            launch_root: self.binding.identity.launch_root,
            vmm_identity: self.binding.vmm_identity,
            endpoint_root: self.binding.identity.endpoint_root,
            cgroup: self.binding.cgroup,
            terminal_epoch: epoch,
            recovery_generation: self.recovery_generation,
            effect_channel_root: root(TerminalRootKind::EffectChannel)?,
            capability_boundary_root: root(TerminalRootKind::CapabilityBoundary)?,
            broker_frontier_root: root(TerminalRootKind::BrokerFrontier)?,
            custodian_evidence_root: root(TerminalRootKind::CustodianEvidence)?,
            semantic_receipt_root: root(TerminalRootKind::SemanticReceipt)?,
            vmm_subsystem_root: root(TerminalRootKind::VmmSubsystem)?,
            cgroup_kill_requested_boottime_ns: kernel.kill_requested_boottime_ns,
            cgroup_populated_zero_boottime_ns: kernel.populated_zero_boottime_ns,
            vmm_pidfd_exit_observed: kernel.vmm_pidfd_exit_observed,
            raw_kernel_evidence_root: kernel.raw_evidence_root.clone(),
            kernel_observation: kernel,
            _sealed: PrivateSeal,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunClosureProofV3 {
    schema: &'static str,
    algorithm: &'static str,
    run_id: String,
    execution_id: String,
    capsule_id: String,
    process_identity: String,
    challenge_root: String,
    launch_root: String,
    vmm_identity: VmmIdentity,
    endpoint_root: String,
    cgroup: CgroupIdentity,
    terminal_epoch: u64,
    recovery_generation: u64,
    effect_channel_root: String,
    capability_boundary_root: String,
    broker_frontier_root: String,
    custodian_evidence_root: String,
    semantic_receipt_root: String,
    vmm_subsystem_root: String,
    cgroup_kill_requested_boottime_ns: u64,
    cgroup_populated_zero_boottime_ns: u64,
    vmm_pidfd_exit_observed: bool,
    raw_kernel_evidence_root: String,
    kernel_observation: KernelClosureObservation,
    #[serde(skip)]
    _sealed: PrivateSeal,
}

impl RunClosureProofV3 {
    pub fn schema(&self) -> &'static str {
        self.schema
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub fn capsule_id(&self) -> &str {
        &self.capsule_id
    }

    pub(crate) fn process_identity(&self) -> &str {
        &self.process_identity
    }

    pub fn challenge_root(&self) -> &str {
        &self.challenge_root
    }

    pub fn launch_root(&self) -> &str {
        &self.launch_root
    }

    pub fn vmm_identity(&self) -> &str {
        &self.vmm_identity.root
    }

    pub(crate) fn vmm_birth_identity_root(&self) -> &str {
        &self.vmm_identity.birth_identity_root
    }

    pub fn endpoint_root(&self) -> &str {
        &self.endpoint_root
    }

    pub fn recovery_generation(&self) -> u64 {
        self.recovery_generation
    }

    pub(crate) fn terminal_epoch(&self) -> u64 {
        self.terminal_epoch
    }

    pub(crate) fn effect_channel_root(&self) -> &str {
        &self.effect_channel_root
    }

    pub(crate) fn broker_frontier_root(&self) -> &str {
        &self.broker_frontier_root
    }

    pub(crate) fn custodian_evidence_root(&self) -> &str {
        &self.custodian_evidence_root
    }

    pub(crate) fn semantic_receipt_root(&self) -> &str {
        &self.semantic_receipt_root
    }

    pub(crate) fn capability_boundary_root(&self) -> &str {
        &self.capability_boundary_root
    }

    pub(crate) fn raw_kernel_evidence_root(&self) -> &str {
        &self.raw_kernel_evidence_root
    }

    pub(crate) fn vmm_subsystem_root(&self) -> &str {
        &self.vmm_subsystem_root
    }

    pub(crate) fn matches_measured_vmm(
        &self,
        measured: &crate::measured_launch::VmmIncarnation,
    ) -> bool {
        self.vmm_identity.pid == measured.pid()
            && self.vmm_identity.start_ticks == measured.start_time_ticks()
            && self.vmm_identity.boot_id == measured.boot_id()
    }
}

/// Production issuer: the old arbitrary-root join remains test-only. These
/// inputs are live owned capabilities plus the existing Linux observer output.
#[cfg(target_os = "linux")]
pub(crate) fn issue_production(
    launch: &crate::measured_launch::ProductionContainedLaunch,
    frozen: &crate::broker_rpc::FrozenMeasuredBroker,
    semantic: &crate::integration::JoinedEvidence,
    custody: &crate::production_session::ClosedCustodian,
    capsule_id: &str,
    kernel: KernelClosureObservation,
) -> Result<RunClosureProofV3, &'static str> {
    let (run, frontier, semantic_root, epoch) = semantic.terminal_binding();
    let v = &kernel.vmm_identity;
    if !launch.supports_measured_brokered_c0_profile()
        || !launch.network_is_explicitly_empty()
        || launch.run_id() != frozen.run_id()
        || launch.execution_id() != frozen.execution_id()
        || launch.bound_challenge() != Some(frozen.challenge_root())
        || launch.run_id() != run
        || frontier != frozen.frontier_root()
        || epoch != "effects-frozen-v1"
        || launch.broker_endpoint_blake3() != frozen.endpoint_root()
        || custody.run_id != run
        || custody.frontier_root != frontier
        || launch.vmm_birth_identity_root() != Some(v.birth_identity_root.as_str())
        || v.pid != launch.vmm().pid()
        || v.start_ticks != launch.vmm().start_time_ticks()
        || v.boot_id != launch.vmm().boot_id()
        || v.pid_namespace_inode != launch.owned_pid_namespace_inode()
        || launch.owned_cgroup_device_inode() != (kernel.cgroup.device, kernel.cgroup.inode)
        || v.cgroup != kernel.cgroup
        || custody.process.pid() == v.pid
        || kernel.terminal_epoch != 1
        || kernel.recovery_generation != 0
        || frozen.frozen_boottime_ns == 0
        || kernel.kill_requested_boottime_ns < frozen.frozen_boottime_ns
        || kernel.populated_zero_boottime_ns < kernel.kill_requested_boottime_ns
        || !kernel.vmm_pidfd_exit_observed
        || kernel.pidfd_poll_revents & libc::POLLIN == 0
        || kernel.pidfd_poll_revents & (libc::POLLERR | libc::POLLNVAL) != 0
        || !kernel.raw_cgroup_procs.trim().is_empty()
        || !kernel.raw_cgroup_threads.trim().is_empty()
        || parse_production_populated(&kernel.raw_cgroup_events) != Some(0)
        || kernel.raw_evidence_root != kernel_raw_root(&kernel)
        || semantic.poweroff_observation_root() != Some(kernel.raw_evidence_root.as_str())
        || [
            capsule_id,
            semantic_root,
            frontier,
            &custody.root,
            &custody.journal_root,
        ]
        .iter()
        .any(|s| s.len() != 64)
    {
        return Err(
            "production closure identities, phase ordering or kernel observations disagree",
        );
    }
    let capability_boundary_root=blake3::hash(&serde_json::to_vec(&(
        "realm.supported-capability-closure/v1",frozen.root(),frozen.channel_root(),&custody.root,
        "rootfs-read-only;no-workspace-drive;broker-revoked;custodian-cleanly-reaped;explicit-child-fds",
    )).map_err(|_|"closure encoding failed")?).to_hex().to_string();
    Ok(RunClosureProofV3 {
        schema: RUN_CLOSURE_SCHEMA,
        algorithm: RUN_CLOSURE_ALGORITHM,
        run_id: run.into(),
        execution_id: launch.execution_id().into(),
        capsule_id: capsule_id.into(),
        process_identity: custody.process.root().into(),
        challenge_root: frozen.challenge_root().into(),
        launch_root: launch.canonical_hash_blake3().into(),
        vmm_identity: kernel.vmm_identity.clone(),
        endpoint_root: frozen.endpoint_root().into(),
        cgroup: kernel.cgroup.clone(),
        terminal_epoch: 1,
        recovery_generation: 0,
        effect_channel_root: frozen.channel_root(),
        capability_boundary_root,
        broker_frontier_root: frontier.into(),
        custodian_evidence_root: custody.root.clone(),
        semantic_receipt_root: semantic_root.into(),
        vmm_subsystem_root: launch.production_launch_root(),
        cgroup_kill_requested_boottime_ns: kernel.kill_requested_boottime_ns,
        cgroup_populated_zero_boottime_ns: kernel.populated_zero_boottime_ns,
        vmm_pidfd_exit_observed: kernel.vmm_pidfd_exit_observed,
        raw_kernel_evidence_root: kernel.raw_evidence_root.clone(),
        kernel_observation: kernel,
        _sealed: PrivateSeal,
    })
}
#[cfg(target_os = "linux")]
fn parse_production_populated(raw: &str) -> Option<u8> {
    let values = raw
        .lines()
        .filter_map(|line| line.strip_prefix("populated "))
        .collect::<Vec<_>>();
    if values.len() == 1 {
        values[0].parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct TestJoinInputs<'a> {
    pub(crate) run_id: &'a str,
    pub(crate) execution_id: &'a str,
    pub(crate) capsule_id: &'a str,
    pub(crate) process_identity: &'a str,
    pub(crate) challenge_root: &'a str,
    pub(crate) launch_root: &'a str,
    pub(crate) endpoint_root: &'a str,
    pub(crate) broker_frontier_root: &'a str,
    pub(crate) semantic_receipt_root: &'a str,
    pub(crate) vmm_pid_override: Option<u32>,
    pub(crate) vmm_birth_identity_override: Option<&'a str>,
}

#[cfg(test)]
pub(crate) fn test_proof_for_join(
    inputs: TestJoinInputs<'_>,
    vmm: &crate::measured_launch::VmmIncarnation,
) -> RunClosureProofV3 {
    let cgroup = CgroupIdentity {
        mount_id: 9,
        device: 10,
        inode: 11,
    };
    let vmm_pid = inputs.vmm_pid_override.unwrap_or_else(|| vmm.pid());
    let vmm_identity = VmmIdentity::measured(
        vmm_pid,
        vmm.start_time_ticks(),
        789,
        790,
        vmm.boot_id().into(),
        &cgroup,
        inputs
            .vmm_birth_identity_override
            .map(str::to_owned)
            .unwrap_or_else(|| blake3::hash(b"test-vmm-birth").to_hex().to_string()),
    );
    let vmm_root = vmm_identity.root.clone();
    let identity = RunTerminalIdentity::measured(RunTerminalIdentityFields {
        run_id: inputs.run_id.into(),
        execution_id: inputs.execution_id.into(),
        capsule_id: inputs.capsule_id.into(),
        process_identity: inputs.process_identity.into(),
        challenge_root: inputs.challenge_root.into(),
        launch_root: inputs.launch_root.into(),
        vmm_identity_root: vmm_root,
        endpoint_root: inputs.endpoint_root.into(),
    })
    .expect("test closure identity is well-formed");
    let binding = HostRunBinding::measured(identity.clone(), vmm_identity.clone(), cgroup.clone())
        .expect("test closure host binding is well-formed");
    let terminal_binding =
        TerminalBinding::measured(identity, 7, 2).expect("test terminal binding is well-formed");
    let digest = |label: &str| blake3::hash(label.as_bytes()).to_hex().to_string();
    let root_specs = [
        (
            TerminalRootKind::CapabilityBoundary,
            digest("capability-boundary"),
        ),
        (TerminalRootKind::EffectChannel, digest("effect-channel")),
        (
            TerminalRootKind::BrokerFrontier,
            inputs.broker_frontier_root.into(),
        ),
        (
            TerminalRootKind::CustodianEvidence,
            digest("custodian-evidence"),
        ),
        (
            TerminalRootKind::SemanticReceipt,
            inputs.semantic_receipt_root.into(),
        ),
        (TerminalRootKind::VmmSubsystem, digest("vmm-subsystem")),
    ];
    let mut join = ClosureJoin::new(binding, 2);
    for (kind, root) in root_specs {
        join.attach_terminal_root(
            HostTerminalRoot::measured(terminal_binding.clone(), kind, root)
                .expect("test terminal root is well-formed"),
        )
        .expect("test terminal root matches the same run");
    }
    let mut kernel = KernelClosureObservation {
        cgroup,
        vmm_identity,
        terminal_epoch: 7,
        recovery_generation: 2,
        kill_requested_boottime_ns: 100,
        populated_zero_boottime_ns: 200,
        vmm_pidfd_exit_observed: true,
        raw_evidence_root: String::new(),
        raw_cgroup_events: "populated 0\nfrozen 0\n".into(),
        raw_cgroup_procs: String::new(),
        raw_cgroup_threads: String::new(),
        pidfd_poll_revents: libc::POLLIN,
    };
    kernel.raw_evidence_root = kernel_raw_root(&kernel);
    join.attach_kernel_observation(kernel)
        .expect("test kernel closure is well-formed");
    join.seal().expect("test closure proof seals")
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct PrivateSeal;

#[cfg(test)]
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
fn parse_populated_snapshot(events: &str) -> Option<u8> {
    let mut found = None;
    for line in events.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() == Some("populated") {
            if found.is_some() {
                return None;
            }
            found = match (fields.next(), fields.next()) {
                (Some("0"), None) => Some(0),
                (Some("1"), None) => Some(1),
                _ => return None,
            };
        }
    }
    found
}

#[cfg(any(target_os = "linux", test))]
fn kernel_raw_root(observation: &KernelClosureObservation) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"realm.cgroup.close.raw.v3\0");
    hash.update(&observation.cgroup.mount_id.to_le_bytes());
    hash.update(&observation.cgroup.device.to_le_bytes());
    hash.update(&observation.cgroup.inode.to_le_bytes());
    hash.update(&observation.vmm_identity.pid.to_le_bytes());
    hash.update(&observation.vmm_identity.start_ticks.to_le_bytes());
    hash.update(&observation.vmm_identity.pid_namespace_inode.to_le_bytes());
    hash.update(
        &observation
            .vmm_identity
            .cgroup_namespace_inode
            .to_le_bytes(),
    );
    hash.update(&observation.vmm_identity.cgroup.mount_id.to_le_bytes());
    hash.update(&observation.vmm_identity.cgroup.device.to_le_bytes());
    hash.update(&observation.vmm_identity.cgroup.inode.to_le_bytes());
    for value in [
        observation.vmm_identity.boot_id.as_bytes(),
        observation.vmm_identity.birth_identity_root.as_bytes(),
        observation.vmm_identity.root.as_bytes(),
    ] {
        hash.update(&(value.len() as u64).to_le_bytes());
        hash.update(value);
    }
    hash.update(&observation.terminal_epoch.to_le_bytes());
    hash.update(&observation.recovery_generation.to_le_bytes());
    hash.update(&observation.kill_requested_boottime_ns.to_le_bytes());
    hash.update(&observation.populated_zero_boottime_ns.to_le_bytes());
    hash.update(&[u8::from(observation.vmm_pidfd_exit_observed)]);
    hash.update(&observation.pidfd_poll_revents.to_le_bytes());
    for raw in [
        observation.raw_cgroup_events.as_bytes(),
        observation.raw_cgroup_procs.as_bytes(),
        observation.raw_cgroup_threads.as_bytes(),
    ] {
        hash.update(&(raw.len() as u64).to_le_bytes());
        hash.update(raw);
    }
    hash.finalize().to_hex().to_string()
}

#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use super::{CgroupIdentity, KernelClosureObservation, VmmIdentity, kernel_raw_root};
    use std::fs;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;

    #[derive(Debug)]
    pub(crate) enum CgroupOpenError {
        NotCgroupV2,
        Unsupported(&'static str),
        Refused(&'static str),
        Io(io::Error),
        Malformed(&'static str),
    }

    impl From<io::Error> for CgroupOpenError {
        fn from(error: io::Error) -> Self {
            Self::Io(error)
        }
    }

    impl std::fmt::Display for CgroupOpenError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NotCgroupV2 => write!(f, "path is not on a cgroup-v2 filesystem"),
                Self::Unsupported(feature) => {
                    write!(f, "required kernel feature unavailable: {feature}")
                }
                Self::Refused(reason) => write!(f, "closure refused: {reason}"),
                Self::Io(error) => write!(f, "{error}"),
                Self::Malformed(input) => write!(f, "malformed kernel interface: {input}"),
            }
        }
    }

    impl std::error::Error for CgroupOpenError {}

    pub(crate) struct CgroupV2Run {
        dir: OwnedFd,
        path: PathBuf,
        expected_proc_path: String,
        identity: CgroupIdentity,
        remove_on_drop: bool,
    }

    pub(crate) struct PinnedVmm {
        pidfd: OwnedFd,
        identity: VmmIdentity,
    }

    impl PinnedVmm {
        pub(crate) fn measured_pid(&self) -> u32 {
            self.identity.pid
        }
    }

    /// Process identity captured while the pidfd returned by clone3 is held.
    /// This is a custody identifier; it does not claim what the process did.
    #[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
    pub(crate) struct RunOwnedProcessIdentity {
        pid: u32,
        start_ticks: u64,
        pid_namespace_inode: u64,
        cgroup_namespace_inode: u64,
        boot_id: String,
        cgroup: CgroupIdentity,
        root: String,
    }

    impl RunOwnedProcessIdentity {
        pub(crate) fn pid(&self) -> u32 {
            self.pid
        }

        pub(crate) fn start_ticks(&self) -> u64 {
            self.start_ticks
        }

        pub(crate) fn root(&self) -> &str {
            &self.root
        }

        pub(crate) fn matches_measured_vmm(
            &self,
            measured: &crate::measured_launch::VmmIncarnation,
        ) -> bool {
            self.pid == measured.pid()
                && self.start_ticks == measured.start_time_ticks()
                && self.boot_id == measured.boot_id()
                && self.pid_namespace_inode != 0
                && self.cgroup_namespace_inode != 0
                && self.cgroup.mount_id != 0
                && self.cgroup.device != 0
                && self.cgroup.inode != 0
                && lower_hex_64(&self.root)
        }
    }

    /// Child born directly into its run cgroup with a pidfd returned atomically.
    /// The pidfd is never recreated from a numeric PID.
    pub(crate) struct RunOwnedChild {
        pid: libc::pid_t,
        pidfd: OwnedFd,
        identity: RunOwnedProcessIdentity,
    }

    /// An explicitly granted descriptor for a run-owned child. All other
    /// inherited descriptors are closed before exec. Targets must be unique
    /// and in the bounded range 3..=4095.
    pub(crate) struct ChildFdMapping<'a> {
        pub(crate) source: &'a OwnedFd,
        pub(crate) target: libc::c_int,
    }

    pub(crate) struct ChildLaunch<'a> {
        pub(crate) program: &'a Path,
        pub(crate) arguments: &'a [&'a std::ffi::OsStr],
        pub(crate) working_directory: &'a Path,
        pub(crate) stdin: &'a fs::File,
        pub(crate) stdout: &'a fs::File,
        pub(crate) stderr: &'a fs::File,
    }

    struct PreparedChildFd {
        source: OwnedFd,
        target: libc::c_int,
    }

    impl RunOwnedChild {
        pub(crate) fn pid(&self) -> libc::pid_t {
            self.pid
        }

        #[cfg(test)]
        pub(crate) fn pidfd(&self) -> &OwnedFd {
            &self.pidfd
        }

        pub(crate) fn identity(&self) -> &RunOwnedProcessIdentity {
            &self.identity
        }

        pub(crate) fn wait_clean(
            self,
            timeout: Duration,
        ) -> Result<RunOwnedProcessIdentity, CgroupOpenError> {
            let deadline = Instant::now() + timeout;
            while !pidfd_exited(&self.pidfd)?.0 {
                if Instant::now() >= deadline {
                    return Err(CgroupOpenError::Refused("run-owned child did not close"));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let mut status = 0;
            if unsafe { libc::waitpid(self.pid, &mut status, 0) } != self.pid
                || !libc::WIFEXITED(status)
                || libc::WEXITSTATUS(status) != 0
            {
                return Err(CgroupOpenError::Refused(
                    "run-owned child did not exit cleanly",
                ));
            }
            Ok(self.identity)
        }
    }

    #[repr(C)]
    struct Clone3Args {
        flags: u64,
        pidfd: u64,
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
        set_tid: u64,
        set_tid_size: u64,
        cgroup: u64,
    }

    impl PinnedVmm {}

    impl CgroupV2Run {
        /// Create a uniquely named child below the supervisor's current cgroup.
        /// This succeeds only inside a delegated cgroup-v2 domain. It does not
        /// move the supervisor or any pre-existing process into the child.
        #[cfg(test)]
        pub(crate) fn create_for_current(execution_id: &str) -> Result<Self, CgroupOpenError> {
            if execution_id.is_empty() || execution_id.len() > 256 {
                return Err(CgroupOpenError::Malformed("invalid execution identity"));
            }
            let current = current_cgroup_directory()?;
            if read_path(&current.join("cgroup.type"))?.trim() != "domain" {
                return Err(CgroupOpenError::Unsupported("delegated domain cgroup"));
            }
            let current_procs = read_path(&current.join("cgroup.procs"))?;
            let own_pid = std::process::id().to_string();
            if !current_procs.lines().any(|line| line == own_pid) {
                return Err(CgroupOpenError::Malformed(
                    "supervisor is not in its reported cgroup",
                ));
            }
            let digest = blake3::hash(execution_id.as_bytes()).to_hex().to_string();
            let child = current.join(format!("realm-v6-{}", &digest[..24]));
            fs::create_dir(&child).map_err(|error| {
                if error.kind() == io::ErrorKind::PermissionDenied {
                    CgroupOpenError::Unsupported("delegated cgroup-v2 write access")
                } else {
                    CgroupOpenError::Io(error)
                }
            })?;
            match Self::open(&child) {
                Ok(mut run) => {
                    run.remove_on_drop = true;
                    Ok(run)
                }
                Err(error) => {
                    let _ = fs::remove_dir(&child);
                    Err(error)
                }
            }
        }

        /// Start a host helper with a pidfd at birth and place it in this run's
        /// cgroup before it can execute. Unsupported clone3/cgroup setups refuse.
        /// Start a child with a pidfd at birth, inside this run's cgroup, and
        /// pass only the explicitly mapped descriptors through exec.
        pub(crate) fn spawn_owned_with_fds(
            &self,
            launch: ChildLaunch<'_>,
            fd_mappings: &[ChildFdMapping<'_>],
        ) -> Result<RunOwnedChild, CgroupOpenError> {
            self.ensure_identity_stable()?;
            let (pid, pidfd) = clone3_exec_in_cgroup(launch, self.dir.as_raw_fd(), fd_mappings)?;
            let identity = match self.process_identity(&pidfd) {
                Ok(identity) => identity,
                Err(error) => {
                    let _ = pidfd_signal(&pidfd, libc::SIGKILL);
                    let _ = wait_child(pid);
                    let _ = self.kill_all();
                    let _ = self.wait_until_empty(Duration::from_secs(2));
                    return Err(error);
                }
            };
            if let Err(error) = self.ensure_identity_stable() {
                let _ = pidfd_signal(&pidfd, libc::SIGKILL);
                let _ = wait_child(pid);
                let _ = self.kill_all();
                let _ = self.wait_until_empty(Duration::from_secs(2));
                return Err(error);
            }
            Ok(RunOwnedChild {
                pid,
                pidfd,
                identity,
            })
        }

        fn process_identity(
            &self,
            pidfd: &OwnedFd,
        ) -> Result<RunOwnedProcessIdentity, CgroupOpenError> {
            let pid = pidfd_pid(pidfd)?;
            if process_cgroup(pid)? != self.expected_proc_path {
                return Err(CgroupOpenError::Malformed(
                    "clone3 child is outside its run cgroup",
                ));
            }
            let start_ticks = process_start_ticks(pid)?;
            let pid_namespace_inode = fs::metadata(format!("/proc/{pid}/ns/pid"))?.ino();
            let cgroup_namespace_inode = fs::metadata(format!("/proc/{pid}/ns/cgroup"))?.ino();
            let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .to_owned();
            let mut hash = blake3::Hasher::new();
            hash.update(b"realm.run-owned-process.identity.v1\0");
            hash.update(&pid.to_le_bytes());
            hash.update(&start_ticks.to_le_bytes());
            hash.update(&pid_namespace_inode.to_le_bytes());
            hash.update(&cgroup_namespace_inode.to_le_bytes());
            hash.update(&(boot_id.len() as u64).to_le_bytes());
            hash.update(boot_id.as_bytes());
            hash.update(&self.identity.mount_id.to_le_bytes());
            hash.update(&self.identity.device.to_le_bytes());
            hash.update(&self.identity.inode.to_le_bytes());
            Ok(RunOwnedProcessIdentity {
                pid,
                start_ticks,
                pid_namespace_inode,
                cgroup_namespace_inode,
                boot_id,
                cgroup: self.identity.clone(),
                root: hash.finalize().to_hex().to_string(),
            })
        }

        /// Open only a pre-created, non-root domain cgroup. The caller owns
        /// provisioning and must already have moved all run processes into it.
        pub(crate) fn open(path: &Path) -> Result<Self, CgroupOpenError> {
            if fs::symlink_metadata(path)?.file_type().is_symlink() {
                return Err(CgroupOpenError::Malformed("cgroup path is a symlink"));
            }
            let path = fs::canonicalize(path)?;
            let path_c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
                .map_err(|_| CgroupOpenError::Malformed("cgroup path contains NUL"))?;
            let fd = unsafe {
                libc::open(
                    path_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error().into());
            }
            let dir = unsafe { OwnedFd::from_raw_fd(fd) };
            let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut fs) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            if fs.f_type != CGROUP2_SUPER_MAGIC {
                return Err(CgroupOpenError::NotCgroupV2);
            }
            let metadata = fs::metadata(format!("/proc/self/fd/{}", dir.as_raw_fd()))?;
            let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", dir.as_raw_fd()))?;
            let mount_id = fdinfo
                .lines()
                .find_map(|line| line.strip_prefix("mnt_id:\t"))
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(CgroupOpenError::Malformed("fdinfo missing mnt_id"))?;
            let expected_proc_path = expected_cgroup_path(&path, mount_id)?;
            if read_at(&dir, "cgroup.type")?.trim() != "domain" {
                return Err(CgroupOpenError::Unsupported("domain cgroup"));
            }
            for required in [
                "cgroup.kill",
                "cgroup.events",
                "cgroup.procs",
                "cgroup.threads",
            ] {
                if !exists_at(&dir, required)? {
                    return Err(CgroupOpenError::Unsupported(required));
                }
            }
            Ok(Self {
                dir,
                path,
                expected_proc_path,
                identity: CgroupIdentity {
                    mount_id,
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
                remove_on_drop: false,
            })
        }

        /// First pidfd pin for the official jailer's adopted child, acquired
        /// while Firecracker is idle and before InstanceStart. This is not a
        /// claim that the pidfd was returned by clone3. The existing measured
        /// incarnation, the kernel's direct-child relationship, and this exact
        /// owned cgroup must all agree before any guest execution is permitted.
        pub(crate) fn pin_idle_adopted_vmm(
            &self,
            measured: &crate::measured_launch::VmmIncarnation,
        ) -> Result<(PinnedVmm, RunOwnedProcessIdentity), CgroupOpenError> {
            use std::os::fd::FromRawFd;
            let raw =
                unsafe { libc::syscall(libc::SYS_pidfd_open, measured.pid() as i32, 0) } as i32;
            if raw < 0 {
                return Err(io::Error::last_os_error().into());
            }
            let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
            let birth = self.process_identity(&pidfd)?;
            if !birth.matches_measured_vmm(measured) {
                return Err(CgroupOpenError::Malformed(
                    "adopted VMM differs from measured incarnation",
                ));
            }
            let mut child: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // waitid on this held pidfd rejects a process that is not our child.
            // WNOWAIT preserves lifecycle ownership; an exited child refuses.
            if unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    pidfd.as_raw_fd() as u32,
                    &mut child,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                return Err(io::Error::last_os_error().into());
            }
            if unsafe { child.si_pid() } != 0 || pidfd_exited(&pidfd)?.0 {
                return Err(CgroupOpenError::Refused(
                    "adopted VMM exited before InstanceStart",
                ));
            }
            let pinned = self.pin_vmm(pidfd, &birth)?;
            Ok((pinned, birth))
        }
        /// Pin the exact VMM incarnation while it is alive and verify that the
        /// pidfd still names the process measured at clone3 birth. A restarted
        /// supervisor that lost this pidfd may clean up by cgroup identity,
        /// but cannot recreate this proof input from a numeric PID.
        pub(crate) fn pin_vmm(
            &self,
            pidfd: OwnedFd,
            birth_identity: &RunOwnedProcessIdentity,
        ) -> Result<PinnedVmm, CgroupOpenError> {
            let pid = pidfd_pid(&pidfd)?;
            let observed_birth_identity = self.process_identity(&pidfd)?;
            if &observed_birth_identity != birth_identity || observed_birth_identity.pid != pid {
                return Err(CgroupOpenError::Malformed(
                    "VMM identity changed after clone3 birth measurement",
                ));
            }
            let pid_namespace_inode = observed_birth_identity.pid_namespace_inode;
            let cgroup_namespace_inode = observed_birth_identity.cgroup_namespace_inode;
            let supervisor_cgroup_namespace_inode = fs::metadata("/proc/self/ns/cgroup")?.ino();
            if cgroup_namespace_inode != supervisor_cgroup_namespace_inode {
                return Err(CgroupOpenError::Unsupported(
                    "VMM cgroup namespace differs from supervisor",
                ));
            }
            let identity = VmmIdentity::measured(
                pid,
                observed_birth_identity.start_ticks,
                pid_namespace_inode,
                cgroup_namespace_inode,
                observed_birth_identity.boot_id.clone(),
                &observed_birth_identity.cgroup,
                birth_identity.root().to_owned(),
            );
            Ok(PinnedVmm { pidfd, identity })
        }

        /// Remove a run cgroup only after every process and thread is gone.
        /// On refusal, preserve it for external recovery instead of hiding a
        /// surviving process by dropping evidence.
        pub(crate) fn remove_empty(&self) -> Result<(), CgroupOpenError> {
            self.ensure_identity_stable()?;
            let events = read_at(&self.dir, "cgroup.events")?;
            if parse_populated(&events)? != 0
                || !read_at(&self.dir, "cgroup.procs")?.trim().is_empty()
                || !read_at(&self.dir, "cgroup.threads")?.trim().is_empty()
            {
                return Err(CgroupOpenError::Refused("run cgroup is not empty"));
            }
            fs::remove_dir(&self.path)?;
            Ok(())
        }

        pub(crate) fn kill_all(&self) -> Result<(), CgroupOpenError> {
            self.ensure_identity_stable()?;
            write_at(&self.dir, "cgroup.kill", b"1")?;
            Ok(())
        }

        pub(crate) fn wait_until_empty(&self, timeout: Duration) -> Result<(), CgroupOpenError> {
            let started = Instant::now();
            loop {
                self.ensure_identity_stable()?;
                let events = read_at(&self.dir, "cgroup.events")?;
                if parse_populated(&events)? == 0
                    && read_at(&self.dir, "cgroup.procs")?.trim().is_empty()
                    && read_at(&self.dir, "cgroup.threads")?.trim().is_empty()
                {
                    return Ok(());
                }
                if started.elapsed() >= timeout {
                    return Err(CgroupOpenError::Refused("timeout waiting for cgroup empty"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        /// Uses cgroup.kill (which is designed to cover concurrent forks and
        /// migrations) then requires recursive populated=0, empty process and
        /// thread lists, and a readable pidfd for the measured VMM.
        pub(crate) fn kill_and_observe(
            &self,
            vmm: &PinnedVmm,
            terminal_epoch: u64,
            recovery_generation: u64,
            timeout: Duration,
        ) -> Result<KernelClosureObservation, CgroupOpenError> {
            if terminal_epoch == 0 {
                return Err(CgroupOpenError::Malformed("zero terminal epoch"));
            }
            write_at(&self.dir, "cgroup.kill", b"1")?;
            let kill_requested = boottime_ns()?;
            let started = Instant::now();
            loop {
                self.ensure_identity_stable()?;
                let events = read_at(&self.dir, "cgroup.events")?;
                let populated = parse_populated(&events)?;
                let procs = read_at(&self.dir, "cgroup.procs")?;
                let threads = read_at(&self.dir, "cgroup.threads")?;
                let (vmm_exited, poll_revents) = pidfd_exited(&vmm.pidfd)?;
                let procs_empty = procs.trim().is_empty();
                let threads_empty = threads.trim().is_empty();
                if populated == 0 && procs_empty && threads_empty && vmm_exited {
                    let populated_zero = boottime_ns()?;
                    let mut observation = KernelClosureObservation {
                        cgroup: self.identity.clone(),
                        vmm_identity: vmm.identity.clone(),
                        terminal_epoch,
                        recovery_generation,
                        kill_requested_boottime_ns: kill_requested,
                        populated_zero_boottime_ns: populated_zero,
                        vmm_pidfd_exit_observed: true,
                        raw_evidence_root: String::new(),
                        raw_cgroup_events: events,
                        raw_cgroup_procs: procs,
                        raw_cgroup_threads: threads,
                        pidfd_poll_revents: poll_revents,
                    };
                    observation.raw_evidence_root = kernel_raw_root(&observation);
                    return Ok(observation);
                }
                if started.elapsed() >= timeout {
                    return Err(CgroupOpenError::Refused("timeout or live cgroup member"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn ensure_identity_stable(&self) -> Result<(), CgroupOpenError> {
            let metadata = fs::metadata(format!("/proc/self/fd/{}", self.dir.as_raw_fd()))?;
            if metadata.dev() != self.identity.device || metadata.ino() != self.identity.inode {
                return Err(CgroupOpenError::Malformed("cgroup identity changed"));
            }
            let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", self.dir.as_raw_fd()))?;
            let mount_id = fdinfo
                .lines()
                .find_map(|line| line.strip_prefix("mnt_id:\t"))
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(CgroupOpenError::Malformed("fdinfo missing mnt_id"))?;
            if mount_id != self.identity.mount_id {
                return Err(CgroupOpenError::Malformed("cgroup mount identity changed"));
            }
            let current = fs::canonicalize(format!("/proc/self/fd/{}", self.dir.as_raw_fd()))?;
            if current != self.path {
                return Err(CgroupOpenError::Malformed(
                    "cgroup path was detached or replaced",
                ));
            }
            Ok(())
        }
    }

    fn clone3_exec_in_cgroup(
        launch: ChildLaunch<'_>,
        cgroup_fd: libc::c_int,
        fd_mappings: &[ChildFdMapping<'_>],
    ) -> Result<(libc::pid_t, OwnedFd), CgroupOpenError> {
        const CLONE_PIDFD_FLAG: u64 = 0x0000_1000;
        const CLONE_INTO_CGROUP_FLAG: u64 = 0x0002_0000_0000;
        let ChildLaunch {
            program,
            arguments,
            working_directory,
            stdin,
            stdout,
            stderr,
        } = launch;
        if !program.is_absolute() || !working_directory.is_absolute() || cgroup_fd < 0 {
            return Err(CgroupOpenError::Malformed(
                "run-owned launch requires absolute paths and a live cgroup fd",
            ));
        }
        let program_c = std::ffi::CString::new(program.as_os_str().as_bytes())
            .map_err(|_| CgroupOpenError::Malformed("program path contains NUL"))?;
        let mut argv_storage = Vec::with_capacity(arguments.len() + 1);
        argv_storage.push(program_c.clone());
        for argument in arguments {
            argv_storage.push(
                std::ffi::CString::new(argument.as_bytes())
                    .map_err(|_| CgroupOpenError::Malformed("argument contains NUL"))?,
            );
        }
        let mut argv = argv_storage
            .iter()
            .map(|argument| argument.as_ptr())
            .collect::<Vec<_>>();
        argv.push(std::ptr::null());
        let cwd = std::ffi::CString::new(working_directory.as_os_str().as_bytes())
            .map_err(|_| CgroupOpenError::Malformed("working directory contains NUL"))?;
        let envp = [std::ptr::null()];
        let prepared_fds = prepare_child_fd_mappings(fd_mappings)?;
        let mut pidfd_raw: libc::c_int = -1;
        let mut args = Clone3Args {
            flags: CLONE_PIDFD_FLAG | CLONE_INTO_CGROUP_FLAG,
            pidfd: (&mut pidfd_raw as *mut libc::c_int) as u64,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: libc::SIGCHLD as u64,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: cgroup_fd as u64,
        };
        // SAFETY: the ABI struct is Linux clone3's documented layout. All
        // pointers are parent-owned and remain valid until this call returns.
        let result = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                &mut args as *mut Clone3Args,
                std::mem::size_of::<Clone3Args>(),
            )
        };
        if result == 0 {
            // Keep the post-clone child path async-signal-safe until execve.
            unsafe {
                if libc::dup2(stdin.as_raw_fd(), libc::STDIN_FILENO) < 0
                    || libc::dup2(stdout.as_raw_fd(), libc::STDOUT_FILENO) < 0
                    || libc::dup2(stderr.as_raw_fd(), libc::STDERR_FILENO) < 0
                {
                    libc::_exit(126);
                }
                for mapping in &prepared_fds {
                    if libc::dup3(mapping.source.as_raw_fd(), mapping.target, 0) < 0 {
                        libc::_exit(126);
                    }
                }
                if libc::chdir(cwd.as_ptr()) < 0 || !close_unmapped_descriptors(&prepared_fds) {
                    libc::_exit(126);
                }
                libc::execve(program_c.as_ptr(), argv.as_mut_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }
        if result < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let pid = result as libc::pid_t;
        if pidfd_raw < 0 {
            // The child is still our unreaped child, so this PID cannot yet be
            // recycled while the fail-closed cleanup signal is issued.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let _ = wait_child(pid);
            return Err(CgroupOpenError::Malformed(
                "clone3 returned no requested pidfd",
            ));
        }
        Ok((pid, unsafe { OwnedFd::from_raw_fd(pidfd_raw) }))
    }

    fn prepare_child_fd_mappings(
        mappings: &[ChildFdMapping<'_>],
    ) -> Result<Vec<PreparedChildFd>, CgroupOpenError> {
        const MAX_MAPPINGS: usize = 64;
        const MAX_TARGET_FD: libc::c_int = 4095;
        if mappings.len() > MAX_MAPPINGS {
            return Err(CgroupOpenError::Malformed("too many child fd mappings"));
        }
        let mut targets = mappings
            .iter()
            .map(|mapping| mapping.target)
            .collect::<Vec<_>>();
        if targets
            .iter()
            .any(|target| !(3..=MAX_TARGET_FD).contains(target))
        {
            return Err(CgroupOpenError::Malformed(
                "child fd target is out of range",
            ));
        }
        targets.sort_unstable();
        if targets.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CgroupOpenError::Malformed("duplicate child fd target"));
        }
        let mut descriptor_limit: libc::rlimit = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut descriptor_limit) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if targets
            .last()
            .is_some_and(|target| *target as libc::rlim_t >= descriptor_limit.rlim_cur)
        {
            return Err(CgroupOpenError::Malformed(
                "child fd target exceeds the descriptor limit",
            ));
        }
        let minimum_source = targets.last().copied().unwrap_or(2).saturating_add(1);
        let mut prepared = Vec::with_capacity(mappings.len());
        for mapping in mappings {
            if unsafe { libc::fcntl(mapping.source.as_raw_fd(), libc::F_GETFD) } < 0 {
                return Err(CgroupOpenError::Malformed("child fd source is not open"));
            }
            let duplicate = unsafe {
                libc::fcntl(
                    mapping.source.as_raw_fd(),
                    libc::F_DUPFD_CLOEXEC,
                    minimum_source,
                )
            };
            if duplicate < 0 {
                return Err(io::Error::last_os_error().into());
            }
            prepared.push(PreparedChildFd {
                source: unsafe { OwnedFd::from_raw_fd(duplicate) },
                target: mapping.target,
            });
        }
        prepared.sort_unstable_by_key(|mapping| mapping.target);
        Ok(prepared)
    }

    /// Close every descriptor at or above 3 except the sorted, explicitly
    /// granted child targets. This function is called after clone3 in the child
    /// and uses only close_range syscalls.
    unsafe fn close_unmapped_descriptors(mappings: &[PreparedChildFd]) -> bool {
        let mut first = 3_u32;
        for mapping in mappings {
            let target = mapping.target as u32;
            if first < target {
                let result =
                    unsafe { libc::syscall(libc::SYS_close_range, first, target - 1, 0_u32) };
                if result < 0 {
                    return false;
                }
            }
            first = target + 1;
        }
        let result = unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 0_u32) };
        if result < 0 {
            return false;
        }
        true
    }

    fn pidfd_signal(pidfd: &OwnedFd, signal: libc::c_int) -> io::Result<()> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0_u32,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn wait_child(pid: libc::pid_t) -> io::Result<()> {
        loop {
            let result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
            if result == pid {
                return Ok(());
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
        }
    }

    fn lower_hex_64(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    impl Drop for CgroupV2Run {
        fn drop(&mut self) {
            if self.remove_on_drop {
                let _ = self.remove_empty();
            }
        }
    }

    #[cfg(test)]
    fn read_path(path: &Path) -> io::Result<String> {
        fs::read_to_string(path)
    }

    #[cfg(test)]
    fn current_cgroup_directory() -> Result<PathBuf, CgroupOpenError> {
        let contents = fs::read_to_string("/proc/self/cgroup")?;
        let mut paths = contents.lines().filter_map(|line| line.strip_prefix("0::"));
        let cgroup = paths.next().ok_or(CgroupOpenError::Malformed(
            "supervisor has no cgroup-v2 membership",
        ))?;
        if paths.next().is_some() || !cgroup.starts_with('/') || cgroup.contains("..") {
            return Err(CgroupOpenError::Malformed(
                "ambiguous supervisor cgroup membership",
            ));
        }
        let cgroup_path = Path::new(cgroup);
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        let mut matches = Vec::new();
        for line in mountinfo.lines() {
            let (before, after) = line
                .split_once(" - ")
                .ok_or(CgroupOpenError::Malformed("mountinfo separator"))?;
            let fields: Vec<_> = before.split_ascii_whitespace().collect();
            let post: Vec<_> = after.split_ascii_whitespace().collect();
            if fields.len() < 5 || post.first() != Some(&"cgroup2") {
                continue;
            }
            let root = PathBuf::from(unescape_mount_field(fields[3]));
            let mountpoint = PathBuf::from(unescape_mount_field(fields[4]));
            let Ok(relative) = cgroup_path.strip_prefix(&root) else {
                continue;
            };
            matches.push((root.components().count(), mountpoint.join(relative)));
        }
        matches
            .into_iter()
            .max_by_key(|(depth, _)| *depth)
            .map(|(_, path)| path)
            .ok_or(CgroupOpenError::Malformed(
                "supervisor cgroup is outside visible cgroup-v2 mounts",
            ))
    }

    fn expected_cgroup_path(path: &Path, mount_id: u64) -> Result<String, CgroupOpenError> {
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        for line in mountinfo.lines() {
            let (before, after) = line
                .split_once(" - ")
                .ok_or(CgroupOpenError::Malformed("mountinfo separator"))?;
            let fields: Vec<_> = before.split_ascii_whitespace().collect();
            let post: Vec<_> = after.split_ascii_whitespace().collect();
            if fields.len() < 5 || post.first() != Some(&"cgroup2") {
                continue;
            }
            if fields[0].parse::<u64>().ok() != Some(mount_id) {
                continue;
            }
            let root = unescape_mount_field(fields[3]);
            let mountpoint = PathBuf::from(unescape_mount_field(fields[4]));
            let relative = path
                .strip_prefix(&mountpoint)
                .map_err(|_| CgroupOpenError::Malformed("cgroup path outside its mount"))?;
            let root_path = PathBuf::from(root);
            let expected = root_path.join(relative);
            let text = expected
                .to_str()
                .ok_or(CgroupOpenError::Malformed("non-UTF8 cgroup path"))?;
            return Ok(if text.starts_with('/') {
                text.to_owned()
            } else {
                format!("/{text}")
            });
        }
        Err(CgroupOpenError::Malformed(
            "cgroup mount id not found in mountinfo",
        ))
    }

    fn unescape_mount_field(value: &str) -> String {
        value
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\")
    }

    fn pidfd_pid(pidfd: &OwnedFd) -> Result<u32, CgroupOpenError> {
        let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))?;
        let pid = info
            .lines()
            .find_map(|line| line.strip_prefix("Pid:\t"))
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(CgroupOpenError::Malformed("pidfd has no live Pid field"))?;
        Ok(pid)
    }

    fn process_cgroup(pid: u32) -> Result<String, CgroupOpenError> {
        let contents = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        let mut paths = contents.lines().filter_map(|line| line.strip_prefix("0::"));
        let path = paths.next().ok_or(CgroupOpenError::Malformed(
            "process has no cgroup-v2 membership",
        ))?;
        if paths.next().is_some() || !path.starts_with('/') || path.contains("..") {
            return Err(CgroupOpenError::Malformed(
                "ambiguous process cgroup membership",
            ));
        }
        Ok(path.to_owned())
    }

    fn process_start_ticks(pid: u32) -> Result<u64, CgroupOpenError> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let close = stat
            .rfind(')')
            .ok_or(CgroupOpenError::Malformed("process stat comm field"))?;
        let fields: Vec<_> = stat[close + 1..].split_ascii_whitespace().collect();
        fields
            .get(19)
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(CgroupOpenError::Malformed("process stat start time"))
    }

    fn open_at(dir: &OwnedFd, name: &str, flags: libc::c_int) -> io::Result<OwnedFd> {
        let name = std::ffi::CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn exists_at(dir: &OwnedFd, name: &str) -> io::Result<bool> {
        let name = std::ffi::CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                &mut metadata,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            if metadata.st_mode & libc::S_IFMT == libc::S_IFLNK {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "symlink cgroup control",
                ));
            }
            Ok(true)
        } else {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }

    fn read_at(dir: &OwnedFd, name: &str) -> io::Result<String> {
        use std::io::Read;
        let mut file = std::fs::File::from(open_at(dir, name, libc::O_RDONLY)?);
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        Ok(text)
    }

    fn write_at(dir: &OwnedFd, name: &str, value: &[u8]) -> io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::File::from(open_at(dir, name, libc::O_WRONLY)?);
        file.write_all(value)?;
        Ok(())
    }

    fn parse_populated(events: &str) -> Result<u8, CgroupOpenError> {
        let mut value = None;
        for line in events.lines() {
            let mut parts = line.split_ascii_whitespace();
            if parts.next() == Some("populated") {
                if value.is_some() {
                    return Err(CgroupOpenError::Malformed("duplicate populated key"));
                }
                value = match parts.next() {
                    Some("0") if parts.next().is_none() => Some(0),
                    Some("1") if parts.next().is_none() => Some(1),
                    _ => return Err(CgroupOpenError::Malformed("invalid populated value")),
                };
            }
        }
        value.ok_or(CgroupOpenError::Malformed("missing populated key"))
    }

    fn pidfd_exited(pidfd: &OwnedFd) -> io::Result<(bool, i16)> {
        let mut pollfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            result == 1 && pollfd.revents & (libc::POLLIN | libc::POLLHUP) != 0,
            pollfd.revents,
        ))
    }

    pub(crate) fn boottime_ns() -> io::Result<u64> {
        let mut time: libc::timespec = unsafe { std::mem::zeroed() };
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((time.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(time.tv_nsec as u64))
    }

    #[cfg(test)]
    mod fd_mapping_tests {
        use super::*;
        use std::os::fd::FromRawFd;

        fn null_fd() -> OwnedFd {
            let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            assert!(fd >= 0);
            unsafe { OwnedFd::from_raw_fd(fd) }
        }

        fn pipe_with_token(token: &[u8]) -> (OwnedFd, fs::File) {
            use std::io::Write;

            let mut pipe = [-1; 2];
            assert_eq!(
                unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            let reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
            let mut writer = fs::File::from(unsafe { OwnedFd::from_raw_fd(pipe[1]) });
            writer.write_all(token).unwrap();
            (reader, writer)
        }

        struct RemoveTestDirectory(PathBuf);

        impl Drop for RemoveTestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        struct KillAndReapOnDrop(RunOwnedChild);

        impl Drop for KillAndReapOnDrop {
            fn drop(&mut self) {
                let _ = pidfd_signal(self.0.pidfd(), libc::SIGKILL);
                let _ = wait_child(self.0.pid());
            }
        }

        #[test]
        fn child_fd_mapping_validation_is_bounded_and_non_ambiguous() {
            let source = null_fd();
            let duplicate_targets = [
                ChildFdMapping {
                    source: &source,
                    target: 3,
                },
                ChildFdMapping {
                    source: &source,
                    target: 3,
                },
            ];
            assert!(prepare_child_fd_mappings(&duplicate_targets).is_err());

            let reserved_target = [ChildFdMapping {
                source: &source,
                target: 2,
            }];
            assert!(prepare_child_fd_mappings(&reserved_target).is_err());

            let out_of_range_target = [ChildFdMapping {
                source: &source,
                target: 4096,
            }];
            assert!(prepare_child_fd_mappings(&out_of_range_target).is_err());

            let too_many = (0..65)
                .map(|index| ChildFdMapping {
                    source: &source,
                    target: index + 3,
                })
                .collect::<Vec<_>>();
            assert!(prepare_child_fd_mappings(&too_many).is_err());

            let valid = [
                ChildFdMapping {
                    source: &source,
                    target: 8,
                },
                ChildFdMapping {
                    source: &source,
                    target: 3,
                },
            ];
            let prepared = prepare_child_fd_mappings(&valid).unwrap();
            assert_eq!(
                prepared
                    .iter()
                    .map(|entry| entry.target)
                    .collect::<Vec<_>>(),
                [3, 8]
            );
            assert!(prepared.iter().all(|entry| entry.source.as_raw_fd() > 8));
        }

        #[test]
        #[ignore = "requires delegated cgroup-v2 and clone3 support; run explicitly on the qualified Linux host"]
        fn clone3_child_receives_only_explicit_fd_mappings() {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::OpenOptionsExt;

            let suffix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let state = std::env::temp_dir()
                .join(format!("realm-v6-fd-map-{}-{suffix}", std::process::id()));
            fs::create_dir(&state).unwrap();
            let _remove_state = RemoveTestDirectory(state.clone());
            let run =
                CgroupV2Run::create_for_current(&format!("fd-map-{}-{suffix}", std::process::id()))
                    .unwrap();

            let (reader_a, writer_a) = pipe_with_token(b"token-a\n");
            let (reader_b, writer_b) = pipe_with_token(b"token-b\n");
            drop(writer_a);
            drop(writer_b);
            let raw_source_a =
                unsafe { libc::fcntl(reader_a.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 70) };
            let raw_source_b =
                unsafe { libc::fcntl(reader_b.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 70) };
            assert_eq!((raw_source_a, raw_source_b), (70, 71));
            let source_a = unsafe { OwnedFd::from_raw_fd(raw_source_a) };
            let source_b = unsafe { OwnedFd::from_raw_fd(raw_source_b) };

            let raw_extra =
                unsafe { libc::fcntl(null_fd().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 80) };
            assert_eq!(raw_extra, 80);
            let extra = unsafe { OwnedFd::from_raw_fd(raw_extra) };
            assert_eq!(
                unsafe { libc::fcntl(extra.as_raw_fd(), libc::F_SETFD, 0) },
                0
            );

            let stdin = fs::File::open("/dev/null").unwrap();
            let stdout_path = state.join("stdout");
            let stdout = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&stdout_path)
                .unwrap();
            let stderr = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(state.join("stderr"))
                .unwrap();
            let script = std::ffi::OsStr::new(
                "read -r value70 <&70 || exit 11; read -r value71 <&71 || exit 12; [ \"$value70\" = token-b ] || exit 13; [ \"$value71\" = token-a ] || exit 14; [ ! -e /proc/$$/fd/80 ] || exit 15; printf granted; exec /bin/sleep 5",
            );
            let arguments = [std::ffi::OsStr::new("-c"), script];
            // Deliberately swap source descriptors 70 and 71 into those same
            // target numbers. Correct remapping requires parent-side copies;
            // a naive sequential dup3 would clobber the second source.
            let mappings = [
                ChildFdMapping {
                    source: &source_a,
                    target: 71,
                },
                ChildFdMapping {
                    source: &source_b,
                    target: 70,
                },
            ];
            let child = KillAndReapOnDrop(
                run.spawn_owned_with_fds(
                    ChildLaunch {
                        program: Path::new("/bin/bash"),
                        arguments: &arguments,
                        working_directory: &state,
                        stdin: &stdin,
                        stdout: &stdout,
                        stderr: &stderr,
                    },
                    &mappings,
                )
                .unwrap(),
            );
            assert_eq!(
                child.0.identity().cgroup,
                run.identity,
                "the child must be born inside the selected run cgroup"
            );

            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let output = fs::read_to_string(&stdout_path).unwrap_or_default();
                if output == "granted" {
                    break;
                }
                if pidfd_exited(child.0.pidfd()).unwrap().0 {
                    let _ = wait_child(child.0.pid());
                    let error_output = fs::read_to_string(state.join("stderr")).unwrap_or_default();
                    panic!("child refused mapped fd: stdout={output:?}, stderr={error_output:?}");
                }
                assert!(
                    Instant::now() < deadline,
                    "child did not report descriptor-map success before timeout"
                );
                std::thread::sleep(Duration::from_millis(10));
            }

            drop(child);
            run.wait_until_empty(Duration::from_secs(2)).unwrap();
            drop(extra);
            assert_eq!(fs::read_to_string(stdout_path).unwrap(), "granted");
            run.remove_empty().unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const F: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    fn vmm() -> VmmIdentity {
        let cgroup = CgroupIdentity {
            mount_id: 9,
            device: 10,
            inode: 11,
        };
        VmmIdentity::measured(123, 456, 789, 790, "boot-1".into(), &cgroup, A.into())
    }

    fn run_identity() -> RunTerminalIdentity {
        RunTerminalIdentity::measured(RunTerminalIdentityFields {
            run_id: "run-1".into(),
            execution_id: "execution-1".into(),
            capsule_id: A.into(),
            process_identity: D.into(),
            challenge_root: E.into(),
            launch_root: A.into(),
            vmm_identity_root: vmm().root,
            endpoint_root: C.into(),
        })
        .unwrap()
    }

    fn binding() -> HostRunBinding {
        HostRunBinding::measured(
            run_identity(),
            vmm(),
            CgroupIdentity {
                mount_id: 9,
                device: 10,
                inode: 11,
            },
        )
        .unwrap()
    }

    fn roots() -> Vec<HostTerminalRoot> {
        roots_for_generation(2)
    }

    fn roots_for_generation(recovery_generation: u64) -> Vec<HostTerminalRoot> {
        let binding = TerminalBinding::measured(run_identity(), 7, recovery_generation).unwrap();
        [
            (TerminalRootKind::CapabilityBoundary, E),
            (TerminalRootKind::EffectChannel, A),
            (TerminalRootKind::BrokerFrontier, B),
            (TerminalRootKind::CustodianEvidence, C),
            (TerminalRootKind::SemanticReceipt, D),
            (TerminalRootKind::VmmSubsystem, F),
        ]
        .into_iter()
        .map(|(kind, root)| HostTerminalRoot::measured(binding.clone(), kind, root.into()).unwrap())
        .collect()
    }

    fn kernel() -> KernelClosureObservation {
        kernel_for_generation(2)
    }

    fn kernel_for_generation(recovery_generation: u64) -> KernelClosureObservation {
        let mut observation = KernelClosureObservation {
            cgroup: CgroupIdentity {
                mount_id: 9,
                device: 10,
                inode: 11,
            },
            vmm_identity: vmm(),
            terminal_epoch: 7,
            recovery_generation,
            kill_requested_boottime_ns: 100,
            populated_zero_boottime_ns: 200,
            vmm_pidfd_exit_observed: true,
            raw_evidence_root: String::new(),
            raw_cgroup_events: "populated 0\nfrozen 0\n".into(),
            raw_cgroup_procs: String::new(),
            raw_cgroup_threads: String::new(),
            pidfd_poll_revents: libc::POLLIN,
        };
        observation.raw_evidence_root = kernel_raw_root(&observation);
        observation
    }

    #[test]
    fn requires_all_terminal_roots_and_kernel_observation_before_seal() {
        let mut join = ClosureJoin::new(binding(), 2);
        for root in roots().into_iter().take(3) {
            join.attach_terminal_root(root).unwrap();
        }
        join.attach_kernel_observation(kernel()).unwrap();
        assert_eq!(
            join.seal().unwrap_err(),
            ClosureRefusal::MissingTerminalRoot
        );
    }

    #[test]
    fn seals_only_same_run_launch_vmm_endpoint_and_cgroup() {
        let mut join = ClosureJoin::new(binding(), 2);
        for root in roots() {
            join.attach_terminal_root(root).unwrap();
        }
        join.attach_kernel_observation(kernel()).unwrap();
        let proof = join.seal().unwrap();
        assert_eq!(proof.schema(), RUN_CLOSURE_SCHEMA);
        assert_eq!(proof.run_id(), "run-1");
        assert_eq!(proof.execution_id(), "execution-1");
        assert_eq!(proof.capsule_id(), A);
        assert_eq!(proof.process_identity(), D);
        assert_eq!(proof.challenge_root(), E);
        assert_eq!(proof.launch_root(), A);
        assert_eq!(proof.vmm_identity(), vmm().root);
        assert_eq!(proof.endpoint_root(), C);
        assert_eq!(proof.recovery_generation(), 2);
        let serialized = serde_json::to_value(&proof).unwrap();
        assert!(serialized.get("accept").is_none());
        assert!(serialized.get("verified").is_none());
        assert_eq!(
            serialized["kernel_observation"]["raw_cgroup_events"],
            "populated 0\nfrozen 0\n"
        );
    }

    #[test]
    fn refuses_cross_run_and_cross_incarnation_roots_and_poisons_join() {
        for (mut root, expected) in [
            (roots()[0].clone(), ClosureRefusal::WrongRun),
            (roots()[0].clone(), ClosureRefusal::WrongExecution),
            (roots()[0].clone(), ClosureRefusal::WrongCapsuleIdentity),
            (roots()[0].clone(), ClosureRefusal::WrongProcessIdentity),
            (roots()[0].clone(), ClosureRefusal::WrongChallenge),
            (roots()[0].clone(), ClosureRefusal::WrongLaunch),
            (roots()[0].clone(), ClosureRefusal::WrongVmmIncarnation),
            (roots()[0].clone(), ClosureRefusal::WrongEndpointSet),
        ] {
            match expected {
                ClosureRefusal::WrongRun => root.binding.identity.run_id = "run-2".into(),
                ClosureRefusal::WrongExecution => {
                    root.binding.identity.execution_id = "execution-2".into()
                }
                ClosureRefusal::WrongCapsuleIdentity => root.binding.identity.capsule_id = F.into(),
                ClosureRefusal::WrongProcessIdentity => {
                    root.binding.identity.process_identity = F.into()
                }
                ClosureRefusal::WrongChallenge => root.binding.identity.challenge_root = F.into(),
                ClosureRefusal::WrongLaunch => root.binding.identity.launch_root = D.into(),
                ClosureRefusal::WrongVmmIncarnation => {
                    root.binding.identity.vmm_identity_root = D.into()
                }
                ClosureRefusal::WrongEndpointSet => root.binding.identity.endpoint_root = D.into(),
                _ => unreachable!(),
            }
            let mut join = ClosureJoin::new(binding(), 0);
            assert_eq!(join.attach_terminal_root(root), Err(expected));
            assert_eq!(
                join.seal().unwrap_err(),
                ClosureRefusal::MissingTerminalRoot
            );
        }
    }

    #[test]
    fn refuses_mixed_epoch_duplicate_roots_live_vmm_and_unstable_cgroup() {
        let mut mixed_epoch = ClosureJoin::new(binding(), 1);
        for mut root in roots_for_generation(1) {
            if root.kind == TerminalRootKind::SemanticReceipt {
                root.binding.terminal_epoch += 1;
            }
            if mixed_epoch.attach_terminal_root(root).is_err() {
                break;
            }
        }
        assert_eq!(
            mixed_epoch.seal().unwrap_err(),
            ClosureRefusal::MissingTerminalRoot
        );

        let mut duplicate = ClosureJoin::new(binding(), 1);
        let first = roots_for_generation(1)[0].clone();
        duplicate.attach_terminal_root(first.clone()).unwrap();
        assert_eq!(
            duplicate.attach_terminal_root(first),
            Err(ClosureRefusal::DuplicateTerminalRoot)
        );

        let mut live = ClosureJoin::new(binding(), 1);
        for root in roots_for_generation(1) {
            live.attach_terminal_root(root).unwrap();
        }
        let mut observation = kernel_for_generation(1);
        observation.vmm_pidfd_exit_observed = false;
        assert_eq!(
            live.attach_kernel_observation(observation),
            Err(ClosureRefusal::VmmStillAlive)
        );

        let mut changed = ClosureJoin::new(binding(), 1);
        for root in roots_for_generation(1) {
            changed.attach_terminal_root(root).unwrap();
        }
        let mut observation = kernel_for_generation(1);
        observation.cgroup.inode += 1;
        assert_eq!(
            changed.attach_kernel_observation(observation),
            Err(ClosureRefusal::KernelCgroupMismatch)
        );

        let mut stale_epoch = ClosureJoin::new(binding(), 1);
        for root in roots_for_generation(1) {
            stale_epoch.attach_terminal_root(root).unwrap();
        }
        let mut observation = kernel_for_generation(1);
        observation.terminal_epoch += 1;
        assert_eq!(
            stale_epoch.attach_kernel_observation(observation),
            Err(ClosureRefusal::WrongTerminalEpoch)
        );
    }

    #[test]
    fn invalid_digest_and_zero_epoch_fail_before_the_join() {
        assert_eq!(
            RunTerminalIdentity::measured(RunTerminalIdentityFields {
                run_id: "r".into(),
                execution_id: "e".into(),
                capsule_id: A.into(),
                process_identity: A.into(),
                challenge_root: F.into(),
                launch_root: "not-a-digest".into(),
                vmm_identity_root: B.into(),
                endpoint_root: C.into(),
            }),
            Err(ClosureRefusal::MalformedBinding)
        );
        assert_eq!(
            TerminalBinding::measured(run_identity(), 0, 1),
            Err(ClosureRefusal::MalformedTerminalRoot)
        );
        let binding = TerminalBinding::measured(run_identity(), 1, 1).unwrap();
        assert_eq!(
            HostTerminalRoot::measured(binding, TerminalRootKind::BrokerFrontier, "bad".into()),
            Err(ClosureRefusal::MalformedTerminalRoot)
        );
    }

    #[test]
    fn kernel_snapshot_must_be_consistent_hash_bound_and_unique() {
        let mut dirty = kernel_for_generation(1);
        dirty.raw_cgroup_events = "populated 0\npopulated 1\n".into();
        dirty.raw_evidence_root = kernel_raw_root(&dirty);
        let mut join = ClosureJoin::new(binding(), 1);
        for root in roots_for_generation(1) {
            join.attach_terminal_root(root).unwrap();
        }
        assert_eq!(
            join.attach_kernel_observation(dirty),
            Err(ClosureRefusal::CgroupNotEmpty)
        );

        let mut tampered = kernel_for_generation(1);
        tampered.raw_evidence_root = D.into();
        let mut join = ClosureJoin::new(binding(), 1);
        for root in roots_for_generation(1) {
            join.attach_terminal_root(root).unwrap();
        }
        assert_eq!(
            join.attach_kernel_observation(tampered),
            Err(ClosureRefusal::InvalidTimestamps)
        );

        let mut foreign_birth_identity = kernel_for_generation(1);
        foreign_birth_identity.vmm_identity.birth_identity_root = F.into();
        foreign_birth_identity.raw_evidence_root = kernel_raw_root(&foreign_birth_identity);
        let mut join = ClosureJoin::new(binding(), 1);
        for root in roots_for_generation(1) {
            join.attach_terminal_root(root).unwrap();
        }
        assert_eq!(
            join.attach_kernel_observation(foreign_birth_identity),
            Err(ClosureRefusal::WrongVmmIncarnation)
        );

        let mut join = ClosureJoin::new(binding(), 1);
        for root in roots_for_generation(1) {
            join.attach_terminal_root(root).unwrap();
        }
        join.attach_kernel_observation(kernel_for_generation(1))
            .unwrap();
        assert_eq!(
            join.attach_kernel_observation(kernel_for_generation(1)),
            Err(ClosureRefusal::DuplicateKernelObservation)
        );
    }

    #[test]
    fn recovery_generation_is_part_of_every_terminal_join() {
        let mut root_join = ClosureJoin::new(binding(), 1);
        assert_eq!(
            root_join.attach_terminal_root(roots()[0].clone()),
            Err(ClosureRefusal::WrongRecoveryGeneration)
        );

        let mut kernel_join = ClosureJoin::new(binding(), 1);
        for root in roots_for_generation(1) {
            kernel_join.attach_terminal_root(root).unwrap();
        }
        assert_eq!(
            kernel_join.attach_kernel_observation(kernel()),
            Err(ClosureRefusal::WrongRecoveryGeneration)
        );
    }

    #[test]
    fn refuses_rehashed_clone3_birth_identity_substitutions() {
        for counter in 0_u64..128 {
            let mut observation = kernel_for_generation(1);
            observation.vmm_identity.birth_identity_root =
                blake3::hash(format!("foreign-clone3-birth:{counter}").as_bytes())
                    .to_hex()
                    .to_string();
            observation.raw_evidence_root = kernel_raw_root(&observation);

            let mut join = ClosureJoin::new(binding(), 1);
            for root in roots_for_generation(1) {
                join.attach_terminal_root(root).unwrap();
            }
            assert_eq!(
                join.attach_kernel_observation(observation),
                Err(ClosureRefusal::WrongVmmIncarnation),
                "substituted clone3 birth root {counter} was accepted"
            );
        }
    }
}
