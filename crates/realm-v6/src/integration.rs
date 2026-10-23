//! Non-authorizing join of actual broker I/O and the V2 semantic model.
//!
//! The broker preallocates an empty output; V2 models its logical creation.
//! Start/Open/Create/Close/Exit/Terminal in V2 remain declarations, not host
//! observations. This join proves consistency, never containment or quiescence.
use crate::frontier::{FrontierAudit, ObjectIdentity, RecordKind};
use crate::semantic_v2::{self as v2, Access, Action};
use crate::{
    Admission, Refusal,
    capsule::{BackendKind, CapsuleObservation, evidence_binding_root},
    measured_launch::{MeasuredLaunchSession, ProductionContainedLaunch},
    mediation::CheckedMediationClaim,
    run_closure::{RUN_CLOSURE_SCHEMA, RunClosureProofV3},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinContext {
    pub head: String,
    pub monitor_id: String,
    pub manifest_root: String,
    pub launch_identity: String,
    pub starting_generation: String,
    pub freeze_epoch: String,
    pub input: ObjectIdentity,
    pub output: ObjectIdentity,
}

#[derive(Debug)]
pub struct JoinedEvidence {
    semantic: v2::LocalVerified,
    binding: SemanticFrontierBinding,
}

#[derive(Debug)]
struct SemanticFrontierBinding {
    run_id: String,
    manifest_root: String,
    semantic_launch_root: String,
    semantic_argv: Vec<String>,
    semantic_policy_root: String,
    starting_generation: String,
    freeze_epoch: String,
    frontier_head: String,
    semantic_receipt_root: String,
    poweroff_observation_root: Option<String>,
}

/// A process-local same-run join. It is not serializable and is not public
/// ACCEPT; it records the exact input binding needed by the generation lane.
pub struct CheckedSameRunEvidence {
    root: String,
    run_id: String,
    execution_id: String,
    challenge_root: String,
    capsule_id: String,
    custody_process_identity: String,
    manifest_root: String,
    measured_launch_root: String,
    parent_generation: String,
    starting_world_root: String,
    final_world_root: String,
    delta_root: String,
    capsule_evidence_root: String,
}

impl CheckedSameRunEvidence {
    /// Content root for this process-local join. The root is evidence only and
    /// cannot reconstruct or serialize the joined capability.
    pub fn root(&self) -> &str {
        &self.root
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub(crate) fn matches_c1_evidence(&self, evidence: &crate::execute::CheckedC1Evidence) -> bool {
        let Ok(parsed) = crate::mediation::check_manifest_claim_shape(
            &evidence.c1_manifest,
            &evidence.c1_manifest_root,
        ) else {
            return false;
        };
        let manifest = parsed.manifest;
        self.root == evidence.same_run_join_root
            && self.run_id == evidence.run_id
            && self.execution_id == evidence.execution_id
            && self.challenge_root == evidence.challenge_binding
            && self.capsule_id == evidence.capsule_id
            && evidence.custody_process_identity.as_deref()
                == Some(self.custody_process_identity.as_str())
            && self.manifest_root == evidence.c1_manifest_root
            && self.measured_launch_root == manifest.measured_launch_blake3
            && self.parent_generation == evidence.accepted_start_root
            && manifest.starting_generation == self.starting_world_root
            && manifest.final_world == self.final_world_root
            && manifest.delta_root == self.delta_root
            && evidence.accepted_start_root == self.starting_world_root
            && evidence.accepted_final_root == self.final_world_root
            && evidence.accepted_delta_root == self.delta_root
            && self.capsule_evidence_root == evidence.evidence_root
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SameRunJoinRefusal {
    MissingHostObservation,
    UnsupportedBackend,
    WrongRun,
    WrongExecution,
    WrongCapsuleIdentity,
    MissingCustodyIdentity,
    WrongCustodyIdentity,
    WrongChallenge,
    WrongMeasuredLaunch,
    WrongVmmIncarnation,
    WrongEndpoint,
    WrongManifest,
    WrongParent,
    WrongSemanticReceipt,
    WrongFrontier,
    MissingBrokerCompletion,
    WrongTask,
    WrongPolicy,
    WrongWorld,
    WrongDelta,
    WrongEvidenceRoot,
}

#[derive(Serialize)]
struct SameRunJoinRoot<'a> {
    schema: &'static str,
    production_launch_root: Option<&'a str>,
    run_id: &'a str,
    execution_id: &'a str,
    custody_process_identity: &'a str,
    capsule_id: &'a str,
    challenge_root: &'a str,
    measured_launch_root: &'a str,
    vmm_identity_root: &'a str,
    vmm_birth_identity_root: &'a str,
    endpoint_root: &'a str,
    manifest_root: &'a str,
    mediation_session_root: &'a str,
    broker_completion_root: &'a str,
    parent_generation: &'a str,
    frontier_head: &'a str,
    semantic_receipt_root: &'a str,
    semantic_launch_root: &'a str,
    task_invocation_root: &'a str,
    policy_root: &'a str,
    freeze_epoch: &'a str,
    starting_world_root: &'a str,
    final_world_root: &'a str,
    delta_root: &'a str,
    capsule_evidence_root: &'a str,
    effect_channel_root: &'a str,
    capability_boundary_root: &'a str,
    custodian_root: &'a str,
    vmm_subsystem_root: &'a str,
    terminal_epoch: u64,
}
impl JoinedEvidence {
    pub(crate) fn poweroff_observation_root(&self) -> Option<&str> {
        self.binding.poweroff_observation_root.as_deref()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn terminal_binding(&self) -> (&str, &str, &str, &str) {
        (
            &self.binding.run_id,
            &self.binding.frontier_head,
            &self.binding.semantic_receipt_root,
            &self.binding.freeze_epoch,
        )
    }
    pub fn dependencies(&self) -> &[v2::ReadDependency] {
        self.semantic.dependencies()
    }
    /// Counterfactual predicate only. Callers cannot obtain a reuse capability.
    pub fn dependencies_match(&self, current: &v2::World) -> bool {
        self.semantic
            .dependencies_match(current, &Default::default())
    }
    pub fn admission(&self) -> Admission {
        Admission::Refuse(Refusal::UnverifiedBoundary)
    }

    /// A checked C1 claim and semantic join are still insufficient for
    /// terminal authority. This path remains refusal-only until the private
    /// host terminal join binds closure, freeze, and generation parent.
    pub fn admission_with_c1(
        &self,
        _claim: &CheckedMediationClaim,
        _observation: &CapsuleObservation,
    ) -> Admission {
        Admission::Refuse(Refusal::UnverifiedBoundary)
    }

    /// Production publication requires the actual canonical opaque capability.
    /// A direct measurement or a serialized handoff cannot enter this issuer.
    pub fn checked_same_run(
        &self,
        claim: &CheckedMediationClaim,
        observation: &CapsuleObservation,
        production: &ProductionContainedLaunch,
        closure: &RunClosureProofV3,
    ) -> Result<CheckedSameRunEvidence, SameRunJoinRefusal> {
        if !production.supports_measured_brokered_c0_profile() {
            return Err(SameRunJoinRefusal::UnsupportedBackend);
        }
        join_checked_same_run(
            self,
            claim,
            observation,
            production,
            closure,
            Some(production.production_launch_root()),
        )
    }

    #[cfg(test)]
    fn checked_test_same_run(
        &self,
        claim: &CheckedMediationClaim,
        observation: &CapsuleObservation,
        measured: &MeasuredLaunchSession,
        closure: &RunClosureProofV3,
    ) -> Result<CheckedSameRunEvidence, SameRunJoinRefusal> {
        join_checked_same_run(self, claim, observation, measured, closure, None)
    }
}
fn check(ok: bool) -> Result<(), Refusal> {
    if ok {
        Ok(())
    } else {
        Err(Refusal::DependencyMismatch)
    }
}

pub fn admission_for_c1(
    _claim: &CheckedMediationClaim,
    _observation: &CapsuleObservation,
) -> Admission {
    Admission::Refuse(Refusal::UnverifiedBoundary)
}
fn hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Checks every broker I/O in order against every semantic I/O. Expected roots
/// are caller claims until supplied by a protected host service; even coforged
/// arguments cannot produce public ACCEPT or REUSE.
pub fn join(
    audit: &FrontierAudit,
    input: &v2::Input,
    context: &JoinContext,
) -> Result<JoinedEvidence, Refusal> {
    let receipt = &input.receipt;
    let semantic = v2::validate(receipt, &input.expected)?;
    check(
        context.input != context.output
            && !context.manifest_root.is_empty()
            && !context.launch_identity.is_empty()
            && !context.starting_generation.is_empty()
            && context.freeze_epoch == receipt.health.epoch
            && context.starting_generation == receipt.authority_parent
            && context.launch_identity
                == hash(&serde_json::to_vec(&receipt.launch).map_err(|_| Refusal::Malformed)?)
            && audit.head == context.head
            && audit
                .records()
                .last()
                .is_some_and(|r| r.hash == context.head),
    )?;
    // The declared output is either pinned empty before service, or absent
    // until a journaled creation. Neither diagnostic profile grants authority.
    let prepared_output = receipt.initial.get("output");
    check(
        receipt.initial.len() == if prepared_output.is_some() { 2 } else { 1 }
            && receipt.initial.contains_key("input")
            && receipt.final_world.len() == 2
            && receipt.final_world.contains_key("output")
            && receipt.launch.allowed_inputs.as_slice() == ["input"]
            && receipt.launch.allowed_outputs.as_slice() == ["output"]
            && receipt.directories.is_empty(),
    )?;
    let initial = &receipt.initial["input"];
    let output = &receipt.final_world["output"];
    let mut input_version = hash(&initial.bytes);
    if let Some(prepared) = prepared_output {
        check(
            prepared.incarnation == output.incarnation
                && prepared.version == 0
                && prepared.bytes.is_empty()
                && prepared.mode == output.mode,
        )?;
    }
    let mut output_version = if prepared_output.is_some() {
        hash(
            format!(
                "output-v1:{}:{}:{}",
                context.output.device,
                context.output.inode,
                hash(&[])
            )
            .as_bytes(),
        )
    } else {
        crate::frontier::absent_output_version()
    };
    let mut output_bytes = Vec::new();
    let mut output_generation = 0u64;
    let mut operations = receipt
        .events
        .iter()
        .filter_map(|e| match &e.action {
            Action::Open { .. }
            | Action::Create { .. }
            | Action::Read { .. }
            | Action::Write { .. }
            | Action::Close { .. } => Some(&e.action),
            _ => None,
        })
        .peekable();
    let mut intent = None;
    let mut open_handles = std::collections::BTreeMap::<(u32, String), bool>::new();
    for record in audit.records() {
        check(
            record.run_id == receipt.run
                && record.monitor_id == context.monitor_id
                && record.mediation_manifest_root == context.manifest_root
                && record.launch_identity == context.launch_identity
                && record.starting_generation == context.starting_generation,
        )?;
        if record.kind == RecordKind::Seal {
            check(record.freeze_epoch.as_deref() == Some(context.freeze_epoch.as_str()))?;
            continue;
        }
        if record.kind == RecordKind::IntentCreate {
            check(
                prepared_output.is_none() && intent.is_none()
                    // Broker operation IDs are generated from the RPC stream;
                    // bind the matching result below instead of imposing a
                    // host-side fixture label on a real request.
                    && !record.operation_id.is_empty()
                    && record.object.is_none()
                    && record.object_version_before.as_ref() == Some(&output_version)
                    && record.object_version_after.is_none()
                    && record.requested == 0
                    && record.completed == 0
                    && record.bytes.is_empty(),
            )?;
            intent = Some(record);
            continue;
        }
        let is_output = record.object.as_ref() == Some(&context.output);
        check(is_output || record.object.as_ref() == Some(&context.input))?;
        let version = if is_output {
            &mut output_version
        } else {
            &mut input_version
        };
        check(record.object_version_before.as_ref() == Some(version))?;
        match record.kind {
            RecordKind::IntentCreate => unreachable!("handled before object matching"),
            RecordKind::ResultCreate => {
                check(intent.is_some_and(|pending| {
                    pending.kind == RecordKind::IntentCreate
                        && pending.operation_id == record.operation_id
                        && pending.object_version_before == record.object_version_before
                }))?;
                let Some(Action::Create {
                    fd,
                    handle,
                    path,
                    incarnation,
                    mode,
                }) = operations.next()
                else {
                    return Err(Refusal::DependencyMismatch);
                };
                let expected_incarnation =
                    hash(&serde_json::to_vec(&context.output).map_err(|_| Refusal::Malformed)?);
                let expected_effect_version = hash(
                    format!(
                        "output-v1:{}:{}:{}",
                        context.output.device,
                        context.output.inode,
                        hash(&[])
                    )
                    .as_bytes(),
                );
                check(
                    is_output
                        && record.offset == 0
                        && record.requested == 0
                        && record.completed == 0
                        && record.bytes.is_empty()
                        && record.object_version_before.as_ref() == Some(&output_version)
                        && record.object_version_after.as_ref() == Some(&expected_effect_version)
                        && *path == "output"
                        && *incarnation == expected_incarnation
                        && *mode == output.mode
                        && output.incarnation == expected_incarnation
                        && open_handles.insert((*fd, handle.clone()), true).is_none(),
                )?;
                output_version = expected_effect_version;
                output_generation = 0;
                intent = None;
            }
            RecordKind::IntentRead | RecordKind::IntentWrite => {
                let Some(action) = operations.peek() else {
                    return Err(Refusal::DependencyMismatch);
                };
                let handle_matches = match &**action {
                    Action::Read { fd, handle, .. } if record.kind == RecordKind::IntentRead => {
                        open_handles.get(&(*fd, handle.clone())) == Some(&is_output)
                    }
                    Action::Write { fd, handle, .. } if record.kind == RecordKind::IntentWrite => {
                        open_handles.get(&(*fd, handle.clone())) == Some(&is_output)
                    }
                    _ => false,
                };
                check(handle_matches)?;
                intent = Some(record);
            }
            RecordKind::ResultIdentify => {
                let Some(Action::Open {
                    fd,
                    handle,
                    path,
                    access,
                    ..
                }) = operations.next()
                else {
                    return Err(Refusal::DependencyMismatch);
                };
                check(
                    (path == "output") == is_output
                        && matches!(
                            (is_output, access),
                            (true, Access::Write) | (false, Access::Read)
                        )
                        && open_handles
                            .insert((*fd, handle.clone()), is_output)
                            .is_none()
                        && record.object_version_before.as_ref() == Some(version),
                )?;
            }
            RecordKind::ResultRead => {
                check(intent.is_some_and(|pending| {
                    pending.kind == RecordKind::IntentRead
                        && pending.operation_id == record.operation_id
                        && pending.offset == record.offset
                        && pending.requested == record.requested
                }))?;
                let Some(Action::Read {
                    fd,
                    handle,
                    incarnation,
                    version: semantic_version,
                    offset,
                    requested,
                    returned,
                    returned_length,
                    ..
                }) = operations.next()
                else {
                    return Err(Refusal::DependencyMismatch);
                };
                check(
                    open_handles.get(&(*fd, handle.clone())) == Some(&is_output)
                        && *incarnation
                            == if is_output {
                                output.incarnation.clone()
                            } else {
                                initial.incarnation.clone()
                            }
                        && *semantic_version
                            == if is_output {
                                output_generation
                            } else {
                                initial.version
                            }
                        && *offset == record.offset
                        && *requested == record.requested
                        && *returned_length == record.completed
                        && *returned == record.bytes,
                )?;
                intent = None;
            }
            RecordKind::ResultWrite => {
                check(intent.is_some_and(|pending| {
                    pending.kind == RecordKind::IntentWrite
                        && pending.operation_id == record.operation_id
                        && pending.offset == record.offset
                        && pending.requested == record.requested
                }))?;
                let Some(Action::Write {
                    fd,
                    handle,
                    incarnation,
                    before_version,
                    after_version,
                    offset,
                    requested,
                    returned_length,
                    ..
                }) = operations.next()
                else {
                    return Err(Refusal::DependencyMismatch);
                };
                let pending = intent.take().ok_or(Refusal::EventGap)?;
                check(
                    open_handles.get(&(*fd, handle.clone())) == Some(&is_output)
                        && is_output
                        && *incarnation == output.incarnation
                        && *before_version == output_generation
                        && *offset == record.offset
                        && *requested == pending.bytes
                        && *returned_length == record.completed,
                )?;
                let start = usize::try_from(record.offset).map_err(|_| Refusal::ResourceLimit)?;
                let end = start
                    .checked_add(record.bytes.len())
                    .ok_or(Refusal::ResourceLimit)?;
                check(end <= 4096 && start <= output_bytes.len())?;
                if record.completed > 0 {
                    output_bytes.resize(output_bytes.len().max(end), 0);
                    output_bytes[start..end].copy_from_slice(&record.bytes);
                    output_generation += 1;
                    *version = hash(
                        format!(
                            "output-write-v1:{}:{}:{}:{}",
                            version,
                            output_generation,
                            record.operation_id,
                            hash(&output_bytes)
                        )
                        .as_bytes(),
                    );
                }
                check(
                    *after_version == output_generation
                        && record.object_version_after.as_ref() == Some(version),
                )?;
            }
            RecordKind::ResultClose => {
                let Some(Action::Close { fd, handle }) = operations.next() else {
                    return Err(Refusal::DependencyMismatch);
                };
                check(
                    intent.is_none()
                        && open_handles.remove(&(*fd, handle.clone())) == Some(is_output)
                        && record.object_version_before.as_ref() == Some(version),
                )?;
            }
            RecordKind::ResultControl => return Err(Refusal::DependencyMismatch),
            RecordKind::Seal => unreachable!(),
        }
    }
    check(
        operations.next().is_none()
            && intent.is_none()
            && open_handles.is_empty()
            && output_bytes == output.bytes
            && output_generation == output.version,
    )?;
    let semantic_launch_root =
        hash(&serde_json::to_vec(&receipt.launch).map_err(|_| Refusal::Malformed)?);
    Ok(JoinedEvidence {
        semantic,
        binding: SemanticFrontierBinding {
            run_id: receipt.run.clone(),
            manifest_root: context.manifest_root.clone(),
            semantic_launch_root,
            semantic_argv: receipt.launch.argv.clone(),
            semantic_policy_root: receipt.launch.policy.clone(),
            starting_generation: receipt.authority_parent.clone(),
            freeze_epoch: context.freeze_epoch.clone(),
            frontier_head: audit.head.clone(),
            semantic_receipt_root: receipt.evidence_root.clone(),
            poweroff_observation_root: receipt.events.iter().find_map(|event| {
                match &event.action {
                    Action::Poweroff { observation_root } => Some(observation_root.clone()),
                    _ => None,
                }
            }),
        },
    })
}

fn join_checked_same_run(
    semantic: &JoinedEvidence,
    claim: &CheckedMediationClaim,
    observation: &CapsuleObservation,
    measured_launch: &MeasuredLaunchSession,
    closure: &RunClosureProofV3,
    production_launch_root: Option<String>,
) -> Result<CheckedSameRunEvidence, SameRunJoinRefusal> {
    let facts = observation.facts();
    let manifest = claim.manifest();
    if !observation.is_host_observed() {
        return Err(SameRunJoinRefusal::MissingHostObservation);
    }
    if facts.backend() != &BackendKind::FirecrackerMeasured {
        return Err(SameRunJoinRefusal::UnsupportedBackend);
    }
    let Some(broker_completion_root) = claim.broker_completion_root() else {
        return Err(SameRunJoinRefusal::MissingBrokerCompletion);
    };
    if facts.run_id() != &manifest.run_id
        || facts.run_id() != &semantic.binding.run_id
        || facts.run_id() != measured_launch.run_id()
        || facts.run_id() != closure.run_id()
    {
        return Err(SameRunJoinRefusal::WrongRun);
    }
    if facts.execution_id() != &manifest.launch_identity
        || facts.execution_id() != measured_launch.execution_id()
        || facts.execution_id() != closure.execution_id()
    {
        return Err(SameRunJoinRefusal::WrongExecution);
    }
    if facts.capsule_id() != closure.capsule_id() {
        return Err(SameRunJoinRefusal::WrongCapsuleIdentity);
    }
    let Some(custody_process_identity) = facts.custody_process_identity().as_deref() else {
        return Err(SameRunJoinRefusal::MissingCustodyIdentity);
    };
    if custody_process_identity != closure.process_identity() {
        return Err(SameRunJoinRefusal::WrongCustodyIdentity);
    }
    if facts.completion_evidence() != closure.challenge_root() {
        return Err(SameRunJoinRefusal::WrongChallenge);
    }
    if manifest.measured_launch_blake3 != measured_launch.canonical_hash_blake3()
        || manifest.measured_launch_blake3 != closure.launch_root()
        || !measured_launch.matches_manifest(manifest)
    {
        return Err(SameRunJoinRefusal::WrongMeasuredLaunch);
    }
    if measured_launch.vmm_birth_identity_root() != Some(closure.vmm_birth_identity_root())
        || !closure.matches_measured_vmm(measured_launch.vmm())
    {
        return Err(SameRunJoinRefusal::WrongVmmIncarnation);
    }
    if manifest.broker_endpoint_identity != measured_launch.broker_endpoint_blake3()
        || manifest.broker_endpoint_identity != closure.endpoint_root()
    {
        return Err(SameRunJoinRefusal::WrongEndpoint);
    }
    if claim.session_binding_root() != semantic.binding.manifest_root {
        return Err(SameRunJoinRefusal::WrongManifest);
    }
    if facts.starting_world() != &manifest.starting_generation
        || semantic.binding.starting_generation != manifest.starting_generation
    {
        return Err(SameRunJoinRefusal::WrongParent);
    }
    if semantic.binding.semantic_receipt_root != closure.semantic_receipt_root() {
        return Err(SameRunJoinRefusal::WrongSemanticReceipt);
    }
    if semantic.binding.frontier_head != closure.broker_frontier_root() {
        return Err(SameRunJoinRefusal::WrongFrontier);
    }
    if claim.broker_frontier_root() != Some(semantic.binding.frontier_head.as_str()) {
        return Err(SameRunJoinRefusal::WrongFrontier);
    }
    if !measured_launch.semantic_invocation_matches(&semantic.binding.semantic_argv)
        || manifest.task_blake3 != measured_launch.policy_identity().task_blake3()
    {
        return Err(SameRunJoinRefusal::WrongTask);
    }
    if semantic.binding.semantic_policy_root != manifest.host_policy_blake3 {
        return Err(SameRunJoinRefusal::WrongPolicy);
    }
    if facts.final_world().as_deref() != Some(manifest.final_world.as_str()) {
        return Err(SameRunJoinRefusal::WrongWorld);
    }
    if facts.delta_root() != &manifest.delta_root {
        return Err(SameRunJoinRefusal::WrongDelta);
    }
    if facts.evidence_root().as_deref() != Some(evidence_binding_root(facts).as_str()) {
        return Err(SameRunJoinRefusal::WrongEvidenceRoot);
    }
    if production_launch_root.is_some()
        && (facts.exit_code().is_some()
            || semantic.poweroff_observation_root() != Some(closure.raw_kernel_evidence_root()))
    {
        return Err(SameRunJoinRefusal::WrongSemanticReceipt);
    }
    if closure.schema() != RUN_CLOSURE_SCHEMA {
        return Err(SameRunJoinRefusal::WrongMeasuredLaunch);
    }

    let root_payload = SameRunJoinRoot {
        schema: "realm.same-run-publication-join/v5",
        production_launch_root: production_launch_root.as_deref(),
        run_id: facts.run_id(),
        execution_id: facts.execution_id(),
        custody_process_identity,
        capsule_id: facts.capsule_id(),
        challenge_root: closure.challenge_root(),
        measured_launch_root: measured_launch.canonical_hash_blake3(),
        vmm_identity_root: closure.vmm_identity(),
        vmm_birth_identity_root: closure.vmm_birth_identity_root(),
        endpoint_root: closure.endpoint_root(),
        manifest_root: claim.root(),
        mediation_session_root: claim.session_binding_root(),
        broker_completion_root,
        parent_generation: &manifest.starting_generation,
        frontier_head: &semantic.binding.frontier_head,
        semantic_receipt_root: &semantic.binding.semantic_receipt_root,
        semantic_launch_root: &semantic.binding.semantic_launch_root,
        task_invocation_root: &manifest.task_blake3,
        policy_root: &manifest.host_policy_blake3,
        freeze_epoch: &semantic.binding.freeze_epoch,
        starting_world_root: facts.starting_world(),
        final_world_root: facts.final_world().as_deref().expect("checked above"),
        delta_root: facts.delta_root(),
        capsule_evidence_root: facts.evidence_root().as_deref().expect("checked above"),
        effect_channel_root: closure.effect_channel_root(),
        capability_boundary_root: closure.capability_boundary_root(),
        custodian_root: closure.custodian_evidence_root(),
        vmm_subsystem_root: closure.vmm_subsystem_root(),
        terminal_epoch: closure.terminal_epoch(),
    };
    let bytes =
        serde_json::to_vec(&root_payload).map_err(|_| SameRunJoinRefusal::WrongEvidenceRoot)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"realm.same-run-publication-join.v5\0");
    hasher.update(&bytes);
    let root = hasher.finalize().to_hex().to_string();
    Ok(CheckedSameRunEvidence {
        root,
        run_id: facts.run_id().clone(),
        execution_id: facts.execution_id().clone(),
        challenge_root: closure.challenge_root().into(),
        capsule_id: facts.capsule_id().clone(),
        custody_process_identity: custody_process_identity.to_owned(),
        manifest_root: claim.root().into(),
        measured_launch_root: measured_launch.canonical_hash_blake3().into(),
        parent_generation: manifest.starting_generation.clone(),
        starting_world_root: facts.starting_world().clone(),
        final_world_root: facts
            .final_world()
            .as_deref()
            .expect("checked above")
            .into(),
        delta_root: facts.delta_root().clone(),
        capsule_evidence_root: facts
            .evidence_root()
            .as_deref()
            .expect("checked above")
            .into(),
    })
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn test_checked_same_run_evidence(
    evidence: &crate::execute::CheckedC1Evidence,
) -> CheckedSameRunEvidence {
    let parsed = crate::mediation::check_manifest_claim_shape(
        &evidence.c1_manifest,
        &evidence.c1_manifest_root,
    )
    .expect("test evidence contains a valid manifest");
    CheckedSameRunEvidence {
        root: evidence.same_run_join_root.clone(),
        run_id: evidence.run_id.clone(),
        execution_id: evidence.execution_id.clone(),
        challenge_root: evidence.challenge_binding.clone(),
        capsule_id: evidence.capsule_id.clone(),
        custody_process_identity: evidence
            .custody_process_identity
            .clone()
            .expect("test evidence includes custody identity"),
        manifest_root: evidence.c1_manifest_root.clone(),
        measured_launch_root: parsed.manifest.measured_launch_blake3,
        parent_generation: evidence.accepted_start_root.clone(),
        starting_world_root: evidence.accepted_start_root.clone(),
        final_world_root: evidence.accepted_final_root.clone(),
        delta_root: evidence.accepted_delta_root.clone(),
        capsule_evidence_root: evidence.evidence_root.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{capsule::CheckResult, frontier, semantic_v2 as v2};
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::MetadataExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        audit: FrontierAudit,
        input: v2::Input,
        context: JoinContext,
    }

    struct CheckedSameRunFixture {
        semantic: Fixture,
        _launch_fixture: crate::measured_launch::tests::Fixture,
        launch: crate::measured_launch::MeasuredLaunchSession,
        claim: crate::mediation::CheckedMediationClaim,
        observation: crate::capsule::CapsuleObservation,
        closure: crate::run_closure::RunClosureProofV3,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn hash(bytes: &[u8]) -> String {
        blake3::hash(bytes).to_hex().to_string()
    }

    fn fixture(run_id: &str, policy_byte: u8) -> Fixture {
        let run_id = hash(run_id.as_bytes());
        let parent = hash(b"same-run-parent");
        let manifest_root = hash(format!("manifest-{policy_byte}").as_bytes());
        let launch = v2::Launch {
            task: hash(b"task"),
            executable: hash(b"executable"),
            interpreter: None,
            libraries: Vec::new(),
            argv: vec!["test-task".into()],
            environment: BTreeMap::new(),
            cwd: "/work".into(),
            policy: hash(&[policy_byte]),
            generation: 0,
            allowed_inputs: vec!["input".into()],
            allowed_outputs: vec!["output".into()],
            time_rng_policy: hash(b"fixed"),
        };
        fixture_with_binding(run_id, parent, manifest_root, launch)
    }

    fn fixture_with_binding(
        run_id: String,
        parent: String,
        manifest_root: String,
        launch: v2::Launch,
    ) -> Fixture {
        let unique = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "realm-v6-same-run-join-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let input_bytes: Vec<u8> = (0..32).collect();
        let output_bytes = b"joined-output".to_vec();
        fs::write(root.join("input"), &input_bytes).unwrap();
        fs::write(root.join("output"), []).unwrap();
        let object_identity = |name: &str| {
            let metadata = fs::metadata(root.join(name)).unwrap();
            ObjectIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        };
        let epoch = "freeze-1".to_string();
        let launch_identity = hash(&serde_json::to_vec(&launch).unwrap());
        let mut broker = frontier::EffectFrontier::create(
            &root,
            &run_id,
            "same-run-join-test",
            &root.join("input"),
            &root.join("output"),
        )
        .unwrap();
        broker
            .bind_topology(&manifest_root, &launch_identity, &parent)
            .unwrap();
        broker.record_identify("input-open", false).unwrap();
        let returned = broker.read("input-read", false, 0, 8).unwrap();
        broker.record_close("input-close", false).unwrap();
        broker.record_identify("output-open", true).unwrap();
        let written = broker.write("output-write", 0, &output_bytes).unwrap();
        assert_eq!(written, output_bytes.len());
        broker.record_close("output-close", true).unwrap();
        let head = broker.seal(&epoch).unwrap();

        let process = "declared-process".to_string();
        let actions = vec![
            Action::Start { parent: None },
            Action::Open {
                fd: 0,
                handle: "input".into(),
                path: "input".into(),
                incarnation: "input-v1".into(),
                access: Access::Read,
            },
            Action::Read {
                fd: 0,
                handle: "input".into(),
                incarnation: "input-v1".into(),
                version: 0,
                offset: 0,
                requested: 8,
                returned: returned.clone(),
                returned_length: returned.len() as u64,
                end: v2::ReadEnd::Complete,
            },
            Action::Close {
                fd: 0,
                handle: "input".into(),
            },
            Action::Open {
                fd: 1,
                handle: "output".into(),
                path: "output".into(),
                incarnation: "output-v1".into(),
                access: Access::Write,
            },
            Action::Write {
                fd: 1,
                handle: "output".into(),
                incarnation: "output-v1".into(),
                before_version: 0,
                after_version: 1,
                offset: 0,
                requested: output_bytes.clone(),
                returned_length: output_bytes.len() as u64,
            },
            Action::Close {
                fd: 1,
                handle: "output".into(),
            },
            Action::Exit { code: 0 },
            Action::Terminal,
        ];
        let events = actions
            .into_iter()
            .enumerate()
            .map(|(sequence, action)| v2::Event {
                sequence: sequence as u64,
                run: run_id.clone(),
                process: process.clone(),
                epoch: epoch.clone(),
                action,
            })
            .collect::<Vec<_>>();
        let initial = BTreeMap::from([
            (
                "input".into(),
                v2::Object {
                    incarnation: "input-v1".into(),
                    version: 0,
                    bytes: input_bytes,
                    mode: 0o400,
                },
            ),
            (
                "output".into(),
                v2::Object {
                    incarnation: "output-v1".into(),
                    version: 0,
                    bytes: Vec::new(),
                    mode: 0o600,
                },
            ),
        ]);
        let mut final_world = initial.clone();
        final_world.insert(
            "output".into(),
            v2::Object {
                incarnation: "output-v1".into(),
                version: 1,
                bytes: output_bytes,
                mode: 0o600,
            },
        );
        let mut receipt = v2::Receipt {
            format: 2,
            run: run_id.clone(),
            authority_parent: parent.clone(),
            launch: launch.clone(),
            directories: Default::default(),
            initial: initial.clone(),
            events,
            dependencies: Vec::new(),
            final_world,
            health: v2::Health {
                epoch: epoch.clone(),
                source_count: 9,
                gaps: 0,
                duplicates: 0,
                reorder: 0,
                overflow: 0,
                restart: 0,
                partial: 0,
                delayed: 0,
                pending: 0,
                logger_died: false,
            },
            evidence_root: String::new(),
        };
        receipt.dependencies = v2::derive(&receipt).unwrap();
        v2::seal(&mut receipt).unwrap();
        let expected = v2::ExpectedContext {
            run: run_id.clone(),
            process,
            epoch: epoch.clone(),
            authority_parent: parent.clone(),
            launch,
            directories: Default::default(),
            initial,
            source_count: receipt.events.len() as u64,
            source_root: receipt.evidence_root.clone(),
        };
        let context = JoinContext {
            head,
            monitor_id: "same-run-join-test".into(),
            manifest_root,
            launch_identity,
            starting_generation: parent,
            freeze_epoch: epoch,
            input: object_identity("input"),
            output: object_identity("output"),
        };
        let audit =
            frontier::audit_journal(broker.journal_path(), &run_id, &context.monitor_id).unwrap();
        Fixture {
            root,
            audit,
            input: v2::Input { receipt, expected },
            context,
        }
    }

    fn checked_same_run_fixture() -> CheckedSameRunFixture {
        let launch_fixture = crate::measured_launch::tests::Fixture::new();
        let launch = launch_fixture.capture_c0_diagnostic_profile().unwrap();
        let mut manifest = crate::measured_launch::tests::matching_manifest(&launch);
        let parent = hash(b"checked-same-run-parent");
        let challenge =
            crate::mediation::MediationChallenge::test_only(&hash(b"checked-same-run-challenge"));
        let challenge_root = challenge.root().to_owned();
        manifest.starting_generation = parent.clone();
        manifest.final_world = hash(b"checked-same-run-final");
        manifest.delta_root = hash(b"checked-same-run-delta");
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_root = hash(&manifest_bytes);
        let semantic_launch = v2::Launch {
            task: manifest.task_blake3.clone(),
            executable: hash(b"checked-same-run-executable"),
            interpreter: None,
            libraries: Vec::new(),
            argv: vec!["test-task".into()],
            environment: BTreeMap::new(),
            cwd: "/work".into(),
            policy: manifest.host_policy_blake3.clone(),
            generation: 0,
            allowed_inputs: vec!["input".into()],
            allowed_outputs: vec!["output".into()],
            time_rng_policy: hash(b"checked-same-run-time-rng"),
        };
        let semantic_launch_identity =
            hash(&serde_json::to_vec(&semantic_launch).expect("semantic launch serializes"));
        let session_binding = crate::mediation::MediationSessionBinding::from_measured_launch(
            &launch,
            &semantic_launch_identity,
            &parent,
            &challenge,
        )
        .unwrap();
        let semantic = fixture_with_binding(
            launch.run_id().into(),
            parent.clone(),
            session_binding.root().into(),
            semantic_launch,
        );
        let completion = crate::mediation::MeasuredBrokerCompletion::test_only_from_sealed_session(
            &session_binding,
            &semantic.audit.head,
        );
        let process_identity = hash(b"checked-same-run-custody-process");
        let capsule_id = hash(b"checked-same-run-capsule");
        let mut facts = crate::capsule::CapsuleFacts {
            run_id: launch.run_id().into(),
            execution_id: launch.execution_id().into(),
            backend: BackendKind::FirecrackerMeasured,
            workspace_identity: parent.clone(),
            capsule_id: capsule_id.clone(),
            custody_process_identity: Some(process_identity.clone()),
            descendants: Vec::new(),
            starting_world: parent,
            final_world: Some(manifest.final_world.clone()),
            observed_effects: Vec::new(),
            exit_code: Some(0),
            crashed: false,
            quiescence: CheckResult::Verified,
            monitor_loss: CheckResult::Verified,
            network: CheckResult::Verified,
            filesystem: CheckResult::Verified,
            frozen: CheckResult::Verified,
            evidence_root: None,
            sequence_start: 0,
            sequence_end: Some(1),
            unsupported_effects: Vec::new(),
            runtime_identity: launch.runtime_identity().into(),
            network_policy_identity: launch.network_policy_blake3(),
            completion_evidence: challenge_root.clone(),
            finalization_evidence: hash(b"checked-same-run-finalization"),
            pause_snapshot_evidence: hash(b"checked-same-run-pause-snapshot"),
            vmm_terminal_observation_root: None,
            delta_root: manifest.delta_root.clone(),
        };
        facts.evidence_root = Some(crate::capsule::evidence_binding_root(&facts));
        let observation = crate::capsule::CapsuleObservation::from_host_facts(
            facts,
            "test-host-observation".into(),
        )
        .unwrap();
        let claim = crate::mediation::CheckedMediationClaim::issue_for_measured_session(
            &manifest_bytes,
            &manifest_root,
            &observation,
            &session_binding,
            &completion,
        )
        .unwrap();
        assert_eq!(claim.session_binding_root(), session_binding.root());
        assert_ne!(claim.root(), claim.session_binding_root());
        let closure = crate::run_closure::test_proof_for_join(
            crate::run_closure::TestJoinInputs {
                run_id: launch.run_id(),
                execution_id: launch.execution_id(),
                capsule_id: &capsule_id,
                process_identity: &process_identity,
                challenge_root: &challenge_root,
                launch_root: launch.canonical_hash_blake3(),
                endpoint_root: &launch.broker_endpoint_blake3(),
                broker_frontier_root: &semantic.audit.head,
                semantic_receipt_root: &semantic.input.receipt.evidence_root,
                vmm_pid_override: None,
                vmm_birth_identity_override: None,
            },
            launch.vmm(),
        );
        CheckedSameRunFixture {
            semantic,
            _launch_fixture: launch_fixture,
            launch,
            claim,
            observation,
            closure,
        }
    }

    #[test]
    fn semantic_join_retains_the_shutdown_observation_binding() {
        let mut fixture = fixture("shutdown-run", 1);
        let root = "a".repeat(64);
        let event = fixture
            .input
            .receipt
            .events
            .iter_mut()
            .find(|e| matches!(e.action, Action::Exit { .. }))
            .unwrap();
        event.action = Action::Poweroff {
            observation_root: root.clone(),
        };
        fixture.input.receipt.dependencies = v2::derive(&fixture.input.receipt).unwrap();
        v2::seal(&mut fixture.input.receipt).unwrap();
        fixture.input.expected.source_root = fixture.input.receipt.evidence_root.clone();
        let joined = join(&fixture.audit, &fixture.input, &fixture.context).unwrap();
        assert_eq!(joined.poweroff_observation_root(), Some(root.as_str()));
        assert_eq!(
            joined.admission(),
            Admission::Refuse(Refusal::UnverifiedBoundary)
        );
    }

    #[test]
    fn host_broker_and_semantic_join_produces_a_non_authorizing_binding() {
        let fixture = fixture("run-a", 1);
        let joined = join(&fixture.audit, &fixture.input, &fixture.context).unwrap();
        assert!(!joined.dependencies().is_empty());
        assert_eq!(
            joined.admission(),
            Admission::Refuse(Refusal::UnverifiedBoundary)
        );
        assert_eq!(joined.binding.run_id, hash(b"run-a"));
        assert_eq!(joined.binding.frontier_head, fixture.audit.head);
        assert_eq!(
            joined.binding.semantic_receipt_root,
            fixture.input.receipt.evidence_root
        );
    }

    #[test]
    fn private_terminal_join_binds_custody_process_identity() {
        let fixture = checked_same_run_fixture();
        let joined = join(
            &fixture.semantic.audit,
            &fixture.semantic.input,
            &fixture.semantic.context,
        )
        .unwrap();
        let checked = joined
            .checked_test_same_run(
                &fixture.claim,
                &fixture.observation,
                &fixture.launch,
                &fixture.closure,
            )
            .unwrap();
        assert_eq!(checked.run_id(), fixture.launch.run_id());
        assert_eq!(checked.execution_id(), fixture.launch.execution_id());

        let mut missing_custody_facts = fixture.observation.facts().clone();
        missing_custody_facts.custody_process_identity = None;
        let missing_custody_observation = crate::capsule::CapsuleObservation::from_host_facts(
            missing_custody_facts,
            "test-host-observation-without-custody".into(),
        )
        .unwrap();
        assert!(matches!(
            joined.checked_test_same_run(
                &fixture.claim,
                &missing_custody_observation,
                &fixture.launch,
                &fixture.closure,
            ),
            Err(SameRunJoinRefusal::MissingCustodyIdentity)
        ));

        let facts = fixture.observation.facts();
        let foreign_process = hash(b"foreign-custody-process");
        let foreign_closure = crate::run_closure::test_proof_for_join(
            crate::run_closure::TestJoinInputs {
                run_id: fixture.launch.run_id(),
                execution_id: fixture.launch.execution_id(),
                capsule_id: fixture.closure.capsule_id(),
                process_identity: &foreign_process,
                challenge_root: fixture.closure.challenge_root(),
                launch_root: fixture.launch.canonical_hash_blake3(),
                endpoint_root: &fixture.launch.broker_endpoint_blake3(),
                broker_frontier_root: &fixture.semantic.audit.head,
                semantic_receipt_root: &fixture.semantic.input.receipt.evidence_root,
                vmm_pid_override: None,
                vmm_birth_identity_override: None,
            },
            fixture.launch.vmm(),
        );
        assert_ne!(
            facts.custody_process_identity().as_deref(),
            Some(foreign_closure.process_identity())
        );
        assert!(matches!(
            joined.checked_test_same_run(
                &fixture.claim,
                &fixture.observation,
                &fixture.launch,
                &foreign_closure,
            ),
            Err(SameRunJoinRefusal::WrongCustodyIdentity)
        ));
    }

    #[test]
    fn private_terminal_join_requires_measured_broker_completion() {
        let fixture = checked_same_run_fixture();
        let joined = join(
            &fixture.semantic.audit,
            &fixture.semantic.input,
            &fixture.semantic.context,
        )
        .unwrap();
        let manifest_bytes = serde_json::to_vec(fixture.claim.manifest()).unwrap();
        let manifest_root = hash(&manifest_bytes);
        let claim = crate::mediation::CheckedMediationClaim::issue_c1_claim(
            &manifest_bytes,
            &manifest_root,
            &fixture.observation,
        )
        .unwrap();

        assert!(matches!(
            joined.checked_test_same_run(
                &claim,
                &fixture.observation,
                &fixture.launch,
                &fixture.closure,
            ),
            Err(SameRunJoinRefusal::MissingBrokerCompletion)
        ));
        assert!(fixture.claim.broker_completion_root().is_some());
    }

    #[test]
    fn private_terminal_join_rejects_measured_broker_frontier_substitution() {
        let fixture = checked_same_run_fixture();
        let joined = join(
            &fixture.semantic.audit,
            &fixture.semantic.input,
            &fixture.semantic.context,
        )
        .unwrap();
        let manifest_bytes = serde_json::to_vec(fixture.claim.manifest()).unwrap();
        let manifest_root = hash(&manifest_bytes);
        let session = crate::mediation::MediationSessionBinding::from_measured_launch(
            &fixture.launch,
            &fixture.semantic.context.launch_identity,
            &fixture.claim.manifest().starting_generation,
            &crate::mediation::MediationChallenge::test_only(
                fixture.observation.facts().completion_evidence(),
            ),
        )
        .unwrap();
        let foreign_completion =
            crate::mediation::MeasuredBrokerCompletion::test_only_from_sealed_session(
                &session,
                &hash(b"foreign broker frontier"),
            );
        let claim = crate::mediation::CheckedMediationClaim::issue_for_measured_session(
            &manifest_bytes,
            &manifest_root,
            &fixture.observation,
            &session,
            &foreign_completion,
        )
        .unwrap();

        assert!(matches!(
            joined.checked_test_same_run(
                &claim,
                &fixture.observation,
                &fixture.launch,
                &fixture.closure,
            ),
            Err(SameRunJoinRefusal::WrongFrontier)
        ));
    }

    #[test]
    fn measured_broker_completion_rejects_foreign_challenge() {
        let fixture = checked_same_run_fixture();
        let manifest_bytes = serde_json::to_vec(fixture.claim.manifest()).unwrap();
        let manifest_root = hash(&manifest_bytes);
        let foreign_challenge = hash(b"foreign challenge for same measured execution");
        let foreign_challenge = crate::mediation::MediationChallenge::test_only(&foreign_challenge);
        let binding = crate::mediation::MediationSessionBinding::from_measured_launch(
            &fixture.launch,
            &fixture.semantic.context.launch_identity,
            &fixture.claim.manifest().starting_generation,
            &foreign_challenge,
        )
        .unwrap();
        let completion = crate::mediation::MeasuredBrokerCompletion::test_only_from_sealed_session(
            &binding,
            &fixture.semantic.audit.head,
        );

        assert_eq!(
            crate::mediation::CheckedMediationClaim::issue_for_measured_session(
                &manifest_bytes,
                &manifest_root,
                &fixture.observation,
                &binding,
                &completion,
            ),
            Err(crate::mediation::MediationFailure::ChallengeMismatch)
        );
    }

    #[test]
    fn completion_cannot_attach_to_a_pre_run_binding_for_another_parent() {
        let fixture = checked_same_run_fixture();
        let trusted_parent = &fixture.claim.manifest().starting_generation;
        let foreign_binding = crate::mediation::MediationSessionBinding::from_measured_launch(
            &fixture.launch,
            &fixture.semantic.context.launch_identity,
            &hash(b"foreign-parent"),
            &crate::mediation::MediationChallenge::test_only(
                fixture.observation.facts().completion_evidence(),
            ),
        )
        .unwrap();
        let manifest_bytes = serde_json::to_vec(fixture.claim.manifest()).unwrap();
        let manifest_root = hash(&manifest_bytes);
        assert_eq!(
            crate::mediation::CheckedMediationClaim::issue_for_measured_session(
                &manifest_bytes,
                &manifest_root,
                &fixture.observation,
                &foreign_binding,
                &crate::mediation::MeasuredBrokerCompletion::test_only_from_sealed_session(
                    &crate::mediation::MediationSessionBinding::from_measured_launch(
                        &fixture.launch,
                        &fixture.semantic.context.launch_identity,
                        trusted_parent,
                        &crate::mediation::MediationChallenge::test_only(
                            fixture.observation.facts().completion_evidence(),
                        ),
                    )
                    .unwrap(),
                    &fixture.semantic.audit.head,
                ),
            ),
            Err(crate::mediation::MediationFailure::MeasuredSessionMismatch)
        );

        let mut foreign_manifest = fixture.claim.manifest().clone();
        let run_id = foreign_manifest.run_id.clone();
        let execution_id = foreign_manifest.launch_identity.clone();
        foreign_manifest.measured_launch_blake3 = hash(b"other measured VMM incarnation");
        let foreign_bytes = serde_json::to_vec(&foreign_manifest).unwrap();
        let foreign_root = hash(&foreign_bytes);
        let correct_binding = crate::mediation::MediationSessionBinding::from_measured_launch(
            &fixture.launch,
            &fixture.semantic.context.launch_identity,
            trusted_parent,
            &crate::mediation::MediationChallenge::test_only(
                fixture.observation.facts().completion_evidence(),
            ),
        )
        .unwrap();
        assert_eq!(foreign_manifest.run_id, run_id);
        assert_eq!(foreign_manifest.launch_identity, execution_id);
        assert_eq!(
            crate::mediation::CheckedMediationClaim::issue_for_measured_session(
                &foreign_bytes,
                &foreign_root,
                &fixture.observation,
                &correct_binding,
                &crate::mediation::MeasuredBrokerCompletion::test_only_from_sealed_session(
                    &correct_binding,
                    &fixture.semantic.audit.head,
                ),
            ),
            Err(crate::mediation::MediationFailure::MeasuredSessionMismatch)
        );
    }

    #[test]
    fn private_terminal_join_rejects_165_foreign_identity_compositions() {
        let fixture = checked_same_run_fixture();
        let joined = join(
            &fixture.semantic.audit,
            &fixture.semantic.input,
            &fixture.semantic.context,
        )
        .unwrap();
        let endpoint_root = fixture.launch.broker_endpoint_blake3();
        let cases = [
            SameRunJoinRefusal::WrongRun,
            SameRunJoinRefusal::WrongExecution,
            SameRunJoinRefusal::WrongCapsuleIdentity,
            SameRunJoinRefusal::WrongCustodyIdentity,
            SameRunJoinRefusal::WrongChallenge,
            SameRunJoinRefusal::WrongMeasuredLaunch,
            SameRunJoinRefusal::WrongEndpoint,
            SameRunJoinRefusal::WrongFrontier,
            SameRunJoinRefusal::WrongSemanticReceipt,
            SameRunJoinRefusal::WrongVmmIncarnation,
            SameRunJoinRefusal::WrongVmmIncarnation,
        ];

        for (class_index, expected) in cases.into_iter().enumerate() {
            for attempt in 0..15u32 {
                let foreign =
                    hash(format!("terminal-join-foreign-{class_index}-{attempt}").as_bytes());
                let mut inputs = crate::run_closure::TestJoinInputs {
                    run_id: fixture.launch.run_id(),
                    execution_id: fixture.launch.execution_id(),
                    capsule_id: fixture.closure.capsule_id(),
                    process_identity: fixture.closure.process_identity(),
                    challenge_root: fixture.closure.challenge_root(),
                    launch_root: fixture.launch.canonical_hash_blake3(),
                    endpoint_root: &endpoint_root,
                    broker_frontier_root: &fixture.semantic.audit.head,
                    semantic_receipt_root: &fixture.semantic.input.receipt.evidence_root,
                    vmm_pid_override: None,
                    vmm_birth_identity_override: None,
                };
                match class_index {
                    0 => inputs.run_id = &foreign,
                    1 => inputs.execution_id = &foreign,
                    2 => inputs.capsule_id = &foreign,
                    3 => inputs.process_identity = &foreign,
                    4 => inputs.challenge_root = &foreign,
                    5 => inputs.launch_root = &foreign,
                    6 => inputs.endpoint_root = &foreign,
                    7 => inputs.broker_frontier_root = &foreign,
                    8 => inputs.semantic_receipt_root = &foreign,
                    9 => inputs.vmm_pid_override = Some(70_000 + attempt),
                    10 => inputs.vmm_birth_identity_override = Some(&foreign),
                    _ => unreachable!(),
                }
                let closure = crate::run_closure::test_proof_for_join(inputs, fixture.launch.vmm());
                assert!(
                    matches!(
                        joined.checked_test_same_run(
                            &fixture.claim,
                            &fixture.observation,
                            &fixture.launch,
                            &closure,
                        ),
                        Err(reason) if reason == expected
                    ),
                    "terminal join mutation class={class_index} attempt={attempt}"
                );
            }
        }
    }

    #[test]
    fn hostile_same_run_join_mutation_corpus_refuses_all_100_compositions() {
        let fixture = fixture("same-run-hostile-corpus", 1);
        for case_index in 0..100usize {
            let mut input = fixture.input.clone();
            let mut context = fixture.context.clone();
            let foreign = hash(format!("foreign-root-{case_index}").as_bytes());
            match case_index % 31 {
                0 => input.receipt.run = foreign,
                1 => input.expected.run = foreign,
                2 => input.receipt.authority_parent = foreign,
                3 => input.expected.authority_parent = foreign,
                4 => input.receipt.events[0].process = foreign,
                5 => input.receipt.events[1].run = foreign,
                6 => {
                    if let Action::Read { returned, .. } = &mut input.receipt.events[2].action {
                        returned[0] ^= (case_index as u8).max(1);
                    }
                }
                7 => {
                    if let Action::Read {
                        returned_length, ..
                    } = &mut input.receipt.events[2].action
                    {
                        *returned_length += 1;
                    }
                }
                8 => {
                    if let Action::Read { version, .. } = &mut input.receipt.events[2].action {
                        *version += 1;
                    }
                }
                9 => input.receipt.initial.get_mut("input").unwrap().bytes[0] ^= 1,
                10 => input.receipt.final_world.get_mut("output").unwrap().bytes[0] ^= 1,
                11 => input.receipt.dependencies[0].returned[0] ^= 1,
                12 => input.receipt.health.source_count += 1,
                13 => input.receipt.health.duplicates = 1,
                14 => input.receipt.evidence_root = foreign,
                15 => input.expected.source_root = foreign,
                16 => context.head = foreign,
                17 => context.monitor_id = foreign,
                18 => context.manifest_root = foreign,
                19 => context.launch_identity = foreign,
                20 => context.starting_generation = foreign,
                21 => context.freeze_epoch = foreign,
                22 => context.input.inode += 1,
                23 => context.output.device += 1,
                24 => std::mem::swap(&mut context.input, &mut context.output),
                25 => context.input.device += 1,
                26 => context.output.inode += 1,
                27 => input.receipt.launch.argv[0].push_str("-foreign"),
                28 => input.receipt.events.swap(2, 3),
                29 => {
                    let Action::Write { requested, .. } = &mut input.receipt.events[5].action
                    else {
                        panic!("fixture write action index changed");
                    };
                    requested[0] ^= 0x20;
                    input.receipt.final_world.get_mut("output").unwrap().bytes = requested.clone();
                    input.receipt.dependencies = v2::derive(&input.receipt).unwrap();
                    v2::seal(&mut input.receipt).unwrap();
                    input.expected.source_root = input.receipt.evidence_root.clone();
                    assert!(v2::validate(&input.receipt, &input.expected).is_ok());
                }
                30 => {
                    input.receipt.launch.argv[0].push_str("-resealed");
                    input.expected.launch = input.receipt.launch.clone();
                    input.receipt.dependencies = v2::derive(&input.receipt).unwrap();
                    v2::seal(&mut input.receipt).unwrap();
                    input.expected.source_root = input.receipt.evidence_root.clone();
                    context.launch_identity =
                        hash(&serde_json::to_vec(&input.receipt.launch).unwrap());
                    assert!(v2::validate(&input.receipt, &input.expected).is_ok());
                }
                _ => unreachable!(),
            }
            assert!(
                join(&fixture.audit, &input, &context).is_err(),
                "hostile composition {case_index} unexpectedly joined"
            );
        }
    }

    #[test]
    fn valid_frontier_and_semantic_receipt_from_different_runs_refuse() {
        let first = fixture("run-a", 1);
        let second = fixture("run-b", 1);
        assert!(join(&first.audit, &second.input, &second.context).is_err());
    }

    #[test]
    fn same_run_id_does_not_hide_foreign_manifest_or_launch_history() {
        let first = fixture("run-reused", 1);
        let second = fixture("run-reused", 2);
        assert_ne!(
            first.input.receipt.evidence_root,
            second.input.receipt.evidence_root
        );
        assert!(join(&first.audit, &second.input, &second.context).is_err());
    }
}
