//! Consuming bridge. Ordinary records never enter this boundary.
use super::*;
use crate::{
    capsule::{BackendKind, CapsuleFacts, CapsuleObservation, CheckResult},
    coding_referee::OwnedCodingTaskCheck,
    coding_submission::{
        CODING_PROFILE, CodingFileCommitment, CodingPublicationData, CodingTransferContract,
    },
    filesystem_world::{FilesystemObject, FilesystemWorld},
    integration::coding::{CodingNativeEvidence, JoinedCodingEvidence},
    supervisor::RetiredCodingVmm,
};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

fn bad(reason: impl std::fmt::Debug) -> ExecuteError {
    ExecuteError::Supervisor(format!("coding publication refused: {reason:?}"))
}
impl RetiredCodingVmm {
    /// Consume the actual retired VMM/custody, owned checker and runtime
    /// provenance. This cannot be called with a serialized retirement report.
    /// Native qualification is checked before any candidate is materialized.
    pub fn finalize_coding(
        self,
        referee: OwnedCodingTaskCheck,
        provenance: crate::coding_provenance::OwnedCodingProvenance,
    ) -> Result<CheckedExecutionForPublication, ExecuteError> {
        self.finalize_coding_inner(referee, provenance, None)
    }
    pub fn finalize_coding_workflow(
        self,
        referee: OwnedCodingTaskCheck,
        provenance: crate::coding_provenance::OwnedCodingProvenance,
        workflow: crate::coding_runtime::attempt_history::OwnedNativeWorkflow,
    ) -> Result<CheckedExecutionForPublication, ExecuteError> {
        self.finalize_coding_inner(referee, provenance, Some(Box::new(workflow)))
    }
    fn finalize_coding_inner(
        self,
        referee: OwnedCodingTaskCheck,
        provenance: crate::coding_provenance::OwnedCodingProvenance,
        workflow: Option<Box<crate::coding_runtime::attempt_history::OwnedNativeWorkflow>>,
    ) -> Result<CheckedExecutionForPublication, ExecuteError> {
        let custody = self
            .owned_custody
            .ok_or_else(|| bad("missing native custody"))?;
        let semantic = JoinedCodingEvidence::from_native(
            &custody,
            &referee,
            &provenance,
            &self.production,
            &self.kernel_observation,
            workflow.as_deref(),
        )
        .map_err(bad)?;
        let (scope, bytes, native, frozen, starting) = custody.publication_inputs();
        let packet = scope.submission.decode(bytes).map_err(bad)?;
        let world = |contents: &[u8]| -> Result<FilesystemWorld, ExecuteError> {
            let entries = BTreeMap::from([(
                "output".into(),
                FilesystemObject::File {
                    content_blake3: digest_bytes(contents),
                    mode: 0o600,
                },
            )]);
            Ok(FilesystemWorld {
                root: digest_bytes(&serde_json::to_vec(&entries).map_err(bad)?),
                entries,
            })
        };
        let data = CodingPublicationData {
            semantic_evidence: Some(semantic.receipt().clone()),
            contract: CodingTransferContract {
                schema_version: 1,
                profile: CODING_PROFILE.into(),
                submission: scope.submission.clone(),
                source_commit: scope.source_commit.clone(),
                semantic_commitment: semantic.receipt().root().map_err(bad)?,
                files: packet.files.map(|f| CodingFileCommitment {
                    path: f.path,
                    bytes: f.text.len() as u64,
                    content_blake3: digest_bytes(f.text.as_bytes()),
                    mode: f.mode,
                }),
            },
            submission: bytes.to_vec(),
            native_before: world(b"")?,
            native_after: world(bytes)?,
        };
        data.validate().map_err(bad)?;
        if data.native_before.root != starting {
            return Err(bad("custody starting world differs"));
        }
        let delta = data.native_delta().map_err(bad)?;
        let capsule_id = digest_bytes(
            format!(
                "{}:{}:capsule",
                scope.submission.run_id, scope.submission.execution_id
            )
            .as_bytes(),
        );
        let closure = crate::run_closure::issue_coding(
            &self.production,
            frozen,
            &semantic,
            native,
            &capsule_id,
            self.kernel_observation,
        )
        .map_err(bad)?;
        let closure_root = digest_bytes(&serde_json::to_vec(&closure).map_err(bad)?);
        let snapshot_root = digest_bytes(
            &serde_json::to_vec(&(
                "realm.coding-frozen-effect-world/v1",
                frozen.completion.root(),
                &frozen.barrier,
                &data.native_before,
                &data.native_after,
                &semantic.receipt().packet_blake3,
            ))
            .map_err(bad)?,
        );
        let mut facts = CapsuleFacts {
            run_id: scope.submission.run_id.clone(),
            execution_id: scope.submission.execution_id.clone(),
            backend: BackendKind::FirecrackerMeasured,
            workspace_identity: starting.into(),
            capsule_id,
            custody_process_identity: Some(native.process.root().into()),
            descendants: vec![],
            starting_world: starting.into(),
            final_world: Some(data.native_after.root.clone()),
            observed_effects: vec!["output".into()],
            exit_code: None,
            crashed: false,
            quiescence: CheckResult::Verified,
            monitor_loss: CheckResult::Verified,
            network: CheckResult::Verified,
            filesystem: CheckResult::Verified,
            frozen: CheckResult::Verified,
            evidence_root: None,
            sequence_start: 0,
            sequence_end: Some(1),
            unsupported_effects: vec![],
            runtime_identity: self.production.runtime_identity().into(),
            network_policy_identity: self.production.network_policy_blake3(),
            completion_evidence: scope.submission.challenge_root.clone(),
            finalization_evidence: closure_root.clone(),
            pause_snapshot_evidence: snapshot_root,
            vmm_terminal_observation_root: Some(closure_root),
            delta_root: delta,
        };
        facts.evidence_root = Some(crate::capsule::evidence_binding_root(&facts));
        let observation =
            CapsuleObservation::from_host_facts(facts, self.production.production_launch_root())
                .map_err(bad)?;
        let manifest = self.production.coding_manifest(
            &data.native_before.root,
            &data.native_after.root,
            observation.facts().delta_root(),
        );
        let manifest_bytes = serde_json::to_vec(&manifest).map_err(bad)?;
        let manifest_root = digest_bytes(&manifest_bytes);
        let claim = crate::mediation::CheckedMediationClaim::issue_for_coding_session(
            &manifest_bytes,
            &manifest_root,
            &observation,
            &semantic,
            &frozen.completion,
            &self.production,
        )
        .map_err(bad)?;
        let same_run = crate::integration::join_native_binding(
            &semantic.binding,
            &claim,
            &observation,
            &self.production,
            &closure,
            Some(self.production.production_launch_root()),
            crate::integration::SameRunSemanticScope::CodingFiniteEffects,
        )
        .map_err(bad)?;
        let f = observation.facts();
        let command = vec![CODING_PROFILE.into()];
        let intent = domain_digest("realm.intent", &serde_json::to_vec(&command).map_err(bad)?);
        let effect_bytes = serde_json::to_vec(&data.contract).map_err(bad)?;
        let effect = domain_digest(
            crate::coding_submission::TRANSFER_CONTRACT_DOMAIN,
            &effect_bytes,
        );
        let evidence = CheckedC1Evidence {
            schema_version: 9,
            file_contract: None,
            coding: Some(data),
            verifier_decision: "CHECKED_FOR_PUBLICATION".into(),
            run_id: f.run_id().clone(),
            execution_id: f.execution_id().clone(),
            capsule_id: f.capsule_id().clone(),
            custody_process_identity: f.custody_process_identity().clone(),
            challenge_binding: f.completion_evidence().clone(),
            checked_claim_root: claim.root().into(),
            accepted_decision_identity: accepted_decision_identity(
                9,
                claim.root(),
                &manifest_root,
                f.run_id(),
                f.execution_id(),
                f.capsule_id(),
                f.completion_evidence(),
                f.evidence_root()
                    .as_deref()
                    .ok_or_else(|| bad("missing evidence root"))?,
                same_run.root(),
                &intent,
                &effect,
                f.starting_world(),
                f.final_world()
                    .as_deref()
                    .ok_or_else(|| bad("missing final world"))?,
                f.delta_root(),
            ),
            same_run_join_root: same_run.root().into(),
            accepted_start_root: f.starting_world().clone(),
            accepted_final_root: f
                .final_world()
                .clone()
                .ok_or_else(|| bad("missing final world"))?,
            accepted_delta_root: f.delta_root().clone(),
            evidence_root: f
                .evidence_root()
                .clone()
                .ok_or_else(|| bad("missing evidence root"))?,
            vmm_terminal_observation_root: f.vmm_terminal_observation_root().clone(),
            finalization_evidence: f.finalization_evidence().clone(),
            pause_snapshot_evidence: f.pause_snapshot_evidence().clone(),
            c1_manifest_root: manifest_root,
            c1_manifest: manifest_bytes,
            command,
            allowed_effects: vec!["filesystem".into()],
            allowed_paths: vec!["output".into()],
            observed_effects: f.observed_effects().clone(),
            unsupported_effects: vec![],
            timeout_ms: 120000,
            intent_identity: intent,
            effect_contract_identity: effect,
        };
        // Materialization is transport only: scan both detached images and check
        // against original sealed custody worlds before the canonical issuer.
        let (before_image, after_image) =
            materialize(&self.state, evidence.coding.as_ref().unwrap())?;
        let result = ExecuteResult {
            schema_version: 1,
            run_id: f.run_id().clone(),
            execution_id: f.execution_id().clone(),
            guest_exit_code: None,
            guest_crashed: None,
            vmm_pid: None,
            vmm_start_time_ticks: None,
            starting_world_commitment: f.starting_world().clone(),
            final_world_commitment: f.final_world().clone(),
            delta_root: Some(f.delta_root().clone()),
            starting_workspace_image: Some(before_image),
            final_workspace_image: Some(after_image),
            observed_effects: f.observed_effects().clone(),
            proposed_effects: vec!["filesystem".into()],
            evidence_root: f.evidence_root().clone(),
            receipt_path: None,
            verifier_decision: Admission::Refuse(crate::Refusal::UnverifiedBoundary),
            reason_code: "CHECKED_FOR_PUBLICATION".into(),
            task_success: false,
            unsupported_effects: vec![],
            runtime_ms: 0,
            overhead_ms: 0,
        };
        let mut capability = CheckedExecutionForPublication::issue_coding_from_native(
            result,
            evidence,
            CodingNativeEvidence {
                finite_referee: Some(&referee),
                observation: Some(&observation),
                production: Some(&self.production),
                mediation: Some(&claim),
                closure: Some(&closure),
                semantics: Some(&semantic),
            },
        )
        .map_err(bad)?;
        capability._native_workflow_owners = workflow;
        Ok(capability)
    }
}

fn materialize(
    state: &Path,
    data: &CodingPublicationData,
) -> Result<(PathBuf, PathBuf), ExecuteError> {
    let directory = state.join("canonical-coding-worlds");
    fs::create_dir(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let mut images = Vec::new();
    for (label, bytes, expected) in [
        ("before", b"".as_slice(), &data.native_before),
        ("after", data.submission.as_slice(), &data.native_after),
    ] {
        let tree = directory.join(label);
        fs::create_dir(&tree)?;
        let mut output = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(tree.join("output"))?;
        output.set_permissions(fs::Permissions::from_mode(0o600))?;
        output.write_all(bytes)?;
        output.sync_all()?;
        let image = directory.join(format!("{label}.ext4"));
        let image_file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&image)?;
        image_file.set_len(16 * 1024 * 1024)?;
        let status = std::process::Command::new("mke2fs")
            .args(["-q", "-t", "ext4", "-F", "-d"])
            .arg(&tree)
            .arg(&image)
            .status()?;
        if !status.success() {
            return Err(bad("coding world image construction failed"));
        }
        crate::production_session::debugfs(&image, "rmdir /lost+found")?;
        fs::set_permissions(&image, fs::Permissions::from_mode(0o400))?;
        fs::File::open(&image)?.sync_all()?;
        let scanned =
            crate::supervisor::scan_detached_workspace(&image, &directory, label).map_err(bad)?;
        if &scanned != expected {
            return Err(bad("detached coding world differs from sealed packet"));
        }
        images.push(image);
    }
    Ok((images.remove(0), images.remove(0)))
}
