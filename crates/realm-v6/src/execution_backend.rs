//! Backend seam for REALM's runtime-to-launch lifecycle.
//!
//! The runtime owns the ToolCall and TaskEnvelope. The optimizer owns graded
//! launch products and confinement. This adapter preserves that type boundary;
//! observations remain diagnostic and never authorize ACCEPT or publication.

use crate::{
    capsule::CapsuleObservation,
    measured_launch::{
        DirectMeasuredLaunch, LaunchAssuranceGrade, PolicyIdentity, ProductionContainedLaunch,
    },
    task_envelope::TaskEnvelope,
};
#[cfg(target_os = "linux")]
use crate::{
    measured_launch::{LaunchEvidence, MeasuredLaunchSession},
    supervisor::{FirecrackerSupervisor, SupervisorError},
};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt, path::PathBuf};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecutionBackendCapabilities {
    pub backend_id: String,
    pub host_requirement: String,
    pub runtime_profile: String,
    pub guest_network: bool,
    pub workspace_format: String,
    pub observes_final_workspace_delta: bool,
    pub closes_all_guest_effects: bool,
}

#[derive(Debug)]
pub struct BackendError {
    pub stage: &'static str,
    pub detail: String,
}

impl BackendError {
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn new(stage: &'static str, detail: impl Into<String>) -> Self {
        Self {
            stage,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stage, self.detail)
    }
}

impl Error for BackendError {}

#[derive(Clone, Debug)]
pub struct BackendTask<'a> {
    pub envelope: &'a TaskEnvelope,
    pub policy: PolicyIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackendLaunchContext {
    pub run_id: String,
    pub execution_id: String,
    pub task_envelope_identity: String,
    pub measured_launch_identity: Option<String>,
    pub assurance_grade: Option<LaunchAssuranceGrade>,
    pub launch_evidence_path: Option<PathBuf>,
    pub topology_root: String,
    pub vmm_process_identity: Option<String>,
    pub vmm_pid: u32,
    pub process_start_ticks: u64,
}

pub enum BackendLaunchEvidence {
    Direct(Box<DirectMeasuredLaunch>),
    Production(Box<ProductionContainedLaunch>),
}

pub struct BackendExecutionResult {
    pub backend_id: String,
    pub capabilities: ExecutionBackendCapabilities,
    pub launch: BackendLaunchContext,
    pub launch_evidence: Option<BackendLaunchEvidence>,
    pub observation: CapsuleObservation,
    pub detached_workspace: PathBuf,
}

/// Called after launch identity and pinned-input revalidation, directly before
/// InstanceStart. A backend cannot substitute a runtime-built launch object.
pub trait ExecutionBackend: Send + Sync {
    fn capabilities(&self) -> ExecutionBackendCapabilities;

    fn execute(
        &self,
        task: BackendTask<'_>,
        before_guest_start: &mut dyn FnMut(&BackendLaunchContext) -> Result<(), BackendError>,
    ) -> Result<BackendExecutionResult, BackendError>;
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub struct FirecrackerBackend {
    supervisor: FirecrackerSupervisor,
}

#[cfg(target_os = "linux")]
impl FirecrackerBackend {
    pub fn new(supervisor: FirecrackerSupervisor) -> Self {
        Self { supervisor }
    }

    pub(crate) fn execute_with_guest_rpc<G>(
        &self,
        task: BackendTask<'_>,
        before_guest_start: &mut dyn FnMut(&BackendLaunchContext) -> Result<(), BackendError>,
        guest_rpc: &mut G,
    ) -> Result<BackendExecutionResult, BackendError>
    where
        G: FnMut(&mut std::os::unix::net::UnixStream, &TaskEnvelope) -> Result<(), SupervisorError>,
    {
        let envelope_identity = task
            .envelope
            .identity()
            .map_err(|_| BackendError::new("task_envelope", "identity encoding failed"))?;
        let mut prestart_context = None;
        let mut launch_hook = |session: &MeasuredLaunchSession| {
            let context = direct_session_context(session, &envelope_identity, None)
                .map_err(|error| SupervisorError::Protocol(error.to_string()))?;
            before_guest_start(&context).map_err(|error| {
                SupervisorError::Protocol(format!("BrokerRpc launch binding refused: {error}"))
            })?;
            prestart_context = Some(context);
            Ok(())
        };
        let (observation, launch) = self
            .supervisor
            .run_measured_brokered_with_rpc(task.envelope, task.policy, &mut launch_hook, guest_rpc)
            .map_err(|error| BackendError::new("firecracker_lifecycle", error.to_string()))?;

        let (completed_context, prestart_measurement) = match &launch {
            LaunchEvidence::Direct(product) => (
                direct_product_context(product, &envelope_identity)
                    .map_err(|error| BackendError::new("launch_binding", error))?,
                product.canonical_hash_blake3().to_owned(),
            ),
            LaunchEvidence::Production(product) => {
                let mut context = direct_session_context(product, &envelope_identity, None)
                    .map_err(|_| {
                        BackendError::new("launch_binding", "VMM identity encoding failed")
                    })?;
                context.assurance_grade = Some(LaunchAssuranceGrade::ProductionContained);
                context.measured_launch_identity = Some(product.production_launch_root());
                (context, product.prestart_measurement_identity().to_owned())
            }
        };
        let prestart_context = prestart_context.ok_or_else(|| {
            BackendError::new("launch_binding", "BrokerRpc prestart hook did not run")
        })?;
        let mut original_context = completed_context.clone();
        original_context.measured_launch_identity = Some(prestart_measurement);
        original_context.assurance_grade = Some(LaunchAssuranceGrade::DirectFunctional);
        original_context.launch_evidence_path = Some(self.supervisor.backend.state_dir.clone());
        if !direct_launch_context_matches(&prestart_context, &original_context) {
            return Err(BackendError::new(
                "launch_binding",
                "prestart BrokerRpc binding differs from the completed DirectMeasuredLaunch",
            ));
        }

        let capabilities = self.capabilities();
        Ok(BackendExecutionResult {
            backend_id: capabilities.backend_id.clone(),
            capabilities,
            launch: completed_context,
            launch_evidence: Some(match launch {
                LaunchEvidence::Direct(product) => BackendLaunchEvidence::Direct(product),
                LaunchEvidence::Production(product) => BackendLaunchEvidence::Production(product),
            }),
            detached_workspace: self.supervisor.working_workspace_image.clone(),
            observation,
        })
    }
}

#[cfg(target_os = "linux")]
impl ExecutionBackend for FirecrackerBackend {
    fn capabilities(&self) -> ExecutionBackendCapabilities {
        ExecutionBackendCapabilities {
            backend_id: "realm-v6-broker-rpc-firecracker".into(),
            host_requirement: "Linux x86_64 with usable KVM".into(),
            runtime_profile: "MEASURED_DIAGNOSTIC_ONLY".into(),
            guest_network: false,
            workspace_format: "single private ext4 block image".into(),
            observes_final_workspace_delta: true,
            closes_all_guest_effects: false,
        }
    }

    fn execute(
        &self,
        task: BackendTask<'_>,
        before_guest_start: &mut dyn FnMut(&BackendLaunchContext) -> Result<(), BackendError>,
    ) -> Result<BackendExecutionResult, BackendError> {
        let envelope_identity = task
            .envelope
            .identity()
            .map_err(|_| BackendError::new("task_envelope", "identity encoding failed"))?;
        let mut prestart_context = None;
        let mut launch_hook = |session: &MeasuredLaunchSession| {
            let context = direct_session_context(session, &envelope_identity, None)
                .map_err(|error| SupervisorError::Protocol(error.to_string()))?;
            before_guest_start(&context).map_err(|error| {
                SupervisorError::Protocol(format!("BrokerRpc launch binding refused: {error}"))
            })?;
            prestart_context = Some(context);
            Ok(())
        };
        let (observation, launch) = self
            .supervisor
            .run_measured_brokered(task.envelope, task.policy, &mut launch_hook)
            .map_err(|error| BackendError::new("firecracker_lifecycle", error.to_string()))?;

        let (completed_context, prestart_measurement) = match &launch {
            LaunchEvidence::Direct(product) => (
                direct_product_context(product, &envelope_identity)
                    .map_err(|error| BackendError::new("launch_binding", error))?,
                product.canonical_hash_blake3().to_owned(),
            ),
            LaunchEvidence::Production(product) => {
                let mut context = direct_session_context(product, &envelope_identity, None)
                    .map_err(|_| {
                        BackendError::new("launch_binding", "VMM identity encoding failed")
                    })?;
                context.assurance_grade = Some(LaunchAssuranceGrade::ProductionContained);
                context.measured_launch_identity = Some(product.production_launch_root());
                (context, product.prestart_measurement_identity().to_owned())
            }
        };
        let prestart_context = prestart_context.ok_or_else(|| {
            BackendError::new("launch_binding", "BrokerRpc prestart hook did not run")
        })?;
        let mut original_context = completed_context.clone();
        original_context.measured_launch_identity = Some(prestart_measurement);
        original_context.assurance_grade = Some(LaunchAssuranceGrade::DirectFunctional);
        original_context.launch_evidence_path = Some(self.supervisor.backend.state_dir.clone());
        if !direct_launch_context_matches(&prestart_context, &original_context) {
            return Err(BackendError::new(
                "launch_binding",
                "prestart BrokerRpc binding differs from the completed DirectMeasuredLaunch",
            ));
        }

        let capabilities = self.capabilities();
        Ok(BackendExecutionResult {
            backend_id: capabilities.backend_id.clone(),
            capabilities,
            launch: completed_context,
            launch_evidence: Some(match launch {
                LaunchEvidence::Direct(product) => BackendLaunchEvidence::Direct(product),
                LaunchEvidence::Production(product) => BackendLaunchEvidence::Production(product),
            }),
            detached_workspace: self.supervisor.working_workspace_image.clone(),
            observation,
        })
    }
}

#[cfg(target_os = "linux")]
fn direct_session_context(
    launch: &MeasuredLaunchSession,
    task_envelope_identity: &str,
    launch_evidence_path: Option<PathBuf>,
) -> Result<BackendLaunchContext, serde_json::Error> {
    let vmm_process_identity = blake3::hash(&serde_json::to_vec(launch.vmm())?)
        .to_hex()
        .to_string();
    Ok(BackendLaunchContext {
        run_id: launch.run_id().to_owned(),
        execution_id: launch.execution_id().to_owned(),
        task_envelope_identity: task_envelope_identity.to_owned(),
        measured_launch_identity: Some(launch.canonical_hash_blake3().to_owned()),
        assurance_grade: Some(LaunchAssuranceGrade::DirectFunctional),
        launch_evidence_path,
        topology_root: launch.vm_config_blake3().to_owned(),
        vmm_process_identity: Some(vmm_process_identity),
        vmm_pid: launch.vmm().pid(),
        process_start_ticks: launch.vmm().start_time_ticks(),
    })
}

#[cfg(target_os = "linux")]
fn direct_product_context(
    launch: &DirectMeasuredLaunch,
    task_envelope_identity: &str,
) -> Result<BackendLaunchContext, String> {
    direct_session_context(
        launch,
        task_envelope_identity,
        Some(launch.evidence_dir().to_path_buf()),
    )
    .map_err(|_| "measured VMM identity encoding failed".to_owned())
}

#[cfg(any(target_os = "linux", test))]
fn direct_launch_context_matches(
    prestart: &BackendLaunchContext,
    completed: &BackendLaunchContext,
) -> bool {
    prestart.run_id == completed.run_id
        && prestart.execution_id == completed.execution_id
        && prestart.task_envelope_identity == completed.task_envelope_identity
        && prestart.measured_launch_identity == completed.measured_launch_identity
        && prestart.assurance_grade == Some(LaunchAssuranceGrade::DirectFunctional)
        && completed.assurance_grade == Some(LaunchAssuranceGrade::DirectFunctional)
        && prestart.launch_evidence_path.is_none()
        && completed
            .launch_evidence_path
            .as_ref()
            .is_some_and(|path| path.is_absolute())
        && prestart.topology_root == completed.topology_root
        && prestart.vmm_process_identity == completed.vmm_process_identity
        && prestart.vmm_pid == completed.vmm_pid
        && prestart.process_start_ticks == completed.process_start_ticks
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn firecracker_profile_reports_observation_limits_without_authority() {
        let backend = FirecrackerBackend::new(FirecrackerSupervisor {
            backend: crate::execute::C1BackendInputPaths {
                firecracker: PathBuf::new(),
                kernel: PathBuf::new(),
                rootfs: PathBuf::new(),
                workspace_device: PathBuf::new(),
                guest_supervisor: PathBuf::new(),
                state_dir: PathBuf::new(),
                production_jailer: None,
            },
            starting_workspace_image: PathBuf::new(),
            working_workspace_image: PathBuf::new(),
            timeout: std::time::Duration::from_secs(1),
        });
        let capabilities = backend.capabilities();
        assert_eq!(capabilities.backend_id, "realm-v6-broker-rpc-firecracker");
        assert_eq!(capabilities.runtime_profile, "MEASURED_DIAGNOSTIC_ONLY");
        assert!(!capabilities.guest_network);
        assert!(capabilities.observes_final_workspace_delta);
        assert!(!capabilities.closes_all_guest_effects);
    }
}

#[cfg(test)]
mod launch_adapter_tests {
    use super::*;

    fn context(evidence_path: Option<PathBuf>) -> BackendLaunchContext {
        BackendLaunchContext {
            run_id: "run-1".into(),
            execution_id: "e".repeat(64),
            task_envelope_identity: "t".repeat(64),
            measured_launch_identity: Some("m".repeat(64)),
            assurance_grade: Some(LaunchAssuranceGrade::DirectFunctional),
            launch_evidence_path: evidence_path,
            topology_root: "c".repeat(64),
            vmm_process_identity: Some("v".repeat(64)),
            vmm_pid: 10,
            process_start_ticks: 11,
        }
    }

    #[test]
    fn direct_launch_adapter_rejects_identity_drift() {
        let base = context(None);
        let complete = context(Some(PathBuf::from("/tmp/direct-launch")));
        assert!(direct_launch_context_matches(&base, &complete));

        let mut mutant = complete.clone();
        mutant.task_envelope_identity.push('x');
        assert!(!direct_launch_context_matches(&base, &mutant));
        let mut mutant = complete.clone();
        mutant.topology_root.push('x');
        assert!(!direct_launch_context_matches(&base, &mutant));
        let mut mutant = complete.clone();
        mutant.process_start_ticks += 1;
        assert!(!direct_launch_context_matches(&base, &mutant));
    }
}
