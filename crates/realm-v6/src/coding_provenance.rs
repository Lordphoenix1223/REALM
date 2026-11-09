//! Native finite-tool provenance. Only the live relay and kernel descriptor
//! producers can seal this owner. External planner reasoning remains unobserved.
use crate::{coding_submission::CodingExecutionScope, measured_launch::MeasuredLaunchSession};
#[derive(Debug, thiserror::Error)]
pub enum CodingProvenanceRefusal {
    #[error(
        "REFUSE_UNVERIFIED_BOUNDARY: native relay/resource ownership is absent or already consumed"
    )]
    UnobservedRuntimeBoundary,
    #[error("REFUSE_UNVERIFIED_BOUNDARY: native qualification requires root Linux x86_64")]
    UnsupportedHost,
    #[error(
        "REFUSE_UNVERIFIED_BOUNDARY: fixed-runtime temporal alias/endpoint qualification is not registered; native observations grant no publication authority"
    )]
    MissingQualifiedRuntimeContract,
    #[error("REFUSE_UNVERIFIED_BOUNDARY: {0}")]
    InvalidNativeBoundary(String),
}
/// Actual native owner; diagnostic JSON cannot reconstruct it.
/// ```compile_fail
/// let _: realm_v6::coding_provenance::OwnedCodingProvenance = serde_json::from_str("{}").unwrap();
/// ```
pub struct OwnedCodingProvenance {
    root: String,
    identity_record: serde_json::Value,
    measurement: String,
    scope: CodingExecutionScope,
    frontier: String,
    barrier: String,
    capture: crate::coding_relay::RelayCapture,
    resources: crate::vmm_resources::ObservedVmmResources,
    fence: crate::coding_fence::EnforcedCodingLaunch,
    qualification: Option<QualifiedFixedRuntime>,
}
// Private qualification requires both original native owners and an admission
// verified against the independently provisioned setup authority.
struct QualifiedFixedRuntime {
    admission: crate::runtime_admission::ReviewedRuntimeAdmission,
    evidence: crate::runtime_admission::QualificationEvidence,
}
fn observed_host_identity() -> Result<serde_json::Value, CodingProvenanceRefusal> {
    let mut value = std::mem::MaybeUninit::<libc::utsname>::uninit();
    if unsafe { libc::uname(value.as_mut_ptr()) } != 0 {
        return Err(CodingProvenanceRefusal::InvalidNativeBoundary(
            "uname unavailable".into(),
        ));
    }
    let value = unsafe { value.assume_init() };
    let text = |field: &[libc::c_char]| unsafe {
        std::ffi::CStr::from_ptr(field.as_ptr())
            .to_string_lossy()
            .into_owned()
    };
    let abi = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, 0, 0, 1) };
    if abi < 3 {
        return Err(CodingProvenanceRefusal::InvalidNativeBoundary(
            "mandatory Landlock ABI unavailable".into(),
        ));
    }
    Ok(
        serde_json::json!({"sysname":text(&value.sysname),"release":text(&value.release),
        "version":text(&value.version),"machine":text(&value.machine),"landlock_abi":abi,
        "basis":"current kernel query; not installed-policy readback or independent host admission"}),
    )
}
impl OwnedCodingProvenance {
    pub fn root(&self) -> &str {
        &self.root
    }
    /// Native-generated observation commitment material. This diagnostic data
    /// cannot reconstruct the owner or supply independent runtime admission.
    pub fn identity_record(&self) -> &serde_json::Value {
        &self.identity_record
    }
    pub fn qualification_evidence(
        &self,
    ) -> Option<&crate::runtime_admission::QualificationEvidence> {
        self.qualification.as_ref().map(|q| &q.evidence)
    }
    pub(crate) fn has_verified_vmm_fd_boundary(&self) -> bool {
        self.qualification.as_ref().is_some_and(|q| {
            q.admission.identity() == q.evidence.admission_identity
                && q.evidence.identity().is_ok_and(|root| root == self.root)
                && now_unix().is_ok_and(|now| q.admission.policy().permits_time(now))
        })
    }
    pub(crate) fn matches_native(
        &self,
        measured: &MeasuredLaunchSession,
        scope: &CodingExecutionScope,
        frontier: &str,
        barrier: &str,
    ) -> bool {
        serde_json::to_vec(&self.identity_record).is_ok_and(|bytes| {
            let observed = blake3::hash(&bytes).to_hex().to_string();
            self.qualification.as_ref().map_or_else(
                || observed == self.root,
                |q| {
                    q.evidence.observation_root == observed
                        && q.evidence.identity().is_ok_and(|root| root == self.root)
                        && q.admission.identity() == q.evidence.admission_identity
                        && now_unix().is_ok_and(|now| q.admission.policy().permits_time(now))
                        && q.evidence.admission == *q.admission.envelope()
                        && crate::runtime_admission::RuntimeTuple::from_observations(
                            &self.identity_record,
                            scope,
                        )
                        .is_ok_and(|actual| actual == q.admission.policy().expected)
                        && crate::runtime_admission::validate_observations(
                            &self.identity_record,
                            scope,
                        )
                        .is_ok()
                },
            )
        }) && self.measurement == measured.canonical_hash_blake3()
            && self.scope == *scope
            && self.frontier == frontier
            && self.barrier == barrier
            && self.resources.matches(measured)
            && self.capture.matches_native(measured)
            && self.capture.revalidate().is_ok()
            && self.fence.matches_terminal(measured)
    }
    pub(crate) fn seal(
        retired: &mut crate::supervisor::RetiredCodingVmm,
        referee: &(impl crate::coding_referee::NativeRefereeEvidence + ?Sized),
        capture: crate::coding_relay::RelayCapture,
        resources: crate::vmm_resources::ObservedVmmResources,
        admission: Option<crate::runtime_admission::ReviewedRuntimeAdmission>,
    ) -> Result<Self, CodingProvenanceRefusal> {
        let fail = |s: &str| CodingProvenanceRefusal::InvalidNativeBoundary(s.into());
        let custody = retired
            .owned_custody
            .as_ref()
            .ok_or_else(|| fail("original custody absent"))?;
        custody
            .validate_retired(&retired.production)
            .map_err(|e| fail(&format!("{e:?}")))?;
        let (scope, packet, native, frozen, _) = custody.publication_inputs();
        if !capture.matches_native(&retired.production)
            || !resources.matches(&retired.production)
            || !referee.native_binding(scope, packet, &native.root, frozen.completion.root())
        {
            return Err(fail("retirement/resource/referee identity differs"));
        }
        let capture_root = capture
            .verify(scope, packet, referee)
            .map_err(|e| fail(&e.to_string()))?;
        let fence = retired
            .coding_fence
            .as_ref()
            .ok_or_else(|| fail("original pre-VMM enforcement owner absent"))?;
        fence
            .revalidate_objects()
            .map_err(|e| fail(&e.to_string()))?;
        if !fence.matches_terminal(&retired.production) {
            return Err(fail("original fence belongs to another retired execution"));
        }
        let fence_record = fence.record();
        let measurement = retired.production.canonical_hash_blake3().to_owned();
        let frontier = frozen.completion.frontier_root().to_owned();
        let barrier = frozen.barrier.clone();
        let identity_record = serde_json::json!({
            "domain":"realm.native-coding-provenance/v2",
            "profile_source_blake3":crate::runtime_admission::profile_source_root(),
            "controller_policy_blake3":crate::controller_guard::policy_root(),
            "authority":"NONE", "qualification":"NOT_REGISTERED",
            "measurement":measurement, "scope":scope, "frontier":frontier, "barrier":barrier,
            "capture_root":capture_root, "resources_root":resources.root(),
            "fence":fence_record, "controller":capture.controller_identity(),
            "referee_root":referee.root(), "referee_identity_record":referee.identity_record(),
            "containment":retired.production.containment_record(),
            "host":observed_host_identity()?,
            "resources_raw_json":std::str::from_utf8(resources.identity_bytes()).map_err(|e|fail(&e.to_string()))?,
            "terminal":retired.kernel_observation,
            "trust_basis":"native-owned observations; independent profile/build/host admission absent"
        });
        let bytes = serde_json::to_vec(&identity_record).map_err(|e| fail(&e.to_string()))?;
        let observation_root = blake3::hash(&bytes).to_hex().to_string();
        // Only the original fence/capture/resources/referee/custody and clean
        // retirement owners above can reach this private constructor.
        let qualification = admission
            .map(|admission| {
                validate_admitted_scope(&admission, scope)?;
                crate::runtime_admission::validate_observations(&identity_record, scope)
                    .map_err(|e| fail(&e))?;
                let actual = crate::runtime_admission::RuntimeTuple::from_observations(
                    &identity_record,
                    scope,
                )
                .map_err(|e| fail(&e))?;
                if actual != admission.policy().expected {
                    return Err(fail("actual retired runtime differs from admitted tuple"));
                }
                let qualified_at_unix = now_unix()?;
                if !admission.policy().permits_time(qualified_at_unix) {
                    return Err(fail("runtime admission expired before qualification"));
                }
                let evidence = crate::runtime_admission::QualificationEvidence {
                    schema_version: 1,
                    admission: admission.envelope().clone(),
                    admission_identity: admission.identity().to_owned(),
                    observed_runtime: actual,
                    observation_root: observation_root.clone(),
                    admitted_at_unix: admission.admitted_at_unix(),
                    qualified_at_unix,
                };
                Ok(QualifiedFixedRuntime {
                    admission,
                    evidence,
                })
            })
            .transpose()?;
        let root = match &qualification {
            Some(q) => q.evidence.identity().map_err(|e| fail(&e))?,
            None => observation_root,
        };
        Ok(Self {
            root,
            identity_record,
            measurement,
            scope: scope.clone(),
            frontier,
            barrier,
            capture,
            resources,
            fence: retired
                .coding_fence
                .take()
                .ok_or_else(|| fail("original fence owner already consumed"))?,
            qualification,
        })
    }
}
/// Diagnostic kernel-access probe. Success means only that this process can
/// inspect its own open description; it is never a VMM qualification result.
pub fn inspect_kernel_access() -> Result<(), CodingProvenanceRefusal> {
    crate::vmm_resources::inspection_preflight()
        .map_err(|e| CodingProvenanceRefusal::InvalidNativeBoundary(e.to_string()))
}
/// Source availability only. Actual resource, endpoint and scope qualification
/// happens in the mandatory production runtime before/during the launch.
pub fn preflight() -> Result<(), CodingProvenanceRefusal> {
    if std::env::consts::ARCH != "x86_64" || unsafe { libc::geteuid() } != 0 {
        return Err(CodingProvenanceRefusal::UnsupportedHost);
    }
    inspect_kernel_access()?;
    Err(CodingProvenanceRefusal::MissingQualifiedRuntimeContract)
}
impl crate::supervisor::RetiredCodingVmm {
    pub fn require_coding_provenance(
        &mut self,
    ) -> Result<OwnedCodingProvenance, CodingProvenanceRefusal> {
        let observed = self
            .owned_provenance
            .as_ref()
            .ok_or(CodingProvenanceRefusal::UnobservedRuntimeBoundary)?;
        if !observed.has_verified_vmm_fd_boundary() {
            return Err(CodingProvenanceRefusal::MissingQualifiedRuntimeContract);
        }
        self.owned_provenance
            .take()
            .ok_or(CodingProvenanceRefusal::UnobservedRuntimeBoundary)
    }
}

fn now_unix() -> Result<u64, CodingProvenanceRefusal> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|e| CodingProvenanceRefusal::InvalidNativeBoundary(e.to_string()))
}
pub fn preflight_with_admission(
    envelope: &crate::runtime_admission::SignedRuntimeAdmission,
) -> Result<crate::runtime_admission::ReviewedRuntimeAdmission, CodingProvenanceRefusal> {
    if std::env::consts::ARCH != "x86_64" || unsafe { libc::geteuid() } != 0 {
        return Err(CodingProvenanceRefusal::UnsupportedHost);
    }
    inspect_kernel_access()?;
    envelope
        .admit_now()
        .map_err(CodingProvenanceRefusal::InvalidNativeBoundary)
}
fn validate_admitted_scope(
    admission: &crate::runtime_admission::ReviewedRuntimeAdmission,
    scope: &CodingExecutionScope,
) -> Result<(), CodingProvenanceRefusal> {
    match (&admission.policy().task_inputs, &scope.task_inputs_blake3) {
        (None, None) => {}
        (Some(inputs), Some(_)) if inputs.matches_scope(scope) => {}
        _ => {
            return Err(CodingProvenanceRefusal::InvalidNativeBoundary(
                "original task input admission differs".into(),
            ));
        }
    }
    let expected = &admission.policy().expected;
    if scope.runtime_admission_id.as_deref() != Some(admission.identity())
        || scope.source_commit != expected.source_commit
        || scope.submission.task_sha256 != expected.task_sha256
        || scope.submission.worker_sha256 != expected.worker_sha256
        || scope.checker_sha256 != expected.checker_sha256
        || scope.checker_scope_sha256 != expected.checker_scope_sha256
        || !admission.policy().permits_time(now_unix()?)
    {
        return Err(CodingProvenanceRefusal::InvalidNativeBoundary(
            "prelaunch scope or admission validity differs".into(),
        ));
    }
    Ok(())
}
pub(crate) fn validate_prelaunch(
    admission: &crate::runtime_admission::ReviewedRuntimeAdmission,
    scope: &CodingExecutionScope,
    backend: &crate::execute::C1BackendInputPaths,
    python: &std::path::Path,
) -> Result<(), CodingProvenanceRefusal> {
    use crate::measured_launch::FileIdentity;
    validate_admitted_scope(admission, scope)?;
    let fail = |s: String| CodingProvenanceRefusal::InvalidNativeBoundary(s);
    let e = &admission.policy().expected;
    let host = observed_host_identity()?;
    let jailer = backend
        .production_jailer
        .as_ref()
        .ok_or_else(|| fail("production jailer required by admission".into()))?;
    let bwrap = std::path::Path::new("/usr/bin/bwrap")
        .canonicalize()
        .map_err(|x| fail(format!("prelaunch bwrap: {x}")))?;
    let python = python
        .canonicalize()
        .map_err(|x| fail(format!("prelaunch python: {x}")))?;
    for (path, expected) in [
        (backend.firecracker.as_path(), &e.vmm_blake3),
        (backend.kernel.as_path(), &e.kernel_blake3),
        (backend.rootfs.as_path(), &e.rootfs_blake3),
        (jailer.jailer.as_path(), &e.jailer_blake3),
        (python.as_path(), &e.checker_python_blake3),
        (bwrap.as_path(), &e.checker_bwrap_blake3),
    ] {
        let actual = FileIdentity::measure(path).map_err(|x| {
            fail(format!(
                "prelaunch admitted object {}: {x:?}",
                path.display()
            ))
        })?;
        if actual.blake3() != expected {
            return Err(fail(format!(
                "prelaunch admitted object differs: {}",
                path.display()
            )));
        }
    }
    let (_held, controller) =
        crate::runtime_admission::protected_running_supervisor().map_err(fail)?;
    if controller.blake3() != e.native_controller_blake3
        || crate::controller_guard::policy_root() != e.controller_policy_blake3
        || crate::coding_fence::stage_digest() != e.stage_blake3
        || host["release"] != e.kernel_release
        || host["version"] != e.kernel_version
        || host["machine"] != e.machine
        || host["landlock_abi"] != e.landlock_abi
        || jailer.uid != e.vmm_uid
        || jailer.gid != e.vmm_gid
        || jailer.memory_max_bytes != e.memory_max_bytes
        || jailer.pids_max != e.pids_max
        || e.cpu_max != "100000 100000"
    {
        return Err(fail(
            "prelaunch runtime/host/controller differs from admission".into(),
        ));
    }
    Ok(())
}

/// Recheck expiry and actual launched immutable objects immediately before the
/// guest starts, after preparation and any wait for the START control message.
pub(crate) fn validate_instance_start(
    admission: &crate::runtime_admission::ReviewedRuntimeAdmission,
    scope: &CodingExecutionScope,
    measured: &MeasuredLaunchSession,
) -> Result<(), CodingProvenanceRefusal> {
    validate_admitted_scope(admission, scope)?;
    let e = &admission.policy().expected;
    if measured.firecracker_identity().blake3() != e.vmm_blake3
        || measured.kernel_identity().blake3() != e.kernel_blake3
        || measured.rootfs_identity().blake3() != e.rootfs_blake3
        || measured.vmm().owner() != (e.vmm_uid, e.vmm_gid)
    {
        return Err(CodingProvenanceRefusal::InvalidNativeBoundary(
            "actual prepared runtime differs from admission".into(),
        ));
    }
    Ok(())
}
