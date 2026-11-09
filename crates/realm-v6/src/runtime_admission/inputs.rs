//! Separate, same-attempt inputs for the immutable rootfs profile.
//! Serialized inputs are data; only the original supervisor owns their sealed FD.
use super::*;
use crate::{coding_submission::SubmissionContract, native_workflow::NativeSubtask};

pub fn protocol_root() -> String {
    blake3::hash(b"realm.immutable-rootfs-task-bootstrap/v1:submission,native_subtask,runtime,policy;before-hello-on-original-control-stream").to_hex().to_string()
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTaskInputs {
    pub schema: String,
    pub submission: SubmissionContract,
    pub native_subtask: NativeSubtask,
    pub runtime_blake3: String,
    pub policy_blake3: String,
}
impl NativeTaskInputs {
    pub fn root(&self) -> Result<String> {
        self.submission.validate().map_err(str::to_owned)?;
        self.native_subtask.validate().map_err(str::to_owned)?;
        if self.schema != "realm.native-task-inputs/v1"
            || !digest(&self.runtime_blake3)
            || !digest(&self.policy_blake3)
        {
            return Err("invalid native task input contract".into());
        }
        Ok(
            blake3::hash(&serde_json::to_vec(self).map_err(|e| e.to_string())?)
                .to_hex()
                .to_string(),
        )
    }
    pub(super) fn validate_policy(&self, policy: &RuntimeAdmissionPolicy) -> Result<()> {
        self.root()?;
        if policy.task_input_protocol.as_deref() != Some(protocol_root().as_str())
            || self.submission.task_sha256 != policy.expected.task_sha256
            || self.submission.worker_sha256 != policy.expected.worker_sha256
            || self.runtime_blake3
                != blake3::hash(&serde_json::to_vec(&policy.expected).map_err(|e| e.to_string())?)
                    .to_hex()
                    .as_str()
            || self.policy_blake3 != policy.input_policy_root()?
        {
            return Err("task inputs differ from independently installed runtime/policy".into());
        }
        Ok(())
    }
    pub fn matches_scope(&self, scope: &CodingExecutionScope) -> bool {
        self.submission == scope.submission
            && Some(&self.native_subtask) == scope.native_subtask.as_ref()
            && self
                .root()
                .is_ok_and(|root| scope.task_inputs_blake3.as_ref() == Some(&root))
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct OwnedTaskInputs {
    file: std::fs::File,
    data: NativeTaskInputs,
    root: String,
    rootfs: Option<(
        std::path::PathBuf,
        std::fs::File,
        crate::measured_launch::FileIdentity,
    )>,
}
#[cfg(target_os = "linux")]
impl OwnedTaskInputs {
    // Called only from the existing protected installed-supervisor loader.
    pub(super) fn create(
        policy: &RuntimeAdmissionPolicy,
        submission: &SubmissionContract,
        step: &NativeSubtask,
    ) -> Result<Self> {
        use std::{io::Write, os::fd::FromRawFd};
        let data = NativeTaskInputs {
            schema: "realm.native-task-inputs/v1".into(),
            submission: submission.clone(),
            native_subtask: step.clone(),
            runtime_blake3: blake3::hash(
                &serde_json::to_vec(&policy.expected).map_err(|e| e.to_string())?,
            )
            .to_hex()
            .to_string(),
            policy_blake3: policy.input_policy_root()?,
        };
        data.validate_policy(policy)?;
        let raw = serde_json::to_vec(&data).map_err(|e| e.to_string())?;
        if raw.len() > 64 * 1024 {
            return Err("native task input bound".into());
        }
        let fd = unsafe {
            libc::memfd_create(
                c"realm-native-task-inputs".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(&raw).map_err(|e| e.to_string())?;
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
        if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
            return Err("native task input sealing failed".into());
        }
        let root = data.root()?;
        Ok(Self {
            file,
            data,
            root,
            rootfs: None,
        })
    }
    pub(crate) fn data(&self) -> &NativeTaskInputs {
        &self.data
    }
    pub(crate) fn root(&self) -> &str {
        &self.root
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{FileExt, MetadataExt},
        };
        let required =
            libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
        if unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GET_SEALS) } != required {
            return Err("original task input seals lost".into());
        }
        let expected = serde_json::to_vec(&self.data).map_err(|e| e.to_string())?;
        let mut actual = vec![0; expected.len()];
        self.file
            .read_exact_at(&mut actual, 0)
            .map_err(|e| e.to_string())?;
        if actual != expected
            || self.file.metadata().map_err(|e| e.to_string())?.len() != actual.len() as u64
            || self.data.root()? != self.root
        {
            return Err("original task input descriptor changed".into());
        }
        if let Some((path, held, original)) = &self.rootfs {
            let current = crate::measured_launch::FileIdentity::measure(path)
                .map_err(|_| "held immutable rootfs unavailable")?;
            let a = held.metadata().map_err(|e| e.to_string())?;
            let b = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
            if current != *original || (a.dev(), a.ino()) != (b.dev(), b.ino()) {
                return Err("post-admission immutable rootfs mutation/replacement".into());
            }
        }
        Ok(())
    }
    pub(crate) fn hold_rootfs(&mut self, path: &std::path::Path, expected: &str) -> Result<()> {
        use std::os::unix::{fs::MetadataExt, fs::OpenOptionsExt};
        let held = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| e.to_string())?;
        let identity = crate::measured_launch::FileIdentity::measure(path)
            .map_err(|_| "immutable rootfs identity unavailable")?;
        let m = held.metadata().map_err(|e| e.to_string())?;
        if !identity.trusted_parent_chain()
            || identity.owner() != (0, 0)
            || identity.mode() & 0o7777 != 0o444
            || m.nlink() != 1
            || identity.blake3() != expected
        {
            return Err("immutable rootfs is not independently pinned/protected mode0444".into());
        }
        self.rootfs = Some((path.to_owned(), held, identity));
        self.revalidate()
    }
    pub(crate) fn validate_policy(&self, p: &RuntimeAdmissionPolicy) -> Result<()> {
        if self.rootfs.is_none() {
            return Err("input admission requires original held immutable rootfs".into());
        }
        self.revalidate()?;
        self.data.validate_policy(p)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn policy_and_scope() -> (RuntimeAdmissionPolicy, CodingExecutionScope) {
        // Explicit DATA fixture. These values establish no admission or VM owner.
        let mut policy = crate::runtime_admission::fixture_candidate().policy;
        policy.task_input_protocol = Some(protocol_root());
        let mut scope = crate::coding_semantics::tests::fixture()
            .semantic_evidence
            .unwrap()
            .prelaunch;
        scope.submission.task_sha256 = policy.expected.task_sha256.clone();
        scope.submission.worker_sha256 = policy.expected.worker_sha256.clone();
        scope.source_commit = policy.expected.source_commit.clone();
        scope.native_subtask = Some(NativeSubtask {
            workflow: "a".repeat(64),
            role: crate::native_workflow::NativeTaskRole::Api,
            attempt: 0,
            history_prefix_blake3: "b".repeat(64),
            predecessor: None,
        });
        (policy, scope)
    }
    #[test]
    fn separate_inputs_bind_immutable_image_runtime_policy_attempt_and_predecessor() {
        let (policy, mut scope) = policy_and_scope();
        let data = NativeTaskInputs {
            schema: "realm.native-task-inputs/v1".into(),
            submission: scope.submission.clone(),
            native_subtask: scope.native_subtask.clone().unwrap(),
            runtime_blake3: blake3::hash(&serde_json::to_vec(&policy.expected).unwrap())
                .to_hex()
                .to_string(),
            policy_blake3: policy.input_policy_root().unwrap(),
        };
        scope.task_inputs_blake3 = Some(data.root().unwrap());
        data.validate_policy(&policy).unwrap();
        assert!(data.matches_scope(&scope));
        for case in 0..6 {
            let mut p = policy.clone();
            let mut s = scope.clone();
            let mut d = data.clone();
            match case {
                0 => p.expected.rootfs_blake3 = "c".repeat(64),
                1 => p.expected.native_controller_blake3 = "c".repeat(64),
                2 => d.submission.run_id = "c".repeat(64),
                3 => d.native_subtask.history_prefix_blake3 = "c".repeat(64),
                4 => p.official_campaign_blake3 = "c".repeat(64),
                _ => s.task_inputs_blake3 = Some("c".repeat(64)),
            }
            assert!(
                d.validate_policy(&p).is_err() || !d.matches_scope(&s),
                "case {case}"
            );
        }
        let mut fresh = scope.clone();
        fresh.submission.run_id = "d".repeat(64);
        assert!(!data.matches_scope(&fresh));
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn local_owner() -> OwnedTaskInputs {
        let (p, s) = policy_and_scope();
        OwnedTaskInputs::create(&p, &s.submission, s.native_subtask.as_ref().unwrap()).unwrap()
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn actual_sealed_input_owner_rejects_child_writes_and_post_measurement_image_changes() {
        use std::{
            io::Write,
            os::{fd::AsRawFd, unix::fs::PermissionsExt},
        };
        let mut owner = local_owner();
        owner.revalidate().unwrap();
        // The real inherited Linux FD is immutable even to the same UID.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let written =
                unsafe { libc::pwrite(owner.file.as_raw_fd(), b"x".as_ptr().cast(), 1, 0) };
            let errno = std::io::Error::last_os_error().raw_os_error();
            unsafe {
                libc::_exit(if written == -1 && errno == Some(libc::EPERM) {
                    0
                } else {
                    1
                })
            };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(status, 0);
        owner.revalidate().unwrap();
        let root = std::env::temp_dir().join(format!(
            "realm-input-mutation-{}",
            crate::mediation::MediationChallenge::fresh()
                .unwrap()
                .root()
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("rootfs");
        std::fs::write(&path, b"original image bytes").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert!(owner.hold_rootfs(&path, &"f".repeat(64)).is_err()); // unprotected/unapproved source cannot enter production.
        // Component-only retained FD snapshot; deliberately bypasses NO runtime
        // guard and creates NO NativeCodingAttempt, admission or qualification.
        let original = crate::measured_launch::FileIdentity::measure(&path).unwrap();
        owner.rootfs = Some((path.clone(), std::fs::File::open(&path).unwrap(), original));
        owner.revalidate().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.write_all(b"substituted bytes!!!").unwrap();
        file.sync_all().unwrap();
        assert!(owner.revalidate().is_err());
        std::fs::rename(&path, root.join("original-retained")).unwrap();
        std::fs::write(&path, b"original image bytes").unwrap();
        assert!(owner.revalidate().is_err());
        if let Some(output) = std::env::var_os("REALM_INPUT_COMPONENT_EVIDENCE") {
            let record = serde_json::json!({"schema":"realm.local-sealed-input-component/v1","authority":"NONE",
                "native_vm_owners":0,"parent_pid":std::process::id(),"original_child_pid":child,"waitpid_status":status,
                "input_root":owner.root(),"seals":unsafe{libc::fcntl(owner.file.as_raw_fd(),libc::F_GET_SEALS)},
                "child_write_errno":"EPERM","input_descriptor_unchanged":true,"image_evidence_directory":root,
                "post_mutation_revalidation":"REFUSE","post_replacement_revalidation":"REFUSE",
                "production_rootfs_guard":"REFUSE_UNPROTECTED_LOCAL_FIXTURE","qualification":"NOT_RUN"});
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)
                .unwrap();
            file.write_all(&serde_json::to_vec_pretty(&record).unwrap())
                .unwrap();
            file.sync_all().unwrap();
        }
        // Preserve evidence files. They are disposable local component bytes.
    }
}
