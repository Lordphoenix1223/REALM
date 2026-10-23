//! Validated command plan for the official Firecracker jailer.
//!
//! The supervisor passes this validated plan to the official jailer after it
//! materializes the bound resources. The plan alone does not establish
//! confinement or mint production evidence; those claims require live host
//! observations from the supervisor's post-launch verifier.

use std::path::{Component, Path, PathBuf};

const LOCKED_FIRECRACKER_RELEASE: &str = "v1.17.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkPolicy {
    /// The Firecracker API configuration must contain no network interfaces.
    NoGuestInterfaces,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JailerPlanError {
    InvalidIdentity,
    InvalidPath,
    ReleasePairMismatch,
    UnsupportedRelease,
    InvalidCgroupLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionJailerPlan {
    jailer: PathBuf,
    firecracker: PathBuf,
    jail_id: String,
    uid: u32,
    gid: u32,
    chroot_base: PathBuf,
    cgroup_parent: PathBuf,
    memory_max_bytes: u64,
    pids_max: u32,
    api_socket_in_jail: PathBuf,
    release: String,
    network_policy: NetworkPolicy,
}

impl ProductionJailerPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        jailer: PathBuf,
        jailer_release: &str,
        firecracker: PathBuf,
        firecracker_release: &str,
        jail_id: String,
        uid: u32,
        gid: u32,
        chroot_base: PathBuf,
        cgroup_parent: PathBuf,
        memory_max_bytes: u64,
        pids_max: u32,
        api_socket_in_jail: PathBuf,
        network_policy: NetworkPolicy,
    ) -> Result<Self, JailerPlanError> {
        if jailer_release != firecracker_release {
            return Err(JailerPlanError::ReleasePairMismatch);
        }
        if jailer_release != LOCKED_FIRECRACKER_RELEASE {
            return Err(JailerPlanError::UnsupportedRelease);
        }
        if !safe_jail_id(&jail_id) || uid == 0 || gid == 0 {
            return Err(JailerPlanError::InvalidIdentity);
        }
        if !jailer.is_absolute()
            || !firecracker.is_absolute()
            || !chroot_base.is_absolute()
            || !safe_relative_path(&cgroup_parent)
            || !api_socket_in_jail.is_absolute()
            || api_socket_in_jail
                .components()
                .any(|part| part == Component::ParentDir)
        {
            return Err(JailerPlanError::InvalidPath);
        }
        if memory_max_bytes == 0 || pids_max == 0 {
            return Err(JailerPlanError::InvalidCgroupLimits);
        }
        Ok(Self {
            jailer,
            firecracker,
            jail_id,
            uid,
            gid,
            chroot_base,
            cgroup_parent,
            memory_max_bytes,
            pids_max,
            api_socket_in_jail,
            release: jailer_release.to_owned(),
            network_policy,
        })
    }

    pub fn jailer_executable(&self) -> &Path {
        &self.jailer
    }

    pub fn release(&self) -> &str {
        &self.release
    }

    pub fn network_policy(&self) -> NetworkPolicy {
        self.network_policy
    }

    /// Arguments for `jailer`; callers must still verify the locked official
    /// binary hashes, create and protect the per-run resource tree, then verify
    /// the actual VMM.
    pub fn arguments(&self) -> Vec<String> {
        vec![
            "--id".into(),
            self.jail_id.clone(),
            "--exec-file".into(),
            self.firecracker.to_string_lossy().into_owned(),
            "--uid".into(),
            self.uid.to_string(),
            "--gid".into(),
            self.gid.to_string(),
            "--chroot-base-dir".into(),
            self.chroot_base.to_string_lossy().into_owned(),
            "--cgroup-version".into(),
            "2".into(),
            "--parent-cgroup".into(),
            self.cgroup_parent.to_string_lossy().into_owned(),
            "--cgroup".into(),
            format!("memory.max={}", self.memory_max_bytes),
            "--cgroup".into(),
            "cpu.max=100000 100000".into(),
            "--cgroup".into(),
            format!("pids.max={}", self.pids_max),
            "--new-pid-ns".into(),
            "--".into(),
            "--api-sock".into(),
            self.api_socket_in_jail.to_string_lossy().into_owned(),
        ]
    }
}

fn safe_jail_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn safe_relative_path(value: &Path) -> bool {
    !value.as_os_str().is_empty()
        && value
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ProductionJailerPlan {
        ProductionJailerPlan::new(
            "/opt/firecracker/jailer-v1.17.0".into(),
            "v1.17.0",
            "/opt/firecracker/firecracker-v1.17.0".into(),
            "v1.17.0",
            "run-0123456789abcdef".into(),
            1001,
            1001,
            "/srv/realm-jailer".into(),
            "realm-v6".into(),
            536_870_912,
            16,
            "/run/firecracker.socket".into(),
            NetworkPolicy::NoGuestInterfaces,
        )
        .unwrap()
    }

    #[test]
    fn plan_uses_official_strict_jailer_options() {
        let plan = plan();
        let args = plan.arguments();
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--cgroup-version", "2"])
        );
        assert!(args.windows(2).any(|pair| pair == ["--new-pid-ns", "--"]));
        assert!(args.iter().any(|arg| arg == "memory.max=536870912"));
        assert!(args.iter().any(|arg| arg == "cpu.max=100000 100000"));
        assert!(args.iter().any(|arg| arg == "pids.max=16"));
        assert!(!args.iter().any(|arg| arg == "--no-seccomp"));
        assert!(!args.iter().any(|arg| arg == "--daemonize"));
        assert_eq!(plan.network_policy(), NetworkPolicy::NoGuestInterfaces);
    }

    #[test]
    fn plan_rejects_unsafe_or_ambiguous_configuration() {
        assert_eq!(
            ProductionJailerPlan::new(
                "/jailer".into(),
                "v1.17.0",
                "/firecracker".into(),
                "v1.16.0",
                "run-1".into(),
                1001,
                1001,
                "/jails".into(),
                "realm-v6".into(),
                512,
                16,
                "/run/fc.sock".into(),
                NetworkPolicy::NoGuestInterfaces,
            ),
            Err(JailerPlanError::ReleasePairMismatch),
        );
        assert_eq!(
            ProductionJailerPlan::new(
                "/jailer".into(),
                "v1.16.0",
                "/firecracker".into(),
                "v1.16.0",
                "run-1".into(),
                1001,
                1001,
                "/jails".into(),
                "realm-v6".into(),
                512,
                16,
                "/run/fc.sock".into(),
                NetworkPolicy::NoGuestInterfaces,
            ),
            Err(JailerPlanError::UnsupportedRelease),
        );
        assert_eq!(
            ProductionJailerPlan::new(
                "/jailer".into(),
                "v1.17.0",
                "/firecracker".into(),
                "v1.17.0",
                "../reuse".into(),
                0,
                1001,
                "/jails".into(),
                "../parent".into(),
                0,
                16,
                "/run/../outside.sock".into(),
                NetworkPolicy::NoGuestInterfaces,
            ),
            Err(JailerPlanError::InvalidIdentity),
        );
    }
}
