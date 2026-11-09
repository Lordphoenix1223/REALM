//! Model-agnostic agent and sandbox boundary for Phase III.
//!
//! The deterministic adapter exercises the same OS sandbox command path as a
//! real adapter. Codex/Claude adapters only become runnable after capability
//! probing and sandbox conformance; unavailable or unsafe execution is a
//! recorded blocker, never an unrestricted fallback.

use realm_core::PathBytes;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum AgentKind {
    Deterministic,
    Codex,
    Claude,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentCapabilities {
    pub kind: AgentKind,
    pub available: bool,
    pub version: Option<String>,
    pub supports_noninteractive: bool,
    pub supports_json_events: bool,
    pub supports_ephemeral_state: bool,
    pub sandbox_mode: String,
    pub note: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxRoots {
    pub candidate: PathBuf,
    pub agent_state: PathBuf,
    pub scratch: PathBuf,
    pub history: PathBuf,
    pub cas: PathBuf,
    pub ledger: PathBuf,
    pub contracts: PathBuf,
    pub oracle: PathBuf,
    pub evaluator: PathBuf,
    pub host: PathBuf,
    pub escape_sentinel: PathBuf,
}

impl SandboxRoots {
    pub fn strict_fixture(root: &Path) -> Self {
        let candidate = root.join("candidate");
        Self {
            agent_state: candidate.join(".realm-agent-state"),
            scratch: candidate.join(".realm-scratch"),
            candidate,
            history: root.join("protected/history"),
            cas: root.join("protected/cas"),
            ledger: root.join("protected/ledger"),
            contracts: root.join("protected/contracts"),
            oracle: root.join("protected/oracle"),
            evaluator: root.join("protected/evaluator"),
            host: root.join("host"),
            escape_sentinel: root.join("host/escape-sentinel"),
        }
    }

    fn protected_roots(&self) -> [(&'static str, &Path); 7] {
        [
            ("history", &self.history),
            ("cas", &self.cas),
            ("ledger", &self.ledger),
            ("contracts", &self.contracts),
            ("oracle", &self.oracle),
            ("evaluator", &self.evaluator),
            ("host", &self.host),
        ]
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SandboxOwnership {
    AgentNative,
    RealmExternal,
    ContainerOrVm,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxAttackResult {
    pub id: String,
    pub target: String,
    pub expected: String,
    pub observed: String,
    pub passed: bool,
    pub exit_code: Option<i32>,
    pub stderr_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KernelSandboxConformance {
    pub schema_version: u16,
    pub ownership: SandboxOwnership,
    pub status: SandboxStatus,
    pub kernel_enforcement: String,
    pub policy_hash: String,
    pub candidate_is_only_writable_root: bool,
    pub environment_sanitized: bool,
    pub network_denied: bool,
    pub all_attacks_passed: bool,
    pub attacks: Vec<SandboxAttackResult>,
    pub inherited_environment: BTreeMap<String, String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxConformance {
    pub status: SandboxStatus,
    pub candidate_write: bool,
    pub outside_write_denied: bool,
    pub history_read_denied: bool,
    pub history_write_denied: bool,
    pub oracle_read_denied: bool,
    pub oracle_write_denied: bool,
    pub escape_sentinel_unchanged: bool,
    pub details: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum SandboxStatus {
    Proven,
    Blocked,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DeterministicOperation {
    Write { path: PathBytes, bytes: Vec<u8> },
    Delete { path: PathBytes },
    Rename { from: PathBytes, to: PathBytes },
    Mkdir { path: PathBytes },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeterministicScript {
    pub script_id: String,
    pub operations: Vec<DeterministicOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentRequest {
    pub prompt: String,
    pub workspace: PathBuf,
    pub state_root: PathBuf,
    pub scratch_root: PathBuf,
    pub history_root: PathBuf,
    pub cas_root: PathBuf,
    pub ledger_root: PathBuf,
    pub contracts_root: PathBuf,
    pub oracle_root: PathBuf,
    pub evaluator_root: PathBuf,
    pub host_root: PathBuf,
    pub timeout_ms: u64,
    pub model: Option<String>,
    pub deterministic_script: Option<DeterministicScript>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentRunRecord {
    pub kind: AgentKind,
    pub version: Option<String>,
    pub model: Option<String>,
    pub prompt_hash: String,
    pub start_unix_ms: u128,
    pub end_unix_ms: u128,
    pub exit_code: Option<i32>,
    pub sandbox: SandboxStatus,
    pub host_escape: bool,
    pub structured_events: u64,
    pub final_message_hash: Option<String>,
    pub note: String,
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("agent I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("agent is unavailable: {0}")]
    Unavailable(String),
    #[error("sandbox is not proven: {0}")]
    SandboxBlocked(String),
    #[error("invalid candidate-relative path: {0}")]
    InvalidPath(String),
    #[error("agent command failed: {0}")]
    CommandFailed(String),
}

pub trait AgentSandbox {
    fn preflight(&self, roots: &SandboxRoots) -> Result<SandboxConformance, AgentError>;
    fn run_program(
        &self,
        roots: &SandboxRoots,
        program: &Path,
        args: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<CommandOutput, AgentError>;
}

pub trait AgentAdapter {
    fn capabilities(&self) -> AgentCapabilities;
    fn run(
        &self,
        request: &AgentRequest,
        sandbox: &dyn AgentSandbox,
    ) -> Result<AgentRunRecord, AgentError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub struct PlatformSandbox;

impl PlatformSandbox {
    pub fn available() -> bool {
        cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").exists()
    }

    const EXECUTABLES: [&'static str; 16] = [
        "/bin/cat",
        "/bin/ln",
        "/bin/ls",
        "/bin/mkdir",
        "/bin/mv",
        "/bin/ps",
        "/bin/rm",
        "/bin/sh",
        "/usr/bin/cmp",
        "/usr/bin/env",
        "/usr/bin/false",
        "/usr/bin/nc",
        "/usr/bin/stat",
        "/usr/bin/tee",
        "/usr/bin/touch",
        "/usr/bin/true",
    ];

    fn prepare_candidate_runtime(roots: &SandboxRoots) -> Result<(), AgentError> {
        for path in [
            &roots.candidate,
            &roots.agent_state,
            &roots.scratch,
            &roots.candidate.join(".realm-home"),
            &roots.candidate.join(".realm-tmp"),
        ] {
            fs::create_dir_all(path)?;
        }
        Ok(())
    }

    fn prepare_roots(roots: &SandboxRoots) -> Result<(), AgentError> {
        Self::prepare_candidate_runtime(roots)?;
        for path in [
            &roots.history,
            &roots.cas,
            &roots.ledger,
            &roots.contracts,
            &roots.oracle,
            &roots.evaluator,
            &roots.host,
        ] {
            fs::create_dir_all(path)?;
        }
        for path in [
            roots.candidate.join("candidate-write"),
            roots.candidate.join("candidate-renamed"),
            roots.candidate.join("candidate-hardlink"),
            roots.candidate.join("history-symlink"),
        ] {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_dir(roots.candidate.join("candidate-directory"));
        for (name, path) in roots.protected_roots() {
            fs::write(path.join("hidden"), format!("{name}-secret"))?;
        }
        fs::write(&roots.escape_sentinel, b"realm-host-sentinel")?;
        Self::validate_roots(roots)
    }

    fn validate_roots(roots: &SandboxRoots) -> Result<(), AgentError> {
        for (label, path) in
            std::iter::once(("candidate", roots.candidate.as_path())).chain(roots.protected_roots())
        {
            if !path.is_absolute() {
                return Err(AgentError::SandboxBlocked(format!(
                    "{label} root is not absolute: {}",
                    path.display()
                )));
            }
            if fs::symlink_metadata(path)?.file_type().is_symlink() {
                return Err(AgentError::SandboxBlocked(format!(
                    "{label} root must not be a symlink"
                )));
            }
        }
        let candidate = fs::canonicalize(&roots.candidate)?;
        for (label, path) in [
            ("agent_state", &roots.agent_state),
            ("scratch", &roots.scratch),
        ] {
            let path = fs::canonicalize(path)?;
            if !path.starts_with(&candidate) {
                return Err(AgentError::SandboxBlocked(format!(
                    "{label} must be inside the candidate-only writable root"
                )));
            }
        }
        for (label, path) in roots.protected_roots() {
            let protected = fs::canonicalize(path)?;
            if protected.starts_with(&candidate) || candidate.starts_with(&protected) {
                return Err(AgentError::SandboxBlocked(format!(
                    "{label} overlaps the candidate root"
                )));
            }
        }
        if !roots.escape_sentinel.starts_with(&roots.host) {
            return Err(AgentError::SandboxBlocked(
                "escape sentinel must live inside the protected host root".into(),
            ));
        }
        Ok(())
    }

    fn profile(roots: &SandboxRoots) -> Result<String, AgentError> {
        Self::validate_roots(roots)?;
        let candidate = fs::canonicalize(&roots.candidate)?;
        let mut profile = String::from(
            "(version 1)\n(deny default)\n(allow process-fork)\n(allow process-exec)\n(allow sysctl-read)\n",
        );
        for ancestor in candidate.ancestors().skip(1) {
            profile.push_str(&format!(
                "(allow file-read-data (literal \"{}\"))\n",
                escape(&ancestor.to_string_lossy())
            ));
        }
        for path in [
            "/bin",
            "/usr/bin",
            "/usr/lib",
            "/System/Library",
            "/Library/Apple/System/Library",
            "/private/var/db/dyld",
        ] {
            profile.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                escape(path)
            ));
        }
        for path in ["/dev/null", "/dev/random", "/dev/urandom"] {
            profile.push_str(&format!(
                "(allow file-read* file-write* (literal \"{}\"))\n",
                escape(path)
            ));
        }
        profile.push_str(&format!(
            "(allow file-read* file-write* (subpath \"{}\"))\n",
            escape(&candidate.to_string_lossy())
        ));
        profile.push_str("(deny network*)\n");
        Ok(profile)
    }

    fn configure_command(command: &mut Command, roots: &SandboxRoots) {
        let candidate = &roots.candidate;
        command
            .current_dir(candidate)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", candidate.join(".realm-home"))
            .env("TMPDIR", candidate.join(".realm-tmp"))
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("REALM_SANDBOX", "1");
    }

    fn sandbox_command(
        roots: &SandboxRoots,
        program: &Path,
        args: &[String],
    ) -> Result<Command, AgentError> {
        let program_allowed = Self::EXECUTABLES
            .iter()
            .any(|allowed| program == Path::new(allowed))
            || program.starts_with(&roots.candidate);
        if !program_allowed {
            return Err(AgentError::SandboxBlocked(format!(
                "program is outside the executable allowlist: {}",
                program.display()
            )));
        }
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .arg("-p")
            .arg(Self::profile(roots)?)
            .arg(program)
            .args(args);
        Self::configure_command(&mut command, roots);
        Ok(command)
    }

    fn run_raw(
        &self,
        roots: &SandboxRoots,
        program: &Path,
        args: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<CommandOutput, AgentError> {
        let mut command = Self::sandbox_command(roots, program, args)?;
        if let Some(bytes) = stdin {
            command.stdin(Stdio::piped());
            let mut child = command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            if let Some(mut input) = child.stdin.take() {
                input.write_all(bytes)?;
            }
            return command_output(child.wait_with_output()?, false);
        }
        command_output(command.output()?, false)
    }

    pub fn strict_conformance(
        &self,
        roots: &SandboxRoots,
    ) -> Result<KernelSandboxConformance, AgentError> {
        if !Self::available() {
            return Ok(KernelSandboxConformance {
                schema_version: 3,
                ownership: SandboxOwnership::RealmExternal,
                status: SandboxStatus::Blocked,
                kernel_enforcement: "macOS Seatbelt via sandbox-exec".into(),
                policy_hash: String::new(),
                candidate_is_only_writable_root: false,
                environment_sanitized: false,
                network_denied: false,
                all_attacks_passed: false,
                attacks: Vec::new(),
                inherited_environment: BTreeMap::new(),
                notes: vec!["/usr/bin/sandbox-exec is unavailable".into()],
            });
        }
        Self::prepare_roots(roots).map_err(|error| {
            AgentError::CommandFailed(format!("sandbox root preparation failed: {error}"))
        })?;
        let profile = Self::profile(roots).map_err(|error| {
            AgentError::CommandFailed(format!("sandbox profile construction failed: {error}"))
        })?;
        let policy_hash = blake3::hash(profile.as_bytes()).to_hex().to_string();
        let mut attacks = Vec::new();

        let write = match self.run_raw(
            roots,
            Path::new("/usr/bin/tee"),
            &["candidate-write".into()],
            Some(b"candidate-ok"),
        ) {
            Ok(output) => output,
            Err(error) if error.to_string().contains("Operation not permitted") => {
                let error_text = error.to_string();
                return Ok(KernelSandboxConformance {
                    schema_version: 3,
                    ownership: SandboxOwnership::RealmExternal,
                    status: SandboxStatus::Blocked,
                    kernel_enforcement: "macOS Seatbelt via /usr/bin/sandbox-exec; Realm is the single sandbox owner".into(),
                    policy_hash,
                    candidate_is_only_writable_root: false,
                    environment_sanitized: false,
                    network_denied: false,
                    all_attacks_passed: false,
                    attacks: vec![SandboxAttackResult {
                        id: "candidate_write".into(),
                        target: "candidate/candidate-write".into(),
                        expected: "ALLOW".into(),
                        observed: "parent execution environment rejected sandbox_apply before child execution".into(),
                        passed: false,
                        exit_code: None,
                        stderr_hash: Some(blake3::hash(error_text.as_bytes()).to_hex().to_string()),
                    }],
                    inherited_environment: BTreeMap::new(),
                    notes: vec![
                        "The managed parent sandbox rejected Realm's Seatbelt owner. Re-run from a normal host process; never weaken the child profile as a workaround.".into(),
                    ],
                });
            }
            Err(error) => return Err(error),
        };
        let write_stderr = String::from_utf8_lossy(&write.stderr);
        if write.status != 0
            && (write_stderr.contains("sandbox_apply")
                || write_stderr.contains("Operation not permitted"))
        {
            return Ok(KernelSandboxConformance {
                schema_version: 3,
                ownership: SandboxOwnership::RealmExternal,
                status: SandboxStatus::Blocked,
                kernel_enforcement: "macOS Seatbelt via /usr/bin/sandbox-exec; Realm is the single sandbox owner".into(),
                policy_hash,
                candidate_is_only_writable_root: false,
                environment_sanitized: false,
                network_denied: false,
                all_attacks_passed: false,
                attacks: vec![attack_result(
                    "candidate_write",
                    "candidate/candidate-write",
                    true,
                    &write,
                    false,
                )],
                inherited_environment: BTreeMap::new(),
                notes: vec![
                    "The managed parent sandbox rejected Realm's Seatbelt owner. Re-run from a normal host process; never weaken the child profile as a workaround.".into(),
                ],
            });
        }
        attacks.push(attack_result(
            "candidate_write",
            "candidate/candidate-write",
            true,
            &write,
            fs::read(roots.candidate.join("candidate-write"))
                .ok()
                .as_deref()
                == Some(b"candidate-ok"),
        ));
        let read = self.run_raw(
            roots,
            Path::new("/bin/cat"),
            &["candidate-write".into()],
            None,
        )?;
        attacks.push(attack_result(
            "candidate_read",
            "candidate/candidate-write",
            true,
            &read,
            read.stdout == b"candidate-ok",
        ));
        let rename = self.run_raw(
            roots,
            Path::new("/bin/mv"),
            &["candidate-write".into(), "candidate-renamed".into()],
            None,
        )?;
        attacks.push(attack_result(
            "candidate_rename",
            "candidate/candidate-renamed",
            true,
            &rename,
            roots.candidate.join("candidate-renamed").exists(),
        ));
        let delete = self.run_raw(
            roots,
            Path::new("/bin/rm"),
            &["-f".into(), "candidate-renamed".into()],
            None,
        )?;
        attacks.push(attack_result(
            "candidate_delete",
            "candidate/candidate-renamed",
            true,
            &delete,
            !roots.candidate.join("candidate-renamed").exists(),
        ));
        let mkdir = self.run_raw(
            roots,
            Path::new("/bin/mkdir"),
            &["candidate-directory".into()],
            None,
        )?;
        attacks.push(attack_result(
            "candidate_mkdir",
            "candidate/candidate-directory",
            true,
            &mkdir,
            roots.candidate.join("candidate-directory").is_dir(),
        ));

        for (label, root) in roots.protected_roots() {
            let marker = root.join("hidden");
            let before = fs::read(&marker)?;
            for (operation, program, args) in [
                (
                    "read",
                    Path::new("/bin/cat"),
                    vec![marker.to_string_lossy().into_owned()],
                ),
                (
                    "metadata",
                    Path::new("/usr/bin/stat"),
                    vec![marker.to_string_lossy().into_owned()],
                ),
                (
                    "write",
                    Path::new("/usr/bin/touch"),
                    vec![root.join("write-probe").to_string_lossy().into_owned()],
                ),
                (
                    "delete",
                    Path::new("/bin/rm"),
                    vec!["-f".into(), marker.to_string_lossy().into_owned()],
                ),
            ] {
                let output = self.run_raw(roots, program, &args, None)?;
                let unchanged = fs::read(&marker).ok().as_deref() == Some(before.as_slice())
                    && !root.join("write-probe").exists();
                attacks.push(attack_result(
                    &format!("{label}_{operation}_denied"),
                    &format!("{label}/{}", marker.file_name().unwrap().to_string_lossy()),
                    false,
                    &output,
                    unchanged,
                ));
            }
        }

        let symlink = roots.candidate.join("history-symlink");
        #[cfg(unix)]
        std::os::unix::fs::symlink(roots.history.join("hidden"), &symlink)?;
        let symlink_read = self.run_raw(
            roots,
            Path::new("/bin/cat"),
            &["history-symlink".into()],
            None,
        )?;
        attacks.push(attack_result(
            "symlink_escape_read_denied",
            "candidate/history-symlink -> history/hidden",
            false,
            &symlink_read,
            true,
        ));
        let symlink_write = self.run_raw(
            roots,
            Path::new("/usr/bin/tee"),
            &["history-symlink".into()],
            Some(b"escape"),
        )?;
        attacks.push(attack_result(
            "symlink_escape_write_denied",
            "candidate/history-symlink -> history/hidden",
            false,
            &symlink_write,
            fs::read(roots.history.join("hidden"))? == b"history-secret",
        ));

        let traversal = roots.history.join("hidden").to_string_lossy().into_owned();
        let traversal_read = self.run_raw(
            roots,
            Path::new("/bin/cat"),
            std::slice::from_ref(&traversal),
            None,
        )?;
        attacks.push(attack_result(
            "absolute_path_escape_read_denied",
            "candidate -> history/hidden",
            false,
            &traversal_read,
            true,
        ));
        let hardlink = self.run_raw(
            roots,
            Path::new("/bin/ln"),
            &[traversal, "candidate-hardlink".into()],
            None,
        )?;
        attacks.push(attack_result(
            "protected_hardlink_creation_denied",
            "history/hidden -> candidate/candidate-hardlink",
            false,
            &hardlink,
            !roots.candidate.join("candidate-hardlink").exists(),
        ));

        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let network = self.run_raw(
            roots,
            Path::new("/usr/bin/nc"),
            &[
                "-G".into(),
                "1".into(),
                "-z".into(),
                "127.0.0.1".into(),
                port.to_string(),
            ],
            None,
        )?;
        let connected = listener.accept().is_ok();
        attacks.push(attack_result(
            "network_loopback_denied",
            "127.0.0.1 ephemeral listener",
            false,
            &network,
            !connected,
        ));

        let environment = self.run_raw(roots, Path::new("/usr/bin/env"), &[], None)?;
        let inherited_environment = String::from_utf8_lossy(&environment.stdout)
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect::<BTreeMap<_, _>>();
        let allowed_environment = ["HOME", "LANG", "LC_ALL", "PATH", "REALM_SANDBOX", "TMPDIR"];
        let environment_sanitized = environment.status == 0
            && inherited_environment
                .keys()
                .all(|key| allowed_environment.contains(&key.as_str()))
            && inherited_environment
                .get("HOME")
                .is_some_and(|home| Path::new(home).starts_with(&roots.candidate))
            && inherited_environment
                .get("TMPDIR")
                .is_some_and(|tmp| Path::new(tmp).starts_with(&roots.candidate));
        attacks.push(attack_result(
            "environment_is_sanitized",
            "child process environment",
            true,
            &environment,
            environment_sanitized,
        ));

        let host_unchanged = fs::read(&roots.escape_sentinel)? == b"realm-host-sentinel";
        let all_attacks_passed = attacks.iter().all(|attack| attack.passed) && host_unchanged;
        let blocked_by_parent = attacks.iter().any(|attack| {
            attack.id == "candidate_write"
                && !attack.passed
                && attack.observed.contains("sandbox_apply")
        });
        Ok(KernelSandboxConformance {
            schema_version: 3,
            ownership: SandboxOwnership::RealmExternal,
            status: if blocked_by_parent {
                SandboxStatus::Blocked
            } else if all_attacks_passed {
                SandboxStatus::Proven
            } else {
                SandboxStatus::Failed
            },
            kernel_enforcement: "macOS Seatbelt via /usr/bin/sandbox-exec; Realm is the single sandbox owner".into(),
            policy_hash,
            candidate_is_only_writable_root: all_attacks_passed,
            environment_sanitized,
            network_denied: attacks
                .iter()
                .find(|attack| attack.id == "network_loopback_denied")
                .is_some_and(|attack| attack.passed),
            all_attacks_passed,
            attacks,
            inherited_environment,
            notes: vec![
                "The child may read/write only the candidate root; agent state, HOME, and TMPDIR are candidate subdirectories.".into(),
                "Cloud model execution is not admitted under this zero-network policy; this conformance proves the child tool boundary, not a frontier-model run.".into(),
                "Run this probe from a normal host process. A managed parent sandbox may reject nested sandbox_apply before Realm's policy is installed.".into(),
            ],
        })
    }
}

impl AgentSandbox for PlatformSandbox {
    fn preflight(&self, roots: &SandboxRoots) -> Result<SandboxConformance, AgentError> {
        Self::prepare_candidate_runtime(roots)?;
        Self::validate_roots(roots)?;
        fs::write(&roots.escape_sentinel, b"realm-host-sentinel")?;

        let candidate_probe = format!(".realm-preflight-write-{}", unique_suffix());
        let candidate_output = self.run_raw(
            roots,
            Path::new("/usr/bin/tee"),
            std::slice::from_ref(&candidate_probe),
            Some(b"candidate-ok"),
        )?;
        let candidate_write = candidate_output.status == 0
            && fs::read(roots.candidate.join(&candidate_probe))
                .ok()
                .as_deref()
                == Some(b"candidate-ok");
        let _ = fs::remove_file(roots.candidate.join(&candidate_probe));

        let probe_root = |label: &str, root: &Path| -> Result<(bool, bool), AgentError> {
            let read = self.run_raw(
                roots,
                Path::new("/bin/ls"),
                &[root.to_string_lossy().into_owned()],
                None,
            )?;
            let write_probe = root.join(format!(".realm-write-probe-{label}-{}", unique_suffix()));
            let write = self.run_raw(
                roots,
                Path::new("/usr/bin/touch"),
                &[write_probe.to_string_lossy().into_owned()],
                None,
            )?;
            Ok((read.status != 0, write.status != 0 && !write_probe.exists()))
        };
        let (history_read_denied, history_write_denied) = probe_root("history", &roots.history)?;
        let (oracle_read_denied, oracle_write_denied) = probe_root("oracle", &roots.oracle)?;
        let (_, host_write_denied) = probe_root("host", &roots.host)?;
        let escape_sentinel_unchanged =
            fs::read(&roots.escape_sentinel).ok().as_deref() == Some(b"realm-host-sentinel");
        let outside_write_denied = history_write_denied && oracle_write_denied && host_write_denied;
        let passed = candidate_write
            && outside_write_denied
            && history_read_denied
            && oracle_read_denied
            && escape_sentinel_unchanged;
        Ok(SandboxConformance {
            status: if passed {
                SandboxStatus::Proven
            } else {
                SandboxStatus::Failed
            },
            candidate_write,
            outside_write_denied,
            history_read_denied,
            history_write_denied,
            oracle_read_denied,
            oracle_write_denied,
            escape_sentinel_unchanged,
            details: vec![
                "Non-destructive runtime preflight: protected roots are probed but never seeded or rewritten.".into(),
                "The full 39-attack admission gate remains sandbox-conformance-v3.".into(),
            ],
        })
    }

    fn run_program(
        &self,
        roots: &SandboxRoots,
        program: &Path,
        args: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<CommandOutput, AgentError> {
        let output = self.run_raw(roots, program, args, stdin)?;
        if output.status != 0 {
            return Err(AgentError::CommandFailed(
                String::from_utf8_lossy(&output.stderr).into(),
            ));
        }
        Ok(output)
    }
}

fn attack_result(
    id: &str,
    target: &str,
    expected_allow: bool,
    output: &CommandOutput,
    state_check: bool,
) -> SandboxAttackResult {
    let allowed = output.status == 0;
    let stderr = String::from_utf8_lossy(&output.stderr);
    SandboxAttackResult {
        id: id.into(),
        target: target.into(),
        expected: if expected_allow { "ALLOW" } else { "DENY" }.into(),
        observed: if stderr.contains("sandbox_apply") {
            format!("sandbox_apply rejected before child execution: {stderr}")
        } else if allowed {
            "ALLOWED".into()
        } else {
            "DENIED".into()
        },
        passed: allowed == expected_allow && state_check,
        exit_code: Some(output.status),
        stderr_hash: (!output.stderr.is_empty())
            .then(|| blake3::hash(&output.stderr).to_hex().to_string()),
    }
}

pub struct DeterministicAgent;

impl AgentAdapter for DeterministicAgent {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            kind: AgentKind::Deterministic,
            available: true,
            version: Some("realm-deterministic-1".into()),
            supports_noninteractive: true,
            supports_json_events: true,
            supports_ephemeral_state: true,
            sandbox_mode: "platform-seatbelt-required".into(),
            note: "Scripted mutations are executed through the same sandbox command boundary."
                .into(),
        }
    }

    fn run(
        &self,
        request: &AgentRequest,
        sandbox: &dyn AgentSandbox,
    ) -> Result<AgentRunRecord, AgentError> {
        let roots = SandboxRoots {
            candidate: request.workspace.clone(),
            agent_state: request.state_root.clone(),
            scratch: request.scratch_root.clone(),
            history: request.history_root.clone(),
            cas: request.cas_root.clone(),
            ledger: request.ledger_root.clone(),
            contracts: request.contracts_root.clone(),
            oracle: request.oracle_root.clone(),
            evaluator: request.evaluator_root.clone(),
            host: request.host_root.clone(),
            escape_sentinel: request
                .host_root
                .join(format!("realm-escape-{}", unique_suffix())),
        };
        let conformance = sandbox.preflight(&roots)?;
        if conformance.status != SandboxStatus::Proven {
            let _ = fs::remove_file(&roots.escape_sentinel);
            return Err(AgentError::SandboxBlocked(format!(
                "preflight status {:?}",
                conformance.status
            )));
        }
        let start = now_ms();
        let script = request
            .deterministic_script
            .as_ref()
            .ok_or_else(|| AgentError::Unavailable("deterministic script missing".into()))?;
        let mut events = 0;
        for operation in &script.operations {
            match operation {
                DeterministicOperation::Write { path, bytes } => {
                    let relative = safe_relative(path)?;
                    let output = sandbox.run_program(
                        &roots,
                        Path::new("/usr/bin/tee"),
                        &[relative.to_string_lossy().into_owned()],
                        Some(bytes),
                    )?;
                    if output.status != 0 {
                        return Err(AgentError::CommandFailed(
                            String::from_utf8_lossy(&output.stderr).into(),
                        ));
                    }
                }
                DeterministicOperation::Delete { path } => {
                    let relative = safe_relative(path)?;
                    let output = sandbox.run_program(
                        &roots,
                        Path::new("/bin/rm"),
                        &["-f".into(), relative.to_string_lossy().into_owned()],
                        None,
                    )?;
                    if output.status != 0 {
                        return Err(AgentError::CommandFailed(
                            String::from_utf8_lossy(&output.stderr).into(),
                        ));
                    }
                }
                DeterministicOperation::Rename { from, to } => {
                    let from = safe_relative(from)?;
                    let to = safe_relative(to)?;
                    if let Some(parent) = to.parent() {
                        fs::create_dir_all(request.workspace.join(parent))?;
                    }
                    let output = sandbox.run_program(
                        &roots,
                        Path::new("/bin/mv"),
                        &[
                            from.to_string_lossy().into_owned(),
                            to.to_string_lossy().into_owned(),
                        ],
                        None,
                    )?;
                    if output.status != 0 {
                        return Err(AgentError::CommandFailed(
                            String::from_utf8_lossy(&output.stderr).into(),
                        ));
                    }
                }
                DeterministicOperation::Mkdir { path } => {
                    let relative = safe_relative(path)?;
                    let output = sandbox.run_program(
                        &roots,
                        Path::new("/usr/bin/mkdir"),
                        &["-p".into(), relative.to_string_lossy().into_owned()],
                        None,
                    )?;
                    if output.status != 0 {
                        return Err(AgentError::CommandFailed(
                            String::from_utf8_lossy(&output.stderr).into(),
                        ));
                    }
                }
            }
            events += 1;
        }
        let host_escape =
            fs::read(&roots.escape_sentinel).ok().as_deref() != Some(b"realm-host-sentinel");
        let _ = fs::remove_file(&roots.escape_sentinel);
        Ok(AgentRunRecord {
            kind: AgentKind::Deterministic,
            version: Some("realm-deterministic-1".into()),
            model: None,
            prompt_hash: blake3::hash(request.prompt.as_bytes()).to_hex().to_string(),
            start_unix_ms: start,
            end_unix_ms: now_ms(),
            exit_code: Some(0),
            sandbox: SandboxStatus::Proven,
            host_escape,
            structured_events: events,
            final_message_hash: None,
            note: script.script_id.clone(),
        })
    }
}

pub struct CodexAdapter {
    capabilities: AgentCapabilities,
}

impl CodexAdapter {
    pub fn probe() -> Self {
        let version = command_text("codex", &["--version"]);
        let help = command_text("codex", &["exec", "--help"]);
        Self {
            capabilities: AgentCapabilities {
                kind: AgentKind::Codex,
                available: version.is_some() && help.is_some(),
                version,
                supports_noninteractive: help.as_deref().is_some_and(|text| text.contains("codex exec")),
                supports_json_events: help.as_deref().is_some_and(|text| text.contains("--json")),
                supports_ephemeral_state: help.as_deref().is_some_and(|text| text.contains("--ephemeral")),
                sandbox_mode: "cloud-control-plane-not-admitted-by-zero-network-policy".into(),
                note: "The installed CLI supports an externally sandboxed mode, but a cloud Codex child cannot run while the strict child policy denies all network. No model run is relabeled as conformance evidence.".into(),
            },
        }
    }
}

impl AgentAdapter for CodexAdapter {
    fn capabilities(&self) -> AgentCapabilities {
        self.capabilities.clone()
    }

    fn run(
        &self,
        _request: &AgentRequest,
        _sandbox: &dyn AgentSandbox,
    ) -> Result<AgentRunRecord, AgentError> {
        if !self.capabilities.available {
            return Err(AgentError::Unavailable("codex CLI is not available".into()));
        }
        Err(AgentError::Unavailable(
            "cloud Codex is not admitted by Realm's strict zero-network child policy; use a parent-side control plane with sandboxed tools or a proven local model"
                .into(),
        ))
    }
}

pub struct ClaudeAdapter {
    capabilities: AgentCapabilities,
}

impl ClaudeAdapter {
    pub fn probe() -> Self {
        let version = command_text("claude", &["--version"]);
        let help = command_text("claude", &["--help"]);
        Self {
            capabilities: AgentCapabilities {
                kind: AgentKind::Claude,
                available: version.is_some() && help.is_some(),
                version,
                supports_noninteractive: help
                    .as_deref()
                    .is_some_and(|text| text.contains("-p") || text.contains("--print")),
                supports_json_events: help.as_deref().is_some_and(|text| text.contains("json")),
                supports_ephemeral_state: false,
                sandbox_mode: "external-sandbox-required".into(),
                note: "Claude availability is probed without starting a session.".into(),
            },
        }
    }
}

impl AgentAdapter for ClaudeAdapter {
    fn capabilities(&self) -> AgentCapabilities {
        self.capabilities.clone()
    }

    fn run(
        &self,
        _request: &AgentRequest,
        _sandbox: &dyn AgentSandbox,
    ) -> Result<AgentRunRecord, AgentError> {
        Err(AgentError::Unavailable("Claude execution adapter is present but no supported isolated CLI invocation was proven in this environment".into()))
    }
}

fn command_text(command: &str, args: &[&str]) -> Option<String> {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn command_output(
    output: std::process::Output,
    require_success: bool,
) -> Result<CommandOutput, AgentError> {
    let status = output.status.code().unwrap_or(-1);
    let result = CommandOutput {
        status,
        stdout: output.stdout,
        stderr: output.stderr,
    };
    if require_success && status != 0 {
        return Err(AgentError::CommandFailed(
            String::from_utf8_lossy(&result.stderr).into(),
        ));
    }
    Ok(result)
}

fn safe_relative(path: &PathBytes) -> Result<PathBuf, AgentError> {
    let path = path.as_path();
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(AgentError::InvalidPath(path.to_string_lossy().into_owned()));
    }
    Ok(path)
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn unique_suffix() -> String {
    format!("{}-{}", std::process::id(), now_ms())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct FakeSandbox;

    impl AgentSandbox for FakeSandbox {
        fn preflight(&self, roots: &SandboxRoots) -> Result<SandboxConformance, AgentError> {
            fs::create_dir_all(&roots.host)?;
            fs::write(&roots.escape_sentinel, b"realm-host-sentinel")?;
            Ok(SandboxConformance {
                status: SandboxStatus::Proven,
                candidate_write: true,
                outside_write_denied: true,
                history_read_denied: true,
                history_write_denied: true,
                oracle_read_denied: true,
                oracle_write_denied: true,
                escape_sentinel_unchanged: true,
                details: Vec::new(),
            })
        }
        fn run_program(
            &self,
            roots: &SandboxRoots,
            program: &Path,
            args: &[String],
            stdin: Option<&[u8]>,
        ) -> Result<CommandOutput, AgentError> {
            let relative = args.last().cloned().unwrap_or_default();
            if program.ends_with("tee") {
                let bytes = stdin.unwrap_or_default();
                fs::write(roots.candidate.join(relative), bytes)?;
            }
            Ok(CommandOutput {
                status: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
    }

    #[test]
    fn deterministic_adapter_has_stable_script_identity() {
        let root = std::env::temp_dir().join(format!("realm-agent-{}", unique_suffix()));
        fs::create_dir_all(&root).unwrap();
        let roots = SandboxRoots::strict_fixture(&root);
        let request = AgentRequest {
            prompt: "write".into(),
            workspace: roots.candidate.clone(),
            state_root: roots.agent_state.clone(),
            scratch_root: roots.scratch.clone(),
            history_root: roots.history.clone(),
            cas_root: roots.cas.clone(),
            ledger_root: roots.ledger.clone(),
            contracts_root: roots.contracts.clone(),
            oracle_root: roots.oracle.clone(),
            evaluator_root: roots.evaluator.clone(),
            host_root: roots.host.clone(),
            timeout_ms: 1000,
            model: None,
            deterministic_script: Some(DeterministicScript {
                script_id: "fixture-task-1".into(),
                operations: vec![DeterministicOperation::Write {
                    path: PathBytes(b"a.txt".to_vec()),
                    bytes: b"hello".to_vec(),
                }],
            }),
        };
        fs::create_dir_all(&request.workspace).unwrap();
        let result = DeterministicAgent.run(&request, &FakeSandbox).unwrap();
        assert_eq!(result.note, "fixture-task-1");
        assert!(!result.host_escape);
        assert_eq!(fs::read(request.workspace.join("a.txt")).unwrap(), b"hello");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn strict_roots_keep_all_writable_state_inside_candidate() {
        let root = std::env::temp_dir().join(format!("realm-agent-roots-{}", unique_suffix()));
        let roots = SandboxRoots::strict_fixture(&root);
        PlatformSandbox::prepare_roots(&roots).unwrap();
        assert!(roots.agent_state.starts_with(&roots.candidate));
        assert!(roots.scratch.starts_with(&roots.candidate));
        for (_, protected) in roots.protected_roots() {
            assert!(!protected.starts_with(&roots.candidate));
        }
        let profile = PlatformSandbox::profile(&roots).unwrap();
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains(&format!(
            "(allow file-read* file-write* (subpath \"{}\"))",
            escape(&fs::canonicalize(&roots.candidate).unwrap().to_string_lossy())
        )));
        for (_, protected) in roots.protected_roots() {
            assert!(!profile.contains(&format!(
                "file-write* (subpath \"{}\")",
                escape(&protected.to_string_lossy())
            )));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn strict_roots_reject_writable_state_outside_candidate() {
        let root = std::env::temp_dir().join(format!("realm-agent-bad-roots-{}", unique_suffix()));
        let mut roots = SandboxRoots::strict_fixture(&root);
        roots.agent_state = root.join("escaped-agent-state");
        for path in [
            &roots.candidate,
            &roots.agent_state,
            &roots.scratch,
            &roots.history,
            &roots.cas,
            &roots.ledger,
            &roots.contracts,
            &roots.oracle,
            &roots.evaluator,
            &roots.host,
        ] {
            fs::create_dir_all(path).unwrap();
        }
        assert!(PlatformSandbox::validate_roots(&roots).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
