//! Length-framed logical-file RPC. A stream may later be bound to AF_VSOCK;
//! stream framing and local tests do not authenticate a guest process.
use crate::frontier::{EffectFrontier, FrontierFailure};
use crate::mediation::{
    CapabilityLedger, CheckedMediationClaim, MeasuredBrokerCompletion, MediationSessionBinding,
    ProcessIncarnation,
};
#[cfg(any(target_os = "linux", test))]
use crate::task_envelope::TaskEnvelope;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{Read, Write};

const MAX_FRAME: usize = 2 * 1024 * 1024;
const MAX_RANGE: u64 = 1024 * 1024;
const BOOTSTRAP_MAGIC: &str = "REALM-C0-BOOTSTRAP-V2";
#[cfg(any(target_os = "linux", test))]
const TRANSFORM_SCRIPT: &str = "set -eu\ntest -f /workspace/input.txt\ncat /workspace/input.txt > /workspace/result.txt\nprintf 'processed\\n' >> /workspace/result.txt\n";
#[cfg(any(target_os = "linux", test))]
const OUTSIDE_WRITE_SCRIPT: &str = "set -eu\nprintf 'realm-bypass\\n' > /etc/realm-bypass\n";
#[cfg(any(target_os = "linux", test))]
const SAFE_TASK_ENVIRONMENT: [&str; 4] =
    ["PATH=/usr/bin:/bin", "LANG=C.UTF-8", "TZ=UTC", "HOME=/tmp"];

/// Provider-neutral normalized call crossing the runtime-to-broker boundary.
/// The first supported adapter is intentionally only `shell.exec`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeToolCall {
    pub run_id: String,
    pub agent_id: String,
    pub call_id: String,
    pub tool_id: String,
    pub schema_version: String,
    pub args: serde_json::Value,
    pub capability_ref: String,
    #[serde(default)]
    pub parent_event: Option<String>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedToolCall {
    pub run_id: String,
    pub call_id: String,
    pub tool_id: String,
    pub capability_ref: String,
    pub executable: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub safe_environment: Vec<String>,
    pub timeout_ms: u64,
    pub input_workspace_identity: String,
    pub effect_contract: Vec<String>,
    pub effect_contract_identity: String,
    pub outside_workspace_probe: bool,
    pub brokered_file_write: Option<BrokeredFileWrite>,
    pub runtime_family: Option<crate::runtime_effects::TaskFamily>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BrokeredFileWrite {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[cfg(any(target_os = "linux", test))]
fn safe_runtime_identity(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

#[cfg(any(target_os = "linux", test))]
fn read_string_arg(args: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    args.get(key)?.as_str().map(str::to_owned)
}

#[cfg(any(target_os = "linux", test))]
fn read_string_array_arg(
    args: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<Vec<String>> {
    args.get(key)?
        .as_array()?
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect()
}

/// Routing values delivered by the host broker over the already bound C0
/// transport. Echoing these values never authenticates the guest or VM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcBootstrap {
    pub run_id: String,
    pub process: ProcessIncarnation,
    pub capability: u64,
    pub challenge_root: String,
    pub input_version: String,
    pub output_version: String,
}

fn safe_bootstrap_run_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn lower_hex_64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn write_bytes_frame<W: Write>(stream: &mut W, body: &[u8]) -> Result<(), RpcFailure> {
    if body.is_empty() || body.len() > MAX_FRAME {
        return Err(RpcFailure::Frame);
    }
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .map_err(|_| RpcFailure::Io)?;
    stream.write_all(body).map_err(|_| RpcFailure::Io)?;
    stream.flush().map_err(|_| RpcFailure::Io)
}

/// Decode the host's initial C0 frame. This is a protocol parser, not a
/// host-observation or admission check.
pub fn read_bootstrap<R: Read>(stream: &mut R) -> Result<RpcBootstrap, RpcFailure> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).map_err(|_| RpcFailure::Io)?;
    let n = u32::from_be_bytes(length) as usize;
    if n == 0 || n > 512 {
        return Err(RpcFailure::Frame);
    }
    let mut body = vec![0; n];
    stream.read_exact(&mut body).map_err(|_| RpcFailure::Io)?;
    let text = std::str::from_utf8(&body).map_err(|_| RpcFailure::Frame)?;
    let lines: Vec<_> = text.split('\n').collect();
    if lines.len() != 10 || lines[0] != BOOTSTRAP_MAGIC || !lines[9].is_empty() {
        return Err(RpcFailure::Frame);
    }
    let [
        run_id,
        launch,
        serial,
        birth,
        capability,
        challenge_root,
        input_version,
        output_version,
    ] = [
        lines[1], lines[2], lines[3], lines[4], lines[5], lines[6], lines[7], lines[8],
    ];
    if !safe_bootstrap_run_id(run_id)
        || !lower_hex_64(launch)
        || (!challenge_root.is_empty() && !lower_hex_64(challenge_root))
        || !lower_hex_64(input_version)
        || !lower_hex_64(output_version)
    {
        return Err(RpcFailure::Frame);
    }
    let parse_number = |s: &str| -> Result<u64, RpcFailure> {
        let n = s.parse::<u64>().map_err(|_| RpcFailure::Frame)?;
        if n == 0 || n.to_string() != s {
            return Err(RpcFailure::Frame);
        }
        Ok(n)
    };
    Ok(RpcBootstrap {
        run_id: run_id.into(),
        process: ProcessIncarnation {
            launch: launch.into(),
            serial: parse_number(serial)?,
            birth: parse_number(birth)?,
        },
        capability: parse_number(capability)?,
        challenge_root: challenge_root.into(),
        input_version: input_version.into(),
        output_version: output_version.into(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcKind {
    Identify,
    /// Create the one contract-declared output in the private candidate world.
    /// Its path is fixed by the supervisor; guest JSON supplies no pathname.
    CreateOutput,
    ReadRange,
    WriteRange,
    /// Close one semantic file handle while keeping the process capability live.
    CloseHandle,
    /// Revoke the process's final broker capability at terminalization.
    Close,
    FileRead,
    FileCreate,
    SqliteIncrement,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedRpcStep {
    operation_id: String,
    kind: RpcKind,
    object_id: String,
    offset: u64,
    requested_length: u64,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcRequest {
    pub run_id: String,
    pub process: ProcessIncarnation,
    pub capability: u64,
    pub challenge_root: String,
    pub operation_id: String,
    pub kind: RpcKind,
    pub object_id: String,
    pub expected_version: String,
    pub offset: u64,
    pub requested_length: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcStatus {
    Ok,
    Refuse,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcResponse {
    pub run_id: String,
    pub operation_id: String,
    pub status: RpcStatus,
    pub completed: u64,
    pub resulting_version: String,
    pub evidence_sequence: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcFailure {
    Frame,
    Refused,
    Io,
}

pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(stream: &mut R) -> Result<T, RpcFailure> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).map_err(|_| RpcFailure::Io)?;
    let n = u32::from_be_bytes(length) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(RpcFailure::Frame);
    }
    let mut body = vec![0; n];
    stream.read_exact(&mut body).map_err(|_| RpcFailure::Io)?;
    serde_json::from_slice(&body).map_err(|_| RpcFailure::Frame)
}
pub fn write_frame<W: Write, T: Serialize>(stream: &mut W, value: &T) -> Result<(), RpcFailure> {
    let body = serde_json::to_vec(value).map_err(|_| RpcFailure::Frame)?;
    write_bytes_frame(stream, &body)
}

/// The host-side transport adapter must supply this from a measured launch,
/// never from request JSON. AF_VSOCK CID alone cannot identify a guest PID.
/// A caller cannot promote matching guest JSON into a server peer:
/// ```compile_fail
/// use realm_v6::broker_rpc::PeerBinding;
/// use realm_v6::mediation::ProcessIncarnation;
/// let process = ProcessIncarnation { launch: "x".into(), serial: 1, birth: 1 };
/// let _peer = PeerBinding { run_id: "x".into(), process, capability: 1 };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerBinding {
    run_id: String,
    process: ProcessIncarnation,
    capability: u64,
    challenge_root: String,
}

pub struct BrokerRpc {
    frontier: EffectFrontier,
    ledger: CapabilityLedger,
    authority: SessionAuthority,
    peer: PeerBinding,
    seen: BTreeSet<String>,
    bootstrap_sent: bool,
    expected_steps: Option<Vec<ExpectedRpcStep>>,
    expected_step_index: usize,
    coding_submission: Option<(crate::coding_submission::SubmissionContract, usize)>,
    runtime_effects: Option<crate::runtime_effects::RuntimeEffectBroker>,
    runtime_fault: Option<crate::runtime_effects::FailurePoint>,
}

/// Crate-private witness produced only after the supervisor has closed the
/// measured guest transport and rejected any queued reconnect. It binds the
/// freeze to the same run, execution, challenge, and endpoint used at broker
/// startup. It is not serialized and cannot recreate a broker session.
#[cfg(target_os = "linux")]
pub(crate) struct ClosedMeasuredEffectChannel {
    run_id: String,
    execution_id: String,
    challenge_root: String,
    endpoint_identity_root: String,
}

#[cfg(target_os = "linux")]
impl ClosedMeasuredEffectChannel {
    /// Consume the actual measured connection and listener. A caller-supplied
    /// closure flag or a pathname-only report cannot create this capability.
    #[cfg(target_os = "linux")]
    pub(crate) fn close_owned_transport(
        launch: &crate::measured_launch::MeasuredLaunchSession,
        challenge: &crate::mediation::MediationChallenge,
        listener: std::os::unix::net::UnixListener,
        mut stream: std::os::unix::net::UnixStream,
    ) -> Result<Self, RpcFailure> {
        let endpoint = launch.broker_endpoint();
        endpoint.revalidate().map_err(|_| RpcFailure::Refused)?;
        if listener
            .local_addr()
            .map_err(|_| RpcFailure::Refused)?
            .as_pathname()
            != Some(std::path::Path::new(endpoint.path()))
        {
            return Err(RpcFailure::Refused);
        }
        let peer =
            crate::supervisor::unix_peer_credentials(&stream).map_err(|_| RpcFailure::Refused)?;
        if peer.0 != launch.vmm().pid() || (peer.1, peer.2) != launch.vmm().owner() {
            return Err(RpcFailure::Refused);
        }
        let mut byte = [0u8; 1];
        if stream.read(&mut byte).map_err(|_| RpcFailure::Refused)? != 0 {
            return Err(RpcFailure::Refused);
        }
        listener
            .set_nonblocking(true)
            .map_err(|_| RpcFailure::Refused)?;
        if !matches!(listener.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock) {
            return Err(RpcFailure::Refused);
        }
        stream
            .shutdown(std::net::Shutdown::Both)
            .map_err(|_| RpcFailure::Refused)?;
        drop(stream);
        drop(listener);
        std::fs::remove_file(endpoint.path()).map_err(|_| RpcFailure::Refused)?;
        if !matches!(std::os::unix::net::UnixStream::connect(endpoint.path()),Err(e) if e.kind()==std::io::ErrorKind::NotFound)
        {
            return Err(RpcFailure::Refused);
        }
        Ok(Self {
            run_id: launch.run_id().to_owned(),
            execution_id: launch.execution_id().to_owned(),
            challenge_root: challenge.root().to_owned(),
            endpoint_identity_root: launch.broker_endpoint_blake3(),
        })
    }

    #[cfg(test)]
    fn test_for(binding: &MediationSessionBinding) -> Self {
        Self {
            run_id: binding.run_id().to_owned(),
            execution_id: binding.execution_id().to_owned(),
            challenge_root: binding.challenge_root().to_owned(),
            endpoint_identity_root: binding.endpoint_identity_root().to_owned(),
        }
    }

    fn matches(&self, binding: &MediationSessionBinding) -> bool {
        self.run_id == binding.run_id()
            && self.execution_id == binding.execution_id()
            && self.challenge_root == binding.challenge_root()
            && self.endpoint_identity_root == binding.endpoint_identity_root()
    }
}

enum SessionAuthority {
    Checked(Box<CheckedMediationClaim>),
    Measured(MediationSessionBinding),
    Diagnostic(DiagnosticBinding),
}

impl SessionAuthority {
    fn root(&self) -> &str {
        match self {
            Self::Checked(claim) => claim.session_binding_root(),
            Self::Measured(binding) => binding.root(),
            Self::Diagnostic(binding) => &binding.topology_root,
        }
    }

    fn run_id(&self) -> &str {
        match self {
            Self::Checked(claim) => &claim.manifest().run_id,
            Self::Measured(binding) => binding.run_id(),
            Self::Diagnostic(binding) => &binding.run_id,
        }
    }

    fn broker_identity(&self) -> &str {
        match self {
            Self::Checked(claim) => &claim.manifest().broker_identity,
            Self::Measured(binding) => binding.broker_identity(),
            Self::Diagnostic(binding) => &binding.broker_identity,
        }
    }

    fn launch_identity(&self) -> &str {
        match self {
            Self::Checked(claim) => &claim.manifest().launch_identity,
            Self::Measured(binding) => binding.execution_id(),
            Self::Diagnostic(binding) => &binding.launch_identity,
        }
    }

    fn starting_generation(&self) -> &str {
        match self {
            Self::Checked(claim) => &claim.manifest().starting_generation,
            Self::Measured(binding) => binding.starting_generation(),
            Self::Diagnostic(binding) => &binding.starting_generation,
        }
    }

    fn frontier_launch_identity(&self) -> &str {
        match self {
            Self::Checked(claim) => &claim.manifest().launch_identity,
            Self::Measured(binding) => binding.frontier_launch_identity(),
            Self::Diagnostic(binding) => &binding.semantic_launch_identity,
        }
    }

    fn challenge_root(&self) -> &str {
        match self {
            Self::Checked(_) => "",
            Self::Measured(binding) => binding.challenge_root(),
            Self::Diagnostic(binding) => &binding.challenge_root,
        }
    }

    fn expected_initial_process(&self) -> Option<ProcessIncarnation> {
        match self {
            Self::Checked(_) => None,
            Self::Measured(binding) => Some(binding.initial_process().clone()),
            Self::Diagnostic(binding) => Some(ProcessIncarnation {
                launch: binding.launch_identity.clone(),
                serial: 1,
                birth: binding.vmm_start_ticks,
            }),
        }
    }
}

/// Host supplied diagnostic labels. They remain untrusted and cannot issue a
/// CheckedMediationClaim, seal, freeze, or authorize admission.
pub struct DiagnosticBinding {
    pub run_id: String,
    pub broker_identity: String,
    /// Measured launch root used for process identity and peer routing.
    pub launch_identity: String,
    /// Hash of the canonical semantic_v2::Launch serialized in this run.
    /// It binds the diagnostic frontier to the existing semantic join.
    pub semantic_launch_identity: String,
    pub starting_generation: String,
    pub topology_root: String,
    pub vmm_start_ticks: u64,
    pub challenge_root: String,
}

/// Exercises the production RPC and durable frontier without creating an
/// authorizing mediation claim. The peer values are routing tokens only.
/// This type cannot seal a frontier or become `BrokerRpc` through a public API.
/// ```compile_fail
/// use realm_v6::broker_rpc::DiagnosticBrokerRpc;
/// fn forge(mut diagnostic: DiagnosticBrokerRpc) {
///     diagnostic.seal_after_terminal("epoch").unwrap();
/// }
/// ```
/// ```compile_fail
/// use realm_v6::broker_rpc::DiagnosticBrokerRpc;
/// fn forge(diagnostic: DiagnosticBrokerRpc) {
///     let _completion = diagnostic.finish_measured_session("epoch");
/// }
/// ```
pub struct DiagnosticBrokerRpc {
    inner: BrokerRpc,
}

impl DiagnosticBrokerRpc {
    #[cfg(target_os = "linux")]
    pub(crate) fn into_frontier(mut self) -> EffectFrontier {
        if let Some(runtime) = self.inner.runtime_effects.take() {
            // Completion is reconciled again at consumption; no closure is issued.
            if let Ok(completion) = runtime.completion() {
                self.inner.frontier.attach_runtime_completion(completion);
            }
        }
        self.inner.frontier
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn runtime_report(
        &self,
    ) -> Result<crate::runtime_effects::RecoveryReport, RpcFailure> {
        self.inner
            .runtime_effects
            .as_ref()
            .ok_or(RpcFailure::Refused)?
            .report()
            .map_err(|_| RpcFailure::Refused)
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn attach_runtime(
        &mut self,
        runtime: crate::runtime_effects::RuntimeEffectBroker,
        prefix: &str,
        fault: Option<crate::runtime_effects::FailurePoint>,
        _probe: bool,
    ) -> Result<usize, RpcFailure> {
        if self.inner.coding_submission.is_some() {
            return Err(RpcFailure::Refused);
        }
        let operations = runtime.session().family.operations();
        let steps = operations
            .iter()
            .map(|op| {
                use crate::runtime_effects::EffectOperation;
                let (suffix, kind, object_id, bytes) = match op {
                    EffectOperation::FileRead { bytes, .. } => {
                        ("read", RpcKind::FileRead, "input", bytes.clone())
                    }
                    EffectOperation::FileCreate { bytes, .. } => {
                        ("file", RpcKind::FileCreate, "output", bytes.clone())
                    }
                    EffectOperation::SqliteIncrement { .. } => {
                        ("sqlite", RpcKind::SqliteIncrement, "database", vec![])
                    }
                };
                ExpectedRpcStep {
                    operation_id: format!("{prefix}:{suffix}"),
                    kind,
                    object_id: object_id.into(),
                    offset: 0,
                    requested_length: bytes.len() as u64,
                    bytes,
                }
            })
            .collect::<Vec<_>>();
        let count = steps.len();
        self.inner.expected_steps = Some(steps);
        self.inner.runtime_effects = Some(runtime);
        self.inner.runtime_fault = fault;
        Ok(count)
    }

    pub fn new(frontier: EffectFrontier, binding: DiagnosticBinding) -> Result<Self, RpcFailure> {
        if !safe_bootstrap_run_id(&binding.run_id)
            || binding.broker_identity.is_empty()
            || !lower_hex_64(&binding.launch_identity)
            || !lower_hex_64(&binding.semantic_launch_identity)
            || !lower_hex_64(&binding.starting_generation)
            || !lower_hex_64(&binding.topology_root)
            || binding.vmm_start_ticks == 0
            || !lower_hex_64(&binding.challenge_root)
        {
            return Err(RpcFailure::Refused);
        }
        let process = ProcessIncarnation {
            launch: binding.launch_identity.clone(),
            serial: 1,
            birth: binding.vmm_start_ticks,
        };
        let process_launch = process.launch.clone();
        let (ledger, _) =
            CapabilityLedger::new(&process_launch, process).map_err(|_| RpcFailure::Refused)?;
        let inner =
            BrokerRpc::new_with_authority(frontier, ledger, SessionAuthority::Diagnostic(binding))?;
        Ok(Self { inner })
    }

    pub fn send_bootstrap<W: Write>(&mut self, stream: &mut W) -> Result<(), RpcFailure> {
        self.inner.send_bootstrap(stream)
    }

    pub fn serve_one<S: Read + Write>(&mut self, stream: &mut S) -> Result<(), RpcFailure> {
        self.inner.serve_one(stream)
    }

    /// Diagnostic development only: one structurally bound candidate bundle,
    /// followed by capability revocation. The guest cannot send intermediate
    /// edits, reads, creates, arbitrary paths, or a second bundle. This does not
    /// check coding semantics and cannot produce publication authority.
    pub fn restrict_to_coding_submission(
        &mut self,
        contract: crate::coding_submission::SubmissionContract,
    ) -> Result<(), RpcFailure> {
        contract.validate().map_err(|_| RpcFailure::Refused)?;
        if self.inner.bootstrap_sent
            || !self.inner.seen.is_empty()
            || self.inner.expected_steps.is_some()
            || self.inner.runtime_effects.is_some()
            || self.inner.coding_submission.is_some()
            || contract.run_id != self.inner.authority.run_id()
            || contract.execution_id != self.inner.authority.launch_identity()
            || contract.challenge_root != self.inner.authority.challenge_root()
            || self.inner.frontier.evidence_sequence() != 0
            || self.inner.output_content_digest() != blake3::hash(b"").to_hex().as_str()
        {
            return Err(RpcFailure::Refused);
        }
        self.inner.coding_submission = Some((contract, 0));
        Ok(())
    }

    /// Restrict a diagnostic guest session to the exact ordered requests for
    /// one file create/write action. This remains non-authorizing.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn restrict_to_file_write(
        &mut self,
        prefix: &str,
        path: &str,
        bytes: &[u8],
    ) -> Result<(), RpcFailure> {
        if self.inner.bootstrap_sent
            || self.inner.coding_submission.is_some()
            || !self.inner.seen.is_empty()
            || prefix.is_empty()
            || prefix.len() > 100
            || bytes.is_empty()
            || bytes.len() as u64 > MAX_RANGE
            || path != "output.txt"
        {
            return Err(RpcFailure::Refused);
        }
        self.inner.expected_steps = Some(vec![
            ExpectedRpcStep {
                operation_id: format!("{prefix}:identify"),
                kind: RpcKind::Identify,
                object_id: "output".into(),
                offset: 0,
                requested_length: 0,
                bytes: Vec::new(),
            },
            ExpectedRpcStep {
                operation_id: format!("{prefix}:write"),
                kind: RpcKind::WriteRange,
                object_id: "output".into(),
                offset: 0,
                requested_length: bytes.len() as u64,
                bytes: bytes.to_vec(),
            },
            ExpectedRpcStep {
                operation_id: format!("{prefix}:close"),
                kind: RpcKind::Close,
                object_id: "output".into(),
                offset: 0,
                requested_length: 0,
                bytes: Vec::new(),
            },
        ]);
        self.inner.expected_step_index = 0;
        Ok(())
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn expected_file_write_complete(&self) -> bool {
        self.inner
            .expected_steps
            .as_ref()
            .is_some_and(|steps| self.inner.expected_step_index == steps.len())
    }

    /// In-process transport used by the runtime bridge and its tests. It
    /// exercises the same authenticated request handler as `serve_one`.
    pub fn dispatch_local(
        &mut self,
        operation_id: &str,
        kind: RpcKind,
        object_id: &str,
        offset: u64,
        requested_length: u64,
        bytes: Vec<u8>,
    ) -> Result<RpcResponse, RpcFailure> {
        if !self.inner.bootstrap_sent {
            return Err(RpcFailure::Refused);
        }
        let peer = self.inner.peer.clone();
        let output = object_id == "output";
        let request = RpcRequest {
            run_id: peer.run_id.clone(),
            process: peer.process.clone(),
            capability: peer.capability,
            challenge_root: peer.challenge_root.clone(),
            operation_id: operation_id.to_owned(),
            kind,
            object_id: object_id.to_owned(),
            expected_version: self.inner.frontier.current_version(output).to_owned(),
            offset,
            requested_length,
            bytes,
        };
        Ok(self.inner.handle(&peer, request))
    }

    pub fn frontier_head(&self) -> &str {
        self.inner.frontier.head()
    }

    pub fn evidence_sequence(&self) -> u64 {
        self.inner.evidence_sequence()
    }

    pub fn journal_path(&self) -> &std::path::Path {
        self.inner.journal_path()
    }

    pub fn output_content_digest(&self) -> &str {
        self.inner.output_content_digest()
    }

    pub fn is_poisoned(&self) -> bool {
        self.inner.is_poisoned()
    }

    /// The caller must first observe the VMM's terminal barrier. This seals
    /// only the independent output custodian; the diagnostic broker remains
    /// unsealed and can never produce a checked claim or admission decision.
    pub fn seal_custodian_after_barrier(&mut self, barrier_id: &str) -> Result<String, RpcFailure> {
        let _profile = crate::profile::Span::new("frontier_custody_sealing");
        if self.is_poisoned() || self.inner.frontier.evidence_sequence() == 0 {
            return Err(RpcFailure::Refused);
        }
        self.inner
            .ledger
            .exit(&self.inner.peer.process)
            .map_err(|_| RpcFailure::Refused)?;
        self.inner
            .ledger
            .terminal()
            .map_err(|_| RpcFailure::Refused)?;
        self.inner
            .frontier
            .seal_custodian_after_barrier(barrier_id)
            .map_err(|_| RpcFailure::Refused)
    }

    /// Diagnostic-only durable journal closure after the caller's observed
    /// terminal barrier. This adds no checked claim, freeze token, or admission.
    pub fn seal_frontier_for_diagnostic_audit(
        &mut self,
        epoch: &str,
    ) -> Result<String, RpcFailure> {
        if self.is_poisoned() || epoch.is_empty() {
            return Err(RpcFailure::Refused);
        }
        self.inner
            .frontier
            .seal(epoch)
            .map_err(|_| RpcFailure::Refused)
    }
}

impl BrokerRpc {
    /// Validate the first supported runtime tool contracts at the canonical
    /// broker boundary. Commands and effect lists are derived from fixed profiles.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn validate_tool_call(
        call: &RuntimeToolCall,
        input_workspace_identity: &str,
    ) -> Result<ValidatedToolCall, RpcFailure> {
        if !safe_runtime_identity(&call.run_id, 64)
            || !safe_runtime_identity(&call.agent_id, 64)
            || !safe_runtime_identity(&call.call_id, 64)
            || !matches!(
                call.tool_id.as_str(),
                "shell.exec"
                    | "workspace.write"
                    | "runtime.file"
                    | "runtime.sqlite"
                    | "runtime.combined"
            )
            || call.schema_version != "1"
            || !safe_runtime_identity(&call.capability_ref, 128)
            || !safe_runtime_identity(input_workspace_identity, 64)
            || call.parent_event.as_ref().is_some_and(|event| {
                event.is_empty()
                    || event.len() > 256
                    || !event
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_:-.".contains(&byte))
            })
        {
            return Err(RpcFailure::Refused);
        }
        let args = call.args.as_object().ok_or(RpcFailure::Refused)?;
        if call.tool_id.starts_with("runtime.") {
            if !args.is_empty() {
                return Err(RpcFailure::Refused);
            }
            use crate::runtime_effects::TaskFamily;
            let family = match call.tool_id.as_str() {
                "runtime.file" => TaskFamily::File,
                "runtime.sqlite" => TaskFamily::Sqlite,
                "runtime.combined" => TaskFamily::Combined,
                _ => return Err(RpcFailure::Refused),
            };
            let effect_contract = family
                .operations()
                .iter()
                .map(|op| serde_json::to_string(op).unwrap())
                .collect::<Vec<_>>();
            let safe_environment = SAFE_TASK_ENVIRONMENT
                .iter()
                .map(|v| (*v).to_owned())
                .collect::<Vec<_>>();
            let contract_bytes = serde_json::to_vec(&(
                call,
                input_workspace_identity,
                &effect_contract,
                &safe_environment,
                30_000u64,
            ))
            .map_err(|_| RpcFailure::Frame)?;
            return Ok(ValidatedToolCall {
                run_id: call.run_id.clone(),
                call_id: call.call_id.clone(),
                tool_id: call.tool_id.clone(),
                capability_ref: call.capability_ref.clone(),
                executable: "realm-runtime-effects-v1".into(),
                argv: vec![
                    match family {
                        TaskFamily::File => "file",
                        TaskFamily::Sqlite => "sqlite",
                        TaskFamily::Combined => "combined",
                    }
                    .into(),
                ],
                cwd: "/workspace".into(),
                safe_environment,
                timeout_ms: 30_000,
                input_workspace_identity: input_workspace_identity.into(),
                effect_contract,
                effect_contract_identity: blake3::hash(&contract_bytes).to_hex().to_string(),
                outside_workspace_probe: false,
                brokered_file_write: None,
                runtime_family: Some(family),
            });
        }
        if call.tool_id == "workspace.write" {
            if args.len() != 2 || !args.contains_key("path") || !args.contains_key("content") {
                return Err(RpcFailure::Refused);
            }
            let path = read_string_arg(args, "path").ok_or(RpcFailure::Refused)?;
            let content = read_string_arg(args, "content").ok_or(RpcFailure::Refused)?;
            // First supported write is intentionally one exact, fresh create.
            // Do not turn this into a general filesystem mutation contract.
            if path != "output.txt" || content.as_bytes() != b"ABC" {
                return Err(RpcFailure::Refused);
            }
            let bytes = content.into_bytes();
            let effect_contract = vec!["create-write:output.txt".to_owned()];
            let safe_environment = SAFE_TASK_ENVIRONMENT
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>();
            let timeout_ms = 30_000;
            let contract_bytes = serde_json::to_vec(&serde_json::json!({
                "run_id": call.run_id,
                "agent_id": call.agent_id,
                "call_id": call.call_id,
                "tool_id": call.tool_id,
                "schema_version": call.schema_version,
                "capability_ref": call.capability_ref,
                "parent_event": call.parent_event,
                "args": call.args,
                "input_workspace_identity": input_workspace_identity,
                "safe_environment": safe_environment,
                "timeout_ms": timeout_ms,
                "effect_contract": effect_contract,
            }))
            .map_err(|_| RpcFailure::Frame)?;
            return Ok(ValidatedToolCall {
                run_id: call.run_id.clone(),
                call_id: call.call_id.clone(),
                tool_id: call.tool_id.clone(),
                capability_ref: call.capability_ref.clone(),
                executable: "realm-broker-write-v1".into(),
                argv: vec!["output.txt".into(), "414243".into()],
                cwd: "/workspace".into(),
                safe_environment,
                timeout_ms,
                input_workspace_identity: input_workspace_identity.to_owned(),
                effect_contract,
                effect_contract_identity: blake3::hash(&contract_bytes).to_hex().to_string(),
                outside_workspace_probe: false,
                brokered_file_write: Some(BrokeredFileWrite { path, bytes }),
                runtime_family: None,
            });
        }
        const EXPECTED_ARGS: [&str; 6] = [
            "executable",
            "argv",
            "cwd",
            "env_allowlist",
            "stdin",
            "timeout_seconds",
        ];
        if args.len() != EXPECTED_ARGS.len()
            || EXPECTED_ARGS.iter().any(|key| !args.contains_key(*key))
        {
            return Err(RpcFailure::Refused);
        }
        let executable = read_string_arg(args, "executable").ok_or(RpcFailure::Refused)?;
        let argv = read_string_array_arg(args, "argv").ok_or(RpcFailure::Refused)?;
        let cwd = read_string_arg(args, "cwd").ok_or(RpcFailure::Refused)?;
        let env_allowlist =
            read_string_array_arg(args, "env_allowlist").ok_or(RpcFailure::Refused)?;
        let stdin = read_string_arg(args, "stdin").ok_or(RpcFailure::Refused)?;
        let timeout_seconds = args
            .get("timeout_seconds")
            .and_then(serde_json::Value::as_f64)
            .filter(|value| value.is_finite() && (0.1..=300.0).contains(value))
            .ok_or(RpcFailure::Refused)?;
        if executable != "/bin/sh"
            || cwd != "/workspace"
            || !env_allowlist.is_empty()
            || !stdin.is_empty()
        {
            return Err(RpcFailure::Refused);
        }
        let is_transform = argv.len() == 2 && argv[0] == "-ec" && argv[1] == TRANSFORM_SCRIPT;
        let is_outside_probe =
            argv.len() == 2 && argv[0] == "-ec" && argv[1] == OUTSIDE_WRITE_SCRIPT;
        if !is_transform && !is_outside_probe {
            return Err(RpcFailure::Refused);
        }
        let effect_contract = if is_transform {
            vec!["read:input.txt".to_owned(), "write:result.txt".to_owned()]
        } else {
            vec!["probe:deny:/etc/realm-bypass".to_owned()]
        };
        let safe_environment = SAFE_TASK_ENVIRONMENT
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        let timeout_ms = (timeout_seconds * 1000.0).round() as u64;
        let contract_bytes = serde_json::to_vec(&serde_json::json!({
            "run_id": call.run_id,
            "agent_id": call.agent_id,
            "call_id": call.call_id,
            "tool_id": call.tool_id,
            "schema_version": call.schema_version,
            "capability_ref": call.capability_ref,
            "parent_event": call.parent_event,
            "args": call.args,
            "input_workspace_identity": input_workspace_identity,
            "safe_environment": safe_environment,
            "timeout_ms": timeout_ms,
            "effect_contract": effect_contract,
        }))
        .map_err(|_| RpcFailure::Frame)?;
        let effect_contract_identity = blake3::hash(&contract_bytes).to_hex().to_string();
        Ok(ValidatedToolCall {
            run_id: call.run_id.clone(),
            call_id: call.call_id.clone(),
            tool_id: call.tool_id.clone(),
            capability_ref: call.capability_ref.clone(),
            executable,
            argv,
            cwd,
            safe_environment,
            timeout_ms,
            input_workspace_identity: input_workspace_identity.to_owned(),
            effect_contract,
            effect_contract_identity,
            outside_workspace_probe: is_outside_probe,
            brokered_file_write: None,
            runtime_family: None,
        })
    }

    /// Construct the guest execution representation only after BrokerRpc has
    /// validated the call and derived its effect contract.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn build_task_envelope(
        call: &ValidatedToolCall,
        execution_id: &str,
        capsule_id: &str,
        challenge: &str,
        measured_workspace_identity: &str,
    ) -> Result<TaskEnvelope, RpcFailure> {
        if !lower_hex_64(execution_id)
            || !lower_hex_64(capsule_id)
            || !lower_hex_64(challenge)
            || !lower_hex_64(measured_workspace_identity)
            || call.effect_contract_identity.len() != 64
        {
            return Err(RpcFailure::Refused);
        }
        Ok(TaskEnvelope {
            protocol: 1,
            run_id: call.run_id.clone(),
            tool_call_id: call.call_id.clone(),
            tool_id: call.tool_id.clone(),
            capability_ref: call.capability_ref.clone(),
            effect_contract_identity: call.effect_contract_identity.clone(),
            input_workspace_identity: call.input_workspace_identity.clone(),
            execution_id: execution_id.into(),
            capsule_id: capsule_id.into(),
            challenge: challenge.into(),
            argv: std::iter::once(call.executable.clone())
                .chain(call.argv.clone())
                .collect(),
            cwd: call.cwd.clone(),
            safe_environment: call.safe_environment.clone(),
            timeout_ms: call.timeout_ms,
            workspace_identity: measured_workspace_identity.into(),
            effect_contract: call.effect_contract.clone(),
        })
    }

    pub fn new(
        frontier: EffectFrontier,
        ledger: CapabilityLedger,
        claim: CheckedMediationClaim,
    ) -> Result<Self, RpcFailure> {
        Self::new_with_authority(frontier, ledger, SessionAuthority::Checked(Box::new(claim)))
    }

    /// Start canonical broker service from a measured launch before the
    /// execution's final world and terminal observations exist. The broker
    /// derives its sole initial process and capability from the opaque
    /// measured-session binding. It records effects but cannot mint a checked
    /// mediation claim or publication capability by itself.
    pub fn new_for_measured_session(
        frontier: EffectFrontier,
        binding: MediationSessionBinding,
    ) -> Result<Self, RpcFailure> {
        if !lower_hex_64(binding.frontier_launch_identity()) || binding.initial_process().birth == 0
        {
            return Err(RpcFailure::Refused);
        }
        let (ledger, _) =
            CapabilityLedger::new(binding.execution_id(), binding.initial_process().clone())
                .map_err(|_| RpcFailure::Refused)?;
        Self::new_with_authority(frontier, ledger, SessionAuthority::Measured(binding))
    }

    fn new_with_authority(
        mut frontier: EffectFrontier,
        ledger: CapabilityLedger,
        authority: SessionAuthority,
    ) -> Result<Self, RpcFailure> {
        if frontier.run_id() != authority.run_id()
            || frontier.monitor_id() != authority.broker_identity()
            || ledger.launch_identity() != authority.launch_identity()
            || ledger.poisoned()
        {
            return Err(RpcFailure::Refused);
        }
        let process = ledger.initial_process().ok_or(RpcFailure::Refused)?.clone();
        if authority
            .expected_initial_process()
            .is_some_and(|expected| expected != process)
        {
            return Err(RpcFailure::Refused);
        }
        let capability = ledger.initial_capability().ok_or(RpcFailure::Refused)?;
        let peer = PeerBinding {
            run_id: authority.run_id().to_owned(),
            process,
            capability,
            challenge_root: authority.challenge_root().to_owned(),
        };
        frontier
            .bind_topology(
                authority.root(),
                authority.frontier_launch_identity(),
                authority.starting_generation(),
            )
            .map_err(|_| RpcFailure::Refused)?;
        Ok(Self {
            frontier,
            ledger,
            authority,
            peer,
            seen: BTreeSet::new(),
            bootstrap_sent: false,
            expected_steps: None,
            expected_step_index: 0,
            coding_submission: None,
            runtime_effects: None,
            runtime_fault: None,
        })
    }

    pub fn evidence_sequence(&self) -> u64 {
        self.frontier.evidence_sequence()
    }

    pub fn journal_path(&self) -> &std::path::Path {
        self.frontier.journal_path()
    }

    pub fn output_content_digest(&self) -> &str {
        self.frontier.current_content_digest(true)
    }

    pub fn is_poisoned(&self) -> bool {
        self.frontier.is_poisoned() || self.ledger.poisoned()
    }

    /// True after the measured guest has revoked every effect capability and
    /// all broker requests have left the in-flight set. This does not claim
    /// process termination; the supervisor must close the endpoint and later
    /// supply independent VMM/cgroup closure evidence.
    #[cfg(target_os = "linux")]
    pub(crate) fn task_effects_closed(&self) -> bool {
        self.ledger.effect_authority_closed().is_ok() && !self.frontier.is_poisoned()
    }

    /// Send the run identity, challenge, and initial object versions needed by
    /// the C0 guest. The broker derives these fields from its stored measured
    /// session; the transport adapter must still bind the live connection to
    /// the measured VMM before calling this method.
    pub fn send_bootstrap<W: Write>(&mut self, stream: &mut W) -> Result<(), RpcFailure> {
        let peer = &self.peer;
        let valid = !self.bootstrap_sent
            && self.seen.is_empty()
            && self.frontier.evidence_sequence() == 0
            && !self.frontier.is_poisoned()
            && peer.run_id == self.authority.run_id()
            && peer.process.launch == self.authority.launch_identity()
            && peer.challenge_root == self.authority.challenge_root()
            && safe_bootstrap_run_id(&peer.run_id)
            && lower_hex_64(&peer.process.launch)
            && lower_hex_64(self.frontier.current_version(false))
            && lower_hex_64(self.frontier.current_version(true))
            && self
                .ledger
                .authorize(&peer.process, peer.capability)
                .is_ok();
        if !valid {
            self.refuse();
            return Err(RpcFailure::Refused);
        }
        let body = format!(
            "{BOOTSTRAP_MAGIC}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            peer.run_id,
            peer.process.launch,
            peer.process.serial,
            peer.process.birth,
            peer.capability,
            peer.challenge_root,
            self.frontier.current_version(false),
            self.frontier.current_version(true),
        );
        write_bytes_frame(stream, body.as_bytes()).inspect_err(|_| self.refuse())?;
        self.bootstrap_sent = true;
        Ok(())
    }

    fn handle(&mut self, peer: &PeerBinding, r: RpcRequest) -> RpcResponse {
        let mut answer = RpcResponse {
            run_id: r.run_id.clone(),
            operation_id: r.operation_id.clone(),
            status: RpcStatus::Refuse,
            completed: 0,
            resulting_version: String::new(),
            evidence_sequence: self.frontier.evidence_sequence(),
            bytes: vec![],
        };
        let output = r.object_id == "output";
        let typed_runtime = matches!(
            r.kind,
            RpcKind::FileRead | RpcKind::FileCreate | RpcKind::SqliteIncrement
        );
        let expected_request_matches = match &self.expected_steps {
            None => true,
            Some(steps) => steps.get(self.expected_step_index).is_some_and(|expected| {
                r.operation_id == expected.operation_id
                    && r.kind == expected.kind
                    && r.object_id == expected.object_id
                    && r.offset == expected.offset
                    && r.requested_length == expected.requested_length
                    && r.bytes == expected.bytes
            }),
        };
        if !expected_request_matches && let Some(runtime) = self.runtime_effects.as_ref() {
            let bytes = serde_json::to_vec(&r).unwrap_or_default();
            if runtime
                .record_refusal(&r.operation_id, &bytes, "EFFECT_CONTRACT_BUDGET_OR_ORDER")
                .is_err()
            {
                self.refuse();
                return answer;
            }
        }
        let coding_request_matches = match &self.coding_submission {
            None => true,
            Some((contract, step)) => {
                output
                    && r.offset == 0
                    && match step {
                        0 => {
                            r.operation_id == "coding:submit"
                                && r.kind == RpcKind::WriteRange
                                && r.requested_length == r.bytes.len() as u64
                                && contract.decode(&r.bytes).is_ok()
                        }
                        1 => {
                            r.operation_id == "coding:close"
                                && r.kind == RpcKind::Close
                                && r.requested_length == 0
                                && r.bytes.is_empty()
                        }
                        _ => false,
                    }
            }
        };
        let valid = self.bootstrap_sent
            && r.run_id == self.authority.run_id()
            && peer.run_id == r.run_id
            && peer.process == r.process
            && peer.capability == r.capability
            && r.challenge_root == peer.challenge_root
            && r.challenge_root == self.authority.challenge_root()
            && (r.object_id == "input" || output || (typed_runtime && r.object_id == "database"))
            && r.operation_id.len() <= 128
            && !r.operation_id.is_empty()
            && r.expected_version.len() == 64
            && r.offset.checked_add(r.requested_length).is_some()
            && r.requested_length <= MAX_RANGE
            && (r.bytes.is_empty() || r.bytes.len() as u64 == r.requested_length)
            && expected_request_matches
            && coding_request_matches
            && self.seen.insert(r.operation_id.clone());
        if !valid
            || self
                .ledger
                .begin(&r.process, r.capability, &r.operation_id)
                .is_err()
            || if typed_runtime {
                self.runtime_effects
                    .as_ref()
                    .and_then(|b| b.frontier().ok())
                    .is_none_or(|f| f.session_identity != r.expected_version)
            } else {
                self.frontier.current_version(output) != r.expected_version
            }
        {
            self.refuse();
            return answer;
        }
        if typed_runtime {
            use crate::runtime_effects::{EffectOperation, EffectRequest};
            let operation = match r.kind {
                RpcKind::FileRead => EffectOperation::FileRead {
                    path: "input.txt".into(),
                    bytes: r.bytes.clone(),
                },
                RpcKind::FileCreate => EffectOperation::FileCreate {
                    path: "output.txt".into(),
                    bytes: r.bytes.clone(),
                },
                RpcKind::SqliteIncrement => EffectOperation::SqliteIncrement {
                    database: "counter.sqlite".into(),
                    before: 0,
                    after: 1,
                },
                _ => unreachable!(),
            };
            let request = EffectRequest {
                effect_id: r.operation_id.clone(),
                operation,
            };
            let result = match self.runtime_effects.as_mut() {
                Some(broker) => {
                    if let Some(point) = self.runtime_fault.take() {
                        broker.crash_worker(request, point).and_then(|_| {
                            Err(crate::runtime_effects::EffectError::Unknown(
                                "CRASH_NOT_REACHED",
                            ))
                        })
                    } else {
                        broker.execute(request, None)
                    }
                }
                None => Err(crate::runtime_effects::EffectError::Refuse(
                    "NO_RUNTIME_CAPABILITY",
                )),
            };
            if self.ledger.end(&r.operation_id).is_err() {
                self.refuse();
                return answer;
            }
            match result {
                Ok(record) => {
                    self.expected_step_index += 1;
                    answer.status = RpcStatus::Ok;
                    answer.completed = match r.kind {
                        RpcKind::SqliteIncrement => 1,
                        _ => r.requested_length,
                    };
                    answer.bytes = if r.kind == RpcKind::FileRead {
                        r.bytes.clone()
                    } else {
                        vec![]
                    };
                    answer.resulting_version = record.session_identity;
                    answer.evidence_sequence = record.sequence + 1;
                }
                Err(_) => self.refuse(),
            }
            return answer;
        }
        let result: Result<(u64, Vec<u8>), FrontierFailure> = match r.kind {
            RpcKind::CreateOutput
                if output && r.offset == 0 && r.requested_length == 0 && r.bytes.is_empty() =>
            {
                self.frontier
                    .create_output(&r.operation_id)
                    .map(|_| (0, vec![]))
            }
            RpcKind::Identify if r.offset == 0 && r.requested_length == 0 && r.bytes.is_empty() => {
                self.frontier
                    .record_identify(&r.operation_id, output)
                    .map(|_| (0, vec![]))
            }
            RpcKind::ReadRange if r.bytes.is_empty() => self
                .frontier
                .read(
                    &r.operation_id,
                    output,
                    r.offset,
                    r.requested_length as usize,
                )
                .map(|bytes| (bytes.len() as u64, bytes)),
            RpcKind::WriteRange if output && r.bytes.len() as u64 == r.requested_length => self
                .frontier
                .write(&r.operation_id, r.offset, &r.bytes)
                .map(|n| (n as u64, vec![])),
            RpcKind::CloseHandle
                if r.offset == 0 && r.requested_length == 0 && r.bytes.is_empty() =>
            {
                self.frontier
                    .record_close(&r.operation_id, output)
                    .map(|_| (0, vec![]))
            }
            RpcKind::Close if r.offset == 0 && r.requested_length == 0 && r.bytes.is_empty() => {
                self.frontier
                    .record_close(&r.operation_id, output)
                    .and_then(|_| {
                        self.ledger
                            .close(&r.process, r.capability)
                            .map_err(|_| FrontierFailure::EffectAmbiguous)
                            .map(|_| (0, vec![]))
                    })
            }
            _ => Err(FrontierFailure::InvalidInput),
        };
        if self.ledger.end(&r.operation_id).is_err() {
            self.refuse();
            return answer;
        }
        match result {
            Ok((n, bytes)) => {
                if self.expected_steps.is_some() {
                    self.expected_step_index += 1;
                }
                if let Some((_, step)) = self.coding_submission.as_mut() {
                    *step += 1;
                }
                answer.status = RpcStatus::Ok;
                answer.completed = n;
                answer.bytes = bytes;
                answer.resulting_version = self.frontier.current_version(output).into();
                answer.evidence_sequence = self.frontier.evidence_sequence();
            }
            Err(_) => self.refuse(),
        }
        answer
    }

    fn refuse(&mut self) {
        self.frontier.poison();
        self.ledger.refuse();
    }

    /// One request/response on an already authenticated transport. A lost
    /// response leaves the result durable; retrying the op ID poisons the run.
    pub fn serve_one<S: Read + Write>(&mut self, stream: &mut S) -> Result<(), RpcFailure> {
        let request = match read_frame(stream) {
            Ok(r) => r,
            Err(e) => {
                self.refuse();
                return Err(e);
            }
        };
        let response = self.handle(&self.peer.clone(), request);
        write_frame(stream, &response).inspect_err(|_| {
            self.refuse();
        })
    }

    pub fn seal_after_terminal(&mut self, freeze_epoch: &str) -> Result<String, RpcFailure> {
        if !self.bootstrap_sent || matches!(self.authority, SessionAuthority::Diagnostic(_)) {
            self.refuse();
            return Err(RpcFailure::Refused);
        }
        self.ledger.terminal().map_err(|_| RpcFailure::Refused)?;
        self.frontier
            .confirm_terminal_barrier()
            .map_err(|_| RpcFailure::Refused)?;
        self.frontier
            .seal(freeze_epoch)
            .map_err(|_| RpcFailure::Refused)
    }

    /// Seal the output custodian after the host has observed its terminal
    /// barrier. This records a broker/custodian boundary only; the caller must
    /// still supply independent kernel closure and same-run evidence before
    /// publication authority can be issued.
    pub fn seal_custodian_after_barrier(&mut self, barrier_id: &str) -> Result<String, RpcFailure> {
        if !matches!(self.authority, SessionAuthority::Measured(_))
            || self.frontier.evidence_sequence() == 0
            || barrier_id.is_empty()
        {
            self.refuse();
            return Err(RpcFailure::Refused);
        }
        self.ledger
            .exit(&self.peer.process)
            .map_err(|_| RpcFailure::Refused)?;
        self.ledger.terminal().map_err(|_| RpcFailure::Refused)?;
        self.frontier
            .seal_custodian_after_barrier(barrier_id)
            .map_err(|_| RpcFailure::Refused)
    }

    /// Consume a measured broker after terminal sealing and return the only
    /// token that can bind its frontier to a checked completion claim.
    pub fn finish_measured_session(
        mut self,
        freeze_epoch: &str,
    ) -> Result<MeasuredBrokerCompletion, RpcFailure> {
        if !matches!(&self.authority, SessionAuthority::Measured(_)) {
            self.refuse();
            return Err(RpcFailure::Refused);
        }
        let frontier_root = self.seal_after_terminal(freeze_epoch)?;
        let SessionAuthority::Measured(binding) = self.authority else {
            return Err(RpcFailure::Refused);
        };
        MeasuredBrokerCompletion::from_sealed_session(&binding, &frontier_root)
            .map_err(|_| RpcFailure::Refused)
    }

    /// Freeze a measured broker after the supervisor has closed the exact
    /// guest effect channel. The guest's `Close` RPC must already have revoked
    /// its capability. Process closure is checked separately by
    /// `RunClosureProof`; this transition establishes that no supported effect
    /// can be appended through this broker session.
    #[cfg(target_os = "linux")]
    pub(crate) fn freeze_measured_effects(
        mut self,
        closed_channel: ClosedMeasuredEffectChannel,
        freeze_epoch: &str,
    ) -> Result<FrozenMeasuredBroker, RpcFailure> {
        let _profile = crate::profile::Span::new("effect_freeze");
        if !self.bootstrap_sent {
            self.refuse();
            return Err(RpcFailure::Refused);
        }
        let SessionAuthority::Measured(binding) = &self.authority else {
            self.refuse();
            return Err(RpcFailure::Refused);
        };
        if !closed_channel.matches(binding) || !self.task_effects_closed() {
            self.refuse();
            return Err(RpcFailure::Refused);
        }
        self.frontier
            .confirm_terminal_barrier()
            .map_err(|_| RpcFailure::Refused)?;
        let frontier_root = self
            .frontier
            .seal(freeze_epoch)
            .map_err(|_| RpcFailure::Refused)?;
        if std::env::var_os("REALM_V6_QUALIFY_CONTAINMENT_CONTROLS").is_some() {
            // Exercise the exact custodied frontier from a positive execution.
            // A refused write must leave both durable journal and output version unchanged.
            let before =
                std::fs::read(self.frontier.journal_path()).map_err(|_| RpcFailure::Refused)?;
            let version = self.frontier.current_version(true).to_owned();
            if self.frontier.write("qualification-post-freeze", 0, b"BAD")
                != Err(crate::frontier::FrontierFailure::AlreadySealed)
                || std::fs::read(self.frontier.journal_path()).map_err(|_| RpcFailure::Refused)?
                    != before
                || self.frontier.current_version(true) != version
            {
                return Err(RpcFailure::Refused);
            }
        }
        let SessionAuthority::Measured(binding) = self.authority else {
            return Err(RpcFailure::Refused);
        };
        let completion = MeasuredBrokerCompletion::from_sealed_session(&binding, &frontier_root)
            .map_err(|_| RpcFailure::Refused)?;
        #[cfg(target_os = "linux")]
        let frozen_boottime_ns =
            crate::run_closure::linux::boottime_ns().map_err(|_| RpcFailure::Refused)?;
        #[cfg(not(target_os = "linux"))]
        let frozen_boottime_ns = 0;
        Ok(FrozenMeasuredBroker {
            completion,
            closed_channel,
            frozen_boottime_ns,
        })
    }
}

/// A live broker freeze retains both the completion and the owned-channel
/// closure. Neither can be reconstructed from a report.
#[cfg(target_os = "linux")]
pub(crate) struct FrozenMeasuredBroker {
    completion: MeasuredBrokerCompletion,
    closed_channel: ClosedMeasuredEffectChannel,
    pub(crate) frozen_boottime_ns: u64,
}
#[cfg(target_os = "linux")]
impl std::ops::Deref for FrozenMeasuredBroker {
    type Target = MeasuredBrokerCompletion;
    fn deref(&self) -> &Self::Target {
        &self.completion
    }
}
#[cfg(target_os = "linux")]
impl FrozenMeasuredBroker {
    pub(crate) fn channel_root(&self) -> String {
        let c = &self.closed_channel;
        blake3::hash(
            &serde_json::to_vec(&(
                "realm.closed-effect-channel/v1",
                &c.run_id,
                &c.execution_id,
                &c.challenge_root,
                &c.endpoint_identity_root,
                self.completion.root(),
            ))
            .expect("channel identity serializes"),
        )
        .to_hex()
        .to_string()
    }
    pub(crate) fn endpoint_root(&self) -> &str {
        &self.closed_channel.endpoint_identity_root
    }
}

pub struct GuestClient<S: Read + Write> {
    stream: S,
    peer: PeerBinding,
    next_op: u64,
}
impl<S: Read + Write> GuestClient<S> {
    pub fn new(stream: S, peer: PeerBinding) -> Self {
        Self {
            stream,
            peer,
            next_op: 1,
        }
    }
    pub fn request(
        &mut self,
        kind: RpcKind,
        object: &str,
        version: &str,
        offset: u64,
        len: u64,
        bytes: Vec<u8>,
    ) -> Result<RpcResponse, RpcFailure> {
        let operation_id = format!("{}:{}", self.peer.process.serial, self.next_op);
        self.next_op += 1;
        let req = RpcRequest {
            run_id: self.peer.run_id.clone(),
            process: self.peer.process.clone(),
            capability: self.peer.capability,
            challenge_root: self.peer.challenge_root.clone(),
            operation_id: operation_id.clone(),
            kind,
            object_id: object.into(),
            expected_version: version.into(),
            offset,
            requested_length: len,
            bytes,
        };
        write_frame(&mut self.stream, &req)?;
        let reply: RpcResponse = read_frame(&mut self.stream)?;
        if reply.run_id != req.run_id
            || reply.operation_id != operation_id
            || reply.status != RpcStatus::Ok
            || reply.completed > len
            || reply.resulting_version.len() != 64
        {
            return Err(RpcFailure::Refused);
        }
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediation::{AttachedDevice, MediationManifest, test_only_checked_claim};
    use crate::{
        capsule::{BackendKind, CapsuleFacts, CapsuleObservation, CheckResult},
        execution_backend::{
            BackendError, BackendExecutionResult, BackendLaunchContext, BackendTask,
            ExecutionBackend, ExecutionBackendCapabilities,
        },
        measured_launch::PolicyIdentity,
    };
    use std::fs;
    use std::os::unix::net::UnixStream;

    struct MockTaskBackend {
        expected_run_id: String,
        expected_execution_id: String,
        expected_envelope_identity: String,
    }

    impl ExecutionBackend for MockTaskBackend {
        fn capabilities(&self) -> ExecutionBackendCapabilities {
            ExecutionBackendCapabilities {
                backend_id: "mock-plumbing-only".into(),
                host_requirement: "unit test".into(),
                runtime_profile: "MOCKED_PROTOCOL_PLUMBING".into(),
                guest_network: false,
                workspace_format: "test files".into(),
                observes_final_workspace_delta: false,
                closes_all_guest_effects: false,
            }
        }

        fn execute(
            &self,
            task: BackendTask<'_>,
            before_guest_start: &mut dyn FnMut(&BackendLaunchContext) -> Result<(), BackendError>,
        ) -> Result<BackendExecutionResult, BackendError> {
            let envelope = task.envelope;
            if envelope.run_id != self.expected_run_id
                || envelope.execution_id != self.expected_execution_id
                || envelope
                    .identity()
                    .map_err(|error| BackendError::new("mock_identity", error.to_string()))?
                    != self.expected_envelope_identity
            {
                return Err(BackendError::new(
                    "mock_identity",
                    "backend received a different TaskEnvelope",
                ));
            }
            let launch = BackendLaunchContext {
                run_id: envelope.run_id.clone(),
                execution_id: envelope.execution_id.clone(),
                task_envelope_identity: envelope.identity().unwrap(),
                measured_launch_identity: None,
                assurance_grade: None,
                launch_evidence_path: None,
                topology_root: "c".repeat(64),
                vmm_process_identity: None,
                vmm_pid: 123,
                process_start_ticks: 42,
            };
            before_guest_start(&launch)?;
            let facts = CapsuleFacts {
                run_id: envelope.run_id.clone(),
                execution_id: envelope.execution_id.clone(),
                backend: BackendKind::DiagnosticOnly,
                workspace_identity: envelope.workspace_identity.clone(),
                capsule_id: "d".repeat(64),
                custody_process_identity: Some("d".repeat(64)),
                vmm_terminal_observation_root: None,
                descendants: vec![],
                starting_world: envelope.workspace_identity.clone(),
                final_world: Some("e".repeat(64)),
                observed_effects: vec!["result.txt".into()],
                exit_code: Some(0),
                crashed: false,
                quiescence: CheckResult::Unavailable,
                monitor_loss: CheckResult::Unavailable,
                network: CheckResult::Unavailable,
                filesystem: CheckResult::Unavailable,
                frozen: CheckResult::Unavailable,
                evidence_root: None,
                sequence_start: 0,
                sequence_end: None,
                unsupported_effects: vec!["mock backend; no guest was started".into()],
                runtime_identity: "mock".into(),
                network_policy_identity: "mock".into(),
                completion_evidence: "mock-only".into(),
                finalization_evidence: "mock-only".into(),
                pause_snapshot_evidence: "mock-only".into(),
                delta_root: "e".repeat(64),
            };
            let capabilities = self.capabilities();
            Ok(BackendExecutionResult {
                backend_id: capabilities.backend_id.clone(),
                capabilities,
                launch,
                launch_evidence: None,
                detached_workspace: std::path::PathBuf::new(),
                observation: CapsuleObservation::test_host_observation(facts),
            })
        }
    }

    #[test]
    fn mocked_backend_links_call_envelope_and_frontier_without_guest_execution() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "realm-rpc-mock-plumbing-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        let input_path = dir.join("input");
        let output_path = dir.join("output");
        let input = b"known input\n";
        fs::write(&input_path, input).unwrap();
        fs::write(&output_path, b"").unwrap();

        let tool_call = RuntimeToolCall {
            run_id: "run-mock".into(),
            agent_id: "scripted".into(),
            call_id: "call-mock".into(),
            tool_id: "shell.exec".into(),
            schema_version: "1".into(),
            args: serde_json::json!({
                "executable": "/bin/sh",
                "argv": ["-ec", TRANSFORM_SCRIPT],
                "cwd": "/workspace",
                "env_allowlist": [],
                "stdin": "",
                "timeout_seconds": 30.0,
            }),
            capability_ref: "cap:shell.exec".into(),
            parent_event: None,
        };
        let validated = BrokerRpc::validate_tool_call(&tool_call, &"a".repeat(32)).unwrap();
        let execution_id = "1".repeat(64);
        let envelope = BrokerRpc::build_task_envelope(
            &validated,
            &execution_id,
            &"2".repeat(64),
            &"3".repeat(64),
            &"b".repeat(64),
        )
        .unwrap();
        let envelope_identity = envelope.identity().unwrap();
        let operation_prefix = format!(
            "{}:{}:{}",
            tool_call.run_id, tool_call.call_id, envelope_identity
        );
        let frontier = EffectFrontier::create(
            &dir,
            &tool_call.run_id,
            "mock-plumbing-broker",
            &input_path,
            &output_path,
        )
        .unwrap();
        let backend = MockTaskBackend {
            expected_run_id: tool_call.run_id.clone(),
            expected_execution_id: execution_id,
            expected_envelope_identity: envelope_identity.clone(),
        };
        let mut diagnostic = None;
        let mut broker_input = None;
        let mut frontier = Some(frontier);
        let mut before_guest_start = |launch: &BackendLaunchContext| {
            if launch.execution_id != envelope.execution_id {
                return Err(BackendError::new(
                    "mock_launch",
                    "execution identity changed",
                ));
            }
            let binding = DiagnosticBinding {
                run_id: tool_call.run_id.clone(),
                broker_identity: "mock-plumbing-broker".into(),
                launch_identity: launch.execution_id.clone(),
                starting_generation: "b".repeat(64),
                topology_root: launch.topology_root.clone(),
                vmm_start_ticks: launch.process_start_ticks,
                semantic_launch_identity: "6".repeat(64),
                challenge_root: "5".repeat(64),
            };
            let frontier = frontier
                .take()
                .ok_or_else(|| BackendError::new("mock_broker", "frontier was already consumed"))?;
            let mut broker = DiagnosticBrokerRpc::new(frontier, binding)
                .map_err(|error| BackendError::new("mock_broker", format!("{error:?}")))?;
            let mut bootstrap = Vec::new();
            broker
                .send_bootstrap(&mut bootstrap)
                .map_err(|error| BackendError::new("mock_bootstrap", format!("{error:?}")))?;
            let response = broker
                .dispatch_local(
                    &format!("{operation_prefix}:input"),
                    RpcKind::ReadRange,
                    "input",
                    0,
                    input.len() as u64,
                    Vec::new(),
                )
                .map_err(|error| BackendError::new("mock_read", format!("{error:?}")))?;
            if response.status != RpcStatus::Ok || response.bytes.as_slice() != input {
                return Err(BackendError::new("mock_read", "broker input differed"));
            }
            broker_input = Some(response.bytes);
            diagnostic = Some(broker);
            Ok(())
        };
        let execution = backend
            .execute(
                BackendTask {
                    envelope: &envelope,
                    policy: PolicyIdentity::new("mock-policy".into(), "1".into(), b"p", b"t"),
                },
                &mut before_guest_start,
            )
            .unwrap();
        assert_eq!(execution.observation.facts().run_id(), &tool_call.run_id);
        assert_eq!(
            execution.observation.facts().execution_id(),
            &envelope.execution_id
        );
        assert_eq!(
            execution.observation.facts().backend(),
            &BackendKind::DiagnosticOnly
        );
        assert_eq!(broker_input.as_deref(), Some(input.as_slice()));

        // Deterministic test output only: this mock does not execute the guest command.
        let mock_output = [input.as_slice(), b"processed\n"].concat();
        let mut diagnostic = diagnostic.expect("mock launch hook should initialize BrokerRpc");
        let response = diagnostic
            .dispatch_local(
                &format!("{operation_prefix}:result"),
                RpcKind::WriteRange,
                "output",
                0,
                mock_output.len() as u64,
                mock_output.clone(),
            )
            .unwrap();
        assert_eq!(response.status, RpcStatus::Ok);
        assert_eq!(
            diagnostic.output_content_digest(),
            blake3::hash(&mock_output).to_hex().as_str()
        );

        let result = serde_json::json!({
            "run_id": tool_call.run_id,
            "call_id": tool_call.call_id,
            "tool_id": tool_call.tool_id,
            "capability_ref": tool_call.capability_ref,
            "effect_contract_identity": envelope.effect_contract_identity,
            "task_envelope_identity": envelope_identity,
            "execution_id": envelope.execution_id,
            "process_identity": execution.observation.facts().custody_process_identity(),
            "frontier_head": diagnostic.frontier_head(),
            "frontier_evidence_sequence": diagnostic.evidence_sequence(),
            "output_blake3": blake3::hash(&mock_output).to_hex().as_str(),
        });
        assert_eq!(result["run_id"], tool_call.run_id);
        assert_eq!(result["call_id"], tool_call.call_id);
        assert_eq!(result["task_envelope_identity"], envelope_identity);
        assert_eq!(
            result["effect_contract_identity"],
            envelope.effect_contract_identity
        );
        assert_eq!(result["execution_id"], envelope.execution_id);
        assert_eq!(result["frontier_evidence_sequence"], 4);
        assert_eq!(
            result["output_blake3"],
            blake3::hash(&mock_output).to_hex().as_str()
        );
        assert!(result["frontier_head"].as_str().is_some());
        assert!(result["process_identity"].as_str().is_some());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn diagnostic_session_cannot_seal_even_after_bootstrap() {
        let dir = std::env::temp_dir().join(format!("realm-rpc-diagnostic-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("input"), b"abc").unwrap();
        fs::write(dir.join("output"), b"---").unwrap();
        let frontier = EffectFrontier::create(
            &dir,
            "diagnostic-run",
            "c0-diagnostic-broker",
            &dir.join("input"),
            &dir.join("output"),
        )
        .unwrap();
        let binding = DiagnosticBinding {
            run_id: "diagnostic-run".into(),
            broker_identity: "c0-diagnostic-broker".into(),
            launch_identity: "1".repeat(64),
            semantic_launch_identity: "4".repeat(64),
            starting_generation: "2".repeat(64),
            topology_root: "3".repeat(64),
            vmm_start_ticks: 42,
            challenge_root: "5".repeat(64),
        };
        let mut diagnostic = DiagnosticBrokerRpc::new(frontier, binding).unwrap();
        let mut bootstrap = Vec::new();
        diagnostic.send_bootstrap(&mut bootstrap).unwrap();
        assert_eq!(
            read_bootstrap(&mut bootstrap.as_slice())
                .unwrap()
                .process
                .birth,
            42
        );
        assert_eq!(
            diagnostic.inner.seal_after_terminal("epoch"),
            Err(RpcFailure::Refused)
        );
        assert!(diagnostic.is_poisoned());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn measured_broker_session_starts_before_terminal_claim_exists() {
        let launch_fixture = crate::measured_launch::tests::Fixture::new();
        let launch = launch_fixture.capture_c0_diagnostic_profile().unwrap();
        let parent = "2".repeat(64);
        let binding = MediationSessionBinding::from_measured_launch(
            &launch,
            &"4".repeat(64),
            &parent,
            &crate::mediation::MediationChallenge::test_only(&"3".repeat(64)),
        )
        .unwrap();
        let root =
            std::env::temp_dir().join(format!("realm-rpc-measured-session-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("input"), b"abc").unwrap();
        fs::write(root.join("output"), b"").unwrap();
        let frontier = EffectFrontier::create(
            &root,
            binding.run_id(),
            binding.broker_identity(),
            &root.join("input"),
            &root.join("output"),
        )
        .unwrap();
        let expected_root = binding.root().to_owned();
        let closed_channel = ClosedMeasuredEffectChannel::test_for(&binding);
        let mut broker = BrokerRpc::new_for_measured_session(frontier, binding).unwrap();
        assert_eq!(broker.authority.root(), expected_root);
        assert_eq!(broker.authority.run_id(), launch.run_id());
        assert_eq!(broker.frontier.evidence_sequence(), 0);
        let peer = broker.peer.clone();
        let mut bootstrap = Vec::new();
        broker.send_bootstrap(&mut bootstrap).unwrap();
        let decoded_bootstrap = read_bootstrap(&mut bootstrap.as_slice()).unwrap();
        assert_eq!(decoded_bootstrap.challenge_root, peer.challenge_root);
        assert!(!broker.task_effects_closed());
        let request = |operation_id: &str, kind, expected_version: String| RpcRequest {
            run_id: peer.run_id.clone(),
            process: peer.process.clone(),
            capability: peer.capability,
            challenge_root: peer.challenge_root.clone(),
            operation_id: operation_id.into(),
            kind,
            object_id: "input".into(),
            expected_version,
            offset: 0,
            requested_length: 0,
            bytes: Vec::new(),
        };
        let identify = broker.handle(
            &peer,
            request(
                "measured-identify",
                RpcKind::Identify,
                broker.frontier.current_version(false).into(),
            ),
        );
        assert_eq!(identify.status, RpcStatus::Ok);
        let close = broker.handle(
            &peer,
            request(
                "measured-close",
                RpcKind::Close,
                broker.frontier.current_version(false).into(),
            ),
        );
        assert_eq!(close.status, RpcStatus::Ok);
        assert!(broker.task_effects_closed());
        let completion = broker
            .freeze_measured_effects(closed_channel, "measured-effects-frozen")
            .unwrap();
        assert_eq!(completion.session_binding_root(), expected_root);
        assert_eq!(completion.run_id(), launch.run_id());
        assert_eq!(completion.execution_id(), launch.execution_id());
        assert_eq!(completion.frontier_root().len(), 64);
        assert_eq!(completion.root().len(), 64);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn measured_rpc_refuses_a_foreign_challenge_before_recording_an_effect() {
        let launch_fixture = crate::measured_launch::tests::Fixture::new();
        let launch = launch_fixture.capture_c0_diagnostic_profile().unwrap();
        let challenge = crate::mediation::MediationChallenge::test_only(&"3".repeat(64));
        let binding = MediationSessionBinding::from_measured_launch(
            &launch,
            &"4".repeat(64),
            &"2".repeat(64),
            &challenge,
        )
        .unwrap();
        let root = std::env::temp_dir().join(format!(
            "realm-rpc-challenge-binding-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("input"), b"abc").unwrap();
        fs::write(root.join("output"), b"").unwrap();
        let frontier = EffectFrontier::create(
            &root,
            binding.run_id(),
            binding.broker_identity(),
            &root.join("input"),
            &root.join("output"),
        )
        .unwrap();
        let mut broker = BrokerRpc::new_for_measured_session(frontier, binding).unwrap();
        let mut wire = Vec::new();
        broker.send_bootstrap(&mut wire).unwrap();
        assert_eq!(
            read_bootstrap(&mut wire.as_slice()).unwrap().challenge_root,
            challenge.root()
        );
        let peer = broker.peer.clone();
        let response = broker.handle(
            &peer,
            RpcRequest {
                run_id: peer.run_id.clone(),
                process: peer.process.clone(),
                capability: peer.capability,
                challenge_root: "f".repeat(64),
                operation_id: "foreign-challenge-identify".into(),
                kind: RpcKind::Identify,
                object_id: "input".into(),
                expected_version: broker.frontier.current_version(false).into(),
                offset: 0,
                requested_length: 0,
                bytes: Vec::new(),
            },
        );
        assert_eq!(response.status, RpcStatus::Refuse);
        assert_eq!(broker.frontier.evidence_sequence(), 0);
        assert!(broker.frontier.is_poisoned());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn measured_session_binding_refuses_replaced_vsock_endpoint() {
        use std::{
            os::unix::{fs::PermissionsExt, net::UnixListener},
            path::PathBuf,
        };

        let launch_fixture = crate::measured_launch::tests::Fixture::new();
        let launch = launch_fixture.capture_c0_diagnostic_profile().unwrap();
        let endpoint = PathBuf::from(launch.broker_endpoint().path());
        fs::remove_file(&endpoint).unwrap();
        let _replacement = UnixListener::bind(&endpoint).unwrap();
        fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            MediationSessionBinding::from_measured_launch(
                &launch,
                &"4".repeat(64),
                &"2".repeat(64),
                &crate::mediation::MediationChallenge::test_only(&"3".repeat(64)),
            ),
            Err(crate::mediation::MediationFailure::MeasuredSessionMismatch)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn measured_broker_session_refuses_direct_workspace_profile() {
        let launch_fixture = crate::measured_launch::tests::Fixture::new();
        let launch = launch_fixture.capture().unwrap();
        assert_eq!(
            MediationSessionBinding::from_measured_launch(
                &launch,
                &"4".repeat(64),
                &"2".repeat(64),
                &crate::mediation::MediationChallenge::test_only(&"3".repeat(64)),
            ),
            Err(crate::mediation::MediationFailure::MeasuredSessionMismatch)
        );
    }

    #[test]
    fn diagnostic_handle_close_preserves_capability_until_terminal_close() {
        let dir =
            std::env::temp_dir().join(format!("realm-rpc-close-handle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("input"), b"abc").unwrap();
        fs::write(dir.join("output"), b"").unwrap();
        let frontier = EffectFrontier::create(
            &dir,
            "diagnostic-run",
            "c0-diagnostic-broker",
            &dir.join("input"),
            &dir.join("output"),
        )
        .unwrap();
        let binding = DiagnosticBinding {
            run_id: "diagnostic-run".into(),
            broker_identity: "c0-diagnostic-broker".into(),
            launch_identity: "1".repeat(64),
            semantic_launch_identity: "4".repeat(64),
            starting_generation: "2".repeat(64),
            topology_root: "3".repeat(64),
            vmm_start_ticks: 42,
            challenge_root: "5".repeat(64),
        };
        let mut diagnostic = DiagnosticBrokerRpc::new(frontier, binding).unwrap();
        let mut bootstrap = Vec::new();
        diagnostic.send_bootstrap(&mut bootstrap).unwrap();
        let peer = diagnostic.inner.peer.clone();
        let make_request =
            |operation_id: &str, kind, object_id: &str, version: String| RpcRequest {
                run_id: peer.run_id.clone(),
                process: peer.process.clone(),
                capability: peer.capability,
                challenge_root: peer.challenge_root.clone(),
                operation_id: operation_id.into(),
                kind,
                object_id: object_id.into(),
                expected_version: version,
                offset: 0,
                requested_length: 0,
                bytes: Vec::new(),
            };
        let input_version = diagnostic.inner.frontier.current_version(false).to_owned();
        let close = diagnostic.inner.handle(
            &peer,
            make_request("close-input", RpcKind::CloseHandle, "input", input_version),
        );
        assert_eq!(close.status, RpcStatus::Ok);
        let output_version = diagnostic.inner.frontier.current_version(true).to_owned();
        let identify = diagnostic.inner.handle(
            &peer,
            make_request(
                "identify-output",
                RpcKind::Identify,
                "output",
                output_version,
            ),
        );
        assert_eq!(identify.status, RpcStatus::Ok);
        assert!(!diagnostic.is_poisoned());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bootstrap_rejects_ambiguous_or_corrupt_identity_fields() {
        let valid = format!(
            "REALM-C0-BOOTSTRAP-V2\nrun_1\n{}\n1\n2\n1\n{}\n{}\n{}\n",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        );
        let frame = |body: &str| {
            let mut wire = (body.len() as u32).to_be_bytes().to_vec();
            wire.extend_from_slice(body.as_bytes());
            wire
        };
        assert!(read_bootstrap(&mut frame(&valid).as_slice()).is_ok());
        for bad in [
            valid.replace("run_1", "run/1"),
            valid.replace("\n1\n2\n", "\n01\n2\n"),
            valid.replace(&"a".repeat(64), &"A".repeat(64)),
            format!("{valid}extra\n"),
        ] {
            assert_eq!(
                read_bootstrap(&mut frame(&bad).as_slice()),
                Err(RpcFailure::Frame)
            );
        }
        let mut short = frame(&valid);
        short.pop();
        assert_eq!(read_bootstrap(&mut short.as_slice()), Err(RpcFailure::Io));
    }

    #[test]
    fn workspace_write_contract_is_exact_and_narrow() {
        let call = RuntimeToolCall {
            run_id: "run-write".into(),
            agent_id: "scripted".into(),
            call_id: "call-write".into(),
            tool_id: "workspace.write".into(),
            schema_version: "1".into(),
            args: serde_json::json!({"path": "output.txt", "content": "ABC"}),
            capability_ref: "cap:workspace.write".into(),
            parent_event: None,
        };
        let validated = BrokerRpc::validate_tool_call(&call, &"a".repeat(64)).unwrap();
        assert_eq!(validated.executable, "realm-broker-write-v1");
        assert_eq!(validated.argv, ["output.txt", "414243"]);
        assert_eq!(validated.effect_contract, ["create-write:output.txt"]);
        assert_eq!(validated.brokered_file_write.unwrap().bytes, b"ABC");

        for args in [
            serde_json::json!({"path": "other.txt", "content": "ABC"}),
            serde_json::json!({"path": "output.txt", "content": "changed"}),
            serde_json::json!({"path": "output.txt", "content": "ABC", "mode": 0o777}),
        ] {
            let mut substituted = call.clone();
            substituted.args = args;
            assert!(BrokerRpc::validate_tool_call(&substituted, &"a".repeat(64)).is_err());
        }
    }

    fn coding_fixture() -> (crate::coding_submission::SubmissionContract, Vec<u8>) {
        use crate::coding_submission::{CandidateFile, PATHS, Submission, SubmissionContract};
        let contract = SubmissionContract {
            run_id: "1".repeat(64),
            execution_id: "2".repeat(64),
            challenge_root: "3".repeat(64),
            task_sha256: "4".repeat(64),
            worker_sha256: "5".repeat(64),
        };
        let body = Submission {
            schema: "realm.coding-submission.v1".into(),
            binding: contract.clone(),
            transcript_head: "6".repeat(64),
            // Deliberately not a correct coding task. Structural admission must
            // not be confused with independently verified coding semantics.
            files: PATHS.map(|path| CandidateFile {
                path: path.into(),
                text: "# untrusted protocol fixture\n".into(),
                mode: 0o600,
            }),
        };
        (contract, serde_json::to_vec(&body).unwrap())
    }

    fn coding_broker(
        custodied: bool,
    ) -> (
        std::path::PathBuf,
        DiagnosticBrokerRpc,
        Option<std::thread::JoinHandle<()>>,
    ) {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;
        let (contract, _) = coding_fixture();
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let stem = std::env::temp_dir().join(format!(
            "rcs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let dir = loop {
            let n = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let candidate = stem.with_extension(n.to_string());
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("fresh coding test directory: {e}"),
            }
        };
        fs::write(dir.join("input"), b"").unwrap();
        let output = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join("output"))
            .unwrap();
        let (frontier, thread) = if custodied {
            let journal = OpenOptions::new()
                .read(true)
                .append(true)
                .create_new(true)
                .mode(0o600)
                .open(dir.join("custody.jsonl"))
                .unwrap();
            let mut service =
                crate::custody::CustodyServer::new(output, journal, contract.run_id.clone())
                    .unwrap();
            let (stream, mut server_stream) = UnixStream::pair().unwrap();
            let thread = std::thread::spawn(move || {
                assert!(service.serve_one(&mut server_stream).unwrap()); // write
                assert!(service.serve_one(&mut server_stream).unwrap()); // seal
            });
            let frontier = EffectFrontier::create_custodied(
                &dir,
                &contract.run_id,
                "coding-diagnostic",
                &dir.join("input"),
                fs::File::open(dir.join("output")).unwrap(),
                crate::custody::CustodyClient::new(stream, contract.run_id.clone()),
            )
            .unwrap();
            (frontier, Some(thread))
        } else {
            drop(output);
            (
                EffectFrontier::create(
                    &dir,
                    &contract.run_id,
                    "coding-diagnostic",
                    &dir.join("input"),
                    &dir.join("output"),
                )
                .unwrap(),
                None,
            )
        };
        let binding = DiagnosticBinding {
            run_id: contract.run_id.clone(),
            broker_identity: "coding-diagnostic".into(),
            launch_identity: contract.execution_id.clone(),
            semantic_launch_identity: "7".repeat(64),
            starting_generation: "8".repeat(64),
            topology_root: "9".repeat(64),
            vmm_start_ticks: 7,
            challenge_root: contract.challenge_root.clone(),
        };
        let mut broker = DiagnosticBrokerRpc::new(frontier, binding).unwrap();
        broker.restrict_to_coding_submission(contract).unwrap();
        (dir, broker, thread)
    }

    #[test]
    fn coding_submission_refuses_identity_shape_and_projection_substitution() {
        let (contract, bytes) = coding_fixture();
        assert!(contract.decode(&bytes).is_ok());
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut changes = vec![];
        for field in [
            "run_id",
            "execution_id",
            "challenge_root",
            "task_sha256",
            "worker_sha256",
        ] {
            let mut changed = value.clone();
            changed["binding"][field] = "a".repeat(64).into();
            changes.push(serde_json::to_vec(&changed).unwrap());
        }
        for (key, new) in [
            ("path", serde_json::json!("../escape")),
            ("mode", serde_json::json!(true)),
            ("text", serde_json::json!("é".repeat(16385))),
        ] {
            let mut changed = value.clone();
            changed["files"][1][key] = new;
            changes.push(serde_json::to_vec(&changed).unwrap());
        }
        let mut changed = value.clone();
        changed["files"].as_array_mut().unwrap().reverse();
        changes.push(serde_json::to_vec(&changed).unwrap());
        let mut changed = value.clone();
        changed["authority"] = "ACCEPT".into();
        changes.push(serde_json::to_vec(&changed).unwrap());
        let mut changed = value;
        changed["files"].as_array_mut().unwrap().pop();
        changes.push(serde_json::to_vec(&changed).unwrap());
        changes.push(bytes.iter().copied().chain(*b" x").collect());
        changes.push(vec![b' '; crate::coding_submission::MAX_SUBMISSION + 1]);
        let duplicate = String::from_utf8(bytes).unwrap().replace(
            "\"transcript_head\":",
            "\"transcript_head\":\"bad\",\"transcript_head\":",
        );
        changes.push(duplicate.into_bytes());
        for changed in changes {
            assert!(contract.decode(&changed).is_err());
        }
    }

    #[test]
    fn coding_submission_unauthorized_intermediate_requests_leave_output_and_frontier_unchanged() {
        use std::os::unix::fs::MetadataExt;
        let (_, bytes) = coding_fixture();
        for case in 0..8 {
            let (dir, mut diagnostic, _) = coding_broker(false);
            assert!(
                diagnostic
                    .restrict_to_file_write("mixed", "output.txt", b"ABC")
                    .is_err()
            );
            diagnostic.send_bootstrap(&mut Vec::new()).unwrap();
            assert!(
                diagnostic
                    .restrict_to_coding_submission(coding_fixture().0)
                    .is_err()
            );
            let journal_before = fs::read(diagnostic.journal_path()).unwrap();
            let inode = fs::metadata(dir.join("output")).unwrap().ino();
            let peer = diagnostic.inner.peer.clone();
            let mut request = RpcRequest {
                run_id: peer.run_id.clone(),
                process: peer.process.clone(),
                capability: peer.capability,
                challenge_root: peer.challenge_root.clone(),
                operation_id: "coding:submit".into(),
                kind: RpcKind::WriteRange,
                object_id: "output".into(),
                expected_version: diagnostic.inner.frontier.current_version(true).into(),
                offset: 0,
                requested_length: bytes.len() as u64,
                bytes: bytes.clone(),
            };
            match case {
                0 => request.bytes = b"unauthorized intermediate edit".to_vec(),
                1 => request.offset = 1,
                2 => request.object_id = "input".into(),
                3 => request.kind = RpcKind::CreateOutput,
                4 => request.kind = RpcKind::ReadRange,
                5 => request.run_id = "a".repeat(64),
                6 => request.challenge_root = "a".repeat(64),
                _ => {
                    request.kind = RpcKind::Close;
                    request.operation_id = "coding:close".into();
                    request.bytes.clear();
                    request.requested_length = 0;
                }
            }
            let reply = diagnostic.inner.handle(&peer, request);
            assert_eq!(reply.status, RpcStatus::Refuse);
            assert!(diagnostic.is_poisoned());
            assert_eq!(fs::read(diagnostic.journal_path()).unwrap(), journal_before);
            assert_eq!(fs::read(dir.join("output")).unwrap(), b"");
            assert_eq!(fs::metadata(dir.join("output")).unwrap().ino(), inode);
            drop(diagnostic);
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn coding_submission_custody_records_exactly_one_bundle_and_rejects_second_write() {
        use std::os::unix::fs::MetadataExt;
        let (contract, bytes) = coding_fixture();
        let (dir, mut diagnostic, thread) = coding_broker(true);
        let (mut guest, mut host) = UnixStream::pair().unwrap();
        guest
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        host.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let broker_thread = std::thread::spawn(move || {
            diagnostic.send_bootstrap(&mut host).unwrap();
            diagnostic.serve_one(&mut host).unwrap();
            diagnostic.serve_one(&mut host).unwrap();
            diagnostic
        });
        crate::coding_submission::send(&mut guest, &contract, &bytes).unwrap();
        let mut diagnostic = broker_thread.join().unwrap();
        assert_eq!(fs::read(dir.join("output")).unwrap(), bytes);
        diagnostic
            .seal_custodian_after_barrier("diagnostic-only-barrier")
            .unwrap();
        diagnostic
            .seal_frontier_for_diagnostic_audit("diagnostic-only-barrier")
            .unwrap();
        thread.unwrap().join().unwrap();
        let frontier = crate::frontier::audit_bytes(
            &fs::read(diagnostic.journal_path()).unwrap(),
            &contract.run_id,
            "coding-diagnostic",
        )
        .unwrap();
        let m = fs::metadata(dir.join("output")).unwrap();
        let custody = crate::custody::audit_custody_against_frontier(
            &fs::read(dir.join("custody.jsonl")).unwrap(),
            &frontier,
            &crate::frontier::ObjectIdentity {
                device: m.dev(),
                inode: m.ino(),
            },
        )
        .unwrap();
        assert_eq!(custody.committed_write_count, 1);
        assert_eq!(
            custody.final_output_digest,
            blake3::hash(&bytes).to_hex().as_str()
        );
        let before = fs::read(diagnostic.journal_path()).unwrap();
        let second = diagnostic
            .dispatch_local(
                "coding:submit",
                RpcKind::WriteRange,
                "output",
                0,
                bytes.len() as u64,
                bytes.clone(),
            )
            .unwrap();
        assert_eq!(second.status, RpcStatus::Refuse);
        assert_eq!(fs::read(diagnostic.journal_path()).unwrap(), before);
        assert_eq!(fs::read(dir.join("output")).unwrap(), bytes);
        drop(diagnostic);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn coding_submission_python_adapter_uses_actual_native_custody_and_unknown_delivery() {
        use std::os::unix::{fs::MetadataExt, net::UnixListener};
        let scripts = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/v7");
        for mode in ["ok", "lost", "foreign"] {
            let (contract, bytes) = coding_fixture();
            let (dir, mut diagnostic, custody_thread) = coding_broker(mode == "ok");
            let mut expected = contract.clone();
            let packet_bytes = if mode == "foreign" {
                expected.execution_id = "a".repeat(64);
                let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                value["binding"] = serde_json::to_value(&expected).unwrap();
                serde_json::to_vec(&value).unwrap()
            } else {
                bytes.clone()
            };
            fs::write(dir.join("packet.json"), &packet_bytes).unwrap();
            fs::write(
                dir.join("binding.json"),
                serde_json::to_vec(&expected).unwrap(),
            )
            .unwrap();
            let listener = UnixListener::bind(dir.join("wire.sock")).unwrap();
            let script = r#"
import json,pathlib,socket,sys
sys.path.insert(0,sys.argv[1])
import coding_native_client as client
root=pathlib.Path(sys.argv[2]); mode=sys.argv[3]
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:
    stream.settimeout(5); stream.connect(str(root/'wire.sock'))
    try:
        receipt=client.send_packet(stream,json.loads((root/'binding.json').read_text()),(root/'packet.json').read_bytes())
    except client.NotDispatched:
        assert mode=='foreign'; print('NOT_DISPATCHED')
    except client.DeliveryUnknown:
        assert mode=='lost'; print('UNKNOWN')
    else:
        assert mode=='ok' and receipt['authority']=='NONE' and receipt['realm_artifact'] is None
        print('ACKNOWLEDGED_NONE')
"#;
            let child = std::process::Command::new("python3")
                .args(["-I", "-B", "-c", script])
                .arg(&scripts)
                .arg(&dir)
                .arg(mode)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let (mut wire, _) = listener.accept().unwrap();
            wire.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            diagnostic.send_bootstrap(&mut wire).unwrap();
            let bootstrap_journal = fs::read(diagnostic.journal_path()).unwrap();
            match mode {
                "ok" => {
                    diagnostic.serve_one(&mut wire).unwrap();
                    diagnostic.serve_one(&mut wire).unwrap();
                }
                "lost" => {
                    let request = read_frame(&mut wire).unwrap();
                    let reply = diagnostic
                        .inner
                        .handle(&diagnostic.inner.peer.clone(), request);
                    assert_eq!(reply.status, RpcStatus::Ok);
                }
                _ => {}
            }
            if mode == "foreign" {
                let mut byte = [0];
                assert_eq!(wire.read(&mut byte).unwrap(), 0);
            }
            drop(wire);
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                String::from_utf8(output.stdout).unwrap().trim(),
                match mode {
                    "ok" => "ACKNOWLEDGED_NONE",
                    "lost" => "UNKNOWN",
                    _ => "NOT_DISPATCHED",
                }
            );
            if mode == "ok" {
                assert_eq!(fs::read(dir.join("output")).unwrap(), bytes);
                diagnostic
                    .seal_custodian_after_barrier("diagnostic-only-barrier")
                    .unwrap();
                diagnostic
                    .seal_frontier_for_diagnostic_audit("diagnostic-only-barrier")
                    .unwrap();
                custody_thread.unwrap().join().unwrap();
                let frontier = crate::frontier::audit_bytes(
                    &fs::read(diagnostic.journal_path()).unwrap(),
                    &contract.run_id,
                    "coding-diagnostic",
                )
                .unwrap();
                let m = fs::metadata(dir.join("output")).unwrap();
                let custody = crate::custody::audit_custody_against_frontier(
                    &fs::read(dir.join("custody.jsonl")).unwrap(),
                    &frontier,
                    &crate::frontier::ObjectIdentity {
                        device: m.dev(),
                        inode: m.ino(),
                    },
                )
                .unwrap();
                assert_eq!(custody.committed_write_count, 1);
                assert_eq!(
                    custody.final_output_digest,
                    blake3::hash(&bytes).to_hex().as_str()
                );
                let before = fs::read(diagnostic.journal_path()).unwrap();
                assert_eq!(
                    diagnostic
                        .dispatch_local(
                            "coding:submit",
                            RpcKind::WriteRange,
                            "output",
                            0,
                            bytes.len() as u64,
                            bytes.clone()
                        )
                        .unwrap()
                        .status,
                    RpcStatus::Refuse
                );
                assert_eq!(fs::read(diagnostic.journal_path()).unwrap(), before);
                assert_eq!(fs::read(dir.join("output")).unwrap(), bytes);
            } else if mode == "lost" {
                // No Close arrived. Preserve committed bytes and unsealed history;
                // never synthesize completion to make this control pass.
                assert_eq!(fs::read(dir.join("output")).unwrap(), bytes);
                let before = fs::read(diagnostic.journal_path()).unwrap();
                assert!(
                    crate::frontier::audit_bytes(&before, &contract.run_id, "coding-diagnostic")
                        .is_err()
                );
                assert_eq!(
                    diagnostic
                        .dispatch_local(
                            "coding:submit",
                            RpcKind::WriteRange,
                            "output",
                            0,
                            bytes.len() as u64,
                            bytes.clone()
                        )
                        .unwrap()
                        .status,
                    RpcStatus::Refuse
                );
                assert_eq!(fs::read(diagnostic.journal_path()).unwrap(), before);
                assert_eq!(fs::read(dir.join("output")).unwrap(), bytes);
            } else {
                assert_eq!(fs::read(dir.join("output")).unwrap(), b"");
                assert_eq!(
                    fs::read(diagnostic.journal_path()).unwrap(),
                    bootstrap_journal
                );
            }
            drop(diagnostic);
            drop(listener);
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn coding_submission_foreign_bootstrap_refuses_before_any_dispatch() {
        struct WireProbe {
            input: std::io::Cursor<Vec<u8>>,
            writes: Vec<u8>,
        }
        impl Read for WireProbe {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                self.input.read(bytes)
            }
        }
        impl Write for WireProbe {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.writes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for field in ["run_id", "execution_id", "challenge_root"] {
            let (dir, mut diagnostic, _) = coding_broker(false);
            let mut bootstrap = vec![];
            diagnostic.send_bootstrap(&mut bootstrap).unwrap();
            let (contract, bytes) = coding_fixture();
            let mut body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            body["binding"][field] = "a".repeat(64).into();
            let foreign: crate::coding_submission::SubmissionContract =
                serde_json::from_value(body["binding"].clone()).unwrap();
            assert_ne!(contract, foreign);
            let journal = fs::read(diagnostic.journal_path()).unwrap();
            let mut stream = WireProbe {
                input: std::io::Cursor::new(bootstrap),
                writes: vec![],
            };
            assert_eq!(
                crate::coding_submission::send(
                    &mut stream,
                    &foreign,
                    &serde_json::to_vec(&body).unwrap()
                ),
                Err(crate::coding_submission::DeliveryFailure::NotDispatched)
            );
            assert!(stream.writes.is_empty());
            assert_eq!(fs::read(diagnostic.journal_path()).unwrap(), journal);
            assert_eq!(fs::read(dir.join("output")).unwrap(), b"");
            drop(diagnostic);
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn coding_submission_lost_write_reply_is_unknown_with_actual_committed_bytes() {
        let (contract, bytes) = coding_fixture();
        let (dir, mut diagnostic, _) = coding_broker(false);
        let (mut guest, mut host) = UnixStream::pair().unwrap();
        guest
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        host.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let server = std::thread::spawn(move || {
            diagnostic.send_bootstrap(&mut host).unwrap();
            let request = read_frame(&mut host).unwrap();
            let reply = diagnostic
                .inner
                .handle(&diagnostic.inner.peer.clone(), request);
            assert_eq!(reply.status, RpcStatus::Ok);
            // Actual write committed; deliberately drop its reply/transport.
            drop(host);
            diagnostic
        });
        assert_eq!(
            crate::coding_submission::send(&mut guest, &contract, &bytes),
            Err(crate::coding_submission::DeliveryFailure::Unknown)
        );
        let mut diagnostic = server.join().unwrap();
        assert_eq!(fs::read(dir.join("output")).unwrap(), bytes);
        let journal = fs::read(diagnostic.journal_path()).unwrap();
        let retry = diagnostic
            .dispatch_local(
                "coding:submit",
                RpcKind::WriteRange,
                "output",
                0,
                bytes.len() as u64,
                bytes.clone(),
            )
            .unwrap();
        assert_eq!(retry.status, RpcStatus::Refuse);
        assert_eq!(fs::read(diagnostic.journal_path()).unwrap(), journal);
        assert_eq!(fs::read(dir.join("output")).unwrap(), bytes);
        drop(diagnostic);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn brokered_file_write_requires_identify_write_close_in_order() {
        let dir = std::env::temp_dir().join(format!(
            "realm-rpc-file-write-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("input"), b"").unwrap();
        fs::write(dir.join("output"), b"").unwrap();
        let frontier = EffectFrontier::create(
            &dir,
            "run-write",
            "broker-write-test",
            &dir.join("input"),
            &dir.join("output"),
        )
        .unwrap();
        let binding = DiagnosticBinding {
            run_id: "run-write".into(),
            broker_identity: "broker-write-test".into(),
            launch_identity: "1".repeat(64),
            starting_generation: "2".repeat(64),
            topology_root: "3".repeat(64),
            vmm_start_ticks: 7,
            semantic_launch_identity: "6".repeat(64),
            challenge_root: "5".repeat(64),
        };
        let mut diagnostic = DiagnosticBrokerRpc::new(frontier, binding).unwrap();
        let prefix = format!("fw:{}", "4".repeat(64));
        diagnostic
            .restrict_to_file_write(&prefix, "output.txt", b"ABC")
            .unwrap();
        diagnostic.send_bootstrap(&mut Vec::new()).unwrap();
        let identify = diagnostic
            .dispatch_local(
                &format!("{prefix}:identify"),
                RpcKind::Identify,
                "output",
                0,
                0,
                vec![],
            )
            .unwrap();
        assert_eq!(identify.status, RpcStatus::Ok);
        let write = diagnostic
            .dispatch_local(
                &format!("{prefix}:write"),
                RpcKind::WriteRange,
                "output",
                0,
                3,
                b"ABC".to_vec(),
            )
            .unwrap();
        assert_eq!(write.status, RpcStatus::Ok);
        let close = diagnostic
            .dispatch_local(
                &format!("{prefix}:close"),
                RpcKind::Close,
                "output",
                0,
                0,
                vec![],
            )
            .unwrap();
        assert_eq!(close.status, RpcStatus::Ok);
        assert!(diagnostic.expected_file_write_complete());
        assert_eq!(diagnostic.evidence_sequence(), 4);
        assert_eq!(
            diagnostic.output_content_digest(),
            blake3::hash(b"ABC").to_hex().as_str()
        );
        drop(diagnostic);
        assert_eq!(fs::read(dir.join("output")).unwrap(), b"ABC");
        fs::remove_dir_all(dir).unwrap();

        let dir = std::env::temp_dir().join(format!(
            "realm-rpc-file-write-order-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("input"), b"").unwrap();
        fs::write(dir.join("output"), b"").unwrap();
        let frontier = EffectFrontier::create(
            &dir,
            "run-write-order",
            "broker-write-test",
            &dir.join("input"),
            &dir.join("output"),
        )
        .unwrap();
        let binding = DiagnosticBinding {
            run_id: "run-write-order".into(),
            broker_identity: "broker-write-test".into(),
            launch_identity: "1".repeat(64),
            starting_generation: "2".repeat(64),
            topology_root: "3".repeat(64),
            vmm_start_ticks: 7,
            semantic_launch_identity: "6".repeat(64),
            challenge_root: "5".repeat(64),
        };
        let mut diagnostic = DiagnosticBrokerRpc::new(frontier, binding).unwrap();
        let prefix = format!("fw:{}", "5".repeat(64));
        diagnostic
            .restrict_to_file_write(&prefix, "output.txt", b"ABC")
            .unwrap();
        diagnostic.send_bootstrap(&mut Vec::new()).unwrap();
        let write_first = diagnostic
            .dispatch_local(
                &format!("{prefix}:write"),
                RpcKind::WriteRange,
                "output",
                0,
                3,
                b"ABC".to_vec(),
            )
            .unwrap();
        assert_eq!(write_first.status, RpcStatus::Refuse);
        assert!(!diagnostic.expected_file_write_complete());
        assert!(diagnostic.is_poisoned());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rpc_read_write_retry_and_terminal() {
        let dir = std::env::temp_dir().join(format!("realm-rpc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("input"), b"abc").unwrap();
        fs::write(dir.join("output"), b"---").unwrap();
        let launch = "1".repeat(64);
        let m = MediationManifest {
            schema: 2,
            run_id: "rpc-run".into(),
            vm_config_blake3: "a".repeat(64),
            guest_kernel_blake3: "b".repeat(64),
            rootfs_blake3: "c".repeat(64),
            task_blake3: "d".repeat(64),
            guest_policy_blake3: "e".repeat(64),
            seccomp_blake3: "f".repeat(64),
            measured_launch_hash_domain: crate::measured_launch::MEASURED_LAUNCH_HASH_DOMAIN.into(),
            measured_launch_hash_version: crate::measured_launch::MEASURED_LAUNCH_HASH_VERSION,
            measured_launch_blake3: "9".repeat(64),
            broker_endpoint_identity: "8".repeat(64),
            host_policy_identifier: "fixture-policy".into(),
            host_policy_version: "1".into(),
            host_policy_blake3: "7".repeat(64),
            launch_identity: launch.clone(),
            starting_generation: "2".repeat(64),
            final_world: "3".repeat(64),
            delta_root: "4".repeat(64),
            runtime_identity: "5".repeat(64),
            network_policy_identity: "6".repeat(64),
            broker_identity: "broker".into(),
            broker_endpoint: "vsock:host:7000".into(),
            devices: vec![
                AttachedDevice {
                    kind: "rootfs".into(),
                    identity: "c".repeat(64),
                    read_only: true,
                },
                AttachedDevice {
                    kind: "broker_vsock".into(),
                    identity: "vsock:host:7000".into(),
                    read_only: true,
                },
            ],
            network_devices: vec![],
            shared_mounts: vec![],
            inherited_fds: vec![],
            writable_mappings: vec![],
            other_storage_aliases: vec![],
            max_task_processes: 1,
        };
        let b = serde_json::to_vec(&m).unwrap();
        let claim = test_only_checked_claim(&b, blake3::hash(&b).to_hex().as_ref()).unwrap();
        let frontier = EffectFrontier::create(
            &dir,
            "rpc-run",
            "broker",
            &dir.join("input"),
            &dir.join("output"),
        )
        .unwrap();
        let p = ProcessIncarnation {
            launch: launch.clone(),
            serial: 1,
            birth: 1,
        };
        let (ledger, cap) = CapabilityLedger::new(&launch, p.clone()).unwrap();
        let mut server = BrokerRpc::new(frontier, ledger, claim).unwrap();
        let peer = PeerBinding {
            run_id: "rpc-run".into(),
            process: p.clone(),
            capability: cap,
            challenge_root: String::new(),
        };
        let mut bootstrap_wire = Vec::new();
        server.send_bootstrap(&mut bootstrap_wire).unwrap();
        let bootstrap = read_bootstrap(&mut bootstrap_wire.as_slice()).unwrap();
        assert_eq!(bootstrap.run_id, "rpc-run");
        assert_eq!(bootstrap.process, p);
        assert_eq!(bootstrap.capability, cap);
        assert_eq!(
            bootstrap.input_version,
            server.frontier.current_version(false)
        );
        assert_eq!(
            bootstrap.output_version,
            server.frontier.current_version(true)
        );
        let mut r = RpcRequest {
            run_id: "rpc-run".into(),
            process: bootstrap.process,
            capability: cap,
            challenge_root: bootstrap.challenge_root,
            operation_id: "r1".into(),
            kind: RpcKind::ReadRange,
            object_id: "input".into(),
            expected_version: server.frontier.current_version(false).into(),
            offset: 0,
            requested_length: 3,
            bytes: vec![],
        };
        let reply = server.handle(&peer, r.clone());
        assert_eq!(reply.status, RpcStatus::Ok);
        assert_eq!(reply.bytes, b"abc");
        assert_eq!(reply.evidence_sequence, 2);
        assert_eq!(server.handle(&peer, r.clone()).status, RpcStatus::Refuse);
        assert!(server.frontier.is_poisoned());
        assert_eq!(server.seal_after_terminal("e1"), Err(RpcFailure::Refused));
        r.operation_id = "other".into();
        assert_eq!(server.handle(&peer, r).status, RpcStatus::Refuse);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn framed_guest_client_closes_before_terminal_seal() {
        let dir = std::env::temp_dir().join(format!("realm-rpc-framed-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("input"), b"abc").unwrap();
        fs::write(dir.join("output"), b"---").unwrap();
        let launch = "1".repeat(64);
        let m = MediationManifest {
            schema: 2,
            run_id: "framed-run".into(),
            vm_config_blake3: "a".repeat(64),
            guest_kernel_blake3: "b".repeat(64),
            rootfs_blake3: "c".repeat(64),
            task_blake3: "d".repeat(64),
            guest_policy_blake3: "e".repeat(64),
            seccomp_blake3: "f".repeat(64),
            measured_launch_hash_domain: crate::measured_launch::MEASURED_LAUNCH_HASH_DOMAIN.into(),
            measured_launch_hash_version: crate::measured_launch::MEASURED_LAUNCH_HASH_VERSION,
            measured_launch_blake3: "9".repeat(64),
            broker_endpoint_identity: "8".repeat(64),
            host_policy_identifier: "fixture-policy".into(),
            host_policy_version: "1".into(),
            host_policy_blake3: "7".repeat(64),
            launch_identity: launch.clone(),
            starting_generation: "2".repeat(64),
            final_world: "3".repeat(64),
            delta_root: "4".repeat(64),
            runtime_identity: "5".repeat(64),
            network_policy_identity: "6".repeat(64),
            broker_identity: "broker".into(),
            broker_endpoint: "vsock:host:7000".into(),
            devices: vec![
                AttachedDevice {
                    kind: "rootfs".into(),
                    identity: "c".repeat(64),
                    read_only: true,
                },
                AttachedDevice {
                    kind: "broker_vsock".into(),
                    identity: "vsock:host:7000".into(),
                    read_only: true,
                },
            ],
            network_devices: vec![],
            shared_mounts: vec![],
            inherited_fds: vec![],
            writable_mappings: vec![],
            other_storage_aliases: vec![],
            max_task_processes: 1,
        };
        let bytes = serde_json::to_vec(&m).unwrap();
        let claim =
            test_only_checked_claim(&bytes, blake3::hash(&bytes).to_hex().as_ref()).unwrap();
        let frontier = EffectFrontier::create(
            &dir,
            "framed-run",
            "broker",
            &dir.join("input"),
            &dir.join("output"),
        )
        .unwrap();
        let input_version = frontier.current_version(false).to_string();
        let output_version = frontier.current_version(true).to_string();
        let root = ProcessIncarnation {
            launch: launch.clone(),
            serial: 1,
            birth: 1,
        };
        let (ledger, cap) = CapabilityLedger::new(&launch, root.clone()).unwrap();
        let server = BrokerRpc::new(frontier, ledger, claim).unwrap();
        let peer = PeerBinding {
            run_id: "framed-run".into(),
            process: root.clone(),
            capability: cap,
            challenge_root: String::new(),
        };
        let (mut guest, mut host) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            let mut server = server;
            server.send_bootstrap(&mut host).unwrap();
            for _ in 0..4 {
                server.serve_one(&mut host).unwrap();
            }
            server.ledger.exit(&root).unwrap();
            let head = server.seal_after_terminal("epoch-1").unwrap();
            (server, head)
        });
        let bootstrap = read_bootstrap(&mut guest).unwrap();
        assert_eq!(bootstrap.run_id, peer.run_id);
        assert_eq!(bootstrap.process, peer.process);
        assert_eq!(bootstrap.capability, peer.capability);
        assert_eq!(bootstrap.input_version, input_version);
        assert_eq!(bootstrap.output_version, output_version);
        let mut client = GuestClient::new(guest, peer);
        let id = client
            .request(RpcKind::Identify, "input", &input_version, 0, 0, vec![])
            .unwrap();
        assert_eq!(id.evidence_sequence, 1);
        let read = client
            .request(RpcKind::ReadRange, "input", &input_version, 0, 3, vec![])
            .unwrap();
        assert_eq!(read.bytes, b"abc");
        assert_eq!(read.evidence_sequence, 3);
        let write = client
            .request(
                RpcKind::WriteRange,
                "output",
                &output_version,
                0,
                3,
                b"ABC".to_vec(),
            )
            .unwrap();
        assert_eq!(write.completed, 3);
        assert_eq!(write.evidence_sequence, 5);
        let close = client
            .request(
                RpcKind::Close,
                "output",
                &write.resulting_version,
                0,
                0,
                vec![],
            )
            .unwrap();
        assert_eq!(close.evidence_sequence, 6);
        let (server, head) = worker.join().unwrap();
        let audit = crate::frontier::audit_mediated_journal_against(
            server.frontier.journal_path(),
            "framed-run",
            "broker",
            &head,
            server.authority.root(),
            &launch,
            &m.starting_generation,
        )
        .unwrap();
        assert_eq!(audit.committed_write_count, 1);
        assert_eq!(
            audit.records()[0].kind,
            crate::frontier::RecordKind::ResultIdentify
        );
        assert_eq!(
            audit.records()[5].kind,
            crate::frontier::RecordKind::ResultClose
        );
        assert_eq!(fs::read(dir.join("output")).unwrap(), b"ABC");
        assert_eq!(
            crate::frontier::audit_mediated_journal_against(
                server.frontier.journal_path(),
                "framed-run",
                "broker",
                &head,
                &"0".repeat(64),
                &launch,
                &m.starting_generation
            ),
            Err(FrontierFailure::StaleRoot)
        );
        let BrokerRpc {
            mut frontier,
            ledger,
            authority,
            ..
        } = server;
        let SessionAuthority::Checked(claim) = authority else {
            panic!("test fixture lost checked authority");
        };
        let snapshots = dir.join("snapshots");
        fs::create_dir(&snapshots).unwrap();
        let candidate = frontier
            .stage_snapshot_candidate(
                &snapshots,
                &m.starting_generation,
                &launch,
                &"3".repeat(64),
                &"4".repeat(64),
            )
            .unwrap();
        let freeze =
            crate::freeze::draft_freeze_epoch(&ledger, &frontier, &claim, &candidate).unwrap();
        assert_eq!(
            crate::freeze::publication_token(&freeze),
            Err(crate::freeze::FreezeFailure::UnverifiedImmutability)
        );
        let handoff = crate::v5_handoff::draft_v5_handoff_bound(
            &candidate,
            &audit,
            &freeze,
            &m.starting_generation,
            &"5".repeat(64),
            b"unverified receipt",
        )
        .unwrap();
        assert_eq!(handoff.mediation_manifest_root, claim.root());
        assert_eq!(handoff.freeze_binding_root, freeze.binding_root);
        fs::remove_dir_all(dir).unwrap();
    }
}
