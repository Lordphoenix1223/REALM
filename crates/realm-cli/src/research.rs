//! Locked, reproducible research packet runner.
//!
//! `protocol.yaml` v1 intentionally uses the JSON-compatible YAML subset so
//! the bytes have one strict parser and canonical serialization. This runner
//! records observations; it never labels a result as a paper counterexample.

use serde::{Deserialize, Serialize};
use std::os::unix::fs::MetadataExt;
use std::{
    collections::BTreeMap,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
};

const PROTOCOL_SCHEMA: &str = "realm.research.protocol/v1";
const LOCK_SCHEMA: &str = "realm.research.protocol-lock/v1";
const ORACLE_SCHEMA: &str = "realm.research.oracle-result/v1";
const EVIDENCE_SCHEMA: &str = "realm.research.attack-evidence/v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Protocol {
    schema: String,
    claim_id: String,
    paper: String,
    exact_claim: String,
    scope: String,
    assumptions: Vec<String>,
    falsification_condition: String,
    baseline_script: String,
    attack_script: String,
    oracle_script: String,
    oracle_world_file: String,
    #[serde(default)]
    witness_file: Option<String>,
    oracle_observation: String,
    environment: String,
    stopping_rule: String,
    approval_name: String,
    approval_statement: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtocolLock {
    schema: String,
    hash_domain: String,
    protocol_hash: String,
    materials: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OracleResult {
    schema: String,
    observed_falsification: bool,
    world_root: String,
    evidence_root: String,
    observation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AttackEvidence {
    schema: String,
    protocol_hash: String,
    classification: String,
    baseline_exit: i32,
    baseline_oracle: OracleResult,
    attack_exit: i32,
    attack_oracle: OracleResult,
    limitations: Vec<String>,
    files: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MinimizeEvidence {
    schema: String,
    protocol_hash: String,
    initial_steps: usize,
    minimized_steps: usize,
    trials: usize,
    baseline_oracle: OracleResult,
    final_oracle: OracleResult,
    minimality_claim: String,
    files: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceDocument {
    schema: String,
    paper: String,
    source_url: String,
    version: String,
    source_digest: String,
    review_notes: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClaimCandidate {
    exact_claim: String,
    scope: String,
    assumptions: Vec<String>,
    proposed_falsification: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClaimCandidates {
    claims: Vec<ClaimCandidate>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProposalEnvelope {
    schema: String,
    review_status: String,
    source_hash: String,
    claims: Vec<ClaimCandidate>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PackManifest {
    schema: String,
    evidence_hashes: BTreeMap<String, String>,
}

/// In-memory copy of every locked packet input. Protocol scripts run under
/// the caller's OS account and can see the evidence tree, so file permissions
/// alone cannot keep one script from replacing a later script. Execute the
/// captured bytes and restore the evidence snapshot after each child exits.
struct LockedPacket {
    root: PathBuf,
    files: BTreeMap<String, Vec<u8>>,
    directories: BTreeMap<PathBuf, (u64, u64)>,
}

impl LockedPacket {
    fn load(packet: &Path, protocol: &Protocol) -> Result<Self, Box<dyn Error>> {
        let metadata = fs::symlink_metadata(packet)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("locked packet snapshot is not a regular directory".into());
        }
        let root = fs::canonicalize(packet)?;
        let mut directories = BTreeMap::new();
        directories.insert(PathBuf::new(), directory_identity(&root)?);
        let mut names = vec![
            "protocol.yaml".to_owned(),
            "protocol.lock.json".to_owned(),
            protocol.baseline_script.clone(),
            protocol.attack_script.clone(),
            protocol.oracle_script.clone(),
        ];
        if let Some(witness) = &protocol.witness_file {
            names.push(witness.clone());
        }
        names.sort();
        names.dedup();
        let mut files = BTreeMap::new();
        for name in names {
            if !safe_relative_path(&name) {
                return Err("locked packet contains an unsafe path".into());
            }
            let relative_parent = Path::new(&name)
                .parent()
                .ok_or("locked packet file has no parent")?;
            let mut relative_directory = PathBuf::new();
            for component in relative_parent.components() {
                relative_directory.push(component.as_os_str());
                let directory = root.join(&relative_directory);
                let metadata = fs::symlink_metadata(&directory)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err("locked packet contains a non-directory parent".into());
                }
                directories.insert(relative_directory.clone(), directory_identity(&directory)?);
            }
            files.insert(name.clone(), fs::read(packet.join(name))?);
        }
        Ok(Self {
            root,
            files,
            directories,
        })
    }

    fn script(&self, name: &str) -> Result<&str, Box<dyn Error>> {
        let bytes = self
            .files
            .get(name)
            .ok_or_else(|| format!("script is not part of the locked packet: {name}"))?;
        let script = std::str::from_utf8(bytes)?;
        if script.contains('\0') {
            return Err(format!("script contains a NUL byte: {name}").into());
        }
        Ok(script)
    }

    fn restore(&self, packet: &Path) -> Result<(), Box<dyn Error>> {
        for (relative, expected_identity) in &self.directories {
            let directory = self.root.join(relative);
            let metadata = fs::symlink_metadata(&directory)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || directory_identity(&directory)? != *expected_identity
            {
                return Err("locked packet snapshot directory changed during execution".into());
            }
            if relative.as_os_str().is_empty() && fs::canonicalize(packet)? != self.root {
                return Err("locked packet snapshot path changed during execution".into());
            }
        }
        let root = &self.root;
        for (name, bytes) in &self.files {
            let relative = Path::new(name);
            if !safe_relative_path(name) {
                return Err("locked packet contains an unsafe restore path".into());
            }
            let destination = root.join(relative);
            let parent = destination
                .parent()
                .ok_or("locked packet file has no parent directory")?;
            if !fs::canonicalize(parent)?.starts_with(root) {
                return Err("locked packet parent escaped its snapshot".into());
            }
            let mut temporary = destination.clone();
            let name_root = blake3::hash(name.as_bytes()).to_hex().to_string();
            let suffix = format!("restore-{}-{}", std::process::id(), &name_root[..12]);
            temporary.set_extension(suffix);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            if let Err(error) = fs::rename(&temporary, &destination) {
                let _ = fs::remove_file(&temporary);
                return Err(error.into());
            }
        }
        Ok(())
    }
}

struct WitnessSnapshot {
    path: PathBuf,
    parent: PathBuf,
    bytes: Vec<u8>,
    parent_identity: (u64, u64),
}

/// Pins the output directory object for one baseline or attack case. Scripts
/// write modeled world state there, but must not redirect later oracle reads
/// or runner-owned output files by replacing the directory pathname.
struct CaseDirectory {
    path: PathBuf,
    identity: (u64, u64),
}

struct LockedScriptInvocation<'a> {
    packet: &'a Path,
    locked_packet: &'a LockedPacket,
    script: &'a str,
    case_dir: &'a CaseDirectory,
    role: &'a str,
    protocol_hash: &'a str,
    witness_path: Option<&'a Path>,
    oracle_world_root: Option<&'a str>,
    oracle_world_input: Option<&'a [u8]>,
}

struct OracleWorldSnapshot {
    canonical_json: Vec<u8>,
    root: String,
}

impl CaseDirectory {
    fn capture(path: &Path) -> Result<Self, Box<dyn Error>> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("research case path is not a regular directory".into());
        }
        let path = fs::canonicalize(path)?;
        let identity = directory_identity(&path)?;
        Ok(Self { path, identity })
    }

    fn verify(&self) -> Result<(), Box<dyn Error>> {
        let metadata = fs::symlink_metadata(&self.path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || fs::canonicalize(&self.path)? != self.path
            || directory_identity(&self.path)? != self.identity
        {
            return Err("research case directory changed during script execution".into());
        }
        Ok(())
    }
}

impl WitnessSnapshot {
    fn capture(path: &Path) -> Result<Self, Box<dyn Error>> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("research witness is not a regular file".into());
        }
        let path = fs::canonicalize(path)?;
        let parent = path
            .parent()
            .ok_or("research witness has no parent directory")?
            .to_path_buf();
        Ok(Self {
            bytes: fs::read(&path)?,
            path,
            parent_identity: directory_identity(&parent)?,
            parent,
        })
    }

    fn restore(&self) -> Result<(), Box<dyn Error>> {
        let parent_metadata = fs::symlink_metadata(&self.parent)?;
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || fs::canonicalize(&self.parent)? != self.parent
            || directory_identity(&self.parent)? != self.parent_identity
        {
            return Err("research witness parent changed during execution".into());
        }
        let mut temporary = self.path.clone();
        let filename = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("research witness filename is not UTF-8")?;
        let path_root = blake3::hash(self.path.as_os_str().to_string_lossy().as_bytes())
            .to_hex()
            .to_string();
        temporary.set_file_name(format!(
            "{filename}.restore-{}-{}",
            std::process::id(),
            &path_root[..12]
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&self.bytes)?;
        file.sync_all()?;
        drop(file);
        if let Err(error) = fs::rename(&temporary, &self.path) {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        Ok(())
    }
}

fn directory_identity(path: &Path) -> Result<(u64, u64), Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("expected a stable non-symlink directory".into());
    }
    Ok((metadata.dev(), metadata.ino()))
}

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args {
        [action, source, packet] if action == "import" => {
            import_source(Path::new(source), Path::new(packet))
        }
        [action, source, proposals, output] if action == "propose-claims" => {
            propose_claims(Path::new(source), Path::new(proposals), Path::new(output))
        }
        [action, packet] if action == "lint" => {
            lint(Path::new(packet))?;
            println!("protocol lint: VALID; approval and falsification fields are present");
            Ok(())
        }
        [action, packet] if action == "lock" => {
            let lock = lock(Path::new(packet))?;
            println!("locked protocol {}", lock.protocol_hash);
            Ok(())
        }
        [action, packet, evidence] if action == "reproduce" => {
            reproduce(Path::new(packet), Path::new(evidence))
        }
        [action, packet, evidence] if action == "attack" => {
            attack(Path::new(packet), Path::new(evidence))
        }
        [action, packet, evidence] if action == "minimize" => {
            minimize(Path::new(packet), Path::new(evidence))
        }
        [action, evidence] if action == "verify" => verify(Path::new(evidence)),
        [action, evidence, destination] if action == "pack" => {
            pack(Path::new(evidence), Path::new(destination))
        }
        _ => Err("usage: realm research import <source.json> <new-packet> | propose-claims <source.json> <candidates.json> <output.json> | lint <packet> | lock <packet> | reproduce <packet> <evidence-dir> | attack <locked-packet> <evidence-dir> | minimize <locked-packet> <evidence-dir> | verify <evidence-dir> | pack <evidence-dir> <new-pack-dir>".into()),
    }
}

fn import_source(source: &Path, packet: &Path) -> Result<(), Box<dyn Error>> {
    let document: SourceDocument = serde_json::from_slice(&fs::read(source)?)?;
    if document.schema != "realm.research.source/v1"
        || document.paper.trim().is_empty()
        || document.source_url.trim().is_empty()
        || document.version.trim().is_empty()
        || !valid_digest(&document.source_digest)
        || document.review_notes.trim().is_empty()
    {
        return Err("source metadata is incomplete or unsupported".into());
    }
    fs::create_dir(packet)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(packet.join("source.json"))?;
    output.write_all(&serde_json::to_vec_pretty(&document)?)?;
    output.sync_all()?;
    println!("source metadata imported; paper bytes and claims remain human-reviewed inputs");
    Ok(())
}

fn propose_claims(source: &Path, candidates: &Path, output: &Path) -> Result<(), Box<dyn Error>> {
    let source: SourceDocument = serde_json::from_slice(&fs::read(source)?)?;
    let claims: ClaimCandidates = serde_json::from_slice(&fs::read(candidates)?)?;
    if source.schema != "realm.research.source/v1"
        || !valid_digest(&source.source_digest)
        || claims.claims.is_empty()
        || claims.claims.iter().any(|claim| {
            claim.exact_claim.trim().is_empty()
                || claim.scope.trim().is_empty()
                || claim.assumptions.is_empty()
                || claim.assumptions.iter().any(|item| item.trim().is_empty())
                || claim.proposed_falsification.trim().is_empty()
        })
    {
        return Err("source or proposed claim candidate is incomplete".into());
    }
    let source_hash = hash_file_bytes(&serde_json::to_vec(&source)?)?;
    let envelope = ProposalEnvelope {
        schema: "realm.research.claim-proposals/v1".into(),
        review_status: "UNAPPROVED_PROPOSALS_NOT_ATTACKABLE".into(),
        source_hash,
        claims: claims.claims,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(&serde_json::to_vec_pretty(&envelope)?)?;
    file.sync_all()?;
    println!(
        "claim proposals recorded as unapproved; lock requires a separately reviewed protocol"
    );
    Ok(())
}

fn load_protocol(packet: &Path) -> Result<Protocol, Box<dyn Error>> {
    let bytes = fs::read(packet.join("protocol.yaml"))?;
    let protocol: Protocol = serde_json::from_slice(&bytes)?;
    validate_protocol(packet, &protocol)?;
    Ok(protocol)
}

fn lint(packet: &Path) -> Result<(), Box<dyn Error>> {
    let _ = load_protocol(packet)?;
    Ok(())
}

fn validate_protocol(packet: &Path, protocol: &Protocol) -> Result<(), Box<dyn Error>> {
    let nonempty = [
        &protocol.claim_id,
        &protocol.paper,
        &protocol.exact_claim,
        &protocol.scope,
        &protocol.falsification_condition,
        &protocol.oracle_observation,
        &protocol.environment,
        &protocol.stopping_rule,
        &protocol.approval_name,
        &protocol.approval_statement,
    ];
    if protocol.schema != PROTOCOL_SCHEMA
        || nonempty.iter().any(|value| value.trim().is_empty())
        || protocol.assumptions.is_empty()
        || protocol
            .assumptions
            .iter()
            .any(|value| value.trim().is_empty())
    {
        return Err("protocol schema or required locked claim fields are missing".into());
    }
    let names = [
        protocol.baseline_script.as_str(),
        protocol.attack_script.as_str(),
        protocol.oracle_script.as_str(),
    ];
    if names.iter().any(|name| !safe_relative_path(name))
        || protocol.attack_script == protocol.oracle_script
        || protocol.baseline_script == protocol.oracle_script
    {
        return Err("protocol scripts must be distinct safe relative paths".into());
    }
    if !safe_relative_path(&protocol.oracle_world_file)
        || names.contains(&protocol.oracle_world_file.as_str())
        || protocol.witness_file.as_deref() == Some(protocol.oracle_world_file.as_str())
    {
        return Err("oracle world input must be a distinct safe relative path".into());
    }
    let mut script_hashes = BTreeMap::new();
    let packet_root = fs::canonicalize(packet)?;
    for name in names {
        let path = packet.join(name);
        if !fs::symlink_metadata(&path)?.file_type().is_file() {
            return Err(format!("protocol script is not a regular file: {name}").into());
        }
        if !fs::canonicalize(&path)?.starts_with(&packet_root) {
            return Err(format!("protocol script resolves outside packet: {name}").into());
        }
        script_hashes.insert(name, hash_file(&path)?);
    }
    if script_hashes.get(protocol.attack_script.as_str())
        == script_hashes.get(protocol.oracle_script.as_str())
    {
        return Err("attack and independent-oracle scripts must have different content".into());
    }
    if let Some(witness_name) = &protocol.witness_file {
        if !safe_relative_path(witness_name) || names.contains(&witness_name.as_str()) {
            return Err("witness path must be distinct and inside the packet".into());
        }
        let path = packet.join(witness_name);
        if !fs::symlink_metadata(&path)?.file_type().is_file()
            || !fs::canonicalize(&path)?.starts_with(&packet_root)
        {
            return Err("witness must be a regular file inside the packet".into());
        }
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        let steps = value
            .get("steps")
            .and_then(serde_json::Value::as_array)
            .ok_or("witness must contain a JSON steps array")?;
        if steps.is_empty() {
            return Err("witness steps array must be non-empty".into());
        }
        script_hashes.insert(witness_name.as_str(), hash_file(&path)?);
    }
    Ok(())
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn protocol_hash(protocol: &Protocol) -> Result<String, Box<dyn Error>> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"realm.research.protocol.v1\0");
    hasher.update(&serde_json::to_vec(protocol)?);
    Ok(hasher.finalize().to_hex().to_string())
}

fn lock(packet: &Path) -> Result<ProtocolLock, Box<dyn Error>> {
    let protocol = load_protocol(packet)?;
    let mut materials = BTreeMap::new();
    for name in [
        protocol.baseline_script.as_str(),
        protocol.attack_script.as_str(),
        protocol.oracle_script.as_str(),
    ] {
        materials.insert(name.to_owned(), hash_file(&packet.join(name))?);
    }
    if let Some(witness) = &protocol.witness_file {
        materials.insert(witness.clone(), hash_file(&packet.join(witness))?);
    }
    let lock = ProtocolLock {
        schema: LOCK_SCHEMA.into(),
        hash_domain: "realm.research.protocol.v1".into(),
        protocol_hash: protocol_hash(&protocol)?,
        materials,
    };
    let bytes = serde_json::to_vec_pretty(&lock)?;
    let path = packet.join("protocol.lock.json");
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(lock)
}

fn require_lock(packet: &Path) -> Result<(Protocol, ProtocolLock), Box<dyn Error>> {
    let protocol = load_protocol(packet)?;
    let lock: ProtocolLock = serde_json::from_slice(&fs::read(packet.join("protocol.lock.json"))?)?;
    if lock.schema != LOCK_SCHEMA
        || lock.hash_domain != "realm.research.protocol.v1"
        || lock.protocol_hash != protocol_hash(&protocol)?
    {
        return Err("protocol is unlocked, changed, or uses an unsupported hash domain".into());
    }
    for name in [
        protocol.baseline_script.as_str(),
        protocol.attack_script.as_str(),
        protocol.oracle_script.as_str(),
    ] {
        if lock.materials.get(name) != Some(&hash_file(&packet.join(name))?) {
            return Err(format!("locked script changed: {name}").into());
        }
    }
    if let Some(witness) = &protocol.witness_file
        && lock.materials.get(witness) != Some(&hash_file(&packet.join(witness))?)
    {
        return Err(format!("locked witness changed: {witness}").into());
    }
    if lock.materials.len() != 3 + usize::from(protocol.witness_file.is_some()) {
        return Err("lock contains missing or unsupported material entries".into());
    }
    Ok((protocol, lock))
}

fn reproduce(packet: &Path, evidence_dir: &Path) -> Result<(), Box<dyn Error>> {
    let (protocol, lock) = require_lock(packet)?;
    let evidence_dir = prepare_evidence_dir(evidence_dir)?;
    snapshot_packet(packet, &protocol, &lock, &evidence_dir)?;
    let packet = evidence_dir.join("inputs");
    let locked_packet = LockedPacket::load(&packet, &protocol)?;
    let witness = protocol
        .witness_file
        .as_deref()
        .map(|name| packet.join(name));
    let case_dir = evidence_dir.join("baseline");
    fs::create_dir(&case_dir)?;
    let case_snapshot = CaseDirectory::capture(&case_dir)?;
    let baseline_exit = run_script(
        &packet,
        &locked_packet,
        &protocol.baseline_script,
        &case_snapshot,
        "baseline",
        &lock.protocol_hash,
        witness.as_deref(),
    )?;
    if baseline_exit != 0 {
        write_status(&evidence_dir, "BASELINE_EXECUTION_FAILED")?;
        return Err("baseline script failed; raw stdout/stderr were retained".into());
    }
    let baseline_oracle = run_oracle(
        &packet,
        &locked_packet,
        &protocol,
        &case_snapshot,
        "baseline",
        &lock.protocol_hash,
        witness.as_deref(),
    )?;
    if baseline_oracle.observed_falsification {
        write_status(&evidence_dir, "BASELINE_PROTOCOL_INVALID")?;
        return Err("independent oracle reports falsification on the declared baseline".into());
    }
    write_status(&evidence_dir, "BASELINE_REPRODUCED_ORACLE_REPORT_ONLY")?;
    println!("baseline oracle observation recorded; no paper claim is adjudicated");
    Ok(())
}

fn attack(packet: &Path, evidence_dir: &Path) -> Result<(), Box<dyn Error>> {
    let (protocol, lock) = require_lock(packet)?;
    let evidence_dir = prepare_evidence_dir(evidence_dir)?;
    snapshot_packet(packet, &protocol, &lock, &evidence_dir)?;
    let packet = evidence_dir.join("inputs");
    let locked_packet = LockedPacket::load(&packet, &protocol)?;
    let witness = protocol
        .witness_file
        .as_deref()
        .map(|name| packet.join(name));
    let baseline_dir = evidence_dir.join("baseline");
    let attack_dir = evidence_dir.join("attack");
    fs::create_dir(&baseline_dir)?;
    fs::create_dir(&attack_dir)?;
    let baseline_snapshot = CaseDirectory::capture(&baseline_dir)?;
    let attack_snapshot = CaseDirectory::capture(&attack_dir)?;

    let baseline_exit = run_script(
        &packet,
        &locked_packet,
        &protocol.baseline_script,
        &baseline_snapshot,
        "baseline",
        &lock.protocol_hash,
        witness.as_deref(),
    )?;
    if baseline_exit != 0 {
        write_status(&evidence_dir, "BASELINE_EXECUTION_FAILED")?;
        return Err("baseline script failed; attack was not run".into());
    }
    let baseline_oracle = run_oracle(
        &packet,
        &locked_packet,
        &protocol,
        &baseline_snapshot,
        "baseline",
        &lock.protocol_hash,
        witness.as_deref(),
    )?;
    if baseline_oracle.observed_falsification {
        write_status(&evidence_dir, "BASELINE_PROTOCOL_INVALID")?;
        return Err("baseline oracle reported falsification; attack was not run".into());
    }
    let attack_exit = run_script(
        &packet,
        &locked_packet,
        &protocol.attack_script,
        &attack_snapshot,
        "attack",
        &lock.protocol_hash,
        witness.as_deref(),
    )?;
    if attack_exit != 0 {
        write_status(&evidence_dir, "ATTACK_EXECUTION_FAILED")?;
        return Err("attack script failed; raw stdout/stderr were retained".into());
    }
    let attack_oracle = run_oracle(
        &packet,
        &locked_packet,
        &protocol,
        &attack_snapshot,
        "attack",
        &lock.protocol_hash,
        witness.as_deref(),
    )?;
    let classification = if attack_oracle.observed_falsification {
        "ORACLE_REPORTED_FALSIFICATION_REQUIRES_HUMAN_REVIEW"
    } else {
        "NO_FALSIFICATION_OBSERVED"
    };
    let mut evidence = AttackEvidence {
        schema: EVIDENCE_SCHEMA.into(),
        protocol_hash: lock.protocol_hash,
        classification: classification.into(),
        baseline_exit,
        baseline_oracle,
        attack_exit,
        attack_oracle,
        limitations: vec![
            "the runner does not prove the oracle is independent; reviewers must inspect its implementation and data path".into(),
            "an oracle-reported falsification is a lead, not a scientific counterexample or paper refutation".into(),
            "scripts execute with the caller's operating-system privileges and are not sandboxed by this runner".into(),
        ],
        files: BTreeMap::new(),
    };
    evidence.files = evidence_file_hashes(&evidence_dir)?;
    let bytes = serde_json::to_vec_pretty(&evidence)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence_dir.join("evidence.json"))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    println!("{classification}; evidence is observational and requires independent review");
    Ok(())
}

fn minimize(packet: &Path, evidence_dir: &Path) -> Result<(), Box<dyn Error>> {
    let (protocol, lock) = require_lock(packet)?;
    let witness_name = protocol
        .witness_file
        .as_ref()
        .ok_or("minimize requires a locked witness_file in protocol.yaml")?;
    let evidence_dir = prepare_evidence_dir(evidence_dir)?;
    snapshot_packet(packet, &protocol, &lock, &evidence_dir)?;
    let packet = evidence_dir.join("inputs");
    let locked_packet = LockedPacket::load(&packet, &protocol)?;
    let locked_witness = packet.join(witness_name);
    let mut witness: serde_json::Value = serde_json::from_slice(&fs::read(&locked_witness)?)?;
    let mut steps = witness
        .get("steps")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .ok_or("locked witness must contain a steps array")?;
    if steps.is_empty() {
        return Err("locked witness has no steps to minimize".into());
    }
    let initial_steps = steps.len();
    let baseline_dir = evidence_dir.join("baseline");
    fs::create_dir(&baseline_dir)?;
    let baseline_snapshot = CaseDirectory::capture(&baseline_dir)?;
    let baseline_exit = run_script(
        &packet,
        &locked_packet,
        &protocol.baseline_script,
        &baseline_snapshot,
        "baseline",
        &lock.protocol_hash,
        Some(&locked_witness),
    )?;
    if baseline_exit != 0 {
        write_status(&evidence_dir, "BASELINE_EXECUTION_FAILED")?;
        return Err("baseline failed; minimization did not start".into());
    }
    let baseline_oracle = run_oracle(
        &packet,
        &locked_packet,
        &protocol,
        &baseline_snapshot,
        "baseline",
        &lock.protocol_hash,
        Some(&locked_witness),
    )?;
    if baseline_oracle.observed_falsification {
        write_status(&evidence_dir, "BASELINE_PROTOCOL_INVALID")?;
        return Err("baseline oracle reports falsification; minimization stopped".into());
    }

    let initial_dir = evidence_dir.join("initial");
    fs::create_dir(&initial_dir)?;
    let initial_case = initial_dir.join("case");
    fs::create_dir(&initial_case)?;
    let initial_snapshot = CaseDirectory::capture(&initial_case)?;
    let initial_exit = run_script(
        &packet,
        &locked_packet,
        &protocol.attack_script,
        &initial_snapshot,
        "initial-attack",
        &lock.protocol_hash,
        Some(&locked_witness),
    )?;
    if initial_exit != 0 {
        write_status(&evidence_dir, "INITIAL_ATTACK_FAILED")?;
        return Err("initial attack failed; no witness was minimized".into());
    }
    let initial_oracle = run_oracle(
        &packet,
        &locked_packet,
        &protocol,
        &initial_snapshot,
        "initial-attack",
        &lock.protocol_hash,
        Some(&locked_witness),
    )?;
    if !initial_oracle.observed_falsification {
        write_status(&evidence_dir, "INITIAL_ORACLE_NO_FALSIFICATION")?;
        return Err("locked witness does not satisfy the frozen falsification predicate".into());
    }

    let trials_dir = evidence_dir.join("trials");
    fs::create_dir(&trials_dir)?;
    let mut trials = 0usize;
    let mut granularity = 2usize;
    while steps.len() > 1 {
        let chunk_size = steps.len().div_ceil(granularity);
        let mut reduced = false;
        for start in (0..steps.len()).step_by(chunk_size) {
            let end = (start + chunk_size).min(steps.len());
            let candidate_steps: Vec<_> = steps
                .iter()
                .enumerate()
                .filter(|(index, _)| *index < start || *index >= end)
                .map(|(_, step)| step.clone())
                .collect();
            let trial_dir = trials_dir.join(format!("trial-{trials:04}"));
            fs::create_dir(&trial_dir)?;
            let mut candidate = witness.clone();
            candidate["steps"] = serde_json::Value::Array(candidate_steps.clone());
            let candidate_path = trial_dir.join("witness.json");
            fs::write(&candidate_path, serde_json::to_vec_pretty(&candidate)?)?;
            let case_dir = trial_dir.join("case");
            fs::create_dir(&case_dir)?;
            let case_snapshot = CaseDirectory::capture(&case_dir)?;
            let attack_exit = run_script(
                &packet,
                &locked_packet,
                &protocol.attack_script,
                &case_snapshot,
                "minimize-attack",
                &lock.protocol_hash,
                Some(&candidate_path),
            )?;
            let trial_oracle = if attack_exit == 0 {
                run_oracle(
                    &packet,
                    &locked_packet,
                    &protocol,
                    &case_snapshot,
                    "minimize-attack",
                    &lock.protocol_hash,
                    Some(&candidate_path),
                )
                .ok()
            } else {
                None
            };
            let preserves = trial_oracle
                .as_ref()
                .is_some_and(|result| result.observed_falsification);
            fs::write(
                trial_dir.join("trial.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "candidate_steps": candidate_steps.len(),
                    "attack_exit": attack_exit,
                    "oracle": trial_oracle,
                    "preserves_falsification": preserves
                }))?,
            )?;
            trials += 1;
            if preserves {
                steps = candidate_steps;
                witness["steps"] = serde_json::Value::Array(steps.clone());
                granularity = granularity.saturating_sub(1).max(2);
                reduced = true;
                break;
            }
        }
        if reduced {
            continue;
        }
        if granularity >= steps.len() {
            break;
        }
        granularity = (granularity * 2).min(steps.len());
    }

    let final_dir = evidence_dir.join("final");
    fs::create_dir(&final_dir)?;
    let final_witness = final_dir.join("minimized-witness.json");
    witness["steps"] = serde_json::Value::Array(steps.clone());
    fs::write(&final_witness, serde_json::to_vec_pretty(&witness)?)?;
    let final_case = final_dir.join("case");
    fs::create_dir(&final_case)?;
    let final_snapshot = CaseDirectory::capture(&final_case)?;
    let final_exit = run_script(
        &packet,
        &locked_packet,
        &protocol.attack_script,
        &final_snapshot,
        "final-attack",
        &lock.protocol_hash,
        Some(&final_witness),
    )?;
    if final_exit != 0 {
        return Err("minimized witness attack failed on final replay".into());
    }
    let final_oracle = run_oracle(
        &packet,
        &locked_packet,
        &protocol,
        &final_snapshot,
        "final-attack",
        &lock.protocol_hash,
        Some(&final_witness),
    )?;
    if !final_oracle.observed_falsification {
        return Err("minimized witness did not preserve the independent oracle predicate".into());
    }
    fs::write(
        evidence_dir.join("minimize.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "realm.research.minimization/v1",
            "witness": witness,
            "initial_steps": initial_steps,
            "minimized_steps": steps.len(),
            "trials": trials
        }))?,
    )?;
    let mut evidence = MinimizeEvidence {
        schema: "realm.research.minimize-evidence/v1".into(),
        protocol_hash: lock.protocol_hash,
        initial_steps,
        minimized_steps: steps.len(),
        trials,
        baseline_oracle,
        final_oracle,
        minimality_claim: "1-deletion-minimal over top-level steps for the supplied oracle; oracle determinism and global minimality are not proven".into(),
        files: BTreeMap::new(),
    };
    evidence.files = minimize_file_hashes(&evidence_dir)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence_dir.join("minimize-evidence.json"))?;
    file.write_all(&serde_json::to_vec_pretty(&evidence)?)?;
    file.sync_all()?;
    println!(
        "oracle-preserving witness minimized from {initial_steps} to {} steps; human review still required",
        steps.len()
    );
    Ok(())
}

fn prepare_evidence_dir(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    fs::create_dir(path)?;
    fs::canonicalize(path).map_err(Into::into)
}

fn run_script(
    packet: &Path,
    locked_packet: &LockedPacket,
    script: &str,
    case_dir: &CaseDirectory,
    role: &str,
    protocol_hash: &str,
    witness_path: Option<&Path>,
) -> Result<i32, Box<dyn Error>> {
    let output = run_locked_script(LockedScriptInvocation {
        packet,
        locked_packet,
        script,
        case_dir,
        role,
        protocol_hash,
        witness_path,
        oracle_world_root: None,
        oracle_world_input: None,
    })?;
    Ok(output.status.code().unwrap_or(128))
}

fn run_locked_script(invocation: LockedScriptInvocation<'_>) -> Result<Output, Box<dyn Error>> {
    let LockedScriptInvocation {
        packet,
        locked_packet,
        script,
        case_dir,
        role,
        protocol_hash,
        witness_path,
        oracle_world_root,
        oracle_world_input,
    } = invocation;
    let packet = fs::canonicalize(packet)?;
    case_dir.verify()?;
    let witness_snapshot = witness_path.map(WitnessSnapshot::capture).transpose()?;
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(locked_packet.script(script)?)
        .current_dir(&case_dir.path)
        .env("REALM_RESEARCH_CASE_DIR", &case_dir.path)
        .env("REALM_RESEARCH_ROLE", role)
        .env("REALM_RESEARCH_PROTOCOL_HASH", protocol_hash);
    if let Some(path) = witness_path {
        command.env("REALM_RESEARCH_WITNESS_PATH", path);
    }
    if let Some(root) = oracle_world_root {
        command.env("REALM_RESEARCH_WORLD_ROOT", root);
    }
    let output = if let Some(world_input) = oracle_world_input {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match command.spawn() {
            Ok(mut child) => {
                let Some(stdin) = child.stdin.take() else {
                    return Err("oracle world snapshot stdin was not piped".into());
                };
                std::thread::scope(|scope| {
                    let writer = scope.spawn(move || {
                        let mut stdin = stdin;
                        stdin.write_all(world_input)
                    });
                    let output_result = child.wait_with_output();
                    let input_result = writer.join().unwrap_or_else(|_| {
                        Err(std::io::Error::other(
                            "oracle world snapshot writer panicked",
                        ))
                    });
                    input_result.and(output_result)
                })
            }
            Err(error) => Err(error),
        }
    } else {
        command.output()
    };
    // A child script can edit files in the evidence tree. Restore the captured
    // protocol, lock, scripts, and witness before any later phase reads them.
    let packet_restore = locked_packet.restore(&packet);
    let witness_restore = witness_snapshot
        .as_ref()
        .map(WitnessSnapshot::restore)
        .transpose();
    packet_restore?;
    witness_restore?;
    case_dir.verify()?;
    let output = output?;
    save_output(&case_dir.path, role, &output)?;
    Ok(output)
}

fn run_oracle(
    packet: &Path,
    locked_packet: &LockedPacket,
    protocol: &Protocol,
    case_dir: &CaseDirectory,
    role: &str,
    protocol_hash: &str,
    witness_path: Option<&Path>,
) -> Result<OracleResult, Box<dyn Error>> {
    case_dir.verify()?;
    let world_snapshot = oracle_world_snapshot(case_dir, &protocol.oracle_world_file)?;
    let oracle_role = format!("{role}-oracle");
    let output = run_locked_script(LockedScriptInvocation {
        packet,
        locked_packet,
        script: &protocol.oracle_script,
        case_dir,
        role: &oracle_role,
        protocol_hash,
        witness_path,
        oracle_world_root: Some(&world_snapshot.root),
        oracle_world_input: Some(&world_snapshot.canonical_json),
    })?;
    if output.status.code().unwrap_or(128) != 0 {
        return Err(format!("independent oracle command failed for {role}").into());
    }
    let result: OracleResult = serde_json::from_slice(&output.stdout)?;
    if result.schema != ORACLE_SCHEMA
        || result.world_root != world_snapshot.root
        || !valid_digest(&result.world_root)
        || !valid_digest(&result.evidence_root)
        || result.observation.trim().is_empty()
    {
        return Err("oracle result is malformed or unsupported".into());
    }
    if oracle_world_snapshot(case_dir, &protocol.oracle_world_file)?.root != world_snapshot.root {
        return Err("oracle left its case world input modified".into());
    }
    Ok(result)
}

fn oracle_world_snapshot(
    case_dir: &CaseDirectory,
    relative: &str,
) -> Result<OracleWorldSnapshot, Box<dyn Error>> {
    if !safe_relative_path(relative) {
        return Err("oracle world path is unsafe".into());
    }
    case_dir.verify()?;
    let path = case_dir.path.join(relative);
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("oracle world input must be a regular non-symlink file".into());
    }
    let canonical = fs::canonicalize(&path)?;
    if !canonical.starts_with(&case_dir.path) {
        return Err("oracle world input escaped its case directory".into());
    }
    let opened = File::open(canonical)?;
    let opened_metadata = opened.metadata()?;
    if !opened_metadata.is_file()
        || (opened_metadata.dev(), opened_metadata.ino()) != (metadata.dev(), metadata.ino())
    {
        return Err("oracle world input changed while it was being opened".into());
    }
    let mut raw = Vec::new();
    opened.take(16 * 1024 * 1024 + 1).read_to_end(&mut raw)?;
    if raw.len() > 16 * 1024 * 1024 {
        return Err("oracle world input exceeds the 16 MiB limit".into());
    }
    let world: serde_json::Value = serde_json::from_slice(&raw)?;
    let canonical_world = serde_json::to_vec(&world)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"realm.research.oracle-world-input.v1\0");
    hasher.update(&canonical_world);
    Ok(OracleWorldSnapshot {
        canonical_json: canonical_world,
        root: hasher.finalize().to_hex().to_string(),
    })
}

fn save_output(case_dir: &Path, role: &str, output: &Output) -> Result<(), Box<dyn Error>> {
    fs::write(case_dir.join(format!("{role}.stdout")), &output.stdout)?;
    fs::write(case_dir.join(format!("{role}.stderr")), &output.stderr)?;
    Ok(())
}

fn write_status(dir: &Path, status: &str) -> Result<(), Box<dyn Error>> {
    fs::write(
        dir.join("status.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": EVIDENCE_SCHEMA,
            "classification": status,
            "authority": "NONE"
        }))?,
    )?;
    Ok(())
}

fn verify(evidence_dir: &Path) -> Result<(), Box<dyn Error>> {
    if evidence_dir.join("PACK.json").exists() {
        let manifest: PackManifest =
            serde_json::from_slice(&fs::read(evidence_dir.join("PACK.json"))?)?;
        if manifest.schema != "realm.research.evidence-pack/v1"
            || tree_hashes(&evidence_dir.join("evidence"))? != manifest.evidence_hashes
        {
            return Err("evidence pack is corrupt or unsupported".into());
        }
        return verify(&evidence_dir.join("evidence"));
    }
    if evidence_dir.join("minimize-evidence.json").exists() {
        let evidence: MinimizeEvidence =
            serde_json::from_slice(&fs::read(evidence_dir.join("minimize-evidence.json"))?)?;
        let (protocol, lock) = require_lock(&evidence_dir.join("inputs"))?;
        let summary: serde_json::Value =
            serde_json::from_slice(&fs::read(evidence_dir.join("minimize.json"))?)?;
        let minimized_steps = summary
            .get("witness")
            .and_then(|value| value.get("steps"))
            .and_then(serde_json::Value::as_array)
            .map(Vec::len);
        if evidence.schema != "realm.research.minimize-evidence/v1"
            || evidence.protocol_hash != lock.protocol_hash
            || protocol.witness_file.is_none()
            || evidence.initial_steps < evidence.minimized_steps
            || evidence.minimized_steps == 0
            || minimized_steps != Some(evidence.minimized_steps)
            || summary.get("schema").and_then(serde_json::Value::as_str)
                != Some("realm.research.minimization/v1")
            || evidence.baseline_oracle.observed_falsification
            || !evidence.final_oracle.observed_falsification
            || evidence.final_oracle.schema != ORACLE_SCHEMA
            || !valid_digest(&evidence.final_oracle.world_root)
            || !valid_digest(&evidence.final_oracle.evidence_root)
            || minimize_file_hashes(evidence_dir)? != evidence.files
        {
            return Err(
                "minimization evidence is malformed, changed, or lost its frozen oracle predicate"
                    .into(),
            );
        }
        println!(
            "minimization evidence hashes valid; witness result remains unauthenticated and human-reviewed"
        );
        return Ok(());
    }
    let evidence: AttackEvidence =
        serde_json::from_slice(&fs::read(evidence_dir.join("evidence.json"))?)?;
    let (protocol, locked) = require_lock(&evidence_dir.join("inputs"))?;
    let expected_classification = if evidence.attack_oracle.observed_falsification {
        "ORACLE_REPORTED_FALSIFICATION_REQUIRES_HUMAN_REVIEW"
    } else {
        "NO_FALSIFICATION_OBSERVED"
    };
    if evidence.schema != EVIDENCE_SCHEMA
        || !valid_digest(&evidence.protocol_hash)
        || locked.protocol_hash != evidence.protocol_hash
        || protocol.claim_id.trim().is_empty()
        || evidence.classification != expected_classification
        || evidence.baseline_exit != 0
        || evidence.attack_exit != 0
        || evidence.baseline_oracle.observed_falsification
        || evidence.attack_oracle.schema != ORACLE_SCHEMA
        || !valid_digest(&evidence.baseline_oracle.world_root)
        || !valid_digest(&evidence.baseline_oracle.evidence_root)
        || !valid_digest(&evidence.attack_oracle.world_root)
        || !valid_digest(&evidence.attack_oracle.evidence_root)
    {
        return Err("evidence has unsupported schema or incomplete baseline/attack result".into());
    }
    let actual = evidence_file_hashes(evidence_dir)?;
    if actual != evidence.files {
        return Err("evidence file set or content hash changed".into());
    }
    println!(
        "evidence hashes valid (unauthenticated local integrity only); classification: {}",
        evidence.classification
    );
    Ok(())
}

fn pack(evidence_dir: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
    verify(evidence_dir)?;
    fs::create_dir(destination)?;
    let evidence_copy = destination.join("evidence");
    copy_tree(evidence_dir, &evidence_copy)?;
    let manifest = PackManifest {
        schema: "realm.research.evidence-pack/v1".into(),
        evidence_hashes: tree_hashes(&evidence_copy)?,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination.join("PACK.json"))?;
    file.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
    file.sync_all()?;
    println!("evidence packed with local content hashes; pack is not externally authenticated");
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir(destination)?;
    for item in fs::read_dir(source)? {
        let item = item?;
        let from = item.path();
        let to = destination.join(item.file_name());
        let metadata = fs::symlink_metadata(&from)?;
        if metadata.file_type().is_symlink() {
            return Err("cannot pack a symlink".into());
        }
        if metadata.is_dir() {
            copy_tree(&from, &to)?;
        } else if metadata.is_file() {
            fs::copy(from, to)?;
        } else {
            return Err("cannot pack a non-regular file".into());
        }
    }
    Ok(())
}

fn tree_hashes(root: &Path) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    fn visit(
        root: &Path,
        current: &Path,
        hashes: &mut BTreeMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        for item in fs::read_dir(current)? {
            let item = item?;
            let path = item.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err("tree contains a symlink".into());
            }
            if metadata.is_dir() {
                visit(root, &path, hashes)?;
            } else if metadata.is_file() {
                let name = path
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/");
                hashes.insert(name, hash_file(&path)?);
            } else {
                return Err("tree contains a non-regular object".into());
            }
        }
        Ok(())
    }
    let mut hashes = BTreeMap::new();
    visit(root, root, &mut hashes)?;
    Ok(hashes)
}

fn minimize_file_hashes(root: &Path) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    let mut hashes = tree_hashes(root)?;
    hashes.remove("minimize-evidence.json");
    Ok(hashes)
}

fn evidence_file_hashes(dir: &Path) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    fn visit(
        root: &Path,
        dir: &Path,
        out: &mut BTreeMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        for item in fs::read_dir(dir)? {
            let item = item?;
            let path = item.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err("evidence tree contains a symlink".into());
            }
            if metadata.is_dir() {
                visit(root, &path, out)?;
            } else if metadata.is_file() {
                if path == root.join("evidence.json") {
                    continue;
                }
                let relative = path
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(relative, hash_file(&path)?);
            } else {
                return Err("evidence tree contains a non-regular object".into());
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(dir, dir, &mut out)?;
    Ok(out)
}

fn hash_file(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 16384];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn hash_file_bytes(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

fn snapshot_packet(
    packet: &Path,
    protocol: &Protocol,
    lock: &ProtocolLock,
    evidence_dir: &Path,
) -> Result<(), Box<dyn Error>> {
    let packet = fs::canonicalize(packet)?;
    let snapshot = evidence_dir.join("inputs");
    fs::create_dir(&snapshot)?;
    for name in [
        "protocol.yaml",
        "protocol.lock.json",
        protocol.baseline_script.as_str(),
        protocol.attack_script.as_str(),
        protocol.oracle_script.as_str(),
    ] {
        let source = packet.join(name);
        if !fs::symlink_metadata(&source)?.file_type().is_file()
            || !fs::canonicalize(&source)?.starts_with(&packet)
        {
            return Err(format!("research input is not a regular in-packet file: {name}").into());
        }
        let destination = snapshot.join(name);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, destination)?;
    }
    if let Some(name) = &protocol.witness_file {
        let source = packet.join(name);
        let destination = snapshot.join(name);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, destination)?;
    }
    for name in [
        protocol.baseline_script.as_str(),
        protocol.attack_script.as_str(),
        protocol.oracle_script.as_str(),
    ] {
        if lock.materials.get(name) != Some(&hash_file(&snapshot.join(name))?) {
            return Err(format!("packet changed while snapshotting locked script: {name}").into());
        }
    }
    if let Some(witness) = &protocol.witness_file
        && lock.materials.get(witness) != Some(&hash_file(&snapshot.join(witness))?)
    {
        return Err(format!("packet changed while snapshotting locked witness: {witness}").into());
    }
    let (_, copied_lock) = require_lock(&snapshot)?;
    if copied_lock.protocol_hash != lock.protocol_hash {
        return Err("packet changed while snapshotting locked protocol".into());
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            loop {
                let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("realm-research-{}-{sequence}", std::process::id()));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create research test directory: {error}"),
                }
            }
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn research_usage_lists_minimization_and_requires_a_locked_attack_packet() {
        let error = run(&[]).unwrap_err().to_string();
        assert!(error.contains("minimize <locked-packet>"));
        assert!(error.contains("attack <locked-packet>"));
        assert!(error.contains("pack <evidence-dir>"));
    }

    fn packet(root: &Path) -> PathBuf {
        let packet = root.join("packet");
        fs::create_dir(&packet).unwrap();
        fs::write(
            packet.join("baseline.sh"),
            "printf '{\"state\":\"baseline\"}' > durable-world.json\nprintf baseline\n",
        )
        .unwrap();
        fs::write(
            packet.join("attack.sh"),
            "printf '{\"state\":\"attack\"}' > durable-world.json\nprintf attack\n",
        )
        .unwrap();
        fs::write(
            packet.join("oracle.sh"),
            r#"#!/bin/sh
if [ "$REALM_RESEARCH_ROLE" = baseline-oracle ]; then falsified=false; else falsified=true; fi
cat >/dev/null
printf '{"schema":"realm.research.oracle-result/v1","observed_falsification":%s,"world_root":"%s","evidence_root":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","observation":"test oracle report"}' "$falsified" "$REALM_RESEARCH_WORLD_ROOT"
"#,
        )
        .unwrap();
        let protocol = serde_json::json!({
            "schema": PROTOCOL_SCHEMA,
            "claim_id": "TEST-1",
            "paper": "synthetic test protocol",
            "exact_claim": "test claim",
            "scope": "synthetic fixture",
            "assumptions": ["isolated temp dir"],
            "falsification_condition": "oracle observes mismatch",
            "baseline_script": "baseline.sh",
            "attack_script": "attack.sh",
            "oracle_script": "oracle.sh",
            "oracle_world_file": "durable-world.json",
            "witness_file": "witness.json",
            "oracle_observation": "fresh world root",
            "environment": "unit test",
            "stopping_rule": "one case",
            "approval_name": "test reviewer",
            "approval_statement": "approve this synthetic fixture only"
        });
        fs::write(
            packet.join("protocol.yaml"),
            serde_json::to_vec_pretty(&protocol).unwrap(),
        )
        .unwrap();
        fs::write(
            packet.join("witness.json"),
            br#"{"steps":["one","two","three","four"]}"#,
        )
        .unwrap();
        packet
    }

    #[test]
    fn attack_refuses_before_lock_without_running_script() {
        let temp = Temp::new();
        let packet = packet(&temp.0);
        let marker = temp.0.join("ran");
        fs::write(
            packet.join("attack.sh"),
            format!("touch '{}'\n", marker.display()),
        )
        .unwrap();
        let result = attack(&packet, &temp.0.join("evidence"));
        assert!(result.is_err());
        assert!(!marker.exists());
    }

    #[test]
    fn attack_requires_unchanged_locked_scripts_and_records_observation() {
        let temp = Temp::new();
        let packet_dir = packet(&temp.0);
        lock(&packet_dir).unwrap();
        let evidence = temp.0.join("attack-evidence");
        attack(&packet_dir, &evidence).unwrap();
        verify(&evidence).unwrap();
        let report: AttackEvidence =
            serde_json::from_slice(&fs::read(evidence.join("evidence.json")).unwrap()).unwrap();
        assert_eq!(
            report.classification,
            "ORACLE_REPORTED_FALSIFICATION_REQUIRES_HUMAN_REVIEW"
        );
        fs::write(packet_dir.join("attack.sh"), "exit 0\n").unwrap();
        assert!(require_lock(&packet_dir).is_err());
    }

    #[test]
    fn attack_script_cannot_replace_the_locked_oracle_before_oracle_execution() {
        let temp = Temp::new();
        let packet_dir = packet(&temp.0);
        let malicious_oracle = r#"printf '{"schema":"realm.research.oracle-result/v1","observed_falsification":false,"world_root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","evidence_root":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","observation":"forged replacement oracle"}'
"#;
        fs::write(
            packet_dir.join("attack.sh"),
            format!(
                "cat > \"$REALM_RESEARCH_CASE_DIR/../inputs/oracle.sh\" <<'REALM_EOF'\n{malicious_oracle}REALM_EOF\nprintf '{{\"state\":\"attack\"}}' > durable-world.json\n"
            ),
        )
        .unwrap();
        lock(&packet_dir).unwrap();

        let evidence = temp.0.join("attack-evidence");
        attack(&packet_dir, &evidence).unwrap();
        verify(&evidence).unwrap();
        let report: AttackEvidence =
            serde_json::from_slice(&fs::read(evidence.join("evidence.json")).unwrap()).unwrap();
        assert!(report.attack_oracle.observed_falsification);
        assert_eq!(report.attack_oracle.observation, "test oracle report");
        let copied_oracle = evidence.join("inputs/oracle.sh");
        let original_oracle = packet_dir.join("oracle.sh");
        assert_eq!(
            fs::read(copied_oracle).unwrap(),
            fs::read(original_oracle).unwrap()
        );
    }

    #[test]
    fn attack_script_cannot_redirect_packet_restore_through_a_symlink() {
        let temp = Temp::new();
        let packet_dir = packet(&temp.0);
        let outside = temp.0.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("oracle.sh"), b"preserve outside bytes").unwrap();
        fs::write(
            packet_dir.join("attack.sh"),
            "mv \"$REALM_RESEARCH_CASE_DIR/../inputs\" \"$REALM_RESEARCH_CASE_DIR/../inputs.saved\"\n\
             ln -s \"$REALM_RESEARCH_CASE_DIR/../../outside\" \"$REALM_RESEARCH_CASE_DIR/../inputs\"\n",
        )
        .unwrap();
        lock(&packet_dir).unwrap();

        let evidence = temp.0.join("attack-evidence");
        assert!(attack(&packet_dir, &evidence).is_err());
        assert_eq!(
            fs::read(outside.join("oracle.sh")).unwrap(),
            b"preserve outside bytes"
        );
        assert!(
            fs::symlink_metadata(evidence.join("inputs"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn attack_script_cannot_replace_packet_root_at_the_same_path() {
        let temp = Temp::new();
        let packet_dir = packet(&temp.0);
        fs::write(
            packet_dir.join("attack.sh"),
            "mv \"$REALM_RESEARCH_CASE_DIR/../inputs\" \"$REALM_RESEARCH_CASE_DIR/../inputs.saved\"\n\
             mkdir \"$REALM_RESEARCH_CASE_DIR/../inputs\"\n",
        )
        .unwrap();
        lock(&packet_dir).unwrap();

        let evidence = temp.0.join("attack-evidence");
        assert!(attack(&packet_dir, &evidence).is_err());
        assert!(evidence.join("inputs").is_dir());
        assert!(!evidence.join("inputs/oracle.sh").exists());
        assert!(evidence.join("inputs.saved/oracle.sh").exists());
    }

    #[test]
    fn attack_script_cannot_redirect_case_oracle_and_output_paths() {
        let temp = Temp::new();
        let packet_dir = packet(&temp.0);
        let outside = temp.0.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"preserve outside bytes").unwrap();
        fs::write(
            packet_dir.join("attack.sh"),
            "mv \"$REALM_RESEARCH_CASE_DIR\" \"$REALM_RESEARCH_CASE_DIR.saved\"\n\
             ln -s \"$REALM_RESEARCH_CASE_DIR/../../outside\" \"$REALM_RESEARCH_CASE_DIR\"\n",
        )
        .unwrap();
        lock(&packet_dir).unwrap();

        let evidence = temp.0.join("attack-evidence");
        assert!(attack(&packet_dir, &evidence).is_err());
        assert_eq!(
            fs::read(outside.join("sentinel")).unwrap(),
            b"preserve outside bytes"
        );
        assert!(!outside.join("attack.stdout").exists());
        assert!(
            fs::symlink_metadata(evidence.join("attack"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn attack_script_cannot_substitute_the_locked_oracle_world_with_a_symlink() {
        let temp = Temp::new();
        let packet_dir = packet(&temp.0);
        let outside = temp.0.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(
            outside.join("durable-world.json"),
            br#"{"state":"outside"}"#,
        )
        .unwrap();
        fs::write(
            packet_dir.join("attack.sh"),
            "rm durable-world.json\n\
             ln -s \"$REALM_RESEARCH_CASE_DIR/../../outside/durable-world.json\" durable-world.json\n",
        )
        .unwrap();
        lock(&packet_dir).unwrap();

        let evidence = temp.0.join("attack-evidence");
        assert!(attack(&packet_dir, &evidence).is_err());
        assert_eq!(
            fs::read(outside.join("durable-world.json")).unwrap(),
            br#"{"state":"outside"}"#
        );
    }

    #[test]
    fn oracle_cannot_change_the_world_after_its_root_was_pinned() {
        let temp = Temp::new();
        let packet_dir = packet(&temp.0);
        fs::write(
            packet_dir.join("oracle.sh"),
            r#"#!/bin/sh
if [ "$REALM_RESEARCH_ROLE" = baseline-oracle ]; then falsified=false; else falsified=true; fi
printf '{"schema":"realm.research.oracle-result/v1","observed_falsification":%s,"world_root":"%s","evidence_root":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","observation":"test oracle report"}' "$falsified" "$REALM_RESEARCH_WORLD_ROOT"
if [ "$REALM_RESEARCH_ROLE" = attack-oracle ]; then printf '{"state":"changed by oracle"}' > durable-world.json; fi
"#,
        )
        .unwrap();
        lock(&packet_dir).unwrap();

        let evidence = temp.0.join("attack-evidence");
        assert!(attack(&packet_dir, &evidence).is_err());
        assert!(!evidence.join("evidence.json").exists());
    }

    #[test]
    fn oracle_receives_the_pinned_world_snapshot_during_mutate_and_restore() {
        let temp = Temp::new();
        let packet_dir = packet(&temp.0);
        fs::write(
            packet_dir.join("oracle.sh"),
            r#"#!/bin/sh
python3 -c '
import json, os, sys
from pathlib import Path

world = json.load(sys.stdin)
path = Path("durable-world.json")
original = path.read_bytes()
path.write_text(json.dumps({"state": "transient"}))
path.write_bytes(original)
print(json.dumps({
    "schema": "realm.research.oracle-result/v1",
    "observed_falsification": os.environ["REALM_RESEARCH_ROLE"] == "attack-oracle",
    "world_root": os.environ["REALM_RESEARCH_WORLD_ROOT"],
    "evidence_root": "b" * 64,
    "observation": world["state"]
}))
'
"#,
        )
        .unwrap();
        lock(&packet_dir).unwrap();

        let evidence = temp.0.join("attack-evidence");
        attack(&packet_dir, &evidence).unwrap();
        verify(&evidence).unwrap();
        let report: AttackEvidence =
            serde_json::from_slice(&fs::read(evidence.join("evidence.json")).unwrap()).unwrap();
        assert_eq!(report.baseline_oracle.observation, "baseline");
        assert_eq!(report.attack_oracle.observation, "attack");
        assert!(report.attack_oracle.observed_falsification);
    }

    #[test]
    fn oracle_report_must_name_the_canonical_world_input_root() {
        let temp = Temp::new();
        let packet_dir = packet(&temp.0);
        fs::write(
            packet_dir.join("oracle.sh"),
            r#"#!/bin/sh
if [ "$REALM_RESEARCH_ROLE" = baseline-oracle ]; then falsified=false; else falsified=true; fi
printf '{"schema":"realm.research.oracle-result/v1","observed_falsification":%s,"world_root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","evidence_root":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","observation":"wrong world root"}' "$falsified"
"#,
        )
        .unwrap();
        lock(&packet_dir).unwrap();

        let evidence = temp.0.join("attack-evidence");
        assert!(attack(&packet_dir, &evidence).is_err());
        assert!(!evidence.join("evidence.json").exists());
    }

    #[test]
    fn attack_script_cannot_change_the_witness_seen_by_the_oracle() {
        let temp = Temp::new();
        let packet_dir = packet(&temp.0);
        let original = fs::read(packet_dir.join("witness.json")).unwrap();
        fs::write(
            packet_dir.join("attack.sh"),
            "printf '{\"steps\":[\"forged\"]}' > \"$REALM_RESEARCH_WITNESS_PATH\"\nprintf '{\"state\":\"attack\"}' > durable-world.json\n",
        )
        .unwrap();
        lock(&packet_dir).unwrap();

        let evidence = temp.0.join("attack-evidence");
        attack(&packet_dir, &evidence).unwrap();
        verify(&evidence).unwrap();
        assert_eq!(
            fs::read(evidence.join("inputs/witness.json")).unwrap(),
            original
        );
        let report: AttackEvidence =
            serde_json::from_slice(&fs::read(evidence.join("evidence.json")).unwrap()).unwrap();
        assert!(report.attack_oracle.observed_falsification);
    }

    #[test]
    fn evidence_verifier_detects_raw_record_mutation_and_classification_laundering() {
        let temp = Temp::new();
        let packet_dir = packet(&temp.0);
        lock(&packet_dir).unwrap();
        let evidence = temp.0.join("attack-evidence");
        attack(&packet_dir, &evidence).unwrap();

        let raw = evidence.join("attack/attack.stdout");
        fs::write(&raw, b"altered after capture").unwrap();
        assert!(verify(&evidence).is_err());
        attack(&packet_dir, &temp.0.join("second-evidence")).unwrap();

        let report_path = temp.0.join("second-evidence/evidence.json");
        let mut report: AttackEvidence =
            serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
        report.classification = "NO_FALSIFICATION_OBSERVED".into();
        fs::write(&report_path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        assert!(verify(&temp.0.join("second-evidence")).is_err());
    }

    #[test]
    fn protocol_rejects_parent_traversal_and_duplicate_oracle_script() {
        let temp = Temp::new();
        let packet_dir = packet(&temp.0);
        let mut protocol: Protocol =
            serde_json::from_slice(&fs::read(packet_dir.join("protocol.yaml")).unwrap()).unwrap();
        let oracle_world_file = protocol.oracle_world_file.clone();
        protocol.oracle_world_file = "../escape.json".into();
        assert!(validate_protocol(&packet_dir, &protocol).is_err());
        protocol.oracle_world_file = oracle_world_file;
        protocol.attack_script = "../escape.sh".into();
        assert!(validate_protocol(&packet_dir, &protocol).is_err());
        protocol.attack_script = protocol.oracle_script.clone();
        assert!(validate_protocol(&packet_dir, &protocol).is_err());
    }

    #[test]
    fn source_import_and_claim_proposals_remain_unapproved() {
        let temp = Temp::new();
        let source_path = temp.0.join("source.json");
        let source = SourceDocument {
            schema: "realm.research.source/v1".into(),
            paper: "paper title".into(),
            source_url: "https://example.invalid/paper".into(),
            version: "v1".into(),
            source_digest: "a".repeat(64),
            review_notes: "primary paper reviewed".into(),
        };
        fs::write(&source_path, serde_json::to_vec(&source).unwrap()).unwrap();
        let packet = temp.0.join("packet");
        import_source(&source_path, &packet).unwrap();
        let candidates_path = temp.0.join("candidates.json");
        fs::write(
            &candidates_path,
            serde_json::to_vec(&ClaimCandidates {
                claims: vec![ClaimCandidate {
                    exact_claim: "exact bounded claim".into(),
                    scope: "declared scope".into(),
                    assumptions: vec!["assumption".into()],
                    proposed_falsification: "oracle condition".into(),
                }],
            })
            .unwrap(),
        )
        .unwrap();
        let output = temp.0.join("proposals.json");
        propose_claims(&source_path, &candidates_path, &output).unwrap();
        let proposals: ProposalEnvelope =
            serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(
            proposals.review_status,
            "UNAPPROVED_PROPOSALS_NOT_ATTACKABLE"
        );
        assert!(fs::read(packet.join("source.json")).is_ok());
    }

    #[test]
    fn packed_evidence_verifies_and_detects_tampering() {
        let temp = Temp::new();
        let packet_dir = packet(&temp.0);
        lock(&packet_dir).unwrap();
        let evidence = temp.0.join("attack-evidence");
        attack(&packet_dir, &evidence).unwrap();
        let packed = temp.0.join("packed");
        pack(&evidence, &packed).unwrap();
        verify(&packed).unwrap();
        fs::write(packed.join("evidence/attack/attack.stdout"), b"tampered").unwrap();
        assert!(verify(&packed).is_err());
    }

    #[test]
    fn minimizer_preserves_frozen_oracle_predicate_and_reduces_steps() {
        let temp = Temp::new();
        let packet_dir = packet(&temp.0);
        lock(&packet_dir).unwrap();
        let evidence = temp.0.join("minimized-evidence");
        minimize(&packet_dir, &evidence).unwrap();
        verify(&evidence).unwrap();
        let witness: serde_json::Value = serde_json::from_slice(
            &fs::read(evidence.join("final/minimized-witness.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(witness["steps"].as_array().unwrap().len(), 1);
        let packed = temp.0.join("minimized-pack");
        pack(&evidence, &packed).unwrap();
        verify(&packed).unwrap();
    }
}
