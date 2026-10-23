//! V6 receipt validation. This crate does not implement a Linux reference monitor.
//! Public admission therefore refuses even structurally valid receipts.

#[cfg(target_os = "linux")]
pub mod broker_exec;
pub mod broker_rpc;
pub mod c1;
pub mod capsule;
pub mod custody;
pub mod execute;
#[cfg(unix)]
pub mod execution_backend;
pub mod filesystem_world;
pub mod freeze;
pub mod frontier;
pub mod generation;
pub mod integration;
pub mod jailer_plan;
#[cfg(target_os = "linux")]
pub mod linux_boundary;
#[cfg(target_os = "linux")]
pub mod linux_scan;
#[cfg(unix)]
pub mod measured_launch;
pub mod mediation;
pub mod profile;
pub mod publication;
pub mod publication_journal;
// Opaque production closure primitives and non-authorizing diagnostics.
pub mod run_closure;
#[cfg(unix)]
pub mod runtime_effects;
pub mod semantic_v2;
pub mod strict_json;
#[cfg(target_os = "linux")]
pub mod supervisor;
pub mod task_envelope;
mod terminal_authority;
pub mod v5_handoff;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub const FORMAT_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bindings {
    pub task_version: String,
    pub starting_state: String,
    pub generation_identity: String,
    pub authority_lineage: String,
    pub capsule_policy: String,
    pub executable_sha256: String,
    pub toolchain_sha256: String,
    pub guest_kernel_sha256: String,
    pub vmm_sha256: String,
    pub image_sha256: String,
    pub environment: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub uid: u32,
    pub limits: String,
    pub outcome_contract: String,
    pub verifier_identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsEntry {
    pub kind: EntryKind,
    #[serde(deserialize_with = "crate::strict_json::present_option")]
    pub content_blake3: Option<String>,
    pub size: u64,
    pub mode: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
}

pub type World = BTreeMap<String, FsEntry>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    ProcessStart,
    ProcessExec,
    ProcessExit,
    Read,
    Write,
    Create,
    Delete,
    Rename,
    Metadata,
    UnsupportedAttempt,
    Quiescence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Attempted,
    Committed,
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub sequence: u64,
    pub execution_id: String,
    pub process_id: String,
    #[serde(deserialize_with = "crate::strict_json::present_option")]
    pub parent_process_id: Option<String>,
    #[serde(deserialize_with = "crate::strict_json::present_option")]
    pub object_id: Option<String>,
    pub raw_operation: String,
    pub kind: EffectKind,
    pub disposition: Disposition,
    #[serde(deserialize_with = "crate::strict_json::present_option")]
    pub path: Option<String>,
    #[serde(deserialize_with = "crate::strict_json::present_option")]
    pub destination: Option<String>,
    #[serde(deserialize_with = "crate::strict_json::present_option")]
    pub after: Option<FsEntry>,
    pub previous_hash: String,
    pub hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub object_id: String,
    pub path: String,
    pub observed_blake3: String,
    pub first_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Segment {
    pub sequence: u64,
    pub first_event: u64,
    pub event_count: u64,
    pub lost_events: u64,
    pub previous_hash: String,
    pub hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub format_version: u16,
    pub execution_id: String,
    pub bindings: Bindings,
    pub starting_world: World,
    pub ordered_effects: Vec<Event>,
    pub effect_root: String,
    pub segments: Vec<Segment>,
    pub segment_root: String,
    pub verifier_derived_dependencies: Vec<Dependency>,
    pub final_world: World,
    pub final_world_root: String,
    pub outcome: String,
    pub verifier_result: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "decision",
    content = "reason",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum Admission {
    Refuse(Refusal),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Refusal {
    Malformed,
    MissingBinding,
    InvalidDigest,
    EventGap,
    EventOrder,
    IdentityAmbiguity,
    UnsupportedEffect,
    ProcessLeak,
    DependencyMismatch,
    WorldMismatch,
    ScanFailure,
    ResourceLimit,
    UnverifiedBoundary,
}

fn hash<T: Serialize>(value: &T) -> Result<String, Refusal> {
    let bytes = serde_json::to_vec(value).map_err(|_| Refusal::Malformed)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

pub fn world_root(world: &World) -> Result<String, Refusal> {
    hash(world)
}

pub fn seal_event(mut event: Event) -> Result<Event, Refusal> {
    event.hash.clear();
    event.hash = hash(&event)?;
    Ok(event)
}

pub fn seal_segment(mut segment: Segment, events: &[Event]) -> Result<Segment, Refusal> {
    segment.hash.clear();
    segment.hash = hash(&(&segment, events))?;
    Ok(segment)
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path.split('/').all(|p| !matches!(p, "" | "." | ".."))
        && !path.contains('\0')
        && !path.contains('\\')
}

fn check_bindings(b: &Bindings) -> Result<(), Refusal> {
    let required = [
        &b.task_version,
        &b.starting_state,
        &b.generation_identity,
        &b.authority_lineage,
        &b.capsule_policy,
        &b.environment,
        &b.cwd,
        &b.limits,
        &b.outcome_contract,
        &b.verifier_identity,
    ];
    if required.iter().any(|s| s.trim().is_empty())
        || b.argv.is_empty()
        || b.argv.iter().any(|s| s.is_empty())
    {
        return Err(Refusal::MissingBinding);
    }
    if ![
        &b.starting_state,
        &b.capsule_policy,
        &b.executable_sha256,
        &b.toolchain_sha256,
        &b.guest_kernel_sha256,
        &b.vmm_sha256,
        &b.image_sha256,
        &b.environment,
        &b.limits,
        &b.outcome_contract,
    ]
    .iter()
    .all(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(Refusal::InvalidDigest);
    }
    Ok(())
}

fn validate_world(world: &World) -> Result<(), Refusal> {
    for (path, entry) in world {
        if entry.mode > 0o7777 {
            return Err(Refusal::Malformed);
        }
        let mut parent = path.as_str();
        while let Some((ancestor, _)) = parent.rsplit_once('/') {
            if world
                .get(ancestor)
                .is_none_or(|entry| entry.kind != EntryKind::Directory)
            {
                return Err(Refusal::WorldMismatch);
            }
            parent = ancestor;
        }
        if !valid_path(path) {
            return Err(Refusal::Malformed);
        }
        match entry.kind {
            EntryKind::File
                if entry
                    .content_blake3
                    .as_ref()
                    .is_none_or(|h| h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit())) =>
            {
                return Err(Refusal::Malformed);
            }
            EntryKind::Directory if entry.content_blake3.is_some() || entry.size != 0 => {
                return Err(Refusal::Malformed);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Validates syntax and internal consistency. This is not a completeness proof.
pub fn validate_receipt(r: &Receipt) -> Result<Vec<Dependency>, Refusal> {
    if r.ordered_effects.len() > 1_000_000
        || r.segments.len() > 1_000_000
        || r.starting_world.len() > 1_000_000
        || r.final_world.len() > 1_000_000
    {
        return Err(Refusal::ResourceLimit);
    }
    if r.format_version != FORMAT_VERSION
        || r.execution_id.is_empty()
        || r.outcome.is_empty()
        || r.verifier_result != "verified"
    {
        return Err(Refusal::Malformed);
    }
    check_bindings(&r.bindings)?;
    validate_world(&r.starting_world)?;
    validate_world(&r.final_world)?;
    if world_root(&r.starting_world)? != r.bindings.starting_state
        || world_root(&r.final_world)? != r.final_world_root
    {
        return Err(Refusal::WorldMismatch);
    }
    let mut world = r.starting_world.clone();
    // Consistency only: initial IDs still require a trusted host manifest.
    let mut path_objects = BTreeMap::<String, String>::new();
    let mut allocated_objects = BTreeSet::<String>::new();
    let mut live = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut dependencies = BTreeMap::<(String, String, String), Dependency>::new();
    let mut previous = "0".repeat(64);
    let mut quiesced = false;
    let mut root_started = false;
    let mut root_process = String::new();
    for (index, event) in r.ordered_effects.iter().enumerate() {
        if event.sequence != index as u64 {
            return Err(Refusal::EventGap);
        }
        if event.previous_hash != previous || seal_event(event.clone())?.hash != event.hash {
            return Err(Refusal::InvalidDigest);
        }
        previous = event.hash.clone();
        if quiesced
            || event.execution_id != r.execution_id
            || event.process_id.is_empty()
            || event.raw_operation.trim().is_empty()
        {
            return Err(Refusal::EventOrder);
        }
        if let Some(path) = &event.path
            && !valid_path(path)
        {
            return Err(Refusal::Malformed);
        }
        if let Some(path) = &event.destination
            && !valid_path(path)
        {
            return Err(Refusal::Malformed);
        }
        // V1 has no operation-ID pairing; an unresolved attempt cannot disappear.
        if event.disposition != Disposition::Committed {
            return Err(Refusal::UnsupportedEffect);
        }
        let lifecycle = matches!(
            event.kind,
            EffectKind::ProcessStart | EffectKind::ProcessExit | EffectKind::Quiescence
        );
        if (lifecycle && (event.path.is_some() || event.object_id.is_some()))
            || (event.kind != EffectKind::ProcessStart && event.parent_process_id.is_some())
            || (event.kind != EffectKind::Rename && event.destination.is_some())
            || (!matches!(
                event.kind,
                EffectKind::Create | EffectKind::Write | EffectKind::Metadata
            ) && event.after.is_some())
        {
            return Err(Refusal::Malformed);
        }
        match event.kind {
            EffectKind::ProcessStart => {
                if event.disposition != Disposition::Committed
                    || !seen.insert(event.process_id.clone())
                    || event
                        .parent_process_id
                        .as_ref()
                        .is_some_and(|p| !live.contains(p))
                    || (event.parent_process_id.is_none() && (root_started || !live.is_empty()))
                {
                    return Err(Refusal::IdentityAmbiguity);
                }
                if event.parent_process_id.is_none() {
                    root_started = true;
                    root_process = event.process_id.clone();
                }
                live.insert(event.process_id.clone());
            }
            EffectKind::ProcessExit => {
                if event.disposition != Disposition::Committed || !live.remove(&event.process_id) {
                    return Err(Refusal::IdentityAmbiguity);
                }
            }
            EffectKind::Quiescence => {
                if event.disposition != Disposition::Committed
                    || !root_started
                    || event.process_id != root_process
                    || !live.is_empty()
                    || index + 1 != r.ordered_effects.len()
                {
                    return Err(Refusal::ProcessLeak);
                }
                quiesced = true;
            }
            EffectKind::UnsupportedAttempt => {
                // Preserve the raw denied attempt in evidence, but do not reuse this realization.
                return Err(Refusal::UnsupportedEffect);
            }
            _ => {
                if !live.contains(&event.process_id) {
                    return Err(Refusal::IdentityAmbiguity);
                }
                if event.disposition != Disposition::Committed {
                    continue;
                }
                let path = event.path.as_ref().ok_or(Refusal::Malformed)?;
                let object = event
                    .object_id
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .ok_or(Refusal::IdentityAmbiguity)?;
                if let Some(bound) = path_objects.get(path) {
                    if bound != object || event.kind == EffectKind::Create {
                        return Err(Refusal::IdentityAmbiguity);
                    }
                } else {
                    // Allocation IDs cannot alias another path or be recycled after unlink.
                    if !allocated_objects.insert(object.clone()) {
                        return Err(Refusal::IdentityAmbiguity);
                    }
                    path_objects.insert(path.clone(), object.clone());
                }
                match event.kind {
                    EffectKind::Read | EffectKind::ProcessExec => {
                        let observed = world.get(path).ok_or(Refusal::WorldMismatch)?;
                        let content = observed
                            .content_blake3
                            .clone()
                            .ok_or(Refusal::WorldMismatch)?;
                        dependencies
                            .entry((object.clone(), path.clone(), content.clone()))
                            .or_insert(Dependency {
                                object_id: object.clone(),
                                path: path.clone(),
                                observed_blake3: content,
                                first_sequence: event.sequence,
                            });
                    }
                    EffectKind::Write | EffectKind::Create | EffectKind::Metadata => {
                        let after = event.after.clone().ok_or(Refusal::Malformed)?;
                        let mut proposed = world.clone();
                        proposed.insert(path.clone(), after.clone());
                        validate_world(&proposed)?;
                        match event.kind {
                            EffectKind::Create if world.contains_key(path) => {
                                return Err(Refusal::WorldMismatch);
                            }
                            EffectKind::Write => {
                                let before = world.get(path).ok_or(Refusal::WorldMismatch)?;
                                if before.kind != EntryKind::File || after.kind != EntryKind::File {
                                    return Err(Refusal::UnsupportedEffect);
                                }
                            }
                            EffectKind::Metadata => {
                                let before = world.get(path).ok_or(Refusal::WorldMismatch)?;
                                if before.kind != after.kind
                                    || before.size != after.size
                                    || before.content_blake3 != after.content_blake3
                                {
                                    return Err(Refusal::UnsupportedEffect);
                                }
                            }
                            _ => {}
                        }
                        world.insert(path.clone(), after);
                    }
                    EffectKind::Delete => {
                        if world
                            .keys()
                            .any(|candidate| candidate.starts_with(&format!("{path}/")))
                        {
                            return Err(Refusal::UnsupportedEffect);
                        }
                        path_objects.remove(path);
                        if event.after.is_some() || world.remove(path).is_none() {
                            return Err(Refusal::WorldMismatch);
                        }
                    }
                    EffectKind::Rename => {
                        let destination = event.destination.as_ref().ok_or(Refusal::Malformed)?;
                        if world.contains_key(destination) {
                            return Err(Refusal::WorldMismatch);
                        }
                        let moved = world.remove(path).ok_or(Refusal::WorldMismatch)?;
                        if moved.kind != EntryKind::File {
                            return Err(Refusal::UnsupportedEffect);
                        }
                        path_objects.remove(path);
                        path_objects.insert(destination.clone(), object.clone());
                        world.insert(destination.clone(), moved);
                        validate_world(&world)?;
                    }
                    _ => return Err(Refusal::UnsupportedEffect),
                }
            }
        }
    }
    if !quiesced {
        return Err(Refusal::ProcessLeak);
    }
    if previous != r.effect_root {
        return Err(Refusal::InvalidDigest);
    }
    let mut next_event = 0usize;
    let mut previous_segment = "0".repeat(64);
    for (index, segment) in r.segments.iter().enumerate() {
        if segment.sequence != index as u64
            || segment.first_event != next_event as u64
            || segment.event_count == 0
        {
            return Err(Refusal::EventGap);
        }
        if segment.lost_events != 0 {
            return Err(Refusal::EventGap);
        }
        let end = next_event
            .checked_add(segment.event_count as usize)
            .ok_or(Refusal::ResourceLimit)?;
        if end > r.ordered_effects.len() {
            return Err(Refusal::EventGap);
        }
        if segment.previous_hash != previous_segment
            || seal_segment(segment.clone(), &r.ordered_effects[next_event..end])?.hash
                != segment.hash
        {
            return Err(Refusal::InvalidDigest);
        }
        previous_segment = segment.hash.clone();
        next_event = end;
    }
    if next_event != r.ordered_effects.len() {
        return Err(Refusal::EventGap);
    }
    if previous_segment != r.segment_root {
        return Err(Refusal::InvalidDigest);
    }
    if world != r.final_world {
        return Err(Refusal::WorldMismatch);
    }
    let derived: Vec<_> = dependencies.into_values().collect();
    if derived != r.verifier_derived_dependencies {
        return Err(Refusal::DependencyMismatch);
    }
    Ok(derived)
}

/// Observation-derived version history, distinct from the legacy deduplicated list.
/// A version ordinal records every observed mutation, including A -> B -> A.
/// It is not proof of consumed byte ranges or an authenticated initial object ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionDependency {
    pub object_id: String,
    pub path: String,
    pub version: u64,
    pub content_blake3: String,
    pub sequence: u64,
    pub executable: bool,
}

pub fn derive_version_dependencies(r: &Receipt) -> Result<Vec<VersionDependency>, Refusal> {
    validate_receipt(r)?;
    let mut current = r.starting_world.clone();
    let mut versions = BTreeMap::<String, u64>::new();
    let mut result = Vec::new();
    for event in &r.ordered_effects {
        if event.disposition != Disposition::Committed {
            continue;
        }
        match event.kind {
            EffectKind::Read | EffectKind::ProcessExec => {
                let path = event.path.as_ref().ok_or(Refusal::Malformed)?;
                let object = event.object_id.as_ref().ok_or(Refusal::IdentityAmbiguity)?;
                let content = current
                    .get(path)
                    .and_then(|entry| entry.content_blake3.clone())
                    .ok_or(Refusal::WorldMismatch)?;
                result.push(VersionDependency {
                    object_id: object.clone(),
                    path: path.clone(),
                    version: *versions.get(object).unwrap_or(&0),
                    content_blake3: content,
                    sequence: event.sequence,
                    executable: event.kind == EffectKind::ProcessExec,
                });
            }
            EffectKind::Create | EffectKind::Write | EffectKind::Metadata => {
                let object = event.object_id.as_ref().ok_or(Refusal::IdentityAmbiguity)?;
                if event.kind != EffectKind::Create {
                    *versions.entry(object.clone()).or_default() += 1;
                }
                current.insert(
                    event.path.clone().ok_or(Refusal::Malformed)?,
                    event.after.clone().ok_or(Refusal::Malformed)?,
                );
            }
            EffectKind::Rename => {
                let entry = current
                    .remove(event.path.as_ref().ok_or(Refusal::Malformed)?)
                    .ok_or(Refusal::WorldMismatch)?;
                current.insert(event.destination.clone().ok_or(Refusal::Malformed)?, entry);
            }
            EffectKind::Delete => {
                current.remove(event.path.as_ref().ok_or(Refusal::Malformed)?);
            }
            _ => {}
        }
    }
    Ok(result)
}

/// Host-side scanner rejects symlinks, hardlinks, devices, sockets and FIFOs.
/// It is a final-state check, not evidence about transient effects.
pub fn scan_world(root: &Path) -> Result<World, Refusal> {
    let mut world = World::new();
    scan_directory(root, root, &mut world)?;
    Ok(world)
}

fn scan_directory(root: &Path, dir: &Path, world: &mut World) -> Result<(), Refusal> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mut children = fs::read_dir(dir)
        .map_err(|_| Refusal::ScanFailure)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Refusal::ScanFailure)?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let path = child.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| Refusal::ScanFailure)?
            .to_str()
            .ok_or(Refusal::ScanFailure)?
            .replace(std::path::MAIN_SEPARATOR, "/");
        if !valid_path(&relative) {
            return Err(Refusal::ScanFailure);
        }
        let meta = fs::symlink_metadata(&path).map_err(|_| Refusal::ScanFailure)?;
        let mode = meta.permissions().mode() & 0o7777;
        let entry = if meta.is_dir() {
            FsEntry {
                kind: EntryKind::Directory,
                content_blake3: None,
                size: 0,
                mode,
            }
        } else if meta.is_file() && meta.nlink() == 1 {
            let bytes = fs::read(&path).map_err(|_| Refusal::ScanFailure)?;
            FsEntry {
                kind: EntryKind::File,
                content_blake3: Some(blake3::hash(&bytes).to_hex().to_string()),
                size: bytes.len() as u64,
                mode,
            }
        } else {
            return Err(Refusal::UnsupportedEffect);
        };
        world.insert(relative, entry);
        if meta.is_dir() {
            scan_directory(root, &path, world)?;
        }
    }
    Ok(())
}

/// Current public gate: no V6 Linux capsule monitor has been validated.
pub fn admit(receipt_json: &[u8], frozen_root: &Path) -> Admission {
    if receipt_json.len() > 64 * 1024 * 1024 {
        return Admission::Refuse(Refusal::ResourceLimit);
    }
    let receipt: Receipt = match strict_json::parse(receipt_json)
        .and_then(|v| serde_json::from_value(v).map_err(|_| Refusal::Malformed))
    {
        Ok(r) => r,
        Err(_) => return Admission::Refuse(Refusal::Malformed),
    };
    if let Err(reason) = validate_receipt(&receipt) {
        return Admission::Refuse(reason);
    }
    #[cfg(target_os = "linux")]
    let scanned = linux_scan::scan_world_linux(frozen_root);
    #[cfg(not(target_os = "linux"))]
    let scanned = scan_world(frozen_root);
    match scanned {
        Ok(world) if world == receipt.final_world => Admission::Refuse(Refusal::UnverifiedBoundary),
        Ok(_) => Admission::Refuse(Refusal::WorldMismatch),
        Err(reason) => Admission::Refuse(reason),
    }
}

/// State transition to use only after a future host-owned boundary verifier exists.
/// It deliberately cannot be reached from the public admission API.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CounterfactualChoice {
    Reuse,
    Recompute,
}

#[cfg(test)]
fn decide_after_verified_boundary(current_state: &str, receipt: &Receipt) -> CounterfactualChoice {
    if current_state == receipt.bindings.starting_state {
        CounterfactualChoice::Reuse
    } else {
        CounterfactualChoice::Recompute
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> (std::path::PathBuf, Receipt) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "realm-v6-test-{}-{nonce}-{}",
            std::process::id(),
            FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("input.txt"), b"hello").unwrap();
        let world = scan_world(&dir).unwrap();
        let root = world_root(&world).unwrap();
        let digest = "a".repeat(64);
        let bindings = Bindings {
            task_version: "task@1".into(),
            starting_state: root.clone(),
            generation_identity: "generation-1".into(),
            authority_lineage: "lineage-1".into(),
            capsule_policy: digest.clone(),
            executable_sha256: digest.clone(),
            toolchain_sha256: digest.clone(),
            guest_kernel_sha256: digest.clone(),
            vmm_sha256: digest.clone(),
            image_sha256: digest.clone(),
            environment: digest.clone(),
            argv: vec!["/bin/tool".into()],
            cwd: "/work".into(),
            uid: 1000,
            limits: digest.clone(),
            outcome_contract: digest.clone(),
            verifier_identity: "host-verifier-1".into(),
        };
        let mut receipt = Receipt {
            format_version: FORMAT_VERSION,
            execution_id: "execution-1".into(),
            bindings,
            starting_world: world.clone(),
            ordered_effects: vec![],
            effect_root: String::new(),
            segments: vec![],
            segment_root: String::new(),
            verifier_derived_dependencies: vec![],
            final_world: world,
            final_world_root: root,
            outcome: "success".into(),
            verifier_result: "verified".into(),
        };
        push(&mut receipt, EffectKind::ProcessStart, "p1", None, None);
        push(
            &mut receipt,
            EffectKind::Read,
            "p1",
            Some("input.txt"),
            Some("obj1"),
        );
        push(&mut receipt, EffectKind::ProcessExit, "p1", None, None);
        push(&mut receipt, EffectKind::Quiescence, "p1", None, None);
        receipt.verifier_derived_dependencies = vec![Dependency {
            object_id: "obj1".into(),
            path: "input.txt".into(),
            observed_blake3: receipt.starting_world["input.txt"]
                .content_blake3
                .clone()
                .unwrap(),
            first_sequence: 1,
        }];
        reseal(&mut receipt);
        (dir, receipt)
    }

    fn push(
        receipt: &mut Receipt,
        kind: EffectKind,
        process: &str,
        path: Option<&str>,
        object: Option<&str>,
    ) {
        let event = Event {
            sequence: receipt.ordered_effects.len() as u64,
            execution_id: receipt.execution_id.clone(),
            process_id: process.into(),
            parent_process_id: None,
            object_id: object.map(str::to_owned),
            raw_operation: format!("{kind:?}"),
            kind,
            disposition: Disposition::Committed,
            path: path.map(str::to_owned),
            destination: None,
            after: None,
            previous_hash: receipt.effect_root.clone().if_empty_then_zeros(),
            hash: String::new(),
        };
        let event = seal_event(event).unwrap();
        receipt.effect_root = event.hash.clone();
        receipt.ordered_effects.push(event);
    }

    trait ZeroHash {
        fn if_empty_then_zeros(self) -> Self;
    }
    impl ZeroHash for String {
        fn if_empty_then_zeros(self) -> Self {
            if self.is_empty() {
                "0".repeat(64)
            } else {
                self
            }
        }
    }

    fn reseal(receipt: &mut Receipt) {
        let mut previous = "0".repeat(64);
        for (index, event) in receipt.ordered_effects.iter_mut().enumerate() {
            event.sequence = index as u64;
            event.previous_hash = previous;
            *event = seal_event(event.clone()).unwrap();
            previous = event.hash.clone();
        }
        receipt.effect_root = previous;
        let segment = Segment {
            sequence: 0,
            first_event: 0,
            event_count: receipt.ordered_effects.len() as u64,
            lost_events: 0,
            previous_hash: "0".repeat(64),
            hash: String::new(),
        };
        let segment = seal_segment(segment, &receipt.ordered_effects).unwrap();
        receipt.segment_root = segment.hash.clone();
        receipt.segments = vec![segment];
    }

    #[test]
    fn valid_structure_still_refuses_without_boundary() {
        let (dir, receipt) = fixture();
        assert_eq!(
            validate_receipt(&receipt).unwrap(),
            receipt.verifier_derived_dependencies
        );
        assert_eq!(
            admit(&serde_json::to_vec(&receipt).unwrap(), &dir),
            Admission::Refuse(Refusal::UnverifiedBoundary)
        );
        assert_eq!(
            decide_after_verified_boundary(&receipt.bindings.starting_state, &receipt),
            CounterfactualChoice::Reuse
        );
        assert_eq!(
            decide_after_verified_boundary("different", &receipt),
            CounterfactualChoice::Recompute
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_and_malformed_bindings_refuse() {
        let (dir, receipt) = fixture();
        let mut json = serde_json::to_value(&receipt).unwrap();
        json["bindings"]
            .as_object_mut()
            .unwrap()
            .remove("generation_identity");
        assert_eq!(
            admit(&serde_json::to_vec(&json).unwrap(), &dir),
            Admission::Refuse(Refusal::Malformed)
        );
        json = serde_json::to_value(&receipt).unwrap();
        json["bindings"]["environment"] = serde_json::Value::String(String::new());
        assert_eq!(
            admit(&serde_json::to_vec(&json).unwrap(), &dir),
            Admission::Refuse(Refusal::MissingBinding)
        );
        json = serde_json::to_value(&receipt).unwrap();
        json["bindings"]["executable_sha256"] = serde_json::Value::String("bad".into());
        assert_eq!(
            admit(&serde_json::to_vec(&json).unwrap(), &dir),
            Admission::Refuse(Refusal::InvalidDigest)
        );
        json = serde_json::to_value(&receipt).unwrap();
        json["bindings"]["environment"] = serde_json::Value::String("unmeasured-env".into());
        assert_eq!(
            admit(&serde_json::to_vec(&json).unwrap(), &dir),
            Admission::Refuse(Refusal::InvalidDigest)
        );
        json = serde_json::to_value(&receipt).unwrap();
        json["extra"] = serde_json::Value::Bool(true);
        assert_eq!(
            admit(&serde_json::to_vec(&json).unwrap(), &dir),
            Admission::Refuse(Refusal::Malformed)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn stream_corruption_and_process_leak_refuse() {
        let (dir, receipt) = fixture();
        let mut gap = receipt.clone();
        gap.ordered_effects[1].sequence = 4;
        assert_eq!(validate_receipt(&gap), Err(Refusal::EventGap));
        let mut duplicate = receipt.clone();
        duplicate
            .ordered_effects
            .insert(2, duplicate.ordered_effects[1].clone());
        assert_eq!(validate_receipt(&duplicate), Err(Refusal::EventGap));
        let mut reordered = receipt.clone();
        reordered.ordered_effects.swap(1, 2);
        assert_eq!(validate_receipt(&reordered), Err(Refusal::EventGap));
        let mut corrupt = receipt.clone();
        corrupt.ordered_effects[1].path = Some("other".into());
        assert_eq!(validate_receipt(&corrupt), Err(Refusal::InvalidDigest));
        let mut missing_segment = receipt.clone();
        missing_segment.segments.clear();
        assert_eq!(validate_receipt(&missing_segment), Err(Refusal::EventGap));
        let mut lost_events = receipt.clone();
        lost_events.segments[0].lost_events = 1;
        assert_eq!(validate_receipt(&lost_events), Err(Refusal::EventGap));
        let mut duplicate_segment = receipt.clone();
        duplicate_segment
            .segments
            .push(duplicate_segment.segments[0].clone());
        assert_eq!(validate_receipt(&duplicate_segment), Err(Refusal::EventGap));
        let mut truncated = receipt.clone();
        truncated.ordered_effects.pop();
        assert_eq!(validate_receipt(&truncated), Err(Refusal::ProcessLeak));
        let mut survivor = receipt.clone();
        survivor.ordered_effects.remove(2);
        survivor.ordered_effects[2].sequence = 2;
        reseal(&mut survivor);
        assert_eq!(validate_receipt(&survivor), Err(Refusal::ProcessLeak));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn forged_dependencies_unsupported_success_and_world_mismatch_refuse() {
        let (dir, receipt) = fixture();
        let mut forged = receipt.clone();
        forged.verifier_derived_dependencies.clear();
        assert_eq!(validate_receipt(&forged), Err(Refusal::DependencyMismatch));
        let mut unsupported = receipt.clone();
        unsupported.ordered_effects[1].kind = EffectKind::UnsupportedAttempt;
        reseal(&mut unsupported);
        assert_eq!(
            validate_receipt(&unsupported),
            Err(Refusal::UnsupportedEffect)
        );
        unsupported.ordered_effects[1].disposition = Disposition::Denied;
        reseal(&mut unsupported);
        assert_eq!(
            validate_receipt(&unsupported),
            Err(Refusal::UnsupportedEffect)
        );
        fs::write(dir.join("input.txt"), b"changed").unwrap();
        assert_eq!(
            admit(&serde_json::to_vec(&receipt).unwrap(), &dir),
            Admission::Refuse(Refusal::WorldMismatch)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn scanner_refuses_symlinks_and_hardlinks() {
        let (dir, _) = fixture();
        symlink("input.txt", dir.join("alias")).unwrap();
        assert_eq!(scan_world(&dir), Err(Refusal::UnsupportedEffect));
        fs::remove_file(dir.join("alias")).unwrap();
        fs::hard_link(dir.join("input.txt"), dir.join("alias")).unwrap();
        assert_eq!(scan_world(&dir), Err(Refusal::UnsupportedEffect));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn child_grandchild_lineage_requires_every_exit() {
        let (dir, mut receipt) = fixture();
        let root_start = receipt.ordered_effects[0].clone();
        let root_exit = receipt.ordered_effects[2].clone();
        let mut child = root_start.clone();
        child.process_id = "p2".into();
        child.parent_process_id = Some("p1".into());
        let mut grandchild = root_start;
        grandchild.process_id = "p3".into();
        grandchild.parent_process_id = Some("p2".into());
        let mut child_exit = root_exit.clone();
        child_exit.process_id = "p2".into();
        let mut grandchild_exit = root_exit;
        grandchild_exit.process_id = "p3".into();
        receipt.ordered_effects.insert(1, child);
        receipt.ordered_effects.insert(2, grandchild);
        receipt.ordered_effects.insert(4, grandchild_exit);
        receipt.ordered_effects.insert(5, child_exit);
        receipt.verifier_derived_dependencies[0].first_sequence = 3;
        reseal(&mut receipt);
        assert!(validate_receipt(&receipt).is_ok());
        receipt.ordered_effects.remove(4);
        reseal(&mut receipt);
        assert_eq!(validate_receipt(&receipt), Err(Refusal::ProcessLeak));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reread_after_write_derives_new_version_dependency() {
        let (dir, mut receipt) = fixture();
        let mut after = receipt.final_world["input.txt"].clone();
        after.content_blake3 = Some(blake3::hash(b"changed").to_hex().to_string());
        after.size = 7;
        let mut write = receipt.ordered_effects[1].clone();
        write.kind = EffectKind::Write;
        write.after = Some(after.clone());
        receipt.ordered_effects.insert(2, write);
        let read = receipt.ordered_effects[1].clone();
        receipt.ordered_effects.insert(3, read);
        receipt
            .final_world
            .insert("input.txt".into(), after.clone());
        receipt.final_world_root = world_root(&receipt.final_world).unwrap();
        let mut new_dependency = receipt.verifier_derived_dependencies[0].clone();
        new_dependency.observed_blake3 = after.content_blake3.unwrap();
        new_dependency.first_sequence = 3;
        receipt.verifier_derived_dependencies.push(new_dependency);
        receipt.verifier_derived_dependencies.sort_by(|a, b| {
            (&a.object_id, &a.path, &a.observed_blake3).cmp(&(
                &b.object_id,
                &b.path,
                &b.observed_blake3,
            ))
        });
        reseal(&mut receipt);
        assert_eq!(validate_receipt(&receipt).unwrap().len(), 2);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn resealed_identity_relabeling_is_refused() {
        let (dir, receipt) = fixture();
        // Property-style enumeration: changing any reread ID cannot mint a new object.
        for id in 0..128 {
            let mut changed = receipt.clone();
            let mut reread = changed.ordered_effects[1].clone();
            reread.object_id = Some(format!("forged-{id}"));
            changed.ordered_effects.insert(2, reread);
            let mut forged = changed.verifier_derived_dependencies[0].clone();
            forged.object_id = format!("forged-{id}");
            forged.first_sequence = 2;
            changed.verifier_derived_dependencies.insert(0, forged);
            reseal(&mut changed);
            assert_eq!(validate_receipt(&changed), Err(Refusal::IdentityAmbiguity));
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn object_id_cannot_alias_another_path() {
        let (dir, mut receipt) = fixture();
        let entry = receipt.starting_world["input.txt"].clone();
        receipt
            .starting_world
            .insert("second.txt".into(), entry.clone());
        receipt.final_world.insert("second.txt".into(), entry);
        receipt.bindings.starting_state = world_root(&receipt.starting_world).unwrap();
        receipt.final_world_root = world_root(&receipt.final_world).unwrap();
        let mut alias = receipt.ordered_effects[1].clone();
        alias.path = Some("second.txt".into());
        receipt.ordered_effects.insert(2, alias);
        let mut forged = receipt.verifier_derived_dependencies[0].clone();
        forged.path = "second.txt".into();
        forged.first_sequence = 2;
        receipt.verifier_derived_dependencies.push(forged);
        reseal(&mut receipt);
        assert_eq!(validate_receipt(&receipt), Err(Refusal::IdentityAmbiguity));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn deleted_allocation_cannot_be_reused() {
        let (dir, mut receipt) = fixture();
        let mut delete = receipt.ordered_effects[1].clone();
        delete.kind = EffectKind::Delete;
        let mut create = delete.clone();
        create.kind = EffectKind::Create;
        create.after = Some(receipt.starting_world["input.txt"].clone());
        receipt.ordered_effects.insert(2, delete);
        receipt.ordered_effects.insert(3, create);
        reseal(&mut receipt);
        assert_eq!(validate_receipt(&receipt), Err(Refusal::IdentityAmbiguity));
        receipt.ordered_effects[3].object_id = Some("new-allocation".into());
        reseal(&mut receipt);
        assert!(validate_receipt(&receipt).is_ok());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rename_retains_identity_and_read_versions() {
        let (dir, mut receipt) = fixture();
        let mut rename = receipt.ordered_effects[1].clone();
        rename.kind = EffectKind::Rename;
        rename.destination = Some("renamed.txt".into());
        receipt.ordered_effects.insert(2, rename);
        let mut read = receipt.ordered_effects[1].clone();
        read.path = Some("renamed.txt".into());
        receipt.ordered_effects.insert(3, read);
        let moved = receipt.final_world.remove("input.txt").unwrap();
        receipt.final_world.insert("renamed.txt".into(), moved);
        receipt.final_world_root = world_root(&receipt.final_world).unwrap();
        let mut dependency = receipt.verifier_derived_dependencies[0].clone();
        dependency.path = "renamed.txt".into();
        dependency.first_sequence = 3;
        receipt.verifier_derived_dependencies.push(dependency);
        reseal(&mut receipt);
        assert!(validate_receipt(&receipt).is_ok());
        receipt.ordered_effects[3].object_id = Some("replacement".into());
        receipt.verifier_derived_dependencies[1].object_id = "replacement".into();
        reseal(&mut receipt);
        assert_eq!(validate_receipt(&receipt), Err(Refusal::IdentityAmbiguity));
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn same_content_rewrite_is_a_distinct_observed_version() {
        let (dir, mut receipt) = fixture();
        let mut write = receipt.ordered_effects[1].clone();
        write.kind = EffectKind::Write;
        write.after = Some(receipt.starting_world["input.txt"].clone());
        receipt.ordered_effects.insert(2, write);
        let reread = receipt.ordered_effects[1].clone();
        receipt.ordered_effects.insert(3, reread);
        reseal(&mut receipt);
        let dependencies = derive_version_dependencies(&receipt).unwrap();
        assert_eq!(dependencies.len(), 2);
        assert_eq!(dependencies[0].version, 0);
        assert_eq!(dependencies[1].version, 1);
        assert_eq!(
            dependencies[0].content_blake3,
            dependencies[1].content_blake3
        );
        assert_eq!(dependencies[0].sequence, 1);
        assert_eq!(dependencies[1].sequence, 3);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unknown_wire_effect_is_malformed() {
        let (dir, receipt) = fixture();
        let mut json = serde_json::to_value(receipt).unwrap();
        json["ordered_effects"][1]["kind"] = serde_json::Value::String("unclassified".into());
        assert_eq!(
            admit(&serde_json::to_vec(&json).unwrap(), &dir),
            Admission::Refuse(Refusal::Malformed)
        );
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(target_os = "linux")]
mod production_session;

pub mod c0_contract;
pub mod coding_submission;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod controller_guard;
