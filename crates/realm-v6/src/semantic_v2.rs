//! Bounded semantic model, not an observer. ExpectedContext is NOT host authority.
//! All public admission paths refuse regardless of locally consistent evidence.
use crate::{Admission, Refusal, hash, valid_path};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_BYTES: usize = 4096;
const MAX_EVENTS: usize = 1024;
fn require(ok: bool, reason: Refusal) -> Result<(), Refusal> {
    if ok { Ok(()) } else { Err(reason) }
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub task: String,
    pub executable: String,
    #[serde(deserialize_with = "crate::strict_json::present_option")]
    pub interpreter: Option<String>,
    pub libraries: Vec<String>,
    pub argv: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub cwd: String,
    pub policy: String,
    pub generation: u64,
    pub allowed_inputs: Vec<String>,
    /// Writable output paths must be declared here. A path may be absent in
    /// S0 and then appear only through an explicit guest `Create` event.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_outputs: Vec<String>,
    pub time_rng_policy: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    pub incarnation: String,
    pub version: u64,
    pub bytes: Vec<u8>,
    pub mode: u32,
}
pub type World = BTreeMap<String, Object>;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Write,
    ReadWrite,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadEnd {
    Complete,
    Short,
    Eof,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Start {
        #[serde(deserialize_with = "crate::strict_json::present_option")]
        parent: Option<String>,
    },
    Open {
        fd: u32,
        handle: String,
        path: String,
        incarnation: String,
        access: Access,
    },
    Create {
        fd: u32,
        handle: String,
        path: String,
        incarnation: String,
        mode: u32,
    },
    Read {
        fd: u32,
        handle: String,
        incarnation: String,
        version: u64,
        offset: u64,
        requested: u64,
        returned: Vec<u8>,
        returned_length: u64,
        end: ReadEnd,
    },
    Write {
        fd: u32,
        handle: String,
        incarnation: String,
        before_version: u64,
        after_version: u64,
        offset: u64,
        requested: Vec<u8>,
        returned_length: u64,
    },
    Close {
        fd: u32,
        handle: String,
    },
    Exit {
        code: i32,
    },
    /// Host-observed guest shutdown, bound to a production terminal witness.
    /// This is distinct from a process exit code and cannot claim one.
    Poweroff {
        observation_root: String,
    },
    Terminal,
    Unsupported {
        operation: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub sequence: u64,
    pub run: String,
    pub process: String,
    pub epoch: String,
    pub action: Action,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum Origin {
    Initial {
        incarnation: String,
        version: u64,
        offset: u64,
    },
    Write {
        sequence: u64,
        offset: u64,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Span {
    pub offset_in_read: u64,
    pub length: u64,
    pub origin: Origin,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadDependency {
    pub sequence: u64,
    pub process: String,
    pub fd: u32,
    pub handle: String,
    pub path: String,
    pub incarnation: String,
    pub observed_version: u64,
    pub offset: u64,
    pub requested: u64,
    pub returned: Vec<u8>,
    pub returned_length: u64,
    pub end: ReadEnd,
    #[serde(deserialize_with = "crate::strict_json::present_option")]
    pub eof_size: Option<u64>,
    pub provenance: Vec<Span>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub epoch: String,
    pub source_count: u64,
    pub gaps: u64,
    pub duplicates: u64,
    pub reorder: u64,
    pub overflow: u64,
    pub restart: u64,
    pub partial: u64,
    pub delayed: u64,
    pub pending: u64,
    pub logger_died: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub format: u32,
    pub run: String,
    pub authority_parent: String,
    pub launch: Launch,
    #[serde(deserialize_with = "crate::strict_json::unique_strings")]
    pub directories: BTreeSet<String>,
    pub initial: World,
    pub events: Vec<Event>,
    pub dependencies: Vec<ReadDependency>,
    pub final_world: World,
    pub health: Health,
    pub evidence_root: String,
}
/// Caller-selected expected observations. Serializing this does not authenticate it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedContext {
    pub run: String,
    pub process: String,
    pub epoch: String,
    pub authority_parent: String,
    pub launch: Launch,
    #[serde(deserialize_with = "crate::strict_json::unique_strings")]
    pub directories: BTreeSet<String>,
    pub initial: World,
    pub source_count: u64,
    pub source_root: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub receipt: Receipt,
    pub expected: ExpectedContext,
}

#[derive(Debug)]
pub struct LocalVerified {
    dependencies: Vec<ReadDependency>,
    initial: World,
    opened_inputs: BTreeSet<String>,
    writable_initial: BTreeSet<String>,
    created_outputs: BTreeSet<String>,
    directories: BTreeSet<String>,
}
impl LocalVerified {
    pub fn dependencies(&self) -> &[ReadDependency] {
        &self.dependencies
    }
    /// Complete dependency comparison within this bounded model, never authority.
    pub fn dependencies_match(&self, current: &World, directories: &BTreeSet<String>) -> bool {
        directories == &self.directories
            && topology(current, directories).is_ok()
            && self.ranges_match(current)
    }
    /// File-range comparison only; callers must also verify directory/policy identity.
    /// This is not a reuse authorization.
    pub fn ranges_match(&self, current: &World) -> bool {
        // Exclusive creation observes absence, not just the bytes that were read.
        if self
            .created_outputs
            .iter()
            .any(|path| current.contains_key(path))
        {
            return false;
        }
        for path in &self.opened_inputs {
            let Some(old) = self.initial.get(path) else {
                return false;
            };
            let Some(new) = current.get(path) else {
                return false;
            };
            if old.incarnation != new.incarnation || old.mode != new.mode {
                return false;
            }
        }
        for path in &self.writable_initial {
            let Some(old) = self.initial.get(path) else {
                return false;
            };
            let Some(new) = current.get(path) else {
                return false;
            };
            // A host-prepared output is an explicit start-state dependency:
            // identity, mode, version, and its empty contents must all match.
            if old != new {
                return false;
            }
        }
        for dependency in &self.dependencies {
            for span in &dependency.provenance {
                if let Origin::Initial {
                    incarnation,
                    offset,
                    ..
                } = &span.origin
                {
                    let Some((path, _)) = self
                        .initial
                        .iter()
                        .find(|(_, o)| &o.incarnation == incarnation)
                    else {
                        return false;
                    };
                    let Some(object) = current.get(path) else {
                        return false;
                    };
                    let start = *offset as usize;
                    let end = start + span.length as usize;
                    let read_start = span.offset_in_read as usize;
                    if object.bytes.get(start..end)
                        != dependency
                            .returned
                            .get(read_start..read_start + span.length as usize)
                    {
                        return false;
                    }
                }
            }
            // EOF is a length observation. For created outputs its length is derived.
            if let Some(size) = dependency.eof_size
                && self.initial.contains_key(&dependency.path)
                && current
                    .get(&dependency.path)
                    .is_none_or(|o| o.bytes.len() as u64 != size)
            {
                return false;
            }
        }
        true
    }
}

#[derive(Clone)]
struct Descriptor {
    handle: String,
    path: String,
    incarnation: String,
    access: Access,
    cursor: u64,
}
struct StateObject {
    object: Object,
    origins: Vec<Origin>,
}
fn same_next(left: &Origin, right: &Origin, distance: u64) -> bool {
    match (left, right) {
        (
            Origin::Initial {
                incarnation: a,
                version: av,
                offset: ao,
            },
            Origin::Initial {
                incarnation: b,
                version: bv,
                offset: bo,
            },
        ) => a == b && av == bv && *ao + distance == *bo,
        (
            Origin::Write {
                sequence: a,
                offset: ao,
            },
            Origin::Write {
                sequence: b,
                offset: bo,
            },
        ) => a == b && *ao + distance == *bo,
        _ => false,
    }
}
fn spans(origins: &[Origin]) -> Vec<Span> {
    let mut result: Vec<Span> = Vec::new();
    for (index, origin) in origins.iter().enumerate() {
        if let Some(last) = result.last_mut()
            && same_next(&last.origin, origin, last.length)
        {
            last.length += 1;
            continue;
        }
        result.push(Span {
            offset_in_read: index as u64,
            length: 1,
            origin: origin.clone(),
        });
    }
    result
}
fn topology(world: &World, directories: &BTreeSet<String>) -> Result<(), Refusal> {
    require(
        world.len() <= 32 && directories.len() <= 32,
        Refusal::ResourceLimit,
    )?;
    let mut ids = BTreeSet::new();
    for path in world.keys().chain(directories.iter()) {
        require(valid_path(path), Refusal::Malformed)?;
        let mut parent = path.as_str();
        while let Some((ancestor, _)) = parent.rsplit_once('/') {
            require(directories.contains(ancestor), Refusal::WorldMismatch)?;
            parent = ancestor;
        }
    }
    for (path, object) in world {
        require(
            !directories.contains(path)
                && !object.incarnation.is_empty()
                && ids.insert(&object.incarnation),
            Refusal::IdentityAmbiguity,
        )?;
        require(
            object.mode <= 0o777 && object.bytes.len() <= MAX_BYTES,
            Refusal::ResourceLimit,
        )?;
    }
    Ok(())
}
fn launch(launch: &Launch) -> Result<(), Refusal> {
    require(
        [
            &launch.task,
            &launch.executable,
            &launch.policy,
            &launch.time_rng_policy,
        ]
        .iter()
        .all(|v| digest(v)),
        Refusal::InvalidDigest,
    )?;
    require(
        launch.interpreter.is_none() && launch.libraries.is_empty(),
        Refusal::UnsupportedEffect,
    )?;
    require(
        launch.cwd == "/work"
            && !launch.argv.is_empty()
            && launch.argv.len() <= 32
            && launch
                .argv
                .iter()
                .all(|v| !v.contains('\0') && v.len() <= 4096)
            && launch.environment.len() <= 32
            && launch.environment.iter().all(|(k, v)| {
                !k.is_empty() && !k.contains(['\0', '=']) && !v.contains('\0') && v.len() <= 4096
            }),
        Refusal::Malformed,
    )?;
    require(
        launch.allowed_inputs.iter().all(|p| valid_path(p))
            && launch.allowed_inputs.windows(2).all(|v| v[0] < v[1])
            && launch.allowed_outputs.iter().all(|p| valid_path(p))
            && launch.allowed_outputs.windows(2).all(|v| v[0] < v[1])
            && launch
                .allowed_inputs
                .iter()
                .all(|path| !launch.allowed_outputs.contains(path)),
        Refusal::Malformed,
    )
}

pub fn evidence_root(receipt: &Receipt) -> Result<String, Refusal> {
    let mut copy = receipt.clone();
    copy.evidence_root.clear();
    hash(&copy)
}
/// Producer sealing is a convenience and never authentication.
pub fn seal(receipt: &mut Receipt) -> Result<(), Refusal> {
    receipt.evidence_root = evidence_root(receipt)?;
    Ok(())
}

fn replay(receipt: &Receipt) -> Result<LocalVerified, Refusal> {
    require(
        receipt.format == 2 && digest(&receipt.run) && digest(&receipt.authority_parent),
        Refusal::Malformed,
    )?;
    require(
        receipt.events.len() <= MAX_EVENTS && receipt.dependencies.len() <= MAX_EVENTS,
        Refusal::ResourceLimit,
    )?;
    launch(&receipt.launch)?;
    topology(&receipt.initial, &receipt.directories)?;
    let initial_paths = receipt.initial.keys().cloned().collect::<Vec<_>>();
    let declared_initial_paths = receipt
        .launch
        .allowed_inputs
        .iter()
        .cloned()
        .chain(
            receipt
                .launch
                .allowed_outputs
                .iter()
                .filter(|path| receipt.initial.contains_key(*path))
                .cloned(),
        )
        .collect::<BTreeSet<_>>();
    require(
        declared_initial_paths == initial_paths.iter().cloned().collect()
            && receipt
                .launch
                .allowed_inputs
                .iter()
                .all(|path| receipt.initial.contains_key(path))
            && receipt.launch.allowed_outputs.iter().all(|path| {
                receipt.initial.get(path).is_none_or(|object| {
                    object.version == 0 && object.bytes.is_empty() && object.mode & 0o222 != 0
                })
            }),
        Refusal::DependencyMismatch,
    )?;
    let health = &receipt.health;
    require(
        !health.epoch.is_empty()
            && health.source_count == receipt.events.len() as u64
            && [
                health.gaps,
                health.duplicates,
                health.reorder,
                health.overflow,
                health.restart,
                health.partial,
                health.delayed,
                health.pending,
            ]
            .iter()
            .all(|n| *n == 0)
            && !health.logger_died,
        Refusal::EventGap,
    )?;
    let mut files: BTreeMap<String, StateObject> = receipt
        .initial
        .iter()
        .map(|(path, object)| {
            let origins = (0..object.bytes.len())
                .map(|i| Origin::Initial {
                    incarnation: object.incarnation.clone(),
                    version: object.version,
                    offset: i as u64,
                })
                .collect();
            (
                path.clone(),
                StateObject {
                    object: object.clone(),
                    origins,
                },
            )
        })
        .collect();
    let mut used_objects: BTreeSet<String> = receipt
        .initial
        .values()
        .map(|o| o.incarnation.clone())
        .collect();
    let mut used_handles = BTreeSet::new();
    let mut descriptors = BTreeMap::<u32, Descriptor>::new();
    let mut dependencies = Vec::new();
    let mut opened_inputs = BTreeSet::new();
    let mut writable_initial = BTreeSet::new();
    let mut process: Option<String> = None;
    let mut ended = false;
    let mut terminal = false;
    for (index, event) in receipt.events.iter().enumerate() {
        require(event.sequence == index as u64, Refusal::EventGap)?;
        require(
            event.run == receipt.run && event.epoch == health.epoch && !terminal,
            Refusal::EventOrder,
        )?;
        if let Action::Start { parent } = &event.action {
            require(
                index == 0 && parent.is_none() && !event.process.is_empty() && process.is_none(),
                Refusal::IdentityAmbiguity,
            )?;
            process = Some(event.process.clone());
            continue;
        }
        require(
            process.as_ref() == Some(&event.process),
            Refusal::IdentityAmbiguity,
        )?;
        if let Action::Terminal = event.action {
            require(
                ended && descriptors.is_empty() && index + 1 == receipt.events.len(),
                Refusal::ProcessLeak,
            )?;
            terminal = true;
            continue;
        }
        require(!ended && process.is_some(), Refusal::ProcessLeak)?;
        match &event.action {
            Action::Open {
                fd,
                handle,
                path,
                incarnation,
                access,
            } => {
                require(
                    *fd <= 1023
                        && !handle.is_empty()
                        && !descriptors.contains_key(fd)
                        && used_handles.insert(handle.clone()),
                    Refusal::IdentityAmbiguity,
                )?;
                let object = &files.get(path).ok_or(Refusal::WorldMismatch)?.object;
                require(
                    &object.incarnation == incarnation,
                    Refusal::IdentityAmbiguity,
                )?;
                if receipt.initial.contains_key(path) {
                    if receipt.launch.allowed_inputs.binary_search(path).is_ok() {
                        require(*access == Access::Read, Refusal::UnsupportedEffect)?;
                        opened_inputs.insert(path.clone());
                    } else if receipt.launch.allowed_outputs.binary_search(path).is_ok() {
                        require(*access == Access::Write, Refusal::UnsupportedEffect)?;
                        writable_initial.insert(path.clone());
                    } else {
                        return Err(Refusal::UnsupportedEffect);
                    }
                }
                descriptors.insert(
                    *fd,
                    Descriptor {
                        handle: handle.clone(),
                        path: path.clone(),
                        incarnation: incarnation.clone(),
                        access: access.clone(),
                        cursor: 0,
                    },
                );
            }
            Action::Create {
                fd,
                handle,
                path,
                incarnation,
                mode,
            } => {
                require(files.len() < 32 && *fd <= 1023, Refusal::ResourceLimit)?;
                require(
                    valid_path(path)
                        && !receipt.directories.contains(path)
                        && !files.contains_key(path),
                    Refusal::WorldMismatch,
                )?;
                if let Some((parent, _)) = path.rsplit_once('/') {
                    require(receipt.directories.contains(parent), Refusal::WorldMismatch)?;
                }
                require(
                    *mode <= 0o777
                        && !incarnation.is_empty()
                        && used_objects.insert(incarnation.clone()),
                    Refusal::IdentityAmbiguity,
                )?;
                require(
                    !handle.is_empty()
                        && !descriptors.contains_key(fd)
                        && used_handles.insert(handle.clone()),
                    Refusal::IdentityAmbiguity,
                )?;
                files.insert(
                    path.clone(),
                    StateObject {
                        object: Object {
                            incarnation: incarnation.clone(),
                            version: 0,
                            bytes: vec![],
                            mode: *mode,
                        },
                        origins: vec![],
                    },
                );
                descriptors.insert(
                    *fd,
                    Descriptor {
                        handle: handle.clone(),
                        path: path.clone(),
                        incarnation: incarnation.clone(),
                        access: Access::ReadWrite,
                        cursor: 0,
                    },
                );
            }
            Action::Read {
                fd,
                handle,
                incarnation,
                version,
                offset,
                requested,
                returned,
                returned_length,
                end,
            } => {
                let descriptor = descriptors.get_mut(fd).ok_or(Refusal::IdentityAmbiguity)?;
                require(
                    &descriptor.handle == handle && &descriptor.incarnation == incarnation,
                    Refusal::IdentityAmbiguity,
                )?;
                require(
                    descriptor.access != Access::Write,
                    Refusal::UnsupportedEffect,
                )?;
                let state = files.get(&descriptor.path).ok_or(Refusal::WorldMismatch)?;
                require(
                    state.object.version == *version && state.object.incarnation == *incarnation,
                    Refusal::DependencyMismatch,
                )?;
                require(
                    *requested <= MAX_BYTES as u64
                        && *offset == descriptor.cursor
                        && *offset <= MAX_BYTES as u64,
                    Refusal::ResourceLimit,
                )?;
                let available = state.object.bytes.len().saturating_sub(*offset as usize) as u64;
                let n = *returned_length;
                require(
                    n == returned.len() as u64 && n <= *requested && n <= available,
                    Refusal::DependencyMismatch,
                )?;
                let ending_ok = match end {
                    ReadEnd::Complete => n == *requested,
                    ReadEnd::Eof => n < *requested && n == available,
                    ReadEnd::Short => n > 0 && n < *requested && n < available,
                };
                require(ending_ok, Refusal::DependencyMismatch)?;
                let start = (*offset as usize).min(state.object.bytes.len());
                let finish = start + n as usize;
                require(
                    &state.object.bytes[start..finish] == returned,
                    Refusal::DependencyMismatch,
                )?;
                dependencies.push(ReadDependency {
                    sequence: event.sequence,
                    process: event.process.clone(),
                    fd: *fd,
                    handle: handle.clone(),
                    path: descriptor.path.clone(),
                    incarnation: incarnation.clone(),
                    observed_version: *version,
                    offset: *offset,
                    requested: *requested,
                    returned: returned.clone(),
                    returned_length: n,
                    end: end.clone(),
                    eof_size: if *end == ReadEnd::Eof {
                        Some(state.object.bytes.len() as u64)
                    } else {
                        None
                    },
                    provenance: spans(&state.origins[start..finish]),
                });
                descriptor.cursor += n;
            }
            Action::Write {
                fd,
                handle,
                incarnation,
                before_version,
                after_version,
                offset,
                requested,
                returned_length,
            } => {
                let descriptor = descriptors.get_mut(fd).ok_or(Refusal::IdentityAmbiguity)?;
                require(
                    &descriptor.handle == handle && &descriptor.incarnation == incarnation,
                    Refusal::IdentityAmbiguity,
                )?;
                require(
                    descriptor.access != Access::Read,
                    Refusal::UnsupportedEffect,
                )?;
                let state = files
                    .get_mut(&descriptor.path)
                    .ok_or(Refusal::WorldMismatch)?;
                require(
                    state.object.version == *before_version,
                    Refusal::DependencyMismatch,
                )?;
                let n = *returned_length;
                require(
                    requested.len() <= MAX_BYTES
                        && n <= requested.len() as u64
                        && *offset == descriptor.cursor
                        && *offset <= state.object.bytes.len() as u64
                        && n <= MAX_BYTES as u64 - *offset,
                    Refusal::ResourceLimit,
                )?;
                let expected_version = before_version
                    .checked_add(u64::from(n > 0))
                    .ok_or(Refusal::ResourceLimit)?;
                require(
                    *after_version == expected_version,
                    Refusal::DependencyMismatch,
                )?;
                let start = *offset as usize;
                let finish = start + n as usize;
                state
                    .object
                    .bytes
                    .resize(state.object.bytes.len().max(finish), 0);
                state.origins.resize(
                    state.object.bytes.len(),
                    Origin::Write {
                        sequence: event.sequence,
                        offset: 0,
                    },
                );
                state.object.bytes[start..finish].copy_from_slice(&requested[..n as usize]);
                for i in 0..n as usize {
                    state.origins[start + i] = Origin::Write {
                        sequence: event.sequence,
                        offset: i as u64,
                    };
                }
                state.object.version = expected_version;
                descriptor.cursor += n;
            }
            Action::Close { fd, handle } => {
                let descriptor = descriptors.remove(fd).ok_or(Refusal::IdentityAmbiguity)?;
                require(descriptor.handle == *handle, Refusal::IdentityAmbiguity)?;
            }
            Action::Exit { code } => {
                require(descriptors.is_empty(), Refusal::ProcessLeak)?;
                require(*code == 0, Refusal::UnsupportedEffect)?;
                ended = true;
            }
            Action::Poweroff { observation_root } => {
                require(descriptors.is_empty(), Refusal::ProcessLeak)?;
                require(digest(observation_root), Refusal::InvalidDigest)?;
                ended = true;
            }
            Action::Unsupported { .. } => return Err(Refusal::UnsupportedEffect),
            _ => return Err(Refusal::EventOrder),
        }
    }
    require(terminal && ended, Refusal::ProcessLeak)?;
    let world: World = files
        .into_iter()
        .map(|(path, state)| (path, state.object))
        .collect();
    topology(&receipt.final_world, &receipt.directories)?;
    require(world == receipt.final_world, Refusal::WorldMismatch)?;
    let created_outputs = world
        .keys()
        .filter(|path| !receipt.initial.contains_key(*path))
        .cloned()
        .collect();
    Ok(LocalVerified {
        dependencies,
        initial: receipt.initial.clone(),
        opened_inputs,
        writable_initial,
        created_outputs,
        directories: receipt.directories.clone(),
    })
}
/// Returns derived observations for producer tooling; it cannot confer trust.
pub fn derive(receipt: &Receipt) -> Result<Vec<ReadDependency>, Refusal> {
    Ok(replay(receipt)?.dependencies)
}

pub fn validate(receipt: &Receipt, expected: &ExpectedContext) -> Result<LocalVerified, Refusal> {
    require(
        receipt.run == expected.run
            && receipt.authority_parent == expected.authority_parent
            && receipt.launch == expected.launch
            && receipt.initial == expected.initial
            && receipt.directories == expected.directories,
        Refusal::MissingBinding,
    )?;
    require(
        receipt.health.epoch == expected.epoch
            && receipt.health.source_count == expected.source_count
            && receipt
                .events
                .first()
                .is_some_and(|e| e.process == expected.process),
        Refusal::EventGap,
    )?;
    let local = replay(receipt)?;
    require(
        local.dependencies == receipt.dependencies,
        Refusal::DependencyMismatch,
    )?;
    require(
        digest(&receipt.evidence_root)
            && evidence_root(receipt)? == receipt.evidence_root
            && receipt.evidence_root == expected.source_root,
        Refusal::InvalidDigest,
    )?;
    Ok(local)
}

pub fn admit(receipt: &Receipt, expected: &ExpectedContext) -> Admission {
    match validate(receipt, expected) {
        Err(reason) => Admission::Refuse(reason),
        Ok(_) => Admission::Refuse(Refusal::UnverifiedBoundary),
    }
}
