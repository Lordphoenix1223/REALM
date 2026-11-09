//! Immutable controlled worlds backed by manifests and Realm CAS.
//!
//! Phase III deliberately starts with a materialized directory backend. A
//! mounted filesystem would add implementation surface before the historical
//! hypothesis has been tested. The world store therefore owns immutable
//! manifests, content-addressed bytes, transaction layers, and disposable
//! materializations.

use realm_cas::{BlobRef, CasError, PreimageStore};
use realm_core::{
    ActorIdentity, ActorKind, EvidenceClass, EvidenceRecord, InputFidelity, IntentContract,
    KnownUnknown, NondeterminismCapsule, NondeterminismKind, NondeterministicInput, PathBytes,
    TransactionCapsule, TransactionId, UnknownReasonCode, WorldReference,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use uuid::Uuid;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
        )]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

id_type!(WorldId);
id_type!(WorldHeadId);
id_type!(BaseGenerationId);
id_type!(WorldManifestId);
id_type!(TransactionLayerId);
id_type!(RecoveryWorldId);
id_type!(CandidateWorldId);
id_type!(RealmObjectId);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ManifestKind {
    RegularFile,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SupportedXattr {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub logical_object_id: RealmObjectId,
    pub kind: ManifestKind,
    pub content_ref: Option<BlobRef>,
    pub metadata_ref: Option<BlobRef>,
    pub link_group: Option<RealmObjectId>,
    pub mode: u32,
    pub size: u64,
    pub symlink_target: Option<PathBytes>,
    pub supported_xattrs: Vec<SupportedXattr>,
}

impl ManifestEntry {
    fn canonical_bytes(&self, include_identity: bool, out: &mut Vec<u8>) {
        if include_identity {
            out.extend_from_slice(self.logical_object_id.0.as_bytes());
        }
        out.push(match self.kind {
            ManifestKind::RegularFile => 1,
            ManifestKind::Directory => 2,
            ManifestKind::Symlink => 3,
            ManifestKind::Other => 4,
        });
        encode_optional_blob(&self.content_ref, out);
        encode_optional_blob(&self.metadata_ref, out);
        if include_identity {
            match self.link_group {
                Some(id) => {
                    out.push(1);
                    out.extend_from_slice(id.0.as_bytes());
                }
                None => out.push(0),
            }
        }
        out.extend_from_slice(&self.mode.to_le_bytes());
        out.extend_from_slice(&self.size.to_le_bytes());
        encode_optional_path(&self.symlink_target, out);
        out.extend_from_slice(&(self.supported_xattrs.len() as u64).to_le_bytes());
        for xattr in &self.supported_xattrs {
            encode_bytes(&xattr.name, out);
            encode_bytes(&xattr.value, out);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorldManifest {
    pub id: WorldManifestId,
    pub entries: BTreeMap<PathBytes, ManifestEntry>,
    pub root_hash: String,
    pub semantic_hash: String,
    pub logical_bytes: u64,
    pub object_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ManifestDisk {
    id: WorldManifestId,
    entries: Vec<(PathBytes, ManifestEntry)>,
    root_hash: String,
    semantic_hash: String,
    logical_bytes: u64,
    object_count: u64,
}

impl From<&WorldManifest> for ManifestDisk {
    fn from(manifest: &WorldManifest) -> Self {
        Self {
            id: manifest.id,
            entries: manifest
                .entries
                .iter()
                .map(|(path, entry)| (path.clone(), entry.clone()))
                .collect(),
            root_hash: manifest.root_hash.clone(),
            semantic_hash: manifest.semantic_hash.clone(),
            logical_bytes: manifest.logical_bytes,
            object_count: manifest.object_count,
        }
    }
}

impl From<ManifestDisk> for WorldManifest {
    fn from(disk: ManifestDisk) -> Self {
        Self {
            id: disk.id,
            entries: disk.entries.into_iter().collect(),
            root_hash: disk.root_hash,
            semantic_hash: disk.semantic_hash,
            logical_bytes: disk.logical_bytes,
            object_count: disk.object_count,
        }
    }
}

impl WorldManifest {
    pub fn new(entries: BTreeMap<PathBytes, ManifestEntry>) -> Self {
        let (root_hash, semantic_hash) = hashes_for_entries(&entries);
        let logical_bytes = entries.values().map(|entry| entry.size).sum();
        let object_count = entries
            .values()
            .map(|entry| entry.logical_object_id)
            .collect::<BTreeSet<_>>()
            .len() as u64;
        Self {
            id: WorldManifestId::new(),
            entries,
            root_hash,
            semantic_hash,
            logical_bytes,
            object_count,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_entries(&self.entries, true)
    }

    pub fn semantic_bytes(&self) -> Vec<u8> {
        canonical_entries(&self.entries, false)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BaseGeneration {
    pub id: BaseGenerationId,
    pub fixture_id: String,
    pub source_manifest: WorldManifestId,
    pub sealed_root_hash: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum DeltaKind {
    Created,
    Deleted,
    ContentChanged,
    MetadataChanged,
    Replaced,
    Renamed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeltaEntry {
    pub path: PathBytes,
    pub kind: DeltaKind,
    pub before: Option<ManifestEntry>,
    pub after: Option<ManifestEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionLayer {
    #[serde(default = "legacy_layer_schema_version")]
    pub schema_version: u16,
    pub id: TransactionLayerId,
    pub parent_head: WorldHeadId,
    pub result_head: WorldHeadId,
    pub parent_manifest: WorldManifestId,
    pub result_manifest: WorldManifestId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule: Option<TransactionCapsule>,
    #[serde(rename = "actor", default, skip_serializing)]
    legacy_actor: Option<String>,
    #[serde(rename = "intent", default, skip_serializing)]
    legacy_intent: Option<String>,
    pub delta: Vec<DeltaEntry>,
    pub semantic_trace: Vec<String>,
    pub committed_unix_ms: u128,
    #[serde(rename = "environment", default, skip_serializing)]
    legacy_environment: BTreeMap<String, String>,
}

impl TransactionLayer {
    pub const SCHEMA_VERSION: u16 = 2;

    /// Return the immutable cross-phase capsule. V1 layers are upgraded in
    /// memory using the layer UUID as a stable transaction UUID; forensic V1
    /// bytes are never rewritten merely by reading them.
    pub fn transaction_capsule(&self) -> TransactionCapsule {
        if let Some(capsule) = &self.capsule {
            return capsule.clone();
        }
        let actor_id = self
            .legacy_actor
            .clone()
            .unwrap_or_else(|| "legacy-unknown".into());
        let raw_intent = self.legacy_intent.clone().unwrap_or_default();
        let mut capsule = TransactionCapsule::new(
            TransactionId(self.id.0),
            None,
            ActorIdentity {
                kind: ActorKind::Unknown,
                actor_id,
                semantic_session_id: None,
                declared_intent: Some(raw_intent.clone()),
            },
            IntentContract::from_raw(raw_intent),
        );
        capsule.parent_world = Some(controlled_world_reference(self.parent_head));
        if !self.legacy_environment.is_empty() {
            capsule.nondeterminism = nondeterminism_from_environment(&self.legacy_environment);
        }
        capsule.evidence.push(EvidenceRecord {
            class: EvidenceClass::AgentDeclaration,
            subject: "legacy-layer-migration".into(),
            evidence_ref: Some(self.id.to_string()),
            detail: Some(
                "Transaction capsule was deterministically projected from a V1 layer.".into(),
            ),
        });
        capsule
    }

    pub fn actor_id(&self) -> &str {
        self.capsule
            .as_ref()
            .map(|capsule| capsule.actor.actor_id.as_str())
            .or(self.legacy_actor.as_deref())
            .unwrap_or("legacy-unknown")
    }

    pub fn raw_intent(&self) -> &str {
        self.capsule
            .as_ref()
            .map(|capsule| capsule.intent.raw_intent.as_str())
            .or(self.legacy_intent.as_deref())
            .unwrap_or("")
    }
}

fn legacy_layer_schema_version() -> u16 {
    1
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorldHead {
    pub id: WorldHeadId,
    pub world_id: WorldId,
    pub base_generation: BaseGenerationId,
    pub manifest: WorldManifestId,
    pub parent: Option<WorldHeadId>,
    pub layers: Vec<TransactionLayerId>,
    pub forked_from: Option<WorldHeadId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MaterializationMarker {
    pub schema_version: u16,
    pub world_head: WorldHeadId,
    pub candidate: CandidateWorldId,
    pub fixture_id: String,
    pub expected_parent: PathBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedWorld {
    pub root: PathBuf,
    pub world_head: WorldHeadId,
    pub candidate: CandidateWorldId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SidecarEntry {
    path: PathBytes,
    object_id: RealmObjectId,
    physical: ObjectKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct IdentitySidecar {
    entries: Vec<SidecarEntry>,
}

impl IdentitySidecar {
    fn object_for(&self, path: &PathBytes, physical: ObjectKey) -> Option<RealmObjectId> {
        self.entries
            .iter()
            .find(|entry| &entry.path == path && entry.physical == physical)
            .or_else(|| self.entries.iter().find(|entry| entry.physical == physical))
            .map(|entry| entry.object_id)
    }
}

#[derive(Debug, Error)]
pub enum WorldError {
    #[error("world I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("CAS error: {0}")]
    Cas(#[from] CasError),
    #[error("world serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("world head is not present: {0}")]
    MissingHead(WorldHeadId),
    #[error("world manifest is not present: {0}")]
    MissingManifest(WorldManifestId),
    #[error("materialization destination is not disposable: {0}")]
    NotDisposable(PathBuf),
    #[error("materialization marker is missing or invalid")]
    InvalidMarker,
    #[error("symlink target escapes the controlled world: {0}")]
    EscapingSymlink(String),
    #[error("manifest validation failed: expected {expected}, observed {observed}")]
    ManifestMismatch { expected: String, observed: String },
    #[error("transaction capsule parent does not match the world lineage")]
    CapsuleParentMismatch,
    #[error("unsupported filesystem entry: {0}")]
    Unsupported(String),
}

pub struct WorldStore {
    root: PathBuf,
    cas: PreimageStore,
}

impl WorldStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, WorldError> {
        let root = root.as_ref().to_path_buf();
        for directory in ["manifests", "bases", "heads", "layers", "sidecars"] {
            fs::create_dir_all(root.join(directory))?;
        }
        let cas = PreimageStore::open(root.join("cas"))?;
        Ok(Self { root, cas })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn cas(&self) -> &PreimageStore {
        &self.cas
    }

    pub fn import(
        &self,
        fixture_id: impl Into<String>,
        source: &Path,
    ) -> Result<WorldHead, WorldError> {
        let fixture_id = fixture_id.into();
        let manifest = self.snapshot_directory(source, None)?;
        self.write_manifest(&manifest)?;
        let base = BaseGeneration {
            id: BaseGenerationId::new(),
            fixture_id,
            source_manifest: manifest.id,
            sealed_root_hash: manifest.root_hash.clone(),
        };
        self.write_json("bases", base.id.to_string(), &base)?;
        let head = WorldHead {
            id: WorldHeadId::new(),
            world_id: WorldId::new(),
            base_generation: base.id,
            manifest: manifest.id,
            parent: None,
            layers: Vec::new(),
            forked_from: None,
        };
        self.write_json("heads", head.id.to_string(), &head)?;
        Ok(head)
    }

    pub fn head(&self, id: WorldHeadId) -> Result<WorldHead, WorldError> {
        self.read_json("heads", id.to_string())?
            .ok_or(WorldError::MissingHead(id))
    }

    pub fn manifest(&self, id: WorldManifestId) -> Result<WorldManifest, WorldError> {
        self.read_json::<ManifestDisk>("manifests", id.to_string())?
            .map(WorldManifest::from)
            .ok_or(WorldError::MissingManifest(id))
    }

    pub fn layer(&self, id: TransactionLayerId) -> Result<TransactionLayer, WorldError> {
        let mut layer: TransactionLayer = self
            .read_json("layers", id.to_string())?
            .ok_or_else(|| WorldError::Unsupported(format!("missing transaction layer {id}")))?;
        if layer.capsule.is_none() {
            layer.capsule = Some(layer.transaction_capsule());
            layer.schema_version = TransactionLayer::SCHEMA_VERSION;
        }
        Ok(layer)
    }

    pub fn fork(&self, source: WorldHeadId) -> Result<WorldHead, WorldError> {
        let parent = self.head(source)?;
        let fork = WorldHead {
            id: WorldHeadId::new(),
            world_id: WorldId::new(),
            base_generation: parent.base_generation,
            manifest: parent.manifest,
            parent: Some(parent.id),
            layers: parent.layers.clone(),
            forked_from: Some(parent.id),
        };
        self.write_json("heads", fork.id.to_string(), &fork)?;
        Ok(fork)
    }

    pub fn history(&self, head: WorldHeadId) -> Result<Vec<TransactionLayer>, WorldError> {
        let head = self.head(head)?;
        head.layers.into_iter().map(|id| self.layer(id)).collect()
    }

    pub fn materialize(
        &self,
        head_id: WorldHeadId,
        destination: &Path,
        fixture_id: impl Into<String>,
    ) -> Result<MaterializedWorld, WorldError> {
        let head = self.head(head_id)?;
        let fixture_id = fixture_id.into();
        if destination.exists() {
            if destination.read_dir()?.next().is_some() {
                return Err(WorldError::NotDisposable(destination.to_path_buf()));
            }
        } else {
            fs::create_dir_all(destination)?;
        }
        let expected_parent = destination
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let marker = MaterializationMarker {
            schema_version: 1,
            world_head: head_id,
            candidate: CandidateWorldId::new(),
            fixture_id,
            expected_parent: PathBytes::from_path(&expected_parent),
        };
        write_marker(destination, &marker)?;
        let manifest = self.manifest(head.manifest)?;
        if let Err(error) = self.materialize_manifest(&manifest, destination) {
            let _ = fs::remove_dir_all(destination);
            return Err(error);
        }
        self.validate_materialized(&manifest, destination)?;
        sync_directory(destination)?;
        fs::write(destination.join("READY"), b"ready\n")?;
        sync_directory(destination)?;
        self.write_sidecar(marker.candidate, &manifest, destination)?;
        Ok(MaterializedWorld {
            root: destination.to_path_buf(),
            world_head: head_id,
            candidate: marker.candidate,
        })
    }

    pub fn destroy_materialized(&self, destination: &Path) -> Result<(), WorldError> {
        let marker = read_marker(destination)?;
        let expected_parent = marker.expected_parent.as_path();
        let actual_parent = destination.parent().unwrap_or_else(|| Path::new("."));
        if fs::canonicalize(expected_parent).ok() != fs::canonicalize(actual_parent).ok() {
            return Err(WorldError::InvalidMarker);
        }
        fs::remove_dir_all(destination)?;
        Ok(())
    }

    pub fn materialization_marker(
        &self,
        destination: &Path,
    ) -> Result<MaterializationMarker, WorldError> {
        read_marker(destination)
    }

    /// Apply one manifest entry inside a disposable materialization. This is
    /// the narrow mutation primitive used by deterministic recovery; it never
    /// accepts a host path outside the candidate root.
    pub fn write_manifest_entry(
        &self,
        destination: &Path,
        path: &PathBytes,
        entry: &ManifestEntry,
    ) -> Result<(), WorldError> {
        let target = safe_join(destination, path)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        if target.exists() || fs::symlink_metadata(&target).is_ok() {
            remove_path(&target)?;
        }
        match entry.kind {
            ManifestKind::Directory => {
                fs::create_dir_all(&target)?;
                set_mode(&target, entry.mode)?;
            }
            ManifestKind::RegularFile => {
                let blob = entry.content_ref.as_ref().ok_or_else(|| {
                    WorldError::Unsupported("file has no content reference".into())
                })?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)?;
                file.write_all(&self.cas.get_bytes(blob)?)?;
                file.sync_all()?;
                set_mode(&target, entry.mode)?;
            }
            ManifestKind::Symlink => {
                let link = entry
                    .symlink_target
                    .as_ref()
                    .ok_or_else(|| WorldError::Unsupported("symlink has no target".into()))?;
                validate_symlink_target(&link.as_path())?;
                symlink(&link.as_path(), &target)?;
            }
            ManifestKind::Other => {
                return Err(WorldError::Unsupported(
                    "cannot materialize other entry".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn remove_manifest_path(
        &self,
        destination: &Path,
        path: &PathBytes,
    ) -> Result<(), WorldError> {
        let target = safe_join(destination, path)?;
        if fs::symlink_metadata(&target).is_ok() {
            remove_path(&target)?;
        }
        Ok(())
    }

    pub fn validate_materialization(
        &self,
        head: WorldHeadId,
        destination: &Path,
    ) -> Result<(), WorldError> {
        let manifest = self.manifest(self.head(head)?.manifest)?;
        self.validate_materialized(&manifest, destination)
    }

    pub fn commit_workspace(
        &self,
        parent_id: WorldHeadId,
        workspace: &Path,
        actor: impl Into<String>,
        intent: impl Into<String>,
        environment: BTreeMap<String, String>,
    ) -> Result<WorldHead, WorldError> {
        let parent = self.head(parent_id)?;
        let parent_transaction = parent
            .layers
            .last()
            .map(|layer| self.layer(*layer))
            .transpose()?
            .map(|layer| layer.transaction_capsule().id);
        let actor = actor.into();
        let intent = intent.into();
        let mut capsule = TransactionCapsule::new(
            TransactionId::new(),
            parent_transaction,
            ActorIdentity {
                kind: ActorKind::OtherAgent,
                actor_id: actor,
                semantic_session_id: None,
                declared_intent: Some(intent.clone()),
            },
            IntentContract::from_raw(intent),
        );
        capsule.parent_world = Some(controlled_world_reference(parent.id));
        capsule.nondeterminism = nondeterminism_from_environment(&environment);
        capsule.evidence.push(EvidenceRecord {
            class: EvidenceClass::PreservedState,
            subject: "controlled-world-commit".into(),
            evidence_ref: Some(parent.manifest.to_string()),
            detail: Some(
                "Effects are represented by an immutable before/after world layer.".into(),
            ),
        });
        self.commit_workspace_with_capsule(parent_id, workspace, capsule)
    }

    pub fn commit_workspace_with_capsule(
        &self,
        parent_id: WorldHeadId,
        workspace: &Path,
        capsule: TransactionCapsule,
    ) -> Result<WorldHead, WorldError> {
        let parent = self.head(parent_id)?;
        let expected_parent = parent
            .layers
            .last()
            .map(|layer| self.layer(*layer))
            .transpose()?
            .map(|layer| layer.transaction_capsule().id);
        if capsule.parent_id != expected_parent
            || capsule.parent_world.as_ref() != Some(&controlled_world_reference(parent.id))
        {
            return Err(WorldError::CapsuleParentMismatch);
        }
        let parent_manifest = self.manifest(parent.manifest)?;
        let sidecar = read_marker(workspace)
            .ok()
            .and_then(|marker| self.read_sidecar(marker.candidate).ok());
        let result_manifest = self.snapshot_directory_with_sidecar(
            workspace,
            Some(&parent_manifest),
            sidecar.as_ref(),
        )?;
        self.write_manifest(&result_manifest)?;
        let delta = diff_manifests(&parent_manifest, &result_manifest);
        let head_id = WorldHeadId::new();
        let layer = TransactionLayer {
            schema_version: TransactionLayer::SCHEMA_VERSION,
            id: TransactionLayerId::new(),
            parent_head: parent.id,
            result_head: head_id,
            parent_manifest: parent.manifest,
            result_manifest: result_manifest.id,
            capsule: Some(capsule),
            legacy_actor: None,
            legacy_intent: None,
            delta,
            semantic_trace: Vec::new(),
            committed_unix_ms: now_unix_ms(),
            legacy_environment: BTreeMap::new(),
        };
        self.write_json("layers", layer.id.to_string(), &layer)?;
        let mut layers = parent.layers;
        layers.push(layer.id);
        let head = WorldHead {
            id: head_id,
            world_id: parent.world_id,
            base_generation: parent.base_generation,
            manifest: result_manifest.id,
            parent: Some(parent.id),
            layers,
            forked_from: None,
        };
        self.write_json("heads", head.id.to_string(), &head)?;
        Ok(head)
    }

    pub fn snapshot_directory(
        &self,
        root: &Path,
        parent: Option<&WorldManifest>,
    ) -> Result<WorldManifest, WorldError> {
        self.snapshot_directory_with_sidecar(root, parent, None)
    }

    fn snapshot_directory_with_sidecar(
        &self,
        root: &Path,
        parent: Option<&WorldManifest>,
        sidecar: Option<&IdentitySidecar>,
    ) -> Result<WorldManifest, WorldError> {
        let mut entries = BTreeMap::new();
        let mut object_keys = HashMap::<ObjectKey, RealmObjectId>::new();
        let mut used_parent_ids = BTreeSet::new();
        self.scan_directory(
            root,
            root,
            parent,
            sidecar,
            &mut object_keys,
            &mut used_parent_ids,
            &mut entries,
        )?;
        Ok(WorldManifest::new(entries))
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_directory(
        &self,
        root: &Path,
        current: &Path,
        parent: Option<&WorldManifest>,
        sidecar: Option<&IdentitySidecar>,
        object_keys: &mut HashMap<ObjectKey, RealmObjectId>,
        used_parent_ids: &mut BTreeSet<RealmObjectId>,
        entries: &mut BTreeMap<PathBytes, ManifestEntry>,
    ) -> Result<(), WorldError> {
        for directory_entry in fs::read_dir(current)? {
            let directory_entry = directory_entry?;
            let name = directory_entry.file_name();
            if name == "REALM-WORLD-MARKER" || name == "READY" {
                continue;
            }
            let path = directory_entry.path();
            let relative = path.strip_prefix(root).unwrap_or(&path);
            let path_bytes = PathBytes::from_path(relative);
            let metadata = fs::symlink_metadata(&path)?;
            let file_type = metadata.file_type();
            let parent_entry = parent.and_then(|manifest| manifest.entries.get(&path_bytes));
            let key = object_key(&metadata, &file_type);
            let physical = physical_key(&metadata);
            let sidecar_id = sidecar.and_then(|sidecar| sidecar.object_for(&path_bytes, physical));
            let object_id = if let Some(parent_entry) = parent_entry {
                if same_kind(parent_entry.kind, &file_type)
                    && sidecar_id == Some(parent_entry.logical_object_id)
                {
                    used_parent_ids.insert(parent_entry.logical_object_id);
                    parent_entry.logical_object_id
                } else if let Some(sidecar_id) = sidecar_id {
                    object_keys.entry(key).or_default_with_new_from(sidecar_id)
                } else {
                    object_keys.entry(key).or_default_with_new()
                }
            } else if let Some(sidecar_id) = sidecar_id {
                object_keys.entry(key).or_default_with_new_from(sidecar_id)
            } else {
                object_keys.entry(key).or_default_with_new()
            };
            let entry = if file_type.is_dir() {
                ManifestEntry {
                    logical_object_id: object_id,
                    kind: ManifestKind::Directory,
                    content_ref: None,
                    metadata_ref: Some(self.metadata_ref(&metadata)?),
                    link_group: None,
                    mode: mode_of(&metadata),
                    size: 0,
                    symlink_target: None,
                    supported_xattrs: Vec::new(),
                }
            } else if file_type.is_symlink() {
                let target = fs::read_link(&path)?;
                validate_symlink_target(&target)?;
                ManifestEntry {
                    logical_object_id: object_id,
                    kind: ManifestKind::Symlink,
                    content_ref: None,
                    metadata_ref: Some(self.metadata_ref(&metadata)?),
                    link_group: None,
                    mode: mode_of(&metadata),
                    size: 0,
                    symlink_target: Some(PathBytes::from_path(&target)),
                    supported_xattrs: Vec::new(),
                }
            } else if file_type.is_file() {
                let content = self.cas.put_file(&path)?;
                ManifestEntry {
                    logical_object_id: object_id,
                    kind: ManifestKind::RegularFile,
                    content_ref: Some(content),
                    metadata_ref: Some(self.metadata_ref(&metadata)?),
                    link_group: Some(object_id),
                    mode: mode_of(&metadata),
                    size: metadata.len(),
                    symlink_target: None,
                    supported_xattrs: Vec::new(),
                }
            } else {
                ManifestEntry {
                    logical_object_id: object_id,
                    kind: ManifestKind::Other,
                    content_ref: None,
                    metadata_ref: Some(self.metadata_ref(&metadata)?),
                    link_group: None,
                    mode: mode_of(&metadata),
                    size: metadata.len(),
                    symlink_target: None,
                    supported_xattrs: Vec::new(),
                }
            };
            entries.insert(path_bytes, entry);
            if file_type.is_dir() {
                self.scan_directory(
                    root,
                    &path,
                    parent,
                    sidecar,
                    object_keys,
                    used_parent_ids,
                    entries,
                )?;
            }
        }
        Ok(())
    }

    fn metadata_ref(&self, metadata: &fs::Metadata) -> Result<BlobRef, WorldError> {
        let bytes = format!("mode={}\\nsize={}\\n", mode_of(metadata), metadata.len());
        Ok(self.cas.put_bytes(bytes.as_bytes())?)
    }

    fn write_sidecar(
        &self,
        candidate: CandidateWorldId,
        manifest: &WorldManifest,
        root: &Path,
    ) -> Result<(), WorldError> {
        let mut entries = Vec::new();
        for (path, entry) in &manifest.entries {
            let target = safe_join(root, path)?;
            if let Ok(metadata) = fs::symlink_metadata(target) {
                entries.push(SidecarEntry {
                    path: path.clone(),
                    object_id: entry.logical_object_id,
                    physical: physical_key(&metadata),
                });
            }
        }
        self.write_json(
            "sidecars",
            candidate.to_string(),
            &IdentitySidecar { entries },
        )
    }

    fn read_sidecar(&self, candidate: CandidateWorldId) -> Result<IdentitySidecar, WorldError> {
        self.read_json("sidecars", candidate.to_string())?
            .ok_or_else(|| WorldError::Unsupported(format!("missing identity sidecar {candidate}")))
    }

    fn materialize_manifest(
        &self,
        manifest: &WorldManifest,
        destination: &Path,
    ) -> Result<(), WorldError> {
        let mut directories = Vec::new();
        for (path, entry) in &manifest.entries {
            let target = safe_join(destination, path)?;
            match entry.kind {
                ManifestKind::Directory => {
                    fs::create_dir_all(&target)?;
                    directories.push((target, entry.mode));
                }
                ManifestKind::RegularFile => {
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    if let Some(blob) = &entry.content_ref {
                        let bytes = self.cas.get_bytes(blob)?;
                        let mut file = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&target)?;
                        file.write_all(&bytes)?;
                        file.sync_all()?;
                    } else {
                        return Err(WorldError::Unsupported(format!(
                            "file {} has no content",
                            path.display_lossy()
                        )));
                    }
                    set_mode(&target, entry.mode)?;
                }
                ManifestKind::Symlink => {
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let link = entry
                        .symlink_target
                        .as_ref()
                        .ok_or_else(|| WorldError::Unsupported("symlink has no target".into()))?;
                    validate_symlink_target(&link.as_path())?;
                    symlink(&link.as_path(), &target)?;
                }
                ManifestKind::Other => {
                    return Err(WorldError::Unsupported(format!(
                        "cannot materialize other entry {}",
                        path.display_lossy()
                    )));
                }
            }
        }
        let mut first_for_object = BTreeMap::<RealmObjectId, PathBuf>::new();
        for (path, entry) in &manifest.entries {
            if entry.kind != ManifestKind::RegularFile {
                continue;
            }
            let target = safe_join(destination, path)?;
            if let Some(first) = first_for_object.get(&entry.logical_object_id) {
                fs::remove_file(&target)?;
                fs::hard_link(first, &target)?;
            } else {
                first_for_object.insert(entry.logical_object_id, target);
            }
        }
        directories.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
        for (directory, mode) in directories {
            set_mode(&directory, mode)?;
        }
        Ok(())
    }

    fn validate_materialized(
        &self,
        expected: &WorldManifest,
        destination: &Path,
    ) -> Result<(), WorldError> {
        let observed = self.snapshot_directory(destination, None)?;
        if expected.semantic_hash != observed.semantic_hash {
            return Err(WorldError::ManifestMismatch {
                expected: expected.semantic_hash.clone(),
                observed: observed.semantic_hash,
            });
        }
        Ok(())
    }

    fn write_manifest(&self, manifest: &WorldManifest) -> Result<(), WorldError> {
        self.write_json(
            "manifests",
            manifest.id.to_string(),
            &ManifestDisk::from(manifest),
        )
    }

    fn write_json<T: Serialize>(
        &self,
        directory: &str,
        name: String,
        value: &T,
    ) -> Result<(), WorldError> {
        let path = self.root.join(directory).join(format!("{name}.json"));
        atomic_write(&path, &serde_json::to_vec_pretty(value)?)
    }

    fn read_json<T: for<'de> Deserialize<'de>>(
        &self,
        directory: &str,
        name: String,
    ) -> Result<Option<T>, WorldError> {
        let path = self.root.join(directory).join(format!("{name}.json"));
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
struct ObjectKey {
    device: u64,
    inode: u64,
    mode: u32,
}

trait OrNew {
    fn or_default_with_new(self) -> RealmObjectId;
    fn or_default_with_new_from(self, object_id: RealmObjectId) -> RealmObjectId;
}

impl OrNew for std::collections::hash_map::Entry<'_, ObjectKey, RealmObjectId> {
    fn or_default_with_new(self) -> RealmObjectId {
        match self {
            std::collections::hash_map::Entry::Occupied(entry) => *entry.get(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let id = RealmObjectId::new();
                entry.insert(id);
                id
            }
        }
    }

    fn or_default_with_new_from(self, object_id: RealmObjectId) -> RealmObjectId {
        match self {
            std::collections::hash_map::Entry::Occupied(entry) => *entry.get(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(object_id);
                object_id
            }
        }
    }
}

fn object_key(metadata: &fs::Metadata, _file_type: &fs::FileType) -> ObjectKey {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ObjectKey {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = file_type;
        ObjectKey {
            device: 0,
            inode: 0,
            mode: 0,
        }
    }
}

fn physical_key(metadata: &fs::Metadata) -> ObjectKey {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ObjectKey {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        ObjectKey {
            device: 0,
            inode: 0,
            mode: 0,
        }
    }
}

fn same_kind(kind: ManifestKind, file_type: &fs::FileType) -> bool {
    match kind {
        ManifestKind::RegularFile => file_type.is_file(),
        ManifestKind::Directory => file_type.is_dir(),
        ManifestKind::Symlink => file_type.is_symlink(),
        ManifestKind::Other => {
            !file_type.is_file() && !file_type.is_dir() && !file_type.is_symlink()
        }
    }
}

fn diff_manifests(before: &WorldManifest, after: &WorldManifest) -> Vec<DeltaEntry> {
    let paths: BTreeSet<PathBytes> = before
        .entries
        .keys()
        .chain(after.entries.keys())
        .cloned()
        .collect();
    let mut delta = Vec::new();
    for path in paths {
        let old = before.entries.get(&path).cloned();
        let new = after.entries.get(&path).cloned();
        let kind = match (&old, &new) {
            (None, Some(_)) => DeltaKind::Created,
            (Some(_), None) => DeltaKind::Deleted,
            (Some(old), Some(new))
                if old.logical_object_id != new.logical_object_id || old.kind != new.kind =>
            {
                DeltaKind::Replaced
            }
            (Some(old), Some(new))
                if old.content_ref.as_ref().map(|b| &b.hash)
                    != new.content_ref.as_ref().map(|b| &b.hash) =>
            {
                DeltaKind::ContentChanged
            }
            (Some(old), Some(new))
                if old.mode != new.mode || old.symlink_target != new.symlink_target =>
            {
                DeltaKind::MetadataChanged
            }
            _ => continue,
        };
        delta.push(DeltaEntry {
            path,
            kind,
            before: old,
            after: new,
        });
    }
    let deleted: Vec<(PathBytes, RealmObjectId)> = delta
        .iter()
        .filter_map(|entry| {
            (entry.kind == DeltaKind::Deleted)
                .then_some((entry.path.clone(), entry.before.as_ref()?.logical_object_id))
        })
        .collect();
    let created: Vec<(PathBytes, RealmObjectId)> = delta
        .iter()
        .filter_map(|entry| {
            (entry.kind == DeltaKind::Created)
                .then_some((entry.path.clone(), entry.after.as_ref()?.logical_object_id))
        })
        .collect();
    for (path, object_id) in deleted {
        if created.iter().any(|(_, candidate)| *candidate == object_id)
            && let Some(entry) = delta.iter_mut().find(|entry| entry.path == path)
        {
            entry.kind = DeltaKind::Renamed;
        }
    }
    delta.sort_by(|a, b| a.path.cmp(&b.path));
    delta
}

fn hashes_for_entries(entries: &BTreeMap<PathBytes, ManifestEntry>) -> (String, String) {
    // The world root is a state hash, not a hash of random Realm object IDs.
    // Logical identity remains in the manifest and sidecar; excluding its
    // UUIDs makes repeated scans of the same supported state deterministic.
    let canonical = canonical_entries(entries, false);
    let semantic = canonical_entries(entries, false);
    (
        blake3::hash(&canonical).to_hex().to_string(),
        blake3::hash(&semantic).to_hex().to_string(),
    )
}

fn nondeterminism_from_environment(
    environment: &BTreeMap<String, String>,
) -> NondeterminismCapsule {
    let encoded = serde_json::to_vec(environment).unwrap_or_default();
    let environment_fingerprint =
        (!environment.is_empty()).then(|| blake3::hash(&encoded).to_hex().to_string());
    NondeterminismCapsule {
        schema_version: NondeterminismCapsule::SCHEMA_VERSION,
        environment_fingerprint,
        inputs: if environment.is_empty() {
            Vec::new()
        } else {
            vec![NondeterministicInput {
                kind: NondeterminismKind::Environment,
                label: "declared-environment".into(),
                fidelity: InputFidelity::CapturedDigest,
                evidence_ref: None,
            }]
        },
        unresolved: vec![KnownUnknown {
            code: UnknownReasonCode::ReplayNondeterminism,
            detail: "Environment values are fingerprinted, not retained as replay inputs.".into(),
            evidence_ref: None,
        }],
    }
}

fn controlled_world_reference(head: WorldHeadId) -> WorldReference {
    WorldReference::new("realm-controlled-world-head", head.to_string())
}

fn canonical_entries(
    entries: &BTreeMap<PathBytes, ManifestEntry>,
    include_identity: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for (path, entry) in entries {
        encode_bytes(&path.0, &mut out);
        entry.canonical_bytes(include_identity, &mut out);
    }
    out
}

fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn encode_optional_path(path: &Option<PathBytes>, out: &mut Vec<u8>) {
    match path {
        Some(path) => {
            out.push(1);
            encode_bytes(&path.0, out);
        }
        None => out.push(0),
    }
}

fn encode_optional_blob(blob: &Option<BlobRef>, out: &mut Vec<u8>) {
    match blob {
        Some(blob) => {
            out.push(1);
            encode_bytes(blob.hash.as_bytes(), out);
            out.extend_from_slice(&blob.size.to_le_bytes());
        }
        None => out.push(0),
    }
}

fn write_marker(root: &Path, marker: &MaterializationMarker) -> Result<(), WorldError> {
    atomic_write(
        &root.join("REALM-WORLD-MARKER"),
        &serde_json::to_vec_pretty(marker)?,
    )
}

fn read_marker(root: &Path) -> Result<MaterializationMarker, WorldError> {
    let path = root.join("REALM-WORLD-MARKER");
    if !path.exists() {
        return Err(WorldError::InvalidMarker);
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn safe_join(root: &Path, relative: &PathBytes) -> Result<PathBuf, WorldError> {
    let path = relative.as_path();
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(WorldError::Unsupported(format!(
            "unsafe relative path {}",
            relative.display_lossy()
        )));
    }
    Ok(root.join(path))
}

fn remove_path(path: &Path) -> Result<(), WorldError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn validate_symlink_target(target: &Path) -> Result<(), WorldError> {
    if target.is_absolute() {
        return Err(WorldError::EscapingSymlink(
            target.to_string_lossy().into_owned(),
        ));
    }
    let mut depth = 0i32;
    for component in target.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return Err(WorldError::EscapingSymlink(
                        target.to_string_lossy().into_owned(),
                    ));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(WorldError::EscapingSymlink(
                    target.to_string_lossy().into_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn mode_of(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.mode()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0o644
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<(), WorldError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

#[cfg(unix)]
fn symlink(target: &Path, destination: &Path) -> Result<(), WorldError> {
    std::os::unix::fs::symlink(target, destination)?;
    Ok(())
}

#[cfg(not(unix))]
fn symlink(_target: &Path, _destination: &Path) -> Result<(), WorldError> {
    Err(WorldError::Unsupported(
        "symlinks are unsupported on this platform".into(),
    ))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), WorldError> {
    let temp = path.with_extension(format!("tmp-{}", unique_suffix()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temp, path)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), WorldError> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn unique_suffix() -> String {
    format!("{}-{}", std::process::id(), now_unix_ms())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("realm-world-{name}-{}", unique_suffix()))
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let root = temp("hash");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a.txt"), b"a").unwrap();
        let store = WorldStore::open(temp("hash-store")).unwrap();
        let first = store.snapshot_directory(&root, None).unwrap();
        let second = store.snapshot_directory(&root, Some(&first)).unwrap();
        assert_eq!(first.semantic_hash, second.semantic_hash);
        assert_eq!(first.root_hash, second.root_hash);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(store.root()).unwrap();
    }

    #[test]
    fn materialize_round_trips_hardlink_and_symlink() {
        let root = temp("roundtrip");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("a"), b"same").unwrap();
        fs::hard_link(source.join("a"), source.join("b")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("a", source.join("link")).unwrap();
        let store = WorldStore::open(temp("roundtrip-store")).unwrap();
        let head = store.import("fixture", &source).unwrap();
        let candidate = root.join("candidate");
        let materialized = store.materialize(head.id, &candidate, "fixture").unwrap();
        assert!(candidate.join("READY").exists());
        assert_eq!(fs::read(candidate.join("a")).unwrap(), b"same");
        #[cfg(unix)]
        assert_eq!(
            fs::read_link(candidate.join("link")).unwrap(),
            PathBuf::from("a")
        );
        store.destroy_materialized(&materialized.root).unwrap();
        assert!(!candidate.exists());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(store.root()).unwrap();
    }

    #[test]
    fn path_reuse_gets_a_new_logical_object_id() {
        let root = temp("path-reuse");
        let source = root.join("source");
        let store_root = temp("path-reuse-store");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("reused.txt"), b"first").unwrap();
        let store = WorldStore::open(&store_root).unwrap();
        let base = store.import("fixture", &source).unwrap();
        let workspace = root.join("candidate");
        let materialized = store.materialize(base.id, &workspace, "fixture").unwrap();
        // Keep the replacement inode allocated while the original still
        // exists. Otherwise filesystems such as ext4 may immediately reuse
        // the just-freed inode, making a final-state snapshot unable to
        // distinguish delete-and-recreate from an in-place write.
        let replacement = workspace.join("replacement.txt");
        fs::write(&replacement, b"second").unwrap();
        fs::rename(replacement, workspace.join("reused.txt")).unwrap();
        let next = store
            .commit_workspace(base.id, &workspace, "test", "replace path", BTreeMap::new())
            .unwrap();
        let before = store.manifest(base.manifest).unwrap();
        let after = store.manifest(next.manifest).unwrap();
        assert_ne!(
            before.entries[&PathBytes(b"reused.txt".to_vec())].logical_object_id,
            after.entries[&PathBytes(b"reused.txt".to_vec())].logical_object_id
        );
        store.destroy_materialized(&materialized.root).unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(store_root).unwrap();
    }

    #[test]
    fn randomized_supported_states_round_trip() {
        let root = temp("randomized");
        let source = root.join("source");
        let store_root = temp("randomized-store");
        fs::create_dir_all(&source).unwrap();
        let store = WorldStore::open(&store_root).unwrap();
        for case in 0..32u32 {
            let path = source.join(format!("file-{case}.txt"));
            fs::write(&path, format!("base-{case}\n")).unwrap();
            let base = store.import(format!("fixture-{case}"), &source).unwrap();
            let candidate = root.join(format!("candidate-{case}"));
            let materialized = store.materialize(base.id, &candidate, "fixture").unwrap();
            if case % 3 == 0 {
                fs::write(&path, format!("host-{case}\n")).unwrap();
            }
            fs::write(
                candidate.join(format!("file-{case}.txt")),
                format!("candidate-{case}\n"),
            )
            .unwrap();
            let next = store
                .commit_workspace(
                    base.id,
                    &candidate,
                    "test",
                    "randomized state",
                    BTreeMap::new(),
                )
                .unwrap();
            let roundtrip = root.join(format!("roundtrip-{case}"));
            let rematerialized = store.materialize(next.id, &roundtrip, "fixture").unwrap();
            assert_eq!(
                store
                    .snapshot_directory(&roundtrip, None)
                    .unwrap()
                    .semantic_hash,
                store.manifest(next.manifest).unwrap().semantic_hash
            );
            store.destroy_materialized(&materialized.root).unwrap();
            store.destroy_materialized(&rematerialized.root).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(store_root).unwrap();
    }

    #[test]
    fn v1_layer_is_read_as_a_v2_capsule_without_rewriting_forensic_bytes() {
        let store_root = temp("layer-migration-store");
        let store = WorldStore::open(&store_root).unwrap();
        let id = TransactionLayerId::new();
        let legacy = serde_json::json!({
            "id": id,
            "parent_head": WorldHeadId::new(),
            "result_head": WorldHeadId::new(),
            "parent_manifest": WorldManifestId::new(),
            "result_manifest": WorldManifestId::new(),
            "actor": "legacy-agent",
            "intent": "repair auth",
            "delta": [],
            "semantic_trace": [],
            "committed_unix_ms": 1,
            "environment": {"SECRET_TOKEN": "must-not-be-reserialized"}
        });
        let path = store_root.join("layers").join(format!("{id}.json"));
        fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
        let forensic_before = fs::read(&path).unwrap();
        let layer = store.layer(id).unwrap();
        assert_eq!(layer.schema_version, TransactionLayer::SCHEMA_VERSION);
        let capsule = layer.transaction_capsule();
        assert_eq!(capsule.id, TransactionId(id.0));
        assert_eq!(capsule.actor.actor_id, "legacy-agent");
        assert_eq!(capsule.intent.raw_intent, "repair auth");
        assert!(capsule.nondeterminism.environment_fingerprint.is_some());
        let upgraded = serde_json::to_string(&layer).unwrap();
        assert!(upgraded.contains("capsule"));
        assert!(!upgraded.contains("must-not-be-reserialized"));
        assert_eq!(fs::read(path).unwrap(), forensic_before);
        fs::remove_dir_all(store_root).unwrap();
    }

    #[test]
    fn escaping_symlink_is_rejected() {
        assert!(validate_symlink_target(Path::new("../../outside")).is_err());
        assert!(validate_symlink_target(Path::new("/outside")).is_err());
    }
}
