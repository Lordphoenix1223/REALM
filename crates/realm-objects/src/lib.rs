//! Object identity and path lineage.
//!
//! Paths are aliases whose validity changes over time. They are never used as
//! the object identity themselves.

use realm_core::{ObjectId, ObjectIdentity, ObjectKind, PathBytes};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PlatformObjectKey {
    pub volume_identity: Vec<u8>,
    pub file_id: Vec<u8>,
    pub generation: Option<Vec<u8>>,
    pub kind: ObjectKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PathRelationKind {
    Primary,
    Hardlink,
    Symlink,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathRelation {
    pub path: PathBytes,
    pub object_id: ObjectId,
    pub relation: PathRelationKind,
    pub valid_from_sequence: u64,
    pub valid_until_sequence: Option<u64>,
}

#[derive(Debug, Error)]
pub enum ObjectError {
    #[error("path is not currently linked to an object: {0}")]
    UnknownPath(String),
    #[error("object key is already active at another path")]
    AmbiguousKey,
}

#[derive(Default)]
pub struct ObjectRegistry {
    objects: BTreeMap<ObjectId, ObjectIdentity>,
    key_to_object: BTreeMap<PlatformObjectKey, ObjectId>,
    retired_keys: BTreeSet<PlatformObjectKey>,
    active_paths: BTreeMap<PathBytes, ObjectId>,
    history: Vec<PathRelation>,
}

impl ObjectRegistry {
    pub fn observe_create(
        &mut self,
        path: PathBytes,
        key: PlatformObjectKey,
        sequence: u64,
    ) -> ObjectId {
        let object_id = if !self.retired_keys.contains(&key) {
            self.key_to_object
                .get(&key)
                .copied()
                .unwrap_or_else(|| self.new_object(&key))
        } else {
            self.new_object(&key)
        };
        self.bind(path, object_id, PathRelationKind::Primary, sequence);
        object_id
    }

    pub fn observe_symlink(
        &mut self,
        path: PathBytes,
        key: PlatformObjectKey,
        sequence: u64,
        target: PathBytes,
    ) -> ObjectId {
        let object_id = self.observe_create(
            path,
            PlatformObjectKey {
                kind: ObjectKind::Symlink,
                ..key
            },
            sequence,
        );
        if let Some(identity) = self.objects.get_mut(&object_id) {
            identity.generation = Some(target.0);
        }
        object_id
    }

    pub fn rename(
        &mut self,
        from: &PathBytes,
        to: PathBytes,
        sequence: u64,
    ) -> Result<ObjectId, ObjectError> {
        let object_id = self
            .active_paths
            .remove(from)
            .ok_or_else(|| ObjectError::UnknownPath(from.display_lossy()))?;
        self.close_relation(from, sequence);
        self.bind(to, object_id, PathRelationKind::Primary, sequence);
        Ok(object_id)
    }

    pub fn link(
        &mut self,
        existing: &PathBytes,
        new_path: PathBytes,
        sequence: u64,
    ) -> Result<ObjectId, ObjectError> {
        let object_id = self
            .active_paths
            .get(existing)
            .copied()
            .ok_or_else(|| ObjectError::UnknownPath(existing.display_lossy()))?;
        self.bind(new_path, object_id, PathRelationKind::Hardlink, sequence);
        Ok(object_id)
    }

    pub fn unlink(&mut self, path: &PathBytes, sequence: u64) -> Result<ObjectId, ObjectError> {
        let object_id = self
            .active_paths
            .remove(path)
            .ok_or_else(|| ObjectError::UnknownPath(path.display_lossy()))?;
        self.close_relation(path, sequence);
        if !self.active_paths.values().any(|value| *value == object_id)
            && let Some(key) = self
                .key_to_object
                .iter()
                .find_map(|(key, value)| (*value == object_id).then_some(key.clone()))
        {
            self.retired_keys.insert(key);
        }
        Ok(object_id)
    }

    pub fn object_at_path(&self, path: &PathBytes) -> Option<ObjectId> {
        self.active_paths.get(path).copied()
    }
    pub fn object(&self, id: ObjectId) -> Option<&ObjectIdentity> {
        self.objects.get(&id)
    }
    pub fn path_history(&self, path: &PathBytes) -> Vec<PathRelation> {
        self.history
            .iter()
            .filter(|relation| &relation.path == path)
            .cloned()
            .collect()
    }
    pub fn all_history(&self) -> &[PathRelation] {
        &self.history
    }

    fn new_object(&mut self, key: &PlatformObjectKey) -> ObjectId {
        let id = ObjectId::new();
        self.objects.insert(
            id,
            ObjectIdentity {
                id,
                volume_identity: Some(key.volume_identity.clone()),
                platform_file_id: Some(key.file_id.clone()),
                generation: key.generation.clone(),
                first_seen_generation: Uuid::new_v4(),
                kind: key.kind,
            },
        );
        self.key_to_object.insert(key.clone(), id);
        id
    }

    fn bind(
        &mut self,
        path: PathBytes,
        object_id: ObjectId,
        relation: PathRelationKind,
        sequence: u64,
    ) {
        if self.active_paths.contains_key(&path) {
            self.close_relation(&path, sequence);
        }
        self.active_paths.insert(path.clone(), object_id);
        self.history.push(PathRelation {
            path,
            object_id,
            relation,
            valid_from_sequence: sequence,
            valid_until_sequence: None,
        });
    }

    fn close_relation(&mut self, path: &PathBytes, sequence: u64) {
        if let Some(relation) = self
            .history
            .iter_mut()
            .rev()
            .find(|relation| &relation.path == path && relation.valid_until_sequence.is_none())
        {
            relation.valid_until_sequence = Some(sequence);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: u8) -> PlatformObjectKey {
        PlatformObjectKey {
            volume_identity: vec![1],
            file_id: vec![id],
            generation: Some(vec![id]),
            kind: ObjectKind::RegularFile,
        }
    }

    #[test]
    fn path_reuse_creates_distinct_objects() {
        let mut registry = ObjectRegistry::default();
        let path = PathBytes(b"a".to_vec());
        let first = registry.observe_create(path.clone(), key(1), 1);
        registry.unlink(&path, 2).unwrap();
        let second = registry.observe_create(path.clone(), key(2), 3);
        assert_ne!(first, second);
        assert_eq!(registry.path_history(&path).len(), 2);
    }

    #[test]
    fn hardlinks_share_object_identity_but_symlink_does_not() {
        let mut registry = ObjectRegistry::default();
        let a = PathBytes(b"a".to_vec());
        let b = PathBytes(b"b".to_vec());
        let link = PathBytes(b"link".to_vec());
        let object = registry.observe_create(a.clone(), key(1), 1);
        assert_eq!(registry.link(&a, b.clone(), 2).unwrap(), object);
        let symlink = registry.observe_symlink(link, key(2), 3, a.clone());
        assert_ne!(object, symlink);
        assert_eq!(registry.object_at_path(&b), Some(object));
    }
}
