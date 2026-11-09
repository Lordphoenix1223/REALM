//! Portable REALM execution identity and an outer, non-authoritative envelope.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::Path,
};
use thiserror::Error;

pub const SCHEMA_VERSION: u16 = 3;
const MAGIC: &[u8] = b"REALM-PORTABLE-3\n";
pub mod host_apply;
pub mod inspection;
pub mod lifecycle;
pub mod observations;
pub mod receipt;
pub mod v6;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmRun {
    pub schema_version: u16,
    pub lifecycle: Lifecycle,
    pub run: RunIdentity,
    pub challenge: Challenge,
    pub intent: Commitment,
    pub starting_state: Commitment,
    pub environment: EnvironmentIdentity,
    pub effect_contract: Commitment,
    #[serde(default)]
    pub inputs: Vec<BlobRef>,
    #[serde(default)]
    pub outputs: Vec<BlobRef>,
    #[serde(default)]
    pub checkpoints: Vec<Checkpoint>,
    #[serde(default)]
    pub observations: Vec<ObservedEvent>,
    #[serde(default)]
    pub proposed_effects: Vec<ProposedEffect>,
    #[serde(default)]
    pub unknown_effects: Vec<UnknownEffect>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
    #[serde(default)]
    pub claims: Vec<Claim>,
    #[serde(default)]
    pub final_state: Option<Commitment>,
    pub seal: Option<Seal>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    #[serde(default)]
    pub attestations: Vec<Attestation>,
    #[serde(default)]
    pub verification: Vec<VerificationRef>,
    #[serde(default)]
    pub publication: PublicationMetadata,
    #[serde(default)]
    pub content: ContentMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Created,
    Executing,
    Checkpointed,
    Frozen,
    Sealed,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub nonce: Option<Digest>,
    pub issued_by: String,
    pub expires_at: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Digest {
    pub algorithm: String,
    pub domain: String,
    pub value: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunIdentity {
    pub run_id: String,
    pub execution_id: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commitment {
    pub identity: String,
    pub digest: Digest,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentIdentity {
    pub runtime: String,
    pub runtime_digest: Digest,
    pub backend: String,
    pub architecture: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRef {
    pub digest: Digest,
    pub size: u64,
    pub media_type: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub id: String,
    pub sequence: u64,
    pub parent: Option<String>,
    pub state: Commitment,
    #[serde(default)]
    pub evidence: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedEvent {
    pub id: String,
    pub kind: String,
    pub target: String,
    pub checkpoint: Option<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedEffect {
    pub id: String,
    pub kind: String,
    pub target: String,
    pub before: Option<Digest>,
    pub after: Option<Digest>,
    pub checkpoint: Option<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownEffect {
    pub kind: String,
    pub target: Option<String>,
    pub reason: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub id: String,
    pub evidence_type: String,
    pub digest: Digest,
    #[serde(default)]
    pub size: Option<u64>,
    pub run_id: String,
    pub checkpoint: Option<String>,
    #[serde(default)]
    pub supports: Vec<String>,
    pub authoritative: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    Agent,
    Observed,
    Proposed,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub id: String,
    pub kind: ClaimKind,
    pub statement: Digest,
    pub run_id: String,
    pub checkpoint: Option<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationDecision {
    Accept,
    Reject,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRef {
    pub id: String,
    pub verifier: String,
    pub result_digest: Digest,
    pub decision: VerificationDecision,
    pub run_id: String,
    pub checkpoint: Option<String>,
    #[serde(default)]
    pub supports: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub id: String,
    pub kind: String,
    pub signer: String,
    pub signed_root: Digest,
    pub signature: BlobRef,
    pub run_id: String,
    pub key_hint: Option<String>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationMetadata {
    pub status: PublicationStatus,
    pub reference: Option<String>,
    pub policy_identity: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<v6::GenerationPublicationEvidence>,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationStatus {
    #[default]
    None,
    Proposed,
    Published,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentMode {
    #[default]
    Portable,
    Thin,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seal {
    pub root: Digest,
    pub lifecycle: Lifecycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationLevel {
    Parsing,
    Integrity,
    ContentComplete,
    AttestationShape,
    ExternalPolicy,
}
pub trait ContentResolver {
    fn resolve(&self, digest: &Digest) -> Result<Option<Vec<u8>>, ArtifactError>;
}
#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid artifact: {0}")]
    Invalid(String),
    #[error("missing blob {0}")]
    MissingBlob(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactBundle {
    pub run: RealmRun,
    pub envelope: Envelope,
    pub blobs: BTreeMap<String, Vec<u8>>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedRealmRun {
    run: RealmRun,
    identity: Digest,
}
impl SealedRealmRun {
    pub fn identity(&self) -> &Digest {
        &self.identity
    }
    pub fn run(&self) -> &RealmRun {
        &self.run
    }
}
impl ArtifactBundle {
    pub fn new(run: RealmRun) -> Self {
        Self {
            run,
            envelope: Envelope::default(),
            blobs: BTreeMap::new(),
        }
    }
    pub fn add_blob(&mut self, bytes: Vec<u8>, media_type: impl Into<String>) -> BlobRef {
        let d = hash("realm.blob", &bytes);
        self.blobs.insert(d.value.clone(), bytes.clone());
        BlobRef {
            digest: d,
            size: bytes.len() as u64,
            media_type: media_type.into(),
        }
    }
    pub fn semantic_identity(&self) -> Result<Digest, ArtifactError> {
        self.validate_at(ValidationLevel::Integrity)?;
        Ok(hash("realm.run", &canonical_json(&self.run)?))
    }
    pub fn transport_identity(&self) -> Result<Digest, ArtifactError> {
        self.validate_at(ValidationLevel::Integrity)?;
        Ok(hash("realm.transport", &self.pack()?))
    }
    pub fn identity(&self) -> Result<Digest, ArtifactError> {
        self.semantic_identity()
    }
    pub fn sealed_run(&self) -> Result<SealedRealmRun, ArtifactError> {
        if self.run.lifecycle != Lifecycle::Sealed {
            return Err(ArtifactError::Invalid("run is not sealed".into()));
        }
        self.validate_at(ValidationLevel::AttestationShape)?;
        Ok(SealedRealmRun {
            run: self.run.clone(),
            identity: self.semantic_identity()?,
        })
    }
    pub fn validate(&self) -> Result<(), ArtifactError> {
        self.validate_at(ValidationLevel::Integrity)
    }
    pub fn validate_at(&self, level: ValidationLevel) -> Result<(), ArtifactError> {
        self.validate_with_resolver(level, None)
    }
    pub fn validate_with_resolver(
        &self,
        level: ValidationLevel,
        resolver: Option<&dyn ContentResolver>,
    ) -> Result<(), ArtifactError> {
        let r = &self.run;
        if r.schema_version != SCHEMA_VERSION {
            return Err(ArtifactError::Invalid("unsupported schema".into()));
        }
        if r.run.run_id.is_empty()
            || r.run.execution_id.is_empty()
            || r.challenge.issued_by.is_empty()
            || r.challenge.nonce.as_ref().is_some_and(|x| !is_digest(x))
        {
            return Err(ArtifactError::Invalid(
                "invalid run/challenge identity".into(),
            ));
        }
        for c in [&r.intent, &r.starting_state, &r.effect_contract] {
            validate_commitment(c)?;
        }
        validate_commitment(&Commitment {
            identity: r.environment.runtime.clone(),
            digest: r.environment.runtime_digest.clone(),
        })?;
        let cps: BTreeSet<_> = r.checkpoints.iter().map(|x| x.id.as_str()).collect();
        if cps.len() != r.checkpoints.len() {
            return Err(ArtifactError::Invalid("duplicate checkpoint".into()));
        }
        let mut sequences = BTreeSet::new();
        if r.checkpoints.iter().any(|x| !sequences.insert(x.sequence)) {
            return Err(ArtifactError::Invalid(
                "duplicate checkpoint sequence".into(),
            ));
        }
        for c in &r.checkpoints {
            validate_commitment(&c.state)?;
            if c.parent
                .as_ref()
                .is_some_and(|p| p == &c.id || !cps.contains(p.as_str()))
            {
                return Err(ArtifactError::Invalid("missing checkpoint parent".into()));
            }
            if let Some(parent) = c.parent.as_ref() {
                let p = r.checkpoints.iter().find(|x| &x.id == parent).unwrap();
                if p.sequence >= c.sequence {
                    return Err(ArtifactError::Invalid("checkpoint sequence order".into()));
                }
            }
            if c.evidence.iter().any(|e| {
                !r.evidence
                    .iter()
                    .any(|x| x.id == *e && x.checkpoint.as_deref() == Some(c.id.as_str()))
            }) {
                return Err(ArtifactError::Invalid(
                    "checkpoint evidence mismatch".into(),
                ));
            }
            for c in &r.checkpoints {
                let mut seen = BTreeSet::new();
                let mut current = Some(c.id.as_str());
                while let Some(id) = current {
                    if !seen.insert(id) {
                        return Err(ArtifactError::Invalid("checkpoint cycle".into()));
                    }
                    current = r
                        .checkpoints
                        .iter()
                        .find(|x| x.id == id)
                        .and_then(|x| x.parent.as_deref());
                }
            }
        }
        if r.lifecycle == Lifecycle::Checkpointed && r.checkpoints.is_empty() {
            return Err(ArtifactError::Invalid(
                "checkpointed state needs checkpoint".into(),
            ));
        }
        if r.lifecycle == Lifecycle::Frozen && r.final_state.is_none() {
            return Err(ArtifactError::Invalid(
                "frozen state needs final world".into(),
            ));
        }
        if r.lifecycle == Lifecycle::Sealed && r.seal.is_none() {
            return Err(ArtifactError::Invalid("sealed state needs seal".into()));
        }
        if r.lifecycle == Lifecycle::Sealed
            && r.seal
                .as_ref()
                .is_some_and(|s| s.lifecycle != Lifecycle::Sealed)
        {
            return Err(ArtifactError::Invalid("seal downgrade".into()));
        }
        if let Some(seal) = &r.seal {
            let mut unsigned = r.clone();
            unsigned.seal = None;
            if seal.root != hash("realm.seal", &canonical_json(&unsigned)?) {
                return Err(ArtifactError::Invalid("seal root mismatch".into()));
            }
        }
        let ids: BTreeSet<_> = r.evidence.iter().map(|e| e.id.as_str()).collect();
        if ids.len() != r.evidence.len() {
            return Err(ArtifactError::Invalid("duplicate evidence".into()));
        }
        let mut object_ids = BTreeSet::new();
        for id in r
            .claims
            .iter()
            .map(|x| &x.id)
            .chain(r.observations.iter().map(|x| &x.id))
            .chain(r.proposed_effects.iter().map(|x| &x.id))
        {
            if !object_ids.insert(id.as_str()) {
                return Err(ArtifactError::Invalid("duplicate semantic object".into()));
            }
        }
        for e in &r.evidence {
            if e.run_id != r.run.run_id
                || !is_digest(&e.digest)
                || e.checkpoint
                    .as_ref()
                    .is_some_and(|c| !cps.contains(c.as_str()))
                || e.supports.iter().any(|x| {
                    !target_exists(r, x) || target_checkpoint(r, x) != e.checkpoint.as_deref()
                })
            {
                return Err(ArtifactError::Invalid("evidence binding mismatch".into()));
            }
        }
        for c in &r.claims {
            if c.run_id != r.run.run_id
                || !is_digest(&c.statement)
                || c.checkpoint
                    .as_ref()
                    .is_some_and(|x| !cps.contains(x.as_str()))
                || c.evidence
                    .iter()
                    .any(|e| !evidence_matches_scope(r, e, c.checkpoint.as_deref()))
            {
                return Err(ArtifactError::Invalid("claim binding mismatch".into()));
            }
        }
        for x in &r.observations {
            if x.checkpoint
                .as_ref()
                .is_some_and(|c| !cps.contains(c.as_str()))
                || x.evidence
                    .iter()
                    .any(|e| !evidence_matches_scope(r, e, x.checkpoint.as_deref()))
            {
                return Err(ArtifactError::Invalid(
                    "observation/effect binding mismatch".into(),
                ));
            }
        }
        for x in &r.proposed_effects {
            if x.checkpoint
                .as_ref()
                .is_some_and(|c| !cps.contains(c.as_str()))
                || x.evidence
                    .iter()
                    .any(|e| !evidence_matches_scope(r, e, x.checkpoint.as_deref()))
            {
                return Err(ArtifactError::Invalid(
                    "observation/effect binding mismatch".into(),
                ));
            }
        }
        for x in r
            .inputs
            .iter()
            .chain(r.outputs.iter())
            .chain(self.envelope.attestations.iter().map(|a| &a.signature))
        {
            if !is_digest(&x.digest) {
                return Err(ArtifactError::Invalid("invalid blob digest".into()));
            }
            validate_blob_ref(x, &self.blobs, self.envelope.content, level, resolver)?;
        }
        for e in &r.evidence {
            validate_evidence_ref(e, &self.blobs, self.envelope.content, level, resolver)?;
        }
        if let Some(publication) = &self.envelope.publication.generation {
            validate_blob_ref(
                &publication.receipt_blob,
                &self.blobs,
                self.envelope.content,
                level,
                resolver,
            )?;
            validate_blob_ref(
                &publication.journal_record_blob,
                &self.blobs,
                self.envelope.content,
                level,
                resolver,
            )?;
        }
        for v in &self.envelope.verification {
            if v.run_id != r.run.run_id
                || !is_digest(&v.result_digest)
                || v.supports.iter().any(|x| !target_exists(r, x))
            {
                return Err(ArtifactError::Invalid(
                    "verification binding mismatch".into(),
                ));
            }
        }
        let semantic_root = hash("realm.run", &canonical_json(r)?);
        v6::validate_v6_evidence(self, &semantic_root, level, resolver)?;
        for a in &self.envelope.attestations {
            if r.lifecycle != Lifecycle::Sealed
                || a.run_id != r.run.run_id
                || a.signed_root != semantic_root
            {
                return Err(ArtifactError::Invalid(
                    "attestation does not bind sealed run".into(),
                ));
            }
        }
        if level == ValidationLevel::ContentComplete && self.envelope.content == ContentMode::Thin {
            for x in r.inputs.iter().chain(r.outputs.iter()) {
                validate_blob_ref(x, &self.blobs, self.envelope.content, level, resolver)?;
            }
        }
        Ok(())
    }
    pub fn seal(&mut self) -> Result<Digest, ArtifactError> {
        self.validate_at(ValidationLevel::Integrity)?;
        if self.run.lifecycle == Lifecycle::Sealed {
            return self
                .run
                .seal
                .as_ref()
                .map(|x| x.root.clone())
                .ok_or_else(|| ArtifactError::Invalid("missing seal".into()));
        }
        if self.run.lifecycle != Lifecycle::Frozen {
            return Err(ArtifactError::Invalid("only frozen runs may seal".into()));
        }
        self.run.lifecycle = Lifecycle::Sealed;
        let mut unsigned = self.run.clone();
        unsigned.seal = None;
        let root = hash("realm.seal", &canonical_json(&unsigned)?);
        self.run.seal = Some(Seal {
            root: root.clone(),
            lifecycle: Lifecycle::Sealed,
        });
        Ok(root)
    }
    pub fn transition(&mut self, next: Lifecycle) -> Result<(), ArtifactError> {
        let legal = matches!(
            (self.run.lifecycle, next),
            (Lifecycle::Created, Lifecycle::Executing)
                | (Lifecycle::Executing, Lifecycle::Checkpointed)
                | (Lifecycle::Executing, Lifecycle::Frozen)
                | (Lifecycle::Checkpointed, Lifecycle::Executing)
                | (Lifecycle::Checkpointed, Lifecycle::Frozen)
        );
        if !legal {
            return Err(ArtifactError::Invalid(
                "illegal lifecycle transition".into(),
            ));
        }
        self.run.lifecycle = next;
        Ok(())
    }
    pub fn is_authorizing(&self) -> bool {
        false
    }
    pub fn pack(&self) -> Result<Vec<u8>, ArtifactError> {
        self.validate_at(ValidationLevel::Integrity)?;
        let mut o = MAGIC.to_vec();
        put(&mut o, &canonical_json(&(&self.run, &self.envelope))?);
        o.extend_from_slice(&(self.blobs.len() as u32).to_be_bytes());
        for (k, v) in &self.blobs {
            put(&mut o, k.as_bytes());
            put(&mut o, v);
        }
        Ok(o)
    }
    pub fn unpack(i: &[u8]) -> Result<Self, ArtifactError> {
        let mut c = Cursor { b: i, p: 0 };
        if c.take(MAGIC.len())? != MAGIC {
            return Err(ArtifactError::Invalid("bad magic".into()));
        }
        let (run, envelope): (RealmRun, Envelope) = serde_json::from_slice(c.frame()?)?;
        let n = u32::from_be_bytes(c.take(4)?.try_into().unwrap());
        let mut blobs = BTreeMap::new();
        for _ in 0..n {
            let k = String::from_utf8(c.frame()?.to_vec())
                .map_err(|_| ArtifactError::Invalid("non-UTF8 key".into()))?;
            if blobs.insert(k, c.frame()?.to_vec()).is_some() {
                return Err(ArtifactError::Invalid("duplicate blob".into()));
            }
        }
        if c.p != i.len() {
            return Err(ArtifactError::Invalid("trailing bytes".into()));
        }
        let x = Self {
            run,
            envelope,
            blobs,
        };
        x.validate()?;
        Ok(x)
    }
    pub fn write(&self, p: impl AsRef<Path>) -> Result<(), ArtifactError> {
        fs::write(p, self.pack()?)?;
        Ok(())
    }
    pub fn open(p: impl AsRef<Path>) -> Result<Self, ArtifactError> {
        Self::unpack(&fs::read(p)?)
    }
    pub fn inspect(&self) -> Result<String, ArtifactError> {
        self.validate()?;
        Ok(format!(
            "REALM run {}\nsemantic identity: {}\ntransport identity: {}\nlifecycle: {:?}\nchallenge: {}\ncheckpoints: {}\nobservations: {}\nproposed effects: {}\nevidence: {}\nverifier attestations: {}\ncontent: {:?}\nauthority: external only",
            self.run.run.run_id,
            self.semantic_identity()?.value,
            self.transport_identity()?.value,
            self.run.lifecycle,
            self.run
                .challenge
                .nonce
                .as_ref()
                .map(|x| x.value.as_str())
                .unwrap_or("<not supplied>"),
            self.run.checkpoints.len(),
            self.run.observations.len(),
            self.run.proposed_effects.len(),
            self.run.evidence.len(),
            self.envelope.verification.len(),
            self.envelope.content
        ))
    }
    pub fn diff(&self, other: &Self) -> Result<String, ArtifactError> {
        self.validate()?;
        other.validate()?;
        let mut changes = Vec::new();
        if self.semantic_identity()? != other.semantic_identity()? {
            changes.push("semantic run identity changed");
        }
        if self.envelope != other.envelope {
            changes.push("outer envelope changed");
        }
        if changes.is_empty() {
            changes.push("no committed changes");
        }
        Ok(changes.join("\n"))
    }
}

fn target_exists(r: &RealmRun, id: &str) -> bool {
    r.claims.iter().any(|x| x.id == id)
        || r.observations.iter().any(|x| x.id == id)
        || r.proposed_effects.iter().any(|x| x.id == id)
}
fn evidence_matches_scope(r: &RealmRun, id: &str, checkpoint: Option<&str>) -> bool {
    r.evidence
        .iter()
        .any(|e| e.id == id && e.checkpoint.as_deref() == checkpoint)
}
fn target_checkpoint<'a>(r: &'a RealmRun, id: &str) -> Option<&'a str> {
    r.claims
        .iter()
        .find(|x| x.id == id)
        .and_then(|x| x.checkpoint.as_deref())
        .or_else(|| {
            r.observations
                .iter()
                .find(|x| x.id == id)
                .and_then(|x| x.checkpoint.as_deref())
        })
        .or_else(|| {
            r.proposed_effects
                .iter()
                .find(|x| x.id == id)
                .and_then(|x| x.checkpoint.as_deref())
        })
}
fn validate_blob_ref(
    x: &BlobRef,
    blobs: &BTreeMap<String, Vec<u8>>,
    mode: ContentMode,
    level: ValidationLevel,
    resolver: Option<&dyn ContentResolver>,
) -> Result<(), ArtifactError> {
    if !is_blob_digest(&x.digest) {
        return Err(ArtifactError::Invalid("invalid blob digest".into()));
    }
    let bytes = match blobs.get(&x.digest.value) {
        Some(bytes) => Some(bytes.clone()),
        None => match resolver {
            Some(resolver) => resolver.resolve(&x.digest)?,
            None => None,
        },
    };
    match bytes {
        Some(bytes) => {
            if bytes.len() as u64 != x.size || hash("realm.blob", &bytes) != x.digest {
                return Err(ArtifactError::Invalid(
                    "blob substitution or size mismatch".into(),
                ));
            }
            Ok(())
        }
        None if mode == ContentMode::Portable || level == ValidationLevel::ContentComplete => {
            Err(ArtifactError::MissingBlob(x.digest.value.clone()))
        }
        None => Ok(()),
    }
}
fn validate_evidence_ref(
    e: &EvidenceRef,
    blobs: &BTreeMap<String, Vec<u8>>,
    mode: ContentMode,
    level: ValidationLevel,
    resolver: Option<&dyn ContentResolver>,
) -> Result<(), ArtifactError> {
    if !is_blob_digest(&e.digest) {
        return Err(ArtifactError::Invalid("invalid evidence digest".into()));
    }
    let bytes = match blobs.get(&e.digest.value) {
        Some(bytes) => Some(bytes.clone()),
        None => match resolver {
            Some(resolver) => resolver.resolve(&e.digest)?,
            None => None,
        },
    };
    match bytes {
        Some(bytes)
            if e.size.is_none_or(|size| size == bytes.len() as u64)
                && hash("realm.blob", &bytes) == e.digest =>
        {
            Ok(())
        }
        Some(_) => Err(ArtifactError::Invalid("evidence substitution".into())),
        None if mode == ContentMode::Portable || level == ValidationLevel::ContentComplete => {
            Err(ArtifactError::MissingBlob(e.digest.value.clone()))
        }
        None => Ok(()),
    }
}
fn validate_commitment(c: &Commitment) -> Result<(), ArtifactError> {
    if c.identity.is_empty() || !is_digest(&c.digest) {
        Err(ArtifactError::Invalid("malformed commitment".into()))
    } else {
        Ok(())
    }
}
fn is_digest(d: &Digest) -> bool {
    d.algorithm == "blake3"
        && !d.domain.is_empty()
        && d.value.len() == 64
        && d.value.bytes().all(|x| x.is_ascii_hexdigit())
}
fn is_blob_digest(d: &Digest) -> bool {
    is_digest(d) && d.domain == "realm.blob"
}
pub fn hash(domain: &str, b: &[u8]) -> Digest {
    Digest {
        algorithm: "blake3".into(),
        domain: domain.into(),
        value: blake3::hash(&[domain.as_bytes(), &[0], b].concat())
            .to_hex()
            .to_string(),
    }
}
fn canonical_json<T: Serialize>(x: &T) -> Result<Vec<u8>, ArtifactError> {
    Ok(serde_json::to_vec(&canon(&serde_json::to_value(x)?))?)
}
fn canon(x: &Value) -> Value {
    match x {
        Value::Object(o) => {
            let mut m = Map::new();
            for (k, v) in o {
                m.insert(k.clone(), canon(v));
            }
            Value::Object(m)
        }
        Value::Array(a) => Value::Array(a.iter().map(canon).collect()),
        _ => x.clone(),
    }
}
fn put(o: &mut Vec<u8>, b: &[u8]) {
    o.extend_from_slice(&(b.len() as u64).to_be_bytes());
    o.extend_from_slice(b)
}
struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ArtifactError> {
        let e = self
            .p
            .checked_add(n)
            .ok_or_else(|| ArtifactError::Invalid("overflow".into()))?;
        if e > self.b.len() {
            return Err(ArtifactError::Invalid("truncated".into()));
        }
        let r = &self.b[self.p..e];
        self.p = e;
        Ok(r)
    }
    fn frame(&mut self) -> Result<&'a [u8], ArtifactError> {
        let n = usize::try_from(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
            .map_err(|_| ArtifactError::Invalid("large frame".into()))?;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run() -> RealmRun {
        let d = |x| hash("realm.test", x);
        RealmRun {
            schema_version: SCHEMA_VERSION,
            lifecycle: Lifecycle::Frozen,
            run: RunIdentity {
                run_id: "r".into(),
                execution_id: "e".into(),
            },
            challenge: Challenge {
                nonce: Some(d(b"n")),
                issued_by: "issuer".into(),
                expires_at: None,
            },
            intent: Commitment {
                identity: "i".into(),
                digest: d(b"i"),
            },
            starting_state: Commitment {
                identity: "s".into(),
                digest: d(b"s"),
            },
            environment: EnvironmentIdentity {
                runtime: "v6".into(),
                runtime_digest: d(b"rt"),
                backend: "b".into(),
                architecture: "a".into(),
            },
            effect_contract: Commitment {
                identity: "p".into(),
                digest: d(b"p"),
            },
            inputs: vec![],
            outputs: vec![],
            checkpoints: vec![],
            observations: vec![],
            proposed_effects: vec![],
            unknown_effects: vec![],
            evidence: vec![],
            claims: vec![],
            final_state: Some(Commitment {
                identity: "f".into(),
                digest: d(b"f"),
            }),
            seal: None,
        }
    }
    #[test]
    fn semantic_excludes_envelope() {
        let mut a = ArtifactBundle::new(run());
        let x = a.semantic_identity().unwrap();
        a.envelope.verification.push(VerificationRef {
            id: "v".into(),
            verifier: "x".into(),
            result_digest: hash("realm.result", b"x"),
            decision: VerificationDecision::Accept,
            run_id: "r".into(),
            checkpoint: None,
            supports: vec![],
        });
        assert_eq!(x, a.semantic_identity().unwrap());
    }
    #[test]
    fn seal_requires_frozen() {
        let mut a = ArtifactBundle::new(run());
        a.run.lifecycle = Lifecycle::Executing;
        assert!(a.seal().is_err());
    }
    #[test]
    fn domain_changes_digest() {
        assert_ne!(hash("a", b"x").value, hash("b", b"x").value);
    }
    #[test]
    fn thin_and_portable_share_semantic_id() {
        let a = ArtifactBundle::new(run());
        let mut b = a.clone();
        b.envelope.content = ContentMode::Thin;
        assert_eq!(
            a.semantic_identity().unwrap(),
            b.semantic_identity().unwrap()
        );
    }
    #[test]
    fn lifecycle_allows_checkpoint_continue_but_not_downgrade() {
        let mut a = ArtifactBundle::new(run());
        a.run.lifecycle = Lifecycle::Created;
        a.transition(Lifecycle::Executing).unwrap();
        a.transition(Lifecycle::Checkpointed).unwrap();
        a.transition(Lifecycle::Executing).unwrap();
        assert!(a.transition(Lifecycle::Created).is_err());
    }
    #[test]
    fn semantic_mutations_change_identity() {
        let base = ArtifactBundle::new(run()).semantic_identity().unwrap();
        let mut changed = ArtifactBundle::new(run());
        changed.run.challenge.issued_by = "other".into();
        assert_ne!(base, changed.semantic_identity().unwrap());
        let mut changed = ArtifactBundle::new(run());
        changed.run.intent.identity = "other".into();
        assert_ne!(base, changed.semantic_identity().unwrap());
        let mut changed = ArtifactBundle::new(run());
        changed.run.final_state = None;
        assert!(changed.semantic_identity().is_err());
    }
}
