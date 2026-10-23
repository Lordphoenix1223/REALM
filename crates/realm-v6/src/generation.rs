//! Identity and layout primitives for managed whole-world publication.
//!
//! These types do not grant publication authority. Identity derivation accepts
//! only the opaque in-process value produced by the checked C1 execution path.

use crate::profile::SyncTrace as _;
use crate::{
    execute::CheckedExecutionForPublication,
    publication_journal::{
        DestinationLock, PublicationJournal, PublicationJournalError, PublicationState,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

#[cfg(target_os = "linux")]
use std::{
    mem::MaybeUninit,
    os::unix::{ffi::OsStrExt, io::AsRawFd},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationIdentity {
    schema_version: u16,
    execution_id: String,
    run_id: String,
    capsule_id: String,
    challenge_binding: String,
    accepted_decision_identity: String,
    accepted_start_root: String,
    accepted_final_root: String,
    accepted_delta_root: String,
    workspace_identity: String,
    generation_id: String,
    publication_id: String,
}

/// Durable receipt for an exchanged managed workspace generation. This is
/// publication evidence only; it does not create or re-evaluate ACCEPT.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationReceipt {
    pub schema_version: u16,
    pub identity: GenerationIdentity,
    pub live_root: String,
    pub previous_root: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenerationRecovery {
    NoPendingPublication,
    Interrupted {
        publication_id: String,
        live_root: String,
    },
    AlreadyPublished(GenerationReceipt),
    Published(GenerationReceipt),
}

impl GenerationIdentity {
    pub fn from_publication_capability(
        execution: &CheckedExecutionForPublication,
        layout: &GenerationLayout,
    ) -> Result<Self, GenerationError> {
        let result = execution.result();
        if !execution.validate_bindings() {
            return Err(GenerationError::Invalid(
                "checked execution binding is incomplete or inconsistent".into(),
            ));
        }
        let generation_id = digest(&(
            "realm-v6-generation-v1",
            &result.run_id,
            &result.execution_id,
            execution.decision_identity(),
            execution.capsule_id(),
            execution.challenge_binding(),
            &layout.workspace_identity,
            execution.accepted_start_root(),
            execution.accepted_final_root(),
            execution.accepted_delta_root(),
        ))?;
        let publication_id = digest(&("realm-v6-publication-v1", &generation_id))?;
        Ok(Self {
            schema_version: 1,
            execution_id: result.execution_id.clone(),
            run_id: result.run_id.clone(),
            capsule_id: execution.capsule_id().into(),
            challenge_binding: execution.challenge_binding().into(),
            accepted_decision_identity: execution.decision_identity().into(),
            accepted_start_root: execution.accepted_start_root().into(),
            accepted_final_root: execution.accepted_final_root().into(),
            accepted_delta_root: execution.accepted_delta_root().into(),
            workspace_identity: layout.workspace_identity.clone(),
            generation_id,
            publication_id,
        })
    }

    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn capsule_id(&self) -> &str {
        &self.capsule_id
    }

    /// This digest binds the C1 completion evidence, which itself commits to
    /// the supervisor challenge, run, and execution. The raw challenge is not
    /// copied into publication metadata.
    pub fn challenge_binding(&self) -> &str {
        &self.challenge_binding
    }

    pub fn accepted_decision_identity(&self) -> &str {
        &self.accepted_decision_identity
    }

    pub fn accepted_start_root(&self) -> &str {
        &self.accepted_start_root
    }

    pub fn accepted_final_root(&self) -> &str {
        &self.accepted_final_root
    }

    pub fn accepted_delta_root(&self) -> &str {
        &self.accepted_delta_root
    }

    pub fn workspace_identity(&self) -> &str {
        &self.workspace_identity
    }

    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    pub fn publication_id(&self) -> &str {
        &self.publication_id
    }

    /// Checks only the internal digest relationships. It is not an ACCEPT
    /// verifier and must never be used to authorize publication by itself.
    pub fn validate_integrity(&self) -> Result<(), GenerationError> {
        if self.schema_version != 1
            || self.execution_id.is_empty()
            || self.run_id.is_empty()
            || self.capsule_id.is_empty()
            || self.challenge_binding.is_empty()
            || self.accepted_decision_identity.is_empty()
            || self.accepted_start_root.is_empty()
            || self.accepted_final_root.is_empty()
            || self.accepted_delta_root.is_empty()
            || self.workspace_identity.is_empty()
            || self.run_id.contains('/')
        {
            return Err(GenerationError::Invalid(
                "generation identity is incomplete".into(),
            ));
        }
        if ![
            self.execution_id.as_str(),
            self.capsule_id.as_str(),
            self.challenge_binding.as_str(),
            self.accepted_decision_identity.as_str(),
            self.accepted_start_root.as_str(),
            self.accepted_final_root.as_str(),
            self.accepted_delta_root.as_str(),
            self.workspace_identity.as_str(),
        ]
        .into_iter()
        .all(valid_digest)
        {
            return Err(GenerationError::Invalid(
                "generation identity contains a malformed digest".into(),
            ));
        }
        let generation_id = digest(&(
            "realm-v6-generation-v1",
            &self.run_id,
            &self.execution_id,
            &self.accepted_decision_identity,
            &self.capsule_id,
            &self.challenge_binding,
            &self.workspace_identity,
            &self.accepted_start_root,
            &self.accepted_final_root,
            &self.accepted_delta_root,
        ))?;
        let publication_id = digest(&("realm-v6-publication-v1", &generation_id))?;
        if self.generation_id != generation_id || self.publication_id != publication_id {
            return Err(GenerationError::Invalid(
                "generation or publication digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

/// Stable sibling paths for a REALM-managed workspace. Construction validates
/// the existing live root and its parent but does not create control state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationLayout {
    live_root: PathBuf,
    parent: PathBuf,
    live_name: String,
    control_root: PathBuf,
    workspace_identity: String,
    root_uid: u32,
    root_gid: u32,
    root_mode: u32,
    mount_id: Option<u64>,
}

impl GenerationLayout {
    pub fn inspect(live_root: impl AsRef<Path>) -> Result<Self, GenerationError> {
        let requested = absolute_path(live_root.as_ref())?;
        let live_name = requested
            .file_name()
            .filter(|name| !name.is_empty())
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                GenerationError::Unsupported("workspace name must be non-empty UTF-8".into())
            })?
            .to_string();
        if live_name == "." || live_name == ".." || live_name.contains('/') {
            return Err(GenerationError::Invalid("invalid workspace name".into()));
        }
        let requested_parent = requested
            .parent()
            .ok_or_else(|| GenerationError::Invalid("workspace has no parent".into()))?;
        validate_no_symlink_ancestors(requested_parent)?;
        let parent = requested_parent.canonicalize()?;
        let live_root = parent.join(&live_name);
        let parent_metadata = fs::symlink_metadata(&parent)?;
        let live_metadata = fs::symlink_metadata(&live_root)?;
        validate_managed_directory(&parent_metadata, "workspace parent")?;
        validate_managed_directory(&live_metadata, "live workspace")?;
        validate_private_mode(parent_metadata.mode(), "workspace parent")?;
        validate_private_mode(live_metadata.mode(), "live workspace")?;
        if parent_metadata.dev() != live_metadata.dev() {
            return Err(GenerationError::Unsupported(
                "live workspace is on a different filesystem from its parent".into(),
            ));
        }
        let parent_mount_id = mount_id(&parent)?;
        if parent_mount_id != mount_id(&live_root)? {
            return Err(GenerationError::Unsupported(
                "live workspace must be on the same mount as its parent".into(),
            ));
        }
        let effective_uid = unsafe { libc::geteuid() };
        if parent_metadata.uid() != effective_uid || live_metadata.uid() != effective_uid {
            return Err(GenerationError::Unsupported(
                "workspace parent and root must be owned by the publisher UID".into(),
            ));
        }
        if live_metadata.gid() != unsafe { libc::getegid() } || live_metadata.mode() & 0o7000 != 0 {
            return Err(GenerationError::Unsupported(
                "live workspace root must use publisher ownership without set-ID or sticky bits"
                    .into(),
            ));
        }
        if parent_metadata.mode() & 0o2000 != 0
            && parent_metadata.gid() != unsafe { libc::getegid() }
        {
            return Err(GenerationError::Unsupported(
                "set-group-ID workspace parent would change generation ownership".into(),
            ));
        }
        let control_name = format!(".{live_name}.realm-control");
        if control_name.len() > 255 {
            return Err(GenerationError::Unsupported(
                "workspace name is too long for managed control paths".into(),
            ));
        }
        let control_root = parent.join(control_name);
        if 1 + live_name.len() + ".realm-generation-".len() + 64 > 255 {
            return Err(GenerationError::Unsupported(
                "workspace name is too long for generation paths".into(),
            ));
        }
        let parent_metadata = fs::metadata(&parent)?;
        let workspace_identity = digest(&(
            "realm-v6-workspace-v1",
            live_root.to_string_lossy().as_ref(),
            parent_metadata.dev(),
            parent_metadata.ino(),
            parent_metadata.uid(),
            parent_metadata.gid(),
            live_name.as_str(),
            live_metadata.uid(),
            live_metadata.gid(),
            live_metadata.mode() & 0o7777,
            parent_mount_id,
        ))?;
        Ok(Self {
            live_root,
            parent,
            live_name,
            control_root,
            workspace_identity,
            root_uid: live_metadata.uid(),
            root_gid: live_metadata.gid(),
            root_mode: live_metadata.mode() & 0o7777,
            mount_id: parent_mount_id,
        })
    }

    pub fn live_root(&self) -> &Path {
        &self.live_root
    }

    pub fn parent(&self) -> &Path {
        &self.parent
    }

    pub fn control_root(&self) -> &Path {
        &self.control_root
    }

    pub fn journal_path(&self) -> PathBuf {
        self.control_root.join("publication.jsonl")
    }

    pub fn receipt_directory(&self) -> PathBuf {
        self.control_root.join("receipts")
    }

    pub fn workspace_identity(&self) -> &str {
        &self.workspace_identity
    }

    pub fn live_name(&self) -> &str {
        &self.live_name
    }

    pub fn root_metadata(&self) -> (u32, u32, u32) {
        (self.root_uid, self.root_gid, self.root_mode)
    }

    pub fn mount_id(&self) -> Option<u64> {
        self.mount_id
    }

    pub fn generation_path(
        &self,
        identity: &GenerationIdentity,
    ) -> Result<PathBuf, GenerationError> {
        identity.validate_integrity()?;
        let name = format!(
            ".{}.realm-generation-{}",
            self.live_name, identity.generation_id
        );
        if name.len() > 255 {
            return Err(GenerationError::Unsupported(
                "workspace name is too long for a generation path".into(),
            ));
        }
        Ok(self.parent.join(name))
    }

    pub fn ensure_control_root(&self) -> Result<(), GenerationError> {
        match fs::symlink_metadata(&self.control_root) {
            Ok(metadata) => {
                validate_managed_directory(&metadata, "control directory")?;
                if metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.mode() & 0o7777 != 0o700
                    || mount_id(&self.control_root)? != self.mount_id
                {
                    return Err(GenerationError::Unsupported(
                        "control directory must be publisher-owned mode 0700".into(),
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&self.control_root)?;
                fs::set_permissions(&self.control_root, fs::Permissions::from_mode(0o700))?;
                let metadata = fs::symlink_metadata(&self.control_root)?;
                validate_managed_directory(&metadata, "control directory")?;
                if metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.mode() & 0o7777 != 0o700
                    || mount_id(&self.control_root)? != self.mount_id
                {
                    return Err(GenerationError::Unsupported(
                        "new control directory failed ownership or mode validation".into(),
                    ));
                }
                sync_directory(&self.parent)?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

/// A separately materialized and rescanned S1 tree. This value does not mark
/// the candidate committable; commit-intent and recovery lifecycle checks are
/// added by the generation journal path.
pub struct PreparedGeneration {
    identity: GenerationIdentity,
    layout: GenerationLayout,
    candidate_root: PathBuf,
    accepted_final_root: String,
    journal_path: PathBuf,
    _lock: DestinationLock,
}

/// A committed generation whose destination lock remains held so a caller can
/// durably bind its `.realm` artifact and advance the authority head before a
/// second publisher observes the new live world.
pub struct CommittedGeneration {
    identity: GenerationIdentity,
    layout: GenerationLayout,
    receipt: GenerationReceipt,
    _lock: DestinationLock,
}

impl CommittedGeneration {
    pub fn identity(&self) -> &GenerationIdentity {
        &self.identity
    }

    pub fn layout(&self) -> &GenerationLayout {
        &self.layout
    }

    pub fn receipt(&self) -> &GenerationReceipt {
        &self.receipt
    }
}

impl PreparedGeneration {
    pub fn identity(&self) -> &GenerationIdentity {
        &self.identity
    }

    pub fn candidate_root(&self) -> &Path {
        &self.candidate_root
    }

    pub fn accepted_final_root(&self) -> &str {
        &self.accepted_final_root
    }

    pub fn layout(&self) -> &GenerationLayout {
        &self.layout
    }
}

/// Exchange the verified candidate with the live root, verify both sides, and
/// persist a receipt through the existing append-only publication journal.
/// The destination lock acquired during preparation remains held until this
/// function returns.
pub fn commit_generation(
    prepared: PreparedGeneration,
) -> Result<GenerationReceipt, GenerationError> {
    let committed = commit_generation_held(prepared)?;
    Ok(committed.receipt.clone())
}

/// Commit while retaining the generation lock in an opaque value. The caller
/// must finish durable lifecycle publication or let the value drop, in which
/// case the live exchange remains detectable as incomplete against the old
/// authority head.
pub fn commit_generation_held(
    prepared: PreparedGeneration,
) -> Result<CommittedGeneration, GenerationError> {
    let _profile = crate::profile::Span::new("generation_exchange");
    crash_at("GENERATION_AFTER_LOCK");
    crash_at("GENERATION_COMMIT_AFTER_LOCK");
    let fresh_layout = GenerationLayout::inspect(prepared.layout.live_root())?;
    if fresh_layout.workspace_identity() != prepared.identity.workspace_identity()
        || fresh_layout.mount_id() != prepared.layout.mount_id()
        || fresh_layout.parent() != prepared.layout.parent()
    {
        let mut journal = PublicationJournal::open(&prepared.journal_path)?;
        record_generation_conflict(
            &mut journal,
            &prepared.identity,
            "managed workspace identity or mount changed after preparation",
        )?;
        return Err(GenerationError::Conflict(
            "managed workspace identity or mount changed after preparation".into(),
        ));
    }

    let mut journal = PublicationJournal::open(&prepared.journal_path)?;
    require_generation_state(
        &journal,
        &prepared.identity,
        PublicationState::GenerationPrepared,
    )?;
    crash_at("GENERATION_BEFORE_LIVE_ROOT_REVALIDATION");
    let initial_live = scan_managed_root(prepared.layout.live_root(), &prepared.layout)?;
    if initial_live.root != prepared.identity.accepted_start_root() {
        record_generation_conflict(
            &mut journal,
            &prepared.identity,
            "live workspace changed from accepted S0 before commit",
        )?;
        return Err(GenerationError::Conflict(
            "live workspace changed from accepted S0 before commit".into(),
        ));
    }
    let initial_candidate = match scan_managed_root(&prepared.candidate_root, &prepared.layout) {
        Ok(world) => world,
        Err(error) => {
            record_generation_integrity_failure(
                &mut journal,
                &prepared.identity,
                &format!("candidate generation cannot be scanned: {error}"),
            )?;
            return Err(error);
        }
    };
    if initial_candidate.root != prepared.identity.accepted_final_root() {
        record_generation_integrity_failure(
            &mut journal,
            &prepared.identity,
            "candidate generation changed after verification",
        )?;
        return Err(GenerationError::Integrity(
            "candidate generation changed after verification".into(),
        ));
    }
    crash_at("GENERATION_AFTER_LIVE_ROOT_REVALIDATION");
    verify_same_mount(&prepared.layout, &prepared.candidate_root)?;
    revalidate_parent_identity(&prepared.layout)?;

    crash_at("GENERATION_BEFORE_COMMIT_INTENT");
    journal.record_generation_state(
        &prepared.identity,
        PublicationState::CommitIntent,
        None,
        None,
        None,
    )?;
    crash_at("GENERATION_AFTER_COMMIT_INTENT");
    journal.record_generation_state(
        &prepared.identity,
        PublicationState::CommitInProgress,
        None,
        None,
        None,
    )?;

    // Revalidate after the durable intent and as close as possible to the
    // namespace syscall. The advisory lock coordinates REALM publishers;
    // unrelated same-UID writers remain outside this contract.
    crash_at("GENERATION_BEFORE_FINAL_REVALIDATION");
    let final_live = match scan_managed_root(prepared.layout.live_root(), &prepared.layout) {
        Ok(world) => world,
        Err(error) => {
            record_generation_integrity_failure(
                &mut journal,
                &prepared.identity,
                &format!("live root failed final pre-commit scan: {error}"),
            )?;
            return Err(error);
        }
    };
    let final_candidate = match scan_managed_root(&prepared.candidate_root, &prepared.layout) {
        Ok(world) => world,
        Err(error) => {
            record_generation_integrity_failure(
                &mut journal,
                &prepared.identity,
                &format!("candidate failed final pre-commit scan: {error}"),
            )?;
            return Err(error);
        }
    };
    if final_live.root != prepared.identity.accepted_start_root() {
        record_generation_conflict(
            &mut journal,
            &prepared.identity,
            "live workspace changed immediately before namespace commit",
        )?;
        return Err(GenerationError::Conflict(
            "live workspace changed immediately before namespace commit".into(),
        ));
    }
    if final_candidate.root != prepared.identity.accepted_final_root() {
        record_generation_integrity_failure(
            &mut journal,
            &prepared.identity,
            "candidate generation changed immediately before namespace commit",
        )?;
        return Err(GenerationError::Integrity(
            "candidate generation changed immediately before namespace commit".into(),
        ));
    }
    verify_same_mount(&prepared.layout, &prepared.candidate_root)?;
    if let Err(error) = revalidate_parent_identity(&prepared.layout) {
        record_generation_conflict(
            &mut journal,
            &prepared.identity,
            &format!("parent identity changed before commit: {error}"),
        )?;
        return Err(error);
    }
    crash_at("GENERATION_AFTER_FINAL_REVALIDATION");
    crash_at("GENERATION_BEFORE_RENAME_EXCHANGE");

    if let Err(exchange_error) = exchange_siblings(&prepared.layout, &prepared.candidate_root) {
        let live_after_error = scan_managed_root(prepared.layout.live_root(), &prepared.layout);
        let candidate_after_error = scan_managed_root(&prepared.candidate_root, &prepared.layout);
        if matches!((&live_after_error, &candidate_after_error),
            (Ok(live), Ok(candidate))
                if live.root == prepared.identity.accepted_start_root()
                    && candidate.root == prepared.identity.accepted_final_root())
        {
            record_generation_conflict(
                &mut journal,
                &prepared.identity,
                &format!("atomic namespace exchange was unsupported or refused: {exchange_error}"),
            )?;
            return Err(GenerationError::Unsupported(format!(
                "atomic RENAME_EXCHANGE failed without mutation: {exchange_error}"
            )));
        }
        record_generation_integrity_failure(
            &mut journal,
            &prepared.identity,
            &format!("exchange failure left an unexpected namespace state: {exchange_error}"),
        )?;
        return Err(GenerationError::Integrity(format!(
            "exchange failure left an unexpected namespace state: {exchange_error}"
        )));
    }
    crash_at("GENERATION_AFTER_RENAME_EXCHANGE");
    crash_at("GENERATION_BEFORE_PARENT_FSYNC");
    sync_directory(&prepared.layout.parent)?;
    crash_at("GENERATION_AFTER_PARENT_FSYNC");

    crash_at("GENERATION_BEFORE_POST_COMMIT_SCAN");
    let live_after = match scan_managed_root(prepared.layout.live_root(), &prepared.layout) {
        Ok(world) => world,
        Err(error) => {
            record_generation_integrity_failure(
                &mut journal,
                &prepared.identity,
                &format!("live root failed post-commit scan: {error}"),
            )?;
            return Err(error);
        }
    };
    let previous_after = match scan_managed_root(&prepared.candidate_root, &prepared.layout) {
        Ok(world) => world,
        Err(error) => {
            record_generation_integrity_failure(
                &mut journal,
                &prepared.identity,
                &format!("previous root failed post-commit scan: {error}"),
            )?;
            return Err(error);
        }
    };
    crash_at("GENERATION_AFTER_POST_COMMIT_SCAN");
    if live_after.root != prepared.identity.accepted_final_root()
        || previous_after.root != prepared.identity.accepted_start_root()
    {
        record_generation_integrity_failure(
            &mut journal,
            &prepared.identity,
            "post-exchange live and previous generations do not match accepted S1/S0",
        )?;
        return Err(GenerationError::Integrity(
            "post-exchange live and previous generations do not match accepted S1/S0".into(),
        ));
    }
    journal.record_generation_state(
        &prepared.identity,
        PublicationState::Committed,
        None,
        None,
        None,
    )?;
    journal.record_generation_state(
        &prepared.identity,
        PublicationState::PublicationVerified,
        Some(live_after.root.clone()),
        None,
        None,
    )?;

    crash_at("GENERATION_BEFORE_RECEIPT_PERSISTENCE");
    let (receipt, receipt_digest) = persist_generation_receipt(
        &prepared.layout,
        &prepared.identity,
        &live_after.root,
        &previous_after.root,
    )?;
    crash_at("GENERATION_AFTER_RECEIPT_PERSISTENCE");
    journal.record_generation_state(
        &prepared.identity,
        PublicationState::ReceiptPersisted,
        Some(live_after.root.clone()),
        Some(receipt_digest.clone()),
        None,
    )?;
    journal.record_generation_state(
        &prepared.identity,
        PublicationState::Published,
        Some(live_after.root),
        Some(receipt_digest),
        None,
    )?;
    let identity = prepared.identity.clone();
    let layout = prepared.layout.clone();
    let lock = prepared._lock;
    Ok(CommittedGeneration {
        identity,
        layout,
        receipt,
        _lock: lock,
    })
}

/// Recover an unfinished generation publication from the actual namespace
/// roots. Journal states alone never decide whether the exchange occurred.
pub fn recover_generation(
    live_root: impl AsRef<Path>,
) -> Result<GenerationRecovery, GenerationError> {
    let layout = GenerationLayout::inspect(live_root)?;
    layout.ensure_control_root()?;
    crash_at("GENERATION_RECOVERY_BEFORE_LOCK");
    let _lock = DestinationLock::acquire(layout.live_root())?;
    crash_at("GENERATION_RECOVERY_AFTER_LOCK");
    revalidate_parent_identity(&layout)?;
    let journal_path = layout.journal_path();
    let mut journal = PublicationJournal::open(&journal_path)?;
    let records = journal.generation_records_for_workspace(layout.workspace_identity());
    let unfinished = records
        .iter()
        .filter(|record| is_unfinished_generation_state(record.state))
        .cloned()
        .collect::<Vec<_>>();
    if unfinished.len() > 1 {
        return Err(GenerationError::Integrity(
            "multiple unresolved generation publications target one workspace".into(),
        ));
    }
    let Some(record) = unfinished.into_iter().next() else {
        let Some(last) = records.last() else {
            return Ok(GenerationRecovery::NoPendingPublication);
        };
        let Some(identity) = last.generation_identity.as_ref() else {
            return Err(GenerationError::Integrity(
                "generation lifecycle record lacks its identity".into(),
            ));
        };
        return match last.state {
            PublicationState::Published => {
                let receipt = verify_persisted_publication(&layout, identity, last)?;
                Ok(GenerationRecovery::AlreadyPublished(receipt))
            }
            PublicationState::Interrupted => {
                let live = scan_managed_root(layout.live_root(), &layout)?;
                if live.root != identity.accepted_start_root()
                    && live.root != identity.accepted_final_root()
                {
                    return Err(GenerationError::Integrity(
                        "interrupted publication no longer has an S0 or S1 live world".into(),
                    ));
                }
                Ok(GenerationRecovery::Interrupted {
                    publication_id: identity.publication_id().into(),
                    live_root: live.root,
                })
            }
            PublicationState::IntegrityFailure => Err(GenerationError::Integrity(
                "journal records an unresolved generation integrity failure".into(),
            )),
            _ => Ok(GenerationRecovery::NoPendingPublication),
        };
    };
    let identity = record.generation_identity.as_ref().ok_or_else(|| {
        GenerationError::Integrity("generation identity missing in journal".into())
    })?;
    identity.validate_integrity()?;
    if identity.workspace_identity() != layout.workspace_identity()
        || identity.publication_id() != record.publication_id
    {
        record_generation_integrity_failure(
            &mut journal,
            identity,
            "journal generation identity does not match the inspected workspace",
        )?;
        return Err(GenerationError::Integrity(
            "journal generation identity does not match the inspected workspace".into(),
        ));
    }
    let live = match scan_managed_root(layout.live_root(), &layout) {
        Ok(world) => world,
        Err(error) => {
            record_generation_integrity_failure(
                &mut journal,
                identity,
                &format!("live workspace cannot be scanned during recovery: {error}"),
            )?;
            return Err(error);
        }
    };
    let candidate_path = layout.generation_path(identity)?;
    if live.root == identity.accepted_start_root() {
        if matches!(
            record.state,
            PublicationState::Committed
                | PublicationState::PublicationVerified
                | PublicationState::ReceiptPersisted
        ) {
            record_generation_integrity_failure(
                &mut journal,
                identity,
                "journal claims commit completion but live world is still S0",
            )?;
            return Err(GenerationError::Integrity(
                "journal claims commit completion but live world is still S0".into(),
            ));
        }
        journal.record_generation_state(
            identity,
            PublicationState::Interrupted,
            None,
            None,
            Some("recovery found live S0; namespace commit was not established".into()),
        )?;
        return Ok(GenerationRecovery::Interrupted {
            publication_id: identity.publication_id().into(),
            live_root: live.root,
        });
    }
    if live.root != identity.accepted_final_root() {
        record_generation_integrity_failure(
            &mut journal,
            identity,
            "live workspace matches neither accepted S0 nor S1",
        )?;
        return Err(GenerationError::Integrity(
            "live workspace matches neither accepted S0 nor S1".into(),
        ));
    }
    if !matches!(
        record.state,
        PublicationState::CommitInProgress
            | PublicationState::Committed
            | PublicationState::PublicationVerified
            | PublicationState::ReceiptPersisted
    ) {
        record_generation_integrity_failure(
            &mut journal,
            identity,
            "live S1 is present without a durable commit-in-progress record",
        )?;
        return Err(GenerationError::Integrity(
            "live S1 is present without a durable commit-in-progress record".into(),
        ));
    }
    let previous = match scan_managed_root(&candidate_path, &layout) {
        Ok(world) => world,
        Err(error) => {
            record_generation_integrity_failure(
                &mut journal,
                identity,
                &format!("previous generation cannot be scanned: {error}"),
            )?;
            return Err(error);
        }
    };
    if previous.root != identity.accepted_start_root() {
        record_generation_integrity_failure(
            &mut journal,
            identity,
            "exchanged previous generation does not match accepted S0",
        )?;
        return Err(GenerationError::Integrity(
            "exchanged previous generation does not match accepted S0".into(),
        ));
    }
    sync_directory(&layout.parent)?;
    if record.state == PublicationState::CommitInProgress {
        journal.record_generation_state(identity, PublicationState::Committed, None, None, None)?;
    }
    if matches!(
        record.state,
        PublicationState::CommitInProgress | PublicationState::Committed
    ) {
        journal.record_generation_state(
            identity,
            PublicationState::PublicationVerified,
            Some(live.root.clone()),
            None,
            None,
        )?;
    }
    let (receipt, receipt_digest) = if record.state == PublicationState::ReceiptPersisted {
        let (receipt, digest) = read_generation_receipt(&layout, identity)?;
        if record.receipt_digest.as_deref() != Some(digest.as_str()) {
            return Err(GenerationError::Integrity(
                "persisted receipt differs from its durable journal digest".into(),
            ));
        }
        (receipt, digest)
    } else {
        persist_generation_receipt(&layout, identity, &live.root, &previous.root)?
    };
    if record.state != PublicationState::ReceiptPersisted {
        journal.record_generation_state(
            identity,
            PublicationState::ReceiptPersisted,
            Some(live.root.clone()),
            Some(receipt_digest.clone()),
            None,
        )?;
    }
    journal.record_generation_state(
        identity,
        PublicationState::Published,
        Some(live.root),
        Some(receipt_digest),
        None,
    )?;
    Ok(GenerationRecovery::Published(receipt))
}

fn is_unfinished_generation_state(state: PublicationState) -> bool {
    matches!(
        state,
        PublicationState::GenerationPreparing
            | PublicationState::GenerationPrepared
            | PublicationState::CommitIntent
            | PublicationState::CommitInProgress
            | PublicationState::Committed
            | PublicationState::PublicationVerified
            | PublicationState::ReceiptPersisted
    )
}

fn require_generation_state(
    journal: &PublicationJournal,
    identity: &GenerationIdentity,
    expected: PublicationState,
) -> Result<(), GenerationError> {
    let record = journal
        .generation_records_for_workspace(identity.workspace_identity())
        .into_iter()
        .find(|record| record.publication_id == identity.publication_id())
        .ok_or_else(|| GenerationError::Conflict("generation is absent from the journal".into()))?;
    if record.state != expected || record.generation_identity.as_ref() != Some(identity) {
        return Err(GenerationError::Conflict(format!(
            "journal state is {:?}; expected {:?}",
            record.state, expected
        )));
    }
    Ok(())
}

fn record_generation_conflict(
    journal: &mut PublicationJournal,
    identity: &GenerationIdentity,
    reason: &str,
) -> Result<(), GenerationError> {
    let record = journal
        .generation_records_for_workspace(identity.workspace_identity())
        .into_iter()
        .find(|record| record.publication_id == identity.publication_id())
        .ok_or_else(|| GenerationError::Conflict("generation is absent from the journal".into()))?;
    if matches!(
        record.state,
        PublicationState::Conflict
            | PublicationState::Failed
            | PublicationState::Interrupted
            | PublicationState::IntegrityFailure
            | PublicationState::Published
    ) {
        return Ok(());
    }
    journal.record_generation_state(
        identity,
        PublicationState::Conflict,
        None,
        None,
        Some(reason.into()),
    )?;
    Ok(())
}

fn record_generation_integrity_failure(
    journal: &mut PublicationJournal,
    identity: &GenerationIdentity,
    reason: &str,
) -> Result<(), GenerationError> {
    let Some(record) = journal
        .generation_records_for_workspace(identity.workspace_identity())
        .into_iter()
        .find(|record| record.publication_id == identity.publication_id())
    else {
        return Err(GenerationError::Conflict(
            "generation is absent from the journal".into(),
        ));
    };
    if record.state == PublicationState::IntegrityFailure
        || matches!(
            record.state,
            PublicationState::Conflict
                | PublicationState::Failed
                | PublicationState::Interrupted
                | PublicationState::Published
        )
    {
        return Ok(());
    }
    journal.record_generation_state(
        identity,
        PublicationState::IntegrityFailure,
        None,
        None,
        Some(reason.into()),
    )?;
    Ok(())
}

fn scan_managed_root(
    root: &Path,
    layout: &GenerationLayout,
) -> Result<crate::filesystem_world::FilesystemWorld, GenerationError> {
    let metadata = fs::symlink_metadata(root)?;
    let (uid, gid, mode) = layout.root_metadata();
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != mode
    {
        return Err(GenerationError::Unsupported(
            "managed workspace root type or metadata changed".into(),
        ));
    }
    if mount_id(root)? != layout.mount_id() {
        return Err(GenerationError::Unsupported(
            "managed workspace root moved to another mount".into(),
        ));
    }
    let world = crate::filesystem_world::scan_directory(root)?;
    validate_source_profile(root, &world)?;
    validate_symlinks(&world)?;
    Ok(world)
}

fn verify_same_mount(layout: &GenerationLayout, candidate: &Path) -> Result<(), GenerationError> {
    let parent = fs::metadata(layout.parent())?;
    let generation = fs::symlink_metadata(candidate)?;
    if generation.file_type().is_symlink()
        || !generation.is_dir()
        || generation.dev() != parent.dev()
        || mount_id(candidate)? != layout.mount_id()
    {
        return Err(GenerationError::Unsupported(
            "live and candidate roots are not sibling directories on the same mount".into(),
        ));
    }
    Ok(())
}

fn revalidate_parent_identity(layout: &GenerationLayout) -> Result<(), GenerationError> {
    let current = GenerationLayout::inspect(layout.live_root())?;
    if current.workspace_identity() != layout.workspace_identity()
        || current.parent() != layout.parent()
        || current.mount_id() != layout.mount_id()
    {
        return Err(GenerationError::Conflict(
            "workspace parent or mount identity changed".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn exchange_siblings(layout: &GenerationLayout, candidate: &Path) -> Result<(), GenerationError> {
    use std::os::unix::ffi::OsStrExt;

    if candidate.parent() != Some(layout.parent()) {
        return Err(GenerationError::Invalid(
            "candidate is not a sibling of the live root".into(),
        ));
    }
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(layout.parent())?;
    let live_name = std::ffi::CString::new(Path::new(layout.live_name()).as_os_str().as_bytes())
        .map_err(|_| GenerationError::Invalid("live root name contains NUL".into()))?;
    let candidate_name = std::ffi::CString::new(
        candidate
            .file_name()
            .ok_or_else(|| GenerationError::Invalid("candidate has no name".into()))?
            .as_bytes(),
    )
    .map_err(|_| GenerationError::Invalid("candidate name contains NUL".into()))?;
    const RENAME_EXCHANGE: libc::c_uint = 2;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2 as libc::c_long,
            parent.as_raw_fd(),
            live_name.as_ptr(),
            parent.as_raw_fd(),
            candidate_name.as_ptr(),
            RENAME_EXCHANGE,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn exchange_siblings(_layout: &GenerationLayout, _candidate: &Path) -> Result<(), GenerationError> {
    Err(GenerationError::Unsupported(
        "whole-generation exchange requires Linux renameat2(RENAME_EXCHANGE)".into(),
    ))
}

fn receipt_path(layout: &GenerationLayout, identity: &GenerationIdentity) -> PathBuf {
    layout
        .receipt_directory()
        .join(format!("{}.json", identity.publication_id()))
}

fn ensure_receipt_directory(layout: &GenerationLayout) -> Result<(), GenerationError> {
    let directory = layout.receipt_directory();
    match fs::symlink_metadata(&directory) {
        Ok(metadata) => validate_receipt_directory(layout, &metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&directory)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
            let metadata = fs::symlink_metadata(&directory)?;
            validate_receipt_directory(layout, &metadata)?;
            sync_directory(layout.control_root())?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_receipt_directory(
    layout: &GenerationLayout,
    metadata: &fs::Metadata,
) -> Result<(), GenerationError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
        || metadata.dev() != fs::metadata(layout.control_root())?.dev()
        || mount_id(&layout.receipt_directory())? != layout.mount_id()
    {
        return Err(GenerationError::Unsupported(
            "generation receipt directory is not private and publisher-owned".into(),
        ));
    }
    Ok(())
}

fn persist_generation_receipt(
    layout: &GenerationLayout,
    identity: &GenerationIdentity,
    live_root: &str,
    previous_root: &str,
) -> Result<(GenerationReceipt, String), GenerationError> {
    ensure_receipt_directory(layout)?;
    let receipt = GenerationReceipt {
        schema_version: 1,
        identity: identity.clone(),
        live_root: live_root.into(),
        previous_root: previous_root.into(),
    };
    let encoded = serde_json::to_vec(&receipt)
        .map_err(|_| GenerationError::Invalid("receipt encoding failed".into()))?;
    let expected_digest = blake3::hash(&encoded).to_hex().to_string();
    let final_path = receipt_path(layout, identity);
    match fs::symlink_metadata(&final_path) {
        Ok(_) => {
            let (existing, digest) = read_generation_receipt(layout, identity)?;
            if existing != receipt || digest != expected_digest {
                return Err(GenerationError::Integrity(
                    "an existing receipt conflicts with the verified generation".into(),
                ));
            }
            return Ok((existing, digest));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| GenerationError::Invalid("system clock predates Unix epoch".into()))?
        .as_nanos();
    let temporary = layout.receipt_directory().join(format!(
        ".{}.{}.{}.tmp",
        identity.publication_id(),
        std::process::id(),
        nonce
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    file.write_all(&encoded)?;
    file.sync_all_traced()?;
    drop(file);
    match fs::hard_link(&temporary, &final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            let (existing, digest) = read_generation_receipt(layout, identity)?;
            if existing != receipt || digest != expected_digest {
                return Err(GenerationError::Integrity(
                    "a concurrent receipt conflicts with the verified generation".into(),
                ));
            }
            return Ok((existing, digest));
        }
        Err(error) => return Err(error.into()),
    }
    fs::remove_file(&temporary)?;
    sync_directory(&layout.receipt_directory())?;
    sync_directory(layout.control_root())?;
    Ok((receipt, expected_digest))
}

fn read_generation_receipt(
    layout: &GenerationLayout,
    identity: &GenerationIdentity,
) -> Result<(GenerationReceipt, String), GenerationError> {
    ensure_receipt_directory(layout)?;
    let path = receipt_path(layout, identity);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(GenerationError::Integrity(
            "generation receipt has unsafe type, owner, or mode".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let receipt: GenerationReceipt = serde_json::from_slice(&bytes)
        .map_err(|_| GenerationError::Integrity("generation receipt is malformed".into()))?;
    if receipt.schema_version != 1
        || receipt.identity != *identity
        || receipt.live_root != identity.accepted_final_root()
        || receipt.previous_root != identity.accepted_start_root()
    {
        return Err(GenerationError::Integrity(
            "generation receipt does not match its accepted identity and roots".into(),
        ));
    }
    let digest = blake3::hash(&bytes).to_hex().to_string();
    Ok((receipt, digest))
}

fn receipt_digest_for(receipt: &GenerationReceipt) -> Result<String, GenerationError> {
    let bytes = serde_json::to_vec(receipt)
        .map_err(|_| GenerationError::Invalid("receipt encoding failed".into()))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn verify_persisted_publication(
    layout: &GenerationLayout,
    identity: &GenerationIdentity,
    record: &crate::publication_journal::PublicationRecord,
) -> Result<GenerationReceipt, GenerationError> {
    if record.state != PublicationState::Published
        || record.post_publication_root.as_deref() != Some(identity.accepted_final_root())
    {
        return Err(GenerationError::Integrity(
            "published journal record lacks the accepted live root".into(),
        ));
    }
    let live = scan_managed_root(layout.live_root(), layout)?;
    let previous = scan_managed_root(&layout.generation_path(identity)?, layout)?;
    if live.root != identity.accepted_final_root()
        || previous.root != identity.accepted_start_root()
    {
        return Err(GenerationError::Integrity(
            "published live or previous generation no longer matches its receipt".into(),
        ));
    }
    let (receipt, digest) = read_generation_receipt(layout, identity)?;
    if record.receipt_digest.as_deref() != Some(digest.as_str())
        || receipt_digest_for(&receipt)? != digest
    {
        return Err(GenerationError::Integrity(
            "published receipt digest differs from the journal".into(),
        ));
    }
    Ok(receipt)
}

/// Construct the exact accepted final world at a hidden sibling path, then
/// rescan it with the production semantic scanner. This performs no live-path
/// mutation and creates no publication authority.
pub fn prepare_candidate(
    execution: &CheckedExecutionForPublication,
    live_root: impl AsRef<Path>,
) -> Result<PreparedGeneration, GenerationError> {
    let _profile = crate::profile::Span::new("generation_construction");
    let layout = GenerationLayout::inspect(live_root)?;
    let identity = GenerationIdentity::from_publication_capability(execution, &layout)?;
    layout.ensure_control_root()?;
    crash_at("GENERATION_BEFORE_LOCK");
    let lock = DestinationLock::acquire(layout.live_root())?;
    crash_at("GENERATION_AFTER_LOCK");
    revalidate_parent_identity(&layout)?;
    let journal_path = layout.journal_path();
    let mut journal = PublicationJournal::open(&journal_path)?;
    if journal.has_unfinished_generation_for_workspace(layout.workspace_identity()) {
        return Err(GenerationError::Conflict(
            "workspace has an unresolved generation publication; recover it first".into(),
        ));
    }
    if journal
        .generation_records_for_workspace(layout.workspace_identity())
        .iter()
        .any(|record| record.publication_id == identity.publication_id())
    {
        return Err(GenerationError::Conflict(
            "this accepted execution already has a generation publication record".into(),
        ));
    }
    let live_before = scan_managed_root(layout.live_root(), &layout)?;
    if live_before.root != identity.accepted_start_root() {
        return Err(GenerationError::Conflict(
            "live workspace no longer matches accepted S0".into(),
        ));
    }
    let candidate_root = layout.generation_path(&identity)?;
    match fs::symlink_metadata(&candidate_root) {
        Ok(_) => {
            return Err(GenerationError::Conflict(
                "candidate generation path already exists".into(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    journal.record_generation_state(
        &identity,
        PublicationState::GenerationPreparing,
        None,
        None,
        None,
    )?;
    let start_image = execution
        .result()
        .starting_workspace_image
        .as_deref()
        .ok_or_else(|| GenerationError::Invalid("accepted execution has no S0 image".into()))?;
    let final_image = execution
        .result()
        .final_workspace_image
        .as_deref()
        .ok_or_else(|| GenerationError::Invalid("accepted execution has no S1 image".into()))?;
    let materialized = with_mounted_images(start_image, final_image, |start, final_world| {
        let before = crate::filesystem_world::scan_directory(start)?;
        let after = crate::filesystem_world::scan_directory(final_world)?;
        if before.root != identity.accepted_start_root
            || after.root != identity.accepted_final_root
            || digest(&crate::filesystem_world::delta(&before, &after))?
                != identity.accepted_delta_root
        {
            return Err(GenerationError::Invalid(
                "accepted workspace images do not reproduce bound S0/S1/delta".into(),
            ));
        }
        validate_source_profile(start, &before)?;
        validate_source_profile(final_world, &after)?;
        ensure_root_metadata_unchanged(start, final_world)?;
        validate_symlinks(&after)?;

        create_generation_directory(&candidate_root)?;
        if mount_id(&candidate_root)? != layout.mount_id {
            return Err(GenerationError::Unsupported(
                "candidate generation is not on the managed workspace mount".into(),
            ));
        }
        crash_at("GENERATION_DURING_CANDIDATE_CREATION");
        copy_tree(final_world, &candidate_root)?;
        crash_at("GENERATION_AFTER_CANDIDATE_CREATION");
        fs::set_permissions(
            &candidate_root,
            fs::Permissions::from_mode(layout.root_metadata().2),
        )?;
        let metadata = fs::symlink_metadata(&candidate_root)?;
        let (root_uid, root_gid, root_mode) = layout.root_metadata();
        if metadata.uid() != root_uid
            || metadata.gid() != root_gid
            || metadata.mode() & 0o7777 != root_mode
        {
            return Err(GenerationError::Invalid(
                "candidate root metadata differs from managed workspace root".into(),
            ));
        }
        let candidate = crate::filesystem_world::scan_directory(&candidate_root)?;
        if candidate.root != identity.accepted_final_root {
            return Err(GenerationError::Invalid(
                "materialized candidate root differs from accepted S1".into(),
            ));
        }
        validate_source_profile(&candidate_root, &candidate)?;
        ensure_no_xattrs(&candidate_root)?;
        sync_directory(&candidate_root)?;
        sync_directory(&layout.parent)?;
        Ok(candidate.root)
    });
    let accepted_final_root = match materialized {
        Ok(root) => root,
        Err(error) => {
            let _ = journal.record_generation_state(
                &identity,
                PublicationState::Failed,
                None,
                None,
                Some(error.to_string()),
            );
            return Err(error);
        }
    };
    journal.record_generation_state(
        &identity,
        PublicationState::GenerationPrepared,
        None,
        None,
        None,
    )?;
    crash_at("GENERATION_AFTER_CANDIDATE_VERIFICATION");
    Ok(PreparedGeneration {
        accepted_final_root,
        identity,
        layout,
        candidate_root,
        journal_path,
        _lock: lock,
    })
}

#[derive(Debug)]
pub enum GenerationError {
    Io(io::Error),
    Invalid(String),
    Unsupported(String),
    Conflict(String),
    Integrity(String),
    Journal(PublicationJournalError),
}

impl std::fmt::Display for GenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "generation I/O: {error}"),
            Self::Invalid(reason) => write!(f, "invalid generation: {reason}"),
            Self::Unsupported(reason) => write!(f, "unsupported generation profile: {reason}"),
            Self::Conflict(reason) => write!(f, "generation publication conflict: {reason}"),
            Self::Integrity(reason) => write!(f, "generation integrity failure: {reason}"),
            Self::Journal(error) => write!(f, "generation journal: {error}"),
        }
    }
}

impl std::error::Error for GenerationError {}

impl From<io::Error> for GenerationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<PublicationJournalError> for GenerationError {
    fn from(error: PublicationJournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<crate::filesystem_world::FilesystemScanError> for GenerationError {
    fn from(error: crate::filesystem_world::FilesystemScanError) -> Self {
        Self::Unsupported(format!("filesystem scan refused: {error:?}"))
    }
}

fn with_mounted_images<T>(
    start_image: &Path,
    final_image: &Path,
    operation: impl FnOnce(&Path, &Path) -> Result<T, GenerationError>,
) -> Result<T, GenerationError> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| GenerationError::Invalid("system clock predates Unix epoch".into()))?
        .as_nanos();
    let temporary = std::env::temp_dir().join(format!(
        "realm-v6-generation-inputs-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&temporary)?;
    let start = temporary.join("start");
    let final_world = temporary.join("final");
    fs::create_dir(&start)?;
    fs::create_dir(&final_world)?;
    if std::env::var_os("REALM_V6_PARALLEL_GENERATION").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        // Both images are detached read-only inputs from a fully closed checked
        // execution. Join both mount outcomes before any scan or candidate copy.
        let _profile = crate::profile::Span::new("post_closure_parallel_readonly_mounts");
        let (a, b) = std::thread::scope(|scope| {
            let a = scope.spawn(|| crate::publication::mount_image(start_image, &start));
            let b = scope.spawn(|| crate::publication::mount_image(final_image, &final_world));
            (a.join(), b.join())
        });
        match (a, b) {
            (Ok(Ok(())), Ok(Ok(()))) => {}
            (a, b) => {
                // Try both cleanups even if one worker failed or panicked.
                let _ = crate::publication::unmount_image(&start);
                let _ = crate::publication::unmount_image(&final_world);
                let _ = fs::remove_dir_all(&temporary);
                return Err(GenerationError::Unsupported(format!(
                    "parallel readonly mount failed: {a:?}; {b:?}"
                )));
            }
        }
    } else {
        if let Err(error) = crate::publication::mount_image(start_image, &start) {
            let _ = fs::remove_dir_all(&temporary);
            return Err(GenerationError::Unsupported(error.to_string()));
        }
        if let Err(error) = crate::publication::mount_image(final_image, &final_world) {
            let _ = crate::publication::unmount_image(&start);
            let _ = fs::remove_dir_all(&temporary);
            return Err(GenerationError::Unsupported(error.to_string()));
        }
    }
    let result = operation(&start, &final_world);
    let final_unmount = crate::publication::unmount_image(&final_world);
    let start_unmount = crate::publication::unmount_image(&start);
    let cleanup = fs::remove_dir_all(&temporary);
    match result {
        Err(error) => {
            let _ = final_unmount;
            let _ = start_unmount;
            let _ = cleanup;
            Err(error)
        }
        Ok(value) => {
            final_unmount?;
            start_unmount?;
            cleanup?;
            Ok(value)
        }
    }
}

fn ensure_root_metadata_unchanged(start: &Path, final_world: &Path) -> Result<(), GenerationError> {
    let before = fs::symlink_metadata(start)?;
    let after = fs::symlink_metadata(final_world)?;
    if !before.is_dir()
        || !after.is_dir()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.mode() & 0o7777 != after.mode() & 0o7777
    {
        return Err(GenerationError::Unsupported(
            "accepted execution changed unmodeled workspace-root metadata".into(),
        ));
    }
    Ok(())
}

fn validate_source_profile(
    root: &Path,
    world: &crate::filesystem_world::FilesystemWorld,
) -> Result<(), GenerationError> {
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(GenerationError::Unsupported(
            "world root must be a real directory".into(),
        ));
    }
    ensure_no_xattrs(root)?;
    let root_device = root_metadata.dev();
    let root_mount_id = mount_id(root)?;
    let mut seen = std::collections::BTreeSet::new();
    validate_source_children(root, root, root_device, root_mount_id, &mut seen)?;
    if seen.len() != world.entries.len() || world.entries.keys().any(|path| !seen.contains(path)) {
        return Err(GenerationError::Invalid(
            "scanner and managed-object validation saw different trees".into(),
        ));
    }
    Ok(())
}

fn validate_source_children(
    root: &Path,
    directory: &Path,
    root_device: u64,
    root_mount_id: Option<u64>,
    seen: &mut std::collections::BTreeSet<String>,
) -> Result<(), GenerationError> {
    let mut children = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for entry in children {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| GenerationError::Invalid("tree entry escaped its root".into()))?;
        let mut components = Vec::new();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(GenerationError::Unsupported(
                    "managed paths must contain only normal components".into(),
                ));
            };
            let name = name.to_str().ok_or_else(|| {
                GenerationError::Unsupported("non-UTF8 workspace names are unsupported".into())
            })?;
            if name.contains('\\') {
                return Err(GenerationError::Unsupported(
                    "backslash-containing workspace names are unsupported".into(),
                ));
            }
            components.push(name);
        }
        let relative_text = components.join("/");
        if relative_text.is_empty() || !seen.insert(relative_text.clone()) {
            return Err(GenerationError::Unsupported(
                "empty or aliased workspace path".into(),
            ));
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.dev() != root_device {
            return Err(GenerationError::Unsupported(
                "nested filesystem or mount point in workspace".into(),
            ));
        }
        if mount_id(&path)? != root_mount_id {
            return Err(GenerationError::Unsupported(
                "nested mount or bind mount in workspace".into(),
            ));
        }
        let mode = metadata.mode() & 0o7777;
        if mode & 0o6000 != 0 {
            return Err(GenerationError::Unsupported(
                "set-user-ID and set-group-ID entries are unsupported".into(),
            ));
        }
        ensure_no_xattrs(&path)?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)?;
            if target.to_str().is_none() {
                return Err(GenerationError::Unsupported(
                    "non-UTF8 symlink targets are unsupported".into(),
                ));
            }
        } else if metadata.is_dir() {
            validate_source_children(root, &path, root_device, root_mount_id, seen)?;
        } else if metadata.is_file() {
            if metadata.nlink() != 1 {
                return Err(GenerationError::Unsupported(
                    "regular files with multiple hard links are unsupported".into(),
                ));
            }
        } else {
            return Err(GenerationError::Unsupported(format!(
                "unsupported workspace object at {relative_text}"
            )));
        }
    }
    Ok(())
}

fn validate_symlinks(
    world: &crate::filesystem_world::FilesystemWorld,
) -> Result<(), GenerationError> {
    use crate::filesystem_world::FilesystemObject;
    for (path, object) in &world.entries {
        let FilesystemObject::Symlink { target, .. } = object else {
            continue;
        };
        let target_path = Path::new(target);
        if target_path.is_absolute() {
            return Err(GenerationError::Unsupported(
                "absolute symlink targets are unsupported".into(),
            ));
        }
        let mut resolved = path
            .rsplit_once('/')
            .map(|(parent, _)| parent.split('/').map(str::to_string).collect::<Vec<_>>())
            .unwrap_or_default();
        for component in target_path.components() {
            match component {
                Component::Normal(name) => resolved.push(
                    name.to_str()
                        .ok_or_else(|| {
                            GenerationError::Unsupported(
                                "non-UTF8 symlink targets are unsupported".into(),
                            )
                        })?
                        .to_string(),
                ),
                Component::CurDir => {}
                Component::ParentDir if !resolved.is_empty() => {
                    resolved.pop();
                }
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(GenerationError::Unsupported(
                        "symlink target escapes the managed workspace".into(),
                    ));
                }
            }
        }
        let mut prefix = String::new();
        for component in &resolved {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            if matches!(
                world.entries.get(&prefix),
                Some(FilesystemObject::Symlink { .. })
            ) {
                return Err(GenerationError::Unsupported(
                    "symlink chains and symlink path components are unsupported".into(),
                ));
            }
        }
    }
    Ok(())
}

fn create_generation_directory(path: &Path) -> Result<(), GenerationError> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.gid() != unsafe { libc::getegid() }
    {
        return Err(GenerationError::Unsupported(
            "new generation root has unexpected ownership".into(),
        ));
    }
    ensure_no_xattrs(path)?;
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), GenerationError> {
    let _profile = crate::profile::Span::new("generation_file_copy");
    let mut children = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for entry in children {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&source_path)?;
            std::os::unix::fs::symlink(target, &destination_path)?;
        } else if metadata.is_dir() {
            fs::create_dir(&destination_path)?;
            fs::set_permissions(&destination_path, fs::Permissions::from_mode(0o700))?;
            copy_tree(&source_path, &destination_path)?;
            fs::set_permissions(
                &destination_path,
                fs::Permissions::from_mode(metadata.mode() & 0o7777),
            )?;
            sync_directory(&destination_path)?;
        } else if metadata.is_file() {
            let mut input = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&source_path)?;
            if !input.metadata()?.is_file() {
                return Err(GenerationError::Invalid(
                    "source object changed type during materialization".into(),
                ));
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&destination_path)?;
            let copied = io::copy(&mut input, &mut output)?;
            crate::profile::bytes("generation_file_copy", "copied_logical", copied);
            fs::set_permissions(
                &destination_path,
                fs::Permissions::from_mode(metadata.mode() & 0o7777),
            )?;
            output.sync_all_traced()?;
        } else {
            return Err(GenerationError::Unsupported(
                "unsupported object appeared during materialization".into(),
            ));
        }
    }
    sync_directory(destination)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_no_xattrs(path: &Path) -> Result<(), GenerationError> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| GenerationError::Invalid("filesystem path contains NUL".into()))?;
    let count = unsafe { libc::llistxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };
    if count == 0 {
        return Ok(());
    }
    if count < 0 {
        let error = io::Error::last_os_error();
        if error
            .raw_os_error()
            .is_some_and(|code| code == libc::ENOTSUP || code == libc::EOPNOTSUPP)
        {
            return Ok(());
        }
        return Err(error.into());
    }
    Err(GenerationError::Unsupported(
        "extended attributes and ACLs are outside the managed semantic profile".into(),
    ))
}

#[cfg(target_os = "linux")]
fn mount_id(path: &Path) -> Result<Option<u64>, GenerationError> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| GenerationError::Invalid("filesystem path contains NUL".into()))?;
    let mut stat = MaybeUninit::<libc::statx>::zeroed();
    let result = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_MNT_ID,
            stat.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(GenerationError::Unsupported(format!(
            "filesystem mount identity query failed: {}",
            io::Error::last_os_error()
        )));
    }
    let stat = unsafe { stat.assume_init() };
    if stat.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(GenerationError::Unsupported(
            "kernel or filesystem does not report statx mount identity".into(),
        ));
    }
    Ok(Some(stat.stx_mnt_id))
}

#[cfg(not(target_os = "linux"))]
fn mount_id(_path: &Path) -> Result<Option<u64>, GenerationError> {
    Ok(None)
}

#[cfg(not(target_os = "linux"))]
fn ensure_no_xattrs(_path: &Path) -> Result<(), GenerationError> {
    Ok(())
}

fn crash_at(point: &str) {
    if std::env::var("REALM_PUBLICATION_CRASH_AT").ok().as_deref() == Some(point) {
        std::process::abort();
    }
}

fn digest<T: Serialize>(value: &T) -> Result<String, GenerationError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| GenerationError::Invalid("identity encoding failed".into()))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn absolute_path(path: &Path) -> Result<PathBuf, GenerationError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn validate_no_symlink_ancestors(path: &Path) -> Result<(), GenerationError> {
    if !path.is_absolute() {
        return Err(GenerationError::Invalid(
            "parent path must be absolute".into(),
        ));
    }
    let mut current = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                if name.to_str().is_none() {
                    return Err(GenerationError::Unsupported(
                        "workspace path components must be UTF-8".into(),
                    ));
                }
                current.push(name);
                let metadata = fs::symlink_metadata(&current)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(GenerationError::Unsupported(
                        "workspace ancestors must be real directories without symlinks".into(),
                    ));
                }
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(GenerationError::Invalid(
                    "workspace path must not contain parent traversal".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_managed_directory(metadata: &fs::Metadata, label: &str) -> Result<(), GenerationError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GenerationError::Unsupported(format!(
            "{label} must be a real directory"
        )));
    }
    Ok(())
}

fn validate_private_mode(mode: u32, label: &str) -> Result<(), GenerationError> {
    if mode & 0o022 != 0 {
        return Err(GenerationError::Unsupported(format!(
            "{label} is writable by group or other users"
        )));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), GenerationError> {
    fs::File::open(path)?.sync_all_traced()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn root(label: &str) -> PathBuf {
        let base = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "realm-generation-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        base
    }

    fn checked_publication_capability() -> CheckedExecutionForPublication {
        crate::execute::test_checked_execution(
            "run-test",
            &"8".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
            &"3".repeat(64),
        )
    }

    struct TreeFixture {
        parent: PathBuf,
        live: PathBuf,
        layout: GenerationLayout,
        identity: GenerationIdentity,
    }

    fn tree_fixture(label: &str) -> TreeFixture {
        let parent = root(label);
        let live = parent.join("workspace");
        let final_tree = parent.join("accepted-final");
        fs::create_dir(&live).unwrap();
        fs::create_dir(&final_tree).unwrap();
        fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&final_tree, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(live.join("target.txt"), b"S0 bytes").unwrap();
        fs::write(final_tree.join("target.txt"), b"S1 bytes").unwrap();
        fs::write(final_tree.join("created.txt"), b"second effect").unwrap();

        let before = crate::filesystem_world::scan_directory(&live).unwrap();
        let after = crate::filesystem_world::scan_directory(&final_tree).unwrap();
        let delta = crate::filesystem_world::delta(&before, &after);
        let delta_root = blake3::hash(&serde_json::to_vec(&delta).unwrap())
            .to_hex()
            .to_string();
        let execution = crate::execute::test_checked_execution(
            "run-test",
            &"8".repeat(64),
            &before.root,
            &after.root,
            &delta_root,
        );
        let layout = GenerationLayout::inspect(&live).unwrap();
        let identity =
            GenerationIdentity::from_publication_capability(&execution, &layout).unwrap();
        layout.ensure_control_root().unwrap();
        let candidate = layout.generation_path(&identity).unwrap();
        create_generation_directory(&candidate).unwrap();
        copy_tree(&final_tree, &candidate).unwrap();
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
        sync_directory(&candidate).unwrap();
        sync_directory(&parent).unwrap();
        TreeFixture {
            parent,
            live,
            layout,
            identity,
        }
    }

    fn journal_through_prepared(fixture: &TreeFixture, through_commit: bool) {
        let mut journal = PublicationJournal::open(fixture.layout.journal_path()).unwrap();
        journal
            .record_generation_state(
                &fixture.identity,
                PublicationState::GenerationPreparing,
                None,
                None,
                None,
            )
            .unwrap();
        journal
            .record_generation_state(
                &fixture.identity,
                PublicationState::GenerationPrepared,
                None,
                None,
                None,
            )
            .unwrap();
        if through_commit {
            journal
                .record_generation_state(
                    &fixture.identity,
                    PublicationState::CommitIntent,
                    None,
                    None,
                    None,
                )
                .unwrap();
            journal
                .record_generation_state(
                    &fixture.identity,
                    PublicationState::CommitInProgress,
                    None,
                    None,
                    None,
                )
                .unwrap();
        }
    }

    #[test]
    fn identity_is_derived_from_the_checked_binding_and_workspace() {
        let parent = root("identity");
        let live = parent.join("workspace");
        fs::create_dir(&live).unwrap();
        fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).unwrap();
        let layout = GenerationLayout::inspect(&live).unwrap();
        let identity = GenerationIdentity::from_publication_capability(
            &checked_publication_capability(),
            &layout,
        )
        .unwrap();
        identity.validate_integrity().unwrap();
        assert_eq!(identity.accepted_start_root(), &"1".repeat(64));
        assert_eq!(identity.accepted_final_root(), &"2".repeat(64));
        assert_eq!(identity.accepted_delta_root(), &"3".repeat(64));
        assert_eq!(identity.workspace_identity(), layout.workspace_identity());
        assert_ne!(identity.generation_id(), identity.publication_id());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn layout_refuses_a_symlink_live_root() {
        let parent = root("symlink");
        let live = parent.join("workspace");
        let target = parent.join("target");
        fs::create_dir(&target).unwrap();
        symlink(&target, &live).unwrap();
        assert!(GenerationLayout::inspect(&live).is_err());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn layout_refuses_group_or_other_writable_roots() {
        let parent = root("permissions");
        let live = parent.join("workspace");
        fs::create_dir(&live).unwrap();
        fs::set_permissions(&live, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(GenerationLayout::inspect(&live).is_err());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn workspace_identity_survives_live_generation_replacement() {
        let parent = root("stable-workspace-id");
        let live = parent.join("workspace");
        let old = parent.join("previous");
        fs::create_dir(&live).unwrap();
        fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).unwrap();
        let first = GenerationLayout::inspect(&live).unwrap();
        fs::rename(&live, &old).unwrap();
        fs::create_dir(&live).unwrap();
        fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).unwrap();
        let second = GenerationLayout::inspect(&live).unwrap();
        assert_eq!(first.workspace_identity(), second.workspace_identity());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn control_directory_is_created_private_and_durable() {
        let parent = root("control");
        let live = parent.join("workspace");
        fs::create_dir(&live).unwrap();
        fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).unwrap();
        let layout = GenerationLayout::inspect(&live).unwrap();
        layout.ensure_control_root().unwrap();
        let metadata = fs::symlink_metadata(layout.control_root()).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn materialization_preserves_the_supported_semantic_tree() {
        use std::os::unix::fs::symlink;

        let parent = root("materialize");
        let source = parent.join("source");
        let candidate = parent.join("candidate");
        fs::create_dir(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(source.join("nested")).unwrap();
        fs::set_permissions(source.join("nested"), fs::Permissions::from_mode(0o750)).unwrap();
        fs::write(source.join("nested/data"), b"accepted bytes").unwrap();
        fs::set_permissions(
            source.join("nested/data"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        symlink("nested/data", source.join("link")).unwrap();
        let expected = crate::filesystem_world::scan_directory(&source).unwrap();
        validate_source_profile(&source, &expected).unwrap();
        validate_symlinks(&expected).unwrap();

        create_generation_directory(&candidate).unwrap();
        copy_tree(&source, &candidate).unwrap();
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            crate::filesystem_world::scan_directory(&candidate)
                .unwrap()
                .root,
            expected.root
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn unsupported_hardlinks_and_escaping_symlinks_refuse_materialization() {
        use std::os::unix::fs::symlink;

        let parent = root("unsupported-links");
        let linked = parent.join("linked");
        fs::create_dir(&linked).unwrap();
        fs::write(linked.join("one"), b"same inode").unwrap();
        fs::hard_link(linked.join("one"), linked.join("two")).unwrap();
        let hardlink_world = crate::filesystem_world::scan_directory(&linked).unwrap();
        assert!(validate_source_profile(&linked, &hardlink_world).is_err());

        let escaping = parent.join("escaping");
        fs::create_dir(&escaping).unwrap();
        symlink("../outside", escaping.join("link")).unwrap();
        let symlink_world = crate::filesystem_world::scan_directory(&escaping).unwrap();
        validate_source_profile(&escaping, &symlink_world).unwrap();
        assert!(validate_symlinks(&symlink_world).is_err());

        let chained = parent.join("chained");
        fs::create_dir(&chained).unwrap();
        fs::write(chained.join("file"), b"inside").unwrap();
        symlink("file", chained.join("first")).unwrap();
        symlink("first", chained.join("second")).unwrap();
        let chained_world = crate::filesystem_world::scan_directory(&chained).unwrap();
        assert!(validate_symlinks(&chained_world).is_err());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn unmodeled_root_metadata_change_refuses() {
        let parent = root("root-metadata");
        let start = parent.join("start");
        let final_world = parent.join("final");
        fs::create_dir(&start).unwrap();
        fs::create_dir(&final_world).unwrap();
        fs::set_permissions(&start, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&final_world, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(ensure_root_metadata_unchanged(&start, &final_world).is_err());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn precommit_recovery_interrupts_once_and_preserves_s0() {
        let fixture = tree_fixture("precommit-recovery");
        journal_through_prepared(&fixture, false);
        let first = recover_generation(&fixture.live).unwrap();
        assert!(matches!(first, GenerationRecovery::Interrupted { .. }));
        assert_eq!(
            crate::filesystem_world::scan_directory(&fixture.live)
                .unwrap()
                .root,
            fixture.identity.accepted_start_root()
        );
        let journal_text = fs::read_to_string(fixture.layout.journal_path()).unwrap();
        let line_count = journal_text.lines().count();
        let second = recover_generation(&fixture.live).unwrap();
        assert!(matches!(second, GenerationRecovery::Interrupted { .. }));
        assert_eq!(
            fs::read_to_string(fixture.layout.journal_path())
                .unwrap()
                .lines()
                .count(),
            line_count
        );
        fs::remove_dir_all(fixture.parent).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_finishes_only_when_live_s1_and_previous_s0_prove_exchange() {
        let fixture = tree_fixture("postexchange-recovery");
        journal_through_prepared(&fixture, true);
        let candidate = fixture.layout.generation_path(&fixture.identity).unwrap();
        exchange_siblings(&fixture.layout, &candidate).unwrap();
        sync_directory(&fixture.parent).unwrap();

        let recovered = recover_generation(&fixture.live).unwrap();
        let GenerationRecovery::Published(receipt) = recovered else {
            panic!("recovery did not finish a proven exchange");
        };
        assert_eq!(receipt.live_root, fixture.identity.accepted_final_root());
        assert_eq!(
            receipt.previous_root,
            fixture.identity.accepted_start_root()
        );
        assert_eq!(
            crate::filesystem_world::scan_directory(&fixture.live)
                .unwrap()
                .root,
            fixture.identity.accepted_final_root()
        );
        assert_eq!(
            crate::filesystem_world::scan_directory(&candidate)
                .unwrap()
                .root,
            fixture.identity.accepted_start_root()
        );
        assert!(matches!(
            recover_generation(&fixture.live).unwrap(),
            GenerationRecovery::AlreadyPublished(_)
        ));
        let journal = PublicationJournal::open(fixture.layout.journal_path()).unwrap();
        assert_eq!(
            journal.generation_records_for_workspace(fixture.layout.workspace_identity())[0].state,
            PublicationState::Published
        );
        fs::remove_dir_all(fixture.parent).unwrap();
    }

    #[test]
    fn recovery_marks_neither_s0_nor_s1_as_integrity_failure() {
        let fixture = tree_fixture("unexpected-live-root");
        journal_through_prepared(&fixture, true);
        fs::write(fixture.live.join("target.txt"), b"third world").unwrap();
        assert!(matches!(
            recover_generation(&fixture.live),
            Err(GenerationError::Integrity(_))
        ));
        let journal = PublicationJournal::open(fixture.layout.journal_path()).unwrap();
        assert_eq!(
            journal.generation_records_for_workspace(fixture.layout.workspace_identity())[0].state,
            PublicationState::IntegrityFailure
        );
        assert!(matches!(
            recover_generation(&fixture.live),
            Err(GenerationError::Integrity(_))
        ));
        fs::remove_dir_all(fixture.parent).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn commit_exchanges_whole_tree_and_persists_bound_receipt() {
        let fixture = tree_fixture("commit-generation");
        journal_through_prepared(&fixture, false);
        let candidate = fixture.layout.generation_path(&fixture.identity).unwrap();
        let lock = DestinationLock::acquire(&fixture.live).unwrap();
        let prepared = PreparedGeneration {
            identity: fixture.identity.clone(),
            layout: fixture.layout.clone(),
            candidate_root: candidate.clone(),
            accepted_final_root: fixture.identity.accepted_final_root().into(),
            journal_path: fixture.layout.journal_path(),
            _lock: lock,
        };
        let receipt = commit_generation(prepared).unwrap();
        assert_eq!(receipt.live_root, fixture.identity.accepted_final_root());
        assert_eq!(
            receipt.previous_root,
            fixture.identity.accepted_start_root()
        );
        assert!(receipt_path(&fixture.layout, &fixture.identity).is_file());
        let journal = PublicationJournal::open(fixture.layout.journal_path()).unwrap();
        assert_eq!(
            journal.generation_records_for_workspace(fixture.layout.workspace_identity())[0].state,
            PublicationState::Published
        );
        assert!(matches!(
            recover_generation(&fixture.live).unwrap(),
            GenerationRecovery::AlreadyPublished(_)
        ));
        fs::remove_dir_all(fixture.parent).unwrap();
    }
}
