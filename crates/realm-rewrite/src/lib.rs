//! Evidence-bounded semantic adapters for Phase IV history rewrite.
//!
//! Adapters are deliberately narrow. Each response names its version and
//! support envelope; conflict and unsupported are first-class results. A clean
//! adapter result is evidence for a deterministic transformation, not proof of
//! arbitrary application semantics.

use rusqlite::{
    Connection,
    session::{ConflictAction, Session},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Component, Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub const STRUCTURED_JSON_ADAPTER_VERSION: &str = "realm-structured-json/v1";
pub const STRUCTURED_TOML_ADAPTER_VERSION: &str = "realm-flat-toml/v1";
pub const GIT_TREE_ADAPTER_VERSION: &str = "realm-git-merge-tree/v1";
pub const SQLITE_SESSION_ADAPTER_VERSION: &str = "realm-sqlite-session/v1";
pub const COUNTERFACTUAL_PROBE_VERSION: &str = "realm-counterfactual-probe/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdapterStatus {
    Applied,
    Conflict,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdapterConflict {
    pub location: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdapterEvidence {
    pub adapter: String,
    pub version: String,
    pub input_hashes: BTreeMap<String, String>,
    pub output_hash: Option<String>,
    pub support_envelope: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StructuredRebaseResponse {
    pub status: AdapterStatus,
    pub value: Option<Value>,
    pub conflicts: Vec<AdapterConflict>,
    pub evidence: AdapterEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TextRebaseResponse {
    pub status: AdapterStatus,
    pub text: Option<String>,
    pub conflicts: Vec<AdapterConflict>,
    pub evidence: AdapterEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitTreeRebaseResponse {
    pub status: AdapterStatus,
    pub tree_oid: Option<String>,
    pub files: BTreeMap<String, Vec<u8>>,
    pub conflicts: Vec<AdapterConflict>,
    pub evidence: AdapterEvidence,
    pub git_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SqliteRebaseResponse {
    pub status: AdapterStatus,
    pub output_path: Option<PathBuf>,
    pub conflicts: Vec<AdapterConflict>,
    pub integrity_check: Option<String>,
    pub foreign_key_violations: usize,
    pub evidence: AdapterEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CounterfactualProbeDecision {
    StabilizedIndependentOutput,
    ChangedOutput,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CounterfactualProbeResult {
    pub schema_version: u16,
    pub version: String,
    pub decision: CounterfactualProbeDecision,
    pub observed_repetitions: usize,
    pub counterfactual_repetitions: usize,
    pub observed_output_hash: Option<String>,
    pub counterfactual_output_hash: Option<String>,
    pub evidence_class: String,
    pub limitation: String,
}

#[derive(Debug, Error)]
pub enum RewriteAdapterError {
    #[error("adapter I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("adapter JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("SQLite adapter error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Git adapter setup failed: {0}")]
    Git(String),
    #[error("unsafe adapter path: {0}")]
    UnsafePath(String),
}

/// Compare repeated deterministic outputs under observed and counterfactual
/// inputs. Equality can stabilize one suspected dependency for the tested
/// transformation; it is not promoted to general causal independence.
pub fn evaluate_counterfactual_probe(
    observed_outputs: &[Vec<u8>],
    counterfactual_outputs: &[Vec<u8>],
) -> CounterfactualProbeResult {
    let stable_hash = |outputs: &[Vec<u8>]| {
        let hashes = outputs
            .iter()
            .map(|output| hash_bytes(output))
            .collect::<BTreeSet<_>>();
        (hashes.len() == 1)
            .then(|| hashes.into_iter().next())
            .flatten()
    };
    let observed_output_hash = stable_hash(observed_outputs);
    let counterfactual_output_hash = stable_hash(counterfactual_outputs);
    let decision = match (&observed_output_hash, &counterfactual_output_hash) {
        (Some(observed), Some(counterfactual)) if observed == counterfactual => {
            CounterfactualProbeDecision::StabilizedIndependentOutput
        }
        (Some(_), Some(_)) => CounterfactualProbeDecision::ChangedOutput,
        _ => CounterfactualProbeDecision::Indeterminate,
    };
    CounterfactualProbeResult {
        schema_version: 1,
        version: COUNTERFACTUAL_PROBE_VERSION.into(),
        decision,
        observed_repetitions: observed_outputs.len(),
        counterfactual_repetitions: counterfactual_outputs.len(),
        observed_output_hash,
        counterfactual_output_hash,
        evidence_class: "COUNTERFACTUALLY_SUPPORTED".into(),
        limitation: "Result applies only to the tested deterministic transformation and inputs; it does not prove general causal independence."
            .into(),
    }
}

/// Transplant the structured change from `observed_target` to
/// `observed_today` onto `replacement`. Objects are merged by JSON Pointer.
/// Arrays and scalar values are atomic: divergent edits conflict.
pub fn rebase_json(
    observed_target: &Value,
    replacement: &Value,
    observed_today: &Value,
) -> StructuredRebaseResponse {
    let mut output = replacement.clone();
    let mut conflicts = Vec::new();
    merge_json_value(
        "",
        observed_target,
        replacement,
        observed_today,
        &mut output,
        &mut conflicts,
    );
    let status = if conflicts.is_empty() {
        AdapterStatus::Applied
    } else {
        AdapterStatus::Conflict
    };
    let value = (status == AdapterStatus::Applied).then_some(output);
    let mut input_hashes = BTreeMap::new();
    input_hashes.insert("observed_target".into(), hash_json(observed_target));
    input_hashes.insert("replacement".into(), hash_json(replacement));
    input_hashes.insert("observed_today".into(), hash_json(observed_today));
    let output_hash = value.as_ref().map(hash_json);
    StructuredRebaseResponse {
        status,
        value,
        conflicts,
        evidence: AdapterEvidence {
            adapter: "structured-json".into(),
            version: STRUCTURED_JSON_ADAPTER_VERSION.into(),
            input_hashes,
            output_hash,
            support_envelope: "JSON objects merge recursively by key; arrays and scalars are atomic; divergent same-pointer edits conflict."
                .into(),
        },
    }
}

fn merge_json_value(
    pointer: &str,
    base: &Value,
    replacement: &Value,
    future: &Value,
    output: &mut Value,
    conflicts: &mut Vec<AdapterConflict>,
) {
    if future == base {
        return;
    }
    if replacement == base || replacement == future {
        *output = future.clone();
        return;
    }
    match (base, replacement, future, output) {
        (
            Value::Object(base),
            Value::Object(replacement),
            Value::Object(future),
            Value::Object(output),
        ) => {
            let keys = base
                .keys()
                .chain(replacement.keys())
                .chain(future.keys())
                .cloned()
                .collect::<BTreeSet<_>>();
            for key in keys {
                let child_pointer = format!("{}/{}", pointer, escape_json_pointer(&key));
                let base_value = base.get(&key).unwrap_or(&Value::Null);
                let replacement_value = replacement.get(&key).unwrap_or(&Value::Null);
                let future_value = future.get(&key).unwrap_or(&Value::Null);
                let mut child_output = replacement_value.clone();
                merge_json_value(
                    &child_pointer,
                    base_value,
                    replacement_value,
                    future_value,
                    &mut child_output,
                    conflicts,
                );
                let replacement_has = replacement.contains_key(&key);
                let future_has = future.contains_key(&key);
                let base_has = base.contains_key(&key);
                if conflicts
                    .last()
                    .is_some_and(|conflict| conflict.location == child_pointer)
                {
                    continue;
                }
                if !future_has && base_has && replacement_has && replacement_value == base_value {
                    output.remove(&key);
                } else if future_has || replacement_has {
                    output.insert(key, child_output);
                }
            }
        }
        _ => conflicts.push(AdapterConflict {
            location: if pointer.is_empty() {
                "/".into()
            } else {
                pointer.into()
            },
            reason: "replacement and observed future diverge from the same atomic base value"
                .into(),
        }),
    }
}

fn escape_json_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn hash_json(value: &Value) -> String {
    blake3::hash(&serde_json::to_vec(value).expect("JSON value serializes"))
        .to_hex()
        .to_string()
}

/// Conservative TOML subset: section headers and scalar `key = value` pairs.
/// Comments, arrays, inline tables, duplicate keys, and dotted keys are
/// unsupported rather than guessed.
pub fn rebase_flat_toml(
    observed_target: &str,
    replacement: &str,
    observed_today: &str,
) -> TextRebaseResponse {
    let parsed = (
        parse_flat_toml(observed_target),
        parse_flat_toml(replacement),
        parse_flat_toml(observed_today),
    );
    let (base, replacement_map, future) = match parsed {
        (Ok(base), Ok(replacement), Ok(future)) => (base, replacement, future),
        _ => {
            return text_response(
                AdapterStatus::Unsupported,
                None,
                vec![AdapterConflict {
                    location: "document".into(),
                    reason: "document is outside the flat scalar TOML support envelope".into(),
                }],
                observed_target,
                replacement,
                observed_today,
            );
        }
    };
    let mut output = replacement_map.clone();
    let mut conflicts = Vec::new();
    let keys = base
        .keys()
        .chain(replacement_map.keys())
        .chain(future.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    for key in keys {
        let base_value = base.get(&key);
        let replacement_value = replacement_map.get(&key);
        let future_value = future.get(&key);
        if future_value == base_value {
            continue;
        }
        if replacement_value == base_value || replacement_value == future_value {
            match future_value {
                Some(value) => {
                    output.insert(key, value.clone());
                }
                None => {
                    output.remove(&key);
                }
            }
        } else {
            conflicts.push(AdapterConflict {
                location: key,
                reason: "replacement and observed future diverge from the same TOML scalar".into(),
            });
        }
    }
    if conflicts.is_empty() {
        text_response(
            AdapterStatus::Applied,
            Some(render_flat_toml(&output)),
            conflicts,
            observed_target,
            replacement,
            observed_today,
        )
    } else {
        text_response(
            AdapterStatus::Conflict,
            None,
            conflicts,
            observed_target,
            replacement,
            observed_today,
        )
    }
}

fn parse_flat_toml(input: &str) -> Result<BTreeMap<String, String>, ()> {
    let mut section = String::new();
    let mut values = BTreeMap::new();
    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#')
            || line.contains('[') && !line.starts_with('[')
            || line.contains('{')
            || line.contains('#')
        {
            return Err(());
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_owned();
            if section.is_empty() || section.contains('.') {
                return Err(());
            }
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(())?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty()
            || key.contains('.')
            || value.is_empty()
            || value.starts_with('[')
            || value.starts_with('{')
        {
            return Err(());
        }
        let full_key = if section.is_empty() {
            key.to_owned()
        } else {
            format!("{section}.{key}")
        };
        if values.insert(full_key, value.to_owned()).is_some() {
            return Err(());
        }
    }
    Ok(values)
}

fn render_flat_toml(values: &BTreeMap<String, String>) -> String {
    let mut roots = Vec::new();
    let mut sections: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (key, value) in values {
        if let Some((section, key)) = key.split_once('.') {
            sections
                .entry(section.into())
                .or_default()
                .push((key.into(), value.clone()));
        } else {
            roots.push((key.clone(), value.clone()));
        }
    }
    let mut output = String::new();
    for (key, value) in roots {
        output.push_str(&format!("{key} = {value}\n"));
    }
    for (section, entries) in sections {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&format!("[{section}]\n"));
        for (key, value) in entries {
            output.push_str(&format!("{key} = {value}\n"));
        }
    }
    output
}

fn text_response(
    status: AdapterStatus,
    text: Option<String>,
    conflicts: Vec<AdapterConflict>,
    observed_target: &str,
    replacement: &str,
    observed_today: &str,
) -> TextRebaseResponse {
    let mut input_hashes = BTreeMap::new();
    input_hashes.insert(
        "observed_target".into(),
        hash_bytes(observed_target.as_bytes()),
    );
    input_hashes.insert("replacement".into(), hash_bytes(replacement.as_bytes()));
    input_hashes.insert(
        "observed_today".into(),
        hash_bytes(observed_today.as_bytes()),
    );
    let output_hash = text.as_ref().map(|text| hash_bytes(text.as_bytes()));
    TextRebaseResponse {
        status,
        text,
        conflicts,
        evidence: AdapterEvidence {
            adapter: "flat-toml".into(),
            version: STRUCTURED_TOML_ADAPTER_VERSION.into(),
            input_hashes,
            output_hash,
            support_envelope: "Scalar key/value pairs and one-level section headers only; arrays, inline tables, dotted keys, comments, and duplicates are unsupported."
                .into(),
        },
    }
}

/// Run Git's real three-way tree merge with the old target tree forced as the
/// merge base, thereby transplanting the observed future onto the replacement
/// without reading or mutating the caller's repository.
pub fn rebase_git_tree(
    observed_target: &BTreeMap<String, Vec<u8>>,
    replacement: &BTreeMap<String, Vec<u8>>,
    observed_today: &BTreeMap<String, Vec<u8>>,
) -> Result<GitTreeRebaseResponse, RewriteAdapterError> {
    validate_file_map(observed_target)?;
    validate_file_map(replacement)?;
    validate_file_map(observed_today)?;
    let root = std::env::temp_dir().join(format!(
        "realm-git-adapter-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&root)?;
    let outcome = git_rebase_in(&root, observed_target, replacement, observed_today);
    let cleanup = fs::remove_dir_all(&root);
    let response = outcome?;
    cleanup?;
    Ok(response)
}

fn git_rebase_in(
    root: &Path,
    observed_target: &BTreeMap<String, Vec<u8>>,
    replacement: &BTreeMap<String, Vec<u8>>,
    observed_today: &BTreeMap<String, Vec<u8>>,
) -> Result<GitTreeRebaseResponse, RewriteAdapterError> {
    git(root, &["init", "--quiet"])?;
    write_file_map(root, observed_target)?;
    git(root, &["add", "--all"])?;
    git(
        root,
        &[
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "observed-target",
        ],
    )?;
    let target = git(root, &["rev-parse", "HEAD"])?;
    write_file_map(root, observed_today)?;
    git(root, &["add", "--all"])?;
    git(
        root,
        &["commit", "--quiet", "--allow-empty", "-m", "observed-today"],
    )?;
    let today = git(root, &["rev-parse", "HEAD"])?;
    git(root, &["checkout", "--quiet", "--detach", &target])?;
    write_file_map(root, replacement)?;
    git(root, &["add", "--all"])?;
    git(
        root,
        &["commit", "--quiet", "--allow-empty", "-m", "replacement"],
    )?;
    let replacement_commit = git(root, &["rev-parse", "HEAD"])?;
    // Both commits are constructed as direct children of `target`. Verify
    // Git's computed merge base before invoking merge-tree. Debian's Git 2.39
    // does not support merge-tree's newer --merge-base option, and omitting
    // that option is equivalent here only because this check proves the exact
    // intended base.
    let merge_base = git(root, &["merge-base", &replacement_commit, &today])?;
    if merge_base != target {
        return Err(RewriteAdapterError::Git(format!(
            "unexpected merge base: expected {target}, got {merge_base}"
        )));
    }
    let output = git_raw(
        root,
        &["merge-tree", "--write-tree", &replacement_commit, &today],
    )?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let tree_oid = stdout
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let status = if output.status.success() {
        AdapterStatus::Applied
    } else if output.status.code() == Some(1) {
        AdapterStatus::Conflict
    } else {
        return Err(RewriteAdapterError::Git(format!(
            "git merge-tree exited {:?}: {}{}",
            output.status.code(),
            stdout,
            String::from_utf8_lossy(&output.stderr)
        )));
    };
    let files = if status == AdapterStatus::Applied {
        read_git_tree(root, tree_oid.expect("clean merge writes a tree"))?
    } else {
        BTreeMap::new()
    };
    let conflicts = if status == AdapterStatus::Conflict {
        vec![AdapterConflict {
            location: "git-tree".into(),
            reason: stdout.trim().to_owned(),
        }]
    } else {
        Vec::new()
    };
    let mut input_hashes = BTreeMap::new();
    input_hashes.insert("observed_target".into(), hash_file_map(observed_target));
    input_hashes.insert("replacement".into(), hash_file_map(replacement));
    input_hashes.insert("observed_today".into(), hash_file_map(observed_today));
    Ok(GitTreeRebaseResponse {
        status,
        tree_oid: tree_oid.map(str::to_owned),
        files: files.clone(),
        conflicts,
        evidence: AdapterEvidence {
            adapter: "git-merge-tree".into(),
            version: GIT_TREE_ADAPTER_VERSION.into(),
            input_hashes,
            output_hash: (status == AdapterStatus::Applied).then(|| hash_file_map(&files)),
            support_envelope: "Git three-way content/tree merge in isolated objects with observed target forced as merge base; clean merge is not semantic proof."
                .into(),
        },
        git_version: git(root, &["--version"])? ,
    })
}

fn git(root: &Path, args: &[&str]) -> Result<String, RewriteAdapterError> {
    let output = git_raw(root, args)?;
    if !output.status.success() {
        return Err(RewriteAdapterError::Git(format!(
            "git {} exited {:?}: {}{}",
            args.join(" "),
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn git_raw(root: &Path, args: &[&str]) -> Result<std::process::Output, RewriteAdapterError> {
    Ok(Command::new("git")
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Realm Adapter")
        .env("GIT_AUTHOR_EMAIL", "realm@invalid")
        .env("GIT_COMMITTER_NAME", "Realm Adapter")
        .env("GIT_COMMITTER_EMAIL", "realm@invalid")
        .output()?)
}

fn validate_file_map(files: &BTreeMap<String, Vec<u8>>) -> Result<(), RewriteAdapterError> {
    for path in files.keys() {
        let path = Path::new(path);
        if path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
            || path.as_os_str().is_empty()
        {
            return Err(RewriteAdapterError::UnsafePath(path.display().to_string()));
        }
    }
    Ok(())
}

fn write_file_map(
    root: &Path,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), RewriteAdapterError> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_name() == ".git" {
            continue;
        }
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    for (path, bytes) in files {
        let path = root.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, bytes)?;
    }
    Ok(())
}

fn read_git_tree(
    root: &Path,
    tree_oid: &str,
) -> Result<BTreeMap<String, Vec<u8>>, RewriteAdapterError> {
    let names = git(root, &["ls-tree", "-r", "--name-only", tree_oid])?;
    let mut files = BTreeMap::new();
    for name in names.lines().filter(|line| !line.is_empty()) {
        let output = git_raw(root, &["show", &format!("{tree_oid}:{name}")])?;
        if !output.status.success() {
            return Err(RewriteAdapterError::Git(format!(
                "could not read merged tree path {name}"
            )));
        }
        files.insert(name.to_owned(), output.stdout);
    }
    Ok(files)
}

fn hash_file_map(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut hasher = blake3::Hasher::new();
    for (path, bytes) in files {
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().to_hex().to_string()
}

fn hash_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Capture a deterministic SQLite Session changeset while executing `mutate`.
/// Only tables explicitly named by the caller are attached.
pub fn capture_sqlite_changeset<F>(
    connection: &Connection,
    tables: &[&str],
    mutate: F,
) -> Result<Vec<u8>, RewriteAdapterError>
where
    F: FnOnce(&Connection) -> rusqlite::Result<()>,
{
    let mut session = Session::new(connection)?;
    for table in tables {
        session.attach(Some(*table))?;
    }
    mutate(connection)?;
    let mut bytes = Vec::new();
    session.changeset_strm(&mut bytes)?;
    Ok(bytes)
}

/// Apply a replacement changeset and then an observed-future changeset to a
/// byte copy of the base database. Any Session conflict aborts; the adapter
/// never chooses OMIT or REPLACE on the caller's behalf.
pub fn rebase_sqlite_session(
    base_path: &Path,
    replacement_changeset: &[u8],
    future_changeset: &[u8],
    output_path: &Path,
) -> Result<SqliteRebaseResponse, RewriteAdapterError> {
    if output_path.exists() {
        return Err(RewriteAdapterError::UnsafePath(format!(
            "output already exists: {}",
            output_path.display()
        )));
    }
    fs::copy(base_path, output_path)?;
    let connection = Connection::open(output_path)?;
    connection.execute_batch("PRAGMA foreign_keys=ON; BEGIN IMMEDIATE;")?;
    let conflicts = Arc::new(Mutex::new(Vec::<AdapterConflict>::new()));
    let apply_one = |bytes: &[u8], label: &'static str| -> rusqlite::Result<()> {
        let recorded = Arc::clone(&conflicts);
        let mut input = bytes;
        connection.apply_strm(
            &mut input,
            None::<fn(&str) -> bool>,
            move |conflict_type, _item| {
                recorded
                    .lock()
                    .expect("conflict mutex poisoned")
                    .push(AdapterConflict {
                        location: label.into(),
                        reason: format!("SQLite Session conflict: {conflict_type:?}"),
                    });
                ConflictAction::SQLITE_CHANGESET_ABORT
            },
        )
    };
    let apply_result = apply_one(replacement_changeset, "replacement")
        .and_then(|_| apply_one(future_changeset, "observed-future"));
    if apply_result.is_err() {
        let _ = connection.execute_batch("ROLLBACK;");
        drop(connection);
        let _ = fs::remove_file(output_path);
        let conflicts = Arc::try_unwrap(conflicts)
            .unwrap_or_else(|_| panic!("SQLite conflict references escaped"))
            .into_inner()
            .expect("conflict mutex poisoned");
        return Ok(sqlite_response(
            AdapterStatus::Conflict,
            None,
            conflicts,
            None,
            0,
            SqliteEvidenceInputs {
                base_path,
                replacement_changeset,
                future_changeset,
            },
        ));
    }
    if let Err(error) = connection.execute_batch("COMMIT;") {
        let _ = connection.execute_batch("ROLLBACK;");
        drop(connection);
        let _ = fs::remove_file(output_path);
        let mut conflicts = Arc::try_unwrap(conflicts)
            .unwrap_or_else(|_| panic!("SQLite conflict references escaped"))
            .into_inner()
            .expect("conflict mutex poisoned");
        conflicts.push(AdapterConflict {
            location: "commit".into(),
            reason: format!("SQLite transaction commit failed: {error}"),
        });
        return Ok(sqlite_response(
            AdapterStatus::Conflict,
            None,
            conflicts,
            None,
            0,
            SqliteEvidenceInputs {
                base_path,
                replacement_changeset,
                future_changeset,
            },
        ));
    }
    let integrity_check: String =
        connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let foreign_key_violations: usize = connection
        .prepare("PRAGMA foreign_key_check")?
        .query_map([], |_| Ok(()))?
        .count();
    drop(connection);
    let output_hash = hash_bytes(&fs::read(output_path)?);
    let mut response = sqlite_response(
        if integrity_check == "ok" && foreign_key_violations == 0 {
            AdapterStatus::Applied
        } else {
            AdapterStatus::Conflict
        },
        Some(output_path.to_path_buf()),
        Vec::new(),
        Some(integrity_check),
        foreign_key_violations,
        SqliteEvidenceInputs {
            base_path,
            replacement_changeset,
            future_changeset,
        },
    );
    response.evidence.output_hash = Some(output_hash);
    Ok(response)
}

struct SqliteEvidenceInputs<'a> {
    base_path: &'a Path,
    replacement_changeset: &'a [u8],
    future_changeset: &'a [u8],
}

fn sqlite_response(
    status: AdapterStatus,
    output_path: Option<PathBuf>,
    conflicts: Vec<AdapterConflict>,
    integrity_check: Option<String>,
    foreign_key_violations: usize,
    inputs: SqliteEvidenceInputs<'_>,
) -> SqliteRebaseResponse {
    let mut input_hashes = BTreeMap::new();
    let base_hash = fs::read(inputs.base_path)
        .map(|bytes| hash_bytes(&bytes))
        .unwrap_or_else(|_| "unreadable".into());
    input_hashes.insert("base_database".into(), base_hash);
    input_hashes.insert(
        "replacement_changeset".into(),
        hash_bytes(inputs.replacement_changeset),
    );
    input_hashes.insert(
        "future_changeset".into(),
        hash_bytes(inputs.future_changeset),
    );
    SqliteRebaseResponse {
        status,
        output_path,
        conflicts,
        integrity_check,
        foreign_key_violations,
        evidence: AdapterEvidence {
            adapter: "sqlite-session".into(),
            version: SQLITE_SESSION_ADAPTER_VERSION.into(),
            input_hashes,
            output_hash: None,
            support_envelope: "SQLite Session changesets for declared primary-keyed tables; conflict abort; schema changes and virtual tables unsupported."
                .into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_disjoint_fields_merge_and_same_field_conflicts() {
        let base = serde_json::json!({"provider":"old","timeout":10});
        let replacement = serde_json::json!({"provider":"new","timeout":10});
        let future = serde_json::json!({"provider":"old","timeout":30});
        let merged = rebase_json(&base, &replacement, &future);
        assert_eq!(merged.status, AdapterStatus::Applied);
        assert_eq!(
            merged.value,
            Some(serde_json::json!({"provider":"new","timeout":30}))
        );

        let conflict = rebase_json(
            &base,
            &replacement,
            &serde_json::json!({"provider":"third","timeout":10}),
        );
        assert_eq!(conflict.status, AdapterStatus::Conflict);
        assert_eq!(conflict.conflicts[0].location, "/provider");
    }

    #[test]
    fn flat_toml_merges_disjoint_scalar_keys() {
        let base = "provider = \"old\"\n[server]\ntimeout = 10\n";
        let replacement = "provider = \"new\"\n[server]\ntimeout = 10\n";
        let future = "provider = \"old\"\n[server]\ntimeout = 30\n";
        let result = rebase_flat_toml(base, replacement, future);
        assert_eq!(result.status, AdapterStatus::Applied);
        assert!(result.text.unwrap().contains("timeout = 30"));
    }

    #[test]
    fn counterfactual_probe_requires_stable_equal_repetitions() {
        let stable = evaluate_counterfactual_probe(
            &[b"same".to_vec(), b"same".to_vec(), b"same".to_vec()],
            &[b"same".to_vec(), b"same".to_vec(), b"same".to_vec()],
        );
        assert_eq!(
            stable.decision,
            CounterfactualProbeDecision::StabilizedIndependentOutput
        );
        let stochastic = evaluate_counterfactual_probe(
            &[b"one".to_vec(), b"two".to_vec()],
            &[b"one".to_vec(), b"one".to_vec()],
        );
        assert_eq!(
            stochastic.decision,
            CounterfactualProbeDecision::Indeterminate
        );
    }

    #[test]
    fn git_adapter_transplants_disjoint_future_and_refuses_same_region() {
        let base = BTreeMap::from([(
            "app.txt".into(),
            b"header\nprovider=old\ncontext-a\ncontext-b\ncontext-c\ntimeout=10\nfooter\n".to_vec(),
        )]);
        let replacement = BTreeMap::from([(
            "app.txt".into(),
            b"header\nprovider=new\ncontext-a\ncontext-b\ncontext-c\ntimeout=10\nfooter\n".to_vec(),
        )]);
        let future = BTreeMap::from([(
            "app.txt".into(),
            b"header\nprovider=old\ncontext-a\ncontext-b\ncontext-c\ntimeout=30\nfooter\n".to_vec(),
        )]);
        let merged = rebase_git_tree(&base, &replacement, &future).unwrap();
        assert_eq!(merged.status, AdapterStatus::Applied);
        assert_eq!(
            merged.files["app.txt"],
            b"header\nprovider=new\ncontext-a\ncontext-b\ncontext-c\ntimeout=30\nfooter\n"
        );

        let future_conflict = BTreeMap::from([(
            "app.txt".into(),
            b"header\nprovider=third\ncontext-a\ncontext-b\ncontext-c\ntimeout=10\nfooter\n"
                .to_vec(),
        )]);
        let conflict = rebase_git_tree(&base, &replacement, &future_conflict).unwrap();
        assert_eq!(conflict.status, AdapterStatus::Conflict);
    }

    #[test]
    fn sqlite_session_preserves_disjoint_later_column_and_aborts_same_column() {
        let root = std::env::temp_dir().join(format!(
            "realm-sqlite-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let base_path = root.join("base.sqlite");
        let base = Connection::open(&base_path).unwrap();
        base.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL);
             INSERT INTO users VALUES(1, 'Ada', 'viewer');",
        )
        .unwrap();
        drop(base);
        let replacement_path = root.join("replacement.sqlite");
        fs::copy(&base_path, &replacement_path).unwrap();
        let replacement_db = Connection::open(&replacement_path).unwrap();
        let replacement = capture_sqlite_changeset(&replacement_db, &["users"], |db| {
            db.execute("UPDATE users SET name='Grace' WHERE id=1", [])?;
            Ok(())
        })
        .unwrap();
        drop(replacement_db);

        let target_path = root.join("target.sqlite");
        fs::copy(&base_path, &target_path).unwrap();
        let target = Connection::open(&target_path).unwrap();
        target
            .execute("UPDATE users SET name='Target' WHERE id=1", [])
            .unwrap();
        let future = capture_sqlite_changeset(&target, &["users"], |db| {
            db.execute("UPDATE users SET role='admin' WHERE id=1", [])?;
            Ok(())
        })
        .unwrap();
        drop(target);
        let output = root.join("rebased.sqlite");
        let response = rebase_sqlite_session(&base_path, &replacement, &future, &output).unwrap();
        assert_eq!(response.status, AdapterStatus::Applied);
        let rebased = Connection::open(&output).unwrap();
        let row: (String, String) = rebased
            .query_row("SELECT name, role FROM users WHERE id=1", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(row, ("Grace".into(), "admin".into()));
        drop(rebased);

        let target_again = Connection::open(&target_path).unwrap();
        let same_column_future = capture_sqlite_changeset(&target_again, &["users"], |db| {
            db.execute("UPDATE users SET name='Future' WHERE id=1", [])?;
            Ok(())
        })
        .unwrap();
        drop(target_again);
        let conflicted_output = root.join("conflicted.sqlite");
        let conflict = rebase_sqlite_session(
            &base_path,
            &replacement,
            &same_column_future,
            &conflicted_output,
        )
        .unwrap();
        assert_eq!(conflict.status, AdapterStatus::Conflict);
        assert!(!conflict.conflicts.is_empty());
        assert!(!conflicted_output.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
