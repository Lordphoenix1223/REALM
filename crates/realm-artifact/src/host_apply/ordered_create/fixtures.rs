//! Disposable NON_AUTHORIZING canonical artifact harness. Not a production issuer.
//! No conversion or accessor exposes its internal VerifiedCreateBatch.
use super::*;

pub const PROFILE: &str = "realm.receiver.NON_AUTHORIZING.ordered-create.v1";

/// Test capability cannot be supplied to production application functions.
/// ```compile_fail
/// # #[cfg(feature = "receiver-fixtures")] {
/// use realm_artifact::host_apply::ordered_create::{apply, fixtures::FixtureBatch};
/// fn escalate(v: FixtureBatch) { apply(&v, todo!(), todo!(), ""); }
/// # }
/// ```
#[derive(Debug)]
pub struct FixtureBatch(VerifiedCreateBatch);

/// Exact content pin must be supplied by the test operator, separately from the
/// candidate. It authenticates fixture bytes ONLY, never execution assertions.
pub fn verify(bytes: &[u8], external_blake3: &str) -> Result<FixtureBatch> {
    if !valid_digest(external_blake3) || digest(bytes) != external_blake3 {
        return refuse("fixture external artifact pin differs");
    }
    let b = candidate::decode(bytes)?;
    if b.run.effect_contract.identity != PROFILE
        || b.run.environment.runtime != "NON_AUTHORIZING_RECEIVER_FIXTURE"
        || b.run.environment.backend != "disposable-filesystem"
        || !b.run.inputs.is_empty()
        || !b.run.evidence.is_empty()
        || !b.run.claims.is_empty()
        || !b.run.observations.is_empty()
        || !b.run.checkpoints.is_empty()
        || !b.envelope.attestations.is_empty()
        || !b.envelope.verification.is_empty()
        || b.envelope.publication != crate::PublicationMetadata::default()
    {
        return refuse(
            "fixture domain only; production claims, attestations and authority forbidden",
        );
    }
    let v = VerifiedCreateBatch {
        artifact: external_blake3.into(),
        run: crate::hash("realm.receiver.fixture.run.v1", b.run.run.run_id.as_bytes()).value,
        head: crate::hash("realm.receiver.fixture.NO_AUTHORITY.v1", bytes).value,
        semantic: b.semantic_identity()?.value,
        authorization: None,
        files: std::array::from_fn(|i| b.blobs[&b.run.outputs[i].digest.value].clone()),
    };
    if b.run.starting_state.digest
        != crate::hash(
            "realm.receiver.fixture.world.v1",
            expected_world(&v, 0)?.as_bytes(),
        )
        || b.run.final_state.as_ref().map(|c| &c.digest)
            != Some(&crate::hash(
                "realm.receiver.fixture.world.v1",
                expected_world(&v, 3)?.as_bytes(),
            ))
    {
        return refuse("fixture initial/final world commitments differ");
    }
    Ok(FixtureBatch(v))
}

#[derive(Debug, Serialize)]
pub struct NonAuthorizing<T: Serialize> {
    pub authority: &'static str,
    pub evidence_class: &'static str,
    pub result: T,
}
fn wrap<T: Serialize>(result: T) -> NonAuthorizing<T> {
    NonAuthorizing {
        authority: "NONE",
        evidence_class: "NON_AUTHORIZING_RECEIVER_FIXTURE",
        result,
    }
}
impl FixtureBatch {
    // Internal non-authorizing handoff. The batch never becomes public/native
    // authority; Stage 8 still allocates only a NEW disposable destination.
    #[cfg(feature = "receiver-fixtures")]
    pub(super) fn into_stage8(self, parent: &Path, task: &str) -> Result<super::stage8::Session> {
        super::stage8::Session::disposable_verified(self.0, parent, task)
    }

    pub fn receive(
        &self,
        destination: &Path,
        state: &Path,
        approval: Option<&str>,
    ) -> super::super::coding_lifecycle::TransferAttempt {
        super::super::coding_lifecycle::fixture_receive(
            &self.0.artifact,
            &self.0,
            destination,
            state,
            approval,
        )
    }

    pub fn prepare(&self, destination: &Path) -> Result<NonAuthorizing<OrderedPlan>> {
        Ok(wrap(preflight(&self.0, destination)?))
    }
    pub fn apply(
        &self,
        destination: &Path,
        state: &Path,
        approval: &str,
    ) -> Result<NonAuthorizing<OrderedReceipt>> {
        Ok(wrap(apply(&self.0, destination, state, approval)?))
    }
    pub fn progress(
        &self,
        destination: &Path,
        state: &Path,
    ) -> Result<NonAuthorizing<OrderedProgress>> {
        Ok(wrap(progress(&self.0, destination, state)?))
    }
    pub fn final_verify(
        &self,
        destination: &Path,
        state: &Path,
    ) -> Result<NonAuthorizing<OrderedReceipt>> {
        Ok(wrap(verify_host(&self.0, destination, state)?))
    }
}

/// Generate a canonical .realm solely for disposable receiver testing. The
/// profile is deliberately rejected by the production entry point.
pub fn artifact(run: &str, files: [Vec<u8>; 3]) -> Result<Vec<u8>> {
    use crate::*;
    let commitment = |name: &str, bytes: &[u8]| Commitment {
        identity: name.into(),
        digest: hash(name, bytes),
    };
    let v = VerifiedCreateBatch {
        artifact: "0".repeat(64),
        run: "0".repeat(64),
        head: "0".repeat(64),
        semantic: "0".repeat(64),
        authorization: None,
        files: files.clone(),
    };
    let mut b = ArtifactBundle::new(RealmRun {
        schema_version: SCHEMA_VERSION,
        lifecycle: Lifecycle::Frozen,
        run: RunIdentity {
            run_id: run.into(),
            execution_id: format!("fixture:{run}"),
        },
        challenge: Challenge {
            nonce: Some(hash(PROFILE, run.as_bytes())),
            issued_by: PROFILE.into(),
            expires_at: None,
        },
        intent: commitment(PROFILE, b"receiver mechanics only"),
        starting_state: commitment(
            "realm.receiver.fixture.world.v1",
            expected_world(&v, 0)?.as_bytes(),
        ),
        environment: EnvironmentIdentity {
            runtime: "NON_AUTHORIZING_RECEIVER_FIXTURE".into(),
            runtime_digest: hash(PROFILE, b"no measured execution"),
            backend: "disposable-filesystem".into(),
            architecture: "fixture".into(),
        },
        effect_contract: commitment(PROFILE, b"three ordered create-only files; 0600; max32768"),
        inputs: vec![],
        outputs: vec![],
        checkpoints: vec![],
        observations: vec![],
        proposed_effects: vec![],
        unknown_effects: vec![],
        evidence: vec![],
        claims: vec![],
        final_state: Some(commitment(
            "realm.receiver.fixture.world.v1",
            expected_world(&v, 3)?.as_bytes(),
        )),
        seal: None,
    });
    for (i, bytes) in files.into_iter().enumerate() {
        let output = b.add_blob(bytes, "text/x-python");
        b.run.proposed_effects.push(ProposedEffect {
            id: format!("fixture-create-{i}"),
            kind: "create".into(),
            target: PATHS[i].into(),
            before: None,
            after: Some(output.digest.clone()),
            checkpoint: None,
            evidence: vec![],
        });
        b.run.outputs.push(output);
    }
    b.seal()?;
    let bytes = b.pack()?;
    verify(&bytes, &digest(&bytes))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::tests::Fixture;
    use super::*;
    use std::fs;
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt, symlink},
    };

    fn files() -> [Vec<u8>; 3] {
        [b"a\n".to_vec(), b"b\n".to_vec(), b"c\n".to_vec()]
    }
    fn checked() -> (Vec<u8>, FixtureBatch) {
        let bytes = artifact("fixture-a", files()).unwrap();
        let v = verify(&bytes, &digest(&bytes)).unwrap();
        (bytes, v)
    }
    fn reseal(b: &mut ArtifactBundle) -> Vec<u8> {
        b.run.seal = None;
        b.run.lifecycle = crate::Lifecycle::Frozen;
        b.seal().unwrap();
        b.pack().unwrap()
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn mac_extended_acl_grants_refuse_despite_private_mode() {
        for kind in 0..5 {
            let f = Fixture::new();
            let (_, v) = checked();
            let a = v.prepare(&f.dest).unwrap().result.approval_id().unwrap();
            let path = match kind {
                0 => f.dest.clone(),
                1 => f.state.clone(),
                2 => {
                    v.apply(&f.dest, &f.state, &a).unwrap();
                    f.dest.join(PATHS[0])
                }
                3 => f.root.clone(),
                _ => {
                    v.apply(&f.dest, &f.state, &a).unwrap();
                    f.state.join("journal.jsonl")
                }
            };
            let expected = if kind == 2 || kind == 4 { 0o600 } else { 0o700 };
            let rule = if kind == 2 || kind == 4 {
                "everyone allow read"
            } else {
                "everyone allow list,add_file,search"
            };
            let status = std::process::Command::new("/bin/chmod")
                .args(["+a", rule])
                .arg(&path)
                .status()
                .unwrap();
            assert!(status.success());
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, expected);
            if kind == 2 || kind == 4 {
                assert!(v.final_verify(&f.dest, &f.state).is_err());
            } else {
                assert!(v.apply(&f.dest, &f.state, &a).is_err());
                assert!(!f.dest.join(PATHS[0]).exists());
            }
        }
    }
    #[test]
    fn canonical_artifact_to_separate_workspace_and_repeat() {
        let f = Fixture::new();
        let (bytes, v) = checked();
        assert!(candidate::verify(&bytes).is_err());
        let before = fs::read_dir(&f.state).unwrap().count();
        let p = v.prepare(&f.dest).unwrap();
        assert_eq!(p.authority, "NONE");
        assert_eq!(fs::read_dir(&f.state).unwrap().count(), before);
        let a = p.result.approval_id().unwrap();
        let r = v.apply(&f.dest, &f.state, &a).unwrap();
        assert_eq!(r.authority, "NONE");
        assert!(r.result.verified);
        let snapshot = f.snapshot();
        assert_eq!(v.final_verify(&f.dest, &f.state).unwrap().result, r.result);
        assert_eq!(v.apply(&f.dest, &f.state, &a).unwrap().result, r.result);
        assert_eq!(f.snapshot(), snapshot);
        assert_eq!(
            v.progress(&f.dest, &f.state)
                .unwrap()
                .result
                .completed_operations,
            3
        );
        for (path, bytes) in PATHS.iter().zip(files()) {
            assert_eq!(fs::read(f.dest.join(path)).unwrap(), bytes);
        }
    }
    #[test]
    fn one_library_lifecycle_handles_three_distinct_artifacts_and_retries() {
        for variant in 0..3 {
            let f = Fixture::new();
            let content = [
                format!("# UNIT_TEST_ONLY case {variant} totals\n").into_bytes(),
                format!("# UNIT_TEST_ONLY case {variant} report\n").into_bytes(),
                format!("# UNIT_TEST_ONLY case {variant} checks\n").into_bytes(),
            ];
            let bytes = artifact(&format!("fixture-variant-{variant}"), content.clone()).unwrap();
            let v = verify(&bytes, &digest(&bytes)).unwrap();
            let prepared = v.receive(&f.dest, &f.state, None);
            assert_eq!(prepared.status, "PREPARED_REQUIRES_SEPARATE_APPROVAL");
            assert!(!prepared.application_dispatched);
            assert_eq!(prepared.authority, "NONE");
            assert_eq!(prepared.artifact_blake3, digest(&bytes));
            assert_eq!(fs::read_dir(&f.state).unwrap().count(), 0);
            let a = prepared.approval_id.unwrap();
            let bad = v.receive(&f.dest, &f.state, Some("forged"));
            assert_eq!(bad.status, "REFUSED");
            assert!(!bad.application_dispatched);
            assert_eq!(fs::read_dir(&f.state).unwrap().count(), 0);
            let result = v.receive(&f.dest, &f.state, Some(&a));
            assert_eq!(result.status, "NON_AUTHORIZING_FIXTURE_APPLIED");
            assert_eq!(result.authority, "NONE");
            assert_eq!(result.stages[1].status, "NOT_APPLICABLE_FIXTURE");
            assert!(result.receipt.as_ref().unwrap().verified);
            let before = f.snapshot();
            assert_eq!(v.receive(&f.dest, &f.state, Some(&a)).status, result.status);
            assert_eq!(f.snapshot(), before);
            for (path, expected) in PATHS.iter().zip(content) {
                assert_eq!(fs::read(f.dest.join(path)).unwrap(), expected);
            }
            fs::write(f.dest.join(PATHS[1]), b"altered").unwrap();
            let failure = v.receive(&f.dest, &f.state, Some(&a));
            assert_eq!(failure.status, "INCOMPLETE_APPLICATION");
            assert!(failure.application_dispatched);
            assert!(failure.receipt.is_none());
            assert_eq!(failure.stages[5].status, "NOT_RUN");
        }
    }
    #[test]
    fn expired_policy_stops_resume_but_does_not_hide_read_only_progress() {
        let f = Fixture::new();
        let (_, mut v) = checked();
        let now = super::super::coding_transfer::now_unix().unwrap();
        let historical = v.prepare(&f.dest).unwrap().result;
        assert!(
            serde_json::to_value(&historical)
                .unwrap()
                .get("authorization")
                .is_none()
        );
        let old_json = serde_json::to_vec(&historical).unwrap();
        assert!(
            serde_json::from_slice::<OrderedPlan>(&old_json)
                .unwrap()
                .authorization
                .is_none()
        );
        v.0.authorization = Some(AuthorizationBinding {
            policy_id: "e".repeat(64),
            domain: super::super::coding_transfer::AUTHORIZATION_DOMAIN.into(),
            nonce: "f".repeat(64),
            destination: Directory::open(&f.dest).unwrap().identity().unwrap(),
            not_before_unix: now - 1,
            expires_at_unix: now + 2,
        });
        let a = v.prepare(&f.dest).unwrap().result.approval_id().unwrap();
        assert_ne!(historical.approval_id().unwrap(), a);
        assert!(apply_inner(&v.0, &f.dest, &f.state, &a, Fault::Boundary(0, 6)).is_err());
        let snapshot = f.snapshot();
        let journal = fs::read(f.state.join("journal.jsonl")).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(v.apply(&f.dest, &f.state, &a).is_err());
        assert_eq!(
            v.progress(&f.dest, &f.state)
                .unwrap()
                .result
                .completed_operations,
            1
        );
        assert_eq!(fs::read(f.state.join("journal.jsonl")).unwrap(), journal);
        assert_eq!(f.snapshot(), snapshot);
    }
    #[test]
    fn bounded_coding_parser_rejects_graph_bombs_before_general_validation() {
        let (bytes, _) = checked();
        let mut b = ArtifactBundle::unpack(&bytes).unwrap();
        b.run.checkpoints = (0..17)
            .map(|i| crate::Checkpoint {
                id: format!("c{i}"),
                sequence: i,
                parent: if i == 0 {
                    None
                } else {
                    Some(format!("c{}", i - 1))
                },
                state: b.run.starting_state.clone(),
                evidence: vec![],
            })
            .collect();
        let raw = reseal(&mut b);
        // The canonical general schema remains compatible; coding is narrower.
        assert!(ArtifactBundle::unpack(&raw).is_ok());
        assert!(
            candidate::inspect(&raw)
                .unwrap_err()
                .to_string()
                .contains("resource budget")
        );
        b.run.checkpoints.clear();
        b.run.environment.runtime = "x".repeat(1024 * 1024);
        let raw = reseal(&mut b);
        assert!(
            candidate::inspect(&raw)
                .unwrap_err()
                .to_string()
                .contains("metadata resource budget")
        );
    }
    #[test]
    fn transfer_reader_rejects_parent_aliases_hard_links_fifos_and_traversal() {
        let f = Fixture::new();
        let (bytes, _) = checked();
        let file = f.root.join("candidate.realm");
        fs::write(&file, &bytes).unwrap();
        assert_eq!(super::super::read_transfer_file(&file).unwrap(), bytes);
        let alias = f.root.join("alias");
        symlink(&f.root, &alias).unwrap();
        assert!(super::super::read_transfer_file(&alias.join("candidate.realm")).is_err());
        for p in [
            f.root.join("dest/../candidate.realm"),
            f.root.join("./candidate.realm"),
        ] {
            assert!(super::super::read_transfer_file(&p).is_err());
        }
        let fifo = std::ffi::CString::new(f.root.join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(super::super::read_transfer_file(&f.root.join("fifo")).is_err());
        fs::hard_link(&file, f.root.join("hardlink")).unwrap();
        assert!(super::super::read_transfer_file(&file).is_err());
    }
    #[test]
    fn concurrent_ordered_journals_never_adopt_each_others_files() {
        let f = Fixture::new();
        let (bytes, v) = checked();
        let a = v.prepare(&f.dest).unwrap().result.approval_id().unwrap();
        let second = f.root.join("second-state");
        fs::create_dir(&second).unwrap();
        fs::set_permissions(&second, fs::Permissions::from_mode(0o700)).unwrap();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                barrier.wait();
                v.apply(&f.dest, &f.state, &a)
            });
            let other = scope.spawn(|| {
                let w = verify(&bytes, &digest(&bytes)).unwrap();
                barrier.wait();
                w.apply(&f.dest, &second, &a)
            });
            let one = first.join().unwrap();
            let two = other.join().unwrap();
            // Scheduling may stop both after a partial prefix. At most one
            // journal may report a fully verified application.
            assert!(!(one.is_ok() && two.is_ok()));
            for (path, expected) in PATHS.iter().zip(files()) {
                if f.dest.join(path).exists() {
                    assert_eq!(fs::read(f.dest.join(path)).unwrap(), expected);
                }
            }
            if one.is_ok() {
                assert!(v.final_verify(&f.dest, &f.state).is_ok());
            }
            if two.is_ok() {
                assert!(v.final_verify(&f.dest, &second).is_ok());
            }
        });
    }
    #[test]
    fn payload_cross_run_pin_and_approval_substitutions_refuse() {
        let f = Fixture::new();
        let (bytes, v) = checked();
        let a = v.prepare(&f.dest).unwrap().result.approval_id().unwrap();
        for i in (0..bytes.len()).step_by(31) {
            let mut tampered = bytes.clone();
            tampered[i] ^= 1;
            assert!(verify(&tampered, &digest(&bytes)).is_err());
        }
        let other = artifact("fixture-b", files()).unwrap();
        assert!(verify(&other, &digest(&bytes)).is_err());
        let w = verify(&other, &digest(&other)).unwrap();
        assert!(w.apply(&f.dest, &f.state, &a).is_err());
        assert!(v.apply(&f.dest, &f.state, &"f".repeat(64)).is_err());
        assert_eq!(fs::read_dir(&f.dest).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&f.state).unwrap().count(), 0);
    }
    #[test]
    fn malicious_projections_and_false_worlds_refuse_even_with_updated_pins() {
        let (bytes, _) = checked();
        for target in [
            "../escape",
            "/tmp/escape",
            "sub/totals.py",
            "./totals.py",
            "totals.py/",
            "TOTALS.py",
            "report.py",
            "totals.py\0",
        ] {
            let mut b = ArtifactBundle::unpack(&bytes).unwrap();
            b.run.proposed_effects[0].target = target.into();
            let bad = reseal(&mut b);
            assert!(verify(&bad, &digest(&bad)).is_err());
        }
        for op in ["write", "delete", "shell", "rename", "Create", ""] {
            let mut b = ArtifactBundle::unpack(&bytes).unwrap();
            b.run.proposed_effects[1].kind = op.into();
            let bad = reseal(&mut b);
            assert!(verify(&bad, &digest(&bad)).is_err());
        }
        for kind in 0..5 {
            let mut b = ArtifactBundle::unpack(&bytes).unwrap();
            match kind {
                0 => b.run.unknown_effects.push(crate::UnknownEffect {
                    kind: "network".into(),
                    target: None,
                    reason: "unknown".into(),
                }),
                1 => b.run.outputs.swap(0, 1),
                2 => b.run.starting_state.digest = crate::hash("false-world", b"stale"),
                3 => {
                    b.run.final_state.as_mut().unwrap().digest = crate::hash("false-world", b"PASS")
                }
                _ => b.run.environment.runtime = "realm-v6-production".into(),
            }
            let bad = reseal(&mut b);
            assert!(verify(&bad, &digest(&bad)).is_err());
        }
    }
    #[test]
    fn canonical_encoding_bounds_and_truncation_refuse() {
        let (bytes, _) = checked();
        for end in (0..bytes.len()).step_by(17) {
            let bad = &bytes[..end];
            assert!(verify(bad, &digest(bad)).is_err());
        }
        let mut b = bytes.clone();
        b.push(0);
        assert!(verify(&b, &digest(&b)).is_err());
        assert!(artifact("empty", [vec![], vec![1], vec![2]]).is_err());
        assert!(artifact("large", [vec![0; MAX_FILE as usize + 1], vec![1], vec![2]]).is_err());
        // A whitespace-prefixed frame is semantically identical to the parser,
        // but is not the canonical transport. Recompute the external pin too.
        let start = b"REALM-PORTABLE-3\n".len();
        let n = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap()) as usize;
        let mut alternate = bytes[..start].to_vec();
        alternate.extend_from_slice(&((n + 1) as u64).to_be_bytes());
        alternate.push(b' ');
        alternate.extend_from_slice(&bytes[start + 8..]);
        assert!(ArtifactBundle::unpack(&alternate).is_ok());
        assert!(verify(&alternate, &digest(&alternate)).is_err());
    }
    #[test]
    fn read_only_progress_is_accurate_at_all_interruption_boundaries() {
        for i in 0..3 {
            for boundary in 1..=6 {
                let f = Fixture::new();
                let (_, v) = checked();
                let a = v.prepare(&f.dest).unwrap().result.approval_id().unwrap();
                assert!(
                    apply_inner(&v.0, &f.dest, &f.state, &a, Fault::Boundary(i, boundary)).is_err()
                );
                let journal = fs::read(f.state.join("journal.jsonl")).unwrap();
                let snapshot = f.snapshot();
                let p = v.progress(&f.dest, &f.state).unwrap().result;
                assert_eq!(p.completed_operations, i + usize::from(boundary == 6));
                assert_eq!(
                    p.physical_state.starts_with("REFUSE_RECONCILE"),
                    boundary == 1
                );
                assert!(v.final_verify(&f.dest, &f.state).is_err());
                assert_eq!(fs::read(f.state.join("journal.jsonl")).unwrap(), journal);
                assert_eq!(f.snapshot(), snapshot);
                if boundary != 1 {
                    assert!(v.apply(&f.dest, &f.state, &a).unwrap().result.verified);
                } else {
                    assert!(v.apply(&f.dest, &f.state, &a).is_err());
                }
            }
        }
    }
    #[test]
    fn stale_symlink_hardlink_modes_and_final_corruption_refuse() {
        for kind in 0..5 {
            let f = Fixture::new();
            let (_, v) = checked();
            let a = v.prepare(&f.dest).unwrap().result.approval_id().unwrap();
            match kind {
                0 => fs::write(f.dest.join(PATHS[0]), b"stale").unwrap(),
                1 => symlink(f.root.join("escape"), f.dest.join(PATHS[0])).unwrap(),
                2 => {
                    fs::write(f.root.join("source"), b"a\n").unwrap();
                    fs::hard_link(f.root.join("source"), f.dest.join(PATHS[0])).unwrap();
                }
                3 => fs::set_permissions(&f.dest, fs::Permissions::from_mode(0o755)).unwrap(),
                _ => fs::write(f.state.join("extra"), b"PASS").unwrap(),
            }
            assert!(v.apply(&f.dest, &f.state, &a).is_err());
            assert!(!f.dest.join(PATHS[1]).exists());
        }
        let f = Fixture::new();
        let (_, v) = checked();
        let a = v.prepare(&f.dest).unwrap().result.approval_id().unwrap();
        v.apply(&f.dest, &f.state, &a).unwrap();
        fs::write(f.dest.join(PATHS[2]), b"wrong").unwrap();
        assert!(v.final_verify(&f.dest, &f.state).is_err());
        assert!(
            v.progress(&f.dest, &f.state)
                .unwrap()
                .result
                .physical_state
                .starts_with("REFUSE_RECONCILE")
        );
    }
    #[test]
    #[ignore = "isolated subprocess helper invoked by canonical_artifact_sigkill_campaign"]
    fn canonical_crash_child() {
        let root = std::path::PathBuf::from(std::env::var("REALM_RECEIVER_TEST_ROOT").unwrap());
        let bytes = fs::read(root.join("candidate.realm")).unwrap();
        let pin = std::env::var("REALM_RECEIVER_TEST_PIN").unwrap();
        let v = verify(&bytes, &pin).unwrap();
        let a = std::env::var("REALM_RECEIVER_TEST_APPROVAL").unwrap();
        v.apply(&root.join("dest"), &root.join("state"), &a)
            .unwrap();
        panic!("crash hook was not reached");
    }
    #[test]
    fn sigkill_during_final_observation_requires_a_fresh_observation_after_lost_reply() {
        use std::os::unix::process::ExitStatusExt;
        let f = Fixture::new();
        let (bytes, v) = checked();
        fs::write(f.root.join("candidate.realm"), &bytes).unwrap();
        let a = v.prepare(&f.dest).unwrap().result.approval_id().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "host_apply::ordered_create::fixtures::tests::canonical_crash_child",
                "--ignored",
            ])
            .env("REALM_RECEIVER_TEST_ROOT", &f.root)
            .env("REALM_RECEIVER_TEST_PIN", digest(&bytes))
            .env("REALM_RECEIVER_TEST_APPROVAL", &a)
            .env("REALM_ORDERED_TEST_CRASH", "4:0")
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let before = f.snapshot();
        let journal = fs::read(f.state.join("journal.jsonl")).unwrap();
        assert!(v.final_verify(&f.dest, &f.state).unwrap().result.verified);
        assert_eq!(
            v.receive(&f.dest, &f.state, Some(&a)).status,
            "NON_AUTHORIZING_FIXTURE_APPLIED"
        );
        assert_eq!(f.snapshot(), before);
        assert_eq!(fs::read(f.state.join("journal.jsonl")).unwrap(), journal);
    }
    #[test]
    fn canonical_artifact_sigkill_campaign() {
        use std::os::unix::process::ExitStatusExt;
        for (i, boundary) in (0..3)
            .flat_map(|i| (1..=6).map(move |b| (i, b)))
            .chain([(0, 0), (3, 0)])
        {
            let f = Fixture::new();
            let (bytes, v) = checked();
            fs::write(f.root.join("candidate.realm"), &bytes).unwrap();
            let a = v.prepare(&f.dest).unwrap().result.approval_id().unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "host_apply::ordered_create::fixtures::tests::canonical_crash_child",
                    "--ignored",
                ])
                .env("REALM_RECEIVER_TEST_ROOT", &f.root)
                .env("REALM_RECEIVER_TEST_PIN", digest(&bytes))
                .env("REALM_RECEIVER_TEST_APPROVAL", &a)
                .env("REALM_ORDERED_TEST_CRASH", format!("{i}:{boundary}"))
                .status()
                .unwrap();
            assert_eq!(status.signal(), Some(libc::SIGKILL));
            assert!(v.final_verify(&f.dest, &f.state).is_err());
            let prefix = f.snapshot();
            if boundary == 1 {
                assert!(v.apply(&f.dest, &f.state, &a).is_err());
            } else {
                assert!(v.apply(&f.dest, &f.state, &a).unwrap().result.verified);
            }
            assert_eq!(&f.snapshot()[..prefix.len()], prefix.as_slice());
        }
    }
    #[test]
    fn missing_progress_or_lost_receipt_never_invents_completion() {
        for name in ["journal.jsonl", "receipt.json"] {
            let f = Fixture::new();
            let (_, v) = checked();
            let a = v.prepare(&f.dest).unwrap().result.approval_id().unwrap();
            v.apply(&f.dest, &f.state, &a).unwrap();
            let inodes = f.snapshot();
            fs::remove_file(f.state.join(name)).unwrap();
            assert!(v.final_verify(&f.dest, &f.state).is_err());
            if name == "receipt.json" {
                assert!(v.apply(&f.dest, &f.state, &a).unwrap().result.verified);
            } else {
                assert!(v.apply(&f.dest, &f.state, &a).is_err());
                assert!(!f.state.join("journal.jsonl").exists());
            }
            assert_eq!(f.snapshot(), inodes);
        }
    }
    #[test]
    fn journal_descriptor_is_cloexec_and_final_inspection_preserves_metadata() {
        let f = Fixture::new();
        let (_, v) = checked();
        let a = v.prepare(&f.dest).unwrap().result.approval_id().unwrap();
        v.apply(&f.dest, &f.state, &a).unwrap();
        let d = Directory::open(&f.dest).unwrap();
        let plan = v.0.plan(&d).unwrap();
        let j = Journal::open(&f.state, &d, false, &plan).unwrap();
        assert_ne!(
            unsafe { libc::fcntl(j.file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert_eq!(
            unsafe { libc::fcntl(j.file.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
            libc::O_RDONLY
        );
        drop(j);
        let before = fs::metadata(f.state.join("journal.jsonl")).unwrap();
        v.progress(&f.dest, &f.state).unwrap();
        v.final_verify(&f.dest, &f.state).unwrap();
        let after = fs::metadata(f.state.join("journal.jsonl")).unwrap();
        assert_eq!(
            (
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ),
            (
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            )
        );
    }
}

// Real captured data, explicit disposable mechanics, NEVER production authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcedureOperation {
    kind: String,
    index: usize,
    path: String,
    content_blake3: String,
    bytes: usize,
    mode: u32,
    requires_completed: usize,
    source_task: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessfulTask {
    id: String,
    attempt: usize,
    depends_on: Vec<String>,
    criteria_pin: String,
    receipt_json: String,
    receipt_blake3: String,
    inputs: BTreeMap<String, String>,
    outputs: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DevelopmentProcedure {
    schema: String,
    authority: String,
    project_id: String,
    precondition: String,
    commands: Vec<String>,
    network: bool,
    validation: [String; 2],
    successful_tasks: [SuccessfulTask; 2],
    operations: [ProcedureOperation; 3],
    expected_files: BTreeMap<String, String>,
    metadata: serde_json::Value,
}
/// Actual captured archive + typed procedure. This returns only the existing
/// NON_AUTHORIZING mechanics type; it cannot be supplied to production apply.
/// The operator must separately approve the exact fresh disposable destination.
pub fn verify_development_procedure(
    bytes: &[u8],
    pin: &str,
    expectations: &[u8],
    expectations_pin: &str,
    procedure_pin: &str,
) -> Result<FixtureBatch> {
    if unsafe { libc::getuid() } == 0 || unsafe { libc::geteuid() } != unsafe { libc::getuid() } {
        return refuse("development procedure requires an unprivileged operator");
    }
    let payload = super::super::coding_development::capture_payload(
        bytes,
        pin,
        expectations,
        expectations_pin,
    )?;
    let (files, head) = super::super::coding_development::captured_outputs(&payload)?;
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    let freeze: serde_json::Value = serde_json::from_str(
        value["evidence"]["pre_agent_freeze"]
            .as_str()
            .ok_or_else(|| ApplyError::Refuse("freeze missing".into()))?,
    )?;
    let raw = freeze["successful_procedure"]
        .as_str()
        .ok_or_else(|| ApplyError::Refuse("procedure missing".into()))?;
    if !valid_digest(procedure_pin) || digest(raw.as_bytes()) != procedure_pin {
        return refuse("independent procedure pin differs");
    }
    let p: DevelopmentProcedure = super::super::coding_transfer::strict_json(raw.as_bytes())?;
    if p.schema != "realm.development-successful-procedure.v1"
        || p.authority != "NONE"
        || !valid_digest(&p.project_id)
        || p.precondition != "fresh-empty-private-directory"
        || !p.commands.is_empty()
        || p.validation != ["ordered-current-filesystem", "independent-api-and-cli"]
        || p.network
        || !p.metadata.is_object()
        || p.metadata["source_commit"] != freeze["source_commit"]
        || p.expected_files.len() != 3
    {
        return refuse("unsupported procedure capability or precondition");
    }
    for (i, op) in p.operations.iter().enumerate() {
        let owner = if i == 0 { "api" } else { "cli" };
        if op.kind != "create-file"
            || op.index != i
            || op.path != PATHS[i]
            || op.requires_completed != i
            || op.mode != 0o600
            || op.bytes != files[i].len()
            || op.content_blake3 != digest(&files[i])
            || op.source_task != owner
            || p.expected_files.get(PATHS[i]) != Some(&op.content_blake3)
        {
            return refuse("operation deviates from captured successful procedure");
        }
    }
    for (i, t) in p.successful_tasks.iter().enumerate() {
        let id = if i == 0 { "api" } else { "cli" };
        let deps = if i == 0 {
            vec![]
        } else {
            vec!["api".to_string()]
        };
        let r: serde_json::Value = serde_json::from_str(&t.receipt_json)?;
        let status = if i == 0 {
            "PASS_API_SUBTASK"
        } else {
            "PASS_BOUNDED_PROPERTIES"
        };
        if t.id != id
            || t.depends_on != deps
            || !(1..=2).contains(&t.attempt)
            || !valid_digest(&t.criteria_pin)
            || digest(t.receipt_json.as_bytes()) != t.receipt_blake3
            || r["authority"] != "NONE"
            || r["status"] != status
            || r["subject_unchanged"] != true
            || r["scope_sha256"] != t.criteria_pin
            || r["baseline_discrimination"]["passed"] != true
            || !r["api_driver_checks"]
                .as_array()
                .is_some_and(|a| !a.is_empty() && a.iter().all(|v| v["passed"] == true))
        {
            return refuse("missing, failed or substituted successful subtask");
        }
        let paths = if i == 0 {
            [PATHS[0], PATHS[2]]
        } else {
            [PATHS[1], PATHS[2]]
        };
        if t.outputs.len() != 2
            || paths
                .iter()
                .any(|k| !t.outputs.get(*k).is_some_and(|h| valid_digest(h)))
        {
            return refuse("subtask output scope differs");
        }
    }
    let api = &p.successful_tasks[0];
    let cli = &p.successful_tasks[1];
    if api.outputs.get(PATHS[0]) != Some(&digest(&files[0]))
        || cli.inputs.get(PATHS[0]) != api.outputs.get(PATHS[0])
        || cli.outputs.get(PATHS[1]) != Some(&digest(&files[1]))
        || cli.outputs.get(PATHS[2]) != Some(&digest(&files[2]))
    {
        return refuse("dependent procedure inputs or outputs changed");
    }
    Ok(FixtureBatch(VerifiedCreateBatch {
        artifact: pin.into(),
        run: p.project_id,
        head: crate::hash("realm.development.procedure.head", head.as_bytes()).value,
        semantic: procedure_pin.into(),
        files,
        authorization: None,
    }))
}
