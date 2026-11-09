#![cfg(all(target_os = "linux", feature = "test-support"))]

use realm_artifact::lifecycle::{
    GenesisAnchor, LifecycleError, LifecycleTrust, TestPublicationVerification, VerificationState,
    initialize_lifecycle, test_publish_prepared_generation, verify_lifecycle_directory,
};
use realm_v6::{
    execute::{CheckedExecutionForPublication, test_checked_execution_with_images},
    filesystem_world,
    generation::{
        GenerationLayout, GenerationRecovery, PreparedGeneration, prepare_candidate,
        recover_generation,
    },
    publication_journal::{PublicationJournal, PublicationState},
};
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Barrier},
    thread,
};

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "realm-v6-accept-entry-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct PreparedCase {
    _temp: TempTree,
    layout: GenerationLayout,
    prepared: PreparedGeneration,
    execution: CheckedExecutionForPublication,
    trust: LifecycleTrust,
    start_root: String,
    final_root: String,
}

#[derive(Clone)]
struct SyntheticExecutionPlan {
    run_id: String,
    execution_id: String,
    start_root: String,
    final_root: String,
    delta_root: String,
    start_image: PathBuf,
    final_image: PathBuf,
}

impl SyntheticExecutionPlan {
    fn mint(&self) -> CheckedExecutionForPublication {
        test_checked_execution_with_images(
            &self.run_id,
            &self.execution_id,
            &self.start_root,
            &self.final_root,
            &self.delta_root,
            &self.start_image,
            &self.final_image,
        )
    }
}

struct RaceCase {
    _temp: TempTree,
    layout: GenerationLayout,
    trust: LifecycleTrust,
    start_root: String,
    first: SyntheticExecutionPlan,
    second: SyntheticExecutionPlan,
}

fn write_world(path: &Path, final_world: bool) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    // mke2fs creates this directory in every ext4 image; include it in the
    // host fixtures so the semantic roots represent the mounted image.
    fs::create_dir(path.join("lost+found")).unwrap();
    fs::set_permissions(path.join("lost+found"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        path.join("target.txt"),
        if final_world {
            b"S1 bytes"
        } else {
            b"S0 bytes"
        },
    )
    .unwrap();
    fs::set_permissions(path.join("target.txt"), fs::Permissions::from_mode(0o600)).unwrap();
    if final_world {
        fs::write(path.join("created.txt"), b"second effect").unwrap();
        fs::set_permissions(path.join("created.txt"), fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn write_alternate_final_world(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(path.join("lost+found")).unwrap();
    fs::set_permissions(path.join("lost+found"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(path.join("target.txt"), b"alternate S1 bytes").unwrap();
    fs::set_permissions(path.join("target.txt"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(path.join("created.txt"), b"alternate second effect").unwrap();
    fs::set_permissions(path.join("created.txt"), fs::Permissions::from_mode(0o600)).unwrap();
}

fn make_ext4_image(source: &Path, image: &Path) {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(image)
        .unwrap();
    file.set_len(16 * 1024 * 1024).unwrap();
    drop(file);
    let status = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-d"])
        .arg(source)
        .arg(image)
        .status()
        .expect("mkfs.ext4 must be installed for this ignored Linux integration test");
    assert!(status.success(), "mkfs.ext4 failed for {}", image.display());
}

fn prepare_case(label: &str) -> PreparedCase {
    let temp = TempTree::new(label);
    let start_tree = temp.0.join("start-tree");
    let final_tree = temp.0.join("final-tree");
    let live = temp.0.join("workspace");
    let start_image = temp.0.join("start.ext4");
    let final_image = temp.0.join("final.ext4");
    write_world(&start_tree, false);
    write_world(&final_tree, true);
    write_world(&live, false);
    make_ext4_image(&start_tree, &start_image);
    make_ext4_image(&final_tree, &final_image);

    let start = filesystem_world::scan_directory(&start_tree).unwrap();
    let final_world = filesystem_world::scan_directory(&final_tree).unwrap();
    let delta = filesystem_world::delta(&start, &final_world);
    let delta_root = blake3::hash(&serde_json::to_vec(&delta).unwrap())
        .to_hex()
        .to_string();
    let execution_id = blake3::hash(format!("synthetic-{label}-execution").as_bytes())
        .to_hex()
        .to_string();
    let execution = test_checked_execution_with_images(
        &format!("synthetic-{label}-run"),
        &execution_id,
        &start.root,
        &final_world.root,
        &delta_root,
        &start_image,
        &final_image,
    );
    let layout = GenerationLayout::inspect(&live).unwrap();
    let anchor = GenesisAnchor::new(
        layout.workspace_identity(),
        start.root.clone(),
        format!("synthetic-{label}-genesis"),
    );
    let genesis_root = anchor.root().unwrap();
    initialize_lifecycle(&layout, &anchor, &genesis_root).unwrap();
    let trust = LifecycleTrust {
        genesis_root,
        previously_trusted_head_root: anchor.root().unwrap(),
    };
    let prepared = prepare_candidate(&execution, &live).unwrap();
    PreparedCase {
        _temp: temp,
        layout,
        prepared,
        execution,
        trust,
        start_root: start.root,
        final_root: final_world.root,
    }
}

fn prepare_race_case() -> RaceCase {
    let temp = TempTree::new("race");
    let start_tree = temp.0.join("race-start-tree");
    let first_tree = temp.0.join("race-first-tree");
    let second_tree = temp.0.join("race-second-tree");
    let live = temp.0.join("race-workspace");
    let start_image = temp.0.join("race-start.ext4");
    let first_image = temp.0.join("race-first.ext4");
    let second_image = temp.0.join("race-second.ext4");
    write_world(&start_tree, false);
    write_world(&first_tree, true);
    write_alternate_final_world(&second_tree);
    write_world(&live, false);
    make_ext4_image(&start_tree, &start_image);
    make_ext4_image(&first_tree, &first_image);
    make_ext4_image(&second_tree, &second_image);

    let start = filesystem_world::scan_directory(&start_tree).unwrap();
    let first_world = filesystem_world::scan_directory(&first_tree).unwrap();
    let second_world = filesystem_world::scan_directory(&second_tree).unwrap();
    let make_plan = |label: &str,
                     final_world: &realm_v6::filesystem_world::FilesystemWorld,
                     final_image: PathBuf| {
        let delta = filesystem_world::delta(&start, final_world);
        let delta_root = blake3::hash(&serde_json::to_vec(&delta).unwrap())
            .to_hex()
            .to_string();
        SyntheticExecutionPlan {
            run_id: format!("synthetic-race-{label}-run"),
            execution_id: blake3::hash(format!("synthetic-race-{label}-execution").as_bytes())
                .to_hex()
                .to_string(),
            start_root: start.root.clone(),
            final_root: final_world.root.clone(),
            delta_root,
            start_image: start_image.clone(),
            final_image,
        }
    };
    let first = make_plan("first", &first_world, first_image);
    let second = make_plan("second", &second_world, second_image);
    assert_ne!(first.final_root, second.final_root);

    let layout = GenerationLayout::inspect(&live).unwrap();
    let anchor = GenesisAnchor::new(
        layout.workspace_identity(),
        start.root.clone(),
        "synthetic-race-genesis",
    );
    let genesis_root = anchor.root().unwrap();
    initialize_lifecycle(&layout, &anchor, &genesis_root).unwrap();
    let trust = LifecycleTrust {
        genesis_root,
        previously_trusted_head_root: anchor.root().unwrap(),
    };
    RaceCase {
        _temp: temp,
        layout,
        trust,
        start_root: start.root,
        first,
        second,
    }
}

fn race_publisher(
    plan: SyntheticExecutionPlan,
    layout: GenerationLayout,
    trust: LifecycleTrust,
    start: Arc<Barrier>,
) -> Result<TestPublicationVerification, String> {
    let execution = plan.mint();
    start.wait();
    let prepared = prepare_candidate(&execution, layout.live_root())
        .map_err(|error| format!("candidate preparation refused: {error}"))?;
    test_publish_prepared_generation(prepared, execution, &trust)
        .map_err(|error| format!("publication transaction refused: {error}"))
}

/// This test uses an in-process test capability and synthetic ext4 S0/S1
/// images. It tests publication ordering and durable reconstruction, not KVM
/// execution or production authority issuance.
#[test]
#[ignore = "requires root, loop-mount support, and ext4 tools"]
fn synthetic_publication_test_has_no_accept_emitter() {
    let case = prepare_case("positive");
    let published =
        test_publish_prepared_generation(case.prepared, case.execution, &case.trust).unwrap();
    assert_eq!(published.verification_state(), VerificationState::Valid);
    assert_eq!(published.run_id(), "synthetic-positive-run");
    assert_eq!(published.execution_id().len(), 64);
    assert_eq!(published.generation_id().len(), 64);
    assert_eq!(published.publication_id().len(), 64);
    assert_eq!(
        published.parent_authority_head_root(),
        case.trust.previously_trusted_head_root
    );
    assert_eq!(published.authority_head_sequence(), 1);
    assert_eq!(published.verified_transitions(), 1);

    let verification = verify_lifecycle_directory(&case.layout, &case.trust);
    assert_eq!(verification.state, VerificationState::Valid);
    assert_eq!(
        verification.reconstructed_head_root.as_deref(),
        Some(published.authority_head_root())
    );
    assert_eq!(
        filesystem_world::scan_directory(case.layout.live_root())
            .unwrap()
            .root,
        case.final_root
    );
    assert_ne!(case.start_root, case.final_root);
}

#[test]
#[ignore = "requires root, loop-mount support, and ext4 tools"]
fn stale_publisher_is_conflicted_before_live_exchange_and_emits_no_accept() {
    let case = prepare_case("stale");
    let stale_trust = LifecycleTrust {
        genesis_root: case.trust.genesis_root.clone(),
        previously_trusted_head_root: "0".repeat(64),
    };
    let result = test_publish_prepared_generation(case.prepared, case.execution, &stale_trust);
    assert!(matches!(result, Err(LifecycleError::Rollback(_))));
    assert_eq!(
        filesystem_world::scan_directory(case.layout.live_root())
            .unwrap()
            .root,
        case.start_root
    );
    let journal = PublicationJournal::open(case.layout.journal_path()).unwrap();
    let rows = journal.generation_records_for_workspace(case.layout.workspace_identity());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, PublicationState::Conflict);
    assert!(!journal.has_unfinished_generation_for_workspace(case.layout.workspace_identity()));
}

#[test]
#[ignore = "requires root, loop-mount support, and ext4 tools"]
fn concurrent_publishers_from_one_parent_have_one_verified_winner() {
    for _round in 0..3 {
        let case = prepare_race_case();
        assert_eq!(
            filesystem_world::scan_directory(case.layout.live_root())
                .unwrap()
                .root,
            case.start_root
        );
        let start = Arc::new(Barrier::new(3));
        let first = {
            let start = Arc::clone(&start);
            let layout = case.layout.clone();
            let trust = case.trust.clone();
            let plan = case.first.clone();
            thread::spawn(move || race_publisher(plan, layout, trust, start))
        };
        let second = {
            let start = Arc::clone(&start);
            let layout = case.layout.clone();
            let trust = case.trust.clone();
            let plan = case.second.clone();
            thread::spawn(move || race_publisher(plan, layout, trust, start))
        };
        start.wait();

        let first = first.join().unwrap();
        let second = second.join().unwrap();
        let (winner, losing_plan, loser_error) = match (first, second) {
            (Ok(winner), Err(error)) => (winner, case.second.clone(), error),
            (Err(error), Ok(winner)) => (winner, case.first.clone(), error),
            (Ok(_), Ok(_)) => panic!("both publishers advanced from one parent"),
            (Err(first), Err(second)) => {
                panic!("both publishers refused: first={first}; second={second}")
            }
        };
        assert!(
            loser_error.contains("destination is locked by another publisher")
                || loser_error.contains("live workspace no longer matches accepted S0"),
            "unexpected losing publisher refusal: {loser_error}"
        );
        assert_eq!(winner.verification_state(), VerificationState::Valid);
        assert_eq!(winner.authority_head_sequence(), 1);
        let expected_live_root = if winner.run_id() == case.first.run_id {
            &case.first.final_root
        } else {
            assert_eq!(winner.run_id(), case.second.run_id);
            &case.second.final_root
        };
        assert_eq!(
            filesystem_world::scan_directory(case.layout.live_root())
                .unwrap()
                .root,
            *expected_live_root
        );

        let journal = PublicationJournal::open(case.layout.journal_path()).unwrap();
        let rows = journal.generation_records_for_workspace(case.layout.workspace_identity());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, PublicationState::Published);
        assert!(!journal.has_unfinished_generation_for_workspace(case.layout.workspace_identity()));

        for _ in 0..2 {
            assert!(matches!(
                recover_generation(case.layout.live_root()).unwrap(),
                GenerationRecovery::AlreadyPublished(_)
            ));
        }
        let verification = verify_lifecycle_directory(&case.layout, &case.trust);
        assert_eq!(verification.state, VerificationState::Valid);
        assert_eq!(verification.verified_transitions, 1);
        assert_eq!(
            verification.reconstructed_head_root.as_deref(),
            Some(winner.authority_head_root())
        );

        let retry_execution = losing_plan.mint();
        let retry_error = match prepare_candidate(&retry_execution, case.layout.live_root()) {
            Err(realm_v6::generation::GenerationError::Conflict(error)) => error.to_string(),
            Err(error) => panic!("retry refused with an unexpected error: {error}"),
            Ok(_) => panic!("stale loser retry unexpectedly prepared a child"),
        };
        assert!(
            retry_error.contains("live workspace no longer matches accepted S0"),
            "retry did not diagnose the winner's new S1 as stale: {retry_error}"
        );
        assert_eq!(
            filesystem_world::scan_directory(case.layout.live_root())
                .unwrap()
                .root,
            *expected_live_root
        );
        assert_eq!(
            verify_lifecycle_directory(&case.layout, &case.trust).state,
            VerificationState::Valid
        );
    }
}
