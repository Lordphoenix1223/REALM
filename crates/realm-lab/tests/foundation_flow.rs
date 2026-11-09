use realm_cas::PreimageStore;
use realm_contract::compile_contract;
use realm_core::{
    ActorIdentity, ActorKind, EvidenceStrength, Fidelity, ObjectId, ObjectVersion, ObjectVersionId,
    PathBytes, PreservationMethod, RealmEvent, RealmEventKind, TransactionMetadata,
    TransactionState,
};
use realm_recovery::{DisposableRecoveryWorkspace, RecoveryWorkspace, materialize_contract};
use realm_verify::{VerificationStatus, verify_candidate};
use std::{collections::BTreeMap, fs};

#[test]
fn end_to_end_exact_inverse_preserves_independent_state_and_rejects_overreach() {
    let root = std::env::temp_dir().join(format!("realm-foundation-flow-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("x.txt"), b"new target").unwrap();
    fs::write(root.join("q.txt"), b"independent").unwrap();
    let cas = PreimageStore::open(root.join("realm-store/cas")).unwrap();
    let old_blob = cas.put_bytes(b"old target").unwrap();
    let tx = TransactionMetadata::new(
        ActorIdentity {
            kind: ActorKind::OtherAgent,
            actor_id: "fixture".into(),
            semantic_session_id: None,
            declared_intent: Some("change x".into()),
        },
        "synthetic",
        "test",
    );
    let target_tx = tx.id;
    let object_x = ObjectId::new();
    let object_q = ObjectId::new();
    let before = ObjectVersionId::new();
    let after = ObjectVersionId::new();
    let q_version = ObjectVersionId::new();
    let before_version = ObjectVersion {
        id: before,
        object_id: object_x,
        content_hash: Some(blake3::hash(b"old target").to_hex().to_string()),
        metadata_hash: None,
        blob_ref: Some(old_blob.hash.clone()),
        provenance_event: Some(1),
        fidelity: Fidelity::ContentExact,
        preservation: PreservationMethod::ExactCopy,
    };
    let q_version_record = ObjectVersion {
        id: q_version,
        object_id: object_q,
        content_hash: Some(blake3::hash(b"independent").to_hex().to_string()),
        metadata_hash: None,
        blob_ref: None,
        provenance_event: None,
        fidelity: Fidelity::ContentExact,
        preservation: PreservationMethod::ExactCopy,
    };
    let other_tx = realm_core::TransactionId::new();
    let event = |sequence: u64,
                 transaction_id: realm_core::TransactionId,
                 object_id: ObjectId,
                 path: Vec<u8>,
                 kind: RealmEventKind,
                 pre: Option<ObjectVersionId>,
                 post: Option<ObjectVersionId>| RealmEvent {
        schema_version: 1,
        sequence,
        transaction_id,
        actor_id: "fixture".into(),
        process_id: None,
        object_id: Some(object_id),
        object_version_id: post,
        path: Some(PathBytes(path)),
        kind,
        evidence: EvidenceStrength::OsObserved,
        wall_time_ms: sequence as i64,
        monotonic_ns: sequence,
        pre_version: pre,
        post_version: post,
        metadata: serde_json::json!({}),
    };
    let events = vec![
        event(
            1,
            target_tx,
            object_x,
            b"x.txt".to_vec(),
            RealmEventKind::ObjectWriteObserved,
            Some(before),
            Some(after),
        ),
        event(
            2,
            other_tx,
            object_q,
            b"q.txt".to_vec(),
            RealmEventKind::ObjectWriteObserved,
            None,
            Some(q_version),
        ),
    ];
    let mut tx = tx;
    tx.state = TransactionState::Committed;
    let versions = BTreeMap::from([(before, before_version), (q_version, q_version_record)]);
    let current = BTreeMap::from([(object_q, q_version)]);
    let contract = compile_contract(&tx, &events, &versions, &current).unwrap();
    assert_eq!(contract.exact_restores.len(), 1);
    assert_eq!(contract.must_preserve.len(), 1);

    let workspace = DisposableRecoveryWorkspace::unique().unwrap();
    materialize_contract(&workspace, &root, &contract, &cas).unwrap();
    let report = verify_candidate(&root, workspace.root(), &contract).unwrap();
    assert_eq!(report.status, VerificationStatus::Verified);
    assert_eq!(
        fs::read(workspace.root().join("x.txt")).unwrap(),
        b"old target"
    );
    assert_eq!(fs::read(root.join("x.txt")).unwrap(), b"new target");

    fs::write(workspace.root().join("q.txt"), b"tampered").unwrap();
    let rejected = verify_candidate(&root, workspace.root(), &contract).unwrap();
    assert_eq!(rejected.status, VerificationStatus::Rejected);
    assert!(
        rejected
            .violations
            .iter()
            .any(|violation| violation.code == "OUT_OF_SCOPE_MODIFICATION")
    );
    workspace.cleanup().unwrap();
    fs::remove_dir_all(root).unwrap();
}
