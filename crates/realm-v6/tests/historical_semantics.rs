use realm_v6::{Receipt, validate_receipt};
#[test]
fn retained_accepted_invalid_v1_histories_now_refuse() {
    let fixtures: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("semantic_fixtures/historical_v1.json")).unwrap();
    assert_eq!(fixtures.len(), 12);
    for case in fixtures {
        let receipt: Receipt = serde_json::from_value(case["receipt"].clone()).unwrap();
        assert!(
            validate_receipt(&receipt).is_err(),
            "historical bug {}",
            case["id"]
        );
    }
}

#[test]
fn duplicate_path_keys_are_not_silently_overwritten() {
    let raw = include_bytes!("semantic_fixtures/duplicate_path_v1.json");
    assert!(realm_v6::strict_json::parse(raw).is_err());
    assert_eq!(
        realm_v6::admit(raw, std::path::Path::new("/unavailable")),
        realm_v6::Admission::Refuse(realm_v6::Refusal::Malformed)
    );
}
