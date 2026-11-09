use realm_v6::{Admission, Refusal, semantic_v2 as v2};
use serde_json::Value;
fn cases() -> Vec<Value> {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../scripts/v6/semantic_cases/corpus_v2.json"
    ))
    .unwrap();
    corpus["cases"].as_array().unwrap().clone()
}
fn positive(name: &str) -> v2::Input {
    let case = cases()
        .into_iter()
        .find(|v| v["id"] == format!("positive/{name}"))
        .unwrap();
    serde_json::from_value(case["input"].clone()).unwrap()
}
#[test]
fn frozen_139_attacks_and_12_controls() {
    let mut counts = (0, 0);
    for case in cases() {
        let parsed = serde_json::from_value::<v2::Input>(case["input"].clone());
        let result = parsed.and_then(|input| {
            v2::validate(&input.receipt, &input.expected)
                .map_err(|e| serde::de::Error::custom(format!("{e:?}")))
        });
        if case["expected"] == "REJECT" {
            counts.0 += 1;
            assert!(result.is_err(), "{}", case["id"]);
        } else {
            counts.1 += 1;
            assert!(result.is_ok(), "{}: {:?}", case["id"], result.err());
        }
    }
    assert_eq!(counts, (139, 12));
}
#[test]
fn consumed_ranges_ignore_unconsumed_bytes_but_not_incarnation() {
    let input = positive("read_write_own_read");
    let proof = v2::validate(&input.receipt, &input.expected).unwrap();
    let mut current = input.receipt.initial.clone();
    current.get_mut("input").unwrap().bytes[100] = 255;
    current.get_mut("input").unwrap().version += 1;
    assert!(proof.ranges_match(&current));
    current.get_mut("input").unwrap().bytes[0] = 255;
    assert!(!proof.ranges_match(&current));
    current = input.receipt.initial.clone();
    current.get_mut("input").unwrap().incarnation = "new-object".into();
    assert!(!proof.ranges_match(&current));
}
#[test]
fn eof_is_a_dependency_but_short_read_is_not_eof() {
    let input = positive("eof_read");
    let proof = v2::validate(&input.receipt, &input.expected).unwrap();
    let mut current = input.receipt.initial.clone();
    current.get_mut("input").unwrap().bytes.push(1);
    assert!(!proof.ranges_match(&current));
    let input = positive("short_read");
    let proof = v2::validate(&input.receipt, &input.expected).unwrap();
    let mut current = input.receipt.initial.clone();
    current.get_mut("input").unwrap().bytes[8] = 255;
    assert!(proof.ranges_match(&current));
    assert_eq!(proof.dependencies()[0].returned_length, 5);
}
#[test]
fn own_write_read_and_overlaps_have_exact_provenance() {
    let input = positive("overlapping_writes_provenance");
    let proof = v2::validate(&input.receipt, &input.expected).unwrap();
    let read = &proof.dependencies()[1];
    assert_eq!(read.provenance.len(), 2);
    assert_eq!(read.provenance[0].length, 3);
    assert_eq!(
        read.provenance[0].origin,
        v2::Origin::Write {
            sequence: 8,
            offset: 0
        }
    );
    assert_eq!(read.provenance[1].length, 7);
    assert_eq!(
        read.provenance[1].origin,
        v2::Origin::Write {
            sequence: 5,
            offset: 3
        }
    );
    assert_eq!(read.observed_version, 2);
}
#[test]
fn all_public_admission_remains_unavailable_even_with_coforged_context() {
    for case in cases()
        .into_iter()
        .filter(|v| v["expected"] == "LOCAL_VALID")
    {
        let mut input: v2::Input = serde_json::from_value(case["input"].clone()).unwrap();
        assert_eq!(
            v2::admit(&input.receipt, &input.expected),
            Admission::Refuse(Refusal::UnverifiedBoundary)
        );
        input.receipt.launch.executable = "b".repeat(64);
        input.expected.launch = input.receipt.launch.clone();
        v2::seal(&mut input.receipt).unwrap();
        input.expected.source_root = input.receipt.evidence_root.clone();
        assert!(v2::validate(&input.receipt, &input.expected).is_ok());
        assert_eq!(
            v2::admit(&input.receipt, &input.expected),
            Admission::Refuse(Refusal::UnverifiedBoundary)
        );
    }
}
#[test]
fn parser_rejects_partial_duplicate_and_ambiguous_json() {
    let input = positive("read_write_own_read");
    let raw = serde_json::to_vec(&input).unwrap();
    for prefix in 0..raw.len() {
        assert!(realm_v6::strict_json::parse(&raw[..prefix]).is_err());
    }
    for raw in [
        br#"{"x":1,"x":2}"#.as_slice(),
        br#"{"nested":{"fd":1,"fd":2}}"#,
        br#"{"value":1.0}"#,
        br#"{"value":NaN}"#,
    ] {
        assert!(realm_v6::strict_json::parse(raw).is_err());
    }
}

#[test]
fn exclusive_create_absence_is_an_observed_dependency() {
    let input = positive("read_write_own_read");
    let proof = v2::validate(&input.receipt, &input.expected).unwrap();
    let mut current = input.receipt.initial.clone();
    current.insert("output".into(), input.receipt.final_world["output"].clone());
    assert!(!proof.ranges_match(&current));
}

#[test]
fn nullable_fields_are_required_and_sets_cannot_hide_duplicates() {
    let cases: Vec<Value> = serde_json::from_str(include_str!(
        "../../../scripts/v6/semantic_cases/wire_regressions_v2.json"
    ))
    .unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        assert!(
            serde_json::from_value::<v2::Input>(case["input"].clone()).is_err(),
            "{}",
            case["id"]
        );
    }
}

#[test]
fn directory_identity_and_topology_are_separate_dependencies() {
    let input = positive("immutable_directory_input");
    let proof = v2::validate(&input.receipt, &input.expected).unwrap();
    assert!(proof.dependencies_match(&input.receipt.initial, &input.receipt.directories));
    assert!(!proof.dependencies_match(&input.receipt.initial, &Default::default()));
}

#[test]
fn host_observed_poweroff_is_not_forged_as_an_exit_code() {
    let mut input = positive("read_write_own_read");
    let terminal = input
        .receipt
        .events
        .iter_mut()
        .find(|event| matches!(event.action, v2::Action::Exit { code: 0 }))
        .unwrap();
    terminal.action = v2::Action::Poweroff {
        observation_root: "a".repeat(64),
    };
    v2::seal(&mut input.receipt).unwrap();
    input.expected.source_root = input.receipt.evidence_root.clone();
    assert!(v2::validate(&input.receipt, &input.expected).is_ok());

    let terminal = input
        .receipt
        .events
        .iter_mut()
        .find(|event| matches!(event.action, v2::Action::Poweroff { .. }))
        .unwrap();
    terminal.action = v2::Action::Poweroff {
        observation_root: "not-a-digest".into(),
    };
    v2::seal(&mut input.receipt).unwrap();
    input.expected.source_root = input.receipt.evidence_root.clone();
    assert_eq!(
        v2::validate(&input.receipt, &input.expected).unwrap_err(),
        Refusal::InvalidDigest
    );
}
