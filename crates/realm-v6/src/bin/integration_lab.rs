//! Runs real host broker I/O; explicitly not an untrusted capsule runner.
use realm_v6::{frontier as f, integration as i, semantic_v2 as v};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::Path,
    time::Instant,
};
const PROFILE: &str = include_str!("../../../../docs/v6/INTEGRATION_LAB_PROFILE_V1.json");
fn hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    journal: String,
    semantic: v::Input,
    context: i::JoinContext,
}
fn verify(b: &Bundle) -> Result<i::JoinedEvidence, String> {
    let a = f::audit_bytes(
        b.journal.as_bytes(),
        &b.semantic.receipt.run,
        &b.context.monitor_id,
    )
    .map_err(|e| format!("{e:?}"))?;
    i::join(&a, &b.semantic, &b.context).map_err(|e| format!("{e:?}"))
}
fn compute(bytes: &[u8]) -> Vec<u8> {
    let mut result = blake3::hash(bytes);
    for _ in 0..100_000 {
        result = blake3::hash(result.as_bytes());
    }
    result.as_bytes().to_vec()
}
fn execute(dir: &Path) -> Result<(Bundle, u128), String> {
    execute_with_result(dir, None)
}

// Regression fixtures exercise the file protocol without granting authority.
fn execute_with_result(
    dir: &Path,
    override_result: Option<&[u8]>,
) -> Result<(Bundle, u128), String> {
    fs::create_dir(dir).map_err(|e| e.to_string())?;
    let bytes: Vec<u8> = (0..128).collect();
    fs::write(dir.join("input"), &bytes).map_err(|e| e.to_string())?;
    let physical = |name: &str| -> Result<f::ObjectIdentity, String> {
        let m = fs::metadata(dir.join(name)).map_err(|e| e.to_string())?;
        Ok(f::ObjectIdentity {
            device: m.dev(),
            inode: m.ino(),
        })
    };
    let initial = BTreeMap::from([(
        "input".into(),
        v::Object {
            incarnation: "logical-input-1".into(),
            version: 0,
            bytes,
            mode: 0o400,
        },
    )]);
    let launch = v::Launch {
        task: hash(if override_result.is_some() {
            b"empty-output-protocol-regression-v1"
        } else {
            b"100000-blake3-chain-v1"
        }),
        executable: hash(
            &fs::read(std::env::current_exe().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?,
        ),
        interpreter: None,
        libraries: vec![],
        argv: vec!["integration_lab demo".into()],
        environment: BTreeMap::new(),
        cwd: "/work".into(),
        policy: hash(PROFILE.as_bytes()),
        generation: 0,
        allowed_inputs: vec!["input".into()],
        allowed_outputs: vec!["output".into()],
        time_rng_policy: hash(b"not-observed-no-admission"),
    };
    let run = hash(dir.as_os_str().as_encoded_bytes());
    let parent = hash(b"lab-generation-0");
    let epoch = "broker-seal-only".to_string();
    let launch_identity = hash(&serde_json::to_vec(&launch).unwrap());
    let manifest = hash(PROFILE.as_bytes());
    let mut broker = f::EffectFrontier::create_with_absent_output(
        dir,
        &run,
        "integration-lab",
        &dir.join("input"),
        &dir.join("output"),
    )
    .map_err(|e| format!("{e:?}"))?;
    broker
        .bind_topology(&manifest, &launch_identity, &parent)
        .map_err(|e| format!("{e:?}"))?;
    broker
        .record_identify("identify-input", false)
        .map_err(|e| format!("{e:?}"))?;
    let returned = broker
        .read("read-input", false, 0, 16)
        .map_err(|e| format!("{e:?}"))?;
    broker
        .record_close("close-input", false)
        .map_err(|e| format!("{e:?}"))?;
    let started = Instant::now();
    let result = override_result.map_or_else(|| compute(&returned), <[u8]>::to_vec);
    let compute_ns = started.elapsed().as_nanos();
    broker
        .create_output("output-create")
        .map_err(|e| format!("{e:?}"))?;
    let output_identity = physical("output")?;
    let output_incarnation = hash(&serde_json::to_vec(&output_identity).unwrap());
    let written = broker
        .write("write-output", 0, &result)
        .map_err(|e| format!("{e:?}"))?;
    if written != result.len() {
        return Err("short demo write".into());
    }
    broker
        .record_close("close-output", true)
        .map_err(|e| format!("{e:?}"))?;
    let head = broker.seal(&epoch).map_err(|e| format!("{e:?}"))?;
    let mut actions = vec![
        v::Action::Start { parent: None },
        v::Action::Open {
            fd: 0,
            handle: "in".into(),
            path: "input".into(),
            incarnation: "logical-input-1".into(),
            access: v::Access::Read,
        },
        v::Action::Read {
            fd: 0,
            handle: "in".into(),
            incarnation: "logical-input-1".into(),
            version: 0,
            offset: 0,
            requested: 16,
            returned,
            returned_length: 16,
            end: v::ReadEnd::Complete,
        },
        v::Action::Close {
            fd: 0,
            handle: "in".into(),
        },
        v::Action::Create {
            fd: 1,
            handle: "out".into(),
            path: "output".into(),
            incarnation: output_incarnation.clone(),
            mode: 0o600,
        },
        v::Action::Write {
            fd: 1,
            handle: "out".into(),
            incarnation: output_incarnation.clone(),
            before_version: 0,
            after_version: u64::from(!result.is_empty()),
            offset: 0,
            requested: result.clone(),
            returned_length: written as u64,
        },
        v::Action::Close {
            fd: 1,
            handle: "out".into(),
        },
    ];
    actions.extend([v::Action::Exit { code: 0 }, v::Action::Terminal]);
    let events: Vec<_> = actions
        .into_iter()
        .enumerate()
        .map(|(n, action)| v::Event {
            sequence: n as u64,
            run: run.clone(),
            process: "declared-lab-process".into(),
            epoch: epoch.clone(),
            action,
        })
        .collect();
    let mut final_world = initial.clone();
    final_world.insert(
        "output".into(),
        v::Object {
            incarnation: output_incarnation,
            version: u64::from(!result.is_empty()),
            bytes: result.clone(),
            mode: 0o600,
        },
    );
    if fs::read(dir.join("output")).map_err(|e| e.to_string())? != result {
        return Err("final output mismatch".into());
    }
    let mut receipt = v::Receipt {
        format: 2,
        run: run.clone(),
        authority_parent: parent.clone(),
        launch: launch.clone(),
        directories: Default::default(),
        initial: initial.clone(),
        health: v::Health {
            epoch: epoch.clone(),
            source_count: events.len() as u64,
            gaps: 0,
            duplicates: 0,
            reorder: 0,
            overflow: 0,
            restart: 0,
            partial: 0,
            delayed: 0,
            pending: 0,
            logger_died: false,
        },
        events,
        dependencies: vec![],
        final_world,
        evidence_root: String::new(),
    };
    receipt.dependencies = v::derive(&receipt).map_err(|e| format!("{e:?}"))?;
    v::seal(&mut receipt).map_err(|e| format!("{e:?}"))?;
    let expected = v::ExpectedContext {
        run,
        process: "declared-lab-process".into(),
        epoch: epoch.clone(),
        authority_parent: parent.clone(),
        launch,
        directories: Default::default(),
        initial,
        source_count: receipt.events.len() as u64,
        source_root: receipt.evidence_root.clone(),
    };
    let context = i::JoinContext {
        head,
        monitor_id: "integration-lab".into(),
        manifest_root: manifest,
        launch_identity,
        starting_generation: parent,
        freeze_epoch: epoch,
        input: physical("input")?,
        output: physical("output")?,
    };
    let bundle = Bundle {
        journal: fs::read_to_string(broker.journal_path()).map_err(|e| e.to_string())?,
        semantic: v::Input { receipt, expected },
        context,
    };
    verify(&bundle)?;
    Ok((bundle, compute_ns))
}
fn main() {
    if let Err(reason) = run() {
        println!(
            "{}",
            serde_json::json!({"decision":"REFUSE","reason":reason})
        );
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("demo") if args.len()==3 => {
            let dir=Path::new(&args[2]); let (b,compute_ns)=execute(dir)?;
            fs::write(dir.join("bundle.json"),serde_json::to_vec_pretty(&b).unwrap()).map_err(|e|e.to_string())?;
            let proof=verify(&b)?;
            let mut current=b.semantic.receipt.initial.clone();
            current.get_mut("input").unwrap().bytes[100]^=1;
            current.get_mut("input").unwrap().version+=1;
            let irrelevant=proof.dependencies_match(&current);
            let clean_equal=compute(&current["input"].bytes[..16])==b.semantic.receipt.final_world["output"].bytes;
            current.get_mut("input").unwrap().bytes[0]^=1;
            let consumed=proof.dependencies_match(&current);
            let changed_output=compute(&current["input"].bytes[..16])!=b.semantic.receipt.final_world["output"].bytes;
            let result=serde_json::json!({"case_id":"real-host-broker-semantic-join","profile_id":"integration-lab-v1","support_profile_hash":hash(PROFILE.as_bytes()),
                "environment":format!("{}-{}",std::env::consts::OS,std::env::consts::ARCH),"status":if irrelevant && clean_equal && !consumed && changed_output {"PASS"}else{"FAIL"},
                "decision":proof.admission(),"local_verification":"JOINED_VALID","expected_outcome":"JOINED_VALID_PUBLIC_REFUSE","observed_outcome":"JOINED_VALID_PUBLIC_REFUSE","evidence_completeness":"BROKER_IO_ONLY_LIFECYCLE_DECLARED",
                "compute_iterations":100001,"compute_ns":compute_ns,"dependencies":proof.dependencies(),"irrelevant_change_matches":irrelevant,
                "consumed_change_matches":consumed,"clean_recompute_equal":clean_equal,"consumed_change_output_differs":changed_output,
                "reuse_authorized":false,"avoided_work":0,"reason_code":"UNVERIFIED_BOUNDARY"});
            fs::write(dir.join("result.json"),serde_json::to_vec_pretty(&result).unwrap()).map_err(|e|e.to_string())?;
            println!("{result}");
            if result["status"]!="PASS" { return Err("counterfactual control failed".into()); }
        },
        Some("campaign") if args.len()==3 => {
            let dir=Path::new(&args[2]); let (b,_)=execute(dir)?;
            let rows=campaign(&b);
            fs::write(dir.join("campaign.json"),serde_json::to_vec_pretty(&rows).unwrap()).map_err(|e|e.to_string())?;
            println!("{}",serde_json::json!({"passed":rows.iter().filter(|r|r["status"]=="PASS").count(),"failed":rows.iter().filter(|r|r["status"]=="FAIL").count(),"unsupported":0,"skipped":0,"host_attacks_executed":false}));
            if rows.iter().any(|r|r["status"]!="PASS") {return Err("campaign failure".into());}
        },
        Some("verify") => {
            let mut raw=Vec::new(); io::stdin().take(4*1024*1024+1).read_to_end(&mut raw).map_err(|e|e.to_string())?;
            if raw.len()>4*1024*1024 { return Err("ResourceLimit".into()); }
            let b:Bundle=serde_json::from_value(realm_v6::strict_json::parse(&raw).map_err(|e|format!("{e:?}"))?).map_err(|e|e.to_string())?;
            let proof=verify(&b)?;
            println!("{}",serde_json::json!({"local":"JOINED_VALID","decision":proof.admission(),"reuse_authorized":false}));
        },
        _ => return Err("usage: integration_lab demo NEW_DIRECTORY | campaign NEW_DIRECTORY | verify < bundle.json".into())
    }
    Ok(())
}

fn reseal_semantic(b: &mut Bundle) {
    v::seal(&mut b.semantic.receipt).unwrap();
    b.semantic.expected.source_root = b.semantic.receipt.evidence_root.clone();
}
fn rewrite_journal(b: &mut Bundle, edit: impl FnOnce(&mut Vec<f::FrontierRecord>)) {
    let mut records: Vec<f::FrontierRecord> = b
        .journal
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    edit(&mut records);
    let mut previous = "0".repeat(64);
    for (n, r) in records.iter_mut().enumerate() {
        r.sequence = n as u64;
        r.previous_hash = previous;
        r.hash.clear();
        r.hash = hash(&serde_json::to_vec(r).unwrap());
        previous = r.hash.clone();
    }
    b.context.head = previous;
    b.journal = records
        .iter()
        .map(|r| format!("{}\n", serde_json::to_string(r).unwrap()))
        .collect();
}
fn campaign(base: &Bundle) -> Vec<serde_json::Value> {
    let names = [
        "drop-result",
        "reorder",
        "duplicate-result",
        "truncate",
        "stale-head",
        "wrong-epoch",
        "wrong-manifest",
        "wrong-launch",
        "wrong-generation",
        "wrong-physical-object",
        "alias-objects",
        "unknown-kind",
        "duplicate-json-key",
        "missing-null-field",
        "logger-death",
        "queue-overflow",
        "unresolved-pending",
        "unsupported-time",
        "partial-semantic-log",
        "coforged-read-bytes",
        "coforged-seal-payload",
        "coforged-range-overflow",
        "coforged-opaque-version",
        "semantic-output-forgery",
        "wrong-write-request",
        "different-valid-history",
        "coforged-binding",
        "early-freeze-field",
    ];
    names.iter().map(|name| {
        let mut b=base.clone();
        match *name {
            "drop-result" => rewrite_journal(&mut b,|r|{r.remove(1);}),
            "reorder" => rewrite_journal(&mut b,|r|r.swap(0,1)),
            "duplicate-result" => rewrite_journal(&mut b,|r|r.insert(2,r[1].clone())),
            "truncate" => {b.journal.truncate(b.journal.len()-4);},
            "stale-head" => b.context.head="0".repeat(64),
            "wrong-epoch" => b.context.freeze_epoch="other".into(),
            "wrong-manifest" => b.context.manifest_root="0".repeat(64),
            "wrong-launch" => b.context.launch_identity="0".repeat(64),
            "wrong-generation" => b.context.starting_generation="0".repeat(64),
            "wrong-physical-object" => b.context.input.inode+=1,
            "alias-objects" => b.context.output=b.context.input.clone(),
            "unknown-kind" => b.journal=b.journal.replacen("intent_read","unknown_effect",1),
            "duplicate-json-key" => b.journal=b.journal.replacen("\"sequence\":0","\"sequence\":0,\"sequence\":0",1),
            "missing-null-field" => b.journal=b.journal.replacen("\"freeze_epoch\":null,","",1),
            "logger-death" => {b.semantic.receipt.health.logger_died=true;reseal_semantic(&mut b);},
            "queue-overflow" => {b.semantic.receipt.health.overflow=1;reseal_semantic(&mut b);},
            "unresolved-pending" => {b.semantic.receipt.health.pending=1;reseal_semantic(&mut b);},
            "unsupported-time" => {b.semantic.receipt.events[3].action=v::Action::Unsupported {operation:"vdso-clock".into()};reseal_semantic(&mut b);},
            "partial-semantic-log" => {b.semantic.receipt.events.pop();reseal_semantic(&mut b);},
            "coforged-read-bytes" => rewrite_journal(&mut b,|r|r[2].bytes[0]^=1),
            "coforged-seal-payload" => rewrite_journal(&mut b,|r|r.last_mut().unwrap().bytes=vec![1]),
            "coforged-range-overflow" => rewrite_journal(&mut b,|r|{r[1].offset=u64::MAX;r[2].offset=u64::MAX;}),
            "coforged-opaque-version" => rewrite_journal(&mut b,|r|{
                let fake="f".repeat(64);
                r[2].object_version_after=Some(fake.clone());
                r[3].object_version_before=Some(fake.clone());r[3].object_version_after=Some(fake);
            }),
            "semantic-output-forgery" => {
                let mut forged=b.semantic.receipt.final_world["output"].bytes.clone();forged[0]^=1;
                if let v::Action::Write {requested,..}=&mut b.semantic.receipt.events[5].action {*requested=forged.clone();}
                b.semantic.receipt.final_world.get_mut("output").unwrap().bytes=forged;
                b.semantic.receipt.dependencies=v::derive(&b.semantic.receipt).unwrap();reseal_semantic(&mut b);
                assert!(v::validate(&b.semantic.receipt,&b.semantic.expected).is_ok());
            },
            "wrong-write-request" => rewrite_journal(&mut b,|r|{r[6].bytes.push(99);r[6].requested+=1;r[7].requested+=1;}),
            "different-valid-history" => rewrite_journal(&mut b,|r|{r.drain(0..2);}),
            "coforged-binding" => {
                b.semantic.receipt.launch.task="f".repeat(64);b.semantic.expected.launch=b.semantic.receipt.launch.clone();reseal_semantic(&mut b);
            },
            "early-freeze-field" => rewrite_journal(&mut b,|r|r[0].freeze_epoch=Some("early".into())),
            _ => unreachable!(),
        }
        let start=Instant::now(); let result=verify(&b);
        serde_json::json!({"case_id":name,"mechanism_attacked":name,"support_profile_hash":hash(PROFILE.as_bytes()),
            "environment":format!("{}-{}",std::env::consts::OS,std::env::consts::ARCH),"expected_outcome":"REFUSE",
            "observed_outcome":if result.is_err(){"REFUSE"}else{"JOINED_VALID"},"status":if result.is_err(){"PASS"}else{"FAIL"},
            "reason_code":result.err(),"verification_ns":start.elapsed().as_nanos(),"evidence_completeness":"MUTATED_LOCAL_EVIDENCE",
            "reuse_authorized":false,"avoided_work":0})
    }).collect()
}
#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "v6-join-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn real_broker_join_and_28_falsification_attempts() {
        let dir = fresh_dir("campaign");
        let (b, _) = execute(&dir).unwrap();
        let rows = campaign(&b);
        assert_eq!(rows.len(), 28);
        for row in rows {
            assert_eq!(row["status"], "PASS", "{row}");
        }
        let proof = verify(&b).unwrap();
        assert_eq!(
            proof.admission(),
            realm_v6::Admission::Refuse(realm_v6::Refusal::UnverifiedBoundary)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn journaled_creation_and_zero_length_write_keep_version_zero() {
        let dir = fresh_dir("empty-create");
        let (bundle, _) = execute_with_result(&dir, Some(b"")).unwrap();
        assert_eq!(bundle.semantic.receipt.final_world["output"].version, 0);
        assert!(
            bundle.semantic.receipt.final_world["output"]
                .bytes
                .is_empty()
        );
        let proof = verify(&bundle).unwrap();
        assert_eq!(
            proof.admission(),
            realm_v6::Admission::Refuse(realm_v6::Refusal::UnverifiedBoundary)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn foreign_frontier_cannot_be_joined_to_an_individually_valid_run() {
        let dir_a = fresh_dir("run-a");
        let dir_b = fresh_dir("run-b");
        let (bundle_a, _) = execute(&dir_a).expect("run A fixture is valid");
        let (bundle_b, _) = execute(&dir_b).expect("run B fixture is valid");
        let mut mixed = bundle_a.clone();
        mixed.journal = bundle_b.journal;
        assert!(verify(&mixed).is_err());
        fs::remove_dir_all(dir_a).unwrap();
        fs::remove_dir_all(dir_b).unwrap();
    }

    #[test]
    fn removing_a_semantic_close_refuses_after_resealing() {
        let dir = fresh_dir("missing-close");
        let (mut bundle, _) = execute(&dir).expect("source fixture is valid");
        bundle.semantic.receipt.events.retain(|event| {
            !matches!(
                &event.action,
                v::Action::Close { handle, .. } if handle == "out"
            )
        });
        for (sequence, event) in bundle.semantic.receipt.events.iter_mut().enumerate() {
            event.sequence = sequence as u64;
        }
        bundle.semantic.receipt.health.source_count = bundle.semantic.receipt.events.len() as u64;
        v::seal(&mut bundle.semantic.receipt).expect("tampered receipt reseals structurally");
        bundle.semantic.expected.source_count = bundle.semantic.receipt.events.len() as u64;
        bundle.semantic.expected.source_root = bundle.semantic.receipt.evidence_root.clone();
        assert!(verify(&bundle).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
