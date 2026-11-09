//! SYNTHETIC SOFTWARE CONTRACT DATA ONLY. No observation owner, admission
//! capability, publication or destination authorization can be made here.
//! The caller supplies a test signature; no private key is held by this module.
use super::*;
use crate::coding_submission::SubmissionContract;
use serde_json::json;

pub struct FixtureCandidate {
    pub policy: RuntimeAdmissionPolicy,
    scope: CodingExecutionScope,
    observation: Value,
}
impl FixtureCandidate {
    /// Synthetic data-only input profile for independent receiver contract tests.
    /// This does not construct a sealed input owner, admission or VM owner.
    pub fn with_native_task_inputs(mut self) -> Self {
        self.policy.task_input_protocol = Some(super::inputs::protocol_root());
        self.scope.native_subtask = Some(crate::native_workflow::NativeSubtask {
            workflow: "a".repeat(64),
            role: crate::native_workflow::NativeTaskRole::Api,
            attempt: 0,
            history_prefix_blake3: "b".repeat(64),
            predecessor: None,
        });
        let data = super::inputs::NativeTaskInputs {
            schema: "realm.native-task-inputs/v1".into(),
            submission: self.scope.submission.clone(),
            native_subtask: self.scope.native_subtask.clone().unwrap(),
            runtime_blake3: blake3::hash(&serde_json::to_vec(&self.policy.expected).unwrap())
                .to_hex()
                .to_string(),
            policy_blake3: self.policy.input_policy_root().unwrap(),
        };
        self.scope.task_inputs_blake3 = Some(data.root().unwrap());
        self.policy.task_inputs = Some(data);
        self.observation["referee_identity_record"]["domain"] =
            "realm.owned-native-api-check/v1".into();
        self
    }
}
pub struct FixtureBundle {
    pub semantic: coding_semantics::CodingSemanticEvidence,
    pub permitted: SignedRuntimeAdmission,
    pub authority: &'static str,
    pub evidence_class: &'static str,
}
fn d(label: &str) -> String {
    blake3::hash(label.as_bytes()).to_hex().to_string()
}
fn hash(value: &Value) -> String {
    blake3::hash(&serde_json::to_vec(value).unwrap())
        .to_hex()
        .to_string()
}
fn file(name: &str, inode: u64, digest: String) -> Value {
    json!({"path":format!("/TEST_ONLY/{name}"),"blake3":digest,"device":1,"inode":inode,
        "size":1,"owner_uid":0,"owner_gid":0,"mode":0o555,"trusted_parent_chain":true})
}
fn process(pid: u32, vmm: bool) -> Value {
    let cgroup = json!({"mount_id":7,"device":5,"inode":6});
    let boot = "TEST_ONLY_NOT_A_REAL_BOOT";
    let birth = if vmm {
        process(pid, false)["root"].as_str().unwrap().to_owned()
    } else {
        String::new()
    };
    let mut h = blake3::Hasher::new();
    h.update(if vmm {
        b"realm.vmm.pidfd.identity.v2\0"
    } else {
        b"realm.run-owned-process.identity.v1\0"
    });
    h.update(&pid.to_le_bytes());
    for n in [200_u64, 70, 80] {
        h.update(&n.to_le_bytes());
    }
    h.update(&(boot.len() as u64).to_le_bytes());
    h.update(boot.as_bytes());
    for n in [7_u64, 5, 6] {
        h.update(&n.to_le_bytes());
    }
    if vmm {
        h.update(birth.as_bytes());
    }
    let mut value = json!({"pid":pid,"start_ticks":200,"pid_namespace_inode":70,
        "cgroup_namespace_inode":80,"boot_id":boot,"cgroup":cgroup,
        "root":h.finalize().to_hex().to_string()});
    if vmm {
        value["birth_identity_root"] = birth.into();
    }
    value
}

/// Produce unsigned, explicitly synthetic contract inputs. The policy contains
/// actual source fingerprints but every claimed host/process observation is
/// fictitious and must never enter the production admission registry.
pub fn fixture_candidate() -> FixtureCandidate {
    let scope = CodingExecutionScope {
        submission: SubmissionContract {
            run_id: d("TEST_ONLY run"),
            execution_id: d("TEST_ONLY execution"),
            challenge_root: d("TEST_ONLY challenge"),
            task_sha256: d("TEST_ONLY task"),
            worker_sha256: d("TEST_ONLY worker"),
        },
        source_commit: "f".repeat(40),
        checker_sha256: d("TEST_ONLY checker"),
        checker_scope_sha256: d("TEST_ONLY checker scope"),
        runtime_admission_id: None,
        native_subtask: None,
        task_inputs_blake3: None,
    };
    let stage = file("firecracker", 11, d("TEST_ONLY stage"));
    let vmm = file("realm-vmm", 12, d("TEST_ONLY VMM"));
    let kernel = file("kernel", 13, d("TEST_ONLY kernel"));
    let rootfs = file("rootfs.ext4", 14, d("TEST_ONLY rootfs"));
    let jailer = file("jailer", 21, d("TEST_ONLY jailer"));
    let mut entries = serde_json::Map::new();
    for (name, inode, mode) in [
        ("firecracker", 11, 0o100555),
        ("realm-vmm", 12, 0o100555),
        ("kernel", 13, 0o100555),
        ("rootfs.ext4", 14, 0o100555),
        ("dev/kvm", 15, 0o020600),
        ("run", 16, 0o040700),
        ("dev", 17, 0o040700),
    ] {
        entries.insert(
            name.into(),
            json!({"dev":1,"ino":inode,"mode":mode,"uid":0,"gid":0,"rdev":if name=="dev/kvm" {2792} else {0}}),
        );
    }
    let fence = json!({"policy":"realm.coding-fence/v1",
        "prelaunch_profile_blake3":blake3::hash(crate::coding_submission::NATIVE_EXECUTION_PROFILE.as_bytes()).to_hex().to_string(),
        "origin":{"root":{"dev":1,"ino":10},"entries":entries,"reachable_sockets":[],
            "phase":"native stage exec-stop before policy installation"},
        "original_exec_journal":file("TEST-exec.jsonl",22,d("TEST_ONLY exec journal")),
        "pid":100,"start_ticks":200,"stage":stage,"official":vmm,"net_namespace":[1,60],
        "ipc_namespace":[1,90],"qualification":"NOT_REGISTERED","policy_basis":"SYNTHETIC_TEST_ONLY"});
    let mut containment = json!({"prestart_measurement_root":d("TEST_ONLY prestart"),"jail_id":"TEST_ONLY",
        "jailer_pid":99,"jailer_process":{"pid":99,"boot_id":"TEST_ONLY_NOT_A_REAL_BOOT",
            "start_time_ticks":199,"owner_uid":0,"owner_gid":0,"executable":jailer},"jailer_exit_code":0,"vmm_exit_status":0,
        "firecracker_pid":100,"firecracker_pid_namespace":1,"input_binding_root":d("TEST_ONLY inputs"),
        "materialized_resources":[kernel,rootfs],"jailer":jailer,"uid":1000,"gid":1000,
        "user_name":"realm-fc","group_name":"realm-fc",
        "jail_root":{"device":1,"inode":10,"owner":0,"group":0,"mode":0o755},
        "cgroup":{"path":"/TEST_ONLY","device":5,"inode":6,"memory_max_bytes":1073741824_u64,"pids_max":32,"cpu_max":"100000 100000"},
        "cgroup_parent":{"path":"/TEST_ONLY_PARENT","device":5,"inode":8,"owner":0,"group":0,
            "mode":0o755,"subtree_control":["cpu","memory","pids"]},
        "namespaces":{"mount":[1,50],"pid":[1,70],"network":[1,60]},
        "seccomp":{"mode":2,"filter_count":1,"release_binary_sha256":d("TEST_ONLY release SHA")}});
    containment["jailer_process"]["executable"]["path"] = "/proc/99/exe".into();
    containment["jailer_process"]["executable"]["trusted_parent_chain"] = false.into();
    let mut terminal = json!({"cgroup":{"mount_id":7,"device":5,"inode":6},"vmm_identity":process(100,true),
        "terminal_epoch":1,"recovery_generation":0,"kill_requested_boottime_ns":1,"populated_zero_boottime_ns":2,
        "vmm_pidfd_exit_observed":true,"raw_evidence_root":d("placeholder"),"raw_cgroup_events":"populated 0\nfrozen 0\n",
        "raw_cgroup_procs":"","raw_cgroup_threads":"","pidfd_poll_revents":1});
    terminal["raw_evidence_root"] = observations::kernel_root(&terminal).unwrap().into();
    let sources = crate::coding_referee::COMPILED_SOURCES
        .into_iter()
        .enumerate()
        .map(|(i, (name, bytes))| {
            json!([
                format!("/TEST_ONLY/{name}"),
                file(
                    name,
                    30 + i as u64,
                    blake3::hash(bytes).to_hex().to_string()
                )
            ])
        })
        .collect::<Vec<_>>();
    let referee = json!({"domain":"realm.owned-coding-task-check/v2","prelaunch_scope":scope,
        "binding":scope.submission,"packet":d("TEST_ONLY packet"),"native_custody":d("TEST_ONLY custody"),
        "broker_completion":d("TEST_ONLY completion"),"measurement":d("TEST_ONLY measurement"),"barrier":d("TEST_ONLY barrier"),
        "process":process(101,false),"python":file("python",40,d("TEST_ONLY python")),
        "bwrap":file("bwrap",41,d("TEST_ONLY bwrap")),"sources":sources,
        "request_blake3":d("TEST_ONLY request"),"subject_packet_blake3":d("TEST_ONLY packet"),
        "seed":"1","result_blake3":d("TEST_ONLY referee result")});
    let descriptors = json!([
        {"fd":0,"device":1,"inode":18,"mode":0o020666,"flags":0,"target":"/dev/null"},
        {"fd":1,"device":1,"inode":19,"mode":0o100600,"flags":1,"target":"/TEST_ONLY/stdout"},
        {"fd":2,"device":1,"inode":20,"mode":0o100600,"flags":1,"target":"/TEST_ONLY/stderr"},
        {"fd":3,"device":1,"inode":13,"mode":0o100555,"flags":0,"target":"/kernel"},
        {"fd":4,"device":1,"inode":14,"mode":0o100555,"flags":0,"target":"/rootfs.ext4"},
        {"fd":5,"device":1,"inode":15,"mode":0o020600,"flags":2,"target":"/dev/kvm"}
    ]);
    let snapshot = json!({"pid":100,"start_ticks":200,"descriptors":descriptors,"maps":"1000-2000 r-xp 00000000 00:00 0\n"});
    let raw_resources = serde_json::to_string(&json!([
        "realm.actual-vmm-resources/v1",
        d("TEST_ONLY prestart"),
        kernel,
        rootfs,
        [snapshot, snapshot, snapshot]
    ]))
    .unwrap();
    let observation = json!({"domain":"realm.native-coding-provenance/v2","authority":"NONE","qualification":"NOT_REGISTERED",
        "measurement":d("TEST_ONLY measurement"),"scope":scope,"frontier":d("TEST_ONLY frontier"),"barrier":d("TEST_ONLY barrier"),
        "capture_root":d("TEST_ONLY capture"),"resources_root":blake3::hash(raw_resources.as_bytes()).to_hex().to_string(),
        "fence":fence,"controller":file("controller",42,d("TEST_ONLY controller")),"referee_root":hash(&referee),
        "referee_identity_record":referee,"containment":containment,
        "host":{"sysname":"Linux","release":"TEST_ONLY_RELEASE","version":"TEST_ONLY_VERSION","machine":"x86_64",
            "landlock_abi":3,"basis":"SYNTHETIC_TEST_ONLY"},"resources_raw_json":raw_resources,"terminal":terminal,
        "trust_basis":"SYNTHETIC_TEST_ONLY_NO_EXECUTION_AUTHORITY","profile_source_blake3":profile_source_root(),
        "controller_policy_blake3":d("TEST_ONLY controller policy")});
    let policy = RuntimeAdmissionPolicy {
        task_input_protocol: None,
        task_inputs: None,
        schema_version: 1,
        authorization_domain: DOMAIN.into(),
        profile_source_blake3: profile_source_root(),
        semantic_scope: coding_semantics::SCOPE.into(),
        excluded_claims: coding_semantics::EXCLUDED.map(str::to_owned).to_vec(),
        expected: RuntimeTuple::from_observations(&observation, &scope).unwrap(),
        build: RuntimeBuildReview {
            schema: "realm.runtime-build-review/v1".into(),
            source_commit: scope.source_commit.clone(),
            cargo_lock_blake3: blake3::hash(include_bytes!("../../../../Cargo.lock"))
                .to_hex()
                .to_string(),
            build_inputs: BTreeMap::from([("TEST_ONLY_COMPILER".into(), d("TEST_ONLY compiler"))]),
            review_evidence_blake3: d("TEST_ONLY review"),
        },
        official_campaign_blake3: d("TEST_ONLY campaign NEVER EXECUTED"),
        nonce: d("TEST_ONLY admission nonce"),
        not_before_unix: 1000,
        expires_at_unix: 2000,
    };
    policy.validate().unwrap();
    FixtureCandidate {
        policy,
        scope,
        observation,
    }
}

/// Finish synthetic data using an explicitly test-signed statement. This does
/// NOT verify its signature or admit it. The receiver must independently check
/// it against fixture-only trust, and production verification must still refuse.
pub fn finish_fixture(
    mut candidate: FixtureCandidate,
    admission: SignedRuntimeAdmission,
) -> FixtureBundle {
    assert_eq!(admission.policy().unwrap(), candidate.policy);
    let admission_identity = admission.identity().unwrap();
    candidate.scope.runtime_admission_id = Some(admission_identity.clone());
    let v = &mut candidate.observation;
    v["scope"] = serde_json::to_value(&candidate.scope).unwrap();
    v["referee_identity_record"]["prelaunch_scope"] = v["scope"].clone();
    v["referee_root"] = hash(&v["referee_identity_record"]).into();
    observations::validate(v, &candidate.scope).unwrap();
    // Synthetic contract timestamps must fit the supplied TEST statement,
    // including one issued by the real automatic supplier. No real execution
    // or observation time is asserted by this fixture data factory.
    let window = candidate.policy.expires_at_unix - candidate.policy.not_before_unix;
    let admitted_at_unix = candidate.policy.not_before_unix + u64::from(window > 1);
    let qualified_at_unix = candidate.policy.not_before_unix + 2_u64.min(window - 1);
    let qualification = QualificationEvidence {
        schema_version: 1,
        admission: admission.clone(),
        admission_identity,
        observed_runtime: RuntimeTuple::from_observations(v, &candidate.scope).unwrap(),
        observation_root: hash(v),
        admitted_at_unix,
        qualified_at_unix,
    };
    let r = &v["referee_identity_record"];
    let s = |name: &str| r[name].as_str().unwrap().to_owned();
    let semantic = coding_semantics::CodingSemanticEvidence {
        workflow: None,
        scope: if candidate.scope.native_subtask.is_some() {
            coding_semantics::API_SCOPE
        } else {
            coding_semantics::SCOPE
        }
        .into(),
        prelaunch: candidate.scope,
        packet_blake3: s("packet"),
        consumed_request_blake3: s("request_blake3"),
        referee_root: v["referee_root"].as_str().unwrap().into(),
        referee_identity_record: Some(r.clone()),
        provenance_root: qualification.identity().unwrap(),
        runtime_provenance_record: Some(v.clone()),
        runtime_qualification: Some(qualification),
        custody_root: s("native_custody"),
        broker_completion_root: s("broker_completion"),
        frontier_root: v["frontier"].as_str().unwrap().into(),
        measurement_root: s("measurement"),
        barrier_root: s("barrier"),
        excluded_claims: coding_semantics::EXCLUDED.map(str::to_owned).to_vec(),
    };
    semantic.validate_shape().unwrap();
    FixtureBundle {
        semantic,
        permitted: admission,
        authority: "NONE",
        evidence_class: "SYNTHETIC_SOFTWARE_CONTRACT_ONLY",
    }
}
