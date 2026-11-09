//! Strict retained-data checking, never a constructor for native observation owners.
use super::*;
use std::collections::BTreeSet;

fn fields(v: &Value, names: &[&str]) -> Result<()> {
    let map = v.as_object().ok_or("observation object required")?;
    if map.len() != names.len() || names.iter().any(|n| !map.contains_key(*n)) {
        return Err("missing or unknown observation field".into());
    }
    Ok(())
}
fn uint(v: &Value) -> Result<u64> {
    v.as_u64().ok_or("observation integer required".into())
}
fn u32v(v: &Value) -> Result<u32> {
    u32::try_from(uint(v)?).map_err(|_| "observation u32 overflow".into())
}
fn strv(v: &Value) -> Result<&str> {
    v.as_str()
        .filter(|v| v.len() <= 1024 * 1024)
        .ok_or("observation string required".into())
}
fn root(v: &Value) -> Result<&str> {
    let s = strv(v)?;
    if !digest(s) {
        return Err("observation root required".into());
    }
    Ok(s)
}
fn hash(v: &Value) -> Result<String> {
    Ok(
        blake3::hash(&serde_json::to_vec(v).map_err(|e| e.to_string())?)
            .to_hex()
            .to_string(),
    )
}
fn file(v: &Value) -> Result<()> {
    file_shape(v, true)
}
fn file_shape(v: &Value, trusted: bool) -> Result<()> {
    fields(
        v,
        &[
            "path",
            "blake3",
            "device",
            "inode",
            "size",
            "owner_uid",
            "owner_gid",
            "mode",
            "trusted_parent_chain",
        ],
    )?;
    if !Path::new(strv(&v["path"])?).is_absolute()
        || uint(&v["inode"])? == 0
        || uint(&v["device"])? == 0
        || uint(&v["size"])? == 0
        || uint(&v["owner_uid"])? != 0
        || uint(&v["owner_gid"])? != 0
        || uint(&v["mode"])? > 0o7777
        || uint(&v["mode"])? & 0o022 != 0
        || v["trusted_parent_chain"].as_bool() != Some(trusted)
    {
        return Err("unsupported retained file identity".into());
    }
    root(&v["blake3"])?;
    Ok(())
}
fn cg(v: &Value) -> Result<()> {
    fields(v, &["mount_id", "device", "inode"])?;
    for n in ["mount_id", "device", "inode"] {
        if uint(&v[n])? == 0 {
            return Err("empty cgroup identity".into());
        }
    }
    Ok(())
}
fn pair(v: &Value) -> Result<(u64, u64)> {
    let a = v
        .as_array()
        .filter(|v| v.len() == 2)
        .ok_or("namespace pair required")?;
    let p = (uint(&a[0])?, uint(&a[1])?);
    if p.0 == 0 || p.1 == 0 {
        return Err("empty namespace identity".into());
    }
    Ok(p)
}
fn process(v: &Value, is_vmm: bool) -> Result<()> {
    let names = if is_vmm {
        vec![
            "pid",
            "start_ticks",
            "pid_namespace_inode",
            "cgroup_namespace_inode",
            "boot_id",
            "cgroup",
            "birth_identity_root",
            "root",
        ]
    } else {
        vec![
            "pid",
            "start_ticks",
            "pid_namespace_inode",
            "cgroup_namespace_inode",
            "boot_id",
            "cgroup",
            "root",
        ]
    };
    fields(v, &names)?;
    cg(&v["cgroup"])?;
    let pid = u32v(&v["pid"])?;
    if pid == 0
        || uint(&v["start_ticks"])? == 0
        || uint(&v["pid_namespace_inode"])? == 0
        || uint(&v["cgroup_namespace_inode"])? == 0
        || !text(strv(&v["boot_id"])?)
    {
        return Err("invalid process incarnation".into());
    }
    let mut h = blake3::Hasher::new();
    h.update(if is_vmm {
        b"realm.vmm.pidfd.identity.v2\0"
    } else {
        b"realm.run-owned-process.identity.v1\0"
    });
    h.update(&pid.to_le_bytes());
    for n in [
        "start_ticks",
        "pid_namespace_inode",
        "cgroup_namespace_inode",
    ] {
        h.update(&uint(&v[n])?.to_le_bytes());
    }
    let boot = strv(&v["boot_id"])?;
    h.update(&(boot.len() as u64).to_le_bytes());
    h.update(boot.as_bytes());
    for n in ["mount_id", "device", "inode"] {
        h.update(&uint(&v["cgroup"][n])?.to_le_bytes());
    }
    if is_vmm {
        h.update(root(&v["birth_identity_root"])?.as_bytes());
    }
    if v["root"] != h.finalize().to_hex().as_str() {
        return Err("process identity root differs".into());
    }
    Ok(())
}
pub(super) fn kernel_root(v: &Value) -> Result<String> {
    fields(
        v,
        &[
            "cgroup",
            "vmm_identity",
            "terminal_epoch",
            "recovery_generation",
            "kill_requested_boottime_ns",
            "populated_zero_boottime_ns",
            "vmm_pidfd_exit_observed",
            "raw_evidence_root",
            "raw_cgroup_events",
            "raw_cgroup_procs",
            "raw_cgroup_threads",
            "pidfd_poll_revents",
        ],
    )?;
    cg(&v["cgroup"])?;
    process(&v["vmm_identity"], true)?;
    let p = &v["vmm_identity"];
    let mut h = blake3::Hasher::new();
    h.update(b"realm.cgroup.close.raw.v3\0");
    for n in ["mount_id", "device", "inode"] {
        h.update(&uint(&v["cgroup"][n])?.to_le_bytes());
    }
    h.update(&u32v(&p["pid"])?.to_le_bytes());
    for n in [
        "start_ticks",
        "pid_namespace_inode",
        "cgroup_namespace_inode",
    ] {
        h.update(&uint(&p[n])?.to_le_bytes());
    }
    for n in ["mount_id", "device", "inode"] {
        h.update(&uint(&p["cgroup"][n])?.to_le_bytes());
    }
    for n in ["boot_id", "birth_identity_root", "root"] {
        let s = strv(&p[n])?;
        h.update(&(s.len() as u64).to_le_bytes());
        h.update(s.as_bytes());
    }
    for n in [
        "terminal_epoch",
        "recovery_generation",
        "kill_requested_boottime_ns",
        "populated_zero_boottime_ns",
    ] {
        h.update(&uint(&v[n])?.to_le_bytes());
    }
    h.update(&[u8::from(
        v["vmm_pidfd_exit_observed"]
            .as_bool()
            .ok_or("pidfd observation required")?,
    )]);
    let revents = i16::try_from(
        v["pidfd_poll_revents"]
            .as_i64()
            .ok_or("poll flags required")?,
    )
    .map_err(|_| "poll flags overflow")?;
    h.update(&revents.to_le_bytes());
    for n in [
        "raw_cgroup_events",
        "raw_cgroup_procs",
        "raw_cgroup_threads",
    ] {
        let s = strv(&v[n])?;
        h.update(&(s.len() as u64).to_le_bytes());
        h.update(s.as_bytes());
    }
    Ok(h.finalize().to_hex().to_string())
}
fn validate_terminal(v: &Value, containment: &Value, fence: &Value) -> Result<()> {
    if kernel_root(v)? != root(&v["raw_evidence_root"])?
        || v["terminal_epoch"] != 1
        || v["recovery_generation"] != 0
        || v["vmm_pidfd_exit_observed"] != true
        || !strv(&v["raw_cgroup_procs"])?.trim().is_empty()
        || !strv(&v["raw_cgroup_threads"])?.trim().is_empty()
        || uint(&v["kill_requested_boottime_ns"])? == 0
        || uint(&v["populated_zero_boottime_ns"])? < uint(&v["kill_requested_boottime_ns"])?
    {
        return Err("terminal observation incomplete or inconsistent".into());
    }
    let revents = v["pidfd_poll_revents"]
        .as_i64()
        .ok_or("poll flags required")?;
    if revents & 1 == 0 || revents & (8 | 32) != 0 {
        return Err("pidfd terminal flags differ".into());
    }
    let mut events = BTreeMap::new();
    for line in strv(&v["raw_cgroup_events"])?.lines() {
        let x = line.split_whitespace().collect::<Vec<_>>();
        if x.len() != 2
            || events.insert(x[0], x[1]).is_some()
            || !matches!(x[0], "populated" | "frozen")
        {
            return Err("malformed terminal cgroup events".into());
        }
    }
    if events.get("populated") != Some(&"0") {
        return Err("terminal cgroup populated".into());
    }
    // The clone3 birth commitment is the original RunOwnedProcessIdentity
    // over these same incarnation fields, not an arbitrary well-formed hash.
    let mut birth = v["vmm_identity"].clone();
    let birth_root = birth["birth_identity_root"].clone();
    birth
        .as_object_mut()
        .ok_or("birth incarnation required")?
        .remove("birth_identity_root");
    birth["root"] = birth_root;
    process(&birth, false)?;
    let p = &v["vmm_identity"];
    if p["cgroup"] != v["cgroup"]
        || p["pid"] != fence["pid"]
        || p["start_ticks"] != fence["start_ticks"]
        || p["pid"] != containment["firecracker_pid"]
        || uint(&p["pid_namespace_inode"])? != pair(&containment["namespaces"]["pid"])?.1
        || v["cgroup"]["device"] != containment["cgroup"]["device"]
        || v["cgroup"]["inode"] != containment["cgroup"]["inode"]
    {
        return Err("terminal process/cgroup belongs to another launch".into());
    }
    Ok(())
}
fn origin(v: &Value, fence: &Value, containment: &Value) -> Result<()> {
    fields(v, &["root", "entries", "reachable_sockets", "phase"])?;
    fields(&v["root"], &["dev", "ino"])?;
    if v["reachable_sockets"] != serde_json::json!([])
        || v["phase"] != "native stage exec-stop before policy installation"
        || v["root"]["dev"] != containment["jail_root"]["device"]
        || v["root"]["ino"] != containment["jail_root"]["inode"]
    {
        return Err("jail origin differs".into());
    }
    let entries = v["entries"]
        .as_object()
        .filter(|v| v.len() <= 64)
        .ok_or("origin entries required")?;
    for required in [
        "firecracker",
        "realm-vmm",
        "kernel",
        "rootfs.ext4",
        "dev/kvm",
        "run",
    ] {
        if !entries.contains_key(required) {
            return Err("required jail origin absent".into());
        }
    }
    for (name, e) in entries {
        fields(e, &["dev", "ino", "mode", "uid", "gid", "rdev"])?;
        let mode = uint(&e["mode"])?;
        let allowed = match mode & 0o170000 {
            0o040000 => matches!(name.as_str(), "run" | "dev" | "dev/net"),
            0o100000 => matches!(
                name.as_str(),
                "firecracker" | "realm-vmm" | "kernel" | "rootfs.ext4" | "firecracker.pid"
            ),
            0o020000 => matches!(name.as_str(), "dev/kvm" | "dev/net/tun" | "dev/urandom"),
            _ => false,
        };
        if mode & 0o170000 == 0o020000 {
            let expected = match name.as_str() {
                "dev/kvm" => 2792,
                "dev/net/tun" => 2760,
                "dev/urandom" => 265,
                _ => 0,
            };
            if uint(&e["rdev"])? != expected {
                return Err("foreign jail device".into());
            }
        }
        uint(&e["uid"])?;
        uint(&e["gid"])?;
        if !allowed || uint(&e["dev"])? == 0 || uint(&e["ino"])? == 0 {
            return Err("unapproved jail object".into());
        }
    }
    for (name, id) in [
        ("firecracker", &fence["stage"]),
        ("realm-vmm", &fence["official"]),
    ] {
        if entries[name]["dev"] != id["device"] || entries[name]["ino"] != id["inode"] {
            return Err("jail executable alias differs".into());
        }
    }
    Ok(())
}
fn containment(v: &Value, fence: &Value) -> Result<()> {
    fields(
        v,
        &[
            "prestart_measurement_root",
            "jail_id",
            "jailer_pid",
            "jailer_process",
            "jailer_exit_code",
            "vmm_exit_status",
            "firecracker_pid",
            "firecracker_pid_namespace",
            "input_binding_root",
            "materialized_resources",
            "jailer",
            "uid",
            "gid",
            "user_name",
            "group_name",
            "jail_root",
            "cgroup",
            "cgroup_parent",
            "namespaces",
            "seccomp",
        ],
    )?;
    for n in ["prestart_measurement_root", "input_binding_root"] {
        root(&v[n])?;
    }
    file(&v["jailer"])?;
    if v["jailer_exit_code"] != 0
        || v["vmm_exit_status"] != 0
        || v["uid"].as_u64() == Some(0)
        || v["gid"].as_u64() == Some(0)
        || v["firecracker_pid_namespace"] != 1
        || !text(strv(&v["jail_id"])?)
        || v["user_name"] != "realm-fc"
        || v["group_name"] != "realm-fc"
    {
        return Err("unclean or unsupported containment".into());
    }
    let jp = &v["jailer_process"];
    fields(
        jp,
        &[
            "pid",
            "boot_id",
            "start_time_ticks",
            "owner_uid",
            "owner_gid",
            "executable",
        ],
    )?;
    let executable = &jp["executable"];
    if executable != &v["jailer"] {
        // Live VmmIncarnation captures the kernel proc-exe object. Its proc
        // parent flag is false; trust comes from joining the protected named
        // jailer over every retained resource identity field, not its pathname.
        file_shape(executable, false)?;
        if executable["path"] != format!("/proc/{}/exe", u32v(&jp["pid"])?)
            || [
                "blake3",
                "device",
                "inode",
                "size",
                "owner_uid",
                "owner_gid",
                "mode",
            ]
            .iter()
            .any(|n| executable[*n] != v["jailer"][*n])
        {
            return Err("live jailer executable differs from protected object".into());
        }
    } else {
        file(executable)?;
    }
    if u32v(&jp["pid"])? == 0
        || jp["pid"] != v["jailer_pid"]
        || uint(&jp["start_time_ticks"])? == 0
        || !text(strv(&jp["boot_id"])?)
        || jp["owner_uid"] != 0
        || jp["owner_gid"] != 0
    {
        return Err("foreign jailer incarnation".into());
    }
    fields(
        &v["jail_root"],
        &["device", "inode", "owner", "group", "mode"],
    )?;
    fields(
        &v["cgroup"],
        &[
            "path",
            "device",
            "inode",
            "memory_max_bytes",
            "pids_max",
            "cpu_max",
        ],
    )?;
    fields(
        &v["cgroup_parent"],
        &[
            "path",
            "device",
            "inode",
            "owner",
            "group",
            "mode",
            "subtree_control",
        ],
    )?;
    if v["jail_root"]["owner"] != 0
        || v["jail_root"]["group"] != 0
        || v["jail_root"]["mode"] != 0o755
        || uint(&v["jail_root"]["device"])? == 0
        || uint(&v["jail_root"]["inode"])? == 0
        || v["cgroup_parent"]["owner"] != 0
        || uint(&v["cgroup_parent"]["mode"])? & 0o022 != 0
    {
        return Err("unprotected jail/cgroup parent".into());
    }
    let controllers = v["cgroup_parent"]["subtree_control"]
        .as_array()
        .ok_or("cgroup controllers missing")?;
    if !["cpu", "memory", "pids"]
        .iter()
        .all(|n| controllers.iter().any(|v| v == n))
    {
        return Err("cgroup controllers incomplete".into());
    }
    fields(&v["namespaces"], &["mount", "pid", "network"])?;
    for n in ["mount", "pid", "network"] {
        pair(&v["namespaces"][n])?;
    }
    if v["namespaces"]["network"] != fence["net_namespace"] {
        return Err("network namespace differs".into());
    }
    if uint(&v["cgroup"]["memory_max_bytes"])? == 0
        || uint(&v["cgroup"]["pids_max"])? == 0
        || v["cgroup"]["cpu_max"] != "100000 100000"
    {
        return Err("unbounded cgroup configuration".into());
    }
    fields(
        &v["seccomp"],
        &["mode", "filter_count", "release_binary_sha256"],
    )?;
    if v["seccomp"]["mode"] != 2 || uint(&v["seccomp"]["filter_count"])? == 0 {
        return Err("seccomp missing".into());
    }
    root(&v["seccomp"]["release_binary_sha256"])?;
    let material = v["materialized_resources"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 32)
        .ok_or("materialized resource inventory missing")?;
    for f in material {
        file(f)?;
    }
    Ok(())
}
pub(super) fn validate(v: &Value, scope: &CodingExecutionScope) -> Result<()> {
    fields(
        v,
        &[
            "domain",
            "authority",
            "qualification",
            "measurement",
            "scope",
            "frontier",
            "barrier",
            "capture_root",
            "resources_root",
            "fence",
            "controller",
            "referee_root",
            "referee_identity_record",
            "containment",
            "host",
            "resources_raw_json",
            "terminal",
            "trust_basis",
            "profile_source_blake3",
            "controller_policy_blake3",
        ],
    )?;
    if serde_json::to_vec(v).map_err(|e| e.to_string())?.len() > 512 * 1024
        || v["domain"] != "realm.native-coding-provenance/v2"
        || v["authority"] != "NONE"
        || v["qualification"] != "NOT_REGISTERED"
        || v["scope"] != serde_json::to_value(scope).map_err(|e| e.to_string())?
        || v["profile_source_blake3"] != profile_source_root()
    {
        return Err("observation domain/scope/profile differs".into());
    }
    for n in [
        "measurement",
        "frontier",
        "barrier",
        "capture_root",
        "resources_root",
        "referee_root",
        "controller_policy_blake3",
    ] {
        root(&v[n])?;
    }
    file(&v["controller"])?;
    let fence = &v["fence"];
    fields(
        fence,
        &[
            "policy",
            "prelaunch_profile_blake3",
            "origin",
            "original_exec_journal",
            "pid",
            "start_ticks",
            "stage",
            "official",
            "net_namespace",
            "ipc_namespace",
            "qualification",
            "policy_basis",
        ],
    )?;
    if fence["policy"] != "realm.coding-fence/v1"
        || fence["prelaunch_profile_blake3"]
            != blake3::hash(crate::coding_submission::NATIVE_EXECUTION_PROFILE.as_bytes())
                .to_hex()
                .as_str()
    {
        return Err("unsupported fence profile".into());
    }
    for n in ["stage", "official", "original_exec_journal"] {
        file(&fence[n])?;
    }
    pair(&fence["net_namespace"])?;
    pair(&fence["ipc_namespace"])?;
    containment(&v["containment"], fence)?;
    origin(&fence["origin"], fence, &v["containment"])?;
    validate_terminal(&v["terminal"], &v["containment"], fence)?;
    if v["containment"]["jailer_process"]["boot_id"] != v["terminal"]["vmm_identity"]["boot_id"] {
        return Err("jailer incarnation belongs to another host boot".into());
    }
    fields(
        &v["host"],
        &[
            "sysname",
            "release",
            "version",
            "machine",
            "landlock_abi",
            "basis",
        ],
    )?;
    let r = &v["referee_identity_record"];
    let mut referee_fields = vec![
        "domain",
        "prelaunch_scope",
        "binding",
        "packet",
        "native_custody",
        "broker_completion",
        "measurement",
        "barrier",
        "process",
        "python",
        "bwrap",
        "sources",
        "request_blake3",
        "subject_packet_blake3",
        "seed",
        "result_blake3",
    ];
    let refused =
        scope.native_subtask.is_some() && r["domain"] == "realm.owned-coding-task-refusal/v1";
    if refused {
        referee_fields.push("child_exit_code");
        if r["child_exit_code"] != 2 {
            return Err("refusal child exit differs".into());
        }
    }
    fields(r, &referee_fields)?;
    if !refused
        && r["domain"]
            != if scope
                .native_subtask
                .as_ref()
                .is_some_and(|s| s.role == crate::native_workflow::NativeTaskRole::Api)
            {
                "realm.owned-native-api-check/v1"
            } else {
                "realm.owned-coding-task-check/v2"
            }
        || r["prelaunch_scope"] != v["scope"]
        || r["binding"] != serde_json::to_value(&scope.submission).map_err(|e| e.to_string())?
        || r["measurement"] != v["measurement"]
        || r["barrier"] != v["barrier"]
        || r["packet"] != r["subject_packet_blake3"]
        || hash(r)? != v["referee_root"]
    {
        return Err("foreign referee observation".into());
    }
    for n in [
        "packet",
        "native_custody",
        "broker_completion",
        "request_blake3",
        "result_blake3",
    ] {
        root(&r[n])?;
    }
    if strv(&r["seed"])?.parse::<u64>().is_err() {
        return Err("unsupported referee seed".into());
    }
    process(&r["process"], false)?;
    file(&r["python"])?;
    file(&r["bwrap"])?;
    if r["process"]["cgroup"] != v["terminal"]["cgroup"]
        || r["process"]["boot_id"] != v["terminal"]["vmm_identity"]["boot_id"]
        || r["process"]["pid"] == fence["pid"]
    {
        return Err("referee belongs to another cgroup/process".into());
    }
    for item in r["sources"]
        .as_array()
        .filter(|x| x.len() == crate::coding_referee::COMPILED_SOURCES.len())
        .ok_or("source inventory missing")?
    {
        let row = item
            .as_array()
            .filter(|x| x.len() == 2)
            .ok_or("source row differs")?;
        file(&row[1])?;
    }
    let raw = strv(&v["resources_raw_json"])?;
    if blake3::hash(raw.as_bytes()).to_hex().as_str() != v["resources_root"] {
        return Err("resource root differs".into());
    }
    let res = crate::strict_json::parse(raw.as_bytes()).map_err(|_| "resource JSON malformed")?;
    let a = res
        .as_array()
        .filter(|a| a.len() == 5 && a[0] == "realm.actual-vmm-resources/v1")
        .ok_or("resource schema differs")?;
    if a[1] != v["containment"]["prestart_measurement_root"] {
        return Err("resources bind another preparation".into());
    }
    file(&a[2])?;
    file(&a[3])?;
    let material = v["containment"]["materialized_resources"]
        .as_array()
        .ok_or("materialized inventory missing")?;
    for (name, id) in [("kernel", &a[2]), ("rootfs.ext4", &a[3])] {
        if !material.contains(id)
            || v["fence"]["origin"]["entries"][name]["dev"] != id["device"]
            || v["fence"]["origin"]["entries"][name]["ino"] != id["inode"]
        {
            return Err("materialized resource belongs to another jail".into());
        }
    }
    let snapshots = a[4]
        .as_array()
        .filter(|x| x.len() == 3)
        .ok_or("resource phase missing")?;
    for (phase, s) in snapshots.iter().enumerate() {
        fields(s, &["pid", "start_ticks", "descriptors", "maps"])?;
        if s["pid"] != fence["pid"] || s["start_ticks"] != fence["start_ticks"] {
            return Err("cross-run resource census".into());
        }
        let rows = s["descriptors"]
            .as_array()
            .filter(|x| !x.is_empty() && x.len() <= 256)
            .ok_or("descriptor census incomplete")?;
        let mut fds = BTreeSet::new();
        let mut immutable = BTreeSet::new();
        for d in rows {
            fields(d, &["fd", "device", "inode", "mode", "flags", "target"])?;
            let fd = uint(&d["fd"])?;
            if !fds.insert(fd) {
                return Err("duplicate descriptor".into());
            }
            let mode = uint(&d["mode"])?;
            let flags = d["flags"]
                .as_i64()
                .filter(|v| *v >= 0)
                .ok_or("descriptor flags missing")?;
            let target = strv(&d["target"])?;
            match mode & 0o170000 {
                0o100000 if fd == 1 || fd == 2 => {
                    if flags & 3 == 0 {
                        return Err("log descriptor not writable".into());
                    }
                }
                0o100000 => {
                    let approved = [&a[2], &a[3]]
                        .into_iter()
                        .find(|p| p["device"] == d["device"] && p["inode"] == d["inode"])
                        .ok_or("forbidden file descriptor")?;
                    if flags & 3 != 0 {
                        return Err("writable resource alias".into());
                    }
                    immutable.insert(approved["blake3"].as_str().ok_or("file root missing")?);
                }
                0o140000 => {
                    if !target.starts_with("socket:[") {
                        return Err("socket descriptor shape differs".into());
                    }
                }
                0o020000 => {
                    if !(fd == 0 && target == "/dev/null" || fd != 0 && target == "/dev/kvm") {
                        return Err("forbidden device descriptor".into());
                    }
                }
                _ => {
                    if !matches!(
                        target,
                        "anon_inode:[eventfd]"
                            | "anon_inode:[eventpoll]"
                            | "anon_inode:[timerfd]"
                            | "anon_inode:kvm-vm"
                            | "anon_inode:kvm-vcpu"
                            | "anon_inode:[kvm-vm]"
                            | "anon_inode:[kvm-vcpu]"
                    ) {
                        return Err("unknown descriptor channel".into());
                    }
                }
            }
        }
        if phase == 0
            && (!immutable.contains(a[2]["blake3"].as_str().unwrap())
                || !immutable.contains(a[3]["blake3"].as_str().unwrap()))
        {
            return Err("prestart immutable resources absent".into());
        }
        let maps = strv(&s["maps"])?;
        if maps.is_empty() || !maps.ends_with('\n') {
            return Err("map census incomplete".into());
        }
        for line in maps.lines() {
            let x = line.split_whitespace().collect::<Vec<_>>();
            if x.len() < 5 || x[1].len() != 4 {
                return Err("map census malformed".into());
            }
            if x[1].as_bytes()[1] == b'w' && x[1].as_bytes()[3] == b's' && x[4] != "0" {
                let inode = x[4].parse::<u64>().map_err(|_| "map inode malformed")?;
                if !rows.iter().any(|d| {
                    d["inode"].as_u64() == Some(inode)
                        && matches!(
                            d["target"].as_str(),
                            Some("anon_inode:kvm-vcpu" | "anon_inode:[kvm-vcpu]")
                        )
                }) {
                    return Err("forbidden shared writable mapping".into());
                }
            }
        }
    }
    Ok(())
}
