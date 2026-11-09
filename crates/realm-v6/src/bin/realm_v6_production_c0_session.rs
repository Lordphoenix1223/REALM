//! Non-authorizing C0 session entry point for the canonical contained executor.
#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use realm_v6::execute::{C1BackendInputPaths, ExecuteRequest, execute_rootfs_brokered};
    use std::{fs, path::Path};
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 5 {
        return Err(
            "usage: realm_v6_production_c0_session REQUEST.json BACKEND.json CUSTODIAN UID GID"
                .into(),
        );
    }
    let request: ExecuteRequest = serde_json::from_slice(&fs::read(&args[0])?)?;
    let backend: C1BackendInputPaths = serde_json::from_slice(&fs::read(&args[1])?)?;
    let outcome = execute_rootfs_brokered(
        &request,
        &backend,
        Path::new(&args[2]),
        args[3].parse()?,
        args[4].parse()?,
    )?;
    let capability = outcome
        .publication_capability
        .ok_or("contained execution did not yield a checked capability")?;
    let report = serde_json::json!({
        "status": "CLOSED_NON_AUTHORIZING_PRODUCTION_SESSION",
        "authority": false,
        "result": capability.result(),
        "checked_evidence": capability.checked_c1_evidence(),
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    // Deliberately consume and discard the capability. Reports cannot publish.
    drop(capability);
    Ok(())
}
fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = run() {
        eprintln!("PRODUCTION_C0_REFUSE: {error}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("production-contained C0 requires Linux x86_64, cgroup v2, and /dev/kvm");
        std::process::exit(2);
    }
}
