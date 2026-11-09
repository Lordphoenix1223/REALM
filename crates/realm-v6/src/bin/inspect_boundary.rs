#[cfg(target_os = "linux")]
fn main() {
    use realm_v6::linux_boundary::inspect_boundary;
    use std::path::Path;

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: inspect_boundary RECEIPT FROZEN_ROOT VM_CGROUP");
        std::process::exit(2);
    }
    let receipt = std::fs::read(&args[1]).unwrap_or_default();
    let report = inspect_boundary(&receipt, Path::new(&args[2]), Path::new(&args[3]));
    println!(
        "{}",
        serde_json::to_string(&report).expect("report serialization")
    );
    std::process::exit(2);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("inspect_boundary requires Linux");
    std::process::exit(2);
}
