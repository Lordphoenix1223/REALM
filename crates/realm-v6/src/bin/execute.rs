use realm_v6::execute::{ExecuteRequest, execute};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let separator = args.iter().position(|arg| arg == "--");
    let Some(separator) = separator else {
        eprintln!(
            "usage: execute --root ROOT --run-id ID [--timeout-ms N] \
             [--rootfs ROOTFS --workspace-device DEVICE --guest-supervisor SUPERVISOR \
              --firecracker BIN --kernel KERNEL --state-dir DIR] \
             -- COMMAND [ARGS...]"
        );
        std::process::exit(2);
    };
    let mut root = None;
    let mut run_id = None;
    let mut timeout_ms = 30_000;
    let mut rootfs = None;
    let mut workspace_device = None;
    let mut guest_supervisor = None;
    let mut firecracker = None;
    let mut kernel = None;
    let mut state_dir = None;
    let mut index = 1;
    while index < separator {
        match args[index].as_str() {
            "--root" => {
                index += 1;
                root = args.get(index).map(PathBuf::from);
            }
            "--run-id" => {
                index += 1;
                run_id = args.get(index).cloned();
            }
            "--timeout-ms" => {
                index += 1;
                timeout_ms = args
                    .get(index)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
            }
            "--rootfs" => {
                index += 1;
                rootfs = args.get(index).map(PathBuf::from);
            }
            "--workspace-device" => {
                index += 1;
                workspace_device = args.get(index).map(PathBuf::from);
            }
            "--guest-supervisor" => {
                index += 1;
                guest_supervisor = args.get(index).map(PathBuf::from);
            }
            "--firecracker" => {
                index += 1;
                firecracker = args.get(index).map(PathBuf::from);
            }
            "--kernel" => {
                index += 1;
                kernel = args.get(index).map(PathBuf::from);
            }
            "--state-dir" => {
                index += 1;
                state_dir = args.get(index).map(PathBuf::from);
            }
            value => {
                eprintln!("unknown option: {value}");
                std::process::exit(2);
            }
        }
        index += 1;
    }
    let Some(root) = root else {
        eprintln!("--root is required");
        std::process::exit(2);
    };
    let Some(run_id) = run_id else {
        eprintln!("--run-id is required");
        std::process::exit(2);
    };
    let request = ExecuteRequest {
        run_id,
        root,
        command: args[separator + 1..].to_vec(),
        timeout_ms,
        allowed_effects: vec!["filesystem".into()],
        allowed_paths: vec!["target.txt".into()],
        rootfs,
        workspace_device,
        guest_supervisor,
        firecracker,
        kernel,
        state_dir,
    };
    match execute(&request) {
        Ok(result) => {
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        }
        Err(error) => {
            eprintln!("execution request refused: {error}");
            std::process::exit(2);
        }
    }
}
