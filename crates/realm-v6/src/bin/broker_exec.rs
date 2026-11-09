#[cfg(target_os = "linux")]
use realm_v6::{broker_exec::BrokerExecRequest, broker_rpc::BrokerRpc};
#[cfg(target_os = "linux")]
use std::io::Read;
use std::process;

fn main() {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("BrokerRpc contained execution requires Linux/KVM");
        process::exit(69);
    }

    #[cfg(target_os = "linux")]
    {
        let mut input = Vec::new();
        if std::io::stdin()
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut input)
            .is_err()
            || input.is_empty()
            || input.len() > 2 * 1024 * 1024
        {
            eprintln!("BrokerRpc request input is missing or too large");
            process::exit(64);
        }
        let args = std::env::args().collect::<Vec<_>>();
        if args
            .get(1)
            .is_some_and(|arg| arg == "--runtime-effect-worker")
            && args.len() == 3
        {
            if let Err(e) =
                realm_v6::runtime_effects::run_effect_worker(std::path::Path::new(&args[2]), &input)
            {
                eprintln!("{e}");
            }
            process::exit(87);
        }
        let request: BrokerExecRequest = match serde_json::from_slice(&input) {
            Ok(request) => request,
            Err(_) => {
                eprintln!("BrokerRpc ExecTask request is malformed");
                process::exit(64);
            }
        };
        match BrokerRpc::execute_task(request) {
            Ok(result) => println!(
                "{}",
                serde_json::to_string(&result).expect("result serializes")
            ),
            Err(error) => {
                eprintln!("BrokerRpc ExecTask refused: {error}");
                process::exit(2);
            }
        }
    }
}
