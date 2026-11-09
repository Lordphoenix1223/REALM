use realm_v6::{Admission, Refusal, admit};
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let decision = if args.len() != 3 {
        Admission::Refuse(Refusal::Malformed)
    } else {
        match std::fs::read(&args[1]) {
            Ok(bytes) => admit(&bytes, Path::new(&args[2])),
            Err(_) => Admission::Refuse(Refusal::Malformed),
        }
    };
    println!(
        "{}",
        serde_json::to_string(&decision).expect("static admission serialization")
    );
    if matches!(decision, Admission::Refuse(_)) {
        std::process::exit(2);
    }
}
