use realm_v6::filesystem_world::{delta, scan_directory};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Serialize)]
struct Output {
    world: realm_v6::filesystem_world::FilesystemWorld,
    delta_from: Option<realm_v6::filesystem_world::FilesystemWorld>,
    delta: Option<Vec<realm_v6::filesystem_world::FilesystemChange>>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if !(args.len() == 2 || args.len() == 3) {
        eprintln!("usage: scan_world ROOT [START_ROOT]");
        std::process::exit(2);
    }
    let world = match scan_directory(&PathBuf::from(&args[1])) {
        Ok(world) => world,
        Err(_) => {
            eprintln!("filesystem scan refused");
            std::process::exit(1);
        }
    };
    let (delta_from, changes) = if args.len() == 3 {
        let before = match scan_directory(&PathBuf::from(&args[2])) {
            Ok(world) => world,
            Err(_) => {
                eprintln!("starting filesystem scan refused");
                std::process::exit(1);
            }
        };
        (Some(before.clone()), Some(delta(&before, &world)))
    } else {
        (None, None)
    };
    println!(
        "{}",
        serde_json::to_string(&Output {
            world,
            delta_from,
            delta: changes,
        })
        .expect("filesystem world is serializable")
    );
}
