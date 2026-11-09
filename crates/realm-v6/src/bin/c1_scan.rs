//! Offline C1 filesystem scanner. The VMM must already be retired.

use realm_v6::c1::scan_ext4_image;
use std::{env, process};

fn main() {
    let Some(image) = env::args_os().nth(1) else {
        eprintln!("usage: c1_scan FINALIZED_EXT4_IMAGE");
        process::exit(64);
    };
    match scan_ext4_image(image.as_ref()) {
        Ok(world) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&world).expect("world is serializable")
            );
        }
        Err(error) => {
            eprintln!("C1 offline scan refused: {error}");
            process::exit(2);
        }
    }
}
