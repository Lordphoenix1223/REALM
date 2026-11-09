use std::{env, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=native/coding_fence.c");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("coding-fence");
    if env::var("HOST").unwrap() != env::var("TARGET").unwrap() {
        std::fs::write(output, []).unwrap();
        println!(
            "cargo:warning=coding fence unavailable in cross build; CodingTools launch will REFUSE; existing V6 builds remain supported"
        );
        return;
    }
    let status = Command::new("cc")
        .args([
            "-static",
            "-std=gnu11",
            "-O2",
            "-fno-ident",
            "-fstack-protector-strong",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wl,--build-id=none",
            "native/coding_fence.c",
            "-o",
        ])
        .arg(&output)
        .status();
    if !status.is_ok_and(|status| status.success()) {
        // Static libc/compiler availability is a CodingTools prerequisite,
        // not a new requirement for existing V6-only consumers. No failed or
        // partial output can become an executable fence.
        std::fs::write(output, []).unwrap();
        println!(
            "cargo:warning=static coding-fence compiler/link failed; CodingTools launch will REFUSE; existing V6 builds remain supported"
        );
    }
}
