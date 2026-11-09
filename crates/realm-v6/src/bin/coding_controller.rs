//! Pipe-only proposal relay and adversarial syscall probe. No issuer capability.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    if let Err(e) = realm_v6::controller_relay::run() {
        eprintln!("REFUSE: {e}");
        std::process::exit(2);
    }
}
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn main() {
    eprintln!("REFUSE: pipe-only controller requires Linux x86_64 or aarch64");
    std::process::exit(2);
}
