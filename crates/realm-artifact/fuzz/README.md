# Optional parser fuzz targets

These five targets call the existing Rust artifact parser, packer, lifecycle and
shape checks. They issue no authority and do not launch a guest or apply effects.
The standalone dependency graph is pinned by this directory's Cargo.lock.

Compile-check the targets with the supported stable toolchain:

```sh
cargo check --locked --manifest-path crates/realm-artifact/fuzz/Cargo.toml --bins
```

A fuzz campaign additionally needs cargo-fuzz and its compatible toolchain; it
is optional and is not installed or executed automatically. From this directory,
an operator with that toolchain can select `cargo fuzz run parse` or another
named target. Start from reviewed synthetic public artifact samples only.
Private research archives, runtime receipts, VM images and provider evidence are
not a public corpus. Target compilation and finite refusal tests are not evidence
of fuzz coverage, complete execution observation or native qualification.
