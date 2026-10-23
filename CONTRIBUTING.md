# Contribute to the artifact toolkit

Install Rust/Cargo 1.97.1, a C compiler and Python 3.10+. Then:

```sh
./realm demo
cargo test --locked -p realm-artifact --lib --bin realm-artifact --test toolkit_cli
cargo clippy --locked -p realm-artifact --lib --bin realm-artifact --test toolkit_cli -- -D warnings
REALM_CHECKER="$PWD/target/debug/realm-artifact" python3 -B -m unittest discover -s tools -p test_proof_viewer.py -v
```

Start at `crates/realm-artifact/src/inspection.rs` (report adapter), `observations.rs`
(non-authoritative import), `tools/proof_viewer.py` (loopback presentation),
`viewer/` (vanilla HTML/CSS/JS) and `benchmarks/` (finite experiments).
The existing library is the verifier; do not add a parallel browser verifier.

Useful bounded contributions: add a binding substitution case with an explicit
expected result; independently rerun the benchmark; improve keyboard/screen-reader
accessibility; investigate a supported-platform reader issue. Keep unknowns
visible. VALID means content checks only; an authorization request stays incomplete.

A focused PR should state the user-visible trigger, before/after behavior, tested
commands, source/environment, negatives and remaining limits. Preserve failed
experiments. Do not alter native execution authority or make an unimplemented
trust boundary appear to pass. New dependencies and redistribution need review.
