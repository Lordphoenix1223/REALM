# Contribute to REALM

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

Start from current public `main` in a dedicated public clone. Use a `codex/` or
other descriptive topic branch, run the checks below and open a focused PR.
Never push private research history or cherry-pick an unaudited private commit.
See [the maintainer guide](docs/MAINTAINERS.md) for explicit file promotion.

```sh
python3 tools/check_release.py
REALM_CHECKER="$PWD/target/debug/realm-artifact" python3 -B tools/test_launcher.py
```

If your approved change intentionally changes distributed files, refresh the
manifest with `python3 tools/check_release.py --refresh` and review that diff.
A manifest records bytes; it is not a rights or security approval. No CLA is
currently required. Submit only material you have authority to contribute, and
identify third-party sources, licenses and AI assistance where applicable.
