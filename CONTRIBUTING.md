# Contribute to REALM

Working on prose or the static walkthrough? You can start without Rust:
serve the repository with `python3 -m http.server 8873 --bind 127.0.0.1` and open
`http://127.0.0.1:8873/site/`. Keep prepared results labeled as replay. See
[walkthrough reproduction and checks](docs/DEPLOY_WALKTHROUGH.md). Changing the
recorded evidence requires native parity validation.

## Fork → test → PR

Fork the public repository on GitHub, clone **your fork**, and create a topic
branch from its up-to-date main. Reopen in a devcontainer/Codespaces to use the
pinned Rust/Python/C environment, or keep Python 3.10+, Rust/Cargo 1.97.1,
Clippy, a C compiler and libclang installed locally. No private access is needed.
The container uses 2 build jobs and no automatic Cargo build; no VM, Node,
Docker-in-Docker, database service or model key is needed. Choose Codespaces
only within your own approved quota; no Codespace is created by these files.

```sh
python3 tools/dev.py fast       # Python only; native checks explicitly NOT_RUN
python3 tools/dev.py test       # Rust/CLI and real Python contract/viewer checks
./realm example                # actual paired-history experiment
# For verifier, import, integration, fixture or workflow changes:
python3 tools/dev.py sensitive --output realm-validation
```

Use `CARGO_TARGET_DIR` to reuse an existing **public** build cache; do not create
separate targets for each tiny change. Sensitive checks retain the existing real
counterexample and finite benchmark outputs in a fresh directory and fail on
unexpected outcomes. Passing them does not qualify execution authority.

Refresh the manifest after intentional edits, rerun the appropriate lane, push
only your topic branch and open a PR to `Lordphoenix1223/REALM:main`. Include the
commands, source commit/platform, results, remaining limits and any NOT_RUN checks.
The fast workflow runs for small PRs; native regression runs for sensitive paths.
Fork code runs on GitHub-hosted runners with a read-only token, no stored checkout
credential or supplied secrets; never use `pull_request_target` for running it.
First-time forks may await maintainer approval. A zero-step billing/admission
failure is **NOT_RUN**, distinct from a test failure; do not increase spending to
make a check green. Maintainers must inspect Actions changes before approval.

Reviewer guidance: the current maintainer is @Lordphoenix1223; request additional
independent review for verifier/trust-boundary changes when available. No second
reviewer, CODEOWNER requirement or external qualification is invented here.

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
