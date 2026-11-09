# Ray and Ted: current REALM developer base

Use the public `main` branch. Record `git rev-parse HEAD` in adapter
results; `SOURCE_MANIFEST.json` pins the exact canonical source commit and each
shared file. No private checkout, private account, VM image or research evidence
directory is needed for these commands.

Requirements: Python 3.10+, Rust/Cargo 1.97.1, a C compiler, and libclang. On Linux,
the optional native fence requires static libc support; its absence refuses native
launch while ordinary toolkit use remains available. No package is installed by
the commands below. Cargo downloads locked public dependencies if not cached.

```sh
git clone --branch main https://github.com/Lordphoenix1223/REALM.git
cd REALM
git rev-parse HEAD
python3 -B scripts/check_source_manifest.py
cargo build --locked -p realm-artifact -p realm-cli
./realm demo --output /tmp/realm-v7-first-demo
./realm inspect /tmp/realm-v7-first-demo/valid.realm --json
./realm verify /tmp/realm-v7-first-demo/valid.realm --json
```

Use a new output directory each time. For a captured task and actual `.realm`
generation on supported macOS Seatbelt:

```sh
./realm coding-demo --output /tmp/realm-v7-first-coding --disposable-replay
```

This executes saved tool proposals and optionally replays into a disposable
directory. It does not call a model or qualify native execution. The existing
two-history example is `./realm example --output /tmp/realm-v7-first-counterexample`.

Run the portable verification and interface controls:

```sh
python3 -B tools/dev.py test
python3 -B tools/dev.py v7
REALM_CHECKER="$PWD/target/debug/realm-artifact" python3 -B -m unittest discover -s integrations/python/tests -v
PYTHONPATH=scripts/v7 REALM_BINARY="$PWD/target/debug/realm" python3 -B -m unittest scripts/v7/test_native_input_contract.py scripts/v7/test_native_publication_entrypoint.py -v
```

The contributor test lane explicitly reports four root-only Linux device/ownership
fixtures as NOT_RUN for a non-root user; it never grants their capabilities.
Direct `cargo test --locked --workspace` runs them and therefore needs those
component-test prerequisites on Linux. Ordered-application tests require an
ext-family, tmpfs, XFS or Btrfs temporary filesystem on Linux. Overlay/network
filesystems correctly refuse; use an existing supported temporary filesystem
instead of changing the runtime allowlist. macOS uses its supported local path.

Python integrations use `PYTHONPATH=integrations/python` and import `Checker`
from `realm_client`, or `Checker`, `Session`, `SessionRequest`, and `host_support`
from `realm_v7`. The authoritative implementation is Rust. Session examples and
protocol tests are in `scripts/v7/test_vm_session.py`; production setup is not a
contributor quick-start step. The full CLI exposes existing `task`, `transfer`
and development commands; use `target/debug/realm` to print its usage.

Build adapters and notebooks against these interfaces in your assigned projects.
Do not change qualification checks, custody ownership, receipt schemas, installed
profile/trust requirements, refusal behavior or effect restrictions to make an
adapter pass. Report the exact refusal and environment instead. Keep lifecycle
handles in the trusted controller and expose only Session.execute to the agent.

All preview execution results remain subject to the [V7 limitations](V7_PREVIEW.md).


## Ownership and contributions

Ray: keep the agent skill, Jupyter notebooks and Fornax integration in your
adapter project, importing the public `realm_v7` and `realm_client` interfaces.
Reusable, reviewed adapter examples can be proposed under
`integrations/python/adapters/fornax/` in public REALM; that directory is a
proposed contribution location, not an already implemented adapter.

Ted: keep EvalLab, external evaluation orchestration and raw failure datasets in
your evaluation project. Propose portable, licensed synthetic regression cases
under `benchmarks/external/` through a public PR. Record the REALM commit, command,
environment, refusals and failed runs; an intact artifact alone proves neither
observation coverage nor authorization. Do not upload private run archives.

Create a `codex/` or personal topic branch from public `main`, run the relevant
checks and open a PR targeting `main`. You need no private repository access.
For shared core edits, the maintainer reviews and integrates compatible changes
privately, then updates the approved source manifest in the same public PR or a
follow-up before merge. A manifest refusal is a review gate, not permission to
refresh hashes yourself. Adapter tests can be run directly while that review is
pending. Do not alter native custody, runtime admission, receipt/contract schemas,
receiver acceptance, qualification gates or effect restrictions in adapter work.

`codex/v7-preview` is a retained historical release snapshot. Use an exact commit
from the maintainer's handoff for reproducibility; `main` is the development base.
V7 remains EXPERIMENTAL: production native qualification NOT_RUN, authority NONE.
