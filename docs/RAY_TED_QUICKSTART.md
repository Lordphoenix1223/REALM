# Ray and Ted: current REALM developer base

Use the public `codex/v7-preview` branch. Record `git rev-parse HEAD` in adapter
results; `SOURCE_MANIFEST.json` pins the exact canonical source commit and each
shared file. No private checkout, private account, VM image or research evidence
directory is needed for these commands.

Requirements: Python 3.10+, Rust/Cargo 1.97.1, a C compiler, and libclang. On Linux,
the optional native fence requires static libc support; its absence refuses native
launch while ordinary toolkit use remains available. No package is installed by
the commands below. Cargo downloads locked public dependencies if not cached.

```sh
git clone --branch codex/v7-preview https://github.com/Lordphoenix1223/REALM.git
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
