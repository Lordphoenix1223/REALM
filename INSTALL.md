# Install and evaluate

Just exploring? [Open the browser walkthrough](https://lordphoenix1223.github.io/REALM/)
without installing anything. It replays real prepared results; use the local
checker below to verify your own files.

## Prerequisites and platforms

| Workflow | Requirements and current validation |
| --- | --- |
| Artifact checker, counterexample and Proof Viewer | Python 3.10+, Rust/Cargo 1.97.1, C compiler, libclang. macOS ARM64 and Linux x86_64 source builds and checker regressions tested (Ubuntu 24.04 CI). |
| Captured coding demo | A clean Git checkout plus the above. macOS ARM64: `/usr/bin/sandbox-exec`, full demo tested. Linux x86_64: `/usr` Python, bubblewrap and permitted unprivileged namespaces; full demo NOT_RUN for this candidate. |
| Other environments | Native Windows is unsupported; WSL and other coding-demo platforms are untested. No privileged fallback. |

On macOS, use the Command Line Tools C compiler and a discoverable libclang.
Homebrew `llvm` supplies libclang if it is missing. On Debian/Ubuntu, the build
packages are `build-essential`, `pkg-config` and `libclang-dev`; the optional
coding sandbox also needs `bubblewrap`. Install missing prerequisites through
your normal administrator workflow; never run the coding task as root.
[Upstream libclang setup](https://rust-lang.github.io/rust-bindgen/requirements.html).
If bindgen cannot find it, set `LIBCLANG_PATH` to your LLVM installation's `lib`
directory. No system packages or toolchains are installed by the launcher.

Rustup users can select the reference compiler with
`rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt` and
`rustup override set 1.97.1`. Other Rust installations work when they provide
that compiler and Cargo. Clippy and rustfmt are needed for contributor checks, not normal use.

## Reference path: locked source build

Use Python 3.10+, Rust/Cargo 1.97.1, a C compiler and libclang on macOS or Linux. Extract
the source archive, enter the directory, then:

```sh
./realm --help
./realm example
./realm playground
```

Help does not compile or need Cargo. The example builds the locked Rust checker,
runs two controlled workers and retains their actual files/reports. The viewer
prints a loopback URL. It uses the same Rust executable for all checks.
No private worktree, original Git history, account, AI model or VM is needed.
Public Cargo dependencies are fetched unless cached. Development debug information
defaults to disabled; set CARGO_PROFILE_DEV_DEBUG to override it.

Use a fresh output directory for each experiment. Existing evidence is never
replaced: `./realm example --output ANOTHER_DIRECTORY`. Benchmark commands are
`./realm bench --output FRESH_DIRECTORY` and `./realm baseline --output OTHER_DIRECTORY`.
They also work from a manifest-verified archive with no .git directory.

For a standalone checker: `./realm install --root "$HOME/.local/realm"`, then
invoke `~/.local/realm/bin/realm-artifact`. Keep this source directory for the
viewer, examples and benchmark wrappers; cargo install installs only the Rust CLI.
Native Windows and WSL are untested here.

## Captured coding task

From a clean Git clone, with the platform prerequisites above:

```sh
./realm coding-demo --output /tmp/realm-coding-first --disposable-replay
```

Use a new output path on repeat runs. `capture.realm`, `RESULT.json`, receiver
reports and final-state checks are saved there. Omit the replay flag for inspection
only. Expect mechanics PASS and receiver **INCOMPLETE / NONE**; exit zero means
those development checks behaved as expected, not execution authorization.
[Example and contributor instructions](examples/coding/README.md).
The coding runner requires committed source identities; artifact-only commands
also work from Git-free source archives. Verify either with
`python3 tools/check_release.py`.

## Optional local macOS ARM64 binary preview

No native executables are published with v0.1.0-preview.1. This optional preview
is for local maintainer evaluation; use the browser replay or the source build
for the supported public experience.

The separate local preview contains its executable, source, viewer and required
license notices. It needs Python, not Rust/Cargo. After extraction, the same
`./realm example` and `./realm playground` commands work. The launcher checks the
platform and executable SHA-256 before running it. No binary is automatically
fetched. The checksum is not publisher authentication.

This optional preview is unsigned and not notarized. Downloaded-file Gatekeeper
behavior and other Macs are NOT_TESTED. Do not remove quarantine, disable security
controls or bypass warnings to make it work. Source-only research evaluation does
not require notarization. Linux/Windows binaries are not issued by this candidate.

Rebuild included source using `REALM_BUILD_FROM_SOURCE=1 ./realm example --output NEW_DIRECTORY`.
The binary manifest records compiler/source/profile and exact executable hash.
Functional reproducibility is tested; cross-machine bit-identical builds are not
claimed. Source builds may take about a minute; native after-extraction timing
excludes download/extraction/compiler installation and is measured separately.

## Read a result correctly

VALID checks recorded content and bindings. It does not establish complete
observation, truthful logs, task correctness or execution authorization. A valid
artifact with --require-execution returns INCOMPLETE, exit 3. The viewer displays
UNKNOWN / NOT_CHECKED explicitly. Python subprocess or script success is not a
qualified runtime. The two-history counterexample uses cooperative synthetic directories. The coding
demo adds bounded OS child sandbox checks, but its controller, host and observation
coverage remain unqualified. Neither is a production containment guarantee.
