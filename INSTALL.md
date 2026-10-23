# Install and evaluate

## Reference path: locked source build

Use Python 3.10+, Rust/Cargo 1.97.1 and a C compiler on macOS or Linux. Extract
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

## Optional macOS ARM64 binary preview

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
qualified runtime. All example effects are confined by convention to fresh
synthetic test directories; this is not an OS containment guarantee.
