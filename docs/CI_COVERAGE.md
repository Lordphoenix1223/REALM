# Public validation coverage

Every PR runs fast source, selected-secret-marker, provenance, notice-path and
manifest checks. Changed paths select the additional lanes; deletions and the
old side of renames count. Rust, V7 Python, controller/receiver interfaces and
contracts/schemas select native and V7 lanes. Documentation and synchronization
changes retain the inexpensive checks. Validation lane coverage always reports
and fails if a selected job fails or does not run.

- Linux native: finite Rust workspace/toolkit/adapter controls, formatting, strict
  Clippy and optional fuzz-target compilation. Four root-only metadata fixtures
  are explicitly NOT_RUN on an unprivileged runner. No guest/KVM is launched.
- Linux V7 interface:42 ownership/contract/refusal controls, including14 persistent
  keeper controls. The two development-sandbox executions run in the required
  macOS lane instead of being treated as Linux passes.
- macOS V7:30 interface/contract controls, including the real bounded API-referee
  failure/repair campaign and the report-only-repair counterexample.

Actual hosted Linux failures are retained: the first job lacked bubblewrap; with
that prerequisite installed, bubblewrap refused loopback setup (RTM_NEWADDR,
operation not permitted), and the two sandbox executions failed. No runtime
policy, capability restriction or test assertion was relaxed. `tools/dev.py v7`
continues to attempt the full suite on a local host and fails if its sandbox does
not conform. `v7-interface` explicitly selects the contract/ownership controls.
Passing macOS tests does not qualify the failing hosted Linux sandbox.

CI uses standard public-repository runners, read-only repository permissions,
pinned actions, no persisted checkout credentials, no fork secrets and no
pull_request_target. It does not create production trust, run a guest, dispatch
protected effects, call a model or start paid external compute. Fuzz compilation
is not a fuzz campaign. Native production qualification NOT_RUN; authority NONE.
