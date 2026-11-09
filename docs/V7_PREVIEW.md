# V7 experimental developer preview

REALM records bounded coding activity in a `.realm`, checks the recorded content,
and keeps task correctness, runtime evidence, and permission to apply effects
separate. The V7 preview publishes the current implementation, including the
controller, bounded retries and attempt history, Session lifecycle, persistent
native keeper, immutable rootfs/sealed inputs, Stage 7 aggregation, independent
receiving, and restricted Stage 8 application source.

This is a development release. Native x86/KVM execution has not independently
qualified this source. Production receiving remains INCOMPLETE with authority
NONE. Publishing the source does not install trust or authorize protected effects.

## What is usable

| Interface | Supported use | Boundary |
| --- | --- | --- |
| `./realm` | Existing artifact toolkit and bounded saved-proposal coding demo | Supplied records do not prove complete observation |
| `cargo build --locked -p realm-cli` | Full research CLI, binary `target/debug/realm` | Separate from the `./realm` toolkit launcher |
| `integrations/python/realm_client.py` | Rust-backed inspect, verify and observation import | Python does not implement a verifier |
| `integrations/python/realm_v7.py` | Existing Checker and trusted Session facade | Controller owns lifecycle; agent receives only execute |
| `scripts/v7/run_development_vertical.py` | Existing bounded controller and Session development pipeline | Fresh model planning needs separate local login; no paid API fallback |
| Native keeper and sealed-input APIs | Compile, inspect, run nonprivileged refusal controls | Installed protected setup and qualified native positives remain NOT_RUN |
| Stage 8 | Inspect restricted effect policy and run disposable fixture checks | No production destination grant is provided |

## Architecture

The existing controller calls `vm_session.Session`, whose native profile retains
the original keeper and process custody. Failed attempts remain in immutable
attempt history. A dependent CLI task requires the successful API predecessor.
Stage 7 consumes retained owners through the existing publisher. Independent
receiving checks the artifact, every attempt receipt, installed runtime pins and
admission leases. Stage 8 applies only the declared restricted effects when its
separate protected checks and authorization pass. No JSON record can reconstruct
an original process owner or mint authorization.

The rootfs is measured and held before birth; attempt inputs travel separately
in a sealed, same-attempt envelope. The official jailer correction excludes one
authenticated unnecessary vendor device before continuation and requires complete
original custody receipts. It does not admit an additional device capability.
The previous hosted pre-VM failure remains failed evidence. Neither that failure
nor component fixtures qualify the new source.

## Read results precisely

| Value | Meaning |
| --- | --- |
| VALID | Supported recorded content and bindings passed the requested checks |
| INVALID | A supported content or integrity check failed |
| INCOMPLETE | Required evidence or requested execution authority is missing |
| NONE | No execution/application authority was issued |
| NOT_RUN | That capability or experiment was not executed |
| UNSUPPORTED | This reader, profile or environment cannot perform the operation |

VALID does not establish truthful or complete observation, universal task
correctness, or permission to execute. The earlier [counterexample](COUNTEREXAMPLE.md)
and its evidence-completeness limitation remain applicable. No zero-error,
70%-improvement, or production-qualification claim is supported.

## Platforms

macOS ARM64 supports the tested local toolkit and Seatbelt development path.
Linux ARM64 was used for non-root keeper refusal controls in a local container;
that result does not establish sandboxed controller success or x86/KVM execution.
The Linux development Worker requires its existing kernel sandbox prerequisites
and refuses when unavailable. The native measured profile requires Linux x86_64,
KVM, its static fence/compiler prerequisites, separately installed protected
profiles, original process custody and same-run qualification. No such positive
qualification was performed for this preview. Windows/WSL remain untested.

Source correspondence and the exact private source revision are recorded in
`SOURCE_MANIFEST.json`; package version is `0.7.0-experimental.1`.
Start with the [contributor quick start](RAY_TED_QUICKSTART.md).
