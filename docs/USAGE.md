# Check evidence on your own machine

This guide uses the existing Rust checker. For the browser's prepared-result replay,
see [the walkthrough](https://lordphoenix1223.github.io/REALM/). For a first source
build, see [installation](../INSTALL.md).

## Run the two-history experiment

```sh
./realm example
```

Inspect `realm-counterexample/result.json`, each worker's actual files, the outside
observer's evidence and the checker reports. Use a new output directory to repeat:

```sh
./realm example --output another-experiment
```

Both task tests pass; both supplied artifacts are valid and byte-identical. One
worker temporarily changes a file forbidden by the task policy. The cooperative
harness independently reopens it. Supplied logs and final snapshots omit it;
REALM does not detect that runtime-policy violation. Both authorization checks
remain incomplete. See the [full case study](COUNTEREXAMPLE.md).

## Explore the local Proof Viewer

```sh
./realm playground
```

Open the printed loopback URL. Try the intact, tampered and incomplete samples;
flip a byte; inspect activity and unknowns; export the JSON report. To inspect the
counterexample, load `realm-counterexample/hidden/observed.realm`. The Rust checker
runs locally; uploads are temporary and do not leave this machine. This is the
live local tool, unlike the hosted walkthrough's frozen replay.

## Inspect and verify artifacts

```sh
./realm demo
./realm inspect realm-demo/valid.realm --json
./realm verify realm-demo/tampered.realm --json
./realm verify realm-demo/valid.realm --require-execution --json
```

The last two commands intentionally exit 1 and 3. Do not use shell `&&` to pretend
an expected negative exit is a successful verification.

| Result | Exit | What it says |
| --- | --- | --- |
| VALID | 0 | Supported content checks passed. |
| INVALID | 1 | Supplied artifact content is inconsistent or malformed. |
| Usage error | 2 | Check the command arguments. |
| INCOMPLETE | 3 | Available evidence cannot complete the requested check. |
| UNSUPPORTED | 4 | The checker cannot interpret a requested format/feature. |
| IO_ERROR | 5 | The input could not be read as required. |

VALID is not evidence of observer honesty, correct task semantics, exhaustive
observation or execution authorization. UNKNOWN and NOT_CHECKED are deliberate
limits. [Format and JSON contract](ARTIFACT_FORMAT.md).

## Record your own observations

```sh
./realm record run-001 before.txt after.txt supplied.log observed.realm
./realm inspect observed.realm --json
./realm verify observed.realm --require-execution --json
```

Supply your own before/after bytes and log. The importer packages those records;
it neither executes nor contains an agent, and does not make supplied logs trusted.
The execution request remains INCOMPLETE. Never use it as an execution safety gate.

## Reproduce the finite benchmarks

```sh
./realm bench --output realm-bench-fresh
./realm baseline --output realm-baseline-fresh
```

Fresh directories preserve the reports, artifacts and failed probes. The retained
reference aggregates are examples, not a substitute for running the experiment.
[Methods and interpretation](../benchmarks/README.md).

[Documentation home](README.md) · [Back to REALM](../README.md)
