# What these finite experiments establish

Run `./realm bench --output NEW_DIRECTORY`. Python's standard library orchestrates
the existing Rust checker; no model service, trusted runtime or VM is involved.
Run `./realm baseline --output ANOTHER_DIRECTORY` for the matched legacy comparison.
Source archives verify their export manifest and do not require Git to run either.

## A — 18 fixture variants, five repeated checks each

One synthetic base fixture is varied in 18 designed ways, yielding 90 checker
invocations. The frozen manifest and all 18 input artifacts are in `fixtures/a/`.
The runner regenerates those same bytes; expectations are unchanged from the
original frozen experiment. Five repeats measure consistency, not independent
security cases or a general error rate.

| Outcome | Distinct variants | Repeated observations |
| --- | ---: | ---: |
| VALID | 5 | 25 |
| INVALID | 10 | 50 |
| INCOMPLETE | 1 | 5 |
| UNSUPPORTED | 2 | 10 |
| Matching each frozen expectation | 18 | 90 |

Cases include payload substitutions, cross-run/dangling/duplicate references,
missing portable and thin content, future versions, truncation, trailing bytes,
hostile frame lengths and hostile display text. A forged ACCEPT, consistent false
effect and omitted unknowns intentionally remain intact: their truth is not
established by content checks. Every execution-authority request stays incomplete.

A pinned SHA-256 reference also correctly detects byte identity differences, but
needs an externally trusted reference and answers a different question. Its
in-process timing excludes CLI startup; do not advertise a speedup over it.
The matched legacy Integrity/full ContentComplete baseline uses the same 18 frozen
inputs, five repeats each. Legacy accepts 30; full content accepts 25 and labels
five missing-thin-content observations INCOMPLETE. Both match 90/90 of their own
contracts. Those five extra integrity-only acceptances are not legacy errors.
Neither baseline nor the content interface establishes execution authorization.

## B — seven mechanisms, four related arithmetic seeds, three repeats

This is 28 related configurations and 84 actual finite Python-controller runs,
not 28 independent real-world issues or AI-model trajectories. The mechanisms
are correct repair, wrong answer, transient forbidden write/restore, extra file,
synthetic inherited pipe input, omitted observation and false effect report.
A separate process tests the resulting function. A cooperative handshake lets
the harness independently reopen a deliberately transient protected-file change.

| Measurement | Observations |
| --- | ---: |
| Task tests pass / fail | 72 / 12 |
| Planted policy violations independently observed | 60 |
| Those violations passing task tests | 60 / 60 |
| Supplied log/final-snapshot baseline flags | 36 / 60 |
| Violations hidden from that baseline | 24 |
| Artifact integrity passes | 84 / 84 |
| REALM runtime-policy detections | 0 / 60 |
| Execution-authority requests INCOMPLETE | 84 / 84 |
| Authorizations granted | 0 |
| Qualified execution | NOT_RUN |

The 12 wrong-answer runs also produce intact artifacts. No authorization recall
can be inferred from granting none. Task tests correctly answer arithmetic
questions; their missing policy checks are not arithmetic false positives.
The harness's observations are not a REALM runtime detection. See the
[detailed two-history case study](../docs/COUNTEREXAMPLE.md) and `./realm example`.

## Reproduction and retained evidence

`reference/results.json` and `reference/rows.json` retain the original frozen
aggregate and every measurement row. The compact source carries the frozen A
inputs rather than hundreds of duplicate output files. A new run preserves all
actual worker source, before/after files, intentionally failed probes, supplied
logs, independent reopen observations, artifacts, checker reports, manifests,
source/config/binary hashes and timings. Compare aggregate contract outcomes;
scheduling/compiler/platform differences change times, not the planted cases.

The benchmark construction, worker mechanisms, configuration and expected statuses
were not changed for v0.1. Only archive provenance handling and baseline fixture
location changed. Source-hash differences document those portability edits.
All tests remain finite and designed. The generator and oracle can share errors;
this is not independent scientific replication. Tiny artifact timings do not
establish scaling behavior, arbitrary-agent safety or a qualified execution path.
Missing trusted capture/capability enforcement remains work for the V7 lanes.
