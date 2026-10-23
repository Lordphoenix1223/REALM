# Portable artifact and checker contract

This documents the existing **REALM-PORTABLE-3 / schema 3** format and the new
read-only report interface. The implementation remains
[`ArtifactBundle`](../crates/realm-artifact/src/lib.rs); no second verifier was
introduced. This is a research format, not a promise of compatibility with
unknown future versions.

## Container framing

All lengths/counts are unsigned big-endian integers. The sequence is:

1. The ASCII header `REALM-PORTABLE-3\n` (17 bytes, including newline).
2. A u64 byte length and that many UTF-8 JSON bytes: a two-element array
   `[RealmRun, Envelope]`.
3. A u32 number of local blobs.
4. For each blob: u64 key length, UTF-8 digest key, u64 payload length, payload.

Trailing/truncated data and duplicate blob keys are rejected by the existing
reader. The run schema must be 3. Typed run/envelope structures define the
accepted fields. Do not deserialize a future format as an old one and infer
authority. The new reader caps incoming files at 64 MiB; this is a tool limit,
not a claim that every `.realm` producer is limited to that size.

The new checker and `record` reader validate the opened descriptor as a regular
file, using nonblocking Unix opens so a concurrent replacement with a FIFO does
not wait for a writer. Symlinks to regular files remain supported. Reads stay
size-bounded. This is input handling, not a frozen filesystem snapshot: concurrent
writes may yield inconsistent bytes and the recorded digest identifies only the
bytes actually read. It supplies no execution custody or observation guarantee.

Digest commitments use BLAKE3 over UTF-8 domain, a NUL byte, and the committed
bytes. Run identity uses `realm.run` over the engine's recursive canonical JSON
serialization. Do not substitute an arbitrary JSON serializer and expect the
same identity. The engine's transport identity is over its canonical repacking;
the report's separate `input_blake3` hashes the exact incoming file bytes.
Neither hash authenticates a producer without an independently trusted binding.

## Claims and proof levels

- `RealmRun` commits to run identities, challenge (which may be absent), intent,
  starting/final state commitments, environment, input/output blob references,
  checkpoints, observations, proposed effects, unknown effects and evidence.
- `Envelope` carries reported verification/publication, signatures/attestations
  and content mode. These are statements to evaluate under a trust policy, not
  self-authenticating authorization. The new report labels them `reported_*`.
- The existing engine checks structure, referenced digests, checkpoint/run scope,
  seal consistency and applicable V6 bindings. A seal is a content commitment,
  not by itself a trusted digital signature or execution proof.
- `ContentComplete` asks the same engine to resolve all required referenced
  bytes. A thin bundle can pass integrity for included references and still be
  incomplete. The CLI does not fetch missing content or execute artifact content.
- Referenced-content completeness is not complete observation of a process.
  Extra unreferenced local blobs are not evidence of execution, and the report
  does not claim a general authenticated archive or provenance audit.

## JSON report: `realm.artifact-check.v1`

`inspect FILE --json` and `verify FILE --json` emit one JSON document on stdout,
including input errors. CLI argument errors use stderr and exit 2. Consumers
must check the exit code, schema, status and individual proof fields.

| Status | Exit | Meaning |
| --- | --- | --- |
| `VALID` | 0 | Existing integrity and required referenced-content checks passed; no execution authority follows |
| `INVALID` | 1 | Malformed container, inconsistent binding, altered referenced bytes or other engine rejection |
| Usage error | 2 | Wrong command arguments; run `--help` |
| `INCOMPLETE` | 3 | Referenced content is missing, or requested execution authorization cannot be established |
| `UNSUPPORTED` | 4 | Recognized unsupported format/schema or reader size limit |
| `IO_ERROR` | 5 | Missing/unreadable/nonregular input |

Proof fields are deliberately separate: `artifact_integrity` is PASS/FAIL/
NOT_CHECKED; `referenced_content` is COMPLETE/INCOMPLETE/FAIL/NOT_CHECKED;
`observation_completeness` stays UNKNOWN; `execution_authorization` stays
NOT_CHECKED. `--require-execution` refuses to turn content validity into authority.

Metadata includes run/environment/intent, exact and canonical identities,
input/output references, observations, proposed effects, unknown effects,
evidence, and reported decisions/publication. These fields describe the supplied
artifact. In particular, reported ACCEPT is never promoted to checked authority.
Field order is not a protocol guarantee. Legacy commands retain their old
interfaces; use the new report for integrations.

## Samples and producers

The compiled-in sanitized fixture comes from
[`minimal.realm`](../crates/realm-artifact/examples/minimal.realm).
`realm-artifact demo --output FRESH_DIR` materializes that valid fixture, a
one-byte payload corruption and a valid thin bundle with missing content, plus
machine-readable reports. Generated samples remain outside Git.

`record` and [`from_file_observation`](../crates/realm-artifact/src/observations.rs)
package externally supplied snapshots/log bytes without claiming prospective
capture. The [external-process example](../examples/counterexample/run.py)
shows the distinction. Production V6 receipt/capability adapters and lifecycle
trust checks remain separate; this interface cannot mint their capabilities.
