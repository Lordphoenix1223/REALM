# Python subprocess adapter (preview)

Python 3.10+, standard library only. This is a tested integration with
`realm.artifact-check.v1`, **not a broadly stable SDK or a Python verifier**.
Build the public Rust checker with `cargo build --locked -p realm-artifact --bin realm-artifact`.
From the repository root:

```sh
PYTHONPATH=integrations/python python3 - <<'PY'
from realm_client import Checker
checker = Checker('target/debug/realm-artifact')
report = checker.verify('site/evidence/intact.realm')
print(report.status.value, report.checks.referenced_content)
print(report.to_dict())
print(checker.verify('site/evidence/intact.realm', require_execution=True).status.value)
PY
python3 examples/external_agent/run.py --checker target/debug/realm-artifact --output NEW_RUN
python3 integrations/python/run_matrix.py --checker target/debug/realm-artifact --output NEW_MATRIX
REALM_CHECKER="$PWD/target/debug/realm-artifact" python3 -B -m unittest discover -s integrations/python/tests -v
```

`Checker.inspect(path)` and `verify(path, require_execution=False)` return frozen
`Report`/`Checks` values and `Status`. `to_dict()` preserves the native JSON,
including metadata, extra fields and embedded claims; it returns a separate copy.
`metadata` can contain caller claims such as ACCEPT. Those are **data**, not a
trusted execution decision. `VALID` checks supported content, never observer
honesty or execution authorization. Requesting execution returns native
`INCOMPLETE`; observation stays UNKNOWN and execution NOT_CHECKED.

| Native status | Exit | Adapter result |
| --- | --- | --- |
| VALID | 0 | Report; supported content checks passed |
| INVALID | 1 | Report; supported content rejected |
| INCOMPLETE | 3 | Report; requested evidence/authority not established |
| UNSUPPORTED | 4 | Report; unsupported reader/format |
| IO_ERROR | 5 | Report; native file-read error |

`record_observations(run_id, before, after, log, output)` calls the existing Rust
importer on supplied files and then returns its actual `--require-execution`
report. It does not run/mediate your agent. Evidence remains non-authoritative;
unknown effects remain recorded. Output must be fresh; native overwrite refusal
is preserved. Import failures have no JSON report: `NativeCommandError` retains
operation, exit code (usage 2 or I/O 5) and stderr.

Missing/unlaunchable executables raise `CheckerUnavailable`; timeouts raise
`CheckerTimeout`; malformed JSON, unsupported schema, status/exit disagreement
or stronger authority claims raise `ProtocolError`. Other native process failures
retain their code in `NativeCommandError`. No failure becomes a valid report.
The caller supplies a trusted executable; there is no shell, download, auto-build,
artifact upload, environment qualification, network resolution or sandbox.
File contents are not frozen against concurrent writers. Timeout defaults to 30s.

The example executes a small deterministic external worker, not an AI model. Its
separate task test can pass or fail while the supplied record remains intact and
execution authorization incomplete. The matrix reuses frozen fixtures and the
existing real paired-history experiment. It retains reports, inputs, worker
outputs and failures in a new directory. These are finite regression controls,
not independent security cases, a detection improvement or runtime qualification.
