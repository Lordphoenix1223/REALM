# One execution-bound development chain

From a clean, frozen checkout on this Mac, with the existing cached Rust and
Homebrew Python dependencies:

```sh
/opt/homebrew/bin/python3 scripts/v7/run_development_vertical.py \
  --output /private/tmp/realm-vertical-FRESH \
  --task scripts/v7/vertical_task/task.json \
  --task-sha256 14f21362868aed244030e18c61edf294d0355cd299c10ca680b059e1881b71a3 \
  --actions scripts/v7/vertical_task/actions.json \
  --target /private/tmp/realm-vertical-target-20261028 --disposable-replay
```

Use a fresh output pathname each time. The command builds offline, runs the
existing restricted worker, executes candidate code in its existing Seatbelt
sandbox, independently checks the actual subject, audits the captured tool
sequence, and creates `capture.realm` with the existing artifact encoder.
The externally pinned task requires repairs to three files. Codex supplied the
restricted tool proposals; reproducing the command replays those proposals,
not a fresh model inference. No model API or remote compute is used.

The artifact producer receives capture bytes and external expectations. It has
no candidate directory argument. Its output bytes derive from the ordered
captured writes, with all six original evidence documents embedded as explicitly
non-authoritative records. The receiver reconstructs the archive, reports
INCOMPLETE/NONE, and exports its original capture to a separate invocation of
the existing transcript auditor. That auditor verifies SHA-256 chain, transitions,
regenerated check semantics and physical reconstruction against the external task
and source pins. Interpreter and journal-head pins are captured from the original
run and handed independently of the archive; they are integrity pins, not
preauthorized runtime trust.
The Rust diagnostic projection check alone does not authenticate the hash chain,
execution, referee or completeness. These are not production evidence claims.

`RESULT.json` records commands, exits, source identity, artifact hashes, genuine
receiver decision and independently observed unchanged destination bytes/inodes/
mode/link counts. Missing capture and forbidden projections must refuse. A
forbidden tool request also executes through the worker and must refuse.
`FAILURE.json` attributes a failed stage; original evidence is never overwritten.
The script's exit zero means all expected development outcomes occurred; overall
qualification status remains INCOMPLETE. No protected destination application is dispatched. Optional `--disposable-replay`
materializes only the independently audited artifact-derived projection into a
fresh private child using exclusive no-follow creates. A separate process checks
actual final bytes, modes and link counts. This is human-authorized development
mechanics, not receiver authorization; INCOMPLETE/NONE remains unchanged.

Production admission, canonical native publication and application capabilities
are unchanged. A matching JSON transcript cannot create their process-local
native owners. The next hardware gate is the existing official Linux x86 jailer
exec-stop diagnostic with exact held executable, privilege, namespace, cgroup,
resource and stop/reap observations. Passing that diagnostic alone is insufficient:
one separately authorized full native coding run must then supply original
same-run capture, referee, custody and terminal-retirement owners to the sole
issuer, followed by independently provisioned receiver policy and destination
permission. Protected installation and these privileged/remote operations are
not authorized by this development command.

For fresh live AI generation, use the existing harness with `--live-agent` and the pinned data-only tasks in `../fresh_tasks/`. See `evidence/v7/fresh-live-agent-20261030/README.md` for exact commands, actual outcomes and limits. This saved-action command remains a regression, not a fresh solve. PR77's original source and pins remain preserved in Git history; the current combined source also includes its reviewed receiver updates.

For independently repeatable CLI generation and the frozen unrelated task suite, see `scripts/v7/fresh_tasks/README.md`. Older evidence pins remain historical; current source requires its current externally frozen task wrapper.
