# Operating reviewed private/public synchronization

There is one canonical implementation on the private
`codex/integration-v7-20261109` branch. The public developer base is
`main`. Shared files are copied byte-for-byte from an immutable
reviewed source commit; private Git history is never merged into public history.

## Routine workflow

1. Preserve research and owner PRs privately. Integrate compatible source into a
   dedicated private checkpoint through normal review. Keep failed evidence.
2. Review source, licenses, fixtures, secrets and publication scope. Update the
   private `config/public-export.json` with the full source commit and individual
   SHA256 values only after review. New paths and changed bytes are unapproved
   until the manifest changes in a reviewed private commit.
3. Run `python3 -B scripts/public_sync.py check --public PUBLIC_CHECKOUT`.
   The JSON report names changed/new files, unpublished approved files and source
   commits since the last reviewed source. A nonzero exit is a synchronization
   failure, never implicit permission to export.
4. Start a clean public checkout at the fetched base and run:

```sh
python3 -B scripts/public_sync.py publish --public PUBLIC_CHECKOUT \
  --base main --branch codex/sync-FULL_SOURCE_REVISION \
  --validation RETAINED_PRIVATE_VALIDATION_REPORT
```

The command copies approved committed bytes, checks manifests, commits and pushes
a dedicated branch, and opens a draft public PR. It includes file changes, source
identity, exclusions and the validation-report hash. Raw private logs stay private.
Run the documented fresh-clone tests and inspect the full outgoing public diff
before normal review/merge. The reviewed PR targets public main.

`prepare` performs the same approved copy without committing or publishing.
`check` performs no writes except an explicitly requested local report file.
No mode creates execution qualification, installs trust, dispatches native work,
force-pushes, or deletes owner branches. Removed exports require explicit deletion
review. The source checker detects changed published bytes even if someone
refreshes the general release manifest.

## Automation and credentials

The private `public-sync.yml` checks canonical pushes, supports manual dispatch,
and, once registered on default main, checks daily at 13:23 UTC. It uses a
read-only repository token, a shallow anonymous public clone, and no native
builds. The private job summary and retained JSON artifact report exact drift.
Historic expensive research workflows are manual on the canonical branch.

Automatic cross-repository PR writes are disabled until a dedicated, narrowly permissioned
GitHub App with short-lived installation tokens is supplied with contents/pull-request write access to
PUBLIC REALM only. Do not store a broad personal CLI token, give fork PRs secrets,
or run pull-request code with write credentials. Local `publish` uses the
operator's existing `gh` login and is usable without a new service. The monitor
works without a cross-repository write credential; unattended public PR creation
does not. This distinction must remain visible in release status.

The opt-in reviewed-pr job is implemented behind the private repository variable
`PUBLIC_SYNC_ENABLED=true`, using `PUBLIC_SYNC_TOKEN` in the
`public-source-publication` environment. Configure required reviewers on that
environment before enabling it. Supply `config/public-export-validation.json`
with PASS and the exact reviewed source commit. The job refuses changed or new
unreviewed bytes, reuses an existing identical-source PR, and never merges it.

Protect shared branches against force-push/deletion, require normal PR checks and
resolve review conversations. API/CLI schemas and release tags are not silently
updated: contract or tag changes need explicit release review. The original
`v0.1.0-preview.1` tag is retained; this preview issues no replacement tag.

## Recovery

Keep the private all-refs bundle, its verification/hash, dirty-file archives,
original refs and failed-run evidence in private storage. Never publish those
archives. Reconstruct an integration from its exact source commit and the
reviewed manifest. Re-run `check` against both repositories after fetch. Restore
missing approved public bytes through a new synchronization PR. An environment
failure stays failed/NOT_RUN; it must not be repaired by weakening admission.


## Committed monitoring versus local work

The automatic job compares committed canonical bytes with public main. It reports
changed, new, deleted and renamed shared paths, new relevant source outside the
old export prefixes, unpublished approved bytes, public byte divergence and
additional public shared source. A private-only decision must be reviewed and
pinned; a monitor warning never approves publication. Public-only CI/docs remain
outside canonical core scope.

It cannot inspect uncommitted work on a developer's machine. Run the separate
read-only audit locally and retain its JSON privately (paths can be sensitive):

```sh
python3 -B scripts/audit_local_source.py --repo "$PWD" --worktrees --output /tmp/realm-local-audit.json
```

That command hashes modified, staged, untracked and ignored source under the
explicit roots and linked worktrees. It reports unavailable worktrees. It does not
claim a whole-machine search, publish contents or alter a branch. Regular backups
must include dirty files, ignored source and Git shallow metadata. A successful
`git bundle verify` alone is not an actual restoration test; shallow histories
need their original boundary sidecar or a verified complete ancestry recovery.
