# Maintaining public REALM and private research

Public `Lordphoenix1223/REALM` is the long-term home for supported source, issues,
PRs and releases. Private `Lordphoenix1223/REALM-research-private` preserves
experimental implementations/history. Keep separate clones; never mirror refs,
push private branches to public, or merge unrelated histories.

## Ordinary public work

```sh
git clone https://github.com/Lordphoenix1223/REALM.git REALM-public
cd REALM-public
git switch -c codex/describe-change origin/main
# Edit; run relevant Rust/Python tests, example and finite benchmarks.
python3 tools/check_release.py --refresh
python3 tools/check_release.py
# Review source/rights and secret scan; commit only intended files.
git push -u origin HEAD
gh pr create --repo Lordphoenix1223/REALM --draft
```

Review the diff, test evidence, manifest, dependency/rights changes and unknowns.
Merge a focused PR only after the applicable checks and human authorization.
The maintainer can then pull public main normally; the repository is not rebuilt.

## Explicit private-to-public promotion

Start from a clean dedicated public clone at current origin/main. Review precisely
which material is approved, its licensing/asset rights, dependencies and claims.
Keep the approval plan LOCAL and out of Git. Example JSON (replace the hash):

```json
{
  "rights_reviewed": true,
  "purpose": "Approved bounded parser correction",
  "files": [{"source": "path/in/private.rs", "target": "path/in/public.rs",
             "sha256": "EXACT_REVIEWED_SHA256",
             "rights_basis": "Original owner-authorized code; no new third-party material"}]
}
```

Run the bundled helper from public main; it validates all planned bytes/paths
before writing and refuses dirty/non-main destinations, symlinks and history paths:

```sh
python3 tools/promote.py --source /path/to/private-checkout --plan /path/to/LOCAL-plan.json --branch codex/approved-promotion
python3 tools/check_release.py --refresh
python3 tools/check_release.py
# Inspect the entire diff, run relevant tests and gitleaks.
# Review Cargo/lockfile and all upstream notice changes if dependencies changed.
# Commit only intended paths, then push and create a PUBLIC draft PR as above.
```

The helper copies only explicitly selected source bytes; it never imports private
commits, refs or the plan, and never pushes or merges. A reviewed plan is a human
rights decision, not an automated clearance. Any failed gate stops promotion.
Do not attach private inventories, owner documents, account data or raw traces to
public PRs. Summarize only evidence intended for publication.

## Public-to-private synchronization

Use an isolated CLEAN private worktree. Keep its origin on the private repository;
a fetch-only public remote may be added. Do not merge unrelated histories.
For a single reviewed public commit and explicitly selected paths:

```sh
git -C /path/to/public-clone diff --binary APPROVED_COMMIT^ APPROVED_COMMIT -- path/to/file > /tmp/approved-public.patch
cd /path/to/clean-private-worktree
git apply --check /tmp/approved-public.patch
git apply --index /tmp/approved-public.patch
git diff --cached
# Run private compatibility tests; commit and open a PRIVATE PR.
```

If `git apply --check` fails, stop and adapt the selected change manually; do not
reset private work or force a merge. For an initial file, use `git show` from the
public clone and inspect/copy that one file. Preserve private differences and
record the originating public commit in the private commit/PR. Never import
public EXPORT_MANIFEST/PROVENANCE blindly into the full research tree.

## Remote safety

Before every research push, verify the remote is REALM-research-private and its
GitHub visibility is private. Local research clones have a pre-push guard rejecting
other network destinations; hooks are defense in depth and can be bypassed, so
never use `--no-verify` or an alternate push URL to defeat them. Newly created or
previously stopped remote environments must verify/update their checkout remotes
before remote writes. Old-name redirects are deliberately unavailable. Historical
attestation namespaces are protocol identities, not operational push destinations.
