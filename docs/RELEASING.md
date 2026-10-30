# Releases

REALM uses semantic versions with explicit prerelease labels. The current version
candidate is `0.2.0-experimental.1`; the last published tag remains
`0.1.0-preview.1`. APIs/format guarantees remain experimental scope.

1. Start from reviewed public main and choose a version; update workspace version,
   changelog and public docs in a PR. Preserve locked dependency provenance.
2. Run `python3 tools/check_release.py`, Rust tests, launcher/viewer tests, the
   example and finite benchmark/baseline; preserve negative and NOT_RUN evidence.
3. Review rights, all new files, dependency/asset notices and secret scans. Never
   expose private evidence to obtain automated approval.
4. Pin the approved public commit. Create a source archive with `git archive`,
   publish its SHA-256, and mark preview releases as prereleases.
5. Tag exactly that commit and issue release notes with supported environments,
   scientific limits and command examples. Never upload a private Git bundle.

The initial release is source-only. No binary distribution is approved. Optional
local unsigned previews are not release assets; never bypass OS protections.
The existing fast and native workflows use read-only fork tokens, no supplied
secrets and standard `ubuntu-24.04` GitHub-hosted runners. For this **public**
repository, standard runner compute remains free independently of private included
usage. There are no artifact/cache upload steps. [GitHub's billing rules](https://docs.github.com/en/billing/concepts/product-billing/github-actions).
Do not generalize this to private/larger runners, Codespaces or native qualification
experiments; never enable paid usage or change budgets to make a check pass.

Use the normal PR checks where these conditions hold. Record actual current-head
results, including zero-step admission failures as NOT_RUN. Source acceptance
records describe their pinned revision; live GitHub checks are authoritative for
later heads. Never infer a hosted pass from local tests, bypass branch protection,
or merge/tag/publish without the owner's final approval.
