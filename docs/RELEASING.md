# Releases

REALM uses semantic versions with explicit prerelease labels. The current version
is `0.1.0-preview.1`; APIs/format guarantees remain research-preview scope.

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
Hosted CI at launch is NOT_RUN because account usage admission is blocked; local
validation is recorded separately. This repository initially has no Actions
workflows. Enabling CI is an explicit maintainer/account decision, not a passing
check inferred from an empty run.
