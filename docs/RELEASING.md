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
The existing fast and native workflows use read-only fork tokens and no supplied
secrets. PR #8 hosted validation is **NOT_RUN**, deliberately skipped to respect
the current compute authorization boundary; earlier main checks are not evidence
for this head. Do not increase billing or dispatch jobs without authorization.
Before merge, the owner must review the local evidence and explicitly decide
whether to approve hosted validation or accept this documented NOT_RUN limitation.
Never override repository protections or silently present local tests as hosted CI.
