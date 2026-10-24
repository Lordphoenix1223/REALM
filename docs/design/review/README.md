# Human-first experience review

Actual browser captures, 24 October 2026. These are screenshots of GitHub and the hosted walkthrough, not mockups. The matching GitHub first-screen captures use 1280 × 900 viewports; mobile captures use 390 pixels. The screenshots precede only the keyboard skip-link correction and final review documentation.

| View | Actual capture |
| --- | --- |
| GitHub main before | [Before](github-before.webp) |
| GitHub topic branch after | [After](github-after.webp) |
| GitHub topic branch mobile | [Mobile](github-mobile.webp) |
| Hosted walkthrough, light | [Desktop](walkthrough-desktop.webp) |
| Hosted walkthrough, dark | [Dark](walkthrough-dark.webp) |
| Hosted walkthrough, mobile | [Mobile](walkthrough-mobile.webp) |

The prominent no-install link is now on the first GitHub screen. The README shrank from 138 to 85 lines; practical commands moved into the usage guide. Actual comprehension has not been measured with outside users.

## Checks

- `REALM_CHECKER=/path/to/native/realm-artifact python3 -B -m unittest discover -s tools -p test_walkthrough.py -v`: six tests, including exact native parity for eight saved reports. See [test log](walkthrough-tests.log).
- `node --check site/app.js`: passes.
- `python3 tools/check_release.py`: exact source manifest, relative Markdown paths and upstream notice paths.
- [Browser checks](browser-checks.json): three scenarios, original/changed-byte controls, outside reveal, real JSON, clipboard fallback, keyboard, desktop 1280, mobile 390, narrow 320, no horizontal overflow or observed console errors.
- [Contrast calculations](contrast.json): selected text/background pairs at least 6.0:1 in both themes. This is not a full accessibility certification. No screen-reader user study; reduced-motion CSS inspected without OS preference emulation.
- [Initial deployment check](live-deployment-check.json): anonymous HTTP and all 25 deployed-file hashes checked against the initial clean source snapshot. Later snapshots expose their own exact source commit and file hashes at `/DEPLOYMENT.json`.
- Gitleaks directory and public topic-history scans: zero findings. A clean scan is not proof that all secrets are absent.

The Pages deployment succeeds. Source-code CI is not configured and is therefore **NOT_RUN**, not a passing CI claim. Local checks above are separate evidence.

## Preserved boundaries

Native checker, benchmark mechanisms/results, AGENTS.md, license and upstream notices stay unchanged. Benchmark A remains 18 fixture variants repeated five times. Benchmark B remains zero REALM runtime-policy detections among 60 planted violations; all 84 authorization requests are INCOMPLETE. The outside harness reveals the temporary write; the artifact checker does not detect it. Main and the existing release tag are not changed by this PR.

The next useful evaluation is a short real first-time-user comprehension test, not another feature sprint.
