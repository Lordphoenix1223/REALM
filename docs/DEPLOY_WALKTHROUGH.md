# Publish the static evidence walkthrough

The site is vanilla HTML/CSS/JS with frozen native Rust results. No build framework,
external font, upload endpoint, AI account or paid backend is required. It is a
**prepared evidence replay**, not browser-side independent verification.

## Preview locally

```sh
python3 -m http.server 8873 --bind 127.0.0.1
```

Open `http://127.0.0.1:8873/site/`. No Rust is needed to explore the saved results.
To reproduce and verify the evidence, build the existing native checker first:

```sh
./realm demo
python3 tools/build_walkthrough_evidence.py --checker target/debug/realm-artifact
REALM_CHECKER="$PWD/target/debug/realm-artifact" python3 -B -m unittest discover -s tools -p test_walkthrough.py -v
```

The generator reruns the existing example and synthetic demo, freezes actual
checker JSON and artifacts, and separates the outside observer sidecar from the
supplied observations. It adds no new benchmark and does not improve detection
claims. Source hashes, checker binary hash and platform are recorded. Native
reverification of all eight shipped reports must match exactly.

## Build a static deployment snapshot

After reviewing/committing the public source:

```sh
python3 tools/build_walkthrough_site.py --output /tmp/realm-site-NEW
```

Use a new output path. The builder verifies evidence hashes and copies only the
website, prepared evidence and original project license/notice texts. It never
copies Git history, private records, Rust source or native executables.
`DEPLOYMENT.json` records source commit and all deployed hashes. No backend runs.

## GitHub Pages

Use only public `Lordphoenix1223/REALM`. Publish the built snapshot to a dedicated
`gh-pages` branch with ordinary additive commits; never force-push, mirror or
alter source main. In repository **Settings → Pages**, choose **Deploy from a
branch**, `gh-pages`, `/(root)`. This repository setting is separate from merging
the source PR. The public URL is `https://lordphoenix1223.github.io/REALM/`.
GitHub documents [branch publishing](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site).

For subsequent approved updates, check out the existing `gh-pages` branch in its
own clean deployment clone. Replace only that clone's tracked static files with
the new built snapshot, inspect the diff/manifest, commit and push normally. Do
not copy a private worktree or add its Git remote to the deployment clone.

Keep the preview/replay label visible. Check deployment status and fetch the live
page and deployed hashes before claiming it is published. If Pages admission or
Actions is blocked, record **NOT_RUN**, not a code-check failure or a passing
hosted check. Do not change billing, spend limits or broader permissions to fix it.

## Why this is a replay

The native inspection adapter uses filesystem reads; its required V6 dependency
also includes SQLite and platform code. There is no existing browser/WASM entry
point or byte-buffer browser API with demonstrated parity. A port would need
explicit dependency/API work and adversarial parity tests. That is a separate
engineering task, not something to approximate with JavaScript checks here.
No WASM build/parity claim is made by this PR. All verifier code remains unchanged.

[Documentation home](README.md) · [Evidence notes](../site/evidence/README.md)
