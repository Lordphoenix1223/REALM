# Public source contents

EXPORT_MANIFEST.json is the exact selected file inventory; each entry hashes a
distributed file except the manifest itself. `tools/check_release.py` checks it in
a Git clone or source archive, along with notices, links and promoted-source hashes.

The v0.2 experimental candidate adds the existing bounded coding worker, independent
task and transcript checks, capture-derived Rust packing/receiver reconstruction,
explicit disposable replay and independent final-state checks. The example,
frozen inputs, tests and source promotion records are included. No native launch,
installed trust, policy signing, private history, raw private runs, model or VM
image is bundled. Dependency packages and upstream notice texts are unchanged.

The required V6 library still contains research modules; their presence is not a
supported native execution guarantee. Splitting it is future maintenance, not a
new release feature. Historical v0.1 source contents remain preserved by the
original release tag and its manifest.
