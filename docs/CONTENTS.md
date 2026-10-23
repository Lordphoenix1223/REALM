# Exact v0.1 release contents

{
  "crates": 48,
  "third_party_notice_files": 120,
  "frozen_a_inputs": 18
}

Two locked Rust crates (unchanged verifier/library source), one supported CLI,
Python launcher/local server and tests, three viewer files, four original visual
assets, 18 frozen artifact inputs plus their manifest, benchmark/config/baseline
code and reference aggregate/rows, one runnable two-history example, scoped
documentation, two project license texts, NOTICE, dependency notices and export
provenance. EXPORT_MANIFEST.json hashes every other distributed file.

The V6 library is a required existing compile dependency. Its research modules
are not supported launch guarantees. Splitting that library is future maintenance,
not a prerequisite or new feature in this release.

Canonical maintenance additions include public agent guidance, a changelog, issue
and PR templates, a release/maintainer guide, a bounded explicit-file promotion
helper and a manifest/link checker. These extend the audited source snapshot;
verifier, benchmark, dependency and asset bytes remain unchanged.
