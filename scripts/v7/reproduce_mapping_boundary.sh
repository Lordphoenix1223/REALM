#!/bin/sh
# Actual Linux red/green experiment. Never issues publication authority.
set -eu
[ "$(uname -s)" = Linux ] || { echo 'REFUSE: Linux required' >&2; exit 2; }
[ "$#" = 1 ] || { echo 'requires a new absolute output directory' >&2; exit 2; }
case "$1" in /*) ;; *) exit 2 ;; esac
output="$1"
mkdir -m 700 "$output" # existing paths refuse; retained failures are never replaced
baseline=3a8fd8016fe9288b572155662463ebc258c7fd5b
source_root=$(git rev-parse --show-toplevel)
git -C "$source_root" rev-parse HEAD > "$output/auditor-head.txt"
(cd "$source_root" && sha256sum Cargo.lock crates/realm-v6/src/controller_guard.rs \
    crates/realm-v6/src/bin/controller_mapping_probe.rs scripts/v7/test_controller_mapping.py \
    scripts/v7/reproduce_mapping_boundary.sh) > "$output/source-sha256.txt"
mkdir "$output/source-before"
git -C "$source_root" archive "$baseline" Cargo.toml Cargo.lock crates |
    tar -x -C "$output/source-before"
cp "$source_root/crates/realm-v6/src/bin/controller_mapping_probe.rs" \
    "$output/source-before/crates/realm-v6/src/bin/controller_mapping_probe.rs"
export PYTHONDONTWRITEBYTECODE=1
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
cargo build --offline --locked --manifest-path "$output/source-before/Cargo.toml" \
    -p realm-v6 --bin controller_mapping_probe --target-dir "$output/target-before" \
    > "$output/build-before.log" 2>&1
export REALM_MAPPING_PROBE_BINARY="$output/target-before/debug/controller_mapping_probe"
export REALM_MAPPING_CAPTURE="$output/before.json"
before_status=0
python3 -m unittest discover -s "$source_root/scripts/v7" -p test_controller_mapping.py -v \
    > "$output/before.log" 2>&1 || before_status=$?
[ "$before_status" = 1 ] || { echo 'unexpected baseline test status' >&2; exit 2; }
python3 - "$output/before.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
rows = {r['mode']: r for r in report['captures']}
assert set(rows) == {'shared', 'private', 'none'}
for mode, row in rows.items():
    result = json.loads(bytes.fromhex(row['stdout_hex']))
    assert row['exit'] == 0 and result['guard_installed']
    assert result['write_return'] == -1 and result['write_errno'] == 1
    assert row['actual_first_byte_hex'] == ('42' if mode == 'shared' else '41')
assert report['authority'] == 'NONE' and report['qualification'] == 'REFUSE'
PY
cargo build --offline --locked --manifest-path "$source_root/Cargo.toml" \
    -p realm-v6 --bin controller_mapping_probe --target-dir "$output/target-after" \
    > "$output/build-after.log" 2>&1
export REALM_MAPPING_PROBE_BINARY="$output/target-after/debug/controller_mapping_probe"
export REALM_MAPPING_CAPTURE="$output/after.json"
python3 -m unittest discover -s "$source_root/scripts/v7" -p test_controller_mapping.py -v \
    > "$output/after.log" 2>&1
echo 'Reproduced baseline shared-file mutation and fixed startup refusal; AUTHORITY=NONE; qualification=REFUSE'
