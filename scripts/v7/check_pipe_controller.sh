#!/bin/sh
# Non-authorizing local Linux experiment. No remote/model/publisher invocation.
set -eu
if [ "$(uname -s)" != Linux ]; then
    echo 'REFUSE: actual Linux controller process required' >&2
    exit 2
fi
controller_target="${CARGO_TARGET_DIR:-target}"
case "$controller_target" in
    /*) controller_binary="$controller_target/debug/coding_controller" ;;
    *) controller_binary="$(pwd)/$controller_target/debug/coding_controller" ;;
esac
cargo test --offline --locked -p realm-v6 controller_guard::tests --target-dir "$controller_target"
cargo build --offline --locked -p realm-v6 --bin coding_controller --bin controller_mapping_probe --target-dir "$controller_target"
export REALM_PIPE_CONTROLLER_BINARY="$controller_binary"
export REALM_MAPPING_PROBE_BINARY="$(dirname "$controller_binary")/controller_mapping_probe"
export PYTHONDONTWRITEBYTECODE=1
python3 -m unittest discover -s scripts/v7 -p test_pipe_controller.py -v
python3 -m unittest discover -s scripts/v7 -p test_controller_mapping.py -v
python3 -m unittest discover -s scripts/v7 -p test_controller_observations.py -v
echo 'PASS: scoped pipe/filesystem controls; AUTHORITY=NONE; complete-observation qualification=REFUSE' >&2
