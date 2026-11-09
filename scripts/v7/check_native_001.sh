#!/bin/sh
# Actual local/kernel controls only; never a publication qualification bypass.
set -eu
if [ "$(uname -s)" != Linux ]; then
    echo 'REFUSE: Linux kernel required (native x86/KVM qualification NOT_RUN)' >&2
    exit 2
fi
native_target="${CARGO_TARGET_DIR:-target}"
cargo test --offline --locked -p realm-v6 --all-targets
cargo clippy --offline --locked -p realm-v6 -p realm-artifact -p realm-cli --all-targets --features realm-artifact/receiver-fixtures -- -D warnings
cargo build --offline --locked -p realm-v6 --bin coding_controller
case "$native_target" in
    /*) native_controller="$native_target/debug/coding_controller" ;;
    *) native_controller="$PWD/$native_target/debug/coding_controller" ;;
esac
printf '' | "$native_controller" --runtime-probe
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/v7 -p test_native_observation.py -v
sh scripts/v7/check_pipe_controller.sh
echo 'Local controls completed; AUTHORITY=NONE; native coding publication/application NOT_RUN' >&2
