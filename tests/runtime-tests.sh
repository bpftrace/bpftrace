#!/usr/bin/env bash

# Runtime tests need root to load BPF programs. When invoked without root,
# self-elevate via `sudo` while preserving PATH and PYTHONPATH so that the
# Python interpreter and modules from the caller's environment (notably the
# Nix dev shell, where `looseversion` is exposed via PYTHONPATH rather than
# installed into a site-packages directory) remain visible to runtime/engine.
# See https://github.com/bpftrace/bpftrace/issues/5110.
if [[ $EUID -ne 0 ]]; then
    exec sudo --preserve-env=PATH --preserve-env=PYTHONPATH -- \
        "${BASH_SOURCE[0]}" "$@"
fi

set -e;

TESTS_DIR="$(dirname "${BASH_SOURCE[0]}")";
DIR="$( cd $TESTS_DIR >/dev/null && pwd )"
BPFTRACE_RUNTIME_TEST_EXECUTABLE=${BPFTRACE_EXECUTABLE:-$DIR/../src/bpftrace};
export BPFTRACE_RUNTIME_TEST_EXECUTABLE;

# Pre-flight: surface a clear, actionable error when the runtime engine's
# Python deps are not importable. Common cause: the user invoked
# `sudo ./build/tests/runtime-tests.sh` from a Nix dev shell, so sudo
# stripped PATH/PYTHONPATH and python3 (or its modules) come from the host
# instead of the dev shell. See issue #5110.
if ! python3 -c 'import looseversion' >/dev/null 2>&1; then
    >&2 echo "error: runtime tests require the 'looseversion' Python module."
    >&2 echo "If you are using the Nix dev shell, re-run without sudo so this"
    >&2 echo "script can self-elevate while preserving PATH and PYTHONPATH:"
    >&2 echo "    ./build/tests/runtime-tests.sh"
    >&2 echo "Or invoke sudo directly with the env preserved:"
    >&2 echo "    sudo --preserve-env=PATH --preserve-env=PYTHONPATH \\"
    >&2 echo "        ./build/tests/runtime-tests.sh"
    exit 1
fi

echo "===================="
echo "bpftrace --info:"
echo "===================="
"${BPFTRACE_RUNTIME_TEST_EXECUTABLE}" --info;

pushd $TESTS_DIR >/dev/null 2>&1
python3 -u runtime/engine/main.py "$@"
