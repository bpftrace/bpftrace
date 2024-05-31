#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
    >&2 echo "Must be run as root"
    exit 1
fi

set -e;

pushd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1

BPFTRACE_RUNTIME_TEST_EXECUTABLE=${BPFTRACE_RUNTIME_TEST_EXECUTABLE:-@CMAKE_BINARY_DIR@/src/bpftrace};
export BPFTRACE_RUNTIME_TEST_EXECUTABLE;

echo "===================="
echo "bpftrace --info:"
echo "===================="
"${BPFTRACE_RUNTIME_TEST_EXECUTABLE}" --info

python3 -u runtime/engine/main.py "$@"
