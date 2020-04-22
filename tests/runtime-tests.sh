#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    >&2 echo "Must be run as root"
    exit 1
fi

set -e;

pushd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1

BPFTRACE_RUNTIME_TEST_EXECUTABLE=${BPFTRACE_RUNTIME_TEST_EXECUTABLE:-../src/};
export BPFTRACE_RUNTIME_TEST_EXECUTABLE;

python3 runtime/engine/main.py $@
