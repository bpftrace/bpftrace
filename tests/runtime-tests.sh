#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
    >&2 echo "Must be run as root"
    exit 1
fi

set -e;

TESTS_DIR="$(dirname "${BASH_SOURCE[0]}")";
DIR="$( cd $TESTS_DIR >/dev/null && pwd )"
BPFTRACE_RUNTIME_TEST_EXECUTABLE=${BPFTRACE_EXECUTABLE:-$DIR/../src/bpftrace};
export BPFTRACE_RUNTIME_TEST_EXECUTABLE;

echo "===================="
echo "bpftrace --info:"
echo "===================="
"${BPFTRACE_RUNTIME_TEST_EXECUTABLE}" --info;

pushd $TESTS_DIR >/dev/null 2>&1
python3 -u runtime/engine/main.py "$@"
