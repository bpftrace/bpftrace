#!/bin/bash

set -e;

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

BPFTRACE_RUNTIME_TEST_EXECUTABLE=${BPFTRACE_RUNTIME_TEST_EXECUTABLE:-$DIR/../src/};
export BPFTRACE_RUNTIME_TEST_EXECUTABLE;

python main.py;
