#!/bin/bash

set -e;

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

BPFTRACE_RUNTIME=${BPFTRACE_RUNTIME:-$DIR/../src/bpftrace};
export BPFTRACE_RUNTIME;

cd $DIR/runtime/runtime;
python -W ignore -m unittest discover --pattern=*.py;
