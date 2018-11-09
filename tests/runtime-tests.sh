#!/bin/bash

set -e;

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

BPFTRACE_RUNTIME=${BPFTRACE_RUNTIME:-$DIR/../src/bpftrace};
export BPFTRACE_RUNTIME;

cd $DIR/runtime/python;
python2 -m unittest discover --pattern=*.py;
