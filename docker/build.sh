#!/bin/bash

set -e

STATIC_LINKING=${STATIC_LINKING:-OFF}
RUN_TESTS=${RUN_TESTS:-1}

# Install bcc
cd /bcc/build
cp src/cc/libbcc.a /usr/local/lib64/libbcc.a
cp src/cc/libbcc-loader-static.a /usr/local/lib64/libbcc-loader-static.a
cp src/cc/libbpf.a /usr/local/lib64/libbpf.a
cd /

# Build bpftrace
mkdir -p "$1"
cd "$1"
cmake -DCMAKE_BUILD_TYPE="$2" -DSTATIC_LINKING:BOOL=$STATIC_LINKING ../
shift 2
make "$@"

if [ $RUN_TESTS = 1 ]; then
  set +e
  ./tests/bpftrace_test $TEST_ARGS;
  # TODO(mmarchini) re-enable once we figured out how to run it properly on CI
  # make runtime-tests;
fi
