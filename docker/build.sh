#!/bin/bash

set -e

STATIC_LINKING=${STATIC_LINKING:-OFF}
RUN_TESTS=${RUN_TESTS:-1}

# Build bpftrace
mkdir -p "$1"
cd "$1"
cmake -DCMAKE_BUILD_TYPE="$2" -DSTATIC_LINKING:BOOL=$STATIC_LINKING ../
find . -type f -name link.txt | xargs sed -e 's|-Wl,-Bdynamic /usr/lib/llvm8/lib/libLLVM-8.so ||' -i
shift 2
make "$@"

if [ $RUN_TESTS = 1 ]; then
  set +e
  mount -t debugfs debugfs /sys/kernel/debug/
  ./tests/bpftrace_test $TEST_ARGS;
  # TODO(mmarchini) re-enable once we figured out how to run it properly on CI
  # make runtime-tests;
fi
