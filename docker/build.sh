#!/bin/bash

set -e

STATIC_LINKING=${STATIC_LINKING:-OFF}
BUILD_TESTS=${BUILD_TESTS:-ON}
RUN_TESTS=${RUN_TESTS:-1}

# Build bpftrace
mkdir -p "$1"
cd "$1"
cmake -DCMAKE_BUILD_TYPE="$2" -DBUILD_TESTING:BOOL=$BUILD_TESTS -DSTATIC_LINKING:BOOL=$STATIC_LINKING ../
shift 2
make "$@"

if [ $BUILD_TESTS = 1 ] && [ $RUN_TESTS = 1 ]; then
  set +e
  mount -t debugfs debugfs /sys/kernel/debug/
  ./tests/bpftrace_test $TEST_ARGS;
  # TODO(mmarchini) re-enable once we figured out how to run it properly on CI
  # make runtime-tests;
fi
