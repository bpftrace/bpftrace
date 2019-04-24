#!/bin/bash

set -e

STATIC_LINKING=${STATIC_LINKING:-OFF}
RUN_TESTS=${RUN_TESTS:-1}
ls /lib/modules
ls /lib/modules/$(uname -r)

# Build bpftrace
mkdir -p "$1"
cd "$1"
cmake -DCMAKE_BUILD_TYPE="$2" -DSTATIC_LINKING:BOOL=$STATIC_LINKING ../
shift 2
make "$@"

if [ $RUN_TESTS = 1 ]; then
  set +e
  let exit_status=0;
  ./tests/bpftrace_test $TEST_ARGS;
  let exit_status="$exit_status + $?"
  make tools-parsing-test;
  let exit_status="$exit_status + $?"
  # TODO(mmarchini) re-enable once we figured out how to run it properly on CI
  # make runtime-tests;
  exit $exit_status;
fi
