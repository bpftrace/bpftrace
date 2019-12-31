#!/bin/bash

set -e

STATIC_LINKING=${STATIC_LINKING:-OFF}
WARNINGS_AS_ERRORS=${WARNINGS_AS_ERRORS:-OFF}
RUN_TESTS=${RUN_TESTS:-1}

# Build bpftrace
mkdir -p "$1"
cd "$1"
cmake -DCMAKE_BUILD_TYPE="$2" -DSTATIC_LINKING:BOOL=$STATIC_LINKING -DWARNINGS_AS_ERRORS:BOOL=$WARNINGS_AS_ERRORS ../
shift 2
make "$@"

if [ $RUN_TESTS = 1 ]; then
  if [ "$RUN_ALL_TESTS" = "1" ]; then
    ctest -V
  else
    ./tests/bpftrace_test $TEST_ARGS;
  fi
fi
