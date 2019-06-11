#!/bin/bash

set -x
set -e

STATIC_LINKING=${STATIC_LINKING:-OFF}
RUN_TESTS=${RUN_TESTS:-1}
REPOSITORY=${REPOSITORY:-../}

# Build bpftrace
mkdir -p "$1"
cd "$1"
cmake -DCMAKE_BUILD_TYPE="$2" -DSTATIC_LINKING:BOOL=$STATIC_LINKING $REPOSITORY
shift 2
make "$@"

if [ "$RUN_TESTS" = "1" ] || [ "$RUN_ALL_TESTS" = "1" ]; then
  set +e
  if [ "$RUN_ALL_TESTS" = "1" ]; then
    ctest -V
  else
    ./tests/bpftrace_test $TEST_ARGS;
  fi
fi
