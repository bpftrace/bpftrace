#!/bin/bash

set +e;

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

BPFTRACE_EXECUTABLE=${BPFTRACE_EXECUTABLE:-$DIR/../src/bpftrace};

EXIT_STATUS=0;

# TODO(mmarchini) get path from cmake
for f in $(ls ../../tools/*.bt); do
  if $BPFTRACE_EXECUTABLE -d $f 2>/dev/null >/dev/null; then
    echo "$f    passed"
  else
    echo "$f    failed";
    $BPFTRACE_EXECUTABLE -d $f;
    EXIT_STATUS=1;
  fi
done

exit $EXIT_STATUS
