#!/bin/bash

set +e;

if [[ $EUID -ne 0 ]]; then
    >&2 echo "Must be run as root"
    exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

BPFTRACE_EXECUTABLE=${BPFTRACE_EXECUTABLE:-$DIR/../src/bpftrace};

EXIT_STATUS=0;

# TODO(mmarchini) get path from cmake
for f in $(ls ../../tools/*.bt); do
  if $BPFTRACE_EXECUTABLE --unsafe -d $f 2>/dev/null >/dev/null; then
    echo "$f    passed"
  else
    echo "$f    failed";
    $BPFTRACE_EXECUTABLE --unsafe -d $f;
    EXIT_STATUS=1;
  fi
done

exit $EXIT_STATUS
