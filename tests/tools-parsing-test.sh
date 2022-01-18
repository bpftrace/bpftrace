#!/bin/bash

set +e;

if [[ $EUID -ne 0 ]]; then
    >&2 echo "Must be run as root"
    exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

BPFTRACE_EXECUTABLE=${BPFTRACE_EXECUTABLE:-$DIR/../src/bpftrace};

EXIT_STATUS=0;

TOOLDIR=""

OLDTOOLS=${TOOLS_TEST_OLDVERSION:-}

function tooldir() {
    for dir in "../../tools" "/vagrant/tools"; do
        if [[ -d "$dir" ]]; then
            TOOLDIR="$dir"
            return
        fi
    done

    >&2 echo "Tool dir not found"
    exit 1
}

tooldir

for f in "$TOOLDIR"/*.bt; do
  if [[ $OLDTOOLS =~ $(basename $f) ]]; then
      tool=$(dirname $f)/old/$(basename $f)
  else
      tool=$f
  fi
  if $BPFTRACE_EXECUTABLE --unsafe -d $tool 2>/dev/null >/dev/null; then
    echo "$tool    passed"
  else
    echo "$tool    failed";
    $BPFTRACE_EXECUTABLE --unsafe -d $tool;
    EXIT_STATUS=1;
  fi
done

exit $EXIT_STATUS
