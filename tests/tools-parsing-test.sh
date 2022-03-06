#!/bin/bash

set -u
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
IFS=',' read -ra SKIP_TOOLS <<< "${TOOLS_TEST_DISABLE:-"NONE"}"

function set_tooldir() {
  local dir
  for dir in "../../tools" "/vagrant/tools"; do
      if [[ -d "$dir" ]]; then
          TOOLDIR="$dir"
          return
      fi
  done

  >&2 echo "Tool dir not found"
  exit 1
}

function do_test() {
  local file="$1"
  if $BPFTRACE_EXECUTABLE --unsafe -d "$file" 2>/dev/null >/dev/null; then
    echo "$file    passed"
  else
    echo "$file    failed";
    $BPFTRACE_EXECUTABLE --unsafe -d "$file";
    EXIT_STATUS=1;
  fi
}

function skip_test() {
  local name
  name="$(basename "$1")"
  for i in "${SKIP_TOOLS[@]}"; do
    if [[ "$i" == "$name" ]]; then
      return 0
    fi
  done
  return 1
}


function do_tests () {
  local f
  local tool
  for f in "$TOOLDIR"/*.bt; do
    if skip_test "$f"; then
      echo "Skipping $f"
    else
      if [[ $OLDTOOLS =~ $(basename "$f") ]]; then
        tool="$(dirname "$f")/old/$(basename "$f")"
        do_test "$tool"
      else
        do_test "$f"
      fi
    fi
  done
}


set_tooldir
do_tests

exit $EXIT_STATUS
