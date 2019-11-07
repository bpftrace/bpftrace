#!/bin/bash

# Compare the IR generated for the shipped
# tools between two bpftrace builds
#

set -o pipefail
set -e
set -u

if [[ "$#" -ne 3 ]]; then
  echo "Compare IR generated between two bpftrace builds"
  echo ""
  echo "USAGE:"
  echo "$(basename $0) <bpftrace_A> <bpftrace_B> <tooldir>"
  echo ""
  echo "EXAMPLE:"
  echo "$(basename $0) bpftrace bpftrace_master /vagrant/tools"
  echo ""
  exit 1
fi

TOOLDIR=$3
BPF_A=$(command -v "$1") || ( echo "ERROR: $1 not found"; exit 1 )
BPF_B=$(command -v "$2") || ( echo "ERROR: $2 not found"; exit 1 )
[[ -d "$TOOLDIR" ]] || (echo "tooldir does not appear to be a directory: ${TOOLDIR}"; exit 1)

# Set to 1 to only compare result after opt
AFTER_OPT=0

if [ $AFTER_OPT -eq 1 ]; then
  FLAGS="-d"
else
  FLAGS="-dd"
fi

TMPDIR=$(mktemp -d)
[[ $? -ne 0 || -z $TMPDIR ]] && (echo "Failed to create tmp dir"; exit 10)

cd $TMPDIR
set +e

function hash() {
    file="${1}"
    sha1sum "${1}" | awk '{print $1}'
}

function fix_timestamp() {
    cat $@ | awk '/(add|sub) i64 %get_ns/ { $NF = ""} {print}'
}

for script in ${TOOLDIR}/*.bt; do
    s=$(basename ${script/.bt/})
    echo "Checking $s"
    2>&1 $BPF_A "$FLAGS" "$script" | fix_timestamp > "a_${s}"
    2>&1 $BPF_B "$FLAGS" "$script" | fix_timestamp > "b_${s}"
    if [ $? -ne 0 ]; then
        echo "###############################"
        echo "bpftrace failed on script: ${s}"
        echo "###############################"
        continue
    fi
    if [[ $(hash "a_${s}") != $(hash "b_${s}")  ]]; then
        echo "Change detected for script: ${s}"
        diff -b -u "a_${s}" "b_${s}"
    fi
done

[[ -n ${TMPDIR} ]] && rm -rf "${TMPDIR}"
