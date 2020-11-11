#!/bin/bash

# Compare the processing speed for the shipped
# tools between two bpftrace builds
#
# based on scripts/compare_tool_speed.h
#

set -o pipefail
set -e
set -u

if [[ "$#" -lt 3 ]]; then
  echo "Compare tools' speed between two bpftrace builds"
  echo ""
  echo "USAGE:"
  echo "$(basename $0) <bpftrace_A> <bpftrace_B> <tooldir> [<testmode>] [<threshold>]"
  echo ""
  echo "EXAMPLE:"
  echo "$(basename $0) bpftrace bpftrace_master /vagrant/tools"
  echo ""
  echo "NOTE: assume that second bpftrace binary is newer"
  exit 1
fi

TOOLDIR=$3
BPF_A=$(command -v "$1") || ( echo "ERROR: $1 not found"; exit 1 )
BPF_B=$(command -v "$2") || ( echo "ERROR: $2 not found"; exit 1 )
[[ -d "$TOOLDIR" ]] || (echo "tooldir does not appear to be a directory: ${TOOLDIR}"; exit 1)


TMPDIR=$(mktemp -d)
[[ $? -ne 0 || -z $TMPDIR ]] && (echo "Failed to create tmp dir"; exit 10)

cd $TMPDIR
set +e

TESTMODE=${4:-codegen}
if [[ $TESTMODE != "codegen" && $TESTMODE != "semantic" ]]; then
    echo invalid testmode: $TESTMODE
    exit 20
fi
THRESHOLD=${5:-1}
TIME="/usr/bin/time -f%e --"
FLAGS="--no-warnings --test $TESTMODE"

echo $TESTMODE test
echo "Using version $($BPF_A -V) and $($BPF_B -V)"

MAXLEN=0
for script in ${TOOLDIR}/*.bt; do
    s=$(basename ${script/.bt/})
    len=${#s}
    if [[ "$MAXLEN" -lt "$len" ]]; then
        MAXLEN=$len
    fi
done

echo -n "         script"
for i in `seq 0 1 $((MAXLEN - 6))`; do echo -n ' '; done
echo "A     B     diff"

for script in ${TOOLDIR}/*.bt; do
    s=$(basename ${script/.bt/})
    len=${#s}
    space=$((MAXLEN - len))
    echo -n "Checking $s"
    for i in `seq 0 1 $space`; do echo -n ' '; done
    a=`$TIME $BPF_A $FLAGS "$script" 3>&1 1>&2 2>&3 3>&-`
    b=`$TIME $BPF_B $FLAGS "$script" 3>&1 1>&2 2>&3 3>&-`
    if [ $? -ne 0 ]; then
        echo "###############################"
        echo "bpftrace failed on script: ${s}"
        echo "###############################"
        continue
    fi
    d=$(echo $b - $a | bc)
    t=$(echo "$d > $THRESHOLD" | bc)
    mark=""
    if [[ "$t" -eq 1 ]]; then
        mark="*"
    fi
    echo "$a  $b  $d$mark"
done

[[ -n ${TMPDIR} ]] && rm -rf "${TMPDIR}"
