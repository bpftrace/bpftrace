#!/bin/bash

# Compare the ELF generated for the shipped
# tools between two bpftrace builds
#

set -o pipefail
set -e
set -u

if [[ "$#" -ne 4 ]]; then
  echo "Compare IR generated between two bpftrace builds"
  echo ""
  echo "USAGE:"
  echo "$(basename $0) <bpftrace_A> <bpftrace_B> <objdump> <tooldir>"
  echo ""
  echo "EXAMPLE:"
  echo "$(basename $0) bpftrace_master bpftrace llvm-objdump-7 /vagrant/tools"
  echo ""
  exit 1
fi

BPF_A=$(command -v "$1") || ( echo "ERROR: $1 not found"; exit 1 )
BPF_B=$(command -v "$2") || ( echo "ERROR: $2 not found"; exit 1 )
OBJDUMP=$(command -v "$3") || (echo "ERROR: $3 not found"; exit 1 )
TOOLDIR=$4
[[ -d "$TOOLDIR" ]] || (echo "tooldir does not appear to be a directory: ${TOOLDIR}"; exit 1)

TMPDIR=$(mktemp -d)
[[ $? -ne 0 || -z $TMPDIR ]] && (echo "Failed to create tmp dir"; exit 10)

cd $TMPDIR
set +e

function hash() {
    file="${1}"
    sha1sum "${1}" | awk '{print $1}'
}

echo "Using version $($BPF_A -V) and $($BPF_B -V)"

for script in ${TOOLDIR}/*.bt; do
    s=$(basename ${script/.bt/})
    echo "Checking $s"
    2>&1 $BPF_A --emit-elf "a_${s}" "$script" >/dev/null
    2>&1 $BPF_B --emit-elf "b_${s}" "$script" >/dev/null
    if [ $? -ne 0 ]; then
        echo "###############################"
        echo "bpftrace failed on script: ${s}"
        echo "###############################"
        continue
    fi
    if [[ $(hash "a_${s}") != $(hash "b_${s}")  ]]; then
        echo "###############################"
        echo "Change detected for script: ${s}"
        diff -u <($OBJDUMP -S "a_${s}") <($OBJDUMP -S "b_${s}")
    fi
done

[[ -n ${TMPDIR} ]] && rm -rf "${TMPDIR}"
