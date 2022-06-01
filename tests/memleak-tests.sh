#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    >&2 echo "Must be run as root"
    exit 1
fi

set -e;

pushd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1

BPFTRACE_ASAN=${BPFTRACE_ASAN:-../src/bpftrace}

if ! nm $BPFTRACE_ASAN | grep -q __asan; then
    >&2 echo "WARNING: bpftrace seems to be compiled without -fsanitize=address,"
    >&2 echo "results may be incorrect (make sure to use -DBUILD_ASAN=On with CMake)"
fi

if tty -s; then
    RED=`tput setaf 1`
    GREEN=`tput setaf 2`
    NC=`tput sgr 0`
else
    RED=
    GREEN=
    NC=
fi

# Add new testcases here
tests=(
    '"BEGIN { exit(); }"'
    $'"#include <linux/skbuff.h>\n BEGIN { \$x = ((struct sk_buff *)curtask)->data_len; exit(); }"'
    )

echo "${GREEN}[==========]${NC} Running ${#tests[@]} tests"

result=0
for tst in "${tests[@]}"; do
    echo "${GREEN}[ RUN      ]${NC} bpftrace -e $tst"

    export ASAN_OPTIONS="alloc_dealloc_mismatch=0"
    if eval $BPFTRACE_ASAN -e "$tst" > /dev/null 2>&1 ; then
        echo "${GREEN}[       OK ]"
    else
        echo "${RED}[  MEMLEAK ]"
        result=1
    fi
done

echo "${GREEN}[==========]"

if [ $result -eq 0 ]; then
    echo "${GREEN}[  PASSED  ]${NC} All tests were successful"
else
    echo "${RED}[  FAILED  ]${NC} Memory leaks detected"
fi

exit $result

