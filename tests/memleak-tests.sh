#!/usr/bin/env bash

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

result=0

run_tests () {
    local -n tests=$1
    echo "${GREEN}[==========]${NC} Running ${#tests[@]} $3 tests"
    for tst in "${tests[@]}"; do
        echo "${GREEN}[ RUN      ]${NC} bpftrace "$2" $tst"

        export ASAN_OPTIONS="alloc_dealloc_mismatch=0"
        if eval $BPFTRACE_ASAN "$2" "$tst" > /dev/null 2>&1 ; then
            echo "${GREEN}[       OK ]"
        else
            echo "${RED}[  MEMLEAK ]"
            # re-run the command to output the leak information
            eval $BPFTRACE_ASAN "$2" "$tst"
            result=1
        fi
    done
}


# Add new testcases here
program_tests=(
    '"BEGIN { exit(); }"'
    $'"#include <linux/skbuff.h>\n BEGIN { \$x = ((struct sk_buff *)curtask)->data_len; exit(); }"'
    '"BEGIN { print((1, 2)); exit(); }"'
)

listing_tests=(
    '"kprobe_seq_*"'
)
    
run_tests program_tests "-e" "program"
run_tests listing_tests "-l" "listing"

echo "${GREEN}[==========]"

if [ $result -eq 0 ]; then
    echo "${GREEN}[  PASSED  ]${NC} All tests were successful"
else
    echo "${RED}[  FAILED  ]${NC} Memory leaks detected"
fi

exit $result
