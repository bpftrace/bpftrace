#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
    >&2 echo "Must be run as root"
    exit 1
fi

set -e;

TESTS_DIR="$(dirname "${BASH_SOURCE[0]}")";
DIR="$( cd "$TESTS_DIR" >/dev/null && pwd )"
BPFTRACE_RUNTIME_TEST_EXECUTABLE=${BPFTRACE_EXECUTABLE:-$DIR/../src/bpftrace};
export BPFTRACE_RUNTIME_TEST_EXECUTABLE;
FILTER=

__usage__()
{
    echo -e "
self-test.sh [-h|--help] [--filter=<PATTERN>]

    -h, --help           show this information.
    --filter=[PATTERN]   only run the tests matching this pattern.
"
    exit ${1-0}
}

TEMP_ARGS=$(getopt --options h \
    --long help \
    --long filter: \
    --name ${0} -- "$@")

test $? != 0 && __usage__ 1

eval set -- "$TEMP_ARGS"

while true; do
    case $1 in
    --filter)
        shift
        FILTER=$1
        shift
        ;;
    -h | --help)
        shift
        __usage__
        ;;
    --)
        shift
        break
        ;;
    esac
done

echo "===================="
echo "bpftrace --info:"
echo "===================="
"${BPFTRACE_RUNTIME_TEST_EXECUTABLE}" --info;

filter_args=()
[[ -n ${FILTER} ]] && filter_args=( --probe-filter ${FILTER} )

for script in $(find "$TESTS_DIR"/self -type f -a -name \*.bt)
do
    tmplog=$(mktemp)

    "${BPFTRACE_RUNTIME_TEST_EXECUTABLE}" --test "${filter_args[@]}" ${script} 2>&1 | tee "${tmplog}"

    status=${PIPESTATUS[0]}
    if [[ ${status} -ne 0 ]]; then
        if [[ $(grep "No probes to attach" "${tmplog}") ]]; then
            rm -f "${tmplog}"
            continue
        else
            rm -f "${tmplog}"
            exit "${status}"
        fi
    fi

    rm -f "${tmplog}"
done
