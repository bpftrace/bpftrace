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
TMPLOG=

__usage__()
{
    echo -e "
self-test.sh [-h|--help] [--filter=<PATTERN>]

    -h, --help           show this information.
    --filter=[PATTERN]   only run the tests matching this pattern.
"
    exit ${1-0}
}

if ! TEMP_ARGS=$(getopt --options h \
                        --long help \
                        --long filter: \
                        --name "${0}" -- "$@")
then
    __usage__ 1
fi

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

cleanup()
{
    # Prevent leftover temporary files caused by abnormal exits.
    rm -f ${TMPLOG}
}
trap cleanup EXIT

echo "===================="
echo "bpftrace --info:"
echo "===================="
"${BPFTRACE_RUNTIME_TEST_EXECUTABLE}" --info;

filter_matched_count=0
filter_args=()
[[ -n ${FILTER} ]] && filter_args=( --probe-filter "${FILTER}" )

while IFS= read -r -d '' script; do
    TMPLOG=$(mktemp)

    "${BPFTRACE_RUNTIME_TEST_EXECUTABLE}" --test "${filter_args[@]}" "${script}" | tee "${TMPLOG}"

    status=${PIPESTATUS[0]}
    if [[ ${status} -ne 0 ]]; then
        if [[ -n ${FILTER} ]]; then
            if grep -q "^No probes to attach$" "${TMPLOG}"; then
                rm -f "${TMPLOG}"
                continue
            fi
        fi

        rm -f "${TMPLOG}"
        exit "${status}"
    fi

    filter_matched_count=$(( filter_matched_count + 1 ))
    rm -f "${TMPLOG}"
done < <(find "$TESTS_DIR"/self -type f -a -name \*.bt -print0)

if [[ ${filter_matched_count} -eq 0 ]] && [[ -n ${FILTER} ]]; then
   echo >&2 "ERROR: Not match any probe with filter '${FILTER}'"
   exit 2 # ENOENT
fi
