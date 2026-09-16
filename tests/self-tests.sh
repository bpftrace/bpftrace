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
self-tests.sh [-h|--help] [--filter=<PATTERN>]

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
    __usage__ 1 >&2
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
        if [[ $# -ne 0 ]]; then
            echo >&2 "Arguments '${@}' following '--' are not supported"
            exit 1
        fi
        break
        ;;
    *)
        __usage__ 1 >&2
        ;;
    esac
done

echo "===================="
echo "bpftrace --info:"
echo "===================="
"${BPFTRACE_RUNTIME_TEST_EXECUTABLE}" --info;

filter_matched_count=0
filter_args=()
[[ -n ${FILTER} ]] && filter_args=( --probe-filter "${FILTER}" )

tmplog=$(mktemp)
# Prevent leftover temporary files caused by abnormal exits.
trap 'rm -f "${tmplog}"' EXIT

rc=0
while IFS= read -r -d '' script; do
    "${BPFTRACE_RUNTIME_TEST_EXECUTABLE}" --test "${filter_args[@]}" "${script}" | tee "${tmplog}"

    status=${PIPESTATUS[0]}
    if [[ ${status} -ne 0 ]]; then
        if [[ -n ${FILTER} ]] && grep -q "^No probes to attach$" "${tmplog}"; then
                continue
        fi
        rc=${status}
    fi

    filter_matched_count=$(( filter_matched_count + 1 ))
done < <(find "$TESTS_DIR"/self -type f -a -name \*.bt -print0)

if [[ ${filter_matched_count} -eq 0 ]] && [[ -n ${FILTER} ]]; then
    echo >&2 "No probes matched filter '${FILTER}'"
    exit 2
fi

exit "${rc}"
