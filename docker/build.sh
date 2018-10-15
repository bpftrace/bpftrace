set -e

STATIC_LINKING=${STATIC_LINKING:-OFF}
RUN_TESTS=${RUN_TESTS:-1}

mkdir -p "$1"
cd "$1"
cmake -DCMAKE_BUILD_TYPE="$2" -DSTATIC_LINKING:BOOL=$STATIC_LINKING ../
shift 2
make "$@"

if [ $RUN_TESTS = 1 ]; then
  ./tests/bpftrace_test $TEST_ARGS
fi
