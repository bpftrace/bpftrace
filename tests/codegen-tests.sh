#!/bin/bash

# Runs or updates codegen tests' expected LLVM IR
# requires nix
#
# Example usage:
#
#     ./tests/codegen-tests.sh
#

set -eu

BUILD_DIR=build-codegen-update
UPDATE_TESTS=${BPFTRACE_UPDATE_TESTS:-0}
SCRIPT_NAME=$0

function run() {
  nix develop .#bpftrace-llvm12 --command "$@"
}

usage() {
  echo "Usage:"
  echo "    ${SCRIPT_NAME} [OPTIONS]"
  echo ""
  echo " Run or update the codegen tests with nix."
  echo ""
  echo "OPTIONS"
  echo "    -u      Update the tests."
  echo "    -d <BUILD_DIR>   Change the default build directory. Default: ${BUILD_DIR}"
}

while getopts ":d:uh" opt; do
case ${opt} in
    u )
        UPDATE_TESTS=1
        ;;
    d )
        BUILD_DIR=${OPTARG}
        ;;
    h )
        usage
        exit 0
        ;;
esac
done

# Change dir to project root
cd "$(git rev-parse --show-toplevel)"

run cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug -DUSE_SYSTEM_BPF_BCC=1
run make -C "$BUILD_DIR" -j $(nproc)
BPFTRACE_UPDATE_TESTS=${UPDATE_TESTS} run ./"$BUILD_DIR"/tests/bpftrace_test --gtest_filter="codegen*"
