#!/bin/bash

# Updates codegen tests' expected LLVM IR
#
# Example usage:
#
#     ./scripts/update_codegen_tests.sh
#

set -eu

BUILD_DIR=build-codegen-update

function run() {
  nix develop .#bpftrace-llvm12 --command "$@"
}

# Change dir to project root
cd "$(git rev-parse --show-toplevel)"

run cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug -DUSE_SYSTEM_BPF_BCC=1
run make -C "$BUILD_DIR" -j $(nproc)
BPFTRACE_UPDATE_TESTS=1 run ./"$BUILD_DIR"/tests/bpftrace_test --gtest_filter="codegen*"
