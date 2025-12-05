#!/usr/bin/env bash

# Runs bpftrace --fmt against the codebase.
# Requires nix.
#
# Example usage:
#
#     ./scripts/bpftrace_tidy.sh
#

set -eu
shopt -s globstar

BUILD_DIR=build-bpftrace-tidy
SCRIPT_NAME=$0
FIX=

function run() {
  nix develop --command "$@"
}

usage() {
  echo "Usage:"
  echo "    ${SCRIPT_NAME} [OPTIONS]"
  echo ""
  echo " Run `bpftrace --fmt` for all `.bt` files with nix."
  echo ""
  echo "OPTIONS"
  echo "    -d <BUILD_DIR>   Change the default build directory. Default: ${BUILD_DIR}"
}

while getopts ":d:uh" opt; do
case ${opt} in
    d )
        BUILD_DIR=${OPTARG}
        ;;
    h )
        usage
        exit 0
        ;;
esac
done

# Change dir to project root, and build bpftrace.
cd "$(git rev-parse --show-toplevel)"
run cmake -B "$BUILD_DIR"
run make -C "$BUILD_DIR" -j $(nproc)

# Run the formatter on all files.
run find src tests tools -name '*.bt' -exec "$BUILD_DIR/src/bpftrace" --fmt {} -o {} \;
