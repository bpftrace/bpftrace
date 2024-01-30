#!/bin/bash

# Runs clang-tidy against the codebase.
# Requires nix.
#
# Example usage:
#
#     ./scripts/clang_tidy.sh
#

set -eu
shopt -s globstar

BUILD_DIR=build-clang-tidy
SCRIPT_NAME=$0
FIX=

function run() {
  nix develop --command "$@"
}

usage() {
  echo "Usage:"
  echo "    ${SCRIPT_NAME} [OPTIONS]"
  echo ""
  echo " Run clang-tidy and optional apply fixes with nix."
  echo ""
  echo "OPTIONS"
  echo "    -u               Update with fixes."
  echo "    -d <BUILD_DIR>   Change the default build directory. Default: ${BUILD_DIR}"
}

while getopts ":d:uh" opt; do
case ${opt} in
    u )
        FIX=-fix
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

# Clang-tidy has native integration with compile_commands.json.
# Generate it here so that we can teach clang-tidy how to "build" bpftrace.
run cmake -B "$BUILD_DIR" -DCMAKE_EXPORT_COMPILE_COMMANDS=1

# We also generate header files here and there. Rather than hard
# code which files are generated, just build the entire project
# to keep it simple.
run make -C "$BUILD_DIR" -j $(nproc)

# Note that `run-clang-tidy` comes from `clang` nix package but shells out to
# `clang-tidy` and `clang-apply-replacements` from `clang-tools` nix package.
# This may just be trivia but seems like a good gotcha to point out.
#
# Also note we explicitly pass in the files we want to lint. We could
# omit the file list but then generated files from flex/bison will start
# spewing.
#
# Also note $FIX is supposed to be unquoted. The problem is if it's quoted
# and unset, then it's an empty arg and run-clang-tidy will treat it as
# an empty regex which causes all sorts of trouble.
run run-clang-tidy -q -format -config-file .clang-tidy -p "$BUILD_DIR" $FIX \
  '^.*(src|tests)/.*\.(h|cpp)$'
