#!/usr/bin/env bash

# Updates generated files in the codebase.
# Requires nix.
#
# Example usage:
#
#     ./scripts/update_genfiles.sh
#

set -eu
shopt -s globstar

BUILD_DIR=build-genfiles
SCRIPT_NAME=$0
FIX=false

function run() {
  nix develop --command "$@"
}

function find_genfiles() {
  grep --with-filename -r -E '^// automatically generated: do not edit' "$@" | cut -d':' -f1 | uniq
}

usage() {
  echo "Usage:"
  echo "    ${SCRIPT_NAME} [OPTIONS]"
  echo ""
  echo " Update all generated header files with nix."
  echo ""
  echo "OPTIONS"
  echo "    -u               Update with fixes."
  echo "    -d <BUILD_DIR>   Change the default build directory. Default: ${BUILD_DIR}"
}

while getopts ":d:uh" opt; do
case ${opt} in
    u )
        FIX=true
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

# Change dir to project root.
cd "$(git rev-parse --show-toplevel)"

# Generate all the build directory.
run cmake -B "$BUILD_DIR"

# Generate all the relevant header files.
run make -C "$BUILD_DIR" -j $(nproc) genfiles

# Copy all generated files.
DIFFERENT=0
for file in $(find_genfiles src tests); do
  if [[ "$FIX" == "true" ]]; then
    rm -f "$file"
  else
    if ! [[ -f "$BUILD_DIR/$file" ]]; then
      echo "$file is no longer generated."
      DIFFERENT=$(($DIFFERENT+1))
    fi
  fi
done
for file in $(cd "$BUILD_DIR" && find_genfiles src tests); do
  if [[ "$FIX" == "true" ]]; then
    cp -a "$BUILD_DIR/$file" "$file"
  else
    if ! [[ -f "$file" ]]; then
      echo "$file is missing."
      DIFFERENT=$(($DIFFERENT+1))
    else
      if ! diff "$BUILD_DIR/$file" "$file" > /dev/null; then
        echo "$file has differences:"
        diff -u2 "$BUILD_DIR/$file" "$file" || true
        DIFFERENT=$(($DIFFERENT+1))
      fi
    fi
  fi
done

# Check to see if we need to fail.
if [[ "$DIFFERENT" -ne "0" ]]; then
  echo "$DIFFERENT files are different, run \`$SCRIPT_NAME -u\`."
  exit 1
fi
