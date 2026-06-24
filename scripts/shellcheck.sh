#!/usr/bin/env bash

# Runs shellcheck against the codebase.
# Requires nix.
#
# Example usage:
#
#     ./scripts/shellcheck.sh
#

set -eu
shopt -s globstar

SCRIPT_NAME=$0

function run() {
  nix develop --command "$@"
}

usage() {
  echo "Usage:"
  echo "    ${SCRIPT_NAME} [OPTIONS]"
  echo ""
  echo " Run shellcheck for all '.sh' files with nix."
}

while getopts ":h" opt; do
case "${opt}" in
    h )
        usage
        exit 0
        ;;
    * )
        echo "Unknown option ${opt}"
        exit 1
        ;;
esac
done

# Change dir to project root.
cd "$(git rev-parse --show-toplevel)"

# Run shellcheck on all bpftrace shell scripts (excluding the libbpf submodule).
run find .github scripts tests -path './libbpf' -prune -o -name '*.sh' -exec shellcheck {} \;
