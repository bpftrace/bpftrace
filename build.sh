#!/bin/bash
set -e
export BASE=focal
export LLVM_VERSION=12
export RUN_TESTS=1
./build-docker-image.sh
./build-release.sh "$@"
