#!/bin/bash
set -e
export BASE=bionic
export LLVM_VERSION=12
export RUN_TESTS=1
./build-docker-image.sh
./build-release.sh "$@"
