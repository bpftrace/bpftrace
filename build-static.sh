#!/bin/bash
set -eu
export BASE=ubuntu-glibc
export LLVM_VERSION=12
export RUN_TESTS=0
export BUILD_TESTING=OFF
./build-docker-image.sh
docker run --network host --rm -u $(id -u):$(id -g) -v $(pwd):$(pwd) -e STATIC_LINKING=ON -e STATIC_LIBC=OFF -e ALLOW_UNSAFE_PROBE=OFF -e VENDOR_GTEST=ON -e BUILD_TESTING=${BUILD_TESTING} -e RUN_TESTS=${RUN_TESTS} -e EMBED_USE_LLVM=ON bpftrace-builder-${BASE} "$(pwd)/build-static" Release "$@"
