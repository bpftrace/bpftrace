#!/bin/bash
set -eu
export BASE=ubuntu-glibc
export LLVM_VERSION=12
export RUN_TESTS=0
./build-docker-image.sh
docker run --network host --rm -it -u $(id -u):$(id -g) -v $(pwd):$(pwd) -e STATIC_LINKING=ON -e STATIC_LIBC=OFF -e ALLOW_UNSAFE_PROBE=OFF -e VENDOR_GTEST=ON -e RUN_TESTS=${RUN_TESTS} -e EMBED_USE_LLVM=ON bpftrace-builder-${BASE} "$(pwd)/build-static" Release "$@"
