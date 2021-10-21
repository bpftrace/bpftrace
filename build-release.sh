#!/bin/bash
set -eu
docker run --network host --rm -it -u $(id -u):$(id -g) -v $(pwd):$(pwd) -e STATIC_LINKING=OFF -e STATIC_LIBC=OFF -e ALLOW_UNSAFE_PROBE=OFF -e VENDOR_GTEST=ON -e RUN_TESTS=${RUN_TESTS} bpftrace-builder-${BASE} "$(pwd)/build-release-${BASE}" Release "$@"
