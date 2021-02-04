#!/bin/bash
set -e
docker run --network host --rm -it -u $(id -u):$(id -g) -v $(pwd):$(pwd) -e STATIC_LINKING=ON -e STATIC_LIBC=ON -e ALLOW_UNSAFE_PROBE=OFF -e RUN_TESTS=0 bpftrace-builder-alpine "$(pwd)/build-release" Release "$@"
