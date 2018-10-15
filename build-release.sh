#!/bin/bash
set -e
docker run --rm -it -u $(id -u):$(id -g) -v $(pwd):$(pwd) -e STATIC_LINKING=ON -e RUN_TESTS=0 bpftrace-builder-alpine "$(pwd)/build-release" Release "$@"
