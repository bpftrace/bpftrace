#!/bin/bash
set -e
docker run --rm -it -u $(id -u):$(id -g) -v $(pwd):$(pwd) bpftrace-builder "$(pwd)/build-release" Release "$@"
