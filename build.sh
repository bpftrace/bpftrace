#!/bin/bash
pushd docker
docker build -t bpftrace-builder -f Dockerfile.ubuntu .
popd
docker run --rm -u $(id -u):$(id -g) -v $(pwd):$(pwd) bpftrace-builder "$(pwd)"
