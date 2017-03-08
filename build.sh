#!/bin/sh
pushd docker
docker build -t bpftrace-builder -f Dockerfile.ubuntu .
popd
docker run --rm -u $(id -u):$(id -g) -v $(pwd):/bpftrace bpftrace-builder
