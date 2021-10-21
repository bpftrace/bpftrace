#!/bin/bash
set -eu
pushd docker
docker build --network host -t bpftrace-builder-${BASE} --build-arg LLVM_VERSION=${LLVM_VERSION} -f Dockerfile.${BASE} .
popd
