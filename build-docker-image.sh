#!/bin/bash
set -e
pushd docker
docker build -t bpftrace-builder -f Dockerfile.alpine .
popd
