#!/bin/bash
set -e
pushd docker
docker build -t bpftrace-builder-alpine -f Dockerfile.alpine .
popd
