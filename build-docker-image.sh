#!/bin/bash
set -e
pushd docker
docker build --network host -t bpftrace-builder-alpine -f Dockerfile.alpine .
popd
