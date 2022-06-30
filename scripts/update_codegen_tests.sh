#!/bin/bash

# Updates codegen tests' expected LLVM IR
#

set -eu

# Change dir to project root
cd "$(dirname "${BASH_SOURCE[0]}")"
cd ..

# Build docker image
pushd docker
docker build                  \
  --network host              \
  --build-arg LLVM_VERSION=12 \
  -t bpftrace-builder-focal   \
  -f Dockerfile.focal         \
  .
popd

# Update IR
docker run                                \
  --network host                          \
  --rm                                    \
  -it                                     \
  -v $(pwd):$(pwd)                        \
  -e BPFTRACE_UPDATE_TESTS=1              \
  -e TEST_ARGS="--gtest_filter=codegen.*" \
  -e VENDOR_GTEST="ON"                    \
  -e BUILD_LIBBPF="ON"                    \
  bpftrace-builder-focal "$(pwd)/build-codegen-update" Debug "$@"
