#!/bin/bash
#
# This script is the entrypoint for the static build.
#
# To make CI errors easier to reproduce locally, please limit
# this script to using only git, docker, and coreutils.

set -eux

IMAGE=bpftrace-static
cd $(git rev-parse --show-toplevel)

# Build the base image
docker build -t "$IMAGE" -f docker/Dockerfile.static docker/

# Perform bpftrace static build
docker run -v $(pwd):$(pwd) -w $(pwd) -i "$IMAGE" <<'EOF'
set -eux
BUILD_DIR=build-static
cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_VERBOSE_MAKEFILE=ON -DBUILD_TESTING=OFF -DSTATIC_LINKING=ON
make -C "$BUILD_DIR" -j$(nproc)

# Basic smoke test
./"$BUILD_DIR"/src/bpftrace --help

# Validate that it's a mostly static binary except for libc
EXPECTED="/lib/ld-musl-x86_64.so.1\nlibc.musl-x86_64.so.1"
GOT=$(ldd "$BUILD_DIR"/src/bpftrace | awk '{print $1}')
if ! diff <(echo -e "$EXPECTED") <(echo "$GOT"); then
  set +x
  >&2 echo "bpftrace incorrectly linked"
  exit 1
fi
EOF
