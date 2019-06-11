#!/bin/bash

set -x
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
DOCKER_BASE="${DOCKER_BASE:-alpine}"

BUILD_FLAGS=""
IMAGE_NAME="bpftrace-builder-$DOCKER_BASE"

if [ "$LLVM_VERSION" != "" ]; then
  BUILD_FLAGS="$BUILD_FLAGS --build-arg LLVM_VERSION=$LLVM_VERSION"
  IMAGE_NAME="${IMAGE_NAME}-llvm-$LLVM_VERSION"
fi;

if [ $DOCKER_FORCE_REBUILD = 1 ]; then
  BUILD_FLAGS="$BUILD_FLAGS --no-cache"
fi

pushd $DIR/docker
docker build $BUILD_FLAGS -t $IMAGE_NAME -f Dockerfile.$DOCKER_BASE .
popd
