#!/bin/bash
set -x
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

DOCKER_FLAGS="--rm -it  -u $(id -u):$(id -g) -e REPOSITORY=$DIR"
DOCKER_VOLUMES="-v $DIR:$DIR"

DOCKER_BASE="${DOCKER_BASE:-alpine}"
IMAGE_NAME="bpftrace-builder-$DOCKER_BASE"

if [ "$LLVM_VERSION" != "" ]; then
  BUILD_FLAGS="$BUILD_FLAGS --build-arg LLVM_VERSION=$LLVM_VERSION"
  IMAGE_NAME="${IMAGE_NAME}-llvm-$LLVM_VERSION"
fi;

if [ ! -z "$STATIC_LINKING" ]; then
 DOCKER_FLAGS="$DOCKER_FLAGS  -e STATIC_LINKING=$STATIC_LINKING"
elif [ "$DOCKER_BASE" == "alpine" ]; then
 DOCKER_FLAGS="$DOCKER_FLAGS  -e STATIC_LINKING=ON"
fi

if [ ! -z "$RUN_TESTS" ] || [ ! -z "$RUN_ALL_TESTS" ]; then
  DOCKER_FLAGS="$DOCKER_FLAGS --privileged -e RUN_TESTS=$RUN_TESTS"
  DOCKER_VOLUMES="$DOCKER_VOLUMES -v /sys/kernel/debug:/sys/kernel/debug:rw"
fi

if [ ! -z "$TEST_ARGS" ]; then
  DOCKER_FLAGS="$DOCKER_FLAGS -e TEST_ARGS=$TEST_ARGS"
fi

if [ ! -z "$RUN_ALL_TESTS" ]; then
  DOCKER_FLAGS="$DOCKER_FLAGS -e RUN_ALL_TESTS=$RUN_ALL_TESTS"
  DOCKER_VOLUMES="$DOCKER_VOLUMES -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro "
fi

docker run $DOCKER_FLAGS $DOCKER_VOLUMES $IMAGE_NAME "$@"
