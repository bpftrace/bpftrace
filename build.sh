#!/bin/bash
set -x
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $DIR
BUILD_TYPE="${BUILD_TYPE:-release}"

./build-docker-image.sh
./build-${BUILD_TYPE}.sh "$@"
popd
