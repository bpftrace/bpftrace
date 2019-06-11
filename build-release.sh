#!/bin/bash

set -x
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
export BUILD_DIR="${BUILD_DIR:-"${DIR}/build-release"}"

./build-common.sh $BUILD_DIR Release $@
