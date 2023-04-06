#!/bin/bash

set -e

WARNINGS_AS_ERRORS=${WARNINGS_AS_ERRORS:-OFF}
STATIC_LINKING=${STATIC_LINKING:-OFF}
STATIC_LIBC=${STATIC_LIBC:-OFF}
LLVM_VERSION=${LLVM_VERSION:-8} # default llvm to latest version
EMBED_USE_LLVM=${EMBED_USE_LLVM:-OFF}
EMBED_BUILD_LLVM=${EMBED_BUILD_LLVM:-OFF}
ALLOW_UNSAFE_PROBE=${ALLOW_UNSAFE_PROBE:-OFF}
DEPS_ONLY=${DEPS_ONLY:-OFF}
BUILD_TESTING=${BUILD_TESTING:-ON}
RUN_TESTS=${RUN_TESTS:-1}
RUN_MEMLEAK_TEST=${RUN_MEMLEAK_TEST:-0}
VENDOR_GTEST=${VENDOR_GTEST:-OFF}
CI_TIMEOUT=${CI_TIMEOUT:-0}
CC=${CC:cc}
CXX=${CXX:c++}
ENABLE_SKB_OUTPUT=${ENABLE_SKB_OUTPUT:-ON}
USE_SYSTEM_BPF_BCC=${USE_SYSTEM_BPF_BCC:-OFF}

if [[ $LLVM_VERSION -eq 13 ]]; then 
  touch /usr/lib/llvm-13/bin/llvm-omp-device-info
fi


mkdir -p "$1"
cd "$1"

# Build vendored libraries first
../build-libs.sh

# Build bpftrace
cmake -DCMAKE_BUILD_TYPE="$2" \
      -DWARNINGS_AS_ERRORS:BOOL=$WARNINGS_AS_ERRORS \
      -DSTATIC_LINKING:BOOL=$STATIC_LINKING \
      -DSTATIC_LIBC:BOOL=$STATIC_LIBC \
      -DEMBED_USE_LLVM:BOOL=$EMBED_USE_LLVM \
      -DEMBED_BUILD_LLVM:BOOL=$EMBED_BUILD_LLVM \
      -DEMBED_LLVM_VERSION=$LLVM_VERSION \
      -DALLOW_UNSAFE_PROBE:BOOL=$ALLOW_UNSAFE_PROBE \
      -DVENDOR_GTEST=$VENDOR_GTEST \
      -DBUILD_ASAN:BOOL=$RUN_MEMLEAK_TEST \
      -DBUILD_TESTING:BOOL=$BUILD_TESTING \
      -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
      -DENABLE_SKB_OUTPUT:BOOL=$ENABLE_SKB_OUTPUT \
      -DUSE_SYSTEM_BPF_BCC:BOOL=$USE_SYSTEM_BPF_BCC \
      "${CMAKE_EXTRA_FLAGS}" \
      ../
shift 2

# It is necessary to build embedded llvm and clang targets first,
# so that their headers can be referenced
[[ $DEPS_ONLY == "ON" ]] && exit 0
make "$@" -j $(nproc)

if [ $RUN_TESTS = 1 ]; then
  if [ "$RUN_ALL_TESTS" = "1" ]; then
    ctest -V --exclude-regex "$TEST_GROUPS_DISABLE"
  else
    ./tests/bpftrace_test $TEST_ARGS;
  fi
fi

# Memleak tests require bpftrace built with -fsanitize=address so it cannot be
# usually run with unit/runtime tests (RUN_TESTS should be set to 0). 
if [ $RUN_MEMLEAK_TEST = 1 ]; then
  ./tests/memleak-tests.sh
fi
