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
RUN_TESTS=${RUN_TESTS:-1}
VENDOR_GTEST=${VENDOR_GTEST:-OFF}
CI_TIMEOUT=${CI_TIMEOUT:-0}
BUILD_LIBBPF=${BUILD_LIBBPF:-OFF}
CC=${CC:cc}
CXX=${CXX:c++}

if [[ $BUILD_LIBBPF = ON ]]; then
  mkdir /src
  git clone https://github.com/libbpf/libbpf.git /src/libbpf
  cd /src/libbpf/src
  CC=gcc make -j$(nproc)
  # libbpf defaults to /usr/lib64 which doesn't work on debian like systems
  # this should work on both
  PREFIX=/usr/local/ LIBDIR=/usr/local/lib make install install_uapi_headers
fi

# Build bpftrace
mkdir -p "$1"
cd "$1"
cmake -DCMAKE_BUILD_TYPE="$2" \
      -DWARNINGS_AS_ERRORS:BOOL=$WARNINGS_AS_ERRORS \
      -DSTATIC_LINKING:BOOL=$STATIC_LINKING \
      -DSTATIC_LIBC:BOOL=$STATIC_LIBC \
      -DEMBED_USE_LLVM:BOOL=$EMBED_USE_LLVM \
      -DEMBED_BUILD_LLVM:BOOL=$EMBED_BUILD_LLVM \
      -DEMBED_LLVM_VERSION=$LLVM_VERSION \
      -DALLOW_UNSAFE_PROBE:BOOL=$ALLOW_UNSAFE_PROBE \
      -DVENDOR_GTEST=$VENDOR_GTEST \
      -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
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
