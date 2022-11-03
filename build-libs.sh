#!/bin/bash

set -o pipefail
set -ex

BPFTRACE_DIR=$(dirname $(realpath "$0"))
DESTDIR="${PWD}/build-libs"
mkdir -p "$DESTDIR"

# If CC is empty (as it is in some CI environments),
# look for gcc or clang instead.
if [[ ! "$CC" ]]; then
  if [[ "$(which gcc)" ]]; then
    CC=gcc
  elif [[ "$(which clang)" ]]; then
    CC=clang
  else
    CC="${CXX}"
  fi
fi

# Build libbpf first

make -C "${BPFTRACE_DIR}/libbpf/src" -j$(nproc) \
  CC="${CC}" \
  OBJDIR="${DESTDIR}" PREFIX="${DESTDIR}" \
  install install_uapi_headers

# Build bcc against the libbpf we just built

mkdir -p "${DESTDIR}/bcc"
cd "${DESTDIR}/bcc"

# Generate and install in two separate steps.
# By default, the install make target will try to install
# the C++ examples as well. Unfortunately, those don't all
# compile against musl/alpine, and it tries to compile them
# even with INSTALL_CPP_EXAMPLES=OFF.
#
# This very precise setup saves build time and works on alpine.

# This logic conceptually matches libbpf's Makefile, so
# libbpf and libbcc end up in the same folder.
if [[ "$(uname -m)" =~ .*(64|s390x).* ]]; then
  INSTALL_LIBDIR=lib64
else
  INSTALL_LIBDIR=lib
fi

BCC_CMAKE_PARAMS="-DCMAKE_INSTALL_PREFIX='${DESTDIR}' \
    -DCMAKE_PREFIX_PATH='${DESTDIR}' \
    -DCMAKE_USE_LIBBPF_PACKAGE=ON \
    -DCMAKE_INSTALL_LIBDIR=${INSTALL_LIBDIR} \
    -DENABLE_MAN=0 \
    -DENABLE_EXAMPLES=0 \
    -DENABLE_TESTS=0 \
    -DENABLE_LIBDEBUGINFOD=0 \
    -DLUAJIT= \
    -DENABLE_LLVM_NATIVECODEGEN=0"

cmake \
    ${BCC_CMAKE_PARAMS} \
    "${BPFTRACE_DIR}/bcc"

make -j$(nproc) \
  clang_frontend api-static bcc-loader-static bcc-shared bcc-static \
  bpf-shared bpf-static bps

cmake \
    ${BCC_CMAKE_PARAMS} \
    -P cmake_install.cmake
