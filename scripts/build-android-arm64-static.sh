#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_DIR=${BUILD_DIR:-"$ROOT/build-android-arm64-static"}
DEPS_PREFIX=${DEPS_PREFIX:-"$HOME/android/tool/ExtendedAndroidTools/out/android/arm64"}
LLVM_PREFIX=${LLVM_PREFIX:-"$HOME/android/tool/ExtendedAndroidTools/build/android/arm64/llvm"}
ANDROID_NDK=${ANDROID_NDK:-/opt/ndk/android-ndk-r27b}
ANDROID_ABI=${ANDROID_ABI:-arm64-v8a}
ANDROID_PLATFORM=${ANDROID_PLATFORM:-android-30}
LLVM_BIN="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
SYSROOT="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
ANDROID_LIB="$SYSROOT/usr/lib/aarch64-linux-android/30"

test -d "$DEPS_PREFIX"
test -f "$LLVM_PREFIX/lib/libclang.a"
test -f "$DEPS_PREFIX/lib/libbcc.a"
test -f "$DEPS_PREFIX/lib/libbcc_bpf.a"
test -f "$DEPS_PREFIX/lib/libbcc-loader-static.a"
test -f "$DEPS_PREFIX/lib/libbpf.a"
test -f "$DEPS_PREFIX/lib/libdw.a"
test -f "$DEPS_PREFIX/lib/libelf.a"
test -f "$DEPS_PREFIX/lib/liblzma.a"

mkdir -p "$BUILD_DIR"

if [[ -n "${LIBBZ2_LIBRARIES:-}" ]]; then
  BZ2_LIBRARIES=$LIBBZ2_LIBRARIES
else
  BZ2_LIBRARIES="$BUILD_DIR/libempty-bz2.a"
  "$LLVM_BIN/llvm-ar" rc "$BZ2_LIBRARIES"
fi

cmake -S "$ROOT" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI="$ANDROID_ABI" \
  -DANDROID_PLATFORM="$ANDROID_PLATFORM" \
  -DANDROID_STL=c++_static \
  -DSTATIC_LINKING=ON \
  -DBUILD_TESTING=OFF \
  -DENABLE_MAN=OFF \
  -DENABLE_SYSTEMD=OFF \
  -DUSE_SYSTEM_LIBBPF=ON \
  -DCMAKE_PREFIX_PATH="$DEPS_PREFIX" \
  -DCMAKE_FIND_ROOT_PATH="$DEPS_PREFIX" \
  -DLIBBCC_INCLUDE_DIRS="$DEPS_PREFIX/include" \
  -DLIBBCC_LIBRARIES="$DEPS_PREFIX/lib/libbcc.a" \
  -DLIBBCC_BPF_LIBRARIES="$DEPS_PREFIX/lib/libbcc_bpf.a" \
  -DLIBBCC_LOADER_LIBRARY_STATIC="$DEPS_PREFIX/lib/libbcc-loader-static.a" \
  -DLIBBPF_INCLUDE_DIRS="$DEPS_PREFIX/include" \
  -DLIBBPF_LIBRARIES="$DEPS_PREFIX/lib/libbpf.a" \
  -DLIBDW_INCLUDE_DIRS="$DEPS_PREFIX/include/elfutils" \
  -DLIBDW_LIBRARIES="$DEPS_PREFIX/lib/libdw.a" \
  -DLIBELF_INCLUDE_DIRS="$DEPS_PREFIX/include" \
  -DLIBELF_LIBRARIES="$DEPS_PREFIX/lib/libelf.a" \
  -DLIBBZ2_LIBRARIES="$BZ2_LIBRARIES" \
  -DLLVM_DIR="$LLVM_PREFIX/lib/cmake/llvm" \
  -DClang_DIR="$LLVM_PREFIX/lib/cmake/clang" \
  -DLIBCEREAL_INCLUDE_DIRS="$DEPS_PREFIX/include" \
  -DZLIB_LIBRARY_RELEASE="$ANDROID_LIB/libz.so" \
  -DZLIB_INCLUDE_DIR="$SYSROOT/usr/include"

cmake --build "$BUILD_DIR" -j4

OUTPUT="$BUILD_DIR/src/bpftrace"
file "$OUTPUT"
readelf -h "$OUTPUT" | grep -E 'Class:|Machine:'
readelf -d "$OUTPUT" | grep 'NEEDED' || true
printf '%s\n' "$OUTPUT"
