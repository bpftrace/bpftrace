#!/bin/bash

set -e

WARNINGS_AS_ERRORS=${WARNINGS_AS_ERRORS:-OFF}
STATIC_LINKING=${STATIC_LINKING:-OFF}
STATIC_LIBC=${STATIC_LIBC:-OFF}
LLVM_VERSION=${LLVM_VERSION:-8} # default llvm to latest version
EMBED_LLVM=${EMBED_LLVM:-OFF}
EMBED_CLANG=${EMBED_CLANG:-OFF}
EMBED_LIBCLANG_ONLY=${EMBED_LIBCLANG_ONLY:-OFF}
EMBED_BCC=${EMBED_BCC:-OFF}
EMBED_LIBELF=${EMBED_LIBELF:-OFF}
EMBED_BINUTILS=${EMBED_BINUTILS:-OFF}
ANDROID_ABI=${ANDROID_ABI:-""}
DEPS_ONLY=${DEPS_ONLY:-OFF}
RUN_TESTS=${RUN_TESTS:-1}
CI_TIMEOUT=${CI_TIMEOUT:-0}

# If running on Travis, we may need several builds incrementally building up
# the cache in order to cold-start the build cache within the 50 minute travis
# job timeout. The gist is to kill the job safely and save the cache and run
# again until the build cache is fully warmed
with_timeout()
{
  if [[ $CI_TIMEOUT -gt 0 ]];then
    set +e
    [[ -z $CI_TIME_REMAINING ]] && CI_TIME_REMAINING=$CI_TIMEOUT
    start_time="$(date -u +%s)"
    timeout $CI_TIME_REMAINING $@
    rc=$?
    end_time="$(date -u +%s)"
    elapsed="$(($end_time-$start_time))"
    CI_TIME_REMAINING=$((CI_TIME_REMAINING-elapsed))
    echo "{$CI_TIME_REMAINING}s remains for other jobs"

    if [[ $rc -eq 124 ]];then
      echo "Exiting early on timeout to upload cache and retry..."
      echo "This is expected on a cold cache / new LLVM release."
      echo "Retry the build until it passes, so long as it progresses."
      echo "see docs/embedded_builds.md for more info"
      exit 0
    elif [[ $rc -ne 0 ]];then
      exit $rc # preserve set -e behavior on non-timeout
    fi
    set -e # resume set -e
  else
    $@
  fi
}

# Build bpftrace
mkdir -p "$1"
cd "$1"

if [[ -n "$ANDROID_ABI"  ]];then
  # https://developer.android.com/ndk/guides/abis
  # Valid ABIS are:
  # - armeabi-v7a
  # - arm64-v8a
  # - x86_64
  cmake_extra_flags="-DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
                     -DANDROID_ABI=${ANDROID_ABI} -DANDROID_NATIVE_API_LEVEL=28"
else
  cmake_extra_flags=""
fi

# FIXME build the embed string separately, like is done for android, this is
# getting out of hand
cmake -DCMAKE_BUILD_TYPE="$2" -DWARNINGS_AS_ERRORS:BOOL=$WARNINGS_AS_ERRORS \
      -DSTATIC_LINKING:BOOL=$STATIC_LINKING -DSTATIC_LIBC:BOOL=$STATIC_LIBC \
      -DEMBED_LLVM:BOOL=$EMBED_LLVM -DEMBED_CLANG:BOOL=$EMBED_CLANG \
      -DEMBED_LIBCLANG_ONLY:BOOL=$EMBED_LIBCLANG_ONLY \
      -DEMBED_BCC:BOOL=$EMBED_BCC -DEMBED_LIBELF:BOOL=$EMBED_LIBELF \
      -DEMBED_BINUTILS=$EMBED_BINUTILS \
       ${cmake_extra_flags} \
      -DLLVM_VERSION=$LLVM_VERSION  ../
shift 2

# It is necessary to build embedded llvm and clang targets first,
# so that their headers can be referenced
[[ $EMBED_LLVM  == "ON" ]] && with_timeout make embedded_llvm -j`nproc`
[[ $EMBED_CLANG == "ON" ]] && with_timeout make embedded_clang -j`nproc`
[[ $EMBED_BCC == "ON" ]] && with_timeout make embedded_bcc -j`nproc`
[[ $EMBED_BINUTILS == "ON" ]] && with_timeout make embedded_binutils -j`nproc`
[[ $DEPS_ONLY == "ON" ]] && exit 0
make "$@"

if [ $RUN_TESTS = 1 ]; then
  if [ "$RUN_ALL_TESTS" = "1" ]; then
    ctest -V
  else
    ./tests/bpftrace_test $TEST_ARGS;
  fi
fi
