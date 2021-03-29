#!/bin/bash

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

curl -L --output /tmp/cmake.tar.gz \
  https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0-linux-x86_64.tar.gz

tar -xf /tmp/cmake.tar.gz -C /usr/local/

mkdir embedded_build
pushd embedded_build >/dev/null
/usr/local/cmake-3.20.0-linux-x86_64/bin/cmake -S /bpftrace/docker/llvm -DEMBED_LLVM=1 -DEMBED_CLANG=1 -DLLVM_VERSION=12
with_timeout make embedded_llvm "$@"
with_timeout make embedded_clang "$@"
popd >/dev/null


# build bcc
mkdir -p /src
git clone https://github.com/$bcc_org/bcc /src/bcc
cd /src/bcc
git checkout $bcc_ref
git submodule update
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ../
make -j$(nproc)
make install
mkdir -p /usr/local/lib
cp src/cc/libbcc.a /usr/local/lib/libbcc.a
cp src/cc/libbcc-loader-static.a /usr/local/lib/libbcc-loader-static.a
cp ./src/cc/libbcc_bpf.a /usr/local/lib/libbpf.a
cp ./src/cc/libbcc_bpf.a /usr/local/lib/libbcc_bpf.a

/build.sh "$@"
