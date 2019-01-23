FROM alpine:3.8
RUN apk add --update \
  bison \
  build-base \
  clang-dev \
  clang-static \
  curl \
  cmake \
  elfutils-dev \
  flex-dev \
  git \
  linux-headers \
  llvm5-dev \
  llvm5-static \
  python \
  zlib-dev

# Put LLVM directories where CMake expects them to be
RUN ln -s /usr/lib/cmake/llvm5 /usr/lib/cmake/llvm
RUN ln -s /usr/include/llvm5/llvm /usr/include/llvm
RUN ln -s /usr/include/llvm5/llvm-c /usr/include/llvm-c

# Alpine currently does not have a package for bcc. Until they do,
# we'll peg the alpine build to bcc v0.8.0
#
# We're building here so docker can cache the build layer
WORKDIR /
RUN curl -L https://github.com/iovisor/bcc/archive/v0.8.0.tar.gz \
  --output /bcc.tar.gz
RUN tar xvf /bcc.tar.gz
RUN mv bcc-0.8.0 bcc
RUN cd /bcc && mkdir build && cd build && cmake .. && make install -j4 && \
  cp src/cc/libbcc.a /usr/local/lib64/libbcc.a && \
  cp src/cc/libbcc-loader-static.a /usr/local/lib64/libbcc-loader-static.a && \
  cp src/cc/libbpf.a /usr/local/lib64/libbpf.a


COPY build.sh /build.sh
ENTRYPOINT ["/bin/sh", "/build.sh"]
