FROM alpine:3.8
RUN apk add --update \
  bison \
  build-base \
  clang-dev \
  clang-static \
  cmake \
  elfutils-dev \
  flex-dev \
  git \
  linux-headers \
  llvm5-dev \
  llvm5-static \
  zlib-dev

# Put LLVM directories where CMake expects them to be
RUN ln -s /usr/lib/cmake/llvm5 /usr/lib/cmake/llvm
RUN ln -s /usr/include/llvm5/llvm /usr/include/llvm
RUN ln -s /usr/include/llvm5/llvm-c /usr/include/llvm-c

COPY build.sh /build.sh
ENTRYPOINT ["/bin/sh", "/build.sh"]
