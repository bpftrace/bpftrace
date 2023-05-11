#! /usr/bin/env bash

docker buildx build --push -t ghcr.io/iovisor/llvm --platform=linux/arm64,linux/amd64 -f docker/Dockerfile.llvm-cross .
