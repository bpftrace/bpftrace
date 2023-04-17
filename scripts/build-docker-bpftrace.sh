#! /usr/bin/env bash

docker buildx build -t ghcr.io/iovisor/bpftrace --platform=linux/arm64,linux/amd64 -f docker/Dockerfile.cross .
