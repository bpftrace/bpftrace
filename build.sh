#!/bin/bash
set -e
./build-docker-image.sh
./build-release.sh "$@"
