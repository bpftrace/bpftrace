#!/bin/bash

## Don't add to this
EXIT=0
LLVM_VERSION=12

if ! LLVM=$(command -v "llvm-as-${LLVM_VERSION}" || command -v llvm-as); then
  echo "llvm-as not found, exiting"
  exit 1
fi

if ! $LLVM --version | grep -q "LLVM version ${LLVM_VERSION}"; then
  echo "llvm-as is not version ${LLVM_VERSION}"
fi

if [[ -z "$1" ]]; then
  echo "Usage: $0 <source dir>"
  exit 1
fi

for file in "${1}"/tests/codegen/llvm/*.ll; do
    if $LLVM -o /dev/null "${file}"; then
      echo -e "[   OK   ]\t$file"
    else
      echo -e "[ FAILED ]\t$file"
      EXIT=1
    fi
done

exit $EXIT
