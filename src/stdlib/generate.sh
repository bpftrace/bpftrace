#!/bin/bash

set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <name> <files...>"
  exit 1
fi

cat <<EOF
#include "stdlib/stdlib.h"

namespace bpftrace::stdlib {
EOF

declare name=$1
shift
declare count=0
for arg; do
  # It may be problematic to have null bytes embedded inside the C file, so we
  # need to ensure that we are using the fully escape string.
  echo "const static char data_${count}[] = "
  python - <<EOF
f = open("${arg}", "rb");
s = "".join(["\\\\x%02x" % x for x in f.read()])
for p in [s[i:min(i+76, len(s))] for i in range(0, len(s), 76)]:
  print("  \"" + p + "\"")
EOF
  echo ";"
  echo "static auto &u_${count} = Unit::add(\"${name}\", data_${count}, sizeof(data_${count}));";
  count=$(($count+1))
done

cat <<EOF
} // namespace bpftrace::stdlib
EOF
