#!/usr/bin/env bash

# Syncs headers from a local kernel repository.
#
# This script attempts to find the transitive closure over the C headers that
# are generally needed for BPF programs. This is not an easy task: headers can
# include other headers based on `#define`s (e.g. whether `__KERNEL__` is set)
# and these defines are often set for BPF programs, and headers can include
# different headers depend on the architecture. This script is fundamentally
# fragile, and contains hacks in an attempt to do the right thing. This script
# should improve over time as these special cases are identified, and as our
# requirements for C interop generally become less ambiguous.
#
# Please include the kernel commit used when checking in new synced headers.
#
# Example usage:
#
#     ./scripts/sync_headers.sh ~/my-linux-repo
#

set -eu
shopt -s globstar

SCRIPT_NAME=$0

usage() {
  echo "Usage:"
  echo "    ${SCRIPT_NAME} <linux-repository>"
  echo ""
  echo " Sync vendored headers for the standard library."
}

if [[ "$#" -ne 1 ]]; then
  usage
  exit 1
fi
declare -r LINUX=$1

# The `HEADERS` variable contains a list of general purpose headers that are
# known to be important/useful for building the standard library and C
# extensions. This is seeded by the set that have been vendored by `libbpf`.
#
# The key is the header (relative to the include path) and the value is whether
# this require is required (failure to include is a failure).
declare -A HEADERS
HEADERS=(
  ["linux/bpf_common.h"]=true
  ["linux/bpf.h"]=true
  ["linux/btf.h"]=true
  ["linux/errno.h"]=true
  ["linux/fcntl.h"]=true
  ["linux/openat2.h"]=true
  ["linux/if_link.h"]=true
  ["linux/if_xdp.h"]=true
  ["linux/netdev.h"]=true
  ["linux/netlink.h"]=true
  ["linux/pkt_cls.h"]=true
  ["linux/pkt_sched.h"]=true
  ["linux/perf_event.h"]=true
  # These are not neccessary found transitively, since it depends on the
  # current architecture. So add these explicitly.
  ["linux/byteorder/little_endian.h"]=true
  ["linux/byteorder/big_endian.h"]=true
  # These are also not always found transitively.
  ["linux/kernel.h"]=true
  ["linux/netdev.h"]=true
  ["linux/sysinfo.h"]=true
  # This is not necessarily found transitively, and is not available at all
  # for certain archiectures. So allow failure for this file.
  ["asm/posix_types_64.h"]=false
  # These will end up coming from the non-uapi kernel directory, but may be
  # included when code is built as `__KERNEL__`. They won't be found be the
  # automatic transitive search, so we add them manually.
  ["linux/compiler.h"]=true
  ["linux/compiler_types.h"]=true
  ["linux/compiler_attributes.h"]=true
  ["linux/kasan-checks.h"]=true
  ["linux/kcsan-checks.h"]=true
  ["linux/compiler-clang.h"]=true # N.B. only care about clang.
  ["asm/rwonce.h"]=true
)

# When a header is found to be sourced from an `asm/` directory, we will
# identify all the other architecture variants that need to be copied. This is
# a list of the Linux architecture directories that we will create and check.
# Transient headers are subject to the same `required` status as the original.
declare -a ARCHES
ARCHES=(
  "x86"
  "arm"
  "arm64"
  "s390"
  "powerpc"
  "mips"
  "riscv"
  "loongarch"
)

function sync() {
  local -r header=$1

  if [[ "$header" =~ asm/.* ]]; then
    # We are but a single architecture. When copying any architecture-specific
    # header, we attempt to copy versions from all architectures and put them
    # in `asm/${arch}` instead. This is then resolved at runtime into the
    # correct directory. While we build different versions of the binary with
    # different files, this is a simple enough scheme. See the `ClangBuild`
    # pass for where this is effectively undone.
    asmpath="${header##asm/}"
    for arch in "${ARCHES[@]}"; do
      if [[ -f "src/stdlib/include/asm/${arch}/${asmpath}" ]]; then
        # This is done already. Since one assembly header exists, they all must
        # exist and we don't want to bother doing the transitive check.
        return 0
      fi
      echo -n "Syncing arch-specific ${header} for ${arch}..." 2>&1
      basepath=$(dirname "asm/${arch}/${asmpath}")
      mkdir -p "src/stdlib/include/${basepath}"
      # Attempt to copy from the arch-specific directory, but fall back to
      # the `asm-generic` directory if it is not present there. This is the
      # case for some files, as these may be merged in the exported version.
      if ! (cp --preserve=mode "${LINUX}/arch/${arch}/include/uapi/asm/${asmpath}" \
                               "src/stdlib/include/${basepath}" 2>/dev/null ||
            cp --preserve=mode "${LINUX}/include/uapi/asm-generic/${asmpath}" \
                               "src/stdlib/include/${basepath}" 2>/dev/null || \
            cp --preserve=mode "${LINUX}/include/asm-generic/${asmpath}" \
                               "src/stdlib/include/${basepath}" 2>/dev/null); then
        # We can specifically ignore this header.
        if [[ "${HEADERS[$header]}" != "false" ]]; then
          echo "failed."
          return 1
        else
          echo "skipped."
        fi
      else
        echo "done."
      fi
    done
  else
    # This is a simpler header and is not arch-specific.
    if [[ -f "src/stdlib/include/${header}" ]]; then
      return 0 # Done already, see above.
    fi
    echo -n "Syncing ${header}..." 2>&1
    basepath=$(dirname "${header}")
    mkdir -p "src/stdlib/include/${basepath}"
    if ! (cp --preserve=mode "${LINUX}/include/uapi/${header}" \
                             "src/stdlib/include/${basepath}" 2>/dev/null || \
          cp --preserve=mode "${LINUX}/include/${header}" \
                             "src/stdlib/include/${basepath}" 2>/dev/null); then
      # We can specifically ignore this header.
      if [[ "${HEADERS[$header]}" != "false" ]]; then
        echo "failed."
        return 1
      else
        echo "skipped."
      fi
    else
      echo "done."
    fi
  fi

  # In order to discover transitive headers required, we run a basic compile
  # and emit all touched headers. Note that this is run on the **system**
  # headers, and therefore assumes a stable structure for user headers.
  # Kernel-specific headers will need to be listed manually above, this step is
  # effectively best-effort.
  local -r tmpfile=$(mktemp --tmpdir "XXXXXX.c")
  echo "#include <$1>" > "${tmpfile}"
  local nesting
  local transitive_header
  clang -H -o /dev/null -c "${tmpfile}" 2>&1 | grep -E '.h$' | \
  (while read nesting transitive_header; do
    local relpath="${transitive_header##*/include/}"
    sync "${relpath}"
  done)
  rm -f "${tmpfile}"
}

# Wipe existing synced headers.
rm -rf \
  src/stdlib/include/asm \
  src/stdlib/include/asm-* \
  src/stdlib/include/linux

# Recursively vendor headers.
for header in "${!HEADERS[@]}"; do
  sync "${header}"
done
