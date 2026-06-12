#!/bin/bash
#
# This script creates builds the official release artifacts.
#
# Usage examples:
#         ./scripts/create-assets.sh
#         OUT=../out-dir ./scripts/create-assets.sh
#
# Arch-specific assets (the binary and the bundle) are suffixed with the host
# architecture
#
# Tools and man pages are only built when BUILD_SHARED_ASSETS=1.
#

ZSTDFLAGS="-19"
ARCH="$(uname -m)"

# Whether to also build the arch-independent archives (tools, man pages).
: "${BUILD_SHARED_ASSETS:=1}"

function err() {
  echo >&2 "$(tput setaf 1)ERROR: $*$(tput sgr0)"
  exit 1
}
function info() {
  echo "$(tput bold)$*$(tput sgr0)"
}

[[ -d tools ]] || err "'tools' directory not found, run script from bpftrace root dir"
[[ -d man ]] || err "'man' directory not found, run script from bpftrace root dir"
command -v zstd >/dev/null 2>&1 || err "zstd command not found, required for release"
command -v asciidoctor >/dev/null 2>&1 || err "asciidoctor not found, required for manpage"

# Take value from environment if set, otherwise use a tempdir
: "${OUT:=$(mktemp -d)}" || err "Failed to create temp dir"
TMP="${OUT}/tmp"

echo "Using '$OUT' as assert dir"

set -e

info "Staging tools"

# bit of copying to avoid confusing tar flags not great but works
mkdir -p "$TMP/bin"

cp tools/*.bt "$TMP/bin"
chmod +x "$TMP/bin/"*.bt

info "Staging man pages"
mkdir -p "$TMP/share/man/man8"
cp man/man8/*.8 "$TMP/share//man/man8/"
gzip -n "$TMP/share/man/man8/"*
asciidoctor man/adoc/bpftrace.adoc  -b manpage -o - | gzip -n - > "$TMP/share/man/man8/bpftrace.8.gz"

# The tools and man archives are arch-independent, so only one runner needs to
# build them for a multi-arch release.
if [[ "$BUILD_SHARED_ASSETS" == "1" ]]; then
  info "Creating tools archive"
  tar --xz -cf "$OUT/tools.tar.xz" -C "$TMP/bin" "."
  info "Creating man archive"
  tar --xz -cf "$OUT/man.tar.xz" -C "$TMP/share" man
fi

info "Building bpftrace appimage"
nix build .?submodules=1#appimage

info "Creating bundle"
cp ./result "$OUT/bpftrace-$ARCH"
cp ./result "$TMP/bin/bpftrace"
tar -cf "$OUT/binary_tools_man-bundle-$ARCH.tar" -C "$TMP" bin share
zstd $ZSTDFLAGS -q -k "$OUT/binary_tools_man-bundle-$ARCH.tar"
xz "$OUT/binary_tools_man-bundle-$ARCH.tar"

echo "All assets created in $OUT"
[[ -d "$TMP" ]] && rm -rf "$TMP"
