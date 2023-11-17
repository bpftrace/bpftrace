#!/bin/bash
#
# This script creates builds the official release artifacts.
#
# Usage examples:
#         ./scripts/create-assets.sh
#         OUT=../out-dir ./scripts/create-assets.sh
#

ZSTDFLAGS="-19"

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
: ${OUT:=$(mktemp -d)} || err "Failed to create temp dir"
TMP="${OUT}/tmp"

echo "Using '$OUT' as assert dir"

set -e

info "Creating tools archive"

# bit of copying to avoid confusing tar flags not great but works
mkdir -p "$TMP/bin"

cp tools/*.bt tools/*.txt "$TMP/bin"
rm -f "$TMP/bin/CMakeLists.txt"
chmod +x "$TMP/bin/"*.bt

tar --xz -cf "$OUT/tools-with-help.tar.xz" -C "$TMP/bin" "."

rm "$TMP/bin/"*.txt
tar --xz -cf "$OUT/tools.tar.xz" -C "$TMP/bin" "."

info "Creating man archive"
mkdir -p "$TMP/share/man/man8"
cp man/man8/*.8 "$TMP/share//man/man8/"
gzip "$TMP/share/man/man8/"*
asciidoctor man/adoc/bpftrace.adoc  -b manpage -o - | gzip - > "$TMP/share/man/man8/bpftrace.8.gz"
tar --xz -cf "$OUT/man.tar.xz" -C "$TMP/share" man

info "Building bpftrace appimage"
nix build .#appimage

info "Creating bundle"
cp ./result "$OUT/bpftrace"
cp ./result "$TMP/bin/bpftrace"
tar -cf "$OUT/binary_tools_man-bundle.tar" -C "$TMP" bin share
zstd $ZSTDFLAGS -q -k "$OUT/binary_tools_man-bundle.tar"
xz "$OUT/binary_tools_man-bundle.tar"

echo "All assets created in $OUT"
[[ -d "$TMP" ]] && rm -rf "$TMP"
