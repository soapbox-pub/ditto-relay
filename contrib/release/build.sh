#!/bin/sh
# Build Ditto Relay the way a release publishes it: a static musl binary from
# the `release` profile. The release workflow and a build by hand both run
# this. Run from the repository root:
#
#   contrib/release/build.sh OUTDIR [ARCH...]
#
# ARCH is x86_64 or aarch64, both by default; either is built on either. Writes
# ditto-relay-VERSION-linux-ARCH to OUTDIR, VERSION from Cargo.toml. Needs the
# Rust rust-toolchain.toml names and contrib/release/tools.sh's tools on PATH.
set -eu

if [ $# -lt 1 ]; then
    echo "Usage: $0 OUTDIR [ARCH...]" >&2
    exit 2
fi
outdir="$1"
shift
[ $# -gt 0 ] || set -- x86_64 aarch64

version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)"

# zig's linker holds every object file open at once.
ulimit -n "$(ulimit -Hn)"
mkdir -p "$outdir"
for arch in "$@"; do
    case "$arch" in
        x86_64 | aarch64) ;;
        *)
            echo "Unknown architecture $arch: use x86_64 or aarch64." >&2
            exit 2
            ;;
    esac
    cargo zigbuild --release --locked --target "$arch-unknown-linux-musl"
    bin="$outdir/ditto-relay-$version-linux-$arch"
    # CARGO_TARGET_DIR, where an environment sets one: some CI runners share
    # one between runs.
    cp "${CARGO_TARGET_DIR:-target}/$arch-unknown-linux-musl/release/ditto-relay" "$bin"
    # A musl binary that still asks for a dynamic loader fails on glibc hosts
    # with a misleading "No such file or directory"; refuse to make one.
    if readelf -l "$bin" | grep -q 'program interpreter'; then
        echo "$bin is dynamically linked." >&2
        exit 1
    fi
done
ls -l "$outdir"
