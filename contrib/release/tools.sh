#!/bin/sh
# Install the tools a release is built with into DIR, pinned with their
# checksums, for the machine this runs on: zig, the C compiler and linker for
# both musl targets (LMDB, libsecp256k1 and zstd are C);
# cargo-zigbuild, which has cargo use it; and nfpm, which builds the packages.
# Anything already in DIR and matching its checksum is kept.
#
#   PATH="$(contrib/release/tools.sh DIR):$PATH"
#
# Prints the directories to put on PATH, and nothing else on stdout.
set -eu

if [ $# -ne 1 ]; then
    echo "Usage: $0 DIR" >&2
    exit 2
fi

zig_version=0.16.0
zigbuild_version=0.23.4
nfpm_version=2.47.0

case "$(uname -m)" in
    x86_64)
        zig_arch=x86_64
        zig_sha256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
        zigbuild_target=x86_64-unknown-linux-musl
        zigbuild_sha256=9e3cf73485edbd45905c8aadbc0fdf869c7ddc3848f0c898229f2680db52e44b
        nfpm_arch=x86_64
        nfpm_sha256=0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783
        ;;
    aarch64 | arm64)
        zig_arch=aarch64
        zig_sha256=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17
        # cargo-zigbuild publishes no musl build for aarch64.
        zigbuild_target=aarch64-unknown-linux-gnu
        zigbuild_sha256=25cf2cdc6cde848b33a761ff2cf46d1efe6ba7e1adfc4b6f3ee2d570cacb5419
        nfpm_arch=arm64
        nfpm_sha256=1c0f5f2999b9a974bfb04fdb0cc3306096de530ac5dbb25d739cc5f5219c919c
        ;;
    *)
        echo "Release builds run on x86_64 or aarch64 Linux, not $(uname -m)." >&2
        exit 1
        ;;
esac

mkdir -p "$1"
dir="$(cd "$1" && pwd)"

# Download URL to FILE in DIR unless it is already there with SHA256, then
# check it.
fetch() {
    if ! (cd "$dir" && echo "$3  $2" | sha256sum -c --status - 2>/dev/null); then
        curl -fsSL -o "$dir/$2" "$1"
    fi
    (cd "$dir" && echo "$3  $2" | sha256sum -c --quiet -) >&2
}

zig="zig-$zig_arch-linux-$zig_version"
fetch "https://ziglang.org/download/$zig_version/$zig.tar.xz" "$zig.tar.xz" "$zig_sha256"
[ -d "$dir/$zig" ] || tar -xJf "$dir/$zig.tar.xz" -C "$dir"

zigbuild="cargo-zigbuild-$zigbuild_version-$zigbuild_target"
fetch "https://github.com/rust-cross/cargo-zigbuild/releases/download/v$zigbuild_version/cargo-zigbuild-$zigbuild_target.tar.xz" \
    "$zigbuild.tar.xz" "$zigbuild_sha256"
if [ ! -d "$dir/$zigbuild" ]; then
    mkdir "$dir/$zigbuild"
    tar -xJf "$dir/$zigbuild.tar.xz" -C "$dir/$zigbuild" --strip-components=1
fi

nfpm="nfpm_${nfpm_version}_Linux_$nfpm_arch"
fetch "https://github.com/goreleaser/nfpm/releases/download/v$nfpm_version/$nfpm.tar.gz" "$nfpm.tar.gz" "$nfpm_sha256"
if [ ! -d "$dir/$nfpm" ]; then
    mkdir "$dir/$nfpm"
    tar -xzf "$dir/$nfpm.tar.gz" -C "$dir/$nfpm"
fi

echo "$dir/$zig:$dir/$zigbuild:$dir/$nfpm"
