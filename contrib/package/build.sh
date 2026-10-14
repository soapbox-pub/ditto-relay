#!/bin/sh
# Package a release binary as a .deb and an .rpm, with nfpm
# (https://nfpm.goreleaser.com). Run from the repository root:
#
#   contrib/package/build.sh VERSION ARCH BINARY OUTDIR
#
# ARCH is x86_64 or aarch64. Writes ditto-relay-VERSION-linux-ARCH.deb and .rpm
# to OUTDIR.
set -eu

if [ $# -ne 4 ]; then
    echo "Usage: $0 VERSION ARCH BINARY OUTDIR" >&2
    exit 2
fi
version="$1"
arch="$2"
binary="$3"
outdir="$4"

# nfpm's architectures are Go's; it names them the rpm way itself.
case "$arch" in
    x86_64) nfpm_arch=amd64 ;;
    aarch64) nfpm_arch=arm64 ;;
    *)
        echo "Unknown architecture $arch: use x86_64 or aarch64." >&2
        exit 2
        ;;
esac

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

# contrib/ditto-relay.service and ditto-relay.example.toml are written for an
# install by hand; the package puts the binary in /usr/bin and the data in
# /var/lib/ditto-relay, which the ditto-relay user's default wouldn't be. url
# is commented out, so the service refuses to start until it is set.
sed 's|/usr/local/bin/ditto-relay|/usr/bin/ditto-relay|g' contrib/ditto-relay.service > "$stage/ditto-relay.service"
sed -e 's|^url = \(.*\)$|#url = \1|' \
    -e 's|^#data_dir = "/var/lib/ditto-relay"$|data_dir = "/var/lib/ditto-relay"|' \
    ditto-relay.example.toml > "$stage/ditto-relay.toml"
if ! grep -qx 'ExecStart=/usr/bin/ditto-relay --config /etc/ditto-relay/ditto-relay.toml' "$stage/ditto-relay.service" \
    || grep -q '^url' "$stage/ditto-relay.toml" \
    || ! grep -qx 'data_dir = "/var/lib/ditto-relay"' "$stage/ditto-relay.toml"; then
    echo "contrib/ditto-relay.service or ditto-relay.example.toml changed shape; update $0 to match." >&2
    exit 1
fi

cp "$binary" "$stage/ditto-relay"
cp LICENSE contrib/package/nfpm.yaml contrib/package/*.conf contrib/package/post*.sh contrib/package/pre*.sh "$stage/"

mkdir -p "$outdir"
outdir="$(cd "$outdir" && pwd)"
export DITTO_RELAY_VERSION="$version" DITTO_RELAY_ARCH="$nfpm_arch"
for packager in deb rpm; do
    (cd "$stage" && nfpm package --packager "$packager" --target "$outdir/ditto-relay-$version-linux-$arch.$packager")
done
