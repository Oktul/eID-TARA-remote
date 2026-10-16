#!/usr/bin/env bash
# Copies /relay out of the linux/<arch> image of a skopeo reference, so
# govulncheck -mode=binary scans exactly what customers run (PLAN.md §12).
# The image is FROM scratch, so its layers are unpacked in order.
# Usage: extract-binary.sh <skopeo reference> <amd64|arm64> <output file>
set -euo pipefail
# shellcheck source=.github/scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ $# == 3 ]] || die "usage: extract-binary.sh <skopeo reference> <amd64|arm64> <output file>"
ref=$1 arch=$2 out=$3
[[ $arch == amd64 || $arch == arm64 ]] || die "unsupported architecture $arch"

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
skopeo copy --quiet --override-os linux --override-arch "$arch" "$ref" "dir:$dir/image"

config=$(jq -er '.config.digest' "$dir/image/manifest.json")
jq -e --arg a "$arch" '.os == "linux" and .architecture == $a' "$dir/image/${config#sha256:}" >/dev/null ||
	die "$ref: skopeo selected an image that is not linux/$arch"

mkdir "$dir/root"
mapfile -t layers < <(jq -r '.layers[].digest' "$dir/image/manifest.json")
((${#layers[@]} > 0)) || die "$ref: the image has no layers"
for layer in "${layers[@]}"; do
	[[ $layer =~ ^sha256:[0-9a-f]{64}$ ]] || die "$ref: unexpected layer digest"
	tar --extract --no-same-owner --no-same-permissions --file "$dir/image/${layer#sha256:}" --directory "$dir/root"
done
[[ -f $dir/root/relay && ! -L $dir/root/relay ]] || die "$ref: no /relay binary"
cp "$dir/root/relay" "$out"
