#!/bin/bash
# Packs an upgrade bundle (.nsu) - the single file an administrator uploads in
# Settings > Software & Upgrade.
#
#   make-upgrade.sh <version> <image.tar.gz> <appliance-dir> <out.nsu>
#
# A bundle is a plain tar holding:
#   manifest.json   product, version and the SHA-256 of every other member
#   image.tar.gz    the dashboard container image (`docker save | gzip`)
#   host.tar.gz     host-install.sh + rootfs/, so an upgrade can also update the
#                   appliance's own scripts and units
# Both the dashboard (appliance.py) and the host agent (ns-upgrade) check the
# manifest and the checksums before anything is changed.
set -euo pipefail

VERSION=${1:?version}; IMAGE=${2:?image.tar.gz}; APPL=${3:?appliance dir}; OUT=${4:?output .nsu}

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

cp "$IMAGE" "$T/image.tar.gz"
tar -czf "$T/host.tar.gz" -C "$APPL" --owner=0 --group=0 --numeric-owner host-install.sh rootfs

sha() { sha256sum "$1" | cut -d' ' -f1; }
cat > "$T/manifest.json" <<EOF
{
  "format": 1,
  "product": "netscaler-dashboard",
  "version": "$VERSION",
  "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "image": { "file": "image.tar.gz", "ref": "netscaler-dashboard:$VERSION", "sha256": "$(sha "$T/image.tar.gz")" },
  "host":  { "file": "host.tar.gz", "sha256": "$(sha "$T/host.tar.gz")" }
}
EOF

# manifest first, so it can be read without scanning the whole file
tar --format=ustar -cf "$OUT" -C "$T" --owner=0 --group=0 --numeric-owner manifest.json image.tar.gz host.tar.gz
echo "make-upgrade: $(basename "$OUT")  ($(du -h "$OUT" | cut -f1))"
