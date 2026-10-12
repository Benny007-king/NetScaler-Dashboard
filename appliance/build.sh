#!/usr/bin/env bash
# Builds the two release artefacts:
#
#   netscaler-dashboard-appliance-<version>.ova   first-time install (import into a hypervisor)
#   netscaler-dashboard-upgrade-<version>.nsu     upgrade (upload in Settings > Software & Upgrade)
#
# Needs only Docker - the disk image is assembled inside a privileged container,
# so this runs the same on a developer machine and in CI.
#
#   appliance/build.sh                 # writes to ./dist
#   OUT_DIR=/some/dir appliance/build.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(tr -d ' \t\r\n' < VERSION)
OUT_DIR=${OUT_DIR:-$PWD/dist}
mkdir -p "$OUT_DIR"
OUT_DIR=$(cd "$OUT_DIR" && pwd)

echo "==> Building the dashboard image $VERSION"
docker build -q --build-arg APP_VERSION="$VERSION" -t "netscaler-dashboard:$VERSION" . >/dev/null
docker save "netscaler-dashboard:$VERSION" | gzip -9 > "$OUT_DIR/netscaler-dashboard-image-$VERSION.tar.gz"

SRC_MNT=$PWD; OUT_MNT=$OUT_DIR
if command -v cygpath >/dev/null 2>&1; then      # Git Bash on Windows: Docker wants native paths
  SRC_MNT=$(cygpath -m "$PWD"); OUT_MNT=$(cygpath -m "$OUT_DIR")
  export MSYS_NO_PATHCONV=1
fi

docker run --rm --privileged \
  -e DISK_GB -e CPUS -e MEM_MB -e BASE_URL \
  -v "$SRC_MNT:/src:ro" -v "$OUT_MNT:/out" -v nsd-appliance-cache:/cache \
  debian:13 bash /src/appliance/build-image.sh
