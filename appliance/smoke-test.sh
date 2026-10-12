#!/usr/bin/env bash
# Boots the built OVA in QEMU and tests it end to end - boot, first sign-in, an
# upgrade by upload, and an automatic rollback (see smoke-test-vm.sh).
# Needs only Docker. Uses KVM when the host offers it; otherwise the VM is fully
# emulated, which works everywhere but takes several minutes.
#
#   appliance/smoke-test.sh                 # tests ./dist
#   OUT_DIR=/some/dir appliance/smoke-test.sh
set -euo pipefail
cd "$(dirname "$0")/.."

OUT_DIR=${OUT_DIR:-$PWD/dist}
OUT_DIR=$(cd "$OUT_DIR" && pwd)

SRC_MNT=$PWD; OUT_MNT=$OUT_DIR
if command -v cygpath >/dev/null 2>&1; then      # Git Bash on Windows: Docker wants native paths
  SRC_MNT=$(cygpath -m "$PWD"); OUT_MNT=$(cygpath -m "$OUT_DIR")
  export MSYS_NO_PATHCONV=1
fi

kvm=()
[ -e /dev/kvm ] && kvm=(--device /dev/kvm)

docker run --rm "${kvm[@]}" -e BOOT_TIMEOUT \
  -v "$SRC_MNT:/src:ro" -v "$OUT_MNT:/dist:ro" \
  debian:13 bash /src/appliance/smoke-test-vm.sh
