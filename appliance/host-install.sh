#!/bin/sh
# Installs the appliance's host-side files (rootfs/) into a root filesystem.
#
# Used in two places, so there is exactly one description of the host layout:
#   - when the disk image is built:   host-install.sh /mnt/root <version>
#   - when an upgrade is applied:     host-install.sh / <version>   (shipped in the .nsu)
#
# Only files this project owns are written. Anything an administrator configured
# (a static address in 10-ns-static.network, dashboard.env, the data directory)
# lives in separate files and is never touched.
set -eu

ROOT="${1:?usage: host-install.sh <target-root> <version>}"
VERSION="${2:?usage: host-install.sh <target-root> <version>}"
SRC="$(cd "$(dirname "$0")" && pwd)/rootfs"
[ -d "$SRC" ] || { echo "host-install: rootfs/ not found next to $0" >&2; exit 1; }
ROOT="${ROOT%/}"                       # "/" becomes "", so paths below stay clean

put() {   # put <mode> <path relative to rootfs/>
  mkdir -p "$ROOT/$(dirname "$2")"
  tmp="$(mktemp)"
  tr -d '\r' < "$SRC/$2" > "$tmp"      # tolerate a checkout with CRLF line endings
  # install(1) unlinks the target first: a script that is running right now
  # (ns-upgrade, during an upgrade) keeps its old copy and is not disturbed.
  install -m "$1" -o root -g root "$tmp" "$ROOT/$2"
  rm -f "$tmp"
}

put 0755 opt/ns-appliance/bin/ns-dashboard
put 0755 opt/ns-appliance/bin/ns-upgrade
put 0755 opt/ns-appliance/bin/ns-console
put 0755 opt/ns-appliance/bin/ns-issue
put 0644 etc/systemd/system/ns-dashboard.service
put 0644 etc/systemd/system/ns-upgrade.path
put 0644 etc/systemd/system/ns-upgrade.service
put 0644 etc/systemd/system/ns-issue.service
put 0644 etc/systemd/system/systemd-networkd-wait-online.service.d/ns-appliance.conf
put 0644 etc/systemd/network/20-ns-dhcp.network
put 0644 etc/systemd/journald.conf.d/ns-appliance.conf
put 0644 etc/docker/daemon.json
put 0644 etc/issue
put 0440 etc/sudoers.d/ns-appliance
put 0644 etc/profile.d/ns-console.sh

mkdir -p "$ROOT/etc/ns-appliance" "$ROOT/opt/ns-appliance/seed" "$ROOT/var/lib/ns-dashboard/data/upgrade"
echo "$VERSION" > "$ROOT/etc/ns-appliance/version"

if [ -z "$ROOT" ]; then
  systemctl daemon-reload
  systemctl enable ns-dashboard.service ns-upgrade.path ns-issue.service >/dev/null 2>&1
  systemctl restart ns-issue.service >/dev/null 2>&1 || true
else
  chroot "$ROOT" systemctl enable ns-dashboard.service ns-upgrade.path ns-issue.service >/dev/null 2>&1
fi
echo "host-install: appliance files $VERSION installed into ${ROOT:-/}"
