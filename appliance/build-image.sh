#!/bin/bash
# Builds the appliance disk and packages the release artefacts. Runs INSIDE a
# privileged Debian container started by build.sh (it needs loop devices and
# chroot) with:
#     /src    the repository, read-only
#     /out    where the artefacts go (already holds the dashboard image tarball)
#     /cache  a persistent volume for the downloaded base image
#
# Steps: official Debian cloud image -> raw disk -> grow -> chroot and customise
#        -> streamOptimized VMDK -> OVF + manifest -> OVA, plus the .nsu bundle.
#
# The VMDK is written by VMware's own open-vmdk, not by qemu-img: VMware's
# importer rejects a qemu-img stream disk ("SHA digest ... does not match
# manifest") although the file and the manifest are both correct.
set -euo pipefail

SRC=/src
OUT=/out
CACHE=/cache
WORK=/work
MNT=$WORK/root

VERSION=$(tr -d ' \t\r\n' < "$SRC/VERSION")
DISK_GB=${DISK_GB:-16}
CPUS=${CPUS:-2}
MEM_MB=${MEM_MB:-2048}
BASE_URL=${BASE_URL:-https://cloud.debian.org/images/cloud/trixie/latest}
BASE_IMG=debian-13-generic-amd64.qcow2
OPEN_VMDK_REPO=https://github.com/vmware/open-vmdk
OPEN_VMDK_COMMIT=5afbfb5270099586b93e28ae7585f3c661f379b5      # v3.0.1

NAME=netscaler-dashboard-appliance-$VERSION
SEED=$OUT/netscaler-dashboard-image-$VERSION.tar.gz
RAW=$WORK/disk.raw
LOOP=""

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { echo "build-image: $*" >&2; exit 1; }

[ -f "$SEED" ] || die "missing $SEED - run appliance/build.sh, which builds the dashboard image first"

# ------------------------------------------------------------------ teardown
unmount_all() {
  [ -d "$MNT" ] || return 0
  local m
  # deepest mount points first
  for m in $(awk -v p="$MNT" '$2 == p || index($2, p "/") == 1 {print $2}' /proc/mounts | sort -r); do
    umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null || true
  done
  sync
}
teardown() {
  unmount_all
  [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null || true
}
trap teardown EXIT

# ---------------------------------------------------------------------- tools
say "Installing build tools"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  qemu-utils cloud-guest-utils gdisk fdisk e2fsprogs dosfstools zerofree curl ca-certificates \
  git build-essential zlib1g-dev >/dev/null

VMDK_CONVERT=$CACHE/vmdk-convert-$OPEN_VMDK_COMMIT
if [ ! -x "$VMDK_CONVERT" ]; then
  rm -rf "$WORK/open-vmdk" && mkdir -p "$WORK/open-vmdk"
  ( cd "$WORK/open-vmdk" && git init -q && git fetch -q --depth 1 "$OPEN_VMDK_REPO" "$OPEN_VMDK_COMMIT" \
      && git checkout -q FETCH_HEAD && [ "$(git rev-parse HEAD)" = "$OPEN_VMDK_COMMIT" ] && make -s >/dev/null ) \
    || die "could not build open-vmdk at $OPEN_VMDK_COMMIT"
  install -m 0755 "$WORK/open-vmdk/build/vmdk/vmdk-convert" "$VMDK_CONVERT"
  rm -rf "$WORK/open-vmdk"
fi

# ------------------------------------------------------------------ base image
say "Fetching the Debian base image"
mkdir -p "$CACHE" "$WORK" "$MNT"
want=$(curl -fsSL "$BASE_URL/SHA512SUMS" | awk -v f="$BASE_IMG" '$2 == f {print $1}')
[ -n "$want" ] || die "could not read the checksum of $BASE_IMG from $BASE_URL"
base="$CACHE/$want.qcow2"
if [ ! -f "$base" ]; then
  curl -fL --retry 3 -o "$base.part" "$BASE_URL/$BASE_IMG"
  echo "$want  $base.part" | sha512sum -c - >/dev/null || die "the downloaded base image failed its checksum"
  mv "$base.part" "$base"
  find "$CACHE" -maxdepth 1 -name '*.qcow2' ! -name "$want.qcow2" -delete   # drop superseded images
fi
echo "base image: $BASE_IMG (sha512 ${want:0:16}...)"

# ------------------------------------------------------------------- raw disk
say "Preparing a ${DISK_GB} GB disk"
rm -f "$RAW"
qemu-img convert -f qcow2 -O raw "$base" "$RAW"
qemu-img resize -q -f raw "$RAW" "${DISK_GB}G"

# A container's /dev is a snapshot: device nodes for new loop devices and their
# partitions do not appear by themselves, so create them from sysfs.
for i in $(seq 0 63); do [ -b "/dev/loop$i" ] || mknod "/dev/loop$i" b 7 "$i"; done
LOOP=$(losetup --show -fP "$RAW")
refresh_parts() {
  partx -u "$LOOP" >/dev/null 2>&1 || true
  local p n
  for p in /sys/block/"${LOOP##*/}"/"${LOOP##*/}"p*; do
    [ -e "$p/dev" ] || continue
    n="/dev/${p##*/}"
    rm -f "$n"
    mknod "$n" b $(tr ':' ' ' < "$p/dev")
  done
}
refresh_parts

ROOT_DEV=""; EFI_DEV=""
for p in "$LOOP"p*; do
  case "$(blkid -o value -s TYPE "$p" 2>/dev/null || true)" in
    ext4) ROOT_DEV=$p ;;
    vfat) EFI_DEV=$p ;;
  esac
done
[ -n "$ROOT_DEV" ] || die "no ext4 root partition found in the base image"

sgdisk -e "$LOOP" >/dev/null                       # move the backup GPT to the new end of disk
growpart "$LOOP" "${ROOT_DEV##*p}" >/dev/null
refresh_parts
e2fsck -fy "$ROOT_DEV" >/dev/null 2>&1 || true     # exit 1 only means "fixed"
resize2fs "$ROOT_DEV" >/dev/null 2>&1

# ---------------------------------------------------------------------- chroot
say "Customising the operating system"
mount "$ROOT_DEV" "$MNT"
[ -n "$EFI_DEV" ] && [ -d "$MNT/boot/efi" ] && mount "$EFI_DEV" "$MNT/boot/efi"
mount -t proc proc "$MNT/proc"
mount -t sysfs sys "$MNT/sys"
mount --rbind /dev "$MNT/dev"
mount --make-rslave "$MNT/dev"         # unmounting below must never reach the real /dev
mount -t tmpfs tmpfs "$MNT/run"
mount -t tmpfs tmpfs "$MNT/tmp"

# Name resolution for apt inside the chroot (the image's resolv.conf points at a
# resolver that is not running here). It is replaced with the real link below.
rm -f "$MNT/etc/resolv.conf"
cp /etc/resolv.conf "$MNT/etc/resolv.conf"

# The customisation runs from a file with stdin closed: fed over stdin, a single
# dpkg prompt would read (and swallow) the rest of the script.
cat > "$MNT/tmp/ns-customise.sh" <<'CHROOT'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
APT="apt-get -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
installed() { dpkg-query -W -f '${db:Status-Abbrev}' "$1" 2>/dev/null | grep -q '^ii'; }

# Nothing may start a service while packages are installed in a chroot.
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d

apt-get update -qq
# Security fixes for everything except the boot chain: upgrading the kernel or
# GRUB here would try to reinstall the bootloader from inside a chroot.
# (dpkg-query also lists names it merely knows about, so keep the installed ones.)
held=$(dpkg-query -W -f '${db:Status-Abbrev}${Package}\n' 'linux-image-*' 'grub*' 'shim*' 2>/dev/null \
       | sed -n 's/^ii //p' | tr '\n' ' ')
apt-mark hold $held >/dev/null
$APT upgrade >/dev/null
apt-mark unhold $held >/dev/null

# The image is built for clouds; an appliance configures itself.
for pkg in cloud-init cloud-guest-utils cloud-initramfs-growroot netplan.io ifupdown; do
  if installed "$pkg"; then $APT purge "$pkg" >/dev/null; fi
done
rm -rf /etc/cloud /var/lib/cloud /etc/netplan /etc/network/interfaces.d

pkgs="docker.io jq curl ca-certificates sudo iproute2 less nano open-vm-tools systemd-resolved systemd-timesyncd unattended-upgrades"
apt-cache show docker-cli >/dev/null 2>&1 && pkgs="$pkgs docker-cli"    # split out of docker.io in newer Debian
$APT install --no-install-recommends $pkgs >/dev/null
$APT autoremove --purge >/dev/null
command -v docker >/dev/null || { echo "docker CLI missing after install" >&2; exit 1; }
for unit in systemd-networkd systemd-resolved docker; do
  [ -e "/usr/lib/systemd/system/$unit.service" ] || [ -e "/lib/systemd/system/$unit.service" ] \
    || { echo "$unit.service is missing from the image" >&2; exit 1; }
done

# --- accounts: one console administrator, root locked ----------------------
id nsadmin >/dev/null 2>&1 || useradd -m -s /bin/bash -c "Appliance administrator" nsadmin
echo 'nsadmin:nsadmin' | chpasswd
chage -d 0 nsadmin                 # must choose a new password at first login
passwd -l root >/dev/null

# --- SSH: off until enabled from the console; host keys are never shipped ---
rm -f /etc/ssh/ssh_host_*
systemctl disable ssh.service ssh.socket >/dev/null 2>&1 || true

# --- identity that must be unique per deployed VM ---------------------------
: > /etc/machine-id
rm -f /var/lib/dbus/machine-id /var/lib/systemd/random-seed

echo ns-dashboard > /etc/hostname
if grep -q '^127\.0\.1\.1' /etc/hosts; then
  sed -i 's/^127\.0\.1\.1.*/127.0.1.1 ns-dashboard/' /etc/hosts
else
  echo '127.0.1.1 ns-dashboard' >> /etc/hosts
fi

# The zone the appliance starts in; "Time zone" on the console menu changes it, and
# the dashboard container is started in whatever zone the appliance is set to.
ln -sf /usr/share/zoneinfo/Asia/Jerusalem /etc/localtime
echo Asia/Jerusalem > /etc/timezone

# --- every common virtual disk controller must be in the initramfs ----------
# (the listing goes to a file first: `grep -q` on a pipe ends it early, which
#  `pipefail` would report as a failure even though the module was found)
has_drivers() {
  local k
  for k in /boot/initrd.img-*; do
    lsinitramfs "$k" > /tmp/initramfs.list
    for mod in mptspi vmw_pvscsi ahci sd_mod; do
      grep -q "/$mod\.ko" /tmp/initramfs.list || { echo "  $(basename "$k") lacks $mod"; return 1; }
    done
  done
}
if ! has_drivers; then
  echo "rebuilding the initramfs with MODULES=most"
  mkdir -p /etc/initramfs-tools/conf.d
  echo 'MODULES=most' > /etc/initramfs-tools/conf.d/ns-appliance.conf
  update-initramfs -u -k all >/dev/null
  has_drivers || { echo "the initramfs still lacks a disk driver" >&2; exit 1; }
fi
for mod in e1000 vmxnet3; do
  find /lib/modules -name "$mod.ko*" | grep -q . || { echo "kernel module $mod is missing" >&2; exit 1; }
done

systemctl enable systemd-networkd systemd-resolved systemd-timesyncd docker open-vm-tools >/dev/null 2>&1
CHROOT
chroot "$MNT" /bin/bash /tmp/ns-customise.sh </dev/null

say "Installing the appliance layer"
sh "$SRC/appliance/host-install.sh" "$MNT" "$VERSION"

# Shown on the login screen until the first console login (ns-console removes it).
mkdir -p "$MNT/etc/issue.d"
cat > "$MNT/etc/issue.d/50-first-login.issue" <<'EOF'
  First login   :  nsadmin / nsadmin  (you will be asked to choose a new password)

EOF

install -m 0644 "$SEED" "$MNT/opt/ns-appliance/seed/netscaler-dashboard-$VERSION.tar.gz"

say "Cleaning up"
cat > "$MNT/tmp/ns-cleanup.sh" <<'CHROOT'
set -euo pipefail
rm -f /usr/sbin/policy-rc.d
apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /root/.bash_history /var/tmp/* /var/log/apt /var/log/dpkg.log /var/log/alternatives.log
find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null || true
# systemd-resolved owns name resolution on the running appliance
ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
CHROOT
chroot "$MNT" /bin/bash /tmp/ns-cleanup.sh </dev/null

echo "root filesystem: $(df -h --output=used "$MNT" | tail -1 | tr -d ' ') used of ${DISK_GB}G"
unmount_all
e2fsck -fy "$ROOT_DEV" >/dev/null 2>&1 || true
zerofree "$ROOT_DEV"               # zero the free blocks so they compress away in the VMDK
losetup -d "$LOOP"; LOOP=""

# ------------------------------------------------------------------------- OVA
say "Packaging $NAME.ova"
PKG=$WORK/pkg
rm -rf "$PKG" && mkdir -p "$PKG"
VMDK=$NAME-disk1.vmdk
"$VMDK_CONVERT" "$RAW" "$PKG/$VMDK" >/dev/null
qemu-img compare -f raw -F vmdk "$RAW" "$PKG/$VMDK" >/dev/null || die "the VMDK does not hold the same data as the disk it was made from"
rm -f "$RAW"

sed -e "s|@NAME@|$NAME|g" \
    -e "s|@VERSION@|$VERSION|g" \
    -e "s|@VMDK_FILE@|$VMDK|g" \
    -e "s|@VMDK_SIZE@|$(stat -c %s "$PKG/$VMDK")|g" \
    -e "s|@DISK_BYTES@|$(( DISK_GB * 1024 * 1024 * 1024 ))|g" \
    -e "s|@CPUS@|$CPUS|g" \
    -e "s|@MEM_MB@|$MEM_MB|g" \
    "$SRC/appliance/appliance.ovf.in" | tr -d '\r' > "$PKG/$NAME.ovf"
grep -q '@[A-Z_]*@' "$PKG/$NAME.ovf" && die "unfilled placeholder left in the OVF"

( cd "$PKG" && for f in "$NAME.ovf" "$VMDK"; do
    echo "SHA256($f)= $(sha256sum "$f" | cut -d' ' -f1)"
  done > "$NAME.mf" )

# The OVF standard wants the descriptor first, then the manifest, then the disks.
tar --format=ustar -cf "$OUT/$NAME.ova" -C "$PKG" --owner=0 --group=0 --numeric-owner \
    "$NAME.ovf" "$NAME.mf" "$VMDK"
rm -rf "$PKG"

# --------------------------------------------------------------- upgrade bundle
say "Packaging the upgrade bundle"
NSU=netscaler-dashboard-upgrade-$VERSION.nsu
bash "$SRC/appliance/make-upgrade.sh" "$VERSION" "$SEED" "$SRC/appliance" "$OUT/$NSU"
rm -f "$SEED"                       # an intermediate: it is inside both artefacts now

( cd "$OUT" && sha256sum "$NAME.ova" "$NSU" > SHA256SUMS )
say "Done"
ls -lh "$OUT/$NAME.ova" "$OUT/$NSU" | awk '{print "  " $5 "  " $9}'
cat "$OUT/SHA256SUMS" | sed 's/^/  /'
