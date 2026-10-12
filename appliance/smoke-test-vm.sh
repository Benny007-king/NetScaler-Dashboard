#!/bin/bash
# End-to-end test of the built artefacts. Runs INSIDE a container started by
# smoke-test.sh, with the repository at /src and the artefacts at /dist.
#
# It boots the real OVA in QEMU and checks what an administrator would do:
#   1. the OVA is a well-formed package and its manifest checksums hold
#   2. the appliance boots and the dashboard answers on HTTPS
#   3. first sign-in (admin/admin -> forced password change) works
#   4. a junk upload is refused
#   5. uploading the .nsu performs a real upgrade through the host agent
#   6. uploading a release that cannot start is rolled back automatically
#   7. the console menu: first login, static address, back to DHCP (console-test.py)
set -euo pipefail

SRC=/src; DIST=/dist; WORK=/work
VERSION=$(tr -d ' \t\r\n' < "$SRC/VERSION")
OVA=$DIST/netscaler-dashboard-appliance-$VERSION.ova
NSU=$DIST/netscaler-dashboard-upgrade-$VERSION.nsu
BASE=https://127.0.0.1:8443
JAR=$WORK/cookies
BOOT_TIMEOUT=${BOOT_TIMEOUT:-1800}       # generous: without KVM the VM is fully emulated

step() { printf '\n\033[1m[%s] %s\033[0m\n' "$(date +%H:%M:%S)" "$*"; }
pass() { printf '   \033[32mPASS\033[0m  %s\n' "$*"; }
die()  { printf '   \033[31mFAIL\033[0m  %s\n' "$*"; echo "--- last console output ---"; tail -n 40 "$WORK/serial.log" 2>/dev/null | tr -d '\r' || true; exit 1; }

[ -f "$OVA" ] && [ -f "$NSU" ] || { echo "artefacts for $VERSION not found in $DIST"; exit 1; }
mkdir -p "$WORK/ova"

step "Installing test tools"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends qemu-system-x86 qemu-utils curl jq ca-certificates python3 >/dev/null

cleanup() { [ -f "$WORK/qemu.pid" ] && kill "$(cat "$WORK/qemu.pid")" 2>/dev/null || true; }
trap cleanup EXIT

# ------------------------------------------------------------------ 1. package
step "1. OVA package"
[[ "$(tar -tf "$OVA" | head -n 1)" == *.ovf ]] || die "the OVF descriptor is not the first member of the OVA"
tar -xf "$OVA" -C "$WORK/ova"
while read -r line; do
  f=$(sed -E 's/^SHA256\((.*)\)= .*$/\1/' <<<"$line"); want=${line##*= }
  [ "$(sha256sum "$WORK/ova/$f" | cut -d' ' -f1)" = "$want" ] || die "manifest checksum mismatch for $f"
done < "$WORK"/ova/*.mf
( cd "$DIST" && sha256sum -c SHA256SUMS >/dev/null ) || die "SHA256SUMS does not match the artefacts"
qemu-img info "$WORK"/ova/*.vmdk | grep -q 'streamOptimized' || die "the disk is not a streamOptimized VMDK"
pass "descriptor first, manifest and SHA256SUMS verified, disk is streamOptimized VMDK"

# --------------------------------------------------------------------- 2. boot
step "2. Boot"
qemu-img convert -O qcow2 "$WORK"/ova/*.vmdk "$WORK/disk.qcow2"
accel="tcg,thread=multi"; [ -w /dev/kvm ] && accel=kvm
echo "   accelerator: $accel"
qemu-system-x86_64 -machine q35 -accel "$accel" -cpu max -smp 4 -m 2048 \
  -drive "file=$WORK/disk.qcow2,if=none,id=d0,format=qcow2" -device ide-hd,drive=d0,bus=ide.0 \
  -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:8443-:443" -device e1000,netdev=n0 \
  -chardev "socket,id=ser0,path=$WORK/serial.sock,server=on,wait=off,logfile=$WORK/serial.log" -serial chardev:ser0 \
  -display none -daemonize -pidfile "$WORK/qemu.pid"

running_version() { curl -ks --max-time 5 "$BASE/healthz" 2>/dev/null | jq -r '.version // empty' 2>/dev/null || true; }
wait_version() {   # wait_version <version> <seconds>
  local deadline=$(( SECONDS + $2 ))
  while [ "$SECONDS" -lt "$deadline" ]; do
    [ "$(running_version)" = "$1" ] && return 0
    kill -0 "$(cat "$WORK/qemu.pid")" 2>/dev/null || die "the virtual machine exited"
    sleep 5
  done
  return 1
}
t0=$SECONDS
wait_version "$VERSION" "$BOOT_TIMEOUT" || die "the dashboard did not answer on HTTPS within ${BOOT_TIMEOUT}s"
pass "booted from the shipped disk; dashboard $VERSION answering on HTTPS after $(( SECONDS - t0 ))s"
# QEMU's user-mode network always leases 10.0.2.15; the login screen has to say so.
banner=""; for _ in $(seq 30); do
  grep -q 'NetScaler Dashboard appliance' "$WORK/serial.log" && grep -q 'https://10\.0\.2\.15/' "$WORK/serial.log" && { banner=1; break; }
  sleep 4
done
[ -n "$banner" ] || die "the console login screen does not show the appliance banner with its address"
grep -q 'First login' "$WORK/serial.log" || die "the console login screen does not show the first-login hint"
pass "console login screen shows the banner, the address the appliance was given and the first-login hint"

# ------------------------------------------------------------------ 3. sign-in
step "3. First sign-in"
api() { curl -ks -b "$JAR" -c "$JAR" "$@"; }
[ "$(api -o /dev/null -w '%{http_code}' "$BASE/api/appliance/status")" != 200 ] || die "the API answered without a login"
api -o /dev/null -d username=admin -d password=admin -d auth_source=local "$BASE/login"
[ "$(api -o /dev/null -w '%{http_code}' "$BASE/api/appliance/status")" = 302 ] || die "the default password was not forced to change"
api -o /dev/null -d current_password=admin -d new_password=Smoke-Test-123 -d confirm_password=Smoke-Test-123 "$BASE/change-password"
st=$(api "$BASE/api/appliance/status")
jq -e --arg v "$VERSION" '.appliance == true and .version == $v and .appliance_version == $v' <<<"$st" >/dev/null \
  || die "unexpected appliance status: $st"
pass "default password must be changed; then signed in, appliance mode reported"

# ------------------------------------------------------------ 4. junk refused
step "4. A file that is not an upgrade"
head -c 300000 /dev/urandom > "$WORK/junk.nsu"
upload() { api -o "$WORK/resp.json" -w '%{http_code}' -H 'Content-Type: application/octet-stream' --data-binary "@$1" "$BASE/api/appliance/upgrade"; }
[ "$(upload "$WORK/junk.nsu")" = 400 ] || die "junk was not refused: $(cat "$WORK/resp.json")"
pass "refused: $(jq -r .error "$WORK/resp.json")"

wait_upgrade() {   # wait_upgrade <seconds>  -> prints the final state
  local deadline=$(( SECONDS + $1 )) state=""
  while [ "$SECONDS" -lt "$deadline" ]; do
    state=$(api --max-time 5 "$BASE/api/appliance/status" 2>/dev/null | jq -r '.upgrade.state // empty' 2>/dev/null || true)
    case "$state" in success|failed|rolled_back) echo "$state"; return 0 ;; esac
    sleep 5
  done
  echo "timeout(${state:-no answer})"
}

# ------------------------------------------------------------------ 5. upgrade
step "5. Upgrade by upload"
[ "$(upload "$NSU")" = 200 ] || die "the upgrade bundle was refused: $(cat "$WORK/resp.json")"
state=$(wait_upgrade 1200)
msg=$(api "$BASE/api/appliance/status" | jq -r '.upgrade.message')
[ "$state" = success ] || die "upgrade ended as '$state': $msg"
[ "$(running_version)" = "$VERSION" ] || die "the dashboard is not healthy after the upgrade"
pass "host agent verified, loaded and restarted: $msg"

# ----------------------------------------------------------------- 6. rollback
step "6. A release that cannot start"
# A real, loadable image whose command does not exist: the container can never
# become healthy, so the agent has to bring the previous version back.
B=$WORK/bad; mkdir -p "$B/img" "$B/empty"
tar -cf "$B/img/layer.tar" -C "$B/empty" .
lsha=$(sha256sum "$B/img/layer.tar" | cut -d' ' -f1)
cat > "$B/config.json" <<EOF
{"architecture":"amd64","os":"linux","config":{"Cmd":["/this-release-cannot-start"],"Labels":{"org.opencontainers.image.version":"99.0.0"}},"rootfs":{"type":"layers","diff_ids":["sha256:$lsha"]}}
EOF
csha=$(sha256sum "$B/config.json" | cut -d' ' -f1)
mv "$B/config.json" "$B/img/$csha.json"
echo "[{\"Config\":\"$csha.json\",\"RepoTags\":[\"netscaler-dashboard:99.0.0\"],\"Layers\":[\"layer.tar\"]}]" > "$B/img/manifest.json"
tar -czf "$B/image.tar.gz" -C "$B/img" manifest.json "$csha.json" layer.tar
cat > "$B/manifest.json" <<EOF
{"format":1,"product":"netscaler-dashboard","version":"99.0.0",
 "image":{"file":"image.tar.gz","ref":"netscaler-dashboard:99.0.0","sha256":"$(sha256sum "$B/image.tar.gz" | cut -d' ' -f1)"}}
EOF
tar --format=ustar -cf "$WORK/bad.nsu" -C "$B" manifest.json image.tar.gz
[ "$(upload "$WORK/bad.nsu")" = 200 ] || die "the test bundle was refused: $(cat "$WORK/resp.json")"
state=$(wait_upgrade 1500)
msg=$(api "$BASE/api/appliance/status" | jq -r '.upgrade.message')
[ "$state" = rolled_back ] || die "expected a rollback, got '$state': $msg"
wait_version "$VERSION" 120 || die "the previous version is not serving after the rollback"
api "$BASE/api/appliance/status" | jq -e '.appliance == true' >/dev/null || die "the session/data did not survive the rollback"
pass "rolled back by itself: $msg"

# ------------------------------------------------------------------ 7. console
step "7. Console menu"
python3 "$SRC/appliance/console-test.py" "$WORK/serial.sock" "$BASE" || die "the console menu test failed"

printf '\n\033[1;32mAll appliance checks passed for %s.\033[0m\n' "$VERSION"
