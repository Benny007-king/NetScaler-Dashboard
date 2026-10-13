#!/bin/bash
# Tests the host-side upgrade agent (rootfs/opt/ns-appliance/bin/ns-upgrade) against
# a hostile data directory, and that normal upgrades and rollbacks still work.
#
# The agent runs as root and reads a directory the dashboard container can write.
# Whatever is planted there - links, directories, odd bundles - must never make it
# touch anything outside that directory.
#
# It replaces system paths, so it only runs inside a throwaway container:
#
#   docker run --rm -v "$PWD:/src:ro" debian:13 bash /src/appliance/test-upgrade-agent.sh
set -u
[ -f /.dockerenv ] || { echo "run this inside a throwaway container (see the header)"; exit 2; }

export DEBIAN_FRONTEND=noninteractive
command -v jq >/dev/null 2>&1 || { apt-get -qq update >/dev/null 2>&1; apt-get -qq install -y jq >/dev/null 2>&1; }

# ---- stand-ins for docker / systemctl / curl, and a fast clock for the health wait
mkdir -p /stubs
cat > /stubs/docker <<'EOF'
#!/bin/bash
echo "docker $*" >> /tmp/docker.log
STATE=/tmp/docker-images; touch "$STATE"
has() { grep -qx "$1" "$STATE"; }
add() { has "$1" || echo "$1" >> "$STATE"; }
case "$1" in
  image)
    case "$2" in
      inspect) shift 2; fmt=""; if [ "$1" = "-f" ]; then fmt="$2"; shift 2; fi
               has "$1" || exit 1
               [ -n "$fmt" ] && echo "${TEST_VER:-${1##*:}}"
               exit 0 ;;
      prune) exit 0 ;;
    esac ;;
  load) add "netscaler-dashboard:${TEST_LOAD_TAG:-99.0.0}"; echo "Loaded image: netscaler-dashboard:${TEST_LOAD_TAG:-99.0.0}"; exit 0 ;;
  tag)  add "$3"; exit 0 ;;
esac
exit 0
EOF
cat > /stubs/systemctl <<'EOF'
#!/bin/bash
echo "systemctl $*" >> /tmp/systemctl.log
EOF
cat > /stubs/curl <<'EOF'
#!/bin/bash
echo "{\"ok\":true,\"version\":\"${TEST_HEALTH_VER:-}\"}"
EOF
cat > /stubs/sleep <<'EOF'
#!/bin/bash
exec /usr/bin/sleep 0.01
EOF
cat > /stubs/date <<'EOF'
#!/bin/bash
if [ "${HEALTH_FAST:-}" = 1 ] && [ "${1:-}" = "+%s" ]; then
  n=$(cat /tmp/fakeclock 2>/dev/null || /usr/bin/date +%s); echo "$n"; echo $((n+40)) > /tmp/fakeclock; exit 0
fi
exec /usr/bin/date "$@"
EOF
chmod +x /stubs/*
export PATH=/stubs:$PATH

tr -d '\r' < /src/appliance/rootfs/opt/ns-appliance/bin/ns-upgrade > /ns-upgrade && chmod +x /ns-upgrade
UPG=/ns-upgrade
DATA=/var/lib/ns-dashboard/data; UP=$DATA/upgrade
pass=0; bad=0
ok()  { echo "   ok    $*"; pass=$((pass+1)); }
no()  { echo "   FAIL  $*"; bad=$((bad+1)); }
reset() {
  rm -rf /var/lib/ns-dashboard /run/ns-upgrade.lock /tmp/docker.log /tmp/systemctl.log /tmp/docker-images /tmp/fakeclock /root/victim.txt /root/vdir
  mkdir -p "$UP"; printf 'SECRET\n' > /root/victim.txt; chmod 600 /root/victim.txt
  echo "netscaler-dashboard:current" > /tmp/docker-images
  unset TEST_LOAD_TAG TEST_HEALTH_VER TEST_VER HEALTH_FAST
}
victim_intact() { [ "$(cat /root/victim.txt 2>/dev/null)" = SECRET ]; }
state() { jq -r '.state' "$UP/status.json" 2>/dev/null; }
bundle() {   # bundle <version> [uppercase]   -> writes $UP/incoming.nsu
  local d; d=$(mktemp -d); ( cd "$d"
    printf 'image-%s\n' "$1" > image.tar.gz
    mkdir -p h/rootfs; printf '#!/bin/sh\necho "host-install ran for $2" >> /tmp/hostinstall.log\n' > h/host-install.sh
    tar -czf host.tar.gz -C h host-install.sh rootfs
    is=$(sha256sum image.tar.gz | cut -d' ' -f1); hs=$(sha256sum host.tar.gz | cut -d' ' -f1)
    [ "${2:-}" = uppercase ] && is=$(echo "$is" | tr a-f A-F)
    printf '{"format":1,"product":"netscaler-dashboard","version":"%s","image":{"file":"image.tar.gz","ref":"netscaler-dashboard:%s","sha256":"%s"},"host":{"file":"host.tar.gz","sha256":"%s"}}\n' "$1" "$1" "$is" "$hs" > manifest.json
    tar --format=ustar -cf "$UP/incoming.nsu" manifest.json image.tar.gz host.tar.gz )
  rm -rf "$d"
}

echo "== a hostile data directory"
reset; ln -s /root/victim.txt "$UP/status.json.tmp"; echo x > "$UP/request"; "$UPG" >/dev/null 2>&1
victim_intact && ok "a link planted at status.json.tmp: the root file is untouched" || no "link at status.json.tmp: ROOT FILE OVERWRITTEN"

reset; ln -s /root/victim.txt "$UP/status.json"; echo x > "$UP/request"; "$UPG" >/dev/null 2>&1
victim_intact && ok "a link planted at status.json: the root file is untouched" || no "link at status.json: ROOT FILE OVERWRITTEN"
[ -f "$UP/status.json" ] && [ ! -L "$UP/status.json" ] && [ "$(state)" = failed ] && ok "  ...and status.json is a real file again, saying 'failed'" || no "  ...status.json was not replaced by a real file"

reset; mkdir -p /root/vdir; rm -rf "$UP"; ln -s /root/vdir "$UP"; echo x > /root/vdir/request; "$UPG" >/dev/null 2>&1
[ -z "$(ls -A /root/vdir | grep -v '^request$')" ] && [ -e /root/vdir/request ] && ok "the upgrade directory replaced by a link: nothing written or deleted through it" \
  || no "upgrade directory as a link: root touched the target: $(ls -A /root/vdir | tr '\n' ' ')"

reset; ln -s /root/victim.txt "$UP/incoming.nsu"; echo x > "$UP/request"; "$UPG" >/dev/null 2>&1
victim_intact && [ "$(state)" = failed ] && ok "incoming.nsu is a link: refused, target untouched" || no "incoming.nsu as a link: state=$(state)"

reset; mkdir "$UP/status.json"; echo x > "$UP/request"; "$UPG" >/dev/null 2>&1
[ -f "$UP/status.json" ] && [ "$(state)" = failed ] && ok "status.json planted as a directory: replaced, status still reported" || no "status.json as a directory: no status any more"

reset; ln -s /root/victim.txt "$UP/request"; "$UPG" >/dev/null 2>&1
victim_intact && [ ! -L "$UP/request" ] && ok "the request flag is a link: consumed, target untouched" || no "request flag as a link"

reset; d=$(mktemp -d); ( cd "$d"
  printf '{"format":1,"product":"netscaler-dashboard","version":"99.9.9","image":{"file":"image.tar.gz","ref":"netscaler-dashboard:99.9.9","sha256":"%s"}}\n' "$(printf 'payload\n' | sha256sum | cut -d' ' -f1)" > manifest.json
  ln -s /root/victim.txt image.tar.gz; tar --format=ustar -cf b.tar manifest.json image.tar.gz
  rm image.tar.gz; printf 'payload\n' > image.tar.gz; tar --format=ustar -rf b.tar image.tar.gz; cp b.tar "$UP/incoming.nsu" )
echo x > "$UP/request"; TEST_LOAD_TAG=99.9.9 TEST_HEALTH_VER=99.9.9 "$UPG" >/dev/null 2>&1
victim_intact && ok "a bundle member that is first a link, then a file of the same name: the root file is untouched" || no "link-then-file member: ROOT FILE OVERWRITTEN"

echo "== normal operation"
reset; rm -f /tmp/hostinstall.log; bundle 99.9.9; echo x > "$UP/request"; TEST_LOAD_TAG=99.9.9 TEST_HEALTH_VER=99.9.9 TEST_VER=1.0.0 "$UPG" >/tmp/run.log 2>&1; rc=$?
[ $rc = 0 ] && [ "$(state)" = success ] && grep -q 'host-install ran for 99.9.9' /tmp/hostinstall.log 2>/dev/null && grep -q 'systemctl restart ns-dashboard' /tmp/systemctl.log \
  && ok "a valid bundle installs: success, host files installed, service restarted" || { no "valid bundle: exit $rc state $(state)"; tail -5 /tmp/run.log; }
[ ! -e "$UP/incoming.nsu" ] && [ ! -e /var/lib/ns-dashboard/upgrade-work ] && ok "  ...the bundle and the work directory are cleaned up" || no "  ...leftovers"
[ "$(stat -c %a "$UP/status.json")" = 644 ] && ok "  ...status.json is readable by the dashboard" || no "  ...status.json mode $(stat -c %a "$UP/status.json")"

reset; bundle 99.9.9 uppercase; echo x > "$UP/request"; TEST_LOAD_TAG=99.9.9 TEST_HEALTH_VER=99.9.9 TEST_VER=1.0.0 "$UPG" >/dev/null 2>&1
[ "$(state)" = success ] && ok "upper-case checksums are accepted, as the dashboard accepts them" || no "upper-case checksum: state $(state)"

reset; bundle 99.9.9; echo x > "$UP/request"; TEST_LOAD_TAG=99.9.9 TEST_HEALTH_VER=1.0.0 TEST_VER=1.0.0 HEALTH_FAST=1 "$UPG" >/dev/null 2>&1
[ "$(state)" = rolled_back ] && ok "a version that never becomes healthy is rolled back" || no "unhealthy version: state $(state)"

reset; bundle 0.0.1; echo x > "$UP/request"; TEST_VER=1.0.0 "$UPG" >/dev/null 2>&1
[ "$(state)" = failed ] && jq -r .message "$UP/status.json" | grep -q 'Downgrades' && ok "a downgrade is refused" || no "downgrade: state $(state)"

reset; "$UPG" >/dev/null 2>&1; rc=$?
[ $rc = 0 ] && [ ! -e "$UP/status.json" ] && ok "no request flag: does nothing" || no "no request: exit $rc"

echo; echo "passed $pass, failed $bad"; [ $bad = 0 ]
