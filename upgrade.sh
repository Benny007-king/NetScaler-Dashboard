#!/usr/bin/env bash
# One-command upgrade: pull the latest release and rebuild the version-tagged image.
# Re-attaches to main and fast-forwards, which also recovers a detached-HEAD
# checkout (e.g. after `git checkout vX.Y.Z`), so the build never ends up
# mislabelled with an old version. Honors COMPOSE_FILE if you run behind the proxy.
set -euo pipefail
cd "$(dirname "$0")"

echo "==> Updating source (main)…"
git checkout main
git pull --ff-only

APP_VERSION="$(tr -d ' \t\r\n' < VERSION)"
export APP_VERSION
echo "==> Building netscaler-dashboard:${APP_VERSION} …"
docker compose up -d --build

echo "==> Now running:"
docker inspect netscaler-dashboard \
  --format '{{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null \
  || echo "  (image label unavailable — check 'docker images netscaler-dashboard')"
