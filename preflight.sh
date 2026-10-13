#!/usr/bin/env bash
# Check everything needed to run the NetScaler Dashboard and print a download link
# for whatever is missing. Read-only: it installs nothing and changes nothing.
#
#   ./preflight.sh            # check the Docker install (recommended)
#   ./preflight.sh python     # check running from source instead
cd "$(dirname "$0")" 2>/dev/null || true

MODE="${1:-docker}"
MISSING=0
WARN=0

case "$(uname -s)" in
  Darwin) OS="macOS" ;;
  Linux)  OS="Linux" ;;
  *)      OS="Windows" ;;   # Git Bash / MSYS
esac

if [ -t 1 ]; then
  G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[2m'; B=$'\033[1m'; N=$'\033[0m'
else
  G=""; R=""; Y=""; D=""; B=""; N=""
fi

ok()   { printf "  %s[ OK ]%s %-22s %s\n"        "$G" "$N" "$1" "$D$2$N"; }
bad()  { printf "  %s[MISS]%s %-22s %s\n"        "$R" "$N" "$1" "$2"; MISSING=$((MISSING+1)); }
warn() { printf "  %s[WARN]%s %-22s %s\n"        "$Y" "$N" "$1" "$2"; WARN=$((WARN+1)); }
link() { printf "         %s-> %s%s\n"           "$D" "$1" "$N"; }

# ---- per-OS download links -------------------------------------------------
case "$OS" in
  macOS)
    L_DOCKER="https://www.docker.com/products/docker-desktop/  (or OrbStack: https://orbstack.dev/)"
    L_GIT="https://git-scm.com/download/mac   (or: xcode-select --install)"
    L_PY="https://www.python.org/downloads/macos/   (or: brew install python)" ;;
  Linux)
    L_DOCKER="https://docs.docker.com/engine/install/"
    L_GIT="https://git-scm.com/download/linux   (e.g. sudo apt install git)"
    L_PY="your package manager, e.g. sudo apt install python3 python3-pip python3-venv" ;;
  *)
    L_DOCKER="https://www.docker.com/products/docker-desktop/   (needs WSL2: https://learn.microsoft.com/windows/wsl/install)"
    L_GIT="https://git-scm.com/download/win"
    L_PY="https://www.python.org/downloads/windows/   (tick \"Add python.exe to PATH\")" ;;
esac
L_COMPOSE="https://docs.docker.com/compose/install/linux/"

echo
printf "%sNetScaler Dashboard - preflight check%s   (%s, %s install)\n" "$B" "$N" "$OS" "$MODE"
echo "--------------------------------------------------------------------"

# ---- always needed ---------------------------------------------------------
if command -v git >/dev/null 2>&1; then
  ok "Git" "$(git --version 2>/dev/null)"
else
  bad "Git" "needed to clone and to run upgrade.sh"; link "$L_GIT"
fi

if [ "$MODE" = "python" ]; then
  # ---- running from source -------------------------------------------------
  PY=""
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info>=(3,9) else 1)' 2>/dev/null; then
      PY="$c"; break
    fi
  done
  if [ -n "$PY" ]; then
    ok "Python 3.9+" "$($PY --version 2>&1)"
    if "$PY" -m pip --version >/dev/null 2>&1; then
      ok "pip" "$($PY -m pip --version 2>&1 | cut -d' ' -f1-2)"
    else
      bad "pip" "needed for: pip install -r requirements.txt"; link "$L_PY"
    fi
  else
    bad "Python 3.9+" "the app targets Python 3.9 or newer"; link "$L_PY"
  fi
else
  # ---- containerised (default) ---------------------------------------------
  if command -v docker >/dev/null 2>&1; then
    ok "Docker" "$(docker --version 2>/dev/null)"
    if docker info >/dev/null 2>&1; then
      ok "Docker daemon" "running"
    else
      bad "Docker daemon" "installed but not running - start Docker Desktop / the docker service"
    fi
    if docker compose version >/dev/null 2>&1; then
      ok "Docker Compose v2" "$(docker compose version --short 2>/dev/null)"
    else
      bad "Docker Compose v2" "the 'docker compose' plugin (not the old docker-compose)"; link "$L_COMPOSE"
    fi
  else
    bad "Docker" "runs the dashboard container"; link "$L_DOCKER"
    bad "Docker Compose v2" "ships with Docker Desktop"; link "$L_COMPOSE"
  fi
fi

# ---- environment (warnings only) -------------------------------------------
for p in 443 80; do
  BUSY=""
  # ss first: lsof run by an ordinary user does not see another user's listener
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | grep -q ":$p " && BUSY=1
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1 && BUSY=1
  elif command -v netstat >/dev/null 2>&1; then
    netstat -an 2>/dev/null | grep -qE "[:.]$p .*LISTEN" && BUSY=1
  else
    continue
  fi
  if [ -n "$BUSY" ]; then
    warn "Port $p" "already in use - free it, or set HOST_PORT in .env to publish on another port"
  else
    ok "Port $p" "free"
  fi
done

echo "--------------------------------------------------------------------"
if [ "$MISSING" -eq 0 ]; then
  printf "%sAll required dependencies present.%s" "$G" "$N"
  [ "$WARN" -gt 0 ] && printf "  (%s warning(s) above)" "$WARN"
  echo; echo
  if [ "$MODE" = "python" ]; then
    echo "  Next:  pip install -r requirements.txt  &&  python app.py"
  else
    echo "  Next:  docker compose up -d --build      (then open https://localhost/)"
  fi
  echo
  exit 0
fi
printf "%s%s required dependency/ies missing - install the link(s) above, then re-run.%s\n\n" "$R" "$MISSING" "$N"
echo "  Full guide: https://net-scaler-dashboard-web.vercel.app/docs.html#deps"
echo
exit 1
