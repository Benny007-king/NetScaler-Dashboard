#!/usr/bin/env python3
"""
NetScaler Dashboard (Dual-Stack: NITRO + Next-Gen API)
Compat edition + Unlock Users, with .env configuration (python-dotenv)
UPDATED: Anti-Lockup HA Tracking, Bulletproof nsconfig alerts, Advanced Dynamic Sessions
PRODUCTION READY (GUNICORN WSGI)
"""
from __future__ import annotations

import os
import sys
import json
import re
import hashlib
import hmac
import logging
import secrets
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import pytz
import requests

import appliance
import db
import security
from flask import (
    Flask, render_template, jsonify, request, redirect, url_for,
    session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

# ======================================================================================
# Persistent data directory — ALL runtime state lives here so code updates
# (git pull / image rebuild) never touch it. Back it with a Docker named volume
# or a host bind mount and you never have to reconfigure again.
# ======================================================================================
DATA_DIR = os.getenv("DATA_DIR", "data")
try: os.makedirs(DATA_DIR, exist_ok=True)
except Exception: pass

def _data_path(name):
    return os.path.join(DATA_DIR, name)

def _env_int(name, default, minimum=None):
    """A whole number from the environment. Anything unusable - text, a value in
    quotes left there by an env file, a number below the minimum - falls back to
    the default instead of stopping the application from starting."""
    raw = str(os.getenv(name, '') or '').strip().strip('"\'').strip()
    try:
        v = int(raw) if raw else default
    except ValueError:
        print(f"WARNING: {name}={raw!r} is not a number; using {default}", file=sys.stderr)
        v = default
    return default if (minimum is not None and v < minimum) else v

def _write_json(path, obj, **dump_args):
    """Write a settings file so that a crash, a power cut or a full disk can never
    leave it empty or half-written: the new content goes to a temporary file and
    only replaces the old one once it is complete."""
    tmp = f"{path}.tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(obj, f, **dump_args)
        f.flush()
        try: os.fsync(f.fileno())
        except OSError: pass
    os.replace(tmp, path)

def _read_path(data_file, legacy_name):
    """Path to read from: the DATA_DIR file if present, else a legacy root file
    (belt-and-suspenders in case a migration didn't run). Writes always target
    the DATA_DIR file."""
    if os.path.exists(data_file):
        return data_file
    if legacy_name and os.path.exists(legacy_name):
        return legacy_name
    return data_file

def _migrate_legacy(pairs):
    """Best-effort one-time move of runtime files from the repo root into DATA_DIR.
    Runs before anything is loaded; never overwrites an existing target."""
    import shutil
    for legacy, target in pairs:
        try:
            if (legacy and target and os.path.exists(legacy) and not os.path.exists(target)
                    and os.path.abspath(legacy) != os.path.abspath(target)):
                os.makedirs(os.path.dirname(target) or '.', exist_ok=True)
                shutil.move(legacy, target)   # cross-filesystem safe (copy+remove)
        except Exception:
            pass  # if it can't move, loaders still fall back to the legacy path

AUTH_CONFIG_FILE = os.getenv('AUTH_CONFIG_FILE') or _data_path('auth_config.json')
NODES_CONFIG_FILE = os.getenv('NODES_CONFIG_FILE') or _data_path('nodes_config.json')
LDAP_CONFIG_FILE = os.getenv('LDAP_CONFIG_FILE') or _data_path('ldap_config.json')
FAILOVER_HISTORY_FILE = os.getenv('FAILOVER_HISTORY_FILE') or _data_path('failover_history.json')
HA_STATE_FILE = os.getenv('HA_STATE_FILE') or _data_path('ha_last_state.json')
SECURITY_FILE = os.getenv('SECURITY_FILE') or _data_path('security_checklist.json')
APP_SECRET_FILE = os.getenv('APP_SECRET_FILE') or _data_path('.app_secret')
LOG_FILE = os.getenv('APP_LOG_FILE') or _data_path('netscaler_complete.log')

# Move any legacy root-level files into DATA_DIR once (before anything is loaded).
_migrate_legacy([
    ('auth_config.json', AUTH_CONFIG_FILE),
    ('nodes_config.json', NODES_CONFIG_FILE),
    ('ldap_config.json', LDAP_CONFIG_FILE),
    ('failover_history.json', FAILOVER_HISTORY_FILE),
    ('ha_last_state.json', HA_STATE_FILE),
    ('.app_secret', APP_SECRET_FILE),
    ('dashboard.db', db.DB_FILE),
    ('dashboard.db-wal', db.DB_FILE + '-wal'),
    ('dashboard.db-shm', db.DB_FILE + '-shm'),
])
try:
    import shutil as _sh
    if os.path.isdir('certs') and not os.path.isdir(_data_path('certs')):
        _sh.move('certs', _data_path('certs'))
except Exception: pass

# ======================================================================================
# LDAP Configuration — env vars are defaults; a gitignored ldap_config.json
# (editable from the Settings UI) overrides them at runtime.
# ======================================================================================
AUTH_BACKENDS = {x.strip().lower() for x in os.getenv("AUTH_BACKENDS", "local").split(",") if x.strip()}

def _as_bool(v, default=False):
    if isinstance(v, bool): return v
    if v is None: return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")

_LDAP_ENV_DEFAULTS = {
    "enabled": _as_bool(os.getenv("LDAP_ENABLED", "0")) or ("ldap" in AUTH_BACKENDS),
    "server": os.getenv("LDAP_SERVER", ""),
    "port": _env_int("LDAP_PORT", 389, 1),
    "use_ssl": _as_bool(os.getenv("LDAP_USE_SSL", "0")),
    "base_dn": os.getenv("LDAP_BASE_DN", ""),
    "bind_dn": os.getenv("LDAP_BIND_DN", ""),
    "bind_pw": os.getenv("LDAP_BIND_PASSWORD", ""),
    "user_attr": os.getenv("LDAP_USER_ATTRIBUTE", "sAMAccountName"),
    "allowed_group_dn": os.getenv("LDAP_ALLOWED_GROUP_DN", ""),
    "timeout": _env_int("LDAP_TIMEOUT_SECS", 10, 1),
}

def load_ldap_config() -> dict:
    cfg = dict(_LDAP_ENV_DEFAULTS)
    try:
        src = _read_path(LDAP_CONFIG_FILE, 'ldap_config.json')
        if os.path.exists(src):
            with open(src, "r", encoding="utf-8") as f:
                stored = json.load(f)
            if isinstance(stored, dict):
                cfg.update({k: v for k, v in stored.items() if k in cfg})
    except Exception:
        pass
    cfg["enabled"] = _as_bool(cfg.get("enabled"))
    cfg["use_ssl"] = _as_bool(cfg.get("use_ssl"))
    try: cfg["port"] = int(cfg.get("port") or 389)
    except Exception: cfg["port"] = 389
    try: cfg["timeout"] = int(cfg.get("timeout") or 10)
    except Exception: cfg["timeout"] = 10
    return cfg

LDAP_CFG = load_ldap_config()

def get_ldap_config() -> dict:
    return LDAP_CFG

def save_ldap_config(new: dict) -> dict:
    global LDAP_CFG
    merged = dict(LDAP_CFG)
    for k in _LDAP_ENV_DEFAULTS:
        if k in new:
            merged[k] = new[k]
    if not new.get("bind_pw"):                     # blank = keep the stored password
        merged["bind_pw"] = LDAP_CFG.get("bind_pw", "")
    _write_json(LDAP_CONFIG_FILE, merged, indent=2)
    LDAP_CFG = load_ldap_config()
    db.documents_changed()
    return LDAP_CFG

def ldap_enabled() -> bool:
    c = get_ldap_config()
    return bool(c.get("enabled")) and bool(c.get("server"))

# ======================================================================================
# Environment Setup
# ======================================================================================
try:
    from dotenv import load_dotenv
    BASE_DIR = Path(__file__).resolve().parent
    env_main  = BASE_DIR / os.getenv("ENV_FILE", ".env")
    env_local = BASE_DIR / os.getenv("ENV_FILE_LOCAL", ".env.local")

    if env_main.exists(): load_dotenv(env_main, override=False)
    if env_local.exists(): load_dotenv(env_local, override=True)
except Exception: pass

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception: pass

# ======================================================================================
# Flask App Initialization & Logging
# ======================================================================================
def _load_or_create_secret() -> str:
    """Use APP_SECRET if set, else a persisted random secret so sessions survive
    restarts without shipping a known default key."""
    env = os.getenv("APP_SECRET")
    if env: return env
    path = APP_SECRET_FILE
    try:
        read_from = _read_path(path, '.app_secret')
        if os.path.exists(read_from):
            with open(read_from) as f:
                s = f.read().strip()
            if s: return s
        s = secrets.token_hex(32)
        try:
            # Create with 0600 up-front to avoid a world-readable window.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f: f.write(s)
        except Exception:
            with open(path, "w") as f: f.write(s)
            try: os.chmod(path, 0o600)
            except Exception: pass
        return s
    except Exception:
        return secrets.token_hex(32)

DEFAULT_SESSION_TIMEOUT_MIN = 15

app = Flask(__name__)
app.secret_key = _load_or_create_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=(os.getenv('APP_SSL', '1').lower() in ('1', 'true', 'yes')
                           or os.getenv('TRUST_PROXY', '0').lower() in ('1', 'true', 'yes')),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=DEFAULT_SESSION_TIMEOUT_MIN),
)

def get_session_timeout_min() -> int:
    """Inactivity timeout in minutes (from settings, default 15)."""
    try:
        v = int(NETSCALER_CONFIG.get('session_timeout_minutes', DEFAULT_SESSION_TIMEOUT_MIN))
        return v if v > 0 else DEFAULT_SESSION_TIMEOUT_MIN
    except Exception:
        return DEFAULT_SESSION_TIMEOUT_MIN

def apply_session_timeout():
    """Sync Flask's cookie lifetime with the configured timeout."""
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=get_session_timeout_min())

@app.before_request
def _check_scope_params():
    """`instance` and `node` in the query select what an API call talks to. A
    value that does not exist used to fall through to the first instance (so a
    tab left open on a deleted instance showed another one's data) or to a 500."""
    if not request.path.startswith('/api/'):
        return
    # Settings and commands are small; only the upgrade upload carries a file.
    if (request.method == 'POST' and request.path != '/api/appliance/upgrade'
            and (request.content_length or 0) > 2 * 1024 * 1024):
        return jsonify({'error': 'Request too large'}), 413
    if not session.get('logged_in'):
        return
    inst = request.args.get('instance')
    if inst is not None and inst != '' and str(inst) not in {str(i.get('id')) for i in get_instances()}:
        return jsonify({'error': 'Unknown instance', 'code': 'unknown_instance'}), 404
    node = request.args.get('node')
    if node is not None and node != '' and node not in ('primary', 'secondary'):
        return jsonify({'error': "node must be 'primary' or 'secondary'"}), 400
    if request.path.startswith(_NETSCALER_ONLY) and get_mode(inst) == 'sdx':
        return jsonify({'error': 'This instance is an SDX Management Service. Open one of its NetScaler instances '
                                 'for this (add it as an instance of its own).', 'code': 'sdx'}), 409

# Endpoints that talk to a NetScaler, not to an SDX Management Service.
_NETSCALER_ONLY = ('/api/system-stats', '/api/ha-status', '/api/lb-vservers', '/api/services', '/api/certificates',
                   '/api/user-sessions', '/api/session-', '/api/failover-history', '/api/unlock-user', '/api/security/',
                   '/api/nextgen-debug', '/api/detect-api')

@app.before_request
def _enforce_idle_timeout():
    if not session.get('logged_in'):
        return
    now = time.time()
    last = session.get('last_active', now)
    if now - last > get_session_timeout_min() * 60:
        session.clear()
        if request.path.startswith('/api/') or request.is_json:
            return jsonify({'error': 'Session expired', 'code': 'session_expired'}), 401
        return redirect(url_for('login'))
    # Background auto-refresh polls must NOT count as user activity, otherwise an
    # open dashboard tab would never time out.
    if request.headers.get('X-Idle-Refresh') != '1':
        session['last_active'] = now
        session.permanent = True

# Honor X-Forwarded-* when running behind a reverse proxy (set TRUST_PROXY=1).
if os.getenv('TRUST_PROXY', '0').lower() in ('1', 'true', 'yes'):
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Older Pythons do not know the font type the bundled fonts are served as.
import mimetypes
mimetypes.add_type('font/woff2', '.woff2')

# Content Security Policy — the page loads nothing from other hosts: its libraries
# and fonts are served from static/vendor.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self' data:; "
    "img-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"
)

@app.after_request
def _security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('Referrer-Policy', 'no-referrer')
    resp.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    resp.headers.setdefault('Content-Security-Policy', _CSP)
    # Bundled libraries carry their version in the file name, so they never change.
    if request.path.startswith('/static/vendor/') and resp.status_code == 200:
        resp.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
    # HSTS only makes sense once we're actually on HTTPS.
    if request.is_secure and os.getenv('HSTS_ENABLED', '1').lower() in ('1', 'true', 'yes'):
        resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    return resp

# Rotating log so it can't grow without bound (default 5 MB × 3 backups = ~20 MB cap).
from logging.handlers import RotatingFileHandler
_log_max_bytes = _env_int("APP_LOG_MAX_BYTES", 5 * 1024 * 1024, 1024)
_log_backups = _env_int("APP_LOG_BACKUPS", 3, 0)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=_log_max_bytes, backupCount=_log_backups, encoding='utf-8'),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# ======================================================================================
# Local Dashboard Auth & HA State Tracking Variables
# ======================================================================================
DEFAULT_USERNAME = os.getenv('UI_DEFAULT_USERNAME', 'admin')
DEFAULT_PASSWORD = os.getenv('UI_DEFAULT_PASSWORD', 'admin')
PASSWORD_MIN_LENGTH = 8

# Time zone the dashboard shows and records times in. It comes from TZ - on the
# appliance that is the zone chosen on the console menu, with Docker it is TZ in
# .env - and stays Asia/Jerusalem when nothing is set, as it always was.
_DEFAULT_TZ = "Asia/Jerusalem"

def _app_timezone():
    name = (os.environ.get("TZ") or "").strip().lstrip(":")
    if name:
        try:
            return name, pytz.timezone(name)
        except Exception:
            logger.warning("TZ=%r is not a time zone this system knows - using %s", name, _DEFAULT_TZ)
            # the C library would silently fall back to UTC; keep both in step
            os.environ["TZ"] = _DEFAULT_TZ
            if hasattr(time, "tzset"):
                time.tzset()
    return _DEFAULT_TZ, pytz.timezone(_DEFAULT_TZ)

APP_TZ_NAME, APP_TZ = _app_timezone()

@app.context_processor
def _template_globals():
    return {"app_tz": APP_TZ_NAME}

# Bounded retention for failover history: when it reaches 80% of the cap, prune
# back to 50% (keeping the most recent events) so the file never fills up.
FAILOVER_MAX_EVENTS = _env_int("FAILOVER_MAX_EVENTS", 5000, 10)

def _prune_failover_history(history):
    high = int(FAILOVER_MAX_EVENTS * 0.8)
    low = int(FAILOVER_MAX_EVENTS * 0.5)
    if len(history) >= high:
        # Keep the newest `low` events, preserving chronological (ascending) order.
        history = sorted(history, key=lambda e: e.get('timestamp', ''))[-low:]
    return history

# Releases up to 1.16.0 stored the admin password as an unsalted SHA-256 hex
# digest. Such a value still signs in, and is replaced on that sign-in.
_LEGACY_HASH_RE = re.compile(r'[0-9a-fA-F]{64}')

def hash_password(password: str) -> str:
    """Salted, slow hash of the local admin password: scrypt, or PBKDF2 where
    this Python was built without scrypt."""
    try: return generate_password_hash(password, method='scrypt')
    except Exception: return generate_password_hash(password, method='pbkdf2:sha256')

def is_legacy_hash(stored) -> bool:
    return isinstance(stored, str) and bool(_LEGACY_HASH_RE.fullmatch(stored))

def verify_password(password: str, stored) -> bool:
    if not isinstance(stored, str) or not stored: return False
    if is_legacy_hash(stored):
        return hmac.compare_digest(hashlib.sha256(password.encode('utf-8')).hexdigest(), stored.lower())
    try: return check_password_hash(stored, password)      # constant-time inside
    except Exception: return False

def load_auth_config() -> dict:
    src = _read_path(AUTH_CONFIG_FILE, 'auth_config.json')
    if os.path.exists(src):
        try:
            with open(src, 'r', encoding='utf-8') as f: cfg = json.load(f)
            if (isinstance(cfg, dict) and isinstance(cfg.get('username'), str) and cfg['username']
                    and isinstance(cfg.get('password_hash'), str) and cfg['password_hash']):
                return cfg
            raise ValueError('it does not hold a login')
        except Exception as e:
            # A login that exists but cannot be read must never quietly turn back
            # into the published default. Local sign-in stays closed until an
            # administrator resets it on purpose (appliance console: "Reset the web
            # admin password"; otherwise delete the file and restart).
            logger.error(f"The admin login file {src} cannot be used ({e}). Local sign-in is disabled until it is reset.")
            return {'username': DEFAULT_USERNAME, 'password_hash': '', 'is_default_password': False,
                    'unreadable': True}
    cfg = {
        'username': DEFAULT_USERNAME, 'password_hash': hash_password(DEFAULT_PASSWORD),
        'is_default_password': True, 'created_at': datetime.now(APP_TZ).isoformat(),
        'last_login': None, 'login_attempts': 0, 'last_password_change': None
    }
    save_auth_config(cfg)
    return cfg

def save_auth_config(config: dict) -> None:
    if config.get('unreadable'):
        return                      # never write over a login file we could not read
    try:
        _write_json(AUTH_CONFIG_FILE, config, indent=2, ensure_ascii=False)
        db.documents_changed()
    except Exception as e:
        logger.error(f"Error saving auth config: {e}")

auth_config = load_auth_config()

# ---- sign-in throttling ---------------------------------------------------------------
# After LOGIN_MAX_FAILURES wrong attempts from one address within the window, that
# address has to wait LOGIN_LOCKOUT_SECS. It is per address, so somebody guessing
# passwords cannot lock the real administrator out from another machine.
try: LOGIN_MAX_FAILURES = max(1, int(os.getenv('LOGIN_MAX_FAILURES', '5')))
except ValueError: LOGIN_MAX_FAILURES = 5
try: LOGIN_LOCKOUT_SECS = max(1, int(os.getenv('LOGIN_LOCKOUT_SECS', '300')))
except ValueError: LOGIN_LOCKOUT_SECS = 300
_LOGIN_WINDOW_SECS = 900
_login_fails = {}                    # address -> [failures, first failure, blocked until]
_login_lock = threading.Lock()

def _login_wait(addr) -> int:
    """Seconds this address still has to wait before it may try again (0 = go ahead)."""
    with _login_lock:
        rec = _login_fails.get(addr)
        return max(0, int(rec[2] - time.time() + 0.999)) if rec else 0

def _login_failed(addr) -> None:
    now = time.time()
    with _login_lock:
        if len(_login_fails) > 10000:            # bounded, whatever is thrown at it
            for k in [k for k, v in _login_fails.items() if v[2] < now and now - v[1] > _LOGIN_WINDOW_SECS]:
                _login_fails.pop(k, None)
            if len(_login_fails) > 10000: _login_fails.clear()
        rec = _login_fails.get(addr)
        if not rec or now - rec[1] > _LOGIN_WINDOW_SECS:
            rec = _login_fails[addr] = [0, now, 0.0]
        rec[0] += 1
        if rec[0] >= LOGIN_MAX_FAILURES:
            rec[0], rec[1], rec[2] = 0, now, now + LOGIN_LOCKOUT_SECS

def _login_succeeded(addr) -> None:
    with _login_lock:
        _login_fails.pop(addr, None)

def _login_page(status=200):
    return render_template('login.html', ldap_on=ldap_enabled(),
                           show_default_hint=bool(auth_config.get('is_default_password')),
                           app_version=appliance.app_version()), status

def load_failover_history():
    try:
        if os.path.exists(FAILOVER_HISTORY_FILE):
            with open(FAILOVER_HISTORY_FILE, 'r', encoding='utf-8') as f: return json.load(f)
    except Exception: pass
    return []

def save_failover_history(history):
    try:
        history = _prune_failover_history(history)
        _write_json(FAILOVER_HISTORY_FILE, history, indent=2)
    except Exception: pass

def login_required(fn):
    @wraps(fn)
    def _wrapped(*args, **kwargs):
        wants_json = request.is_json or request.path.startswith('/api/')
        if not session.get('logged_in'):
            if wants_json: return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        # Force-change gate only applies to the local admin account, not LDAP users.
        if (session.get('auth_backend') == 'local' and auth_config.get('is_default_password', False)
                and request.endpoint not in ("change_password", "logout")):
            if wants_json: return jsonify({'error': 'Password change required'}), 403
            return redirect(url_for('change_password'))
        return fn(*args, **kwargs)
    return _wrapped

def _dn_head(dn: str) -> str:
    """Leftmost RDN value, e.g. 'domain admins' from 'CN=Domain Admins,CN=Users,...'."""
    m = re.match(r'\s*[^=,]+=([^,]+)', str(dn or ''))
    return (m.group(1).strip().lower() if m else str(dn or '').strip().lower())

def _dn_norm(dn: str) -> str:
    """A DN in a form two spellings of the same DN share: case and the spaces
    around ',' and '=' do not matter."""
    return re.sub(r'\s*([,=])\s*', r'\1', str(dn or '').strip()).lower()

def _ldap_user_in_group(finder, user_dn, entry, allowed_group, cfg) -> bool:
    """True if the user belongs to allowed_group. Uses AD tokenGroups (which
    includes the PRIMARY group like Domain Admins and nested groups) when
    available, falling back to a lenient memberOf comparison for other LDAPs."""
    allowed = str(allowed_group or '').strip()
    if not allowed:
        return True
    from ldap3 import BASE, SUBTREE
    from ldap3.utils.conv import escape_filter_chars
    head = _dn_head(allowed)
    # A full DN names exactly one group. Only a bare name ("NetScaler-Admins") is
    # looked up by name - matching a DN by its first part alone would let in the
    # members of any group, in any OU or domain, that happens to share the name.
    is_dn = '=' in allowed

    # --- AD tokenGroups path (covers primary + nested group membership) ---
    try:
        if is_dn:
            finder.search(allowed, '(objectClass=group)', search_scope=BASE, attributes=['objectSid'])
        else:
            finder.search(cfg['base_dn'],
                          f"(&(objectClass=group)(cn={escape_filter_chars(head)}))",
                          search_scope=SUBTREE, attributes=['objectSid'])
        group_sid = None
        if finder.entries:
            try: group_sid = finder.entries[0].objectSid.raw_values[0]
            except Exception: group_sid = None
        if group_sid:
            finder.search(user_dn, '(objectClass=*)', search_scope=BASE, attributes=['tokenGroups'])
            if finder.entries:
                try:
                    token_sids = list(finder.entries[0].tokenGroups.raw_values)
                    if group_sid in token_sids:
                        return True
                    logger.info(f"LDAP: user not in group '{head}' (tokenGroups)")
                    return False
                except Exception:
                    pass  # tokenGroups not returned -> fall back
    except Exception as e:
        logger.info(f"LDAP tokenGroups check unavailable ({e}); using memberOf")

    # --- memberOf fallback: the same DN, or the same name when only a name was given ---
    try: groups = [str(g) for g in entry.memberOf.values]
    except Exception: groups = []
    al = _dn_norm(allowed)
    for g in groups:
        if _dn_norm(g) == al or (not is_dn and _dn_head(g) == head):
            return True
    logger.info(f"LDAP: user not in group '{head}' (memberOf: {len(groups)} group(s))")
    return False

def ldap_authenticate(username: str, password: str) -> bool:
    """Verify credentials against LDAP/AD by rebinding as the resolved user DN."""
    if not ldap_enabled(): return False
    if not username or not password: return False
    cfg = get_ldap_config()
    try:
        from ldap3 import Server, Connection, ALL, SUBTREE
        from ldap3.utils.conv import escape_filter_chars
        server = Server(cfg['server'], port=cfg['port'],
                        use_ssl=cfg['use_ssl'], get_info=ALL,
                        connect_timeout=cfg['timeout'])
        # Bind with the service account (or anonymously) to resolve the user's DN.
        # `with` guarantees the socket is unbound even if search() raises.
        with Connection(server, user=cfg['bind_dn'] or None,
                        password=cfg['bind_pw'] or None,
                        auto_bind=True, receive_timeout=cfg['timeout']) as finder:
            flt = f"({cfg['user_attr']}={escape_filter_chars(username)})"
            finder.search(cfg['base_dn'], flt, search_scope=SUBTREE, attributes=['memberOf'])
            if not finder.entries:
                logger.info(f"LDAP: user '{username}' not found with {cfg['user_attr']}")
                return False
            entry = finder.entries[0]
            user_dn = entry.entry_dn
            if not _ldap_user_in_group(finder, user_dn, entry, cfg['allowed_group_dn'], cfg):
                return False

        # Empty DN + password would be an anonymous simple bind on many servers,
        # which returns success and would bypass authentication — reject it.
        if not user_dn:
            return False
        # Rebind as the user to actually verify their password.
        with Connection(server, user=user_dn, password=password,
                        receive_timeout=cfg['timeout']) as user_conn:
            return bool(user_conn.bind())
    except Exception as e:
        logger.warning(f"LDAP auth error for '{username}': {e}")
        return False

def ldap_test_connection(cfg: dict) -> tuple[bool, str]:
    """Validate LDAP server/port/bind by binding with the service account and
    running a base search. Returns (ok, message)."""
    if not cfg.get('server'):
        return False, "LDAP server is required"
    try:
        from ldap3 import Server, Connection, ALL, SUBTREE
    except Exception:
        return False, "ldap3 library not available"
    try:
        server = Server(cfg['server'], port=int(cfg.get('port') or 389),
                        use_ssl=_as_bool(cfg.get('use_ssl')), get_info=ALL,
                        connect_timeout=int(cfg.get('timeout') or 10))
        with Connection(server, user=cfg.get('bind_dn') or None,
                        password=cfg.get('bind_pw') or None,
                        auto_bind=True, receive_timeout=int(cfg.get('timeout') or 10)) as conn:
            base = cfg.get('base_dn') or ''
            if base:
                conn.search(base, '(objectClass=*)', search_scope='BASE', attributes=['objectClass'])
                if not conn.entries:
                    return True, "Connected and bound, but base DN returned no entry (check base_dn)"
            return True, "Connection and bind succeeded"
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e)[:160]}"

# ======================================================================================
# NITRO Client
# ======================================================================================
# Verification is intentionally off for self-signed appliance certs — don't spam logs.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


class _LegacyTLSAdapter(requests.adapters.HTTPAdapter):
    """NetScaler management interfaces often negotiate only legacy ciphers (e.g.
    TLSv1.2 + AES256-SHA). OpenSSL 3's default security level rejects those, which
    shows up as a connection reset. Lower the security level for these calls so
    HTTPS/443 works the same as HTTP/80."""

    def __init__(self, verify_ssl=False, *args, **kwargs):
        self._verify_ssl = verify_ssl
        super().__init__(*args, **kwargs)

    def _ctx(self):
        ctx = ssl.create_default_context()
        try:
            ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        except ssl.SSLError:
            pass
        if not self._verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self._ctx()
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs['ssl_context'] = self._ctx()
        return super().proxy_manager_for(*args, **kwargs)


# Largest response accepted from an appliance, and how long a node that just
# failed to answer is left alone before it is tried again.
NITRO_MAX_BODY_BYTES = _env_int("NITRO_MAX_BODY_MB", 32, 1) * 1024 * 1024
NODE_BACKOFF_SECS = _env_int("NODE_BACKOFF_SECS", 10, 0)
_node_backoff = {}                   # "host:port" -> [retry at, read timeouts in a row]
_node_backoff_lock = threading.Lock()

class _ApplianceSession(requests.Session):
    """The HTTP session used for every call to a NetScaler.

    * A redirect is never followed: the credentials travel in request headers
      and would be sent to wherever the redirect points.
    * A response larger than NITRO_MAX_BODY_BYTES is refused instead of being
      loaded into memory.
    * A node that did not answer is not tried again for NODE_BACKOFF_SECS. The
      dashboard has a handful of worker threads; without this, a few browser tabs
      polling one dead appliance keep all of them waiting on timeouts and nobody
      can sign in.
    """
    def __init__(self, node):
        super().__init__()
        self._node = str(node)

    def _failed(self, at_once):
        if NODE_BACKOFF_SECS <= 0: return
        with _node_backoff_lock:
            rec = _node_backoff.setdefault(self._node, [0.0, 0])
            rec[1] += 1
            if at_once or rec[1] >= 2:
                rec[0] = time.time() + NODE_BACKOFF_SECS

    def request(self, method, url, **kw):
        with _node_backoff_lock:
            rec = _node_backoff.get(self._node)
            if rec and rec[0] > time.time():
                raise requests.ConnectionError(f"{self._node} did not answer a moment ago; trying again shortly")
        kw['allow_redirects'] = False
        kw['stream'] = True
        try:
            r = super().request(method, url, **kw)
            body = r.raw.read(NITRO_MAX_BODY_BYTES + 1, decode_content=True)
        except requests.ConnectionError:             # refused, unreachable, connect timeout
            self._failed(True); raise
        except requests.Timeout:
            self._failed(False); raise
        except requests.RequestException:
            raise
        except Exception as e:                       # urllib3 errors while reading the body
            self._failed(False)
            raise requests.ConnectionError(str(e))
        with _node_backoff_lock:
            _node_backoff.pop(self._node, None)
        if len(body) > NITRO_MAX_BODY_BYTES:
            r.close()
            raise requests.RequestException(
                f"the response from {self._node} is larger than {NITRO_MAX_BODY_BYTES // (1024 * 1024)} MB")
        r._content, r._content_consumed = body, True
        if 300 <= r.status_code < 400:
            raise requests.RequestException(
                f"{self._node} answered with a redirect (HTTP {r.status_code}); redirects are not followed")
        return r

class NetScalerAPI:
    def __init__(self, ip, username, password, port=80, protocol='http'):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.protocol = protocol
        self.base_url = f"{protocol}://{ip}:{port}/nitro/v1"
        self.session = _ApplianceSession(f"{ip}:{port}")
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-NITRO-USER': username,
            'X-NITRO-PASS': password,
            'User-Agent': 'NetScaler-Dashboard-NITRO/1.0'
        })
        # Appliances ship self-signed management certs, so verification is off by
        # default; set NITRO_VERIFY_SSL=1 if you've installed a trusted cert.
        self.session.verify = os.getenv("NITRO_VERIFY_SSL", "0").lower() in ("1", "true", "yes")
        if str(protocol).lower() == 'https':
            self.session.mount('https://', _LegacyTLSAdapter(verify_ssl=self.session.verify))
        try: self.timeout = int(os.getenv("NITRO_TIMEOUT_SECS", "15"))
        except Exception: self.timeout = 15
        # Cap connect time separately so an unreachable/filtered node fails fast
        # instead of hanging for the full read timeout.
        try: self.connect_timeout = int(os.getenv("NITRO_CONNECT_TIMEOUT_SECS", "3"))
        except Exception: self.connect_timeout = 3

    def _to(self, read_timeout):
        return (min(self.connect_timeout, read_timeout), read_timeout)

    def _get(self, path, custom_timeout=None):
        t = custom_timeout if custom_timeout else self.timeout
        r = self.session.get(f"{self.base_url}{path}", timeout=self._to(t))
        r.raise_for_status()
        return r.json()

    def _post(self, path, payload, custom_timeout=None):
        t = custom_timeout if custom_timeout else self.timeout
        r = self.session.post(f"{self.base_url}{path}", json=payload, timeout=self._to(t))
        r.raise_for_status()
        if r.text.strip():
            try: return r.json()
            except Exception: return {'raw': r.text, 'status_code': r.status_code}
        return {'status_code': r.status_code}

    def _post_status(self, path, payload):
        """POST that does not raise on an HTTP error status, so the appliance's own
        error message can be read: (status, NITRO object or None, raw text)."""
        r = self.session.post(f"{self.base_url}{path}", json=payload, timeout=self._to(self.timeout))
        try: body = r.json()
        except Exception: body = None
        return r.status_code, (body if isinstance(body, dict) else None), r.text

    def unlock_user(self, username: str) -> dict:
        """Unlock an AAA user, trying the forms of the call different builds accept.
        It is a success only when the appliance says so - a 2xx answer that is empty
        or a NITRO object with errorcode 0 - never on some other page that happens
        to come back with status 200."""
        from urllib.parse import quote
        attempts = (
            ("/config/aaauser", {"aaauser": {"username": username, "unlockAccount": True}}),
            ("/config/aaauser?action=unlock", {"aaauser": {"username": username}}),
            # the name is one path segment, whatever characters it contains
            (f"/config/aaauser/{quote(username, safe='')}?action=unlock", {"aaauser": {"username": username}}),
        )
        said = []
        for path, payload in attempts:
            try:
                status, body, text = self._post_status(path, payload)
            except Exception as e:
                said.append(f"The appliance could not be reached ({str(e)[:120]})")
                continue
            if 200 <= status < 300 and (not text.strip()
                                        or (body is not None and str(body.get("errorcode", 0)) == "0")):
                return {"errorcode": 0, "message": "Done"}
            if body is not None and body.get("message"):
                said.append(str(body["message"]))
        # Prefer the answer that explains it over "invalid argument" from a form
        # of the call this build does not know.
        for m in said:
            if re.search(r"no such|does not exist|not found|not locked|not authorized|permission", m, re.I):
                return {"errorcode": -1, "message": m}
        return {"errorcode": -1, "message": said[-1] if said else "All unlock attempts failed."}

class SdxAPI(NetScalerAPI):
    """The SDX Management Service's NITRO API (/nitro/v2): the platform, its
    hardware health and the NetScaler (VPX) instances it hosts. Read-only here."""
    def __init__(self, ip, username, password, port=443, protocol='https'):
        super().__init__(ip, username, password, port, protocol)
        self.base_url = f"{protocol}://{ip}:{port}/nitro/v2"

# ======================================================================================
# Next-Gen API Client
# ======================================================================================
# Management path of the Next-Gen API. Overridable so a build that exposes it
# elsewhere can be pointed at without a code change (see /api/nextgen-debug).
NEXTGEN_BASE_PATH = os.getenv("NEXTGEN_BASE_PATH", "/mgmt/api/nextgen/v1")

def _nextgen_candidate_paths():
    """Management API paths worth probing when Next-Gen isn't detected."""
    out, seen = [], set()
    for x in (NEXTGEN_BASE_PATH, "/mgmt/api/nextgen/v1", "/nitro/v2/config", "/api/v1", "/mgmt/api/v1"):
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


class NextGenAPI:
    def __init__(self, ip, username, password, port=443, protocol='https', base_path=None):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.protocol = protocol
        self.base_path = base_path or NEXTGEN_BASE_PATH
        self.base_url = f"{protocol}://{ip}:{port}{self.base_path}"
        self.session = _ApplianceSession(f"{ip}:{port}")
        self.session.verify = os.getenv("NEXTGEN_VERIFY_SSL", "0").lower() in ("1", "true", "yes")
        # Appliance management interfaces negotiate legacy ciphers that OpenSSL 3
        # rejects at its default security level. NITRO got this adapter in 1.4.0;
        # without it here the Next-Gen login fails and we silently fell back.
        if str(protocol).lower() == 'https':
            self.session.mount('https://', _LegacyTLSAdapter(verify_ssl=self.session.verify))
        try: self.timeout = int(os.getenv("NEXTGEN_TIMEOUT_SECS", "15"))
        except Exception: self.timeout = 15
        self.session.headers.update({
            'Content-Type': 'application/json', 'Accept': 'application/json',
            'User-Agent': 'NetScaler-Dashboard-NextGen/1.0'
        })

    def login(self):
        r = self.session.post(f"{self.base_url}/login", json={"login": {"username": self.username, "password": self.password, "timeout": "15min"}}, timeout=self.timeout)
        r.raise_for_status()
        if not r.cookies.get('sessionid'): raise RuntimeError("Next-Gen login succeeded without sessionid cookie")
        return True

    def logout(self):
        r = self.session.post(f"{self.base_url}/logout", timeout=self.timeout)
        return True

    def list_applications(self):
        r = self.session.get(f"{self.base_url}/applications", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

# ======================================================================================
# UI Device Configuration (JSON Based)
# ======================================================================================
def _int(v, default):
    try: return int(v)
    except Exception: return default

# NODES_CONFIG_FILE is defined at the top (under DATA_DIR).
# Deployment topology: 'standalone' (primary only), 'ha' (primary+secondary pair),
# or 'cluster' (primary = Cluster IP / CLIP; members read from /config/clusternode).
VALID_MODES = ('standalone', 'ha', 'cluster', 'sdx')     # sdx: the node is an SDX Management Service

def _blank_node():
    return {'ip': '', 'username': '', 'password': '', 'port': 443, 'protocol': 'https'}

def _default_config():
    return {
        'instances': [{
            'id': 'default', 'name': 'Default', 'mode': 'ha',
            'primary': _blank_node(), 'secondary': _blank_node(),
        }],
        'session_timeout_minutes': DEFAULT_SESSION_TIMEOUT_MIN,
    }

def _migrate_config(cfg):
    """Bring any stored config up to the multi-instance shape. Idempotent:
    a config that already has an 'instances' list is returned untouched, while
    the legacy single-deployment shape ({mode, primary, secondary}) is wrapped
    into one 'Default' instance so existing setups keep working after an update."""
    if not isinstance(cfg, dict):
        return _default_config()
    if isinstance(cfg.get('instances'), list) and cfg['instances']:
        return cfg
    inst = {'id': 'default', 'name': 'Default', 'mode': str(cfg.get('mode', 'ha')).lower()}
    for k, v in cfg.items():
        if isinstance(v, dict):   # primary / secondary node blocks
            inst[k] = v
    if 'primary' not in inst:
        inst['primary'] = _blank_node()
    return {
        'instances': [inst],
        'session_timeout_minutes': cfg.get('session_timeout_minutes', DEFAULT_SESSION_TIMEOUT_MIN),
    }

def _clean_node(node):
    node = node if isinstance(node, dict) else {}
    proto = str(node.get('protocol', 'https')).lower()
    port = _int(node.get('port', 443), 443)
    return {'ip': str(node.get('ip') or '').strip(), 'username': str(node.get('username') or '').strip(),
            'password': node.get('password') if isinstance(node.get('password'), str) else '',
            'port': port if 1 <= port <= 65535 else 443,
            'protocol': proto if proto in ('http', 'https') else 'https'}

def _sane_config(cfg):
    """A config whose shape the rest of the code can rely on, whatever was in the
    file or in a settings copy from a database: only well-formed instances are
    kept (None if there is not a single one)."""
    cfg = _migrate_config(cfg)
    insts, used = [], set()
    for i, inst in enumerate(cfg.get('instances') or []):
        if not isinstance(inst, dict) or not isinstance(inst.get('primary'), dict):
            continue
        iid = str(inst.get('id') or '').strip() or f"inst-{i + 1}"
        if iid in used:
            continue
        used.add(iid)
        mode = str(inst.get('mode', 'ha')).lower()
        mode = mode if mode in VALID_MODES else 'ha'
        out = {'id': iid, 'name': str(inst.get('name') or '').strip() or f"Instance {i + 1}", 'mode': mode,
               'primary': _clean_node(inst['primary'])}
        if mode == 'ha':
            out['secondary'] = _clean_node(inst.get('secondary'))
        insts.append(out)
    if not insts:
        return None
    return {'instances': insts,
            'session_timeout_minutes': min(max(_int(cfg.get('session_timeout_minutes'), DEFAULT_SESSION_TIMEOUT_MIN), 1), 1440)}

def load_nodes_config():
    src = _read_path(NODES_CONFIG_FILE, 'nodes_config.json')
    if os.path.exists(src):
        try:
            with open(src, 'r', encoding='utf-8') as f:
                cfg = _sane_config(json.load(f))
            if cfg is None:
                raise ValueError('it holds no usable instance')
            return cfg
        except Exception as e:
            # A damaged settings file must not keep the dashboard from starting:
            # the administrator needs the web UI to put things right. The file is
            # kept beside the new one for recovery.
            logger.error(f"The settings file {src} cannot be used ({e}). Starting with no instances; "
                         f"the file is kept as {src}.corrupt")
            try: os.replace(src, src + '.corrupt')
            except OSError: pass
    return _default_config()

NETSCALER_CONFIG = load_nodes_config()

def save_nodes_config(config):
    config = _sane_config(config) or _default_config()
    _write_json(NODES_CONFIG_FILE, config, indent=2)
    global NETSCALER_CONFIG
    NETSCALER_CONFIG = config
    db.documents_changed()

def get_instances():
    return NETSCALER_CONFIG.get('instances', [])

def get_instance(instance_id=None):
    """Resolve an instance dict by id; falls back to the first instance so any
    call that omits an instance keeps targeting a valid deployment."""
    insts = get_instances()
    if not insts:
        return {'id': 'default', 'name': 'Default', 'mode': 'ha', 'primary': _blank_node()}
    if instance_id is not None:
        for i in insts:
            if str(i.get('id')) == str(instance_id):
                return i
    return insts[0]

def get_mode(instance_id=None) -> str:
    m = str(get_instance(instance_id).get('mode', 'ha')).lower()
    return m if m in VALID_MODES else 'ha'

def node_items(instance_id=None):
    """(key, cfg) pairs for real node entries in an instance (skips scalars)."""
    return [(k, v) for k, v in get_instance(instance_id).items() if isinstance(v, dict)]

def active_node_keys(instance_id=None):
    """Node keys the UI should surface, per deployment mode."""
    if get_mode(instance_id) in ('standalone', 'cluster', 'sdx'):
        return ['primary']
    return [k for k, _ in node_items(instance_id)]

# Detected API capability per node, namespaced by instance: {instance_id: {node_key: 'nitro'|'nextgen'}}.
API_MODE = {}
# Last-known NITRO hostname per (instance_id, node_key), so a brief unreachable
# blip doesn't blank a node's name in the UI (notably the secondary).
_HOSTNAME_CACHE = {}

def get_api_mode(instance_id, node_key):
    return API_MODE.get(str(get_instance(instance_id).get('id')), {}).get(node_key, 'nitro')

def set_api_mode(instance_id, node_key, mode):
    API_MODE.setdefault(str(get_instance(instance_id).get('id')), {})[node_key] = mode

def validate_env():
    for inst in get_instances():
        iid = inst.get('id')
        missing = [k for k in active_node_keys(iid)
                   if not (inst.get(k) or {}).get('ip')]
        if missing:
            logger.warning(f"Instance '{inst.get('name', iid)}': nodes without an IP: {', '.join(missing)}")

# ======================================================================================
# API Detection & Client Helpers
# ======================================================================================
def _parse_version_tuple(version_str: str):
    m = re.search(r"(\d+)\.(\d+)", str(version_str or ""))
    if not m: return (0, 0)
    return (int(m.group(1)), int(m.group(2)))

def _is_nextgen_supported(version_str: str) -> bool:
    return _parse_version_tuple(version_str) >= (14, 1)

# Why each node ended up on its API mode: {instance_id: {node_key: {...}}}.
# Surfaced in /api/caps so "falls back to NITRO" is explainable, not a mystery.
API_DETECT_INFO = {}

def _set_detect_info(instance_id, node_key, **kw):
    iid = str(get_instance(instance_id).get('id'))
    kw['checked'] = datetime.now(APP_TZ).strftime('%d/%m/%Y %H:%M:%S')
    API_DETECT_INFO.setdefault(iid, {})[node_key] = kw

def get_detect_info(instance_id, node_key):
    return API_DETECT_INFO.get(str(get_instance(instance_id).get('id')), {}).get(node_key, {})

def detect_api_mode_for_node(node_key: str, cfg: dict, instance_id=None):
    if get_mode(instance_id) == 'sdx':
        set_api_mode(instance_id, node_key, 'sdx')
        _set_detect_info(instance_id, node_key, mode='sdx', reason='SDX Management Service (NITRO v2)')
        return
    if not cfg.get('ip') or not cfg.get('username') or not cfg.get('password'):
        set_api_mode(instance_id, node_key, 'nitro')
        _set_detect_info(instance_id, node_key, mode='nitro', reason='Node is not fully configured')
        return
    version, reason = None, ''
    try:
        nitro = NetScalerAPI(cfg['ip'], cfg['username'], cfg['password'], cfg['port'], cfg['protocol'])
        vi = nitro._get('/config/nsversion', custom_timeout=5)
        meta = vi['nsversion'][0] if isinstance(vi.get('nsversion'), list) else vi.get('nsversion', {})
        version = meta.get('version') or meta.get('release') or ''
        if not _is_nextgen_supported(version):
            reason = f"Appliance reports {version or 'an unknown version'} (Next-Gen needs 14.1+)"
        else:
            try:
                ng = NextGenAPI(cfg['ip'], cfg['username'], cfg['password'],
                                port=_int(os.getenv('NS_PORT_HTTPS', '443'), 443), protocol='https')
                ng.login()
                ng.logout()
                set_api_mode(instance_id, node_key, 'nextgen')
                _set_detect_info(instance_id, node_key, mode='nextgen', version=version,
                                 reason='Next-Gen login succeeded', url=ng.base_url)
                logger.info(f"Next-Gen API detected on {node_key} ({cfg.get('ip')}), version {version}")
                return
            except Exception as e:
                reason = f"Next-Gen login failed at {NEXTGEN_BASE_PATH}: {str(e)[:200]}"
    except Exception as e:
        reason = f"Version check failed: {str(e)[:200]}"
    set_api_mode(instance_id, node_key, 'nitro')
    _set_detect_info(instance_id, node_key, mode='nitro', version=version, reason=reason)
    if reason:
        logger.info(f"{node_key} ({cfg.get('ip')}) using NITRO - {reason}")

def _nextgen_probe(cfg):
    """Report-only Next-Gen diagnosis: appliance version, which management paths
    answer, and the real login result. Never changes the stored API mode."""
    port = _int(os.getenv('NS_PORT_HTTPS', '443'), 443)
    ip = cfg.get('ip')
    out = {'ip': ip, 'port': port, 'base_path': NEXTGEN_BASE_PATH,
           'version': None, 'nextgen_supported': None, 'paths': [], 'login': None}
    if not ip:
        out['error'] = 'No IP configured'
        return out
    try:
        nitro = NetScalerAPI(ip, cfg.get('username'), cfg.get('password'), cfg.get('port'), cfg.get('protocol'))
        vi = nitro._get('/config/nsversion', custom_timeout=5)
        meta = vi['nsversion'][0] if isinstance(vi.get('nsversion'), list) else vi.get('nsversion', {})
        out['version'] = meta.get('version') or meta.get('release')
        out['version_parsed'] = list(_parse_version_tuple(out['version']))
        out['nextgen_supported'] = _is_nextgen_supported(out['version'])
    except Exception as e:
        out['version_error'] = str(e)[:200]

    # Unauthenticated GET per candidate: 404 means "not here", 401/403 means it exists.
    sess = requests.Session()
    sess.verify = os.getenv('NEXTGEN_VERIFY_SSL', '0').lower() in ('1', 'true', 'yes')
    sess.mount('https://', _LegacyTLSAdapter(verify_ssl=sess.verify))
    for base in _nextgen_candidate_paths():
        rec = {'url': f"https://{ip}:{port}{base}"}
        try:
            r = sess.get(rec['url'], timeout=5)
            rec['status'] = r.status_code
            rec['looks_present'] = r.status_code not in (404, 400)
            rec['body'] = (r.text or '')[:120]
        except Exception as e:
            rec['error'] = str(e)[:160]
        out['paths'].append(rec)

    try:
        ng = NextGenAPI(ip, cfg.get('username'), cfg.get('password'), port=port, protocol='https')
        ng.login()
        ng.logout()
        out['login'] = {'ok': True, 'url': f"{ng.base_url}/login"}
    except Exception as e:
        out['login'] = {'ok': False, 'url': f"https://{ip}:{port}{NEXTGEN_BASE_PATH}/login",
                        'error': str(e)[:300]}
    return out

def get_nitro(node_key: str, instance_id=None) -> NetScalerAPI:
    cfg = get_instance(instance_id).get(node_key or 'primary') if (node_key or 'primary') in ('primary', 'secondary') else None
    if not isinstance(cfg, dict): raise KeyError(f"Unknown node '{node_key}'")
    return NetScalerAPI(cfg['ip'], cfg['username'], cfg['password'], cfg['port'], cfg['protocol'])

def get_sdx(instance_id=None) -> SdxAPI:
    inst = get_instance(instance_id)
    cfg = inst.get('primary')
    if str(inst.get('mode')) != 'sdx' or not isinstance(cfg, dict) or not cfg.get('ip'):
        raise KeyError('This instance is not an SDX with an address')
    return SdxAPI(cfg['ip'], cfg.get('username', ''), cfg.get('password', ''), cfg.get('port', 443), cfg.get('protocol', 'https'))

def get_nextgen(node_key: str, instance_id=None) -> NextGenAPI:
    cfg = get_instance(instance_id).get(node_key or 'primary') if (node_key or 'primary') in ('primary', 'secondary') else None
    if not isinstance(cfg, dict): raise KeyError(f"Unknown node '{node_key}'")
    return NextGenAPI(cfg['ip'], cfg['username'], cfg['password'], port=_int(os.getenv('NS_PORT_HTTPS', '443'), 443), protocol='https')

# ======================================================================================
# System Overview & Fast HA Tracking Logic
# ======================================================================================
# NITRO reports the configured/effective HA state in `hastatus`
# (`set ha node -hastatus ...`). STAYPRIMARY / STAYSECONDARY are *forced* modes
# that suppress normal failover, so they must be surfaced, not hidden behind the
# plain Primary/Secondary role.
_HA_STATUS_LABELS = {
    'UP':               ('Up', 'ok'),
    'ENABLED':          ('Enabled', 'ok'),
    'STAYPRIMARY':      ('Stay Primary (forced)', 'warn'),
    'STAYSECONDARY':    ('Stay Secondary (forced)', 'warn'),
    'DISABLED':         ('HA Disabled', 'warn'),
    'INIT':             ('Initializing', 'warn'),
    'DUMB':             ('No Peer (dumb)', 'warn'),
    'DOWN':             ('Down', 'bad'),
    'DOWN_TO_UP':       ('Recovering', 'warn'),
    'PARTIALFAIL':      ('Partial Failure', 'bad'),
    'PARTIALFAILSSL':   ('Partial Failure (SSL card)', 'bad'),
    'COMPLETEFAIL':     ('Complete Failure', 'bad'),
    'ROUTEMONITORFAIL': ('Route Monitor Failed', 'bad'),
}

def _ha_status_meta(node):
    """Normalize a hanode's `hastatus` into {code,label,severity,forced} for the UI."""
    if not isinstance(node, dict):
        return {}
    code = str(node.get('hastatus') or node.get('hacurstatus')
               or node.get('hastate') or '').strip().upper()
    if not code:
        return {}
    label, severity = _HA_STATUS_LABELS.get(code, (code.title(), 'warn'))
    return {'code': code, 'label': label, 'severity': severity,
            'forced': code in ('STAYPRIMARY', 'STAYSECONDARY')}

def _get_cluster_nodes_normalized(instance_id=None):
    """Read cluster members from the CLIP (primary) and map them to the hanode shape."""
    try:
        r = get_nitro('primary', instance_id)._get('/config/clusternode', custom_timeout=4)
        nodes = r.get('clusternode', []) if isinstance(r, dict) else []
    except Exception:
        return {}
    norm = []
    for n in nodes:
        if not isinstance(n, dict): continue
        norm.append({
            'id': n.get('nodeid'),
            'name': (f"Cluster Node {n.get('nodeid')}" if n.get('nodeid') is not None else None),
            'ipaddress': n.get('ipaddress') or n.get('nodeip') or n.get('ip') or '',
            'state': str(n.get('masterstate') or n.get('state') or n.get('health') or 'Unknown'),
            'hasync': str(n.get('operationalsyncstate') or n.get('effectivestate') or ''),
            'hastatus': str(n.get('hastatus') or n.get('health') or ''),
        })
    return {'hanode': norm} if norm else {}

def _get_ha_data_fast(instance_id=None):
    # Cluster members and HA nodes are normalized to the same {'hanode': [...]} shape
    # so every downstream caller works regardless of deployment mode.
    if get_mode(instance_id) == 'sdx':
        return {}
    if get_mode(instance_id) == 'cluster':
        return _get_cluster_nodes_normalized(instance_id)
    for nk in active_node_keys(instance_id):
        try:
            nit = get_nitro(nk, instance_id)
            r = nit._get('/config/hanode', custom_timeout=3)
            if isinstance(r, dict) and isinstance(r.get('hanode'), list):
                r['hanode'] = [{k: (v if v is None or isinstance(v, (str, int, float, bool)) else str(v))
                                for k, v in n.items()} for n in r['hanode'] if isinstance(n, dict)]
                return r
        except Exception: pass
    return {}

_ha_track_lock = threading.Lock()

def track_ha_state_changes(nodes, instance_id=None):
    # Several browser tabs poll at once: without the lock each of them saw the old
    # state and recorded the same failover again.
    with _ha_track_lock:
        _track_ha_state_changes(nodes, instance_id)

def _track_ha_state_changes(nodes, instance_id=None):
    inst_key = str(get_instance(instance_id).get('id'))
    last_states = {}
    if os.path.exists(HA_STATE_FILE):
        try:
            with open(HA_STATE_FILE, 'r', encoding='utf-8') as f: last_states = json.load(f)
        except Exception: pass
    _states_before = json.dumps(last_states, sort_keys=True)

    history = load_failover_history()
    changed = False
    new_events = []

    for n in nodes:
        if not isinstance(n, dict): continue
        ip = n.get('ipaddress') or n.get('ip') or n.get('nsip') or ''
        role = str(n.get('state') or n.get('hacurstate') or n.get('haStatus') or n.get('status') or '').upper()
        if ip and role:
            # Kept per instance: two deployments may use the same management
            # addresses, and their roles must not be compared with each other.
            key = f"{inst_key}|{ip}"
            prev = last_states.get(key) or last_states.pop(ip, None)     # second form: files from before 1.16.3
            if prev and prev != role and 'UNKNOWN' not in role:
                _inst = get_instance(instance_id)
                evt = {
                    'timestamp': datetime.now(APP_TZ).isoformat(),
                    'type': 'Role Change',
                    'reason': f"Node HA State Shift",
                    'role_change': f"{prev} -> {role}",
                    'ip': ip,
                    'instance': str(_inst.get('id')),
                    'instance_name': _inst.get('name'),
                }
                history.append(evt)
                new_events.append(evt)
                changed = True
            last_states[key] = role

    if changed:
        save_failover_history(history)
        try: db.add_failover_events(new_events)
        except Exception as e: logger.warning(f"Could not persist failover events: {e}")
    try:
        if json.dumps(last_states, sort_keys=True) != _states_before:     # only when something changed
            _write_json(HA_STATE_FILE, last_states)
            db.documents_changed()
    except Exception: pass

def _roles_from_ha(instance_id=None) -> tuple[dict, dict]:
    raw = _get_ha_data_fast(instance_id)
    roles = {}
    nodes = raw.get('hanode', []) if isinstance(raw, dict) else []
    track_ha_state_changes(nodes, instance_id)
    for n in nodes:
        if isinstance(n, dict):
            ip = n.get('ipaddress') or n.get('ip') or n.get('nsip') or ''
            if ip: roles[ip] = str(n.get('state') or n.get('hacurstate') or 'Unknown')
    return roles, raw

# ======================================================================================
# License & Capacity
# ======================================================================================
_LIC_CACHE = {}                      # (instance, node key) -> (read at, license_info)
LICENSE_WARN_DAYS = 30

_LIC_MODES = {
    'LAS (FIXED BANDWIDTH)': 'LAS - fixed bandwidth', 'LAS': 'LAS - online',
    'LOCAL': 'Local license file', 'POOLED': 'Pooled (NetScaler Console)', 'FIPS-POOLED': 'Pooled, FIPS',
    'CICO': 'Check-in / check-out', 'FIPS-CICO': 'Check-in / check-out, FIPS', 'EXPRESS': 'Express (free)',
    'CPU': 'vCPU (pooled)', 'CPU-LOCAL': 'vCPU (local)', 'SELF MANAGED POOL': 'Self-managed pool',
    'SELF MANAGED VCPU': 'Self-managed vCPU',
}
_EDITIONS = {'PLATINUM': 'Premium', 'ENTERPRISE': 'Advanced', 'STANDARD': 'Standard'}

def _first(d, key):
    v = (d or {}).get(key) if isinstance(d, dict) else None
    if isinstance(v, list):
        v = v[0] if v else {}
    return v if isinstance(v, dict) else {}

def _truthy(v):
    return str(v).strip().upper() in ('TRUE', '1', 'YES', 'ENABLED', 'ON')

def license_info(nitro):
    """What the appliance says about its license: nslicense (edition flags,
    licensing mode, days to expiry), nscapacity (bandwidth / vCPUs, edition) and
    nslicenseserver (pooled / LAS server, grace period). Each part may be missing
    on a build or for a read-only user; what is unknown says so."""
    lic, cap, srv, errors = {}, {}, {}, []
    for path, key, target in (('/config/nslicense', 'nslicense', 'lic'), ('/config/nscapacity', 'nscapacity', 'cap'),
                              ('/config/nslicenseserver', 'nslicenseserver', 'srv')):
        try:
            got = _first(nitro._get(path, custom_timeout=4) or {}, key)
        except Exception as e:
            got = {}
            if target != 'srv':
                errors.append(f"{key}: {str(e)[:100]}")
        if target == 'lic': lic = got
        elif target == 'cap': cap = got
        else: srv = got

    edition = 'Unknown'
    if _truthy(lic.get('isplatinumlic')): edition = 'Premium'
    elif _truthy(lic.get('isenterpriselic')): edition = 'Advanced'
    elif _truthy(lic.get('isstandardlic')): edition = 'Standard'
    elif cap.get('edition'): edition = _EDITIONS.get(str(cap['edition']).upper(), str(cap['edition']).title())
    if _truthy(lic.get('issgwylic')) and edition == 'Unknown': edition = 'Gateway'

    raw_mode = str(lic.get('licensingmode') or '').strip()
    mode = _LIC_MODES.get(raw_mode.upper(), raw_mode or 'Unknown')

    capacity = 'Unknown'
    bw = cap.get('actualbandwidth') or cap.get('bandwidth')
    if _int(cap.get('vcpucount'), 0) > 0 and (_truthy(cap.get('vcpu')) or 'CPU' in raw_mode.upper()):
        capacity = f"{_int(cap.get('vcpucount'), 0)} vCPU"
    elif bw and str(bw) != '0':
        unit = str(cap.get('unit') or 'Mbps') if cap.get('bandwidth') and not cap.get('actualbandwidth') else 'Mbps'
        capacity = f"{bw} {unit}"
    elif _int(lic.get('modelid'), 0) > 0:
        capacity = f"{_int(lic.get('modelid'), 0)} Mbps"

    days = [d for d in (_int(lic.get('daystoexpiration'), -1), _int(cap.get('daystoexpiration'), -1)) if d > 0]
    days_left = min(days) if days else None
    expires_on = ((datetime.now(APP_TZ) + timedelta(days=days_left)).strftime('%d/%m/%Y') if days_left is not None else '')
    las_days = _int(lic.get('daystolasenforcement'), 0)

    grace = _truthy(srv.get('grace'))
    grace_hours = _int(srv.get('gptimeleft'), 0) if grace else 0

    level, notes = 'ok', []
    if grace:
        level = 'bad' if grace_hours <= 72 else 'warn'
        notes.append(f"In the grace period: {grace_hours // 24} day(s) {grace_hours % 24} h left before the license stops working.")
    if days_left is not None and days_left <= LICENSE_WARN_DAYS:
        level = 'bad' if days_left <= 7 else ('warn' if level == 'ok' else level)
        notes.append(f"The license expires in {days_left} day(s), on {expires_on}.")
    if las_days and las_days <= LICENSE_WARN_DAYS and 'LAS' not in raw_mode.upper():
        level = 'warn' if level == 'ok' else level
        notes.append(f"LAS enforcement in {las_days} day(s): move this appliance to LAS licensing before then.")
    if errors and edition == 'Unknown':
        level = 'unknown'

    return {
        'edition': edition, 'mode': mode, 'mode_raw': raw_mode, 'capacity': capacity,
        'days_left': days_left, 'expires_on': expires_on, 'las_enforcement_days': las_days or None,
        'grace': grace, 'grace_hours_left': grace_hours if grace else None,
        'server': str(srv.get('servername') or srv.get('licenseserverip') or ''),
        'server_status': str(srv.get('status') or ''), 'server_type': str(srv.get('type') or ''),
        'vpn_users': _int(lic.get('f_sslvpn_users'), 0) or None,
        'level': level, 'notes': notes, 'errors': errors,
    }

def _cached_license(instance_id, node_key):
    """License info for the health wall: read at most every ten minutes per node."""
    key = (str(instance_id), node_key)
    hit = _LIC_CACHE.get(key)
    if hit and time.time() - hit[0] < 600:
        return hit[1]
    try:
        info = license_info(get_nitro(node_key, instance_id))
    except Exception:
        return hit[1] if hit else None
    _LIC_CACHE[key] = (time.time(), info)
    return info

def _build_node_overview(node_key: str, instance_id=None) -> dict:
    cfg = get_instance(instance_id).get(node_key, {})
    ip = cfg.get('ip')

    try:
        nitro = get_nitro(node_key, instance_id)
        stats = nitro._get('/stat/ns', custom_timeout=3)
        connected = bool(isinstance(stats, dict) and stats.get('ns'))
    except Exception:
        return {'connected': False, 'ip': ip, 'config_changed': False}

    version = None
    try:
        vi = nitro._get('/config/nsversion', custom_timeout=3)
        meta = vi['nsversion'][0] if isinstance(vi.get('nsversion'), list) else vi.get('nsversion', {})
        version = meta.get('version') or meta.get('release')
    except Exception: pass

    role = 'Unknown'
    ha_status = {}
    ha_data = _get_ha_data_fast(instance_id)
    for n in ha_data.get('hanode', []):
        if isinstance(n, dict) and (n.get('ipaddress') or n.get('ip') or n.get('nsip')) == ip:
            role = n.get('state') or n.get('hacurstate') or n.get('haStatus') or 'Unknown'
            ha_status = _ha_status_meta(n)

    # BULLETPROOF configchanged check
    config_changed = False
    try:
        nsconfig_resp = nitro._get('/config/nsconfig', custom_timeout=3).get('nsconfig')
        if isinstance(nsconfig_resp, list) and len(nsconfig_resp) > 0:
            val = str(nsconfig_resp[0].get('configchanged', 'false')).lower()
            config_changed = (val in ['true', '1', 'yes'])
        elif isinstance(nsconfig_resp, dict):
            val = str(nsconfig_resp.get('configchanged', 'false')).lower()
            config_changed = (val in ['true', '1', 'yes'])
    except Exception as e:
        logger.warning(f"Could not fetch configchanged for {node_key}: {e}")

    lic = license_info(nitro)
    _LIC_CACHE[(str(get_instance(instance_id).get('id')), node_key)] = (time.time(), lic)

    return {
        'connected': connected, 'ha_role': role, 'ha_status': ha_status, 'ns_stats': stats,
        'version': version, 'ip': ip, 'config_changed': config_changed,
        # the three keys earlier pages read, and everything else in 'license'
        'license_type': lic['edition'], 'license_mode': lic['mode'], 'bandwidth': lic['capacity'],
        'license': lic,
    }

# ======================================================================================
# Auth / UI Template Routes
# ======================================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    global auth_config
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        source = (request.form.get('auth_source') or 'local').strip().lower()
        addr = request.remote_addr or 'unknown'

        wait = _login_wait(addr)
        if wait:
            mins = (wait + 59) // 60
            flash(f"Too many failed sign-in attempts. Try again in {mins} minute{'' if mins == 1 else 's'}.", 'error')
            return _login_page(429)

        # Honor the chosen authentication source. LDAP only when enabled; local
        # is always available (avoids lockout even if the form says otherwise).
        backend = None
        if source == 'ldap' and ldap_enabled():
            if ldap_authenticate(username, password):
                backend = 'ldap'
        else:
            # Both checks always run, so a wrong user name costs the same as a wrong password.
            user_ok = hmac.compare_digest(username.encode('utf-8'), str(auth_config.get('username') or '').encode('utf-8'))
            pw_ok = verify_password(password, auth_config.get('password_hash'))
            if user_ok and pw_ok:
                backend = 'local'

        if backend:
            _login_succeeded(addr)
            session['logged_in'] = True
            session['user'] = username
            session['auth_backend'] = backend
            session.permanent = True
            session['last_active'] = time.time()
            if backend == 'local':
                if is_legacy_hash(auth_config.get('password_hash')):
                    auth_config['password_hash'] = hash_password(password)
                    logger.info("Admin password hash upgraded from the legacy format")
                auth_config['last_login'] = datetime.now(APP_TZ).isoformat()
                auth_config['login_attempts'] = 0
                save_auth_config(auth_config)
            return redirect(url_for('dashboard'))

        _login_failed(addr)
        logger.warning(f"Failed sign-in ({source}) for {username[:64]!r} from {addr}")
        if source != 'ldap' and auth_config.get('unreadable'):
            flash('The stored admin login could not be read, so local sign-in is disabled. Reset it from the '
                  'appliance console ("Reset the web admin password").', 'error')
        else:
            flash('Invalid credentials', 'error')
    return _login_page()

# POST only: a link on another site must not be able to sign the administrator out.
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    global auth_config
    if request.method == 'POST':
        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')

        if not verify_password(current_pw, auth_config.get('password_hash')):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')
        if not new_pw or len(new_pw) < PASSWORD_MIN_LENGTH:
            flash(f'Password must be at least {PASSWORD_MIN_LENGTH} characters', 'error')
            return render_template('change_password.html')
        if (new_pw == current_pw or new_pw == DEFAULT_PASSWORD
                or new_pw.lower() in (str(auth_config.get('username') or '').lower(), 'password', '12345678')):
            flash('Choose a new password: not the current one, the default, the user name or an obvious one', 'error')
            return render_template('change_password.html')
        if new_pw != confirm_pw:
            flash('New password and confirmation do not match', 'error')
            return render_template('change_password.html')

        auth_config['password_hash'] = hash_password(new_pw)
        auth_config['is_default_password'] = False
        auth_config['last_password_change'] = datetime.now(APP_TZ).isoformat()
        save_auth_config(auth_config)
        flash('Password changed successfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

# ======================================================================================
# LDAP settings API
# ======================================================================================
_LDAP_PUBLIC_FIELDS = ('enabled', 'server', 'port', 'use_ssl', 'base_dn',
                       'bind_dn', 'user_attr', 'allowed_group_dn', 'timeout')

def _ldap_public_view(cfg: dict) -> dict:
    view = {k: cfg.get(k) for k in _LDAP_PUBLIC_FIELDS}
    view['bind_pw_set'] = bool(cfg.get('bind_pw'))   # never expose the password
    return view

def _ldap_from_body(body: dict) -> dict:
    out = {}
    if 'enabled' in body: out['enabled'] = _as_bool(body.get('enabled'))
    if 'use_ssl' in body: out['use_ssl'] = _as_bool(body.get('use_ssl'))
    for k in ('server', 'base_dn', 'bind_dn', 'user_attr', 'allowed_group_dn'):
        if k in body: out[k] = str(body.get(k) or '').strip()
    for k in ('port', 'timeout'):
        if k in body:
            try: out[k] = int(body.get(k))
            except Exception: pass
    if 'bind_pw' in body and isinstance(body.get('bind_pw'), str):
        out['bind_pw'] = body['bind_pw']            # blank keeps stored (handled in save)
    return out

@app.route('/api/ldap-settings', methods=['GET', 'POST'])
@login_required
def api_ldap_settings():
    if request.method == 'POST':
        body = request.get_json(force=True, silent=True)
        if not isinstance(body, dict):
            return jsonify({"success": False, "error": "Invalid payload"}), 400
        try:
            save_ldap_config(_ldap_from_body(body))
        except Exception as e:
            logger.error(f"LDAP settings save failed: {e}")
            return jsonify({"success": False, "error": "Could not save LDAP settings"}), 500
        return jsonify({"success": True, "message": "LDAP settings updated"})
    return jsonify(_ldap_public_view(get_ldap_config()))

@app.route('/api/ldap-test', methods=['POST'])
@login_required
def api_ldap_test():
    body = request.get_json(force=True, silent=True) or {}
    # Test against the submitted values, filling blanks from the stored config.
    cfg = dict(get_ldap_config())
    cfg.update(_ldap_from_body(body))
    if not body.get('bind_pw'):
        cfg['bind_pw'] = get_ldap_config().get('bind_pw', '')
    ok, msg = ldap_test_connection(cfg)
    return jsonify({"success": ok, "message": msg})

# ======================================================================================
# External database (Settings -> Database)
# ======================================================================================
def _db_documents():
    """The settings documents an external database gets a copy of, each with
    whether this dashboard really has it (a file somebody saved) or is still on
    defaults. A dashboard on defaults takes the document from the database."""
    ha = None
    try:
        if os.path.exists(HA_STATE_FILE):
            with open(HA_STATE_FILE, 'r', encoding='utf-8') as f: ha = json.load(f)
    except Exception: ha = None
    return {
        'nodes': (NETSCALER_CONFIG, os.path.exists(NODES_CONFIG_FILE)),
        'auth': (dict(auth_config), os.path.exists(AUTH_CONFIG_FILE) and bool(auth_config.get('password_hash'))
                 and not auth_config.get('is_default_password', False) and not auth_config.get('unreadable')),
        'ldap': (dict(LDAP_CFG), os.path.exists(LDAP_CONFIG_FILE)),
        'ha_state': (ha, isinstance(ha, dict) and bool(ha)),
        'security': (dict(SEC_MARKS), os.path.exists(SECURITY_FILE)),
    }

def _detect_all_api_modes_soon():
    threading.Thread(target=_detect_all_api_modes, name='api-detect-once', daemon=True).start()

def _detect_all_api_modes():
    API_MODE.clear()
    for inst in get_instances():
        for k, cfg in ((kk, vv) for kk, vv in inst.items() if isinstance(vv, dict)):
            try: detect_api_mode_for_node(k, cfg, inst.get('id'))
            except Exception: pass

def _db_apply_document(name, doc):
    """Replace one of this dashboard's settings documents with the database's copy."""
    global LDAP_CFG
    if not isinstance(doc, dict):
        return
    if name == 'nodes':
        cfg = _sane_config(doc)
        if cfg is None:
            logger.error("The instances stored in the external database are not usable; this dashboard's own are kept")
            return
        save_nodes_config(cfg)
        apply_session_timeout()
        _detect_all_api_modes_soon()
    elif name == 'auth' and doc.get('username') and doc.get('password_hash'):
        auth_config.clear()
        auth_config.update(doc)
        save_auth_config(auth_config)
    elif name == 'ldap':
        # only the keys this dashboard knows, each in a simple type
        clean = {k: v for k, v in doc.items()
                 if k in _LDAP_ENV_DEFAULTS and isinstance(v, (str, int, bool)) and len(str(v)) <= 1024}
        if clean:
            _write_json(LDAP_CONFIG_FILE, clean, indent=2)
            LDAP_CFG = load_ldap_config()
    elif name == 'ha_state':
        clean = {str(k)[:200]: str(v)[:64] for k, v in doc.items() if isinstance(v, str)}
        _write_json(HA_STATE_FILE, clean)
    elif name == 'security':
        clean = _clean_marks(doc)
        with _sec_lock:
            _write_json(SECURITY_FILE, clean, indent=2)
            SEC_MARKS.clear()
            SEC_MARKS.update(clean)

db.register_documents(_db_documents, _db_apply_document)

@app.route('/api/database', methods=['GET', 'POST'])
@login_required
def api_database():
    if request.method == 'GET':
        return jsonify(db.status())
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, dict):
        return jsonify({"success": False, "error": "Invalid payload"}), 400
    try:
        if str(body.get('type') or '').lower() == 'builtin':
            res = db.disconnect_external()
            copied = res.get('copied')
            msg = "Now using the built-in store."
            if copied:
                msg += f" {copied['sessions']} session(s) and {copied['failover_events']} failover event(s) were copied back."
            elif res.get('reachable') is False:
                msg += " The database was not reachable, so its history was not copied back."
            return jsonify({"success": True, "message": msg, "status": db.status()})

        cfg = db.clean_config(body, db.stored_config())
        choice = str(body.get('settings_from') or '').lower()
        if choice not in ('local', 'database'):
            # Never guess which side wins: if the database already holds another
            # dashboard's settings, the administrator has to say.
            found = db.test_config(cfg)
            if found['existing']['settings']:
                return jsonify({"success": False, "needs_choice": True, "server": found['server'],
                                "existing": found['existing'],
                                "error": "This database already holds dashboard settings."}), 409
            choice = 'local'
        res = db.connect_external(cfg, choice)
        logger.info(f"External database connected by {session.get('user')}: {res['server']}")
        moved = res['moved']
        msg = f"Connected to {res['server']}."
        if moved['sessions'] or moved['failover_events']:
            msg += f" Moved {moved['sessions']} session(s) and {moved['failover_events']} failover event(s) into it."
        if choice == 'database':
            msg += " Settings were loaded from the database."
        return jsonify({"success": True, "message": msg, "status": db.status()})
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.warning(f"Database settings not applied: {db.describe_error(e)}")
        return jsonify({"success": False, "error": db.describe_error(e)}), 400

@app.route('/api/database/test', methods=['POST'])
@login_required
def api_database_test():
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, dict):
        return jsonify({"success": False, "error": "Invalid payload"}), 400
    try:
        found = db.test_config(db.clean_config(body, db.stored_config()))
        return jsonify({"success": True, "server": found['server'], "existing": found['existing']})
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": db.describe_error(e)}), 400

# ======================================================================================
# JSON API Endpoints (System & Apps)
# ======================================================================================
def _new_instance_id():
    return 'inst-' + os.urandom(4).hex()

def _clean_instance(inst, idx, stored_by_id):
    """Validate one incoming instance and preserve any blank passwords from the
    stored copy (so editing an instance without re-typing passwords is safe)."""
    iid = str(inst.get('id') or '').strip() or _new_instance_id()
    mode = str(inst.get('mode', 'ha')).lower()
    if mode not in VALID_MODES:
        mode = 'ha'
    name = str(inst.get('name') or '').strip() or f"Instance {idx + 1}"
    node_keys = ('primary',) if mode in ('standalone', 'cluster', 'sdx') else ('primary', 'secondary')
    prev = stored_by_id.get(iid, {})
    out = {'id': iid, 'name': name, 'mode': mode}
    for k in node_keys:
        nv = inst.get(k) if isinstance(inst.get(k), dict) else {}
        where = f"{name}, {k} node"
        proto = str(nv.get('protocol', 'https')).lower()
        ip = str(nv.get('ip', '') or '').strip()
        if ip and not re.fullmatch(r'[A-Za-z0-9._:\-\[\]]{1,253}', ip):
            raise ValueError(f"{where}: the address must be a host name or an IP address.")
        port = _int(nv.get('port', 443), -1)
        if not 1 <= port <= 65535:
            raise ValueError(f"{where}: the port must be between 1 and 65535.")
        pw = nv.get('password')
        if pw is not None and not isinstance(pw, str):
            raise ValueError(f"{where}: the password must be text.")
        node = {
            'ip': ip,
            'username': str(nv.get('username', '') or '').strip(),
            'port': port,
            'protocol': proto if proto in ('http', 'https') else 'https',
        }
        old = prev.get(k) if isinstance(prev.get(k), dict) else {}
        if pw:
            node['password'] = pw
        elif old.get('password') and all(node[f] == old.get(f) for f in ('ip', 'username', 'port', 'protocol')):
            node['password'] = old['password']         # blank = keep, for the same node and user only
        elif old.get('password') and ip:
            # Keeping it here would send the stored password to an address or
            # under a user name it was never entered for.
            raise ValueError(f"{where}: the address, port, protocol or user changed - enter the password again.")
        else:
            node['password'] = ''
        out[k] = node
    return out

@app.route('/api/settings', methods=['GET', 'POST'])
@login_required
def api_settings():
    if request.method == 'POST':
        body = request.get_json(force=True, silent=True)
        if not isinstance(body, dict):
            return jsonify({"success": False, "error": "Invalid payload"}), 400

        # Session inactivity timeout (minutes), clamped to a sane range.
        try:
            st = int(body.get('session_timeout_minutes', get_session_timeout_min()))
        except Exception:
            st = DEFAULT_SESSION_TIMEOUT_MIN
        st = min(max(st, 1), 1440)

        # Accept the new instances array; fall back to migrating a legacy body.
        # A body that says nothing about instances changes the timeout only.
        incoming = body.get('instances')
        legacy = any(k in body for k in ('primary', 'secondary', 'mode'))
        if incoming is None and not legacy:
            save_nodes_config({'instances': get_instances(), 'session_timeout_minutes': st})
            apply_session_timeout()
            return jsonify({"success": True, "message": "Settings updated",
                            "instances": [{'id': i['id'], 'name': i['name']} for i in get_instances()]})
        if not isinstance(incoming, list):
            incoming = _migrate_config(body).get('instances', [])

        stored_by_id = {str(i.get('id')): i for i in get_instances()}
        clean, used = [], set()
        try:
            for idx, inst in enumerate(incoming):
                if not isinstance(inst, dict):
                    continue
                ci = _clean_instance(inst, idx, stored_by_id)
                while ci['id'] in used:            # guarantee unique ids
                    ci['id'] = _new_instance_id()
                used.add(ci['id'])
                clean.append(ci)
        except ValueError as e:
            return jsonify({"success": False, "error": f"{e} Nothing was changed."}), 400
        if not clean:
            # An empty list used to replace every configured instance (and its
            # stored passwords) with one blank default.
            return jsonify({"success": False, "error": "At least one instance is required. Nothing was changed."}), 400

        try:
            save_nodes_config({'instances': clean, 'session_timeout_minutes': st})
        except OSError as e:
            logger.error(f"Settings could not be saved: {e}")
            return jsonify({"success": False, "error": "The settings could not be written to disk "
                            f"({e.strerror or e}). Nothing was changed."}), 500
        apply_session_timeout()
        _detect_all_api_modes_soon()       # in the background: a save never waits for unreachable nodes
        return jsonify({"success": True, "message": "Settings updated",
                        "instances": [{'id': i['id'], 'name': i['name']} for i in clean]})

    # GET: full config with passwords blanked.
    safe = json.loads(json.dumps(NETSCALER_CONFIG))
    for inst in safe.get('instances', []):
        for k, v in inst.items():
            if isinstance(v, dict):
                v['password'] = ''
    safe['session_timeout_minutes'] = get_session_timeout_min()
    return jsonify(safe)

def _to_pct(v):
    """Best-effort percentage float from a NITRO stat value."""
    try:
        f = float(str(v).strip())
        return round(f, 1) if f == f and f not in (float('inf'), float('-inf')) else None   # no NaN / inf in JSON
    except Exception:
        return None

def _node_probe(instance_id, node_key, cfg):
    """Cheap reachability + load probe for one node (powers the health wall)."""
    out = {'key': node_key, 'ip': cfg.get('ip', ''), 'name': '',
           'reachable': False, 'cpu': None, 'mem': None}
    if not cfg.get('ip'):
        out['error'] = 'No IP configured'
        return out
    try:
        ns = get_nitro(node_key, instance_id)._get('/stat/ns', custom_timeout=3) or {}
        ns = ns.get('ns', {})
        if isinstance(ns, list):
            ns = ns[0] if ns else {}
        out['reachable'] = bool(ns)
        out['cpu'] = _to_pct(ns.get('cpuusagepcnt', ns.get('cpuusage')))
        out['mem'] = _to_pct(ns.get('memusagepcnt', ns.get('memusagepct')))
    except Exception as e:
        out['error'] = str(e)[:100]
    if out['reachable']:
        lic = _cached_license(instance_id, node_key)
        if lic and lic.get('level') in ('warn', 'bad'):
            out['license'] = {'level': lic['level'], 'notes': lic['notes']}
    # Prefer the cached hostname; only pay for a lookup when we don't have one.
    ck = (instance_id, node_key)
    out['name'] = _HOSTNAME_CACHE.get(ck) or ''
    if out['reachable'] and not out['name']:
        try:
            hn = (get_nitro(node_key, instance_id)
                  ._get('/config/nshostname', custom_timeout=3)
                  .get('nshostname', [{}]) or [{}])[0].get('hostname')
            if hn:
                _HOSTNAME_CACHE[ck] = hn
                out['name'] = hn
        except Exception:
            pass
    return out

def _instance_health(inst):
    """One instance's health card: per-node reachability/load plus HA role+status."""
    iid = str(inst.get('id'))
    if str(inst.get('mode')) == 'sdx':
        return _sdx_health(inst)
    keys = active_node_keys(iid)
    nodes = []
    if keys:
        with ThreadPoolExecutor(max_workers=len(keys)) as ex:
            nodes = list(ex.map(lambda nk: _node_probe(iid, nk, inst.get(nk) or {}), keys))

    # Overlay HA role / hastatus (one call, from whichever node answers).
    try:
        by_ip = {}
        for n in (_get_ha_data_fast(iid).get('hanode') or []):
            if isinstance(n, dict):
                ip = n.get('ipaddress') or n.get('ip') or n.get('nsip')
                if ip:
                    by_ip[str(ip)] = n
        for nd in nodes:
            raw = by_ip.get(str(nd.get('ip')))
            if raw:
                nd['state'] = str(raw.get('state') or raw.get('hacurstate') or '')
                nd['hasync'] = str(raw.get('hasync') or '')
                nd['ha_status'] = _ha_status_meta(raw)
    except Exception:
        pass

    up = sum(1 for n in nodes if n.get('reachable'))
    total = len(nodes)
    warnings = []
    for n in nodes:
        who = n.get('name') or (n.get('key') or '').title()
        hs = n.get('ha_status') or {}
        if not n.get('reachable'):
            warnings.append(f"{who} unreachable")
        elif hs.get('severity') == 'bad' or hs.get('forced'):
            warnings.append(f"{who}: {hs.get('label')}")
        if n.get('license'):
            warnings.append(f"{who}: " + ' '.join(n['license']['notes']))

    role_trouble = False
    if str(inst.get('mode')) == 'ha' and total == 2 and up == 2:
        roles = [str(n.get('state') or '').upper() for n in nodes]
        if all(roles):
            primaries = sum(1 for r in roles if 'PRIMARY' in r)
            if primaries > 1:
                warnings.append("Both nodes report Primary (split brain)"); role_trouble = True
            elif primaries == 0:
                warnings.append("Neither node is Primary"); role_trouble = True

    if total == 0:
        status = 'unknown'
    elif up == 0:
        status = 'down'
    elif up < total or role_trouble or any((n.get('ha_status') or {}).get('severity') == 'bad' for n in nodes):
        status = 'degraded'
    else:
        status = 'up'

    return {'id': iid, 'name': inst.get('name') or iid,
            'mode': str(inst.get('mode', 'ha')).lower(), 'status': status,
            'nodes_up': up, 'nodes_total': total, 'nodes': nodes,
            'warnings': warnings}

# ======================================================================================
# SDX
# ======================================================================================
_SDX_CACHE = {}                      # instance id -> (read at, overview)
_SDX_SOURCES = ('mps', 'mps_health', 'ns', 'xen_health_resource_hw', 'xen_health_monitor', 'xen_health_interface',
                'xen_health_disk', 'sdx_license', 'license_expiry_info')
_sdx_pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix='sdx')

def _rows(v):
    if isinstance(v, dict):
        return [v]
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []

def _pick_any(d, keys, default=''):
    for k in keys:
        v = d.get(k)
        if v not in (None, '', 'NA', 'N/A'):
            return v
    return default

def _bad_status(v):
    return str(v or '').strip().upper() in ('ERROR', 'FAILED', 'FAIL', 'CRITICAL', 'DOWN', 'BAD')

def _dashboard_instances_by_ip():
    """IP -> {id, name, node} for every NetScaler instance configured here."""
    out = {}
    for i in get_instances():
        if str(i.get('mode')) == 'sdx':
            continue
        for nk in ('primary', 'secondary'):
            ip = str((i.get(nk) or {}).get('ip') or '').strip()
            if ip:
                out.setdefault(ip, {'id': str(i.get('id')), 'name': i.get('name') or str(i.get('id')), 'node': nk})
    return out

def sdx_overview(instance_id=None, fresh=False):
    """Everything the SDX view shows, read in parallel from the Management Service.
    A part that cannot be read is named in 'errors'; nothing is ever written."""
    iid = str(get_instance(instance_id).get('id'))
    hit = _SDX_CACHE.get(iid)
    if hit and not fresh and time.time() - hit[0] < 30:
        return hit[1]
    api = get_sdx(iid)

    def one(name):
        try:
            d = api._get('/config/' + name, custom_timeout=8) or {}
            return name, d.get(name, []), None
        except Exception as e:
            return name, None, str(e)[:160]

    got, errors = {}, {}
    for name, val, err in _sdx_pool.map(one, _SDX_SOURCES):
        if err is None:
            got[name] = val
        else:
            errors[name] = err
    reachable = 'mps' in got or 'ns' in got
    mps = (_rows(got.get('mps')) or [{}])[0]
    health = (_rows(got.get('mps_health')) or [{}])[0]
    platform = {
        'hostname': str(_pick_any(mps, ['hostname'])), 'platform': str(_pick_any(mps, ['platform'])),
        'serial': str(_pick_any(mps, ['serial'])), 'product': str(_pick_any(mps, ['product'])),
        'version': ' '.join(str(x) for x in (_pick_any(mps, ['product_version']), _pick_any(mps, ['build_number_short', 'build_number'])) if x),
        'bios': str(_pick_any(mps, ['bios_version'])), 'uptime': str(_pick_any(mps, ['uptime'])),
        'hypervisor_uptime': str(_pick_any(mps, ['hypervisor_uptime'])),
        'cpu': _to_pct(health.get('cpu_usage')), 'memory': _to_pct(health.get('memory_usage')),
        'disk': _to_pct(health.get('disk_usage')),
    }
    hardware = []
    for kind, src in (('Hardware', 'xen_health_resource_hw'), ('Sensor', 'xen_health_monitor')):
        for x in _rows(got.get(src)):
            hardware.append({'kind': kind, 'name': str(_pick_any(x, ['name'], '?')),
                             'value': str(_pick_any(x, ['current_value'])), 'expected': str(_pick_any(x, ['expected_value'])),
                             'unit': str(_pick_any(x, ['unit'])), 'status': str(_pick_any(x, ['status'], 'NA')),
                             'failures': _int(x.get('number_of_failures'), 0)})
    interfaces = [{'port': str(_pick_any(x, ['port', 'mapped_port'], '?')), 'name': str(_pick_any(x, ['display_name', 'mapped_port'])),
                   'state': str(_pick_any(x, ['state'], '?')), 'rx_errors': _int(x.get('rx_errors'), 0),
                   'tx_errors': _int(x.get('tx_errors'), 0), 'vf': f"{_int(x.get('vf_assigned'), 0)}/{_int(x.get('vf_total'), 0)}"}
                  for x in _rows(got.get('xen_health_interface'))]
    disks = [{'name': str(_pick_any(x, ['name', 'disk_name', 'device_name', 'slot'], '?')),
              'status': str(_pick_any(x, ['status', 'state', 'health'], 'NA')),
              'size': str(_pick_any(x, ['size', 'capacity', 'disk_size', 'total_size'])),
              'detail': {k: str(v)[:80] for k, v in x.items() if k not in ('id',) and v not in (None, '')}}
             for x in _rows(got.get('xen_health_disk'))]
    lic = (_rows(got.get('sdx_license')) or [{}])[0]
    license_ = {
        'platform': str(_pick_any(lic, ['platform'])), 'server': str(_pick_any(lic, ['license_server_name'])),
        'pooled': _truthy(lic.get('is_pooled_license')),
        'max_throughput': _int(lic.get('max_throughput'), 0), 'available_throughput': _int(lic.get('available_throughput'), 0),
        'max_instances': _int(_pick_any(lic, ['max_number_of_ns_instances', 'max_number_of_instances'], 0), 0),
        'available_instances': _int(_pick_any(lic, ['available_number_of_ns_instances', 'available_number_of_instances'], 0), 0),
        'expiring': sorted(({'feature': str(_pick_any(x, ['feature'], '?')), 'days': _int(x.get('expirydays'), -1),
                             'count': _int(x.get('expirycount'), 0)} for x in _rows(got.get('license_expiry_info'))),
                           key=lambda e: e['days'] if e['days'] >= 0 else 10 ** 9),
    }
    by_ip = _dashboard_instances_by_ip()
    instances = []
    for x in _rows(got.get('ns')):
        ip = str(_pick_any(x, ['ip_address', 'ipv4_address']))
        vm = str(_pick_any(x, ['vm_state'], '?'))
        st = str(_pick_any(x, ['instance_state', 'state'], '?'))
        instances.append({
            'name': str(_pick_any(x, ['name'], ip or '?')), 'ip': ip, 'vm_state': vm, 'state': st,
            'status': str(_pick_any(x, ['status'])), 'health': str(_pick_any(x, ['health'])),
            'reason': str(_pick_any(x, ['reason']))[:200], 'role': str(_pick_any(x, ['instance_mode'])),
            'version': str(_pick_any(x, ['version'])), 'cpu': _to_pct(x.get('ns_cpu_usage')),
            'memory': _to_pct(x.get('ns_memory_usage')), 'throughput': _int(x.get('throughput'), 0),
            'rx': _pick_any(x, ['ns_rx']), 'tx': _pick_any(x, ['ns_tx']), 'http_req': _pick_any(x, ['http_req']),
            'cores': _int(_pick_any(x, ['cpu_core_pe', 'number_of_cpu', 'number_of_cores'], 0), 0),
            'memory_mb': _int(x.get('vm_memory_total'), 0), 'uptime': str(_pick_any(x, ['uptime'])),
            'license': str(_pick_any(x, ['license', 'license_edition'])),
            'ok': vm.lower() == 'running' and st.upper() in ('UP', '?'),
            'dashboard': by_ip.get(ip),
        })
    instances.sort(key=lambda i: i['name'].lower())
    data = {
        'instance': iid, 'reachable': reachable, 'platform': platform, 'hardware': hardware,
        'hardware_errors': [h for h in hardware if _bad_status(h['status'])],
        'interfaces': interfaces, 'disks': disks, 'license': license_, 'instances': instances,
        'errors': errors, 'read_at': time.time(),
    }
    _SDX_CACHE[iid] = (time.time(), data)
    return data

def _sdx_health(inst):
    """The health wall card of an SDX: the platform, its hardware, its instances."""
    iid = str(inst.get('id'))
    cfg = inst.get('primary') or {}
    node = {'key': 'primary', 'ip': cfg.get('ip', ''), 'name': '', 'reachable': False, 'cpu': None, 'mem': None}
    out = {'id': iid, 'name': inst.get('name') or iid, 'mode': 'sdx', 'status': 'unknown', 'nodes_up': 0,
           'nodes_total': 1, 'nodes': [node], 'warnings': []}
    if not cfg.get('ip'):
        node['error'] = 'No IP configured'
        return out
    try:
        d = sdx_overview(iid)
    except Exception as e:
        node['error'] = str(e)[:100]
        out['status'] = 'down'
        out['warnings'].append('Management Service unreachable')
        return out
    if not d['reachable']:
        out['status'] = 'down'
        out['warnings'].append('Management Service unreachable')
        node['error'] = next(iter(d['errors'].values()), 'no answer')
        return out
    p = d['platform']
    node.update(reachable=True, name=p.get('hostname') or 'Management Service', cpu=p.get('cpu'), mem=p.get('memory'))
    out['nodes_up'] = 1
    warn = [f"{h['name']}: {h['status']}" for h in d['hardware_errors']][:4]
    down = [i for i in d['instances'] if not i['ok']]
    warn += [f"{i['name']}: {i['vm_state']}/{i['state']}" for i in down][:4]
    soon = [e for e in d['license']['expiring'] if 0 <= e['days'] <= LICENSE_WARN_DAYS]
    warn += [f"License {e['feature']} expires in {e['days']} day(s)" for e in soon][:2]
    out['warnings'] = warn
    out['status'] = 'degraded' if (d['hardware_errors'] or down or soon) else 'up'
    out['sdx'] = {'platform': p.get('platform'), 'version': p.get('version'), 'hostname': p.get('hostname'),
                  'hardware_errors': len(d['hardware_errors']),
                  'instances': [{'name': i['name'], 'ip': i['ip'], 'ok': i['ok'], 'vm_state': i['vm_state'],
                                 'state': i['state'], 'dashboard': i['dashboard']} for i in d['instances']]}
    return out

def sdx_host_of(ip):
    """The SDX (from what was read lately) that hosts the NetScaler at this IP."""
    for iid, (ts, d) in list(_SDX_CACHE.items()):
        if time.time() - ts > 3600:
            continue
        for i in d.get('instances', []):
            if i.get('ip') and i['ip'] == str(ip):
                inst = next((x for x in get_instances() if str(x.get('id')) == iid), {})
                return {'sdx_id': iid, 'sdx_name': inst.get('name') or iid, 'vpx_name': i['name'],
                        'hostname': (d.get('platform') or {}).get('hostname', '')}
    return None

@app.route('/api/sdx/overview')
@login_required
def api_sdx_overview():
    inst = request.args.get('instance')
    if get_mode(inst) != 'sdx':
        return jsonify({'error': 'This instance is not an SDX.'}), 400
    try:
        d = sdx_overview(inst, fresh=request.args.get('fresh') == '1')
    except KeyError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'The Management Service could not be read: {str(e)[:200]}'}), 502
    if not d['reachable']:
        return jsonify({'error': 'The Management Service could not be read: '
                                 + next(iter(d['errors'].values()), 'no answer'), 'errors': d['errors']}), 502
    return jsonify(d)

def start_api_detect_thread():
    """Re-check each node's API capability periodically, so the Next-Gen API being
    enabled on an appliance — or a node that was simply unreachable at boot — is
    picked up on its own, without a restart or any manual action."""
    interval = _int(os.getenv('API_DETECT_INTERVAL_SECS', '600'), 600)
    if interval <= 0:
        return

    def _loop():
        while True:
            time.sleep(interval)
            try:
                for inst in get_instances():
                    iid = inst.get('id')
                    for nk in active_node_keys(iid):
                        detect_api_mode_for_node(nk, inst.get(nk) or {}, iid)
            except Exception as e:
                logger.warning(f"API capability re-detection failed: {e}")

    threading.Thread(target=_loop, name='api-detect', daemon=True).start()
    logger.info(f"API capability re-detection every {interval}s")

@app.route('/api/detect-api', methods=['POST'])
@login_required
def api_detect_api():
    """Re-run API capability detection now, without restarting the dashboard —
    so enabling the Next-Gen API on the appliance is picked up immediately."""
    body = request.get_json(silent=True) or {}
    inst = request.args.get('instance') or body.get('instance')
    i = get_instance(inst)
    out = {}
    for k in active_node_keys(inst):
        detect_api_mode_for_node(k, i.get(k) or {}, i.get('id'))
        out[k] = dict(get_detect_info(inst, k), mode=get_api_mode(inst, k))
    return jsonify({'success': True, 'instance': i.get('id'), 'nodes': out})

@app.route('/api/nextgen-debug')
@login_required
def api_nextgen_debug():
    """Why Next-Gen isn't being used: version, reachable management paths, and
    the actual login error for each node of the instance."""
    inst = request.args.get('instance')
    i = get_instance(inst)
    return jsonify({
        'instance': i.get('id'),
        'base_path': NEXTGEN_BASE_PATH,
        'ns_port_https': _int(os.getenv('NS_PORT_HTTPS', '443'), 443),
        'nodes': {k: _nextgen_probe(i.get(k) or {}) for k in active_node_keys(inst)},
    })

@app.route('/api/instances-health')
@login_required
def api_instances_health():
    """Health of every configured instance, for the all-instances wall.
    Instances (and their nodes) are probed in parallel so the wall stays fast."""
    insts = get_instances()
    if not insts:
        return jsonify({'instances': []})
    with ThreadPoolExecutor(max_workers=min(8, len(insts))) as ex:
        out = list(ex.map(_instance_health, insts))
    return jsonify({'instances': out,
                    'generated': datetime.now(APP_TZ).strftime('%d/%m/%Y %H:%M:%S')})

@app.route('/api/instances')
@login_required
def api_instances():
    """Lightweight instance list for the switcher and the aggregate wall."""
    out = []
    for i in get_instances():
        out.append({
            'id': i.get('id'), 'name': i.get('name'),
            'mode': str(i.get('mode', 'ha')).lower(),
            'nodes': [{'key': k, 'ip': v.get('ip', '')}
                      for k, v in i.items() if isinstance(v, dict)],
        })
    return jsonify({'instances': out})

@app.route('/api/tls-cert', methods=['POST'])
@login_required
def api_tls_cert():
    body = request.get_json(force=True, silent=True) or {}
    cert_val = body.get('cert')
    key_val = body.get('key')
    if not isinstance(cert_val, str) or (key_val is not None and not isinstance(key_val, str)):
        return jsonify({"success": False, "error": "Certificate and key must be PEM strings"}), 400
    cert_pem = cert_val.strip().encode('utf-8')
    key_pem = (key_val or '').strip().encode('utf-8')
    if not cert_pem:
        return jsonify({"success": False, "error": "Certificate (PEM) is required"}), 400
    try:
        if key_pem:
            from cert_utils import save_pair
            info = save_pair(cert_pem, key_pem)
        else:
            # No key supplied: pair the cert with the key left on disk from a CSR.
            from cert_utils import save_signed_cert
            info = save_signed_cert(cert_pem)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"TLS cert replace failed: {e}")
        return jsonify({"success": False, "error": "Could not save certificate"}), 500
    logger.info(f"TLS certificate replaced by {session.get('user')!r}: {info.get('subject')}, expires {info.get('expires')}")
    msg = (f"Certificate saved and in use for new connections now. Valid for: "
           f"{', '.join(info.get('names') or []) or info.get('subject')}; expires {info.get('expires')}.")
    if info.get('days_left', 999) <= 30:
        msg += f" Note: it expires in {info['days_left']} day(s)."
    return jsonify({"success": True, "message": msg, "certificate": info})

@app.route('/api/tls-ca')
@login_required
def api_tls_ca():
    """Download the local CA certificate to install in a trust store."""
    try:
        from cert_utils import CA_CERT_FILE, ensure_ca
        ensure_ca()
        with open(CA_CERT_FILE, 'rb') as f:
            pem = f.read()
    except Exception as e:
        logger.error(f"CA download failed: {e}")
        return jsonify({"success": False, "error": "No CA certificate available"}), 404
    from flask import Response
    return Response(pem, mimetype='application/x-pem-file',
                    headers={'Content-Disposition': 'attachment; filename="netscaler-dashboard-ca.crt"'})

@app.route('/api/tls-csr', methods=['POST'])
@login_required
def api_tls_csr():
    """Generate a new key + CSR to be signed by your own/corporate CA."""
    body = request.get_json(force=True, silent=True) or {}
    cn, sans = body.get('common_name'), body.get('san')
    if cn is not None and not isinstance(cn, str) or sans is not None and not isinstance(sans, str):
        return jsonify({"success": False, "error": "The host name and the alternative names must be text."}), 400
    cn = (cn or '').strip() or None
    try:
        from cert_utils import generate_csr
        csr_pem = generate_csr(common_name=cn, extra_san=sans).decode('utf-8')
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"CSR generation failed: {e}")
        return jsonify({"success": False, "error": "Could not generate CSR"}), 500
    return jsonify({"success": True, "csr": csr_pem,
                    "message": "CSR generated (a new private key was written; an earlier unsigned request is no longer valid). Get it signed, then upload the signed certificate below."})

@app.route('/api/ping')
@login_required
def api_ping():
    # Cheap keepalive: reaching here already refreshed activity (before_request),
    # since the frontend sends it without the X-Idle-Refresh header on real interaction.
    return jsonify({"ok": True, "timeout_min": get_session_timeout_min()})

@app.route('/api/caps')
@login_required
def api_caps():
    inst = request.args.get('instance')
    iid = get_instance(inst).get('id')
    mode = get_mode(inst)
    if mode == 'sdx':
        v = get_instance(inst).get('primary') or {}
        hit = _SDX_CACHE.get(str(iid))
        name = ((hit[1].get('platform') or {}).get('hostname') if hit else '') or 'Management Service'
        return jsonify({'api_mode': {'primary': 'sdx'}, 'mode': 'sdx', 'primary_node': 'primary', 'instance': iid,
                        'api_detect': {'primary': {'mode': 'sdx', 'reason': 'SDX Management Service (NITRO v2)'}},
                        'nodes': {'primary': {'ip': v.get('ip', ''), 'protocol': v.get('protocol', 'https'),
                                              'port': v.get('port', 443), 'name': name}}})
    default_name = {'primary': 'Cluster (CLIP)' if mode == 'cluster' else 'Primary', 'secondary': 'Secondary'}
    nodes_data = {}
    for k in active_node_keys(inst):
        v = get_instance(inst).get(k, {})
        cache_key = (iid, k)
        try:
            if v.get('ip'):
                hn = get_nitro(k, inst)._get('/config/nshostname', custom_timeout=3).get('nshostname', [{}])[0].get('hostname')
                if hn:
                    _HOSTNAME_CACHE[cache_key] = hn      # remember the real hostname
                else:
                    hn = _HOSTNAME_CACHE.get(cache_key) or default_name.get(k, k.title())
            else:
                hn = f"{default_name.get(k, k.title())} Node"
        except Exception:
            # Node briefly unreachable — keep the last-known hostname if we have one
            # so a network blip doesn't blank the name (e.g. the secondary).
            hn = _HOSTNAME_CACHE.get(cache_key) or default_name.get(k, k.title())
        nodes_data[k] = {'ip': v.get('ip', ''), 'protocol': v.get('protocol', 'https'), 'port': v.get('port', 443), 'name': hn }
    api_mode = {k: get_api_mode(inst, k) for k in active_node_keys(inst)}
    detect = {k: get_detect_info(inst, k) for k in active_node_keys(inst)}
    # Which node currently holds the PRIMARY role, so the UI can follow a failover
    # instead of sticking to whichever node happens to be selected.
    primary_node = 'primary'
    if mode == 'ha':
        try:
            roles = {}
            for n in (_get_ha_data_fast(inst).get('hanode') or []):
                if isinstance(n, dict):
                    ipv = n.get('ipaddress') or n.get('ip') or n.get('nsip')
                    if ipv:
                        roles[str(ipv)] = str(n.get('state') or n.get('hacurstate') or '').upper()
            for k in active_node_keys(inst):
                if 'PRIMARY' in roles.get(str((get_instance(inst).get(k) or {}).get('ip')), ''):
                    primary_node = k
                    break
        except Exception:
            pass
    return jsonify({'api_mode': api_mode, 'nodes': nodes_data, 'mode': mode,
                    'api_detect': detect, 'primary_node': primary_node,
                    'instance': get_instance(inst).get('id')})

@app.route('/api/system-stats')
@login_required
def api_system_stats():
    inst = request.args.get('instance')
    node = request.args.get('node')
    if node:
        try:
            ov = _build_node_overview(node, inst)
            ov['hosted_on'] = sdx_host_of(ov.get('ip'))
            return jsonify({'node': node, 'api_mode': get_api_mode(inst, node), **ov})
        except Exception as e: return jsonify({'error': str(e)}), 500
    try:
        return jsonify({
            'primary': _build_node_overview('primary', inst),
            'secondary': _build_node_overview('secondary', inst),
        })
    except Exception:
        return jsonify({'primary': {'connected': False}, 'secondary': {'connected': False}}), 200

@app.route('/api/ha-status')
@login_required
def api_ha_status():
    inst = request.args.get('instance')
    ha_data = _get_ha_data_fast(inst)
    nodes = ha_data.get('hanode', []) if isinstance(ha_data, dict) else []
    track_ha_state_changes(nodes, inst)

    def get_config_changed(node_key):
        try:
            cfg_resp = get_nitro(node_key, inst)._get('/config/nsconfig', custom_timeout=2).get('nsconfig')
            if isinstance(cfg_resp, list) and len(cfg_resp) > 0:
                return str(cfg_resp[0].get('configchanged', 'false')).lower() in ['true', '1', 'yes']
            elif isinstance(cfg_resp, dict):
                return str(cfg_resp.get('configchanged', 'false')).lower() in ['true', '1', 'yes']
            return False
        except Exception: return False

    hostnames = {}
    for nk in active_node_keys(inst):
        try:
            nit = get_nitro(nk, inst)
            hn = nit._get('/config/nshostname', custom_timeout=2).get('nshostname', [{}])[0].get('hostname')
            if hn: hostnames[nit.ip] = hn
        except Exception: pass

    for n in nodes:
        if not isinstance(n, dict): continue
        ip = n.get('ipaddress') or n.get('ip') or n.get('nsip')
        if ip and not n.get('name') and hostnames.get(ip): n['name'] = hostnames[ip]
        if not n.get('name'):
            st = str(n.get('state', '')).upper()
            n['name'] = 'Primary' if 'PRIMARY' in st else ('Secondary' if 'SECONDARY' in st else (hostnames.get(ip) or 'node'))
        n['ha_status'] = _ha_status_meta(n)

    result = {'mode': get_mode(inst), 'hanode': nodes}
    for nk in active_node_keys(inst):
        result[nk] = {'config_changed': get_config_changed(nk)}
    return jsonify(result)

@app.route('/api/lb-vservers')
@login_required
def api_lb_vservers():
    inst = request.args.get('instance')
    node = request.args.get('node')
    if not node: return jsonify({'connected': False, 'data': {'lbvserver': []}})

    if get_api_mode(inst, node) == 'nextgen':
        try:
            ng = get_nextgen(node, inst)
            ng.login()
            apps = ng.list_applications()
            items = apps.get('applications', []) if isinstance(apps, dict) else (apps if isinstance(apps, list) else [])
            lbv_like = [{'name': a.get('name'), 'ipv46': a.get('vip') or a.get('vipAddress'), 'port': a.get('port'), 'curstate': a.get('state') or 'UP'} for a in items]
            ng.logout()
            # Only answer from Next-Gen when it actually has applications; an empty
            # list usually means the config still lives in classic LB vServers.
            if lbv_like:
                return jsonify({'node': node, 'api_mode': 'nextgen', 'lbvserver': lbv_like})
        except Exception as e:
            logger.warning(f"Next-Gen applications unavailable on {node}, using NITRO: {str(e)[:120]}")

    try:
        data = get_nitro(node, inst)._get('/config/lbvserver', custom_timeout=5) or {}
        return jsonify({'node': node, 'api_mode': 'nitro',
                        **({'lbvserver': data.get('lbvserver', [])} if isinstance(data, dict) else {'lbvserver': []})})
    except Exception: return jsonify({'lbvserver': []})

@app.route('/api/services')
@login_required
def api_services():
    inst = request.args.get('instance')
    node = request.args.get('node')
    if not node: return jsonify({'connected': False, 'data': {'service': [], 'servicegroup': []}})

    # Services and service groups are NITRO objects; a Next-Gen-capable appliance
    # still serves them, so always read them over NITRO rather than returning
    # empty lists (which made the table look broken on a 14.1 node).
    try:
        nitro = get_nitro(node, inst)
        svc  = nitro._get('/config/service', custom_timeout=5) or {}
        sgrp = nitro._get('/config/servicegroup', custom_timeout=5) or {}
        return jsonify({'node': node, 'api_mode': get_api_mode(inst, node),
                        'service': svc.get('service', []) if isinstance(svc, dict) else [],
                        'servicegroup': sgrp.get('servicegroup', []) if isinstance(sgrp, dict) else []})
    except Exception as e:
        logger.warning(f"services fetch failed on {node}: {str(e)[:120]}")
        return jsonify({'service': [], 'servicegroup': []})

# ======================================================================================
# SSL Certificates, chain links & CRLs
# ======================================================================================
@app.route('/api/certificates')
@login_required
def api_certificates():
    inst = request.args.get('instance')
    node = request.args.get('node') or 'primary'
    try:
        nitro = get_nitro(node, inst)
    except KeyError:
        return jsonify({'error': f"Unknown node '{node}'"}), 400

    def _fetch(path, key):
        try:
            data = nitro._get(path, custom_timeout=8) or {}
            val = data.get(key, [])
            if isinstance(val, list): return val
            return [val] if val else []
        except Exception as e:
            logger.warning(f"certificates: {path} failed on {node}: {e}")
            return []

    return jsonify({
        'node': node,
        'certificates': _fetch('/config/sslcertkey', 'sslcertkey'),
        'links': _fetch('/config/sslcertlink', 'sslcertlink'),
        'crls': _fetch('/config/sslcrl', 'sslcrl'),
    })

@app.route('/api/history-stats')
@login_required
def api_history_stats():
    """Local history DB size, row counts, oldest data and retention window."""
    try:
        return jsonify(db.stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ======================================================================================
# Advanced Sessions, Failover History & User Actions
# ======================================================================================
def _pick(s, keys):
    for k in keys:
        v = str(s.get(k, '')).strip()
        if v and v not in ('None', '0.0.0.0', '::'):
            return v
    return ''

def _synthetic_row(user, status, when='', conn_type='—', gateway='—', ip='—', extra=None, sid=None):
    """A non-connection row (Failed attempt / Locked account) shaped like a session
    so it renders in the same table. Persisted with its explicit status."""
    detail = {'gateway': gateway, 'protocol': '—', 'resource': '—', 'source_ip': ip, 'intranet_ip': '—',
              'client_os': '—', 'kind': {'Failed': 'Failed sign-in', 'Locked': 'Locked account'}.get(status, status)}
    if extra:
        detail.update(extra)
    return {
        'user': user or 'Unknown', 'session_id': sid or f"{user}|{status}",
        'type': conn_type, 'status': status, 'duration': '—',
        'ip': ip or '—', 'gateway': gateway or '—',
        'start': when or '', 'end': '', 'detail': detail,
    }

_VS_CACHE = {}
_VS_CACHE_LOCK = threading.Lock()

def _vserver_map(nitro, iid):
    """'ip:port' -> (virtual server name, kind) and server ip -> server name, so a
    session's addresses can be shown by name. Cached for five minutes."""
    with _VS_CACHE_LOCK:
        hit = _VS_CACHE.get(iid)
    if hit and time.time() - hit[0] < 300:
        return hit[1], hit[2]
    vmap, smap = {}, {}
    for path, key, kind in (('/config/vpnvserver?attrs=name,ipv46,port', 'vpnvserver', 'vpn'),
                            ('/config/authenticationvserver?attrs=name,ipv46,port', 'authenticationvserver', 'auth'),
                            ('/config/csvserver?attrs=name,ipv46,port', 'csvserver', 'cs'),
                            ('/config/lbvserver?attrs=name,ipv46,port', 'lbvserver', 'lb')):
        try:
            rows = (nitro._get(path, custom_timeout=5) or {}).get(key) or []
        except Exception:
            continue
        for v in rows if isinstance(rows, list) else []:
            ip = str(v.get('ipv46') or '').strip()
            if ip and ip not in ('0.0.0.0', '::'):
                vmap.setdefault(f"{ip}:{_int(v.get('port'), 0)}", (str(v.get('name') or ''), kind))
    try:
        for sv in (nitro._get('/config/server?attrs=name,ipaddress', custom_timeout=5) or {}).get('server') or []:
            if isinstance(sv, dict) and sv.get('ipaddress'):
                smap.setdefault(str(sv['ipaddress']), str(sv.get('name') or ''))
    except Exception:
        pass
    with _VS_CACHE_LOCK:
        _VS_CACHE[iid] = (time.time(), vmap, smap)
    return vmap, smap

def _cached_vserver_map(iid):
    with _VS_CACHE_LOCK:
        hit = _VS_CACHE.get(iid)
    return (hit[1], hit[2]) if hit else ({}, {})

def _ica_list(nitro):
    """Live ICA connections (TCP and EDT/DTLS), lower-cased keys."""
    out = []
    for path, key in (('/config/vpnicaconnection', 'vpnicaconnection'),
                      ('/config/vpnicadtlsconnection', 'vpnicadtlsconnection')):
        try:
            for raw in (nitro._get(path, custom_timeout=5) or {}).get(key) or []:
                if isinstance(raw, dict):
                    row = {str(k).lower(): v for k, v in raw.items()}
                    row['_dtls'] = key.endswith('dtlsconnection')
                    out.append(row)
        except Exception:
            continue
    return out

def _ica_entry(c, smap):
    dest = str(c.get('destip') or '')
    proto = str(c.get('transproto') or ('UDP' if c.get('_dtls') else 'TCP')).upper()
    return {'server': smap.get(dest) or dest or '—',
            'dest': f"{dest}:{c.get('destport')}" if dest else '—',
            'client': f"{c.get('srcip')}:{c.get('srcport')}" if c.get('srcip') else '—',
            'protocol': 'ICA over EDT (UDP)' if proto == 'UDP' else 'ICA (TCP)',
            'domain': str(c.get('domain') or '')}

def _live_sessions(nitro, iid):
    """Active Gateway / AAA sessions from /config/aaasession. NetScaler lists one
    entry per connection, so entries of one user from one address through one
    virtual server are one session. Raises when the node does not answer."""
    vmap, smap = _vserver_map(nitro, iid)
    try:
        aaa = (nitro._get('/config/aaasession', custom_timeout=6) or {}).get('aaasession') or []
    except requests.HTTPError as e:
        logger.info(f"AAA sessions could not be read: {e}")
        aaa = []
    groups = {}
    for raw in aaa if isinstance(aaa, list) else []:
        try:
            if not isinstance(raw, dict):
                continue
            s = {str(k).lower(): v for k, v in raw.items()}
            user = str(s.get('username') or '').strip()
            if not user:
                continue
            pub = _pick(s, ['publicip', 'clientip', 'srcip'])
            vip = f"{s.get('ipaddress')}:{_int(s.get('port'), 0)}" if s.get('ipaddress') else ''
            g = groups.setdefault((user.lower(), pub, vip), {
                'user': user, 'ip': pub, 'vip': vip, 'conns': 0, 'dest': set(),
                'intranet': '', 'group': '', 'private': '', 'key': ''})
            g['conns'] += 1
            if s.get('destip') and str(s.get('destip')) not in ('0.0.0.0', '::'):
                g['dest'].add(f"{s.get('destip')}:{s.get('destport')}")
            g['intranet'] = g['intranet'] or _pick(s, ['intranetip', 'intranetip6', 'iip'])
            g['group'] = g['group'] or str(s.get('groupname') or '')
            g['private'] = g['private'] or _pick(s, ['privateip'])
            g['key'] = g['key'] or str(s.get('sessionkey') or '')
        except Exception as e:
            logger.info(f"Skipped an aaasession row that could not be read: {e}")
    ica = _ica_list(nitro)
    rows, now_txt, ica_users = [], datetime.now(APP_TZ).strftime('%d/%m/%Y %H:%M:%S'), set()
    for g in groups.values():
        name, kind = vmap.get(g['vip'], ('', ''))
        mine = [c for c in ica if str(c.get('username') or '').lower() == g['user'].lower()
                and (not c.get('srcip') or not g['ip'] or str(c.get('srcip')) == g['ip'])]
        if mine:
            ica_users.add(g['user'].lower())
        if g['intranet']:
            ctype = 'VPN (Full Tunnel)'
        elif kind in ('lb', 'cs', 'auth'):
            ctype = 'Web (AAA)'
        else:
            ctype = 'Web / Workspace'
        dests = sorted(g['dest'])
        detail = {
            'gateway': name or g['vip'] or '—', 'gateway_address': g['vip'] or '—',
            'protocol': 'ICA' if mine else ('SSL-VPN' if g['intranet'] else 'HTTPS'),
            'resource': ', '.join(sorted({_ica_entry(c, smap)['server'] for c in mine})) or
                        ', '.join(smap.get(d.rsplit(':', 1)[0]) or d for d in dests[:5]) or '—',
            'source_ip': g['ip'] or '—', 'intranet_ip': g['intranet'] or '—', 'mapped_ip': g['private'] or '—',
            'groups': g['group'] or '—', 'connections': g['conns'], 'destinations': dests[:20],
            'ica_live': [_ica_entry(c, smap) for c in mine][:20],
            'kind': {'vpn': 'Gateway', 'auth': 'Authentication', 'lb': 'AAA-TM (load balancing)',
                     'cs': 'AAA-TM (content switching)'}.get(kind, 'Gateway/AAA'),
        }
        rows.append({'user': g['user'], 'session_id': g['key'] or f"{g['user']}|{g['ip']}|{name or g['vip']}",
                     'type': ctype, 'status': 'Active', 'duration': '', 'ip': g['ip'] or 'Unknown',
                     'gateway': name or g['vip'] or 'Unknown', 'start': now_txt, 'end': 'Active', 'detail': detail})
    # ICA proxy users who hold an application connection but no AAA session entry
    for c in ica:
        u = str(c.get('username') or '')
        if not u or u.lower() in ica_users:
            continue
        ica_users.add(u.lower())
        e = _ica_entry(c, smap)
        rows.append({'user': u, 'session_id': f"{u}|{c.get('srcip')}|ica", 'type': 'Web / Workspace',
                     'status': 'Active', 'duration': '', 'ip': str(c.get('srcip') or 'Unknown'), 'gateway': 'Unknown',
                     'start': now_txt, 'end': 'Active',
                     'detail': {'gateway': '—', 'protocol': 'ICA', 'resource': e['server'], 'source_ip': str(c.get('srcip') or '—'),
                                'intranet_ip': '—', 'kind': 'ICA proxy', 'ica_live': [e]}})
    return rows

# --------------------------------------------------- sessions: log lines
_CLIENT_TYPES = {'ICA': 'Web / Workspace (ICA proxy)', 'CVPN': 'Clientless VPN', 'RDP': 'RDP proxy',
                 'VPN': 'VPN (Full Tunnel)', 'AGENT': 'VPN (Full Tunnel)', 'PLUGIN': 'VPN (Full Tunnel)'}

def _fmt_ts(ts):
    try:
        return datetime.fromtimestamp(float(ts), APP_TZ).strftime('%d/%m/%Y %H:%M:%S') if ts else ''
    except Exception:
        return ''

def _fmt_dur(secs):
    secs = max(0, int(secs or 0))
    h, m = divmod(secs // 60, 60)
    return f"{h} h {m} min" if h else f"{m} min"

def _apply_gateway_lines(r, rec, vmap):
    """Fill a session from the Gateway's LOGIN/LOGOUT lines for it."""
    li, lo = rec.get('login'), rec.get('logout')
    first = li or lo
    f = dict((lo or {}).get('detail') or {})
    f.update((li or {}).get('detail') or {})
    d = r.setdefault('detail', {})
    start = li['ts'] if li else float(f.get('start_epoch') or lo['ts'])
    r['_start_ts'] = min(start, r.get('_start_ts') or start)
    vs = f.get('vserver') or first.get('url') or ''
    name = vmap.get(vs, ('', ''))[0]
    if name or vs:
        if str(r.get('gateway') or '') in ('', 'Unknown', '—') or r.get('gateway') == vs or str(r.get('gateway', '')).startswith('N/A'):
            r['gateway'] = name or vs
        d['gateway'] = d.get('gateway') if d.get('gateway') not in (None, '', '—', vs) else (name or vs)
        d['gateway_address'] = vs or d.get('gateway_address', '—')
    ct = str(f.get('sslvpn_client_type') or '').upper()
    if ct:
        d['client_type'] = ct
        r['type'] = _CLIENT_TYPES.get(ct, r.get('type') or ct)
    d['gateway_session_id'] = first.get('session') or d.get('gateway_session_id', '—')
    for src, dst in (('browser_type', 'user_agent'), ('group(s)', 'groups'), ('nat_ip', 'mapped_ip'),
                     ('total_bytes_send', 'bytes_sent'), ('total_bytes_recv', 'bytes_received'),
                     ('total_tcp_connections', 'tcp_connections'), ('http_resources_accessed', 'http_resources')):
        v = f.get(src)
        if v and v not in ('N/A', 'Mapped Ip') and d.get(dst) in (None, '', '—'):
            d[dst] = v
    if lo:
        d['logout_method'] = lo.get('action') or f.get('logoutmethod') or '—'
        d['logout_time'] = _fmt_ts(lo['ts'])
        if r.get('status') != 'Active':
            r['status'], r['_end_ts'] = 'Terminated', lo['ts']
    d['login_time'] = _fmt_ts(start)

def _row_from_gateway_lines(rec, vmap, live_ok):
    """A session known only from its log lines. Without a logout line it is
    'Unknown' for 12 hours (the appliance did not list it, but nothing says it
    ended), then 'Terminated'."""
    first = rec.get('login') or rec.get('logout')
    status = 'Terminated'
    if not rec.get('logout') and time.time() - first['ts'] < 12 * 3600:
        status = 'Unknown'
    r = {'user': first.get('username') or 'Unknown', 'ip': first.get('client_ip') or 'Unknown',
         'type': 'Web / Workspace', 'gateway': 'Unknown', 'status': status, 'node': first.get('node'), 'end': '',
         'detail': {'kind': 'Gateway', 'source_ip': first.get('client_ip') or '—'}}
    _apply_gateway_lines(r, rec, vmap)
    if not rec.get('logout'):
        r['detail']['note'] = ('No logout line was received for this session, and the appliance does not list it '
                               'among its active sessions.' if live_ok else
                               'No logout line was received, and the appliance could not be asked whether the '
                               'session is still active.')
    return r

def _apply_login_lines(r, logins, start, end):
    """OS, access type, Gateway FQDN and user agent from the checklist's login
    audit lines of the same user and address."""
    user, ip = str(r.get('user') or '').lower(), r.get('ip')
    near = [e for e in logins if str(e.get('username') or '').lower() == user
            and (not ip or ip == 'Unknown' or not e.get('client_ip') or e['client_ip'] == ip)
            and start - 600 <= e['ts'] <= (end or time.time()) + 60]
    if not near:
        return
    e = near[-1]
    f = e.get('detail') or {}
    d = r.setdefault('detail', {})
    for src, dst in (('os', 'client_os'), ('access type', 'access_type'), ('gateway fqdn', 'gateway_fqdn'),
                     ('gateway', 'gateway_fqdn'), ('user-agent', 'user_agent'), ('session id', 'aaa_session_id')):
        if f.get(src) and d.get(dst) in (None, '', '—'):
            d[dst] = f[src]
    d['login_lines'] = len(near)
    first = min(x['ts'] for x in near)
    if first < (r.get('_start_ts') or first + 1):
        r['_start_ts'] = first

def _apply_app_lines(r, apps, smap, start, end):
    """Published applications the user started during the session (ICASTART /
    ICAEND lines): name, server, start, end."""
    user, ip = str(r.get('user') or '').lower(), r.get('ip')
    pairs = {}
    for e in apps:
        if str(e.get('username') or '').lower() != user:
            continue
        if ip and ip != 'Unknown' and e.get('client_ip') and e['client_ip'] != ip:
            continue
        f = e.get('detail') or {}
        t0 = float(f.get('start_epoch') or e['ts'])
        if not (start - 120 <= t0 <= (end or time.time()) + 120):
            continue
        k = (f.get('source', ''), f.get('destination', ''))
        rec = pairs.setdefault(k, {'app': '', 'start': t0, 'end': None, 'dest': f.get('destination', '')})
        rec['app'] = rec['app'] or f.get('applicationname') or ''
        rec['start'] = min(rec['start'], t0)
        if e['kind'] == 'ica_end':
            rec['end'] = e['ts']
    if not pairs:
        return
    d = r.setdefault('detail', {})
    lst = []
    for rec in sorted(pairs.values(), key=lambda x: x['start']):
        server_ip = rec['dest'].rsplit(':', 1)[0] if rec['dest'] else ''
        lst.append({'app': rec['app'] or '—', 'server': smap.get(server_ip) or server_ip or '—', 'dest': rec['dest'] or '—',
                    'start': _fmt_ts(rec['start']), 'end': _fmt_ts(rec['end']) if rec['end'] else '',
                    'duration': _fmt_dur((rec['end'] or time.time()) - rec['start'])})
    d['applications'] = lst[-30:]
    names = sorted({a['app'] for a in lst if a['app'] != '—'})
    if names:
        d['resource'] = ', '.join(names)
        d['protocol'] = 'ICA'

def _sessions_view(stored, events, vmap, smap, live_ok):
    """The rows the Sessions tab shows: what NITRO reported (stored history), each
    completed from the log lines of the same session, plus the sessions known only
    from log lines, and failed / locked sign-ins."""
    now = time.time()
    events = sorted(events, key=lambda e: e['ts'])
    gw = {}
    for e in events:
        if e['kind'] in ('vpn_login', 'vpn_logout') and e.get('session'):
            k = (e.get('node'), e['session'], str(e.get('username') or '').lower())
            gw.setdefault(k, {})['login' if e['kind'] == 'vpn_login' else 'logout'] = e
    logins = [e for e in events if e['kind'] == 'login']
    apps = [e for e in events if e['kind'] in ('ica_start', 'ica_end')]
    used, out = set(), []

    def gw_window(rec):
        li, lo = rec.get('login'), rec.get('logout')
        f = (lo or {}).get('detail') or {}
        start = li['ts'] if li else float(f.get('start_epoch') or lo['ts'])
        return start, (lo['ts'] if lo else None)

    def match(user, ip, t0, t1):
        best = None
        for k, rec in gw.items():
            if k in used or k[2] != str(user or '').lower():
                continue
            cip = (rec.get('login') or rec.get('logout')).get('client_ip')
            if ip and ip != 'Unknown' and cip and cip != ip:
                continue
            a, b = gw_window(rec)
            # the same session: it began before the dashboard first saw it, and it
            # had not ended before the dashboard last saw it
            if a <= t0 + 300 and (b is None or b >= t1 - 300) and (best is None or a > best[1]):
                best = (k, a)
        return best[0] if best else None

    for r in stored:
        r = dict(r)
        r['detail'] = dict(r.get('detail') or {})
        if r.get('status') in ('Failed', 'Locked'):
            out.append(r)
            continue
        first, last = r.get('first_seen') or now, r.get('last_seen') or now
        r['_start_ts'] = first
        r['_end_ts'] = None if r.get('status') == 'Active' else last
        k = match(r.get('user'), r.get('ip'), first, last)
        if k:
            used.add(k)
            _apply_gateway_lines(r, gw[k], vmap)
        out.append(r)
    for k, rec in gw.items():
        if k not in used:
            r = _row_from_gateway_lines(rec, vmap, live_ok)
            out.append(r)
    for r in out:
        if r.get('status') in ('Failed', 'Locked'):
            continue
        start = r.get('_start_ts') or now
        end = r.get('_end_ts')
        _apply_login_lines(r, logins, start, end)
        _apply_app_lines(r, apps, smap, r.get('_start_ts') or start, end)
        start = r.get('_start_ts') or start
        r['start'] = _fmt_ts(start)
        if r.get('status') == 'Active':
            r['end'] = 'Active'
        elif end:
            r['end'] = _fmt_ts(end)
        elif not r.get('end') or r.get('end') == 'Active':
            r['end'] = '—'
        r['duration'] = _fmt_dur((end or now) - start) if (end or r.get('status') == 'Active') else '—'
    # failed / locked sign-ins written to the log (kept for the whole retention period)
    seen = {(str(r.get('user')).lower(), r.get('status'), r.get('start')) for r in out if r.get('status') in ('Failed', 'Locked')}
    for e in events:
        if e['kind'] not in ('login_failed', 'lockout'):
            continue
        status = 'Locked' if e['kind'] == 'lockout' else 'Failed'
        when = _fmt_ts(e['ts'])
        key = (str(e.get('username') or '').lower(), status, when)
        if key in seen:
            continue
        seen.add(key)
        out.append(_synthetic_row(e.get('username') or '—', status, when=when, ip=e.get('client_ip') or '—',
                                  conn_type='AAA lockout' if status == 'Locked' else 'AAA login',
                                  sid=f"{e.get('username')}|{status}|{e['ts']}",
                                  extra={'failure_reason': (e.get('message') or '')[:200], 'source': 'Gateway log',
                                         'log_line': (e.get('raw') or '')[:400]}))
    for r in out:
        for k in ('_start_ts', '_end_ts', 'first_seen', 'last_seen'):
            r.pop(k, None)
    out.sort(key=lambda r: parse_dmy(r.get('start')), reverse=True)
    return out

def parse_dmy(text):
    try:
        return datetime.strptime(str(text or ''), '%d/%m/%Y %H:%M:%S').timestamp()
    except Exception:
        return 0.0

# Audit lines produced by the MANAGEMENT plane (admin/API/CLI/GUI/SSH logins and
# role-based auth). These are not gateway/AAA end-user activity, so they are
# excluded from the Sessions tab.
_MGMT_AUDIT_RE = re.compile(
    r'CMD_EXECUTED|rba\s+authentication|\bSSHD\b|\bADM_User\b|\bnsnetsvc\b|\bAPPFW\b'
    r'|\bdefault\s+(?:API|CLI|GUI|UI|SYSTEM)\b', re.I)

def _system_usernames(nitro):
    """Management account names, so their login events can be filtered out."""
    try:
        d = nitro._get('/config/systemuser', custom_timeout=4) or {}
        return {'nsroot', 'nsrecover'} | {str(u.get('username', '')).strip().lower()
                                          for u in (d.get('systemuser') or []) if isinstance(u, dict)}
    except Exception:
        # The list could not be read (a read-only account, for example): the
        # built-in management accounts are still never shown.
        return {'nsroot', 'nsrecover'}

def _audit_failed_locked_rows(nitro):
    """Failed logins / lockouts for **AAA / gateway users**, parsed from the
    appliance audit log. Management-plane events (admin/API/CLI/GUI/SSH logins,
    RBA) and any account that exists as a system user are skipped — the Sessions
    tab is about end users, not administrators."""
    rows, seen = [], set()
    sys_users = _system_usernames(nitro)
    try:
        d = nitro._get('/config/auditmessages?args=loglevel:ALL,numofmesgs:100', custom_timeout=6) or {}
        for it in (d.get('auditmessages') or []):
            line = str(it.get('value', '')) if isinstance(it, dict) else str(it)
            if _MGMT_AUDIT_RE.search(line):
                continue                      # management plane - not an AAA session
            low = line.lower()
            is_lock = bool(re.search(r'lock(?:ed)?\s*out|lockout|account\s+(?:is\s+|has\s+been\s+)?locked|user\s+\S+\s+(?:is\s+)?locked', low))
            is_fail = (('login' in low or 'logon' in low or 'authentic' in low)
                       and ('fail' in low or 'illegal' in low or 'denied' in low or 'invalid' in low))
            if not (is_lock or is_fail):
                continue
            # "User <name> - Client_ip ..." is the AAA form; the name may contain any
            # characters. Otherwise the first word after "user".
            m = (re.search(r'\bUser\s+(\S.*?)\s+-\s+Client_ip\b', line)
                 or re.search(r'\buser[:\s]+"?([^\s"\',;<>]+)', line, re.I))
            user = m.group(1).strip()[:120] if m else '—'
            if user.strip().lower() in sys_users:
                continue                      # a management account, not an AAA user
            ipm = re.search(r'(?:remote_ip|client_ip|clientip|from|source)[:\s"]+([0-9.]+)', line, re.I)
            ip = ipm.group(1) if ipm else '—'
            # NetScaler audit stamps are MM/DD/YYYY:HH:MM:SS (US order) — convert to
            # the dashboard's DD/MM/YYYY HH:MM:SS so it sorts/filters correctly.
            tm = re.match(r'\s*(\d{2})/(\d{2})/(\d{4}):(\d{2}:\d{2}:\d{2})', line)
            when = f"{tm.group(2)}/{tm.group(1)}/{tm.group(3)} {tm.group(4)}" if tm else ''
            status = 'Locked' if is_lock else 'Failed'
            key = (user, status, when)
            if key in seen:
                continue
            seen.add(key)
            # Unique per attempt (time-stamped) so each failed login persists as its
            # own row; a lockout is one row per user (current state).
            sid = f"{user}|Locked" if is_lock else f"{user}|Failed|{when or line[:40]}"
            rows.append(_synthetic_row(user, status, when=when, ip=ip, sid=sid,
                        conn_type='AAA lockout' if is_lock else 'AAA login',
                        extra={'log_line': line[:400], 'source': 'Appliance audit log'}))
            if len(rows) >= 30:
                break
    except Exception:
        pass
    return rows

def _locked_and_failed_rows(nitro):
    """Best-effort Locked/Failed rows from AAA users. NITRO field names vary by
    build — see /api/session-debug to confirm what your appliance exposes."""
    rows = []
    try:
        data = nitro._get('/config/aaauser', custom_timeout=4) or {}
        for raw in (data.get('aaauser') or []):
            if not isinstance(raw, dict):
                continue
            u = {str(k).lower(): v for k, v in raw.items()}
            name = u.get('username') or u.get('name')
            if not name:
                continue
            locked = str(_pick(u, ['locked', 'lockedstate', 'islocked', 'lockout',
                                   'accountlocked', 'lockedaccount'])).lower()
            if locked in ('true', '1', 'yes', 'locked', 'on'):
                rows.append(_synthetic_row(name, 'Locked', conn_type='AAA account',
                            when=_pick(u, ['lockedtime', 'locktime', 'lastlockouttime'])))
            fails = _pick(u, ['failedlogins', 'failedloginattempts', 'invalidlogincount', 'failattempts'])
            if fails and str(fails) not in ('0', '0.0'):
                rows.append(_synthetic_row(name, 'Failed', conn_type=f'{fails} attempt(s)',
                            ip=_pick(u, ['lastfailedip', 'clientip', 'srcip']),
                            when=_pick(u, ['lastfailedlogin', 'lastfailuretime', 'lastinvalidlogin'])))
    except Exception:
        pass
    return rows

@app.route('/api/user-sessions')
@login_required
def api_user_sessions():
    inst = request.args.get('instance')
    instance_id = str(get_instance(inst).get('id'))
    node_req = request.args.get('node', 'primary')
    other_node = 'secondary' if node_req == 'primary' else 'primary'
    live, used_node, live_ok = [], None, False

    for nk in [node_req, other_node]:
        if not (get_instance(inst).get(nk) or {}).get('ip'):
            continue
        try:
            nitro = get_nitro(nk, inst)
            live = _live_sessions(nitro, instance_id)
            used_node, live_ok = nk, True
            break
        except (requests.ConnectionError, requests.Timeout):
            continue                         # this node did not answer - ask the other one
        except Exception as e:
            logger.info(f"Sessions could not be read from {nk}: {e}")
            used_node = nk
            break

    extra_rows = []
    if used_node is not None:
        try:
            nit = get_nitro(used_node, inst)
            # Failed/locked: the audit log (end users only) and AAA users. Persisted
            # with the sessions so they do not vanish when the line scrolls away.
            extra_rows = _audit_failed_locked_rows(nit) + _locked_and_failed_rows(nit)
        except Exception:
            pass

    try:
        db.upsert_sessions(node_req, live + extra_rows, instance=instance_id)
        stored = db.get_sessions(days=db.RETENTION_DAYS, instance=instance_id)
        events = db.get_security_events(instance=instance_id, since=time.time() - db.RETENTION_DAYS * 86400,
                                        kinds=security.SESSION_KINDS, limit=20000)
        vmap, smap = _cached_vserver_map(instance_id)
        return jsonify({'sessions': _sessions_view(stored, events, vmap, smap, live_ok),
                        'source': 'history', 'retention_days': db.RETENTION_DAYS,
                        'live': live_ok, 'log_lines': len(events)})
    except Exception as e:
        logger.warning(f"Session history unavailable, returning live only: {e}")

    return jsonify({'sessions': live + extra_rows, 'source': 'live', 'live': live_ok})

@app.route('/api/session-debug')
@login_required
def api_session_debug():
    """One-shot diagnostics (values truncated, secrets redacted): per-node
    reachability + hostname (for the 'secondary hostname missing' case) and the
    raw session/user field names (to pin gateway/locked/failed mapping per build)."""
    inst = request.args.get('instance')

    def redact_row(it):
        row = {}
        for k, vv in it.items():
            if re.search(r'key|pass|secret|token|cookie', str(k), re.I):
                row[k] = '***redacted***'
            else:
                row[k] = str(vv)[:60]
        return row

    def sample(nitro, path, key, n=3):
        try:
            d = nitro._get(path, custom_timeout=6) or {}
            v = d.get(key)
            items = v if isinstance(v, list) else ([v] if v else [])
            return {'count': len(items),
                    'sample': [redact_row(it) for it in items[:n] if isinstance(it, dict)]}
        except Exception as e:
            return {'error': str(e)}

    # Per-node: is it reachable, and what hostname does NITRO report?
    nodes_diag = {}
    for nk in active_node_keys(inst):
        cfg = get_instance(inst).get(nk, {})
        entry = {'configured_ip': cfg.get('ip', ''), 'protocol': cfg.get('protocol'), 'port': cfg.get('port')}
        if not cfg.get('ip'):
            entry['status'] = 'no IP configured'
            nodes_diag[nk] = entry
            continue
        try:
            nit = get_nitro(nk, inst)
            hn = (nit._get('/config/nshostname', custom_timeout=3).get('nshostname', [{}]) or [{}])[0].get('hostname')
            entry['reachable'] = True
            entry['nshostname'] = hn or '(empty)'
        except Exception as e:
            entry['reachable'] = False
            entry['error'] = str(e)[:120]
        nodes_diag[nk] = entry

    # Session/user field names — from the first reachable node.
    fields = {}
    for nk in active_node_keys(inst):
        if nodes_diag.get(nk, {}).get('reachable'):
            nit = get_nitro(nk, inst)
            # Recent audit-log lines (the real source of failed logins / lockouts
            # on an LB appliance). Values are log text, not secrets — show more.
            def audit(nit):
                try:
                    d = nit._get('/config/auditmessages?args=loglevel:ALL,numofmesgs:60', custom_timeout=6) or {}
                    items = d.get('auditmessages') or []
                    lines = [str(it.get('value', it))[:240] for it in items if isinstance(it, dict)]
                    # Surface anything login/lockout related first.
                    hits = [ln for ln in lines if re.search(r'login|logon|lock|fail|denied|authenticat', ln, re.I)]
                    return {'count': len(lines), 'login_related': hits[:15], 'first_lines': lines[:5]}
                except Exception as e:
                    return {'error': str(e)}
            fields = {
                'from_node': nk,
                'hanode': sample(nit, '/config/hanode', 'hanode'),
                'systemsession': sample(nit, '/config/systemsession', 'systemsession', n=6),
                'vpnvserver': sample(nit, '/config/vpnvserver?attrs=name,ipv46,port', 'vpnvserver'),
                'vpnicadtlsconnection': sample(nit, '/config/vpnicadtlsconnection', 'vpnicadtlsconnection'),
                'aaasession': sample(nit, '/config/aaasession', 'aaasession'),
                'vpnicaconnection': sample(nit, '/config/vpnicaconnection', 'vpnicaconnection'),
                'aaauser': sample(nit, '/config/aaauser', 'aaauser', n=8),
                'systemuser': sample(nit, '/config/systemuser', 'systemuser', n=8),
                'auditmessages': audit(nit),
            }
            break

    return jsonify({
        'instance': get_instance(inst).get('id'),
        'mode': get_mode(inst),
        'nodes': nodes_diag,
        'fields': fields or {'note': 'no reachable node — check the reachability above'},
    })

@app.route('/api/session-ica')
@login_required
def api_session_ica():
    """Live ICA connections of one user (application server, protocol, client
    address). NetScaler reports them only while they are open."""
    inst = request.args.get('instance')
    iid = str(get_instance(inst).get('id'))
    user = (request.args.get('user') or '').strip()
    node = request.args.get('node') or 'primary'
    if not user:
        return jsonify({'connections': []})
    conns = []
    for nk in [node, ('secondary' if node == 'primary' else 'primary')]:
        if not (get_instance(inst).get(nk) or {}).get('ip'):
            continue
        try:
            nitro = get_nitro(nk, inst)
            _, smap = _vserver_map(nitro, iid)
            items = _ica_list(nitro)
        except Exception:
            continue
        conns = [_ica_entry(c, smap) for c in items if str(c.get('username') or '').lower() == user.lower()]
        break
    return jsonify({'user': user, 'connections': conns})

@app.route('/api/failover-history')
@login_required
def api_failover_history():
    inst = request.args.get('instance')
    instance_id = str(get_instance(inst).get('id'))
    inst_name = get_instance(inst).get('name')
    history = load_failover_history()
    changed = False
    new_events = []

    ha_data = _get_ha_data_fast(inst)
    nodes = ha_data.get('hanode', []) if isinstance(ha_data, dict) else []

    for n in nodes:
        last_transition = n.get('transtime', '')
        state = n.get('hacurstate') or n.get('state') or 'Unknown'
        ip = n.get('ipaddress', 'Unknown')

        if last_transition:
            exists = any(ev.get('timestamp') == last_transition and ev.get('ip') == ip for ev in history)
            if not exists:
                new_event = {
                    'timestamp': last_transition,
                    'type': 'State Change',
                    'reason': f"Node {ip} state is {state}",
                    'role_change': f"Current: {state}",
                    'ip': ip,
                    'instance': instance_id,
                    'instance_name': inst_name,
                }
                history.append(new_event)
                new_events.append(new_event)
                changed = True

    if changed:
        save_failover_history(history)
        try: db.add_failover_events(new_events)
        except Exception as e: logger.warning(f"Could not persist failover events: {e}")

    # The history DB is authoritative (retention-bounded). Only fall back to the
    # legacy JSON if the DB is genuinely unavailable — an empty DB is a valid
    # answer, otherwise purged-but-stale JSON rows would reappear.
    try:
        events = db.get_failover_events(days=db.RETENTION_DAYS, instance=instance_id)
        return jsonify({'events': events, 'retention_days': db.RETENTION_DAYS})
    except Exception as e:
        logger.warning(f"Failover history DB unavailable, falling back to JSON: {e}")

    history = [e for e in history if str(e.get('instance', instance_id)) == instance_id]
    history.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return jsonify({'events': history})

@app.route('/api/unlock-user', methods=['POST'])
@login_required
def api_unlock_user():
    body = request.get_json(force=True, silent=True) or {}
    inst = body.get('instance')
    node_val = body.get('node') or 'primary'
    username_val = body.get('username') or ''
    if not isinstance(node_val, str) or not isinstance(username_val, str):
        return jsonify({"success": False, "error": "node and username must be strings"}), 400
    node = node_val.strip()
    username = username_val.strip()

    if not username: return jsonify({"success": False, "error": "Missing username"}), 400

    try: nitro = get_nitro(node, inst)
    except KeyError: return jsonify({"success": False, "error": f"Unknown node '{node}'"}), 400

    resp = nitro.unlock_user(username)
    done = isinstance(resp, dict) and resp.get("errorcode") in (0, "0") and not resp.get("error")
    logger.info(f"Unlock of AAA user {username[:120]!r} on {node} requested by {session.get('user')!r}: "
                f"{'done' if done else 'failed - ' + str((resp or {}).get('message', ''))[:200]}")
    if done:
        return jsonify({"success": True, "message": f"User {username} unlocked successfully"})

    msg = str((resp or {}).get("message", "Failed to unlock user")).lower()
    if "does not exist" in msg or "not found" in msg or "no such" in msg: return jsonify({"success": False, "error": f"User '{username}' doesn't exist on the NetScaler."}), 400
    elif "not authorized" in msg or "permission" in msg: return jsonify({"success": False, "error": "You don't have permission to unlock user accounts."}), 400
    elif "not locked" in msg: return jsonify({"success": False, "error": f"User '{username}' is not currently locked."}), 400
    return jsonify({"success": False, "error": msg, "raw": resp}), 400

# ======================================================================================
# Security tab
# ======================================================================================
_sec_lock = threading.Lock()
_SEC_IDS = {c['id'] for c in security.security_catalog.CHECKS}
_SEC_STATES = ('done', 'irrelevant')

def _clean_marks(doc):
    """{instance: {check id: {'state', 'by', 'at'}}}, only known checks and states."""
    out = {}
    for inst, marks in (doc.items() if isinstance(doc, dict) else []):
        if not isinstance(marks, dict):
            continue
        clean = {}
        for cid, m in marks.items():
            if cid in _SEC_IDS and isinstance(m, dict) and m.get('state') in _SEC_STATES:
                clean[cid] = {'state': m['state'], 'by': str(m.get('by') or '')[:120], 'at': str(m.get('at') or '')[:40]}
        if clean:
            out[str(inst)[:64]] = clean
    return out

def _load_marks():
    try:
        with open(SECURITY_FILE, 'r', encoding='utf-8') as f:
            return _clean_marks(json.load(f))
    except FileNotFoundError:
        return {}
    except Exception as e:
        logger.warning(f"{SECURITY_FILE} could not be read ({e}); checklist marks start empty")
        return {}

SEC_MARKS = _load_marks()

def _syslog_sender(ip):
    """The instance a syslog sender belongs to: one of its nodes' addresses, or an
    address given in SYSLOG_EXTRA_SENDERS (ip=instance id, comma separated)."""
    ip = str(ip or '')
    for inst in get_instances():
        for k in ('primary', 'secondary'):
            node = inst.get(k)
            if isinstance(node, dict) and str(node.get('ip') or '').strip() == ip and ip:
                return str(inst.get('id'))
    for pair in os.getenv('SYSLOG_EXTRA_SENDERS', '').split(','):
        a, _, b = pair.strip().partition('=')
        if a.strip() == ip and b.strip():
            return b.strip()
    return None

def _security_targets():
    out = []
    for inst in get_instances():
        iid = str(inst.get('id'))
        if str(inst.get('mode')) == 'sdx':
            continue                             # an SDX Management Service has none of this
        for nk in active_node_keys(iid):
            node = inst.get(nk) or {}
            if node.get('ip'):
                try:
                    out.append((iid, nk, str(node['ip']), get_nitro(nk, iid)))
                except Exception:
                    continue
    return out

def _security_facts(iid, nk, ip, nitro):
    facts = security.collect_facts(nitro, cache_key=(iid, nk), fresh=True)
    if len(facts.get('errors', {})) >= len(security._FACT_SOURCES):
        return                                   # not reachable this time
    checks = security.evaluate(facts, {'dashboard_addresses': _dashboard_addresses()})
    security.series.add(iid, ip, security.sample_counts(checks))

def _dashboard_addresses():
    addrs = set(security.own_addresses())
    try:
        host = (request.host or '').rsplit(':', 1)[0].strip('[]') if request else ''
        if security.valid_ip(host):
            addrs.add(host)
    except Exception:
        pass
    return addrs

def _sec_node(inst):
    node = request.args.get('node', 'primary')
    if node not in ('primary', 'secondary'):
        node = 'primary'
    cfg = get_instance(inst).get(node) or {}
    if not cfg.get('ip') and node == 'secondary':
        node, cfg = 'primary', get_instance(inst).get('primary') or {}
    return node, cfg

def _checklist(inst, fresh=False):
    iid = str(get_instance(inst).get('id'))
    node, cfg = _sec_node(inst)
    if not cfg.get('ip'):
        return None, ('This node has no address configured.', 400)
    facts = security.collect_facts(get_nitro(node, inst), cache_key=(iid, node), fresh=fresh)
    if len(facts.get('errors', {})) >= len(security._FACT_SOURCES):
        first = next(iter(facts['errors'].values()), 'no answer')
        return None, (f"The appliance could not be read: {first}", 502)
    recv = security.receiver.status()
    ctx = {'node_protocol': str(cfg.get('protocol') or ''), 'dashboard_addresses': _dashboard_addresses(),
           'received': recv['senders'].get(str(cfg.get('ip')))}
    checks = security.evaluate(facts, ctx)
    marks = SEC_MARKS.get(iid, {})
    for c in checks:
        c['mark'] = marks.get(c['id'])
    return {'instance': iid, 'node': node, 'node_ip': cfg.get('ip'), 'version': security.ns_version(facts),
            'checks': checks, 'read_errors': facts.get('errors', {}), 'read_at': facts.get('read_at'),
            'vservers': sorted(str(v.get('name')) for v in facts.get('vpn_vserver') or [] if isinstance(v, dict) and v.get('name')),
            'portal_vservers': sorted(str(v.get('name')) for v in facts.get('lb_vserver') or []
                                      if isinstance(v, dict) and v.get('name') and str(v.get('servicetype', '')).upper() in ('HTTP', 'SSL')),
            'dashboard_address': next(iter(sorted(_dashboard_addresses())), ''),
            'receiver': {'port': recv['port'], 'listening': recv['listening'], 'error': recv['error']}}, None

@app.route('/api/security/checklist')
@login_required
def api_security_checklist():
    inst = request.args.get('instance')
    try:
        data, err = _checklist(inst, fresh=request.args.get('fresh') == '1')
    except KeyError as e:
        return jsonify({'error': str(e)}), 400
    if err:
        return jsonify({'error': err[0]}), err[1]
    return jsonify(data)

@app.route('/api/security/mark', methods=['POST'])
@login_required
def api_security_mark():
    body = request.get_json(force=True, silent=True) or {}
    iid = str(get_instance(request.args.get('instance')).get('id'))
    cid, state = str(body.get('id') or ''), str(body.get('state') or '')
    if cid not in _SEC_IDS:
        return jsonify({'error': 'Unknown checklist item.'}), 400
    if state not in _SEC_STATES + ('',):
        return jsonify({'error': "state must be 'done', 'irrelevant' or empty."}), 400
    with _sec_lock:
        marks = {k: dict(v) for k, v in SEC_MARKS.items()}
        mine = marks.setdefault(iid, {})
        if state:
            mine[cid] = {'state': state, 'by': str(session.get('user') or '')[:120],
                         'at': datetime.now(APP_TZ).isoformat(timespec='seconds')}
        else:
            mine.pop(cid, None)
        marks = _clean_marks(marks)
        try:
            _write_json(SECURITY_FILE, marks, indent=2)
        except OSError as e:
            return jsonify({'error': f'The mark could not be saved: {e}'}), 500
        SEC_MARKS.clear()
        SEC_MARKS.update(marks)
    db.documents_changed()
    return jsonify({'ok': True, 'mark': SEC_MARKS.get(iid, {}).get(cid)})

_RANGES = {'1h': (3600, 60), '24h': (86400, 3600), '7d': (7 * 86400, 6 * 3600)}

@app.route('/api/security/activity')
@login_required
def api_security_activity():
    inst = request.args.get('instance')
    iid = str(get_instance(inst).get('id'))
    span, bucket = _RANGES.get(request.args.get('range', '24h'), _RANGES['24h'])
    now = time.time()
    since = now - span
    try:
        events = db.get_security_events(instance=iid, since=since, kinds=security.SECURITY_KINDS, limit=50000)
    except Exception as e:
        return jsonify({'error': f'Security events could not be read: {db.describe_error(e)}'}), 500
    summary = security.summarise(events, since, bucket)
    hits, version, read_err = [], '', None
    try:
        data, err = _checklist(inst)
        if err:
            read_err = err[0]
        else:
            version = data['version']
            names = set()
            hits = security.policy_hits(data['checks'])
            for h in hits:
                names.add(h['policy'])
            trend = security.series.trend(iid, names, since)
            for h in hits:
                pts = trend.get(h['policy'], [])
                h['recent'] = sum(v for _, v in pts)
                h['trend'] = pts[-120:]
    except Exception as e:
        read_err = str(e)[:200]
    k = summary['by_kind']
    waf_blocked = sum(v for a, v in summary['by_action'].items() if 'block' in a and 'not' not in a)
    recv = security.receiver.status()
    node_ips = {str((get_instance(inst).get(n) or {}).get('ip') or '') for n in ('primary', 'secondary')}
    return jsonify({
        'instance': iid, 'range': request.args.get('range', '24h'), 'since': since, 'version': version,
        'kpi': {'waf': k.get('waf', 0) + k.get('bot', 0), 'waf_blocked': waf_blocked,
                'brute_force': k.get('brute_force', 0), 'cookie_hijack': k.get('cookie_hijack', 0),
                'login_failed': k.get('login_failed', 0), 'lockout': k.get('lockout', 0),
                'attackers': len({e['client_ip'] for e in events if e.get('client_ip')})},
        'summary': summary, 'hits': hits, 'hits_error': read_err, 'kinds': security.KINDS,
        'truncated': len(events) >= 50000,
        'receiver': {'port': recv['port'], 'listening': recv['listening'], 'error': recv['error'],
                     'from_this_instance': {ip: v for ip, v in recv['senders'].items() if ip in node_ips},
                     'rejected': recv['rejected'], 'queue_dropped': recv['queue_dropped']},
        'poll_secs': security.POLL_SECS,
    })

@app.route('/api/security/events')
@login_required
def api_security_events():
    inst = request.args.get('instance')
    iid = str(get_instance(inst).get('id'))
    span, _ = _RANGES.get(request.args.get('range', '24h'), _RANGES['24h'])
    kind = request.args.get('kind') or ''
    kinds = [kind] if kind in security.KINDS else list(security.SECURITY_KINDS)
    limit = max(1, min(_int(request.args.get('limit'), 500), 5000))
    try:
        rows = db.get_security_events(instance=iid, since=time.time() - span, kinds=kinds,
                                      text=request.args.get('q') or '', limit=limit)
    except Exception as e:
        return jsonify({'error': f'Security events could not be read: {db.describe_error(e)}'}), 500
    for r in rows:
        r['time'] = _fmt_ts(r['ts'])
        r['kind_label'] = security.KINDS.get(r['kind'], r['kind'])
    return jsonify({'events': rows, 'limit': limit, 'more': len(rows) >= limit})

# ======================================================================================
# Error Handlers
# ======================================================================================
# Version/health endpoints, plus upload-based upgrades when running as the appliance.
appliance.register(app, login_required, DATA_DIR, logger)

@app.errorhandler(404)
def _404(err):
    if request.path.startswith('/api/'): return jsonify({'error': 'Not Found'}), 404
    if not session.get('logged_in'): return redirect(url_for('login'))
    return render_template('dashboard.html'), 404

@app.errorhandler(500)
def _500(err):
    if request.path.startswith('/api/'): return jsonify({'error': 'Internal Server Error'}), 500
    if not session.get('logged_in'): return 'Internal Server Error', 500
    return render_template('dashboard.html'), 500

# ======================================================================================
# Application Startup (Runs on Gunicorn / Flask Dev)
# ======================================================================================
validate_env()
apply_session_timeout()

# History store (sessions + failover) with time-based retention: the built-in
# file, plus the external database when one is configured in Settings.
try:
    db.init_db()
    # Older builds stored management sessions/logins; the Sessions tab is AAA-only.
    db.purge_types(('Management', 'Mgmt login', 'Mgmt lockout'))
    db.migrate_json_failover(FAILOVER_HISTORY_FILE)
    db.start_retention_thread()
    start_api_detect_thread()
except Exception as e:
    logger.error(f"History DB init failed: {e}")

# Security events: syslog from the NetScalers, and their own recent audit lines.
try:
    security.ingest.start(db.add_security_events)
    security.start_receiver(_syslog_sender)
    security.start_poller(_security_targets, _security_facts)
except Exception as e:
    logger.error(f"Security event collection could not start: {e}")

# Which API each node speaks is found out in the background (NITRO until known).
# Doing it here made the start wait for every unreachable appliance in turn - long
# enough, with many of them, for an upgrade's health check to give up.
_detect_all_api_modes_soon()
logger.info("========================================")
logger.info("Starting NetScaler Dashboard (Production Ready via WSGI)")
logger.info(f"Next-Gen verify SSL: {os.getenv('NEXTGEN_VERIFY_SSL', '0')}")
logger.info(f"Next-Gen timeout (s): {os.getenv('NEXTGEN_TIMEOUT_SECS', '15')}")
logger.info("========================================")

if __name__ == '__main__':
    host = os.getenv('APP_HOST', '0.0.0.0')
    port = int(os.getenv('APP_PORT', '443'))
    debug = os.getenv('APP_DEBUG', '0').lower() in ('1', 'true', 'yes')
    use_ssl = os.getenv('APP_SSL', '1').lower() in ('1', 'true', 'yes')
    ssl_context = None
    if use_ssl:
        from cert_utils import CERT_FILE, KEY_FILE, ensure_signed
        ssl_context = ensure_signed(CERT_FILE, KEY_FILE)
    app.run(host=host, port=port, debug=debug, ssl_context=ssl_context)