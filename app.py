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
import logging
import secrets
import ssl
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import pytz
import requests

import db
from flask import (
    Flask, render_template, jsonify, request, redirect, url_for,
    session, flash
)

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
    "port": int(os.getenv("LDAP_PORT", "389") or 389),
    "use_ssl": _as_bool(os.getenv("LDAP_USE_SSL", "0")),
    "base_dn": os.getenv("LDAP_BASE_DN", ""),
    "bind_dn": os.getenv("LDAP_BIND_DN", ""),
    "bind_pw": os.getenv("LDAP_BIND_PASSWORD", ""),
    "user_attr": os.getenv("LDAP_USER_ATTRIBUTE", "sAMAccountName"),
    "allowed_group_dn": os.getenv("LDAP_ALLOWED_GROUP_DN", ""),
    "timeout": int(os.getenv("LDAP_TIMEOUT_SECS", "10") or 10),
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
    with open(LDAP_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)
    LDAP_CFG = load_ldap_config()
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
    SESSION_COOKIE_SECURE=os.getenv('APP_SSL', '1').lower() in ('1', 'true', 'yes'),
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

# Content Security Policy — allows exactly the CDNs/fonts the dashboard loads.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com "
    "https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; "
    "font-src 'self' https://fonts.gstatic.com data:; "
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
    # HSTS only makes sense once we're actually on HTTPS.
    if request.is_secure and os.getenv('HSTS_ENABLED', '1').lower() in ('1', 'true', 'yes'):
        resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    return resp

# Rotating log so it can't grow without bound (default 5 MB × 3 backups = ~20 MB cap).
from logging.handlers import RotatingFileHandler
_log_max_bytes = int(os.getenv("APP_LOG_MAX_BYTES", str(5 * 1024 * 1024)))
_log_backups = int(os.getenv("APP_LOG_BACKUPS", "3"))
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

# Timezone
IL_TZ = pytz.timezone("Asia/Jerusalem")

# Bounded retention for failover history: when it reaches 80% of the cap, prune
# back to 50% (keeping the most recent events) so the file never fills up.
FAILOVER_MAX_EVENTS = int(os.getenv("FAILOVER_MAX_EVENTS", "5000"))

def _prune_failover_history(history):
    high = int(FAILOVER_MAX_EVENTS * 0.8)
    low = int(FAILOVER_MAX_EVENTS * 0.5)
    if len(history) >= high:
        # Keep the newest `low` events, preserving chronological (ascending) order.
        history = sorted(history, key=lambda e: e.get('timestamp', ''))[-low:]
    return history

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def load_auth_config() -> dict:
    try:
        src = _read_path(AUTH_CONFIG_FILE, 'auth_config.json')
        if os.path.exists(src):
            with open(src, 'r', encoding='utf-8') as f: return json.load(f)
    except Exception: pass
    cfg = {
        'username': DEFAULT_USERNAME, 'password_hash': hash_password(DEFAULT_PASSWORD),
        'is_default_password': True, 'created_at': datetime.now(IL_TZ).isoformat(),
        'last_login': None, 'login_attempts': 0, 'last_password_change': None
    }
    save_auth_config(cfg)
    return cfg

def save_auth_config(config: dict) -> None:
    try:
        with open(AUTH_CONFIG_FILE, 'w', encoding='utf-8') as f: json.dump(config, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error saving auth config: {e}")

auth_config = load_auth_config()

def load_failover_history():
    try:
        if os.path.exists(FAILOVER_HISTORY_FILE):
            with open(FAILOVER_HISTORY_FILE, 'r', encoding='utf-8') as f: return json.load(f)
    except Exception: pass
    return []

def save_failover_history(history):
    try:
        history = _prune_failover_history(history)
        with open(FAILOVER_HISTORY_FILE, 'w', encoding='utf-8') as f: json.dump(history, f, indent=2)
    except Exception: pass

def login_required(fn):
    @wraps(fn)
    def _wrapped(*args, **kwargs):
        if not session.get('logged_in'):
            if request.is_json: return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        # Force-change gate only applies to the local admin account, not LDAP users.
        if (session.get('auth_backend') == 'local' and auth_config.get('is_default_password', False)
                and request.endpoint not in ("change_password", "logout")):
            if request.is_json: return jsonify({'error': 'Password change required'}), 403
            return redirect(url_for('change_password'))
        return fn(*args, **kwargs)
    return _wrapped

def _dn_head(dn: str) -> str:
    """Leftmost RDN value, e.g. 'domain admins' from 'CN=Domain Admins,CN=Users,...'.
    Lets an allowed-group value match regardless of CN/OU prefix or path."""
    m = re.match(r'\s*[^=,]+=([^,]+)', str(dn or ''))
    return (m.group(1).strip().lower() if m else str(dn or '').strip().lower())

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

    # --- AD tokenGroups path (covers primary + nested group membership) ---
    try:
        # Find the group by CN (forgiving of an OU/CN or path typo in the stored DN).
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

    # --- memberOf fallback (exact DN or leftmost-RDN value match) ---
    try: groups = [str(g) for g in entry.memberOf.values]
    except Exception: groups = []
    al = allowed.lower()
    for g in groups:
        if g.lower() == al or _dn_head(g) == head:
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


class NetScalerAPI:
    def __init__(self, ip, username, password, port=80, protocol='http'):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.protocol = protocol
        self.base_url = f"{protocol}://{ip}:{port}/nitro/v1"
        self.session = requests.Session()
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

    def unlock_user(self, username: str) -> dict:
        try:
            resp = self._post("/config/aaauser", {"aaauser": {"username": username, "unlockAccount": True}})
            if isinstance(resp, dict) and str(resp.get("errorcode", "0")) not in ("0", "", "None"):
                msg = str(resp.get("message", "")).lower()
                if ("unlockaccount" in msg) or ("invalid" in msg) or ("unknown" in msg): raise ValueError()
            return resp
        except Exception:
            try: return self._post("/config/aaauser?action=unlock", {"aaauser": {"username": username}})
            except Exception:
                try: return self._post(f"/config/aaauser/{username}?action=unlock", {"aaauser": {"username": username}})
                except Exception: return {"errorcode": -1, "message": "All unlock attempts failed."}

# ======================================================================================
# Next-Gen API Client
# ======================================================================================
class NextGenAPI:
    def __init__(self, ip, username, password, port=443, protocol='https'):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.protocol = protocol
        self.base_url = f"{protocol}://{ip}:{port}/mgmt/api/nextgen/v1"
        self.session = requests.Session()
        self.session.verify = os.getenv("NEXTGEN_VERIFY_SSL", "0").lower() in ("1", "true", "yes")
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
VALID_MODES = ('standalone', 'ha', 'cluster')

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

def load_nodes_config():
    src = _read_path(NODES_CONFIG_FILE, 'nodes_config.json')
    if os.path.exists(src):
        with open(src, 'r', encoding='utf-8') as f:
            return _migrate_config(json.load(f))
    return _default_config()

NETSCALER_CONFIG = load_nodes_config()

def save_nodes_config(config):
    config = _migrate_config(config)
    with open(NODES_CONFIG_FILE, 'w', encoding='utf-8') as f: json.dump(config, f, indent=2)
    global NETSCALER_CONFIG
    NETSCALER_CONFIG = config

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
    if get_mode(instance_id) in ('standalone', 'cluster'):
        return ['primary']
    return [k for k, _ in node_items(instance_id)]

# Detected API capability per node, namespaced by instance: {instance_id: {node_key: 'nitro'|'nextgen'}}.
API_MODE = {}

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

def detect_api_mode_for_node(node_key: str, cfg: dict, instance_id=None):
    if not cfg.get('ip') or not cfg.get('username') or not cfg.get('password'):
        set_api_mode(instance_id, node_key, 'nitro')
        return
    try:
        nitro = NetScalerAPI(cfg['ip'], cfg['username'], cfg['password'], cfg['port'], cfg['protocol'])
        vi = nitro._get('/config/nsversion', custom_timeout=5)
        meta = vi['nsversion'][0] if isinstance(vi.get('nsversion'), list) else vi.get('nsversion', {})
        v_str = meta.get('version', '')
        if _is_nextgen_supported(v_str):
            ng = NextGenAPI(cfg['ip'], cfg['username'], cfg['password'], port=_int(os.getenv('NS_PORT_HTTPS', '443'), 443), protocol='https')
            ng.login()
            ng.logout()
            set_api_mode(instance_id, node_key, 'nextgen')
            return
    except Exception: pass
    set_api_mode(instance_id, node_key, 'nitro')

def get_nitro(node_key: str, instance_id=None) -> NetScalerAPI:
    cfg = get_instance(instance_id).get(node_key or 'primary')
    if not cfg: raise KeyError(f"Unknown node '{node_key}'")
    return NetScalerAPI(cfg['ip'], cfg['username'], cfg['password'], cfg['port'], cfg['protocol'])

def get_nextgen(node_key: str, instance_id=None) -> NextGenAPI:
    cfg = get_instance(instance_id).get(node_key or 'primary')
    if not cfg: raise KeyError(f"Unknown node '{node_key}'")
    return NextGenAPI(cfg['ip'], cfg['username'], cfg['password'], port=_int(os.getenv('NS_PORT_HTTPS', '443'), 443), protocol='https')

# ======================================================================================
# System Overview & Fast HA Tracking Logic
# ======================================================================================
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
        })
    return {'hanode': norm} if norm else {}

def _get_ha_data_fast(instance_id=None):
    # Cluster members and HA nodes are normalized to the same {'hanode': [...]} shape
    # so every downstream caller works regardless of deployment mode.
    if get_mode(instance_id) == 'cluster':
        return _get_cluster_nodes_normalized(instance_id)
    for nk in active_node_keys(instance_id):
        try:
            nit = get_nitro(nk, instance_id)
            r = nit._get('/config/hanode', custom_timeout=3)
            if 'hanode' in r: return r
        except Exception: pass
    return {}

def track_ha_state_changes(nodes, instance_id=None):
    last_states = {}
    if os.path.exists(HA_STATE_FILE):
        try:
            with open(HA_STATE_FILE, 'r', encoding='utf-8') as f: last_states = json.load(f)
        except Exception: pass
        
    history = load_failover_history()
    changed = False
    new_events = []

    for n in nodes:
        if not isinstance(n, dict): continue
        ip = n.get('ipaddress') or n.get('ip') or n.get('nsip') or ''
        role = str(n.get('state') or n.get('hacurstate') or n.get('haStatus') or n.get('status') or '').upper()
        if ip and role:
            prev = last_states.get(ip)
            if prev and prev != role and 'UNKNOWN' not in role:
                _inst = get_instance(instance_id)
                evt = {
                    'timestamp': datetime.now(IL_TZ).isoformat(),
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
            last_states[ip] = role

    if changed:
        save_failover_history(history)
        try: db.add_failover_events(new_events)
        except Exception as e: logger.warning(f"Could not persist failover events: {e}")
    try:
        with open(HA_STATE_FILE, 'w', encoding='utf-8') as f: json.dump(last_states, f)
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
    ha_data = _get_ha_data_fast(instance_id)
    for n in ha_data.get('hanode', []):
        if isinstance(n, dict) and (n.get('ipaddress') or n.get('ip') or n.get('nsip')) == ip:
            role = n.get('state') or n.get('hacurstate') or n.get('haStatus') or 'Unknown'

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

    lic_type, lic_mode, bandwidth = "Base / Express", "File Based", "Unknown"
    try:
        lic_data = nitro._get('/config/nslicense', custom_timeout=3).get('nslicense', [{}])[0]
        if lic_data.get('pl') == 'TRUE' or lic_data.get('premium') == 'TRUE': lic_type = "Premium (Platinum)"
        elif lic_data.get('ent') == 'TRUE' or lic_data.get('advanced') == 'TRUE': lic_type = "Advanced (Enterprise)"
        elif lic_data.get('wl') == 'TRUE' or lic_data.get('standard') == 'TRUE': lic_type = "Standard"
        model = lic_data.get('modelid')
        if model and str(model) != '0': bandwidth = f"{model} Mbps"
    except Exception: pass

    try:
        cap_data = nitro._get('/config/nscapacity', custom_timeout=3).get('nscapacity', [{}])[0]
        if cap_data.get('edition'): lic_type = f"{cap_data.get('edition').title()}"
        if cap_data.get('bandwidth') and str(cap_data.get('bandwidth')) != '0':
            bandwidth = f"{cap_data.get('bandwidth')} {cap_data.get('unit', 'Mbps')}"
            lic_mode = "LAS Fixed Bandwidth"
        if cap_data.get('platform') == 'VSERVER': lic_mode = "LAS (Virtual Server Based)"
    except Exception: pass

    return {
        'connected': connected, 'ha_role': role, 'ns_stats': stats,
        'version': version, 'ip': ip, 'config_changed': config_changed,
        'license_type': lic_type, 'license_mode': lic_mode, 'bandwidth': bandwidth,
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

        # Honor the chosen authentication source. LDAP only when enabled; local
        # is always available (avoids lockout even if the form says otherwise).
        backend = None
        if source == 'ldap' and ldap_enabled():
            if ldap_authenticate(username, password):
                backend = 'ldap'
        else:
            if (username == auth_config.get('username')
                    and hash_password(password) == auth_config.get('password_hash')):
                backend = 'local'

        if backend:
            session['logged_in'] = True
            session['user'] = username
            session['auth_backend'] = backend
            session.permanent = True
            session['last_active'] = time.time()
            if backend == 'local':
                auth_config['last_login'] = datetime.now(IL_TZ).isoformat()
                auth_config['login_attempts'] = 0
                save_auth_config(auth_config)
            return redirect(url_for('dashboard'))

        auth_config['login_attempts'] = int(auth_config.get('login_attempts', 0)) + 1
        save_auth_config(auth_config)
        flash('Invalid credentials', 'error')
    return render_template('login.html', ldap_on=ldap_enabled())

@app.route('/logout', methods=['POST', 'GET'])
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

        if hash_password(current_pw) != auth_config.get('password_hash'):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')
        if not new_pw or len(new_pw) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('change_password.html')
        if new_pw != confirm_pw:
            flash('New password and confirmation do not match', 'error')
            return render_template('change_password.html')

        auth_config['password_hash'] = hash_password(new_pw)
        auth_config['is_default_password'] = False
        auth_config['last_password_change'] = datetime.now(IL_TZ).isoformat()
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
    node_keys = ('primary',) if mode in ('standalone', 'cluster') else ('primary', 'secondary')
    prev = stored_by_id.get(iid, {})
    out = {'id': iid, 'name': name, 'mode': mode}
    for k in node_keys:
        nv = inst.get(k) if isinstance(inst.get(k), dict) else {}
        proto = str(nv.get('protocol', 'https')).lower()
        out[k] = {
            'ip': str(nv.get('ip', '')).strip(),
            'username': str(nv.get('username', '')).strip(),
            'port': _int(nv.get('port', 443), 443),
            'protocol': proto if proto in ('http', 'https') else 'https',
            # Blank password on save keeps the stored one for that node.
            'password': nv.get('password') or (prev.get(k) or {}).get('password', ''),
        }
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
        incoming = body.get('instances')
        if not isinstance(incoming, list):
            incoming = _migrate_config(body).get('instances', [])

        stored_by_id = {str(i.get('id')): i for i in get_instances()}
        clean, used = [], set()
        for idx, inst in enumerate(incoming):
            if not isinstance(inst, dict):
                continue
            ci = _clean_instance(inst, idx, stored_by_id)
            while ci['id'] in used:            # guarantee unique ids
                ci['id'] = _new_instance_id()
            used.add(ci['id'])
            clean.append(ci)
        if not clean:
            clean = _default_config()['instances']

        save_nodes_config({'instances': clean, 'session_timeout_minutes': st})
        apply_session_timeout()
        API_MODE.clear()
        for inst in clean:
            for k, cfg in ((kk, vv) for kk, vv in inst.items() if isinstance(vv, dict)):
                detect_api_mode_for_node(k, cfg, inst['id'])
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
            save_pair(cert_pem, key_pem)
        else:
            # No key supplied: pair the cert with the key left on disk from a CSR.
            from cert_utils import save_signed_cert
            save_signed_cert(cert_pem)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"TLS cert replace failed: {e}")
        return jsonify({"success": False, "error": "Could not save certificate"}), 500
    return jsonify({"success": True, "message": "Certificate saved. Restart the dashboard to apply."})

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
    cn = (body.get('common_name') or '').strip() or None
    try:
        from cert_utils import generate_csr
        csr_pem = generate_csr(common_name=cn).decode('utf-8')
    except Exception as e:
        logger.error(f"CSR generation failed: {e}")
        return jsonify({"success": False, "error": "Could not generate CSR"}), 500
    return jsonify({"success": True, "csr": csr_pem,
                    "message": "CSR generated (a new private key was written). Get it signed, then upload the signed certificate below and restart."})

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
    mode = get_mode(inst)
    default_name = {'primary': 'Cluster (CLIP)' if mode == 'cluster' else 'Primary', 'secondary': 'Secondary'}
    nodes_data = {}
    for k in active_node_keys(inst):
        v = get_instance(inst).get(k, {})
        try:
            if v.get('ip'):
                hn = get_nitro(k, inst)._get('/config/nshostname', custom_timeout=3).get('nshostname', [{}])[0].get('hostname')
                if not hn: hn = default_name.get(k, k.title())
            else: hn = f"{default_name.get(k, k.title())} Node"
        except Exception: hn = default_name.get(k, k.title())
        nodes_data[k] = {'ip': v.get('ip', ''), 'protocol': v.get('protocol', 'https'), 'port': v.get('port', 443), 'name': hn }
    api_mode = {k: get_api_mode(inst, k) for k in active_node_keys(inst)}
    return jsonify({'api_mode': api_mode, 'nodes': nodes_data, 'mode': mode,
                    'instance': get_instance(inst).get('id')})

@app.route('/api/system-stats')
@login_required
def api_system_stats():
    inst = request.args.get('instance')
    node = request.args.get('node')
    if node:
        try: return jsonify({'node': node, 'api_mode': get_api_mode(inst, node), **_build_node_overview(node, inst)})
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
            return jsonify({'node': node, 'api_mode': 'nextgen', 'lbvserver': lbv_like})
        except Exception: pass

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

    if get_api_mode(inst, node) == 'nextgen':
        try:
            ng = get_nextgen(node, inst)
            ng.login()
            apps = ng.list_applications()
            ng.logout()
            return jsonify({'node': node, 'api_mode': 'nextgen', 'service': [], 'servicegroup': [], 'applications': apps})
        except Exception: pass

    try:
        nitro = get_nitro(node, inst)
        svc  = nitro._get('/config/service', custom_timeout=5) or {}
        sgrp = nitro._get('/config/servicegroup', custom_timeout=5) or {}
        return jsonify({'node': node, 'api_mode': 'nitro',
                        'service': svc.get('service', []) if isinstance(svc, dict) else [],
                        'servicegroup': sgrp.get('servicegroup', []) if isinstance(sgrp, dict) else []})
    except Exception: return jsonify({'service': [], 'servicegroup': []})

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

def _normalize_session(raw, kind):
    """Map a raw NITRO vpn/aaa session dict into the dashboard's shape, including
    a `detail` block (gateway, connection protocol, resource) for the sub-row."""
    s = {str(k).lower(): v for k, v in raw.items()}
    duration_secs = int(s.get('duration', 0) or 0)
    start_dt = datetime.now().timestamp() - duration_secs
    start = datetime.fromtimestamp(start_dt, IL_TZ).strftime('%d/%m/%Y %H:%M:%S')

    src_ip = _pick(s, ['publicip', 'clientip', 'srcip', 'client_ip', 'ipaddress', 'ip'])
    intranet_ip = _pick(s, ['intranetip', 'iip', 'peip', 'mappedip'])
    gateway = _pick(s, ['vservername', 'vserver', 'vsname', 'gateway', 'gatewayname',
                        'authnvsname', 'agname', 'vpnvservername', 'tmvserver',
                        'vsvrname', 'polarisid', 'gatewayfqdn'])

    # Stable identifier so repeated polls of the same session map to one row.
    # NITRO exposes a per-session key; fall back to user+kind when it's absent.
    session_id = _pick(s, ['sessionkey', 'sessionid', 'sid', 'sessguid',
                           'sessionguid', 'pcbid']) or f"{s.get('username', '')}|{kind}"

    # Connection class for the main row.
    if kind == 'aaa':
        conn_type = 'Web (AAA)'
    elif intranet_ip:
        conn_type = 'VPN (Full Tunnel)'
    else:
        conn_type = 'Web / Workspace'

    # Per-connection protocol (ICA / RDP / SSL-VPN) and end resource, best-effort
    # across the field names NetScaler uses on different builds.
    protocol = _pick(s, ['transportprotocol', 'transport', 'protocol', 'sesstype', 'smartaccess'])
    resource = _pick(s, ['application', 'appname', 'publishedapp', 'resource', 'server', 'destip', 'homepage'])
    detail = {
        'gateway': gateway or '—',
        'protocol': protocol or ('SSL-VPN' if intranet_ip else '—'),
        'resource': resource or '—',
        'source_ip': src_ip or '—',
        'intranet_ip': intranet_ip or '—',
        'client_os': _pick(s, ['clientos', 'deviceos', 'os', 'useragent']) or '—',
        'kind': 'Gateway/VPN' if kind == 'vpn' else 'AAA/Web',
    }
    return {
        'user': s.get('username', 'Unknown'),
        'session_id': session_id,
        'type': conn_type,
        'status': 'Active',
        'duration': f"{duration_secs // 60} min",
        'ip': src_ip or 'Unknown',
        'gateway': gateway or ('N/A (AAA)' if kind == 'aaa' else 'Unknown'),
        'start': start,
        'end': 'Active',
        'detail': detail,
    }

@app.route('/api/user-sessions')
@login_required
def api_user_sessions():
    inst = request.args.get('instance')
    instance_id = str(get_instance(inst).get('id'))
    node_req = request.args.get('node', 'primary')
    other_node = 'secondary' if node_req == 'primary' else 'primary'
    all_sessions = []

    for nk in [node_req, other_node]:
        try:
            nitro = get_nitro(nk, inst)
            vpn_resp = nitro._get('/config/vpnsession', custom_timeout=4)
            aaa_resp = nitro._get('/config/aaasession', custom_timeout=4)

            vpn_sessions = vpn_resp.get('vpnsession', []) if isinstance(vpn_resp, dict) else []
            aaa_sessions = aaa_resp.get('aaasession', []) if isinstance(aaa_resp, dict) else []

            for raw_s in vpn_sessions:
                all_sessions.append(_normalize_session(raw_s, 'vpn'))

            seen_users = {x['user'] for x in all_sessions}
            for raw_s in aaa_sessions:
                if str(raw_s.get('username')) not in seen_users:
                    all_sessions.append(_normalize_session(raw_s, 'aaa'))
            break
        except Exception:
            continue

    # Persist what we just observed, then return the stored history for THIS
    # instance (live sessions plus anything seen within the retention window).
    try:
        db.upsert_sessions(node_req, all_sessions, instance=instance_id)
        return jsonify({'sessions': db.get_sessions(days=db.RETENTION_DAYS, instance=instance_id),
                        'source': 'history', 'retention_days': db.RETENTION_DAYS})
    except Exception as e:
        logger.warning(f"Session history unavailable, returning live only: {e}")

    return jsonify({'sessions': all_sessions, 'source': 'live'})

@app.route('/api/session-ica')
@login_required
def api_session_ica():
    """Live ICA/RDP connection detail for a user (gateway, protocol, published
    resource). NetScaler only reports this for currently-active sessions."""
    inst = request.args.get('instance')
    user = (request.args.get('user') or '').strip()
    node = request.args.get('node') or 'primary'
    if not user:
        return jsonify({'connections': []})
    conns = []
    for nk in [node, ('secondary' if node == 'primary' else 'primary')]:
        try:
            nitro = get_nitro(nk, inst)
        except Exception:
            continue
        # Try the ICA-connection object names used across builds.
        raw_items = []
        for path, key in (('/config/vpnicaconnection', 'vpnicaconnection'),
                          ('/config/icaconnection', 'icaconnection'),
                          ('/config/aaasession', 'aaasession')):
            try:
                d = nitro._get(path, custom_timeout=4) or {}
                v = d.get(key)
                if isinstance(v, list) and v:
                    raw_items = v; break
            except Exception:
                continue
        for raw in raw_items:
            s = {str(k).lower(): v for k, v in raw.items()}
            if user.lower() not in (str(s.get('username', '')).lower(), str(s.get('user', '')).lower()):
                continue
            conns.append({
                'gateway': _pick(s, ['vservername', 'vserver', 'gateway', 'gatewayname']) or '—',
                'protocol': _pick(s, ['protocol', 'transportprotocol', 'transport', 'sesstype']) or 'ICA',
                'resource': _pick(s, ['application', 'appname', 'publishedapp', 'resource', 'server', 'destip']) or '—',
                'server': _pick(s, ['server', 'destip', 'backendserver']) or '—',
                'client_ip': _pick(s, ['clientip', 'publicip', 'srcip']) or '—',
                'device': _pick(s, ['deviceos', 'clientos', 'devicename', 'useragent']) or '—',
            })
        if conns:
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
    if isinstance(resp, dict) and resp.get("errorcode") in (0, "0", None) and not resp.get("error"):
        return jsonify({"success": True, "message": f"User {username} unlocked successfully"})

    msg = str((resp or {}).get("message", "Failed to unlock user")).lower()
    if "does not exist" in msg or "not found" in msg: return jsonify({"success": False, "error": f"User '{username}' doesn't exist on the NetScaler."}), 400
    elif "not authorized" in msg or "permission" in msg: return jsonify({"success": False, "error": "You don't have permission to unlock user accounts."}), 400
    elif "not locked" in msg: return jsonify({"success": False, "error": f"User '{username}' is not currently locked."}), 400
    return jsonify({"success": False, "error": msg, "raw": resp}), 400

# ======================================================================================
# Error Handlers
# ======================================================================================
@app.errorhandler(404)
def _404(err): return jsonify({'error': 'Not Found'}) if request.path.startswith('/api/') else render_template('dashboard.html'), 404

@app.errorhandler(500)
def _500(err): return jsonify({'error': 'Internal Server Error'}) if request.path.startswith('/api/') else render_template('dashboard.html'), 500

# ======================================================================================
# Application Startup (Runs on Gunicorn / Flask Dev)
# ======================================================================================
validate_env()
apply_session_timeout()

# Local history DB (sessions + failover) with time-based retention.
try:
    db.init_db()
    db.migrate_json_failover(FAILOVER_HISTORY_FILE)
    db.start_retention_thread()
except Exception as e:
    logger.error(f"History DB init failed: {e}")

for _inst in get_instances():
    for _nk, _cfg in ((k, v) for k, v in _inst.items() if isinstance(v, dict)):
        detect_api_mode_for_node(_nk, _cfg, _inst.get('id'))

logger.info(f"API modes at startup: {API_MODE}")
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