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
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import pytz
import requests
from flask import (
    Flask, render_template, jsonify, request, redirect, url_for,
    session, flash
)

# ======================================================================================
# LDAP Configuration — env vars are defaults; a gitignored ldap_config.json
# (editable from the Settings UI) overrides them at runtime.
# ======================================================================================
AUTH_BACKENDS = {x.strip().lower() for x in os.getenv("AUTH_BACKENDS", "local").split(",") if x.strip()}
LDAP_CONFIG_FILE = os.getenv("LDAP_CONFIG_FILE", "ldap_config.json")

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
        if os.path.exists(LDAP_CONFIG_FILE):
            with open(LDAP_CONFIG_FILE, "r", encoding="utf-8") as f:
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
    path = os.getenv("APP_SECRET_FILE", ".app_secret")
    try:
        if os.path.exists(path):
            with open(path) as f:
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

LOG_FILE = os.getenv("APP_LOG_FILE", "netscaler_complete.log")
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
AUTH_CONFIG_FILE = os.getenv('AUTH_CONFIG_FILE', 'auth_config.json')
DEFAULT_USERNAME = os.getenv('UI_DEFAULT_USERNAME', 'admin')
DEFAULT_PASSWORD = os.getenv('UI_DEFAULT_PASSWORD', 'admin')

# Timezone & Persistent Files
IL_TZ = pytz.timezone("Asia/Jerusalem")
FAILOVER_HISTORY_FILE = 'failover_history.json'
HA_STATE_FILE = 'ha_last_state.json'

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
        if os.path.exists(AUTH_CONFIG_FILE):
            with open(AUTH_CONFIG_FILE, 'r', encoding='utf-8') as f: return json.load(f)
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
                return False
            entry = finder.entries[0]
            user_dn = entry.entry_dn
            allowed_group = cfg['allowed_group_dn']
            if allowed_group:
                try: groups = [str(g) for g in entry.memberOf.values]
                except Exception: groups = []
                if not any(allowed_group.lower() == g.lower() for g in groups):
                    logger.info(f"LDAP user '{username}' not in allowed group")
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
        self.session.verify = os.getenv("NITRO_VERIFY_SSL", "1").lower() in ("1", "true", "yes")
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

NODES_CONFIG_FILE = 'nodes_config.json'

# Deployment topology: 'standalone' (primary only), 'ha' (primary+secondary pair),
# or 'cluster' (primary = Cluster IP / CLIP; members read from /config/clusternode).
VALID_MODES = ('standalone', 'ha', 'cluster')

def load_nodes_config():
    if os.path.exists(NODES_CONFIG_FILE):
        with open(NODES_CONFIG_FILE, 'r', encoding='utf-8') as f: return json.load(f)
    return {
        'mode': 'ha',
        'primary': { 'ip': '', 'username': '', 'password': '', 'port': 443, 'protocol': 'https'},
        'secondary': { 'ip': '', 'username': '', 'password': '', 'port': 443, 'protocol': 'https'}
    }

NETSCALER_CONFIG = load_nodes_config()

def save_nodes_config(config):
    with open(NODES_CONFIG_FILE, 'w', encoding='utf-8') as f: json.dump(config, f, indent=2)
    global NETSCALER_CONFIG
    NETSCALER_CONFIG = config

def get_mode() -> str:
    m = str(NETSCALER_CONFIG.get('mode', 'ha')).lower()
    return m if m in VALID_MODES else 'ha'

def node_items():
    """(key, cfg) pairs for real node entries only (skips the 'mode' scalar)."""
    return [(k, v) for k, v in NETSCALER_CONFIG.items() if isinstance(v, dict)]

def active_node_keys():
    """Node keys the UI should surface, per deployment mode."""
    if get_mode() in ('standalone', 'cluster'):
        return ['primary']
    return [k for k, _ in node_items()]

API_MODE = {k: 'nitro' for k, _ in node_items()}

def validate_env():
    missing = [k for k, v in node_items() if k in active_node_keys() and not v.get('ip')]
    if missing:
        logger.warning(f"Nodes without an IP configured: {', '.join(missing)}")

# ======================================================================================
# API Detection & Client Helpers
# ======================================================================================
def _parse_version_tuple(version_str: str):
    m = re.search(r"(\d+)\.(\d+)", str(version_str or ""))
    if not m: return (0, 0)
    return (int(m.group(1)), int(m.group(2)))

def _is_nextgen_supported(version_str: str) -> bool:
    return _parse_version_tuple(version_str) >= (14, 1)

def detect_api_mode_for_node(node_key: str, cfg: dict):
    if not cfg.get('ip') or not cfg.get('username') or not cfg.get('password'):
        API_MODE[node_key] = 'nitro'
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
            API_MODE[node_key] = 'nextgen'
            return
    except Exception: pass
    API_MODE[node_key] = 'nitro'

def get_nitro(node_key: str) -> NetScalerAPI:
    cfg = NETSCALER_CONFIG.get(node_key or 'primary')
    if not cfg: raise KeyError(f"Unknown node '{node_key}'")
    return NetScalerAPI(cfg['ip'], cfg['username'], cfg['password'], cfg['port'], cfg['protocol'])

def get_nextgen(node_key: str) -> NextGenAPI:
    cfg = NETSCALER_CONFIG.get(node_key or 'primary')
    if not cfg: raise KeyError(f"Unknown node '{node_key}'")
    return NextGenAPI(cfg['ip'], cfg['username'], cfg['password'], port=_int(os.getenv('NS_PORT_HTTPS', '443'), 443), protocol='https')

# ======================================================================================
# System Overview & Fast HA Tracking Logic
# ======================================================================================
def _get_cluster_nodes_normalized():
    """Read cluster members from the CLIP (primary) and map them to the hanode shape."""
    try:
        r = get_nitro('primary')._get('/config/clusternode', custom_timeout=4)
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

def _get_ha_data_fast():
    # Cluster members and HA nodes are normalized to the same {'hanode': [...]} shape
    # so every downstream caller works regardless of deployment mode.
    if get_mode() == 'cluster':
        return _get_cluster_nodes_normalized()
    for nk in active_node_keys():
        try:
            nit = get_nitro(nk)
            r = nit._get('/config/hanode', custom_timeout=3)
            if 'hanode' in r: return r
        except Exception: pass
    return {}

def track_ha_state_changes(nodes):
    last_states = {}
    if os.path.exists(HA_STATE_FILE):
        try:
            with open(HA_STATE_FILE, 'r', encoding='utf-8') as f: last_states = json.load(f)
        except Exception: pass
        
    history = load_failover_history()
    changed = False
    
    for n in nodes:
        if not isinstance(n, dict): continue
        ip = n.get('ipaddress') or n.get('ip') or n.get('nsip') or ''
        role = str(n.get('state') or n.get('hacurstate') or n.get('haStatus') or n.get('status') or '').upper()
        if ip and role:
            prev = last_states.get(ip)
            if prev and prev != role and 'UNKNOWN' not in role:
                history.append({
                    'timestamp': datetime.now(IL_TZ).isoformat(),
                    'type': 'Role Change',
                    'reason': f"Node HA State Shift",
                    'role_change': f"{prev} -> {role}",
                    'ip': ip
                })
                changed = True
            last_states[ip] = role
            
    if changed: save_failover_history(history)
    try:
        with open(HA_STATE_FILE, 'w', encoding='utf-8') as f: json.dump(last_states, f)
    except Exception: pass

def _roles_from_ha() -> tuple[dict, dict]:
    raw = _get_ha_data_fast()
    roles = {}
    nodes = raw.get('hanode', []) if isinstance(raw, dict) else []
    track_ha_state_changes(nodes)
    for n in nodes:
        if isinstance(n, dict):
            ip = n.get('ipaddress') or n.get('ip') or n.get('nsip') or ''
            if ip: roles[ip] = str(n.get('state') or n.get('hacurstate') or 'Unknown')
    return roles, raw

def _build_node_overview(node_key: str) -> dict:
    cfg = NETSCALER_CONFIG.get(node_key, {})
    ip = cfg.get('ip')
    
    try:
        nitro = get_nitro(node_key)
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
    ha_data = _get_ha_data_fast()
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
@app.route('/api/settings', methods=['GET', 'POST'])
@login_required
def api_settings():
    if request.method == 'POST':
        new_config = request.get_json(force=True, silent=True)
        if not isinstance(new_config, dict):
            return jsonify({"success": False, "error": "Invalid payload"}), 400
        mode = str(new_config.get('mode', NETSCALER_CONFIG.get('mode', 'ha'))).lower()
        new_config['mode'] = mode if mode in VALID_MODES else 'ha'
        # Session inactivity timeout (minutes), clamped to a sane range.
        try:
            st = int(new_config.get('session_timeout_minutes',
                                    NETSCALER_CONFIG.get('session_timeout_minutes', DEFAULT_SESSION_TIMEOUT_MIN)))
        except Exception:
            st = DEFAULT_SESSION_TIMEOUT_MIN
        new_config['session_timeout_minutes'] = min(max(st, 1), 1440)
        for k in ('primary', 'secondary'):
            # Coerce missing/non-dict node entries so .get() below can't crash.
            if not isinstance(new_config.get(k), dict):
                new_config[k] = {}
            # Keep the stored password when the field is left blank.
            if not new_config[k].get('password'):
                new_config[k]['password'] = NETSCALER_CONFIG.get(k, {}).get('password', '')
        save_nodes_config(new_config)
        apply_session_timeout()
        for node_key, cfg in node_items(): detect_api_mode_for_node(node_key, cfg)
        return jsonify({"success": True, "message": "Settings updated"})

    safe_config = json.loads(json.dumps(NETSCALER_CONFIG))
    for k, _ in node_items():
        safe_config[k]['password'] = ''
    safe_config['mode'] = get_mode()
    safe_config['session_timeout_minutes'] = get_session_timeout_min()
    return jsonify(safe_config)

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
    mode = get_mode()
    default_name = {'primary': 'Cluster (CLIP)' if mode == 'cluster' else 'Primary', 'secondary': 'Secondary'}
    nodes_data = {}
    for k in active_node_keys():
        v = NETSCALER_CONFIG.get(k, {})
        try:
            if v.get('ip'):
                hn = get_nitro(k)._get('/config/nshostname', custom_timeout=3).get('nshostname', [{}])[0].get('hostname')
                if not hn: hn = default_name.get(k, k.title())
            else: hn = f"{default_name.get(k, k.title())} Node"
        except Exception: hn = default_name.get(k, k.title())
        nodes_data[k] = {'ip': v.get('ip', ''), 'protocol': v.get('protocol', 'https'), 'port': v.get('port', 443), 'name': hn }
    return jsonify({'api_mode': API_MODE, 'nodes': nodes_data, 'mode': mode})

@app.route('/api/system-stats')
@login_required
def api_system_stats():
    node = request.args.get('node')
    if node:
        try: return jsonify({'node': node, 'api_mode': API_MODE.get(node, 'nitro'), **_build_node_overview(node)})
        except Exception as e: return jsonify({'error': str(e)}), 500
    try:
        return jsonify({
            'primary': _build_node_overview('primary'),
            'secondary': _build_node_overview('secondary'),
        })
    except Exception:
        return jsonify({'primary': {'connected': False}, 'secondary': {'connected': False}}), 200

@app.route('/api/ha-status')
@login_required
def api_ha_status():
    ha_data = _get_ha_data_fast()
    nodes = ha_data.get('hanode', []) if isinstance(ha_data, dict) else []
    track_ha_state_changes(nodes)
    
    def get_config_changed(node_key):
        try:
            cfg_resp = get_nitro(node_key)._get('/config/nsconfig', custom_timeout=2).get('nsconfig')
            if isinstance(cfg_resp, list) and len(cfg_resp) > 0:
                return str(cfg_resp[0].get('configchanged', 'false')).lower() in ['true', '1', 'yes']
            elif isinstance(cfg_resp, dict):
                return str(cfg_resp.get('configchanged', 'false')).lower() in ['true', '1', 'yes']
            return False
        except Exception: return False

    hostnames = {}
    for nk in active_node_keys():
        try:
            nit = get_nitro(nk)
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

    result = {'mode': get_mode(), 'hanode': nodes}
    for nk in active_node_keys():
        result[nk] = {'config_changed': get_config_changed(nk)}
    return jsonify(result)

@app.route('/api/lb-vservers')
@login_required
def api_lb_vservers():
    node = request.args.get('node')
    if not node: return jsonify({'connected': False, 'data': {'lbvserver': []}})

    if API_MODE.get(node, 'nitro') == 'nextgen':
        try:
            ng = get_nextgen(node)
            ng.login()
            apps = ng.list_applications()
            items = apps.get('applications', []) if isinstance(apps, dict) else (apps if isinstance(apps, list) else [])
            lbv_like = [{'name': a.get('name'), 'ipv46': a.get('vip') or a.get('vipAddress'), 'port': a.get('port'), 'curstate': a.get('state') or 'UP'} for a in items]
            ng.logout()
            return jsonify({'node': node, 'api_mode': 'nextgen', 'lbvserver': lbv_like})
        except Exception: pass
            
    try:
        data = get_nitro(node)._get('/config/lbvserver', custom_timeout=5) or {}
        return jsonify({'node': node, 'api_mode': 'nitro',
                        **({'lbvserver': data.get('lbvserver', [])} if isinstance(data, dict) else {'lbvserver': []})})
    except Exception: return jsonify({'lbvserver': []})

@app.route('/api/services')
@login_required
def api_services():
    node = request.args.get('node')
    if not node: return jsonify({'connected': False, 'data': {'service': [], 'servicegroup': []}})
            
    if API_MODE.get(node, 'nitro') == 'nextgen':
        try:
            ng = get_nextgen(node)
            ng.login()
            apps = ng.list_applications()
            ng.logout()
            return jsonify({'node': node, 'api_mode': 'nextgen', 'service': [], 'servicegroup': [], 'applications': apps})
        except Exception: pass
            
    try:
        nitro = get_nitro(node)
        svc  = nitro._get('/config/service', custom_timeout=5) or {}
        sgrp = nitro._get('/config/servicegroup', custom_timeout=5) or {}
        return jsonify({'node': node, 'api_mode': 'nitro',
                        'service': svc.get('service', []) if isinstance(svc, dict) else [],
                        'servicegroup': sgrp.get('servicegroup', []) if isinstance(sgrp, dict) else []})
    except Exception: return jsonify({'service': [], 'servicegroup': []})

# ======================================================================================
# Advanced Sessions, Failover History & User Actions
# ======================================================================================
@app.route('/api/user-sessions')
@login_required
def api_user_sessions():
    node_req = request.args.get('node', 'primary')
    other_node = 'secondary' if node_req == 'primary' else 'primary'
    all_sessions = []
    
    for nk in [node_req, other_node]:
        try:
            nitro = get_nitro(nk)
            vpn_resp = nitro._get('/config/vpnsession', custom_timeout=4)
            aaa_resp = nitro._get('/config/aaasession', custom_timeout=4)
            
            vpn_sessions = vpn_resp.get('vpnsession', []) if isinstance(vpn_resp, dict) else []
            aaa_sessions = aaa_resp.get('aaasession', []) if isinstance(aaa_resp, dict) else []

            # Process VPN sessions dynamically extracting any valid IP/Gateway and calculating Start time
            for raw_s in vpn_sessions:
                s = {str(k).lower(): v for k, v in raw_s.items()}
                
                duration_secs = int(s.get('duration', 0) or 0)
                start_dt = datetime.now().timestamp() - duration_secs
                start_time_str = datetime.fromtimestamp(start_dt, IL_TZ).strftime('%d/%m/%Y %H:%M:%S')
                
                ip_addr = 'Unknown'
                for ip_key in ['publicip', 'clientip', 'peip', 'client_ip', 'ipaddress', 'ip']:
                    val = str(s.get(ip_key, '')).strip()
                    if val and val not in ['None', '0.0.0.0']:
                        ip_addr = val
                        break
                
                gateway = 'Unknown'
                for gw_key in ['vservername', 'vserver', 'vsname', 'destip', 'intranetip']:
                    val = str(s.get(gw_key, '')).strip()
                    if val and val not in ['None', '0.0.0.0']:
                        gateway = val
                        break

                all_sessions.append({
                    'user': s.get('username', 'Unknown'),
                    'type': 'VPN',
                    'status': 'Active',
                    'duration': f"{duration_secs // 60} min",
                    'ip': ip_addr,
                    'gateway': gateway,
                    'start': start_time_str,
                    'end': 'Active'
                })

            # Process AAA sessions without duplicates
            for raw_s in aaa_sessions:
                s = {str(k).lower(): v for k, v in raw_s.items()}
                if not any(x['user'] == s.get('username') for x in all_sessions):
                    duration_secs = int(s.get('duration', 0) or 0)
                    start_dt = datetime.now().timestamp() - duration_secs
                    start_time_str = datetime.fromtimestamp(start_dt, IL_TZ).strftime('%d/%m/%Y %H:%M:%S')

                    ip_addr = 'Unknown'
                    for ip_key in ['publicip', 'clientip', 'peip', 'client_ip', 'ipaddress', 'ip']:
                        val = str(s.get(ip_key, '')).strip()
                        if val and val not in ['None', '0.0.0.0']:
                            ip_addr = val
                            break
                    
                    gateway = 'Unknown'
                    for gw_key in ['vservername', 'vserver', 'vsname', 'destip', 'intranetip']:
                        val = str(s.get(gw_key, '')).strip()
                        if val and val not in ['None', '0.0.0.0']:
                            gateway = val
                            break
                        
                    all_sessions.append({
                        'user': s.get('username', 'Unknown'),
                        'type': 'AAA/Web',
                        'status': 'Active',
                        'duration': f"{duration_secs // 60} min",
                        'ip': ip_addr,
                        'gateway': gateway,
                        'start': start_time_str,
                        'end': 'Active'
                    })
            break
        except Exception:
            continue

    return jsonify({'sessions': all_sessions})

@app.route('/api/failover-history')
@login_required
def api_failover_history():
    history = load_failover_history()
    changed = False

    ha_data = _get_ha_data_fast()
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
                    'ip': ip
                }
                history.append(new_event)
                changed = True
                
    if changed: save_failover_history(history)
    history.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return jsonify({'events': history})

@app.route('/api/unlock-user', methods=['POST'])
@login_required
def api_unlock_user():
    body = request.get_json(force=True, silent=True) or {}
    node_val = body.get('node') or 'primary'
    username_val = body.get('username') or ''
    if not isinstance(node_val, str) or not isinstance(username_val, str):
        return jsonify({"success": False, "error": "node and username must be strings"}), 400
    node = node_val.strip()
    username = username_val.strip()

    if not username: return jsonify({"success": False, "error": "Missing username"}), 400

    try: nitro = get_nitro(node)
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
for node_key, cfg in node_items(): detect_api_mode_for_node(node_key, cfg)

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