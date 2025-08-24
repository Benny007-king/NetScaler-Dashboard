#!/usr/bin/env python3
"""
NetScaler Dashboard (Dual-Stack: NITRO + Next-Gen API)
Compat edition for the original Tailwind dashboard + Unlock Users
=================================================================
This Flask app authenticates locally (admin UI) and talks to NetScaler devices.
It auto-detects per-node whether the device supports the Next-Gen API and will
use it when available; otherwise it falls back to NITRO.

Compatibility endpoints (as expected by templates/dashboard.html):
- GET /api/system-stats       -> {primary:{connected,ha_role,ns_stats,version}, secondary:{...}}
- GET /api/ha-status          -> {primary:{connected,ha_role}, secondary:{...}, hanode:[...]}
- GET /api/system-info        -> {primary:{...}, secondary:{...}}
- GET /api/lb-vservers        -> {connected:bool, data:{lbvserver:[...]}}  (auto-picks active node)
- GET /api/services           -> {connected:bool, data:{service:[...]}}
- POST /api/unlock-user       -> Unlock AAA user on a node (always via NITRO)

Security note
-------------
For lab friendliness, NEXTGEN_VERIFY_SSL defaults to 0 (disabled). Enable it in
production with environment variable NEXTGEN_VERIFY_SSL=1 and install a proper
certificate chain on the ADC(s).
"""
from __future__ import annotations

import os
import sys
import json
import re
import hashlib
import logging
from datetime import datetime
from functools import wraps

import requests
from flask import (
    Flask, render_template, jsonify, request, redirect, url_for,
    session, flash
)

# --------------------------------------------------------------------------------------
# Windows console: prefer UTF-8 to avoid UnicodeEncodeError in logging
# --------------------------------------------------------------------------------------
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# --------------------------------------------------------------------------------------
# Flask app + logging
# --------------------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET", "netscaler-dashboard-secret-key-super-secure-2024")

LOG_FILE = "netscaler_complete.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ],
)
logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------------------
# Local dashboard auth (username/password stored hashed in auth_config.json)
# --------------------------------------------------------------------------------------
AUTH_CONFIG_FILE = 'auth_config.json'
DEFAULT_USERNAME = 'admin'
DEFAULT_PASSWORD = 'admin'


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def _default_auth_config() -> dict:
    return {
        'username': DEFAULT_USERNAME,
        'password_hash': hash_password(DEFAULT_PASSWORD),
        'is_default_password': True,
        'created_at': datetime.now().isoformat(),
        'last_login': None,
        'login_attempts': 0,
        'last_password_change': None,
    }


def load_auth_config() -> dict:
    try:
        if os.path.exists(AUTH_CONFIG_FILE):
            with open(AUTH_CONFIG_FILE, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            logger.info("Loaded existing authentication configuration")
            return cfg
        cfg = _default_auth_config()
        save_auth_config(cfg)
        logger.info("Created default authentication configuration")
        return cfg
    except Exception as e:
        logger.error(f"Error loading auth config: {e}")
        return _default_auth_config()


def save_auth_config(config: dict) -> None:
    try:
        with open(AUTH_CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        logger.info("Authentication configuration saved")
    except Exception as e:
        logger.error(f"Error saving auth config: {e}")


auth_config = load_auth_config()


def login_required(fn):
    @wraps(fn)
    def _wrapped(*args, **kwargs):
        if not session.get('logged_in'):
            if request.is_json:
                return jsonify({'error': 'Authentication required', 'redirect': url_for('login')}), 401
            return redirect(url_for('login'))
        # force change if default password still active
        if auth_config.get('is_default_password', False) and request.endpoint not in ("change_password", "logout"):
            if request.is_json:
                return jsonify({'error': 'Password change required', 'redirect': url_for('change_password')}), 403
            return redirect(url_for('change_password'))
        return fn(*args, **kwargs)
    return _wrapped

# --------------------------------------------------------------------------------------
# NITRO client (simplified): header-based auth (X-NITRO-USER/PASS)
# --------------------------------------------------------------------------------------
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
        verify_env = os.getenv("NITRO_VERIFY_SSL", "1").lower() in ("1", "true", "yes")
        self.session.verify = verify_env
        try:
            self.timeout = int(os.getenv("NITRO_TIMEOUT_SECS", "15"))
        except Exception:
            self.timeout = 15
        logger.info(f"Initialized NITRO client for {self.protocol}://{self.ip}:{self.port}")

    def _get(self, path):
        url = f"{self.base_url}{path}"
        r = self.session.get(url, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _post(self, path, payload):
        url = f"{self.base_url}{path}"
        r = self.session.post(url, json=payload, timeout=self.timeout)
        r.raise_for_status()
        if r.text.strip():
            try:
                return r.json()
            except Exception:
                return {'raw': r.text, 'status_code': r.status_code}
        return {'status_code': r.status_code}

    # Basic info endpoints
    def get_version_info(self):
        try:
            return self._get('/config/nsversion')
        except Exception:
            return None

    def get_lb_vservers(self):
        try:
            return self._get('/config/lbvserver')
        except Exception:
            return {'lbvserver': []}

    def get_services(self):
        try:
            return self._get('/config/service')
        except Exception:
            return {'service': []}

    def get_system_stats(self):
        try:
            return self._get('/stat/ns')
        except Exception:
            return {'ns': {}}

    def get_system_info(self):
        try:
            return self._get('/stat/system')
        except Exception:
            return {'system': {}}

    def get_ha_status(self):
        try:
            return self._get('/config/hanode')
        except Exception:
            return {'hanode': []}

    # AAA unlock (primary path + fallbacks)
    def unlock_user(self, username: str) -> dict:
        """
        Unlock AAA (or local system) user via NITRO.

        Attempts, in order:
          1) POST /config/aaauser { "aaauser": {"username": "<u>", "unlockAccount": true } }
          2) POST /config/aaauser?action=unlock { "aaauser": {"username": "<u>" } }
          3) POST /config/aaauser/<u>?action=unlock { "aaauser": {"username": "<u>" } }
          4) POST /config/systemuser?action=unlock { "systemuser": {"username": "<u>" } }  # local ns admin
        """
        # --- Attempt 1: newer syntax (חלק מהגרסאות מכירות בזה) ---
        primary_payload = {"aaauser": {"username": username, "unlockAccount": True}}
        try:
            resp = self._post("/config/aaauser", primary_payload)

            # אם יש errorcode!=0 (למרות שזו לא שגיאת HTTP) – ננסה נפילות מדרגה.
            if isinstance(resp, dict) and str(resp.get("errorcode", "0")) not in ("0", "", "None"):
                msg = str(resp.get("message", "")).lower()
                if ("unlockaccount" in msg) or ("invalid" in msg) or ("unknown" in msg):
                    raise ValueError(resp.get("message") or "primary payload not supported")
                # במקרה של שגיאות אחרות – נחזיר כמו שהוא.
                return resp

            # הצלחה
            return resp

        except Exception as primary_err:
            # --- Attempt 2: action=unlock עם body ---
            try:
                return self._post(
                    "/config/aaauser?action=unlock",
                    {"aaauser": {"username": username}}
                )
            except Exception as e1:
                # --- Attempt 3: action=unlock עם username בנתיב ---
                try:
                    return self._post(
                        f"/config/aaauser/{username}?action=unlock",
                        {"aaauser": {"username": username}}
                    )
                except Exception as e2:
                    # --- Attempt 4: systemuser (למשתמשי מערכת מקומיים, לא AAA) ---
                    try:
                        return self._post(
                            "/config/systemuser?action=unlock",
                            {"systemuser": {"username": username}}
                        )
                    except Exception as e3:
                        return {
                            "errorcode": -1,
                            "message": (
                                f"All unlock attempts failed. "
                                f"primary={primary_err}; f1={e1}; f2={e2}; f3={e3}"
                            ),
                        }


# --------------------------------------------------------------------------------------
# Next-Gen API client
# --------------------------------------------------------------------------------------
class NextGenAPI:
    def __init__(self, ip, username, password, port=443, protocol='https'):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.protocol = protocol
        self.base_url = f"{protocol}://{ip}:{port}/mgmt/api/nextgen/v1"
        self.session = requests.Session()
        verify_env = os.getenv("NEXTGEN_VERIFY_SSL", "0").lower() in ("1", "true", "yes")
        self.session.verify = verify_env
        try:
            self.timeout = int(os.getenv("NEXTGEN_TIMEOUT_SECS", "15"))
        except Exception:
            self.timeout = 15
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'NetScaler-Dashboard-NextGen/1.0'
        })
        self.session_cookie = None
        logger.info(f"Initialized Next-Gen client for {self.protocol}://{self.ip}:{self.port}")

    def login(self, timeout_str="15min"):
        url = f"{self.base_url}/login"
        payload = {"login": {"username": self.username, "password": self.password, "timeout": timeout_str}}
        r = self.session.post(url, json=payload, timeout=self.timeout)
        r.raise_for_status()
        self.session_cookie = r.cookies.get('sessionid')
        if not self.session_cookie:
            raise RuntimeError("Next-Gen login succeeded without sessionid cookie")
        return True

    def logout(self):
        url = f"{self.base_url}/logout"
        r = self.session.post(url, timeout=self.timeout)
        if r.status_code not in (200, 201, 202, 204):
            r.raise_for_status()
        self.session_cookie = None
        return True

    # Applications
    def list_applications(self):
        url = f"{self.base_url}/applications"
        r = self.session.get(url, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_application_stats(self, name):
        url = f"{self.base_url}/applications/{name}/stats"
        r = self.session.get(url, timeout=self.timeout)
        if r.status_code == 404:
            return {"stats": None}
        r.raise_for_status()
        return r.json()

# --------------------------------------------------------------------------------------
# Device config (primary/secondary)
# --------------------------------------------------------------------------------------
NETSCALER_CONFIG = {
    'primary': {
        'ip': os.getenv('NS_PRIMARY_IP', '10.0.0.90'),
        'username': os.getenv('NS_PRIMARY_USER', 'nsapi'),
        'password': os.getenv('NS_PRIMARY_PASS', 'nsapi1'),
        'port': int(os.getenv('NS_PRIMARY_PORT', '80')),
        'protocol': os.getenv('NS_PRIMARY_PROTO', 'http'),
    },
    'secondary': {
        'ip': os.getenv('NS_SECONDARY_IP', '10.0.0.92'),
        'username': os.getenv('NS_SECONDARY_USER', 'nsapi'),
        'password': os.getenv('NS_SECONDARY_PASS', 'nsapi1'),
        'port': int(os.getenv('NS_SECONDARY_PORT', '80')),
        'protocol': os.getenv('NS_SECONDARY_PROTO', 'http'),
    }
}

# Runtime API mode per node: 'nitro' or 'nextgen'
API_MODE = {k: 'nitro' for k in NETSCALER_CONFIG.keys()}

# --------------------------------------------------------------------------------------
# Version detection helpers
# --------------------------------------------------------------------------------------

def _parse_version_tuple(version_str: str):
    m = re.search(r"(\d+)\.(\d+)", str(version_str or ""))
    if not m:
        return (0, 0)
    return (int(m.group(1)), int(m.group(2)))


def _is_nextgen_supported(version_str: str) -> bool:
    # Conservative: Next-Gen from 14.1 and up
    major, minor = _parse_version_tuple(version_str)
    return (major, minor) >= (14, 1)


def detect_api_mode_for_node(node_key: str, cfg: dict):
    # Env overrides
    if os.getenv("NEXTGEN_FORCE", "0").lower() in ("1", "true", "yes"):
        API_MODE[node_key] = 'nextgen'
        logger.info(f"[{node_key}] API mode forced to NEXTGEN via env")
        return
    if os.getenv("NEXTGEN_DISABLE", "0").lower() in ("1", "true", "yes"):
        API_MODE[node_key] = 'nitro'
        logger.info(f"[{node_key}] API mode forced to NITRO via env")
        return

    # 1) Ask version using NITRO (works on 11.x/12.x/13.x/14.x)
    nitro = NetScalerAPI(cfg['ip'], cfg['username'], cfg['password'], cfg['port'], cfg['protocol'])
    version_str = None
    try:
        vi = nitro.get_version_info()
        if isinstance(vi, dict) and vi.get('nsversion'):
            meta = vi['nsversion'][0] if isinstance(vi['nsversion'], list) else vi['nsversion']
            version_str = meta.get('version')
    except Exception as e:
        logger.warning(f"[{node_key}] Could not get version via NITRO: {e}")

    if version_str and _is_nextgen_supported(version_str):
        # 2) Try Next-Gen login with HTTPS (port/proto via env)
        try:
            ng = NextGenAPI(
                cfg['ip'], cfg['username'], cfg['password'],
                port=int(os.getenv('NS_PORT_HTTPS', '443')),
                protocol=os.getenv('NS_PROTO_HTTPS', 'https')
            )
            ng.login()
            ng.logout()
            API_MODE[node_key] = 'nextgen'
            logger.info(f"[{node_key}] API mode selected: NEXTGEN (version={version_str})")
            return
        except Exception as e:
            logger.warning(f"[{node_key}] Next-Gen login failed; fallback to NITRO: {e}")

    API_MODE[node_key] = 'nitro'
    logger.info(f"[{node_key}] API mode selected: NITRO (version={version_str})")

# --------------------------------------------------------------------------------------
# Helpers to get clients
# --------------------------------------------------------------------------------------

def get_nitro(node_key: str) -> NetScalerAPI:
    cfg = NETSCALER_CONFIG.get(node_key or 'primary')
    if not cfg:
        raise KeyError(f"Unknown node '{node_key}'")
    return NetScalerAPI(cfg['ip'], cfg['username'], cfg['password'], cfg['port'], cfg['protocol'])


def get_nextgen(node_key: str) -> NextGenAPI:
    cfg = NETSCALER_CONFIG.get(node_key or 'primary')
    if not cfg:
        raise KeyError(f"Unknown node '{node_key}'")
    return NextGenAPI(
        cfg['ip'], cfg['username'], cfg['password'],
        port=int(os.getenv('NS_PORT_HTTPS', '443')),
        protocol=os.getenv('NS_PROTO_HTTPS', 'https')
    )

# --------------------------------------------------------------------------------------
# Compatibility helpers (to match original dashboard JSON shapes)
# --------------------------------------------------------------------------------------

def _node_ip(node_key: str) -> str:
    return NETSCALER_CONFIG.get(node_key, {}).get('ip', '')


def _roles_from_ha() -> tuple[dict, dict]:
    """Return (roles_by_ip, raw_ha) from a single NITRO call.
    roles_by_ip maps ip -> role/state string (e.g., 'Primary', 'Secondary').
    """
    try:
        nitro = get_nitro('primary')
        raw = nitro.get_ha_status() or {}
        roles = {}
        nodes = raw.get('hanode', []) if isinstance(raw, dict) else []
        for n in nodes:
            if not isinstance(n, dict):
                continue
            ip = n.get('ipaddress') or n.get('ip') or n.get('nsip') or ''
            role = n.get('state') or n.get('hacurstate') or n.get('haStatus') or n.get('status') or ''
            if ip:
                roles[ip] = str(role)
        return roles, raw
    except Exception as e:
        logger.warning(f"HA status fetch failed: {e}")
        return {}, {'hanode': []}


def _build_node_overview(node_key: str) -> dict:
    """Shape node data as expected by the original dashboard.
    { connected: bool, ha_role: str, ns_stats: {...}, version: str }
    """
    cfg = NETSCALER_CONFIG.get(node_key, {})
    ip = cfg.get('ip')
    nitro = get_nitro(node_key)
    stats = nitro.get_system_stats() or {}
    connected = bool(isinstance(stats, dict) and stats.get('ns'))
    roles, _ = _roles_from_ha()
    role = roles.get(ip, 'Unknown')

    # Try to extract version
    version = None
    try:
        vi = nitro.get_version_info()
        if isinstance(vi, dict) and vi.get('nsversion'):
            meta = vi['nsversion'][0] if isinstance(vi['nsversion'], list) else vi['nsversion']
            version = meta.get('version') or meta.get('release')
    except Exception:
        pass

    return {
        'connected': connected,
        'ha_role': role,
        'ns_stats': stats,
        'version': version,
        'ip': ip,
    }

# --------------------------------------------------------------------------------------
# Auth routes
# --------------------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    global auth_config
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if username == auth_config.get('username') and hash_password(password) == auth_config.get('password_hash'):
            session['logged_in'] = True
            session['user'] = username
            auth_config['last_login'] = datetime.now().isoformat()
            auth_config['login_attempts'] = 0
            save_auth_config(auth_config)
            logger.info(f"Login successful for user '{username}'")
            return redirect(url_for('dashboard'))
        auth_config['login_attempts'] = int(auth_config.get('login_attempts', 0)) + 1
        save_auth_config(auth_config)
        flash('Invalid credentials', 'error')
        logger.warning("Login failed: invalid credentials")
    return render_template('login.html')


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
        auth_config['last_password_change'] = datetime.now().isoformat()
        save_auth_config(auth_config)
        flash('Password changed successfully', 'success')
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

# --------------------------------------------------------------------------------------
# UI route
# --------------------------------------------------------------------------------------
@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

# --------------------------------------------------------------------------------------
# Capability/debug route
# --------------------------------------------------------------------------------------
@app.route('/api/caps')
@login_required
def api_caps():
    return jsonify({
        'api_mode': API_MODE,
        'nodes': {
            k: {
                'ip': v['ip'],
                'protocol': v['protocol'],
                'port': v['port'],
            } for k, v in NETSCALER_CONFIG.items()
        }
    })

# --------------------------------------------------------------------------------------
# NITRO/Next-Gen compatible + compatibility endpoints for original UI
# --------------------------------------------------------------------------------------
@app.route('/api/system-stats')
@login_required
def api_system_stats():
    """Compatibility endpoint.
    - If ?node=... is provided: return a single-node object
      {node, api_mode, connected, ns_stats, ha_role}.
    - Without node: return a combined object with 'primary' and 'secondary'.
    """
    node = request.args.get('node')
    if node:
        try:
            ov = _build_node_overview(node)
            return jsonify({'node': node, 'api_mode': API_MODE.get(node, 'nitro'), **ov})
        except Exception as e:
            logger.exception('system-stats (single) failed')
            return jsonify({'error': str(e)}), 500
    # Combined
    try:
        return jsonify({
            'primary': _build_node_overview('primary'),
            'secondary': _build_node_overview('secondary'),
        })
    except Exception as e:
        logger.exception('system-stats (combined) failed')
        return jsonify({'primary': {'connected': False}, 'secondary': {'connected': False}}), 200


@app.route('/api/ha-status')
@login_required
def api_ha_status():
    """Compatibility endpoint.
    - If ?node=... provided -> return basic hanode for that node.
    - If not -> return object with primary/secondary {connected, ha_role} + raw hanode.
    """
    node = request.args.get('node')
    if node:
        nitro = get_nitro(node)
        data = nitro.get_ha_status()
        return jsonify({'node': node, 'api_mode': API_MODE.get(node, 'nitro'), 'hanode': data.get('hanode', []) if isinstance(data, dict) else []})
    roles, raw = _roles_from_ha()
    primary = _build_node_overview('primary')
    secondary = _build_node_overview('secondary')
    return jsonify({'primary': primary, 'secondary': secondary, 'hanode': raw.get('hanode', [])})


@app.route('/api/system-info')
@login_required
def api_system_info():
    """Return version & basic info per node (combined if no node is given)."""
    node = request.args.get('node')
    if node:
        ov = _build_node_overview(node)
        return jsonify({'node': node, 'api_mode': API_MODE.get(node, 'nitro'), **ov})
    return jsonify({'primary': _build_node_overview('primary'), 'secondary': _build_node_overview('secondary')})


@app.route('/api/lb-vservers')
@login_required
def api_lb_vservers():
    node = request.args.get('node')
    # If no node specified, choose preferred node based on HA (prefer active/primary)
    if not node:
        roles, _ = _roles_from_ha()
        prefer = 'primary'
        pri_role = str(roles.get(NETSCALER_CONFIG['primary']['ip'], '')).upper()
        if 'SECONDARY' in pri_role:
            prefer = 'secondary'
        node = prefer
        try:
            mode = API_MODE.get(node, 'nitro')
            if mode == 'nextgen':
                ng = get_nextgen(node)
                ng.login()
                apps = ng.list_applications()
                items = []
                if isinstance(apps, dict) and isinstance(apps.get('applications'), list):
                    items = apps['applications']
                elif isinstance(apps, dict):
                    for v in apps.values():
                        if isinstance(v, list):
                            items.extend(v)
                elif isinstance(apps, list):
                    items = apps
                lbv_like = []
                for a in items:
                    name = a.get('name') if isinstance(a, dict) else None
                    state = a.get('state') if isinstance(a, dict) else None
                    vip = a.get('vip') or a.get('vipAddress') if isinstance(a, dict) else None
                    port = a.get('port') if isinstance(a, dict) else None
                    lbv_like.append({'name': name or 'application', 'ipv46': vip, 'port': port, 'curstate': state or 'UP'})
                try:
                    ng.logout()
                except Exception:
                    pass
                return jsonify({'connected': True, 'data': {'lbvserver': lbv_like}})
            # NITRO path
            nitro = get_nitro(node)
            data = nitro.get_lb_vservers() or {}
            return jsonify({'connected': True, 'data': {'lbvserver': data.get('lbvserver', []) if isinstance(data, dict) else []}})
        except Exception as e:
            logger.exception('lb-vservers (combined) failed')
            return jsonify({'connected': False, 'data': {'lbvserver': []}})

    # Node-specific (kept from dual-stack behavior)
    mode = API_MODE.get(node, 'nitro')
    if mode == 'nextgen':
        try:
            ng = get_nextgen(node)
            ng.login()
            apps = ng.list_applications()
            lbv_like = []
            items = []
            if isinstance(apps, dict):
                if 'applications' in apps and isinstance(apps['applications'], list):
                    items = apps['applications']
                else:
                    for v in apps.values():
                        if isinstance(v, list):
                            items.extend(v)
            elif isinstance(apps, list):
                items = apps
            for a in items:
                name = a.get('name') if isinstance(a, dict) else None
                state = a.get('state') if isinstance(a, dict) else None
                vip = a.get('vip') or a.get('vipAddress') if isinstance(a, dict) else None
                port = a.get('port') if isinstance(a, dict) else None
                lbv_like.append({'name': name or 'application', 'ipv46': vip, 'port': port, 'curstate': state or 'UP'})
            return jsonify({'node': node, 'api_mode': 'nextgen', 'lbvserver': lbv_like, 'raw': apps})
        except Exception:
            logger.exception('Next-Gen applications fetch failed; falling back to NITRO for this call')
        finally:
            try:
                ng.logout()
            except Exception:
                pass
    nitro = get_nitro(node)
    data = nitro.get_lb_vservers() or {}
    return jsonify({'node': node, 'api_mode': 'nitro', **({'lbvserver': data.get('lbvserver', [])} if isinstance(data, dict) else {'lbvserver': []})})


@app.route('/api/services')
@login_required
def api_services():
    node = request.args.get('node')
    if not node:
        try:
            nitro = get_nitro('primary')
            data = nitro.get_services() or {}
            return jsonify({'connected': True, 'data': {'service': data.get('service', []) if isinstance(data, dict) else []}})
        except Exception as e:
            logger.exception('services (combined) failed')
            return jsonify({'connected': False, 'data': {'service': []}})
    # node-specific (unchanged)
    mode = API_MODE.get(node, 'nitro')
    if mode == 'nextgen':
        try:
            ng = get_nextgen(node)
            ng.login()
            apps = ng.list_applications()
            return jsonify({'node': node, 'api_mode': 'nextgen', 'service': [], 'applications': apps})
        except Exception:
            pass
        finally:
            try:
                ng.logout()
            except Exception:
                pass
    nitro = get_nitro(node)
    data = nitro.get_services()
    return jsonify({'node': node, 'api_mode': 'nitro', **({'service': data.get('service', [])} if isinstance(data, dict) else {'service': []})})

# Native Next-Gen endpoints (optional, richer data)
@app.route('/api/applications')
@login_required
def api_applications():
    node = request.args.get('node', 'primary')
    if API_MODE.get(node) != 'nextgen':
        return jsonify({'error': 'Next-Gen API not enabled for this node', 'node': node, 'api_mode': API_MODE.get(node)}), 501
    try:
        ng = get_nextgen(node)
        ng.login()
        apps = ng.list_applications()
        return jsonify({'node': node, 'api_mode': 'nextgen', 'applications': apps})
    except Exception as e:
        logger.exception("Next-Gen /applications failed")
        return jsonify({'error': str(e)}), 500
    finally:
        try:
            ng.logout()
        except Exception:
            pass


@app.route('/api/application-stats')
@login_required
def api_application_stats_nextgen():
    node = request.args.get('node', 'primary')
    name = request.args.get('name')
    if not name:
        return jsonify({'error': 'Missing application name (name)'}), 400
    if API_MODE.get(node) != 'nextgen':
        return jsonify({'error': 'Next-Gen API not enabled for this node', 'node': node, 'api_mode': API_MODE.get(node)}), 501
    try:
        ng = get_nextgen(node)
        ng.login()
        stats = ng.get_application_stats(name)
        return jsonify({'node': node, 'api_mode': 'nextgen', 'name': name, 'stats': stats})
    except Exception as e:
        logger.exception("Next-Gen /application-stats failed")
        return jsonify({'error': str(e)}), 500
    finally:
        try:
            ng.logout()
        except Exception:
            pass

# (Optional) Basic placeholders so UI doesn't error out
@app.route('/api/failover-history')
@login_required
def api_failover_history():
    # TODO: implement real parsing from ns events if available. For now empty list.
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    _ = (from_date, to_date)
    return jsonify({'events': []})


@app.route('/api/user-sessions')
@login_required
def api_user_sessions():
    # TODO: implement actual sessions aggregation from NITRO / next-gen when available
    return jsonify({'sessions': []})


@app.route('/api/export/failover-history')
@login_required
def api_export_failover():
    return jsonify({'error': 'Export not implemented in this build'}), 501


@app.route('/api/export/user-sessions')
@login_required
def api_export_sessions():
    return jsonify({'error': 'Export not implemented in this build'}), 501

# NEW: Unlock AAA user (always via NITRO)
@app.route('/api/unlock-user', methods=['POST'])
@login_required
def api_unlock_user():
    body = request.get_json(force=True, silent=True) or {}
    node = (body.get('node') or 'primary').strip()
    username = (body.get('username') or '').strip()

    if not username:
        return jsonify({"success": False, "error": "Missing username"}), 400

    try:
        nitro = get_nitro(node)
    except KeyError:
        return jsonify({"success": False, "error": f"Unknown node '{node}'"}), 400

    resp = nitro.unlock_user(username)
    # Normalize response
    if isinstance(resp, dict) and resp.get("errorcode") in (0, "0", None) and not resp.get("error"):
        return jsonify({"success": True, "message": f"User {username} unlocked successfully"})

    msg = (resp or {}).get("message", "Failed to unlock user")
    # Friendly messages for common cases
    ml = msg.lower()
    if "does not exist" in ml or "not found" in ml:
        msg = f"User '{username}' doesn't exist on the NetScaler."
    elif "not authorized" in ml or "permission" in ml:
        msg = "You don't have permission to unlock user accounts."
    elif "not locked" in ml:
        msg = f"User '{username}' is not currently locked."

    return jsonify({"success": False, "error": msg, "raw": resp}), 400

# --------------------------------------------------------------------------------------
# Error handlers
# --------------------------------------------------------------------------------------
@app.errorhandler(404)
def _404(err):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not Found'}), 404
    return render_template('dashboard.html'), 404


@app.errorhandler(500)
def _500(err):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal Server Error'}), 500
    return render_template('dashboard.html'), 500

# --------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------
if __name__ == '__main__':
    host = os.getenv('APP_HOST', '0.0.0.0')
    port = int(os.getenv('APP_PORT', '5000'))
    debug = os.getenv('APP_DEBUG', '0').lower() in ('1', 'true', 'yes')

    # Detect API mode for each node at startup
    for node_key, cfg in NETSCALER_CONFIG.items():
        detect_api_mode_for_node(node_key, cfg)
    logger.info(f"API modes at startup: {API_MODE}")

    logger.info("========================================")
    logger.info("Starting NetScaler Dashboard (Dual-Stack + Compat + Unlock)")
    logger.info(f"Next-Gen verify SSL: {os.getenv('NEXTGEN_VERIFY_SSL', '0')}")
    logger.info(f"Next-Gen timeout (s): {os.getenv('NEXTGEN_TIMEOUT_SECS', '15')}")
    logger.info("========================================")

    # Optional HTTPS for the Flask dev server
    use_ssl = os.getenv('APP_SSL', '0').lower() in ('1', 'true', 'yes')
    ssl_context = 'adhoc' if use_ssl else None

    app.run(host=host, port=port, debug=debug, ssl_context=ssl_context)
