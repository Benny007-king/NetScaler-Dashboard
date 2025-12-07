#!/usr/bin/env python3
"""
NetScaler Dashboard (Dual-Stack: NITRO + Next-Gen API)
Compat edition + Unlock Users, with .env configuration (python-dotenv)
UPDATED: Real User Sessions & Failover Logic
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
from pathlib import Path

import requests
from flask import (
    Flask, render_template, jsonify, request, redirect, url_for,
    session, flash
)


# ===== LDAP configuration =====
AUTH_BACKENDS = {x.strip().lower() for x in os.getenv("AUTH_BACKENDS", "local").split(",") if x.strip()}
LDAP_ENABLED = os.getenv("LDAP_ENABLED", "0").lower() in ("1", "true", "yes")
LDAP_CFG = {
    "server": os.getenv("LDAP_SERVER", ""),
    "port": int(os.getenv("LDAP_PORT", "389") or 389),
    "use_ssl": os.getenv("LDAP_USE_SSL", "0").lower() in ("1","true","yes"),
    "base_dn": os.getenv("LDAP_BASE_DN", ""),
    "bind_dn": os.getenv("LDAP_BIND_DN", ""),
    "bind_pw": os.getenv("LDAP_BIND_PASSWORD", ""),
    "user_attr": os.getenv("LDAP_USER_ATTRIBUTE", "sAMAccountName"),
    "allowed_group_dn": os.getenv("LDAP_ALLOWED_GROUP_DN", ""),
    "timeout": int(os.getenv("LDAP_TIMEOUT_SECS", "10") or 10),
}
try:
    if LDAP_ENABLED and ("ldap" in AUTH_BACKENDS):
        from ldap3 import Server, Connection, ALL, SUBTREE
        from ldap3.utils.conv import escape_filter_chars
        from ldap3.utils.dn import escape_dn_chars
except Exception:
    LDAP_ENABLED = False

# --------------------------------------------------------------------------------------
# Load environment
# --------------------------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    BASE_DIR = Path(__file__).resolve().parent
    env_main  = BASE_DIR / os.getenv("ENV_FILE", ".env")
    env_local = BASE_DIR / os.getenv("ENV_FILE_LOCAL", ".env.local")

    if env_main.exists():
        load_dotenv(env_main, override=False)
        print(f"[dotenv] Loaded: {env_main}")
    else:
        print(f"[dotenv] Not found: {env_main}")

    if env_local.exists():
        load_dotenv(env_local, override=True)
        print(f"[dotenv] Loaded: {env_local} (override)")
    else:
        print(f"[dotenv] Not found: {env_local}")
except Exception as e:
    print(f"[dotenv] Skipped: {e}")

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# --------------------------------------------------------------------------------------
# Flask app + logging
# --------------------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET", "dev-secret-change-me")

LOG_FILE = os.getenv("APP_LOG_FILE", "netscaler_complete.log")
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
# Local dashboard auth
# --------------------------------------------------------------------------------------
AUTH_CONFIG_FILE = os.getenv('AUTH_CONFIG_FILE', 'auth_config.json')
DEFAULT_USERNAME = os.getenv('UI_DEFAULT_USERNAME', 'admin')
DEFAULT_PASSWORD = os.getenv('UI_DEFAULT_PASSWORD', 'admin')


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
        if auth_config.get('is_default_password', False) and request.endpoint not in ("change_password", "logout"):
            if request.is_json:
                return jsonify({'error': 'Password change required', 'redirect': url_for('change_password')}), 403
            return redirect(url_for('change_password'))
        return fn(*args, **kwargs)
    return _wrapped

# --------------------------------------------------------------------------------------
# NITRO client
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

    def get_servicegroups(self):
        try:
            return self._get('/config/servicegroup')
        except Exception:
            return {'servicegroup': []}

    def get_servicegroup_bindings(self):
        try:
            return self._get('/config/servicegroup_service_binding')
        except Exception:
            return {'servicegroup_service_binding': []}

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

    # --- ADDED FOR USER SESSIONS ---
    def get_vpn_sessions(self):
        try:
            # Requires NetScaler Gateway license/feature
            return self._get('/config/vpnsession')
        except Exception:
            return {'vpnsession': []}

    def get_aaa_sessions(self):
        try:
            return self._get('/config/aaasession')
        except Exception:
            return {'aaasession': []}
    # -------------------------------

    def get_hostname(self):
        try:
            res = self._get('/config/nshostname')
            if isinstance(res, dict):
                obj = res.get('nshostname')
                if isinstance(obj, list) and obj:
                    obj = obj[0]
                if isinstance(obj, dict):
                    return obj.get('hostname') or obj.get('name')
        except Exception:
            pass
        return None

    def unlock_user(self, username: str) -> dict:
        primary_payload = {"aaauser": {"username": username, "unlockAccount": True}}
        try:
            resp = self._post("/config/aaauser", primary_payload)
            if isinstance(resp, dict) and str(resp.get("errorcode", "0")) not in ("0", "", "None"):
                msg = str(resp.get("message", "")).lower()
                if ("unlockaccount" in msg) or ("invalid" in msg) or ("unknown" in msg):
                    raise ValueError(resp.get("message") or "primary payload not supported")
                return resp
            return resp
        except Exception as primary_err:
            try:
                return self._post("/config/aaauser?action=unlock", {"aaauser": {"username": username}})
            except Exception as e1:
                try:
                    return self._post(f"/config/aaauser/{username}?action=unlock",
                                      {"aaauser": {"username": username}})
                except Exception as e2:
                    try:
                        return self._post("/config/systemuser?action=unlock",
                                          {"systemuser": {"username": username}})
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
# Device config
# --------------------------------------------------------------------------------------
def _int(v, default):
    try:
        return int(v)
    except Exception:
        return default

NETSCALER_CONFIG = {
    'primary': {
        'ip': os.getenv('NS_PRIMARY_IP', ''),
        'username': os.getenv('NS_PRIMARY_USER', ''),
        'password': os.getenv('NS_PRIMARY_PASS', ''),
        'port': _int(os.getenv('NS_PRIMARY_PORT', '80'), 80),
        'protocol': os.getenv('NS_PRIMARY_PROTO', 'http'),
    },
    'secondary': {
        'ip': os.getenv('NS_SECONDARY_IP', ''),
        'username': os.getenv('NS_SECONDARY_USER', ''),
        'password': os.getenv('NS_SECONDARY_PASS', ''),
        'port': _int(os.getenv('NS_SECONDARY_PORT', '80'), 80),
        'protocol': os.getenv('NS_SECONDARY_PROTO', 'http'),
    }
}

API_MODE = {k: 'nitro' for k in NETSCALER_CONFIG.keys()}

def validate_env():
    missing = []
    for prefix in ('NS_PRIMARY', 'NS_SECONDARY'):
        for key in ('IP', 'USER', 'PASS'):
            if not os.getenv(f'{prefix}_{key}'):
                missing.append(f'{prefix}_{key}')
    if missing:
        logger.warning("Missing env vars (set in .env): %s", ", ".join(missing))

# --------------------------------------------------------------------------------------
# Version detection
# --------------------------------------------------------------------------------------
def _parse_version_tuple(version_str: str):
    m = re.search(r"(\d+)\.(\d+)", str(version_str or ""))
    if not m:
        return (0, 0)
    return (int(m.group(1)), int(m.group(2)))


def _is_nextgen_supported(version_str: str) -> bool:
    major, minor = _parse_version_tuple(version_str)
    return (major, minor) >= (14, 1)


def detect_api_mode_for_node(node_key: str, cfg: dict):
    if os.getenv("NEXTGEN_FORCE", "0").lower() in ("1", "true", "yes"):
        API_MODE[node_key] = 'nextgen'
        logger.info(f"[{node_key}] API mode forced to NEXTGEN via env")
        return
    if os.getenv("NEXTGEN_DISABLE", "0").lower() in ("1", "true", "yes"):
        API_MODE[node_key] = 'nitro'
        logger.info(f"[{node_key}] API mode forced to NITRO via env")
        return

    if not cfg.get('ip') or not cfg.get('username') or not cfg.get('password'):
        logger.warning(f"[{node_key}] Missing IP/username/password; leaving API mode as 'nitro'")
        API_MODE[node_key] = 'nitro'
        return

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
        try:
            ng = NextGenAPI(
                cfg['ip'], cfg['username'], cfg['password'],
                port=_int(os.getenv('NS_PORT_HTTPS', '443'), 443),
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
# Helpers
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
        port=_int(os.getenv('NS_PORT_HTTPS', '443'), 443),
        protocol=os.getenv('NS_PROTO_HTTPS', 'https')
    )

def _roles_from_ha() -> tuple[dict, dict]:
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
    cfg = NETSCALER_CONFIG.get(node_key, {})
    ip = cfg.get('ip')
    nitro = get_nitro(node_key)
    stats = nitro.get_system_stats() or {}
    connected = bool(isinstance(stats, dict) and stats.get('ns'))
    roles, _ = _roles_from_ha()
    role = roles.get(ip, 'Unknown')

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
# Auth/UI routes
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
    return render_template('login.html', auth_backends=AUTH_BACKENDS)


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

@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

# --------------------------------------------------------------------------------------
# API endpoints
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

@app.route('/api/system-stats')
@login_required
def api_system_stats():
    node = request.args.get('node')
    if node:
        try:
            ov = _build_node_overview(node)
            return jsonify({'node': node, 'api_mode': API_MODE.get(node, 'nitro'), **ov})
        except Exception as e:
            logger.exception('system-stats (single) failed')
            return jsonify({'error': str(e)}), 500
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
    node = request.args.get('node')
    hostnames = {}
    for nk in ('primary', 'secondary'):
        try:
            nit = get_nitro(nk)
            hn = nit.get_hostname()
            if hn:
                hostnames[nit.ip] = hn
        except Exception:
            pass

    def enrich(nodes):
        for n in nodes:
            if not isinstance(n, dict):
                continue
            ip = n.get('ipaddress') or n.get('ip') or n.get('nsip')
            if ip and not n.get('name') and hostnames.get(ip):
                n['name'] = hostnames[ip]
            if not n.get('name'):
                st = str(n.get('state', '')).upper()
                n['name'] = 'Primary' if 'PRIMARY' in st else ('Secondary' if 'SECONDARY' in st else (hostnames.get(ip) or 'node'))
        return nodes

    if node:
        nitro = get_nitro(node)
        data = nitro.get_ha_status() or {}
        nodes = data.get('hanode', []) if isinstance(data, dict) else []
        return jsonify({
            'node': node,
            'api_mode': API_MODE.get(node, 'nitro'),
            'hanode': enrich(nodes)
        })

    roles, raw = _roles_from_ha()
    nodes = raw.get('hanode', []) if isinstance(raw, dict) else []
    primary = _build_node_overview('primary')
    secondary = _build_node_overview('secondary')
    return jsonify({
        'primary': primary,
        'secondary': secondary,
        'hanode': enrich(nodes)
    })

@app.route('/api/lb-vservers')
@login_required
def api_lb_vservers():
    node = request.args.get('node')
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
            nitro = get_nitro(node)
            data = nitro.get_lb_vservers() or {}
            return jsonify({'connected': True, 'data': {'lbvserver': data.get('lbvserver', []) if isinstance(data, dict) else []}})
        except Exception:
            return jsonify({'connected': False, 'data': {'lbvserver': []}})

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
            pass
        finally:
            try:
                ng.logout()
            except Exception:
                pass
    nitro = get_nitro(node)
    data = nitro.get_lb_vservers() or {}
    return jsonify({'node': node, 'api_mode': 'nitro',
                    **({'lbvserver': data.get('lbvserver', [])} if isinstance(data, dict) else {'lbvserver': []})})


@app.route('/api/services')
@login_required
def api_services():
    node = request.args.get('node')
    if not node:
        try:
            nitro = get_nitro('primary')
            svc  = nitro.get_services() or {}
            sgrp = nitro.get_servicegroups() or {}
            return jsonify({'connected': True, 'data': {
                'service': svc.get('service', []) if isinstance(svc, dict) else [],
                'servicegroup': sgrp.get('servicegroup', []) if isinstance(sgrp, dict) else []
            }})
        except Exception:
            return jsonify({'connected': False, 'data': {'service': [], 'servicegroup': []}})
    mode = API_MODE.get(node, 'nitro')
    if mode == 'nextgen':
        try:
            ng = get_nextgen(node)
            ng.login()
            apps = ng.list_applications()
            return jsonify({'node': node, 'api_mode': 'nextgen',
                            'service': [], 'servicegroup': [], 'applications': apps})
        except Exception:
            pass
        finally:
            try:
                ng.logout()
            except Exception:
                pass
    nitro = get_nitro(node)
    svc  = nitro.get_services() or {}
    sgrp = nitro.get_servicegroups() or {}
    return jsonify({'node': node, 'api_mode': 'nitro',
                    'service': svc.get('service', []) if isinstance(svc, dict) else [],
                    'servicegroup': sgrp.get('servicegroup', []) if isinstance(sgrp, dict) else []})


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

# --------------------------------------------------------------------------------------
# UPDATED ROUTES: Real Logic for Sessions & Failover
# --------------------------------------------------------------------------------------

@app.route('/api/user-sessions')
@login_required
def api_user_sessions():
    node = request.args.get('node', 'primary')
    
    try:
        nitro = get_nitro(node)
        
        # 1. Fetch VPN/Gateway sessions
        vpn_resp = nitro.get_vpn_sessions()
        vpn_sessions = vpn_resp.get('vpnsession', []) if isinstance(vpn_resp, dict) else []
        
        # 2. Fetch AAA sessions
        aaa_resp = nitro.get_aaa_sessions()
        aaa_sessions = aaa_resp.get('aaasession', []) if isinstance(aaa_resp, dict) else []

        all_sessions = []

        # Process VPN sessions
        for s in vpn_sessions:
            all_sessions.append({
                'user': s.get('username', 'Unknown'),
                'type': 'VPN',
                'status': 'Active',
                'duration': f"{int(s.get('duration', 0)) // 60} min",
                'ip': s.get('clientip', ''),
                'node': node,
                'start': s.get('logintime', '')
            })

        # Process AAA sessions
        for s in aaa_sessions:
            # Deduplicate if user exists in VPN sessions
            if not any(x['user'] == s.get('username') for x in all_sessions):
                all_sessions.append({
                    'user': s.get('username', 'Unknown'),
                    'type': 'AAA/Web',
                    'status': 'Active',
                    'duration': f"{int(s.get('duration', 0)) // 60} min",
                    'ip': s.get('clientip', ''),
                    'node': node,
                    'start': s.get('logintime', '')
                })

        return jsonify({'sessions': all_sessions})

    except Exception as e:
        logger.error(f"Error fetching sessions: {e}")
        return jsonify({'sessions': []})


@app.route('/api/failover-history')
@login_required
def api_failover_history():
    """
    Returns recent HA transition information.
    NetScaler API does not provide a full historical event log (requires syslog),
    so we return the last state transition time.
    """
    node = request.args.get('node', 'primary')
    try:
        nitro = get_nitro(node)
        # Use existing HA status method
        ha_data = nitro.get_ha_status()
        nodes = ha_data.get('hanode', []) if isinstance(ha_data, dict) else []
        
        events = []
        
        for n in nodes:
            # Check for transition time and current state
            last_transition = n.get('transtime', '') 
            state = n.get('hacurstate', 'Unknown')
            ip = n.get('ipaddress', 'Unknown')
            
            if last_transition:
                events.append({
                    'timestamp': last_transition,
                    'type': 'State Change',
                    'reason': f"Node {ip} is currently {state}",
                    'role_change': f"Current: {state}"
                })

        if not events:
            # Just show current system uptime/status if no transition info found
            events.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'System Check',
                'reason': 'System is UP (No recent failover detected via API)',
                'role_change': '-'
            })
            
        return jsonify({'events': events})

    except Exception as e:
        logger.error(f"Error fetching HA history: {e}")
        return jsonify({'events': []})

@app.route('/api/export/failover-history')
@login_required
def api_export_failover():
    # Placeholder for CSV export - could implement later based on above logic
    return jsonify({'error': 'Export not implemented in this build'}), 501

@app.route('/api/export/user-sessions')
@login_required
def api_export_sessions():
    # Placeholder for CSV export
    return jsonify({'error': 'Export not implemented in this build'}), 501

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
    if isinstance(resp, dict) and resp.get("errorcode") in (0, "0", None) and not resp.get("error"):
        return jsonify({"success": True, "message": f"User {username} unlocked successfully"})

    msg = (resp or {}).get("message", "Failed to unlock user")
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

    validate_env()

    for node_key, cfg in NETSCALER_CONFIG.items():
        detect_api_mode_for_node(node_key, cfg)
    logger.info(f"API modes at startup: {API_MODE}")

    logger.info("========================================")
    logger.info("Starting NetScaler Dashboard (Dual-Stack + Compat + Unlock)")
    logger.info(f"Next-Gen verify SSL: {os.getenv('NEXTGEN_VERIFY_SSL', '0')}")
    logger.info(f"Next-Gen timeout (s): {os.getenv('NEXTGEN_TIMEOUT_SECS', '15')}")
    logger.info("========================================")

    use_ssl = os.getenv('APP_SSL', '0').lower() in ('1', 'true', 'yes')
    ssl_context = 'adhoc' if use_ssl else None

    app.run(host=host, port=port, debug=debug, ssl_context=ssl_context)
