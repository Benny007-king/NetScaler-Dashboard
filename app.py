#!/usr/bin/env python3
"""
NetScaler Real Dashboard - Enhanced Version with Authentication, Failover Monitoring and User Sessions
Connects to real NetScaler appliances via NITRO API over HTTP
"""

from flask import Flask, render_template, jsonify, request, make_response, redirect, url_for, session, flash
import requests
import json
import urllib3
from datetime import datetime, timedelta
import threading
import time
import logging
import signal
import traceback
import csv
import io
from collections import defaultdict
import hashlib
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = 'netscaler-dashboard-secret-key-super-secure-2024'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('netscaler_complete.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Authentication configuration
AUTH_CONFIG_FILE = 'auth_config.json'
DEFAULT_USERNAME = 'admin'
DEFAULT_PASSWORD = 'admin'

# Load or initialize authentication configuration
def load_auth_config():
    """Load authentication configuration from file"""
    try:
        if os.path.exists(AUTH_CONFIG_FILE):
            with open(AUTH_CONFIG_FILE, 'r') as f:
                config = json.load(f)
                logger.info("🔐 Loaded existing authentication configuration")
                return config
        else:
            # Create default configuration
            default_config = {
                'username': DEFAULT_USERNAME,
                'password_hash': hash_password(DEFAULT_PASSWORD),
                'is_default_password': True,
                'created_at': datetime.now().isoformat(),
                'last_login': None,
                'login_attempts': 0
            }
            save_auth_config(default_config)
            logger.info("🔐 Created default authentication configuration")
            return default_config
    except Exception as e:
        logger.error(f"Error loading auth config: {str(e)}")
        # Return default config in case of error
        return {
            'username': DEFAULT_USERNAME,
            'password_hash': hash_password(DEFAULT_PASSWORD),
            'is_default_password': True,
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'login_attempts': 0
        }

def save_auth_config(config):
    """Save authentication configuration to file"""
    try:
        with open(AUTH_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        logger.info("🔐 Authentication configuration saved")
    except Exception as e:
        logger.error(f"Error saving auth config: {str(e)}")

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(password, password_hash):
    """Verify password against hash"""
    return hash_password(password) == password_hash

# Load authentication configuration
auth_config = load_auth_config()

# Authentication decorator
def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            if request.is_json:
                return jsonify({'error': 'Authentication required', 'redirect': '/login'}), 401
            return redirect(url_for('login'))
        
        # Check if password change is required
        if auth_config.get('is_default_password', False) and request.endpoint != 'change_password' and request.endpoint != 'logout':
            if request.is_json:
                return jsonify({'error': 'Password change required', 'redirect': '/change-password'}), 403
            return redirect(url_for('change_password'))
        
        return f(*args, **kwargs)
    return decorated_function

# NetScaler Configuration - HTTP Port 80
NETSCALER_CONFIG = {
    'primary': {
        'ip': '10.0.0.100',
        'username': 'nsapi',
        'password': 'nsapi1',
        'port': 80,
        'protocol': 'http'
    },
    'secondary': {
        'ip': '10.0.0.200',
        'username': 'nsapi',
        'password': 'nsapi1',
        'port': 80,
        'protocol': 'http'
    }
}

# Global variables for caching
cached_data = {
    'primary': {},
    'secondary': {},
    'last_update': None,
    'connection_status': {'primary': False, 'secondary': False},
    'debug_info': {'primary': {}, 'secondary': {}},
    'stats_summary': {'total_calls': 0, 'successful_calls': 0, 'failed_calls': 0},
    'ha_roles': {'primary': 'Unknown', 'secondary': 'Unknown'},
    'failover_history': [],  # NEW: Track failover events
    'user_sessions': [],     # NEW: Track user sessions
    'connection_history': [] # NEW: Track connection patterns
}

def get_gateway_from_vservers(api, connection_type):
    """Get the appropriate virtual server as gateway based on connection type"""
    try:
        # Try to get load balancing virtual servers
        lb_vservers = api.get_lb_vservers()
        if lb_vservers and 'lbvserver' in lb_vservers:
            vservers = lb_vservers['lbvserver']
            if not isinstance(vservers, list):
                vservers = [vservers]
            
            # Look for appropriate virtual server based on connection type
            for vserver in vservers:
                vserver_name = vserver.get('name', '').lower()
                
                if connection_type == 'Web':
                    # Look for HTTP/HTTPS virtual servers
                    if any(keyword in vserver_name for keyword in ['http', 'web', 'portal', 'gui', 'mgmt']):
                        return f"Web-Gateway-{vserver.get('ipv46', api.ip)}:{vserver.get('port', '80')}"
                
                elif connection_type == 'VPN':
                    # Look for VPN/SSL virtual servers  
                    if any(keyword in vserver_name for keyword in ['vpn', 'ssl', 'netscaler']):
                        return f"VPN-Gateway-{vserver.get('ipv46', api.ip)}:{vserver.get('port', '443')}"
                
                elif connection_type == 'Workspace':
                    # Look for Citrix/ICA virtual servers
                    if any(keyword in vserver_name for keyword in ['ica', 'citrix', 'workspace', 'xenapp']):
                        return f"Workspace-Gateway-{vserver.get('ipv46', api.ip)}:{vserver.get('port', '443')}"
            
            # If no specific match found, use the first available virtual server
            if vservers:
                first_vserver = vservers[0]
                return f"{connection_type}-Gateway-{first_vserver.get('ipv46', api.ip)}:{first_vserver.get('port', '80')}"
        
        # Fallback to node IP if no virtual servers found
        return f"{connection_type}-Gateway-{api.ip}"
        
    except Exception as e:
        logger.debug(f"Error getting gateway from vservers: {str(e)}")
        return f"{connection_type}-Gateway-{api.ip}"

class NetScalerAPI:
    """NetScaler NITRO API Client - HTTP Version"""
    
    def __init__(self, ip, username, password, port=80, protocol='http'):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.protocol = protocol
        self.base_url = f"{protocol}://{ip}:{port}/nitro/v1"
        self.session = requests.Session()
        
        # Only disable SSL verification if using HTTPS
        if protocol == 'https':
            self.session.verify = False
        
        self.session_id = None
        self.debug_info = []
        
        # Add headers
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'NetScaler-Dashboard/2.0',
            'Accept': 'application/json'
        })
        
        logger.info(f"🔧 Initialized NetScaler API client for {protocol}://{ip}:{port}")
        
    def add_debug_info(self, message):
        """Add debug information"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        debug_msg = f"[{timestamp}] {message}"
        self.debug_info.append(debug_msg)
        logger.debug(f"[{self.ip}] {message}")
        
    def test_connectivity(self):
        """Test basic connectivity to NetScaler"""
        try:
            self.add_debug_info(f"Testing connectivity to {self.protocol}://{self.ip}:{self.port}")
            
            test_url = f"{self.protocol}://{self.ip}:{self.port}"
            response = self.session.get(test_url, timeout=10)
            
            self.add_debug_info(f"Connectivity test - Status: {response.status_code}")
            return response.status_code in [200, 302, 401, 403]
            
        except requests.exceptions.ConnectTimeout:
            self.add_debug_info(f"Connection timeout to {self.ip}:{self.port}")
            return False
        except requests.exceptions.ConnectionError as e:
            self.add_debug_info(f"Connection error: {str(e)}")
            return False
        except Exception as e:
            self.add_debug_info(f"Connectivity test failed: {str(e)}")
            return False
        
    def login(self):
        """Login to NetScaler and get session ID"""
        try:
            self.add_debug_info("🔐 Starting login process")
            
            # Test connectivity first
            if not self.test_connectivity():
                self.add_debug_info("❌ Connectivity test failed, aborting login")
                return False
            
            login_url = f"{self.base_url}/config/login"
            login_data = {
                "login": {
                    "username": self.username,
                    "password": self.password
                }
            }
            
            self.add_debug_info(f"🚀 Attempting login to: {login_url}")
            
            response = self.session.post(
                login_url, 
                json=login_data, 
                timeout=15
            )
            
            self.add_debug_info(f"📋 Login response status: {response.status_code}")
            
            if response.status_code == 201:
                # Check for session token in cookies
                session_token = response.cookies.get('sessionid')
                if session_token:
                    self.session_id = session_token
                    self.add_debug_info(f"✅ Login successful - Session token acquired")
                    logger.info(f"✅ Successfully logged into {self.ip}")
                    return True
                else:
                    self.add_debug_info("⚠️ Login response 201 but no session token found")
                    return False
                    
            else:
                self.add_debug_info(f"❌ Login failed - Status: {response.status_code}")
                try:
                    error_data = response.json()
                    self.add_debug_info(f"Error details: {json.dumps(error_data, indent=2)}")
                except:
                    self.add_debug_info(f"Error response text: {response.text[:200]}...")
                return False
                
        except Exception as e:
            self.add_debug_info(f"💥 Unexpected error during login: {str(e)}")
            return False
    
    def logout(self):
        """Logout from NetScaler"""
        try:
            if self.session_id:
                self.add_debug_info("🚪 Logging out")
                logout_url = f"{self.base_url}/config/logout"
                logout_data = {"logout": {}}
                response = self.session.post(logout_url, json=logout_data, timeout=5)
                self.add_debug_info(f"Logout response: {response.status_code}")
        except Exception as e:
            self.add_debug_info(f"Logout error: {str(e)}")
    
    def make_api_call(self, endpoint, method='GET'):
        """Make API call with enhanced error handling"""
        try:
            url = f"{self.base_url}/{endpoint}"
            self.add_debug_info(f"📡 Making {method} request to: {endpoint}")
            
            if method == 'GET':
                response = self.session.get(url, timeout=15)
            else:
                response = self.session.post(url, timeout=15)
                
            self.add_debug_info(f"📊 API response status: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    # Check for NITRO API error codes
                    if isinstance(data, dict) and 'errorcode' in data:
                        if data['errorcode'] == 0:
                            self.add_debug_info(f"✅ API call successful - {endpoint}")
                            return data
                        else:
                            self.add_debug_info(f"⚠️ NITRO API error: {data.get('message', 'Unknown error')}")
                            return None
                    else:
                        self.add_debug_info(f"✅ API call successful - {endpoint}")
                        return data
                except json.JSONDecodeError:
                    self.add_debug_info(f"❌ Invalid JSON response from {endpoint}")
                    return None
            elif response.status_code == 401:
                self.add_debug_info(f"🔐 Authentication required for {endpoint}")
                return None
            elif response.status_code == 403:
                self.add_debug_info(f"🚫 Access forbidden for {endpoint}")
                return None
            else:
                self.add_debug_info(f"❌ API call failed: {response.status_code} - {endpoint}")
                return None
                
        except requests.exceptions.Timeout:
            self.add_debug_info(f"⏰ Timeout for {endpoint}")
            return None
        except Exception as e:
            self.add_debug_info(f"💥 Exception in {endpoint}: {str(e)}")
            return None
    
    def get_system_stats(self):
        """Get system statistics"""
        return self.make_api_call("stat/system")
    
    def get_ns_stats(self):
        """Get NetScaler statistics"""
        return self.make_api_call("stat/ns")
    
    def get_lb_vservers(self):
        """Get Load Balancing Virtual Servers"""
        return self.make_api_call("config/lbvserver")
    
    def get_ha_status(self):
        """Get High Availability status"""
        return self.make_api_call("config/hanode")
    
    def get_services(self):
        """Get Services status"""
        return self.make_api_call("config/service")
    
    def get_version_info(self):
        """Get version and build information"""
        return self.make_api_call("config/nsversion")
    
    def get_aaa_sessions(self):
        """Get AAA user sessions"""
        return self.make_api_call("config/aaasession")
    
    def get_vpn_sessions(self):
        """Get VPN user sessions"""
        return self.make_api_call("config/vpnsession")
    
    def get_citrix_sessions(self):
        """Get Citrix workspace sessions"""
        return self.make_api_call("config/icasession")

def track_failover_event(old_roles, new_roles):
    """Track failover events"""
    try:
        current_time = datetime.now()
        
        # Check if there was an actual role change
        primary_changed = old_roles.get('primary') != new_roles.get('primary')
        secondary_changed = old_roles.get('secondary') != new_roles.get('secondary')
        
        if primary_changed or secondary_changed:
            # Determine failover type and reason
            failover_type = "Unknown"
            reason = "Role change detected"
            
            # Analyze the change
            if ('Primary' in old_roles.get('primary', '') and 'Secondary' in new_roles.get('primary', '')) or \
               ('Primary' in old_roles.get('secondary', '') and 'Secondary' in new_roles.get('secondary', '')):
                failover_type = "Automatic Failover"
                reason = "Primary node became unavailable"
            elif ('Secondary' in old_roles.get('primary', '') and 'Primary' in new_roles.get('primary', '')) or \
                 ('Secondary' in old_roles.get('secondary', '') and 'Primary' in new_roles.get('secondary', '')):
                failover_type = "Failback"
                reason = "Primary node recovered"
            elif 'Offline' in str(new_roles.values()):
                failover_type = "Node Failure"
                reason = "Node went offline"
            
            failover_event = {
                'timestamp': current_time.isoformat(),
                'type': failover_type,
                'reason': reason,
                'old_primary': old_roles.get('primary', 'Unknown'),
                'new_primary': new_roles.get('primary', 'Unknown'),
                'old_secondary': old_roles.get('secondary', 'Unknown'),
                'new_secondary': new_roles.get('secondary', 'Unknown'),
                'node1_ip': '10.0.0.100',
                'node2_ip': '10.0.0.200',
                'detection_time': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                'duration_minutes': 0  # Will be calculated later
            }
            
            # Add to failover history
            cached_data['failover_history'].append(failover_event)
            
            # Keep only last 50 events
            if len(cached_data['failover_history']) > 50:
                cached_data['failover_history'] = cached_data['failover_history'][-50:]
            
            logger.info(f"🔄 Failover event detected: {failover_type} - {reason}")
            
    except Exception as e:
        logger.error(f"Error tracking failover event: {str(e)}")

def collect_all_user_sessions():
    """Collect user sessions from all NetScaler nodes"""
    try:
        all_sessions = []
        
        # Collect from primary node
        if cached_data.get('primary', {}).get('user_sessions'):
            primary_sessions = cached_data['primary']['user_sessions']
            logger.info(f"Found {len(primary_sessions)} sessions from primary node")
            all_sessions.extend(primary_sessions)
        
        # Collect from secondary node  
        if cached_data.get('secondary', {}).get('user_sessions'):
            secondary_sessions = cached_data['secondary']['user_sessions']
            logger.info(f"Found {len(secondary_sessions)} sessions from secondary node")
            all_sessions.extend(secondary_sessions)
        
        # Remove duplicates based on session_id AND username+client_ip combination
        unique_sessions = {}
        for session in all_sessions:
            # Create unique key based on session_id, username, and client_ip
            unique_key = f"{session.get('session_id', '')}_{session.get('username', '')}_{session.get('client_ip', '')}"
            
            if unique_key not in unique_sessions:
                unique_sessions[unique_key] = session
            else:
                logger.debug(f"Skipping duplicate session: {unique_key}")
        
        # Clear old sessions and add unique ones
        cached_data['user_sessions'] = list(unique_sessions.values())
        logger.info(f"Final result: {len(cached_data['user_sessions'])} unique user sessions after deduplication")
        
    except Exception as e:
        logger.error(f"Error collecting all user sessions: {str(e)}")
        cached_data['user_sessions'] = []

def determine_ha_roles(primary_data, secondary_data):
    """Determine actual HA roles based on HA status"""
    try:
        # Store old roles for failover tracking
        old_roles = cached_data['ha_roles'].copy()
        
        # Default roles
        roles = {'primary': 'Unknown', 'secondary': 'Unknown'}
        
        # Function to check HA status from node data
        def check_node_ha_status(node_data, node_name):
            if not node_data.get('ha_status'):
                return None
                
            ha_status = node_data['ha_status']
            
            # Check if HA is configured
            if 'hanode' in ha_status and ha_status['hanode']:
                ha_nodes = ha_status['hanode']
                if isinstance(ha_nodes, list) and len(ha_nodes) > 0:
                    # Look for this node's status
                    for node in ha_nodes:
                        node_ip = node.get('ipaddress', '')
                        node_state = node.get('state', '').upper()
                        node_prop = node.get('haprop', '').upper()
                        
                        logger.info(f"HA Node found: IP={node_ip}, State={node_state}, Prop={node_prop}")
                        
                        # Determine role based on state
                        if node_state == 'PRIMARY':
                            return 'Primary (Active)'
                        elif node_state == 'SECONDARY':
                            return 'Secondary (Standby)'
                        elif node_prop == 'PRIMARY':
                            return 'Primary (Active)'
                        elif node_prop == 'SECONDARY':
                            return 'Secondary (Standby)'
            
            # Check system stats for alternative HA info
            if node_data.get('system_stats') and 'system' in node_data['system_stats']:
                system_data = node_data['system_stats']['system']
                if isinstance(system_data, list) and len(system_data) > 0:
                    sys_info = system_data[0]
                    ha_status_flag = sys_info.get('hastatus', '').upper()
                    ha_state = sys_info.get('hastate', '').upper()
                    
                    logger.info(f"System HA Info: hastatus={ha_status_flag}, hastate={ha_state}")
                    
                    if ha_state == 'PRIMARY':
                        return 'Primary (Active)'
                    elif ha_state == 'SECONDARY':
                        return 'Secondary (Standby)'
            
            return None
        
        # Check both nodes
        primary_role = check_node_ha_status(primary_data, 'primary')
        secondary_role = check_node_ha_status(secondary_data, 'secondary')
        
        # Set roles based on what we found
        if primary_role:
            roles['primary'] = primary_role
        if secondary_role:
            roles['secondary'] = secondary_role
            
        # If we couldn't determine from HA status, check which one is actually responding with full data
        if roles['primary'] == 'Unknown' and roles['secondary'] == 'Unknown':
            # Check which node has more complete system data
            primary_has_data = (primary_data.get('system_stats') and 
                              primary_data.get('ns_stats') and 
                              cached_data['connection_status'].get('primary', False))
            secondary_has_data = (secondary_data.get('system_stats') and 
                                secondary_data.get('ns_stats') and 
                                cached_data['connection_status'].get('secondary', False))
            
            if primary_has_data and secondary_has_data:
                roles['primary'] = 'Node (Active)'
                roles['secondary'] = 'Node (Standby)'
            elif primary_has_data:
                roles['primary'] = 'Active Node'
                roles['secondary'] = 'Offline'
            elif secondary_has_data:
                roles['primary'] = 'Offline'
                roles['secondary'] = 'Active Node'
        
        # Update global cache
        cached_data['ha_roles'] = roles
        
        # Track failover events
        track_failover_event(old_roles, roles)
        
        logger.info(f"HA Roles determined: Node1({NETSCALER_CONFIG['primary']['ip']})={roles['primary']}, Node2({NETSCALER_CONFIG['secondary']['ip']})={roles['secondary']}")
        
        return roles
        
    except Exception as e:
        logger.error(f"Error determining HA roles: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {'primary': 'Unknown', 'secondary': 'Unknown'}

def collect_user_sessions(node_type, api):
    """Collect user session data from NetScaler"""
    try:
        sessions_data = []
        
        # Try to get AAA sessions
        try:
            aaa_sessions = api.get_aaa_sessions()
            if aaa_sessions and 'aaasession' in aaa_sessions:
                sessions_list = aaa_sessions['aaasession']
                if not isinstance(sessions_list, list):
                    sessions_list = [sessions_list]
                
                for session in sessions_list:
                    session_info = {
                        'session_id': session.get('sessionid', f"aaa_{node_type}_{len(sessions_data)}"),
                        'username': session.get('username', 'Unknown'),
                        'connection_type': 'Web',
                        'client_ip': session.get('sourceip', session.get('clientip', 'Unknown')),
                        'start_time': session.get('starttime', datetime.now().isoformat()),
                        'duration_minutes': session.get('duration', 0),
                        'bytes_sent': session.get('txbytes', 0),
                        'bytes_received': session.get('rxbytes', 0),
                        'node_ip': api.ip,
                        'gateway': get_gateway_from_vservers(api, 'Web'),
                        'status': 'Active',
                        'user_agent': session.get('useragent', 'Web Browser'),
                        'end_time': None
                    }
                    sessions_data.append(session_info)
                    logger.info(f"Found AAA session: {session_info['username']} from {session_info['client_ip']} via {session_info['gateway']}")
        except Exception as e:
            logger.debug(f"No AAA sessions found on {node_type}: {str(e)}")
        
        # Try to get VPN sessions
        try:
            vpn_sessions = api.get_vpn_sessions()
            if vpn_sessions and 'vpnsession' in vpn_sessions:
                sessions_list = vpn_sessions['vpnsession']
                if not isinstance(sessions_list, list):
                    sessions_list = [sessions_list]
                
                for session in sessions_list:
                    session_info = {
                        'session_id': session.get('sessionid', f"vpn_{node_type}_{len(sessions_data)}"),
                        'username': session.get('username', 'Unknown'),
                        'connection_type': 'VPN',
                        'client_ip': session.get('sourceip', session.get('clientip', 'Unknown')),
                        'start_time': session.get('starttime', datetime.now().isoformat()),
                        'duration_minutes': session.get('duration', 0),
                        'bytes_sent': session.get('txbytes', 0),
                        'bytes_received': session.get('rxbytes', 0),
                        'node_ip': api.ip,
                        'gateway': get_gateway_from_vservers(api, 'VPN'),
                        'status': 'Active',
                        'user_agent': 'VPN Client',
                        'end_time': None
                    }
                    sessions_data.append(session_info)
                    logger.info(f"Found VPN session: {session_info['username']} from {session_info['client_ip']} via {session_info['gateway']}")
        except Exception as e:
            logger.debug(f"No VPN sessions found on {node_type}: {str(e)}")
        
        # Try to get Citrix sessions
        try:
            citrix_sessions = api.get_citrix_sessions()
            if citrix_sessions and 'icasession' in citrix_sessions:
                sessions_list = citrix_sessions['icasession']
                if not isinstance(sessions_list, list):
                    sessions_list = [sessions_list]
                
                for session in sessions_list:
                    session_info = {
                        'session_id': session.get('sessionid', f"ica_{node_type}_{len(sessions_data)}"),
                        'username': session.get('username', 'Unknown'),
                        'connection_type': 'Workspace',
                        'client_ip': session.get('sourceip', session.get('clientip', 'Unknown')),
                        'start_time': session.get('starttime', datetime.now().isoformat()),
                        'duration_minutes': session.get('duration', 0),
                        'bytes_sent': session.get('txbytes', 0),
                        'bytes_received': session.get('rxbytes', 0),
                        'node_ip': api.ip,
                        'gateway': get_gateway_from_vservers(api, 'Workspace'),
                        'status': 'Active',
                        'user_agent': 'Citrix Receiver',
                        'end_time': None
                    }
                    sessions_data.append(session_info)
                    logger.info(f"Found Workspace session: {session_info['username']} from {session_info['client_ip']} via {session_info['gateway']}")
        except Exception as e:
            logger.debug(f"No Workspace sessions found on {node_type}: {str(e)}")
        
        # Log the result - either real sessions or empty
        if len(sessions_data) > 0:
            logger.info(f"Collected {len(sessions_data)} real user sessions from {node_type}")
        else:
            logger.info(f"No active user sessions found on {node_type}")
        
        return sessions_data
        
    except Exception as e:
        logger.error(f"Error collecting user sessions from {node_type}: {str(e)}")
        return []

def collect_netscaler_data(node_type, config):
    """Collect data from a NetScaler node with comprehensive error handling"""
    try:
        start_time = time.time()
        logger.info(f"🚀 === Starting data collection for {node_type} ({config['protocol']}://{config['ip']}:{config['port']}) ===")
        
        api = NetScalerAPI(
            config['ip'], 
            config['username'], 
            config['password'], 
            config['port'],
            config['protocol']
        )
        
        # Initialize debug info storage
        cached_data['debug_info'][node_type] = {
            'last_attempt': datetime.now().isoformat(),
            'messages': [],
            'duration': 0,
            'apis_called': 0,
            'apis_successful': 0
        }
        
        if api.login():
            logger.info(f"✅ Successfully logged into {node_type}")
            cached_data['connection_status'][node_type] = True
            
            # Collect various statistics with individual error handling
            collected_data = {}
            api_calls = [
                ('system_stats', api.get_system_stats),
                ('ns_stats', api.get_ns_stats),
                ('lb_vservers', api.get_lb_vservers),
                ('ha_status', api.get_ha_status),
                ('services', api.get_services),
                ('version_info', api.get_version_info)
            ]
            
            successful_calls = 0
            for data_type, api_func in api_calls:
                try:
                    logger.info(f"📊 Collecting {data_type} from {node_type}...")
                    data = api_func()
                    collected_data[data_type] = data
                    if data:
                        successful_calls += 1
                        logger.info(f"✅ {data_type}: Success")
                    else:
                        logger.warning(f"⚠️ {data_type}: No data")
                except Exception as e:
                    logger.error(f"❌ {data_type}: Error - {str(e)}")
                    collected_data[data_type] = None
            
            # Collect user sessions
            try:
                user_sessions = collect_user_sessions(node_type, api)
                collected_data['user_sessions'] = user_sessions
                logger.info(f"📊 Collected {len(user_sessions)} user sessions from {node_type}")
            except Exception as e:
                logger.error(f"❌ Error collecting user sessions from {node_type}: {str(e)}")
                collected_data['user_sessions'] = []
            
            # Store collected data
            cached_data[node_type] = {
                **collected_data,
                'last_update': datetime.now().isoformat(),
                'ip': config['ip'],
                'protocol': config['protocol'],
                'port': config['port'],
                'collection_duration': time.time() - start_time,
                'successful_apis': successful_calls,
                'total_apis': len(api_calls)
            }
            
            # Store debug information
            cached_data['debug_info'][node_type]['messages'] = api.debug_info
            cached_data['debug_info'][node_type]['success'] = True
            cached_data['debug_info'][node_type]['duration'] = time.time() - start_time
            cached_data['debug_info'][node_type]['apis_called'] = len(api_calls)
            cached_data['debug_info'][node_type]['apis_successful'] = successful_calls
            
            api.logout()
            
            # Log comprehensive summary
            logger.info(f"📈 Data collection summary for {node_type}:")
            logger.info(f"  ⏱️  Duration: {time.time() - start_time:.2f}s")
            logger.info(f"  📊 Success rate: {successful_calls}/{len(api_calls)} APIs")
            for data_type, _ in api_calls:
                status = "✅" if collected_data.get(data_type) else "❌"
                logger.info(f"  {status} {data_type}")
            
            # Update global stats
            cached_data['stats_summary']['successful_calls'] += successful_calls
            cached_data['stats_summary']['total_calls'] += len(api_calls)
            
        else:
            cached_data['connection_status'][node_type] = False
            cached_data['debug_info'][node_type]['messages'] = api.debug_info
            cached_data['debug_info'][node_type]['success'] = False
            cached_data['debug_info'][node_type]['duration'] = time.time() - start_time
            logger.error(f"❌ Failed to connect to {node_type}")
            cached_data['stats_summary']['failed_calls'] += 1
            
    except Exception as e:
        cached_data['connection_status'][node_type] = False
        logger.error(f"💥 Critical error collecting data from {node_type}: {str(e)}")
        logger.error(f"📋 Traceback: {traceback.format_exc()}")
        
        if node_type not in cached_data['debug_info']:
            cached_data['debug_info'][node_type] = {}
        cached_data['debug_info'][node_type]['error'] = str(e)
        cached_data['debug_info'][node_type]['success'] = False
        cached_data['debug_info'][node_type]['traceback'] = traceback.format_exc()

def background_data_collector():
    """Background thread to collect data periodically"""
    cycle_count = 0
    while True:
        try:
            cycle_count += 1
            logger.info(f"🔄 Starting data collection cycle #{cycle_count}")
            cycle_start = time.time()
            
            # Collect data from both nodes in parallel
            threads = []
            for node_type, config in NETSCALER_CONFIG.items():
                thread = threading.Thread(
                    target=collect_netscaler_data, 
                    args=(node_type, config)
                )
                thread.start()
                threads.append(thread)
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
            
            # Determine HA roles after data collection
            determine_ha_roles(cached_data.get('primary', {}), cached_data.get('secondary', {}))
            
            # Collect all user sessions from both nodes
            collect_all_user_sessions()
            
            cycle_duration = time.time() - cycle_start
            cached_data['last_update'] = datetime.now().isoformat()
            
            # Log comprehensive cycle summary
            primary_status = "✅" if cached_data['connection_status']['primary'] else "❌"
            secondary_status = "✅" if cached_data['connection_status']['secondary'] else "❌"
            
            logger.info(f"📡 Collection cycle #{cycle_count} completed in {cycle_duration:.2f}s")
            logger.info(f"🔗 Connection status: Primary {primary_status}, Secondary {secondary_status}")
            logger.info(f"👥 Total user sessions: {len(cached_data.get('user_sessions', []))}")
            
            # Log overall statistics
            total_calls = cached_data['stats_summary']['total_calls']
            successful_calls = cached_data['stats_summary']['successful_calls']
            if total_calls > 0:
                success_rate = (successful_calls / total_calls) * 100
                logger.info(f"📊 Overall success rate: {success_rate:.1f}% ({successful_calls}/{total_calls})")
            
        except Exception as e:
            logger.error(f"💥 Error in background data collector: {str(e)}")
            logger.error(f"📋 Traceback: {traceback.format_exc()}")
        
        # Wait 30 seconds before next collection
        time.sleep(30)

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        # Check credentials
        if username == auth_config['username'] and verify_password(password, auth_config['password_hash']):
            session['logged_in'] = True
            session['username'] = username
            
            # Update last login
            auth_config['last_login'] = datetime.now().isoformat()
            auth_config['login_attempts'] = 0
            save_auth_config(auth_config)
            
            logger.info(f"✅ Successful login for user: {username}")
            
            # Check if password change is required
            if auth_config.get('is_default_password', False):
                flash('You must change your password before continuing', 'warning')
                return redirect(url_for('change_password'))
            
            return redirect(url_for('dashboard'))
        else:
            # Increment login attempts
            auth_config['login_attempts'] = auth_config.get('login_attempts', 0) + 1
            save_auth_config(auth_config)
            
            logger.warning(f"❌ Failed login attempt for user: {username}")
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout route"""
    username = session.get('username', 'Unknown')
    session.clear()
    logger.info(f"🚪 User logged out: {username}")
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password page"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([current_password, new_password, confirm_password]):
            flash('All fields are required', 'error')
            return render_template('change_password.html')
        
        # Verify current password
        if not verify_password(current_password, auth_config['password_hash']):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')
        
        # Check if new password matches confirmation
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('change_password.html')
        
        # Check password strength
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('change_password.html')
        
        # Update password
        auth_config['password_hash'] = hash_password(new_password)
        auth_config['is_default_password'] = False
        auth_config['last_password_change'] = datetime.now().isoformat()
        save_auth_config(auth_config)
        
        logger.info(f"🔐 Password changed for user: {session['username']}")
        flash('Password changed successfully', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/')
@login_required
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/debug')
@login_required
def api_debug():
    """Comprehensive debug endpoint"""
    return jsonify({
        'cached_data': cached_data,
        'config': {
            'primary_url': f"{NETSCALER_CONFIG['primary']['protocol']}://{NETSCALER_CONFIG['primary']['ip']}:{NETSCALER_CONFIG['primary']['port']}",
            'secondary_url': f"{NETSCALER_CONFIG['secondary']['protocol']}://{NETSCALER_CONFIG['secondary']['ip']}:{NETSCALER_CONFIG['secondary']['port']}"
        },
        'app_info': {
            'version': '2.1-Auth',
            'protocol': 'HTTP',
            'python_version': f"{__import__('sys').version}",
            'flask_version': f"{__import__('flask').__version__}",
            'auth_enabled': True,
            'current_user': session.get('username'),
            'is_default_password': auth_config.get('is_default_password', False)
        },
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/health')
@login_required
def api_health():
    """Health check endpoint"""
    primary_connected = cached_data['connection_status']['primary']
    secondary_connected = cached_data['connection_status']['secondary']
    
    health_status = "healthy" if primary_connected else "degraded"
    if not primary_connected and not secondary_connected:
        health_status = "unhealthy"
    
    return jsonify({
        'status': health_status,
        'primary_connected': primary_connected,
        'secondary_connected': secondary_connected,
        'last_update': cached_data.get('last_update'),
        'stats_summary': cached_data['stats_summary'],
        'timestamp': datetime.now().isoformat(),
        'authenticated': True,
        'user': session.get('username')
    })

@app.route('/api/system-stats')
@login_required
def api_system_stats():
    """API endpoint for system statistics"""
    try:
        primary_data = cached_data.get('primary', {})
        secondary_data = cached_data.get('secondary', {})
        
        response_data = {
            'primary': {
                'connected': cached_data['connection_status']['primary'],
                'ip': NETSCALER_CONFIG['primary']['ip'],
                'url': f"{NETSCALER_CONFIG['primary']['protocol']}://{NETSCALER_CONFIG['primary']['ip']}:{NETSCALER_CONFIG['primary']['port']}",
                'system': primary_data.get('system_stats', {}),
                'ns_stats': primary_data.get('ns_stats', {}),
                'last_update': primary_data.get('last_update'),
                'collection_duration': primary_data.get('collection_duration', 0),
                'debug': cached_data['debug_info'].get('primary', {}),
                'ha_role': cached_data['ha_roles'].get('primary', 'Unknown')
            },
            'secondary': {
                'connected': cached_data['connection_status']['secondary'],
                'ip': NETSCALER_CONFIG['secondary']['ip'],
                'url': f"{NETSCALER_CONFIG['secondary']['protocol']}://{NETSCALER_CONFIG['secondary']['ip']}:{NETSCALER_CONFIG['secondary']['port']}",
                'system': secondary_data.get('system_stats', {}),
                'ns_stats': secondary_data.get('ns_stats', {}),
                'last_update': secondary_data.get('last_update'),
                'collection_duration': secondary_data.get('collection_duration', 0),
                'debug': cached_data['debug_info'].get('secondary', {}),
                'ha_role': cached_data['ha_roles'].get('secondary', 'Unknown')
            },
            'collection_time': cached_data['last_update'],
            'stats_summary': cached_data['stats_summary']
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error in system stats API: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system-info')
@login_required
def api_system_info():
    """API endpoint for detailed system information"""
    try:
        primary_data = cached_data.get('primary', {})
        secondary_data = cached_data.get('secondary', {})
        
        def extract_system_info(node_data, node_name):
            """Extract system info from node data"""
            try:
                system_stats = node_data.get('system_stats', {})
                version_info = node_data.get('version_info', {})
                
                # Initialize default values
                result = {
                    'connected': cached_data['connection_status'].get(node_name.lower(), False),
                    'version': 'Unknown',
                    'buildnumber': 'Unknown',
                    'hostname': 'Unknown',
                    'mgmtip': 'Unknown',
                    'platformtype': 'Unknown',
                    'serialnumber': 'Unknown',
                    'uptime': 'Unknown',
                    'cpu_usage': 0,
                    'memory_usage': 0,
                    'disk_usage': 0,
                    'last_update': node_data.get('last_update', 'Never'),
                    'ha_role': cached_data['ha_roles'].get(node_name.lower(), 'Unknown')
                }
                
                # Extract system information
                if system_stats and 'system' in system_stats and system_stats['system']:
                    system_info = system_stats['system'][0] if isinstance(system_stats['system'], list) else system_stats['system']
                    
                    result.update({
                        'hostname': system_info.get('hostname', 'Unknown'),
                        'mgmtip': system_info.get('mgmtip', 'Unknown'),
                        'platformtype': system_info.get('platformtype', 'Unknown'),
                        'serialnumber': system_info.get('serialnumber', 'Unknown'),
                        'uptime': system_info.get('starttime', 'Unknown'),
                        'cpu_usage': float(system_info.get('cpuusagepcnt', 0)),
                        'memory_usage': float(system_info.get('memusagepcnt', 0)),
                        'disk_usage': float(system_info.get('disk0perusage', 0))
                    })
                
                # Extract version information
                if version_info and 'nsversion' in version_info and version_info['nsversion']:
                    version_data = version_info['nsversion'][0] if isinstance(version_info['nsversion'], list) else version_info['nsversion']
                    
                    result.update({
                        'version': version_data.get('version', result['version']),
                        'buildnumber': version_data.get('buildnumber', result['buildnumber'])
                    })
                
                return result
                
            except Exception as e:
                logger.error(f"Error extracting system info for {node_name}: {str(e)}")
                return {
                    'connected': False,
                    'error': f'Error extracting system info: {str(e)}'
                }
        
        # Extract info for both nodes
        primary_info = extract_system_info(primary_data, 'Primary')
        secondary_info = extract_system_info(secondary_data, 'Secondary')
        
        response_data = {
            'primary': primary_info,
            'secondary': secondary_info,
            'ha_roles': cached_data['ha_roles']
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error in system info API: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/lb-vservers')
@login_required
def api_lb_vservers():
    """API endpoint for Load Balancing Virtual Servers"""
    try:
        primary_data = cached_data.get('primary', {})
        lb_vservers = primary_data.get('lb_vservers', {})
        
        return jsonify({
            'connected': cached_data['connection_status']['primary'],
            'data': lb_vservers,
            'last_update': primary_data.get('last_update'),
            'collection_duration': primary_data.get('collection_duration', 0)
        })
        
    except Exception as e:
        logger.error(f"Error in LB vservers API: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ha-status')
@login_required
def api_ha_status():
    """API endpoint for High Availability status"""
    try:
        primary_data = cached_data.get('primary', {})
        secondary_data = cached_data.get('secondary', {})
        
        response_data = {
            'primary': {
                'connected': cached_data['connection_status']['primary'],
                'ha_status': primary_data.get('ha_status', {}),
                'ip': NETSCALER_CONFIG['primary']['ip'],
                'ha_role': cached_data['ha_roles'].get('primary', 'Unknown')
            },
            'secondary': {
                'connected': cached_data['connection_status']['secondary'],
                'ha_status': secondary_data.get('ha_status', {}),
                'ip': NETSCALER_CONFIG['secondary']['ip'],
                'ha_role': cached_data['ha_roles'].get('secondary', 'Unknown')
            },
            'ha_roles': cached_data['ha_roles']
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error in HA status API: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services')
@login_required
def api_services():
    """API endpoint for Services status"""
    try:
        primary_data = cached_data.get('primary', {})
        services = primary_data.get('services', {})
        
        return jsonify({
            'connected': cached_data['connection_status']['primary'],
            'data': services,
            'last_update': primary_data.get('last_update')
        })
        
    except Exception as e:
        logger.error(f"Error in services API: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/failover-history')
@login_required
def api_failover_history():
    """API endpoint for failover events history"""
    try:
        from_date = request.args.get('from_date')
        to_date = request.args.get('to_date')
        
        failover_events = cached_data.get('failover_history', [])
        
        # Filter by date range if provided
        if from_date and to_date:
            try:
                from_dt = datetime.fromisoformat(from_date)
                to_dt = datetime.fromisoformat(to_date)
                
                filtered_events = []
                for event in failover_events:
                    event_dt = datetime.fromisoformat(event['timestamp'])
                    if from_dt <= event_dt <= to_dt:
                        filtered_events.append(event)
                        
                failover_events = filtered_events
            except ValueError:
                pass  # Invalid date format, return all events
        
        return jsonify({
            'events': failover_events,
            'total_count': len(failover_events),
            'last_update': cached_data.get('last_update'),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in failover history API: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user-sessions')
@login_required
def api_user_sessions():
    """API endpoint for user sessions with filtering"""
    try:
        # Get filter parameters
        from_date = request.args.get('from_date')
        to_date = request.args.get('to_date')
        connection_type = request.args.get('connection_type')
        username = request.args.get('username')
        status = request.args.get('status')
        
        user_sessions = cached_data.get('user_sessions', [])
        
        # Apply filters
        filtered_sessions = []
        for session in user_sessions:
            # Date filter
            if from_date and to_date:
                try:
                    session_dt = datetime.fromisoformat(session['start_time'])
                    from_dt = datetime.fromisoformat(from_date)
                    to_dt = datetime.fromisoformat(to_date)
                    
                    if not (from_dt <= session_dt <= to_dt):
                        continue
                except ValueError:
                    continue
            
            # Connection type filter
            if connection_type and session.get('connection_type') != connection_type:
                continue
                
            # Username filter
            if username and username.lower() not in session.get('username', '').lower():
                continue
                
            # Status filter
            if status and session.get('status') != status:
                continue
            
            filtered_sessions.append(session)
        
        # Calculate statistics
        stats = {
            'total_sessions': len(filtered_sessions),
            'active_sessions': len([s for s in filtered_sessions if s.get('status') == 'Active']),
            'web_sessions': len([s for s in filtered_sessions if s.get('connection_type') == 'Web']),
            'vpn_sessions': len([s for s in filtered_sessions if s.get('connection_type') == 'VPN']),
            'workspace_sessions': len([s for s in filtered_sessions if s.get('connection_type') == 'Workspace']),
            'unique_users': len(set(s.get('username') for s in filtered_sessions)),
            'total_data_mb': sum(
                (s.get('bytes_sent', 0) + s.get('bytes_received', 0)) / (1024 * 1024) 
                for s in filtered_sessions
            )
        }
        
        return jsonify({
            'sessions': filtered_sessions[:100],  # Limit to 100 sessions for performance
            'total_count': len(filtered_sessions),
            'statistics': stats,
            'filters_applied': {
                'from_date': from_date,
                'to_date': to_date,
                'connection_type': connection_type,
                'username': username,
                'status': status
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in user sessions API: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/user-sessions')
@login_required
def api_export_user_sessions():
    """Export user sessions to CSV"""
    try:
        # Get the same filters as the regular user sessions API
        from_date = request.args.get('from_date')
        to_date = request.args.get('to_date')
        connection_type = request.args.get('connection_type')
        username = request.args.get('username')
        status = request.args.get('status')
        
        user_sessions = cached_data.get('user_sessions', [])
        
        # Apply the same filters
        filtered_sessions = []
        for session in user_sessions:
            # Date filter
            if from_date and to_date:
                try:
                    session_dt = datetime.fromisoformat(session['start_time'])
                    from_dt = datetime.fromisoformat(from_date)
                    to_dt = datetime.fromisoformat(to_date)
                    
                    if not (from_dt <= session_dt <= to_dt):
                        continue
                except ValueError:
                    continue
            
            # Connection type filter
            if connection_type and session.get('connection_type') != connection_type:
                continue
                
            # Username filter
            if username and username.lower() not in session.get('username', '').lower():
                continue
                
            # Status filter
            if status and session.get('status') != status:
                continue
            
            filtered_sessions.append(session)
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Session ID', 'Username', 'Connection Type', 'Client IP', 
            'Start Time', 'End Time', 'Duration (Minutes)', 'Status',
            'Data Sent (MB)', 'Data Received (MB)', 'Gateway', 'Node IP'
        ])
        
        # Write data
        for session in filtered_sessions:
            writer.writerow([
                session.get('session_id', ''),
                session.get('username', ''),
                session.get('connection_type', ''),
                session.get('client_ip', ''),
                session.get('start_time', ''),
                session.get('end_time', ''),
                session.get('duration_minutes', ''),
                session.get('status', ''),
                round(session.get('bytes_sent', 0) / (1024 * 1024), 2),
                round(session.get('bytes_received', 0) / (1024 * 1024), 2),
                session.get('gateway', session.get('node_ip', '')),
                session.get('node_ip', '')
            ])
        
        # Create response
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=netscaler_user_sessions_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        return response
        
    except Exception as e:
        logger.error(f"Error exporting user sessions: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/failover-history')
@login_required
def api_export_failover_history():
    """Export failover history to CSV"""
    try:
        failover_events = cached_data.get('failover_history', [])
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Timestamp', 'Event Type', 'Reason', 'Detection Time',
            'Old Primary Role', 'New Primary Role', 'Old Secondary Role', 'New Secondary Role',
            'Node 1 IP', 'Node 2 IP', 'Duration (Minutes)'
        ])
        
        # Write data
        for event in failover_events:
            writer.writerow([
                event.get('timestamp', ''),
                event.get('type', ''),
                event.get('reason', ''),
                event.get('detection_time', ''),
                event.get('old_primary', ''),
                event.get('new_primary', ''),
                event.get('old_secondary', ''),
                event.get('new_secondary', ''),
                event.get('node1_ip', ''),
                event.get('node2_ip', ''),
                event.get('duration_minutes', 0)
            ])
        
        # Create response
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=netscaler_failover_history_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        return response
        
    except Exception as e:
        logger.error(f"Error exporting failover history: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/refresh')
@login_required
def api_refresh():
    """Force refresh of data"""
    try:
        logger.info("🔄 Manual refresh triggered")
        
        # Clear existing user sessions to prevent accumulation
        cached_data['user_sessions'] = []
        logger.info("🧹 Cleared existing user sessions cache")
        
        for node_type, config in NETSCALER_CONFIG.items():
            thread = threading.Thread(
                target=collect_netscaler_data, 
                args=(node_type, config)
            )
            thread.start()
        
        return jsonify({
            'status': 'refresh_initiated',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in refresh API: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug-ha')
@login_required
def api_debug_ha():
    """Debug endpoint for HA analysis"""
    try:
        primary_data = cached_data.get('primary', {})
        secondary_data = cached_data.get('secondary', {})
        
        debug_info = {
            'timestamp': datetime.now().isoformat(),
            'connection_status': cached_data['connection_status'],
            'ha_roles': cached_data['ha_roles'],
            'primary_analysis': {
                'connected': cached_data['connection_status'].get('primary', False),
                'ip': NETSCALER_CONFIG['primary']['ip'],
                'ha_status_available': bool(primary_data.get('ha_status')),
                'ha_status_raw': primary_data.get('ha_status', {}),
                'system_stats_available': bool(primary_data.get('system_stats')),
                'system_stats_raw': primary_data.get('system_stats', {})
            },
            'secondary_analysis': {
                'connected': cached_data['connection_status'].get('secondary', False),
                'ip': NETSCALER_CONFIG['secondary']['ip'],
                'ha_status_available': bool(secondary_data.get('ha_status')),
                'ha_status_raw': secondary_data.get('ha_status', {}),
                'system_stats_available': bool(secondary_data.get('system_stats')),
                'system_stats_raw': secondary_data.get('system_stats', {})
            }
        }
        
        return jsonify(debug_info)
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@app.route('/api/test-connection/<node_type>')
@login_required
def api_test_connection(node_type):
    """Test connection to specific node"""
    if node_type not in NETSCALER_CONFIG:
        return jsonify({'error': 'Invalid node type'}), 400
    
    config = NETSCALER_CONFIG[node_type]
    
    try:
        api = NetScalerAPI(
            config['ip'], 
            config['username'], 
            config['password'], 
            config['port'],
            config['protocol']
        )
        
        # Test connectivity and login
        connectivity = api.test_connectivity()
        login_success = False
        ha_data = None
        system_data = None
        
        if connectivity:
            login_success = api.login()
            if login_success:
                # Try to get HA status
                try:
                    ha_data = api.get_ha_status()
                    system_data = api.get_system_stats()
                except Exception as e:
                    logger.error(f"Error getting HA/System data during test: {str(e)}")
                
                api.logout()
        
        return jsonify({
            'node_type': node_type,
            'ip': config['ip'],
            'port': config['port'],
            'protocol': config['protocol'],
            'connectivity': connectivity,
            'login_success': login_success,
            'ha_data': ha_data,
            'system_data': system_data,
            'debug_messages': api.debug_info,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info("🛑 Received shutdown signal. Cleaning up...")
    logger.info("✅ Cleanup completed. Exiting.")
    exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("🚀 ========================================")
    logger.info("🚀 NetScaler Enhanced Dashboard v2.1-Auth Starting")
    logger.info("🚀 ========================================")
    logger.info(f"🔐 Authentication enabled - Default user: {DEFAULT_USERNAME}")
    logger.info(f"🔐 Authentication config file: {AUTH_CONFIG_FILE}")
    logger.info(f"🔐 Password change required: {auth_config.get('is_default_password', False)}")
    logger.info(f"🌐 Primary NetScaler: http://{NETSCALER_CONFIG['primary']['ip']}:{NETSCALER_CONFIG['primary']['port']}")
    logger.info(f"🌐 Secondary NetScaler: http://{NETSCALER_CONFIG['secondary']['ip']}:{NETSCALER_CONFIG['secondary']['port']}")
    logger.info(f"📝 Log file: netscaler_complete.log")
    logger.info(f"🔧 Protocol: HTTP (NITRO API)")
    logger.info(f"⚡ Auto-refresh: Every 30 seconds")
    logger.info(f"🔄 Features: Authentication, Failover Monitoring & User Sessions")
    
    # Start background data collection thread
    logger.info("🔄 Starting background data collection thread...")
    collector_thread = threading.Thread(target=background_data_collector, daemon=True)
    collector_thread.start()
    
    # Initial data collection
    logger.info("📊 Performing initial data collection...")
    for node_type, config in NETSCALER_CONFIG.items():
        logger.info(f"🔗 Testing connection to {node_type} ({config['protocol']}://{config['ip']}:{config['port']})...")
        collect_netscaler_data(node_type, config)
    
    # Collect initial user sessions
    collect_all_user_sessions()
    
    logger.info("🌐 Starting Flask web server...")
    logger.info("📊 Dashboard available at: http://localhost:5000")
    logger.info("🔐 Login page: http://localhost:5000/login")
    logger.info("🔍 Debug info available at: http://localhost:5000/api/debug")
    logger.info("❤️ Health check available at: http://localhost:5000/api/health")
    logger.info("🔄 Failover history at: http://localhost:5000/api/failover-history")
    logger.info("👥 User sessions at: http://localhost:5000/api/user-sessions")
    logger.info("⏹️ Press Ctrl+C to stop the server")
    logger.info("========================================")
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
        signal_handler(signal.SIGINT, None)
    except Exception as e:
        logger.error(f"Failed to start Flask application: {str(e)}")
        exit(1)