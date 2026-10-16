"""A stand-in NetScaler Gateway for tests and demos.

It answers like NITRO (one aaasession entry per connection, an error for objects
that do not exist, bulk binding answers) and writes audit lines in the formats a
NetScaler uses. Used in-process by tests/test_security.py, or on its own:

    python tests/fake_netscaler.py 8099 [dashboard-host:514]

serves NITRO on port 8099 and, with a dashboard address, sends it syslog: a burst
of history, then a new event every few seconds. All addresses are documentation
ranges (RFC 5737).
"""
import json
import random
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

GW_IP, NSIP, VDA = "192.0.2.80", "192.0.2.11", "192.0.2.150"
NOW = time.time()
T_LOGIN = NOW - 1800


def stamp(ts):
    return time.strftime("%m/%d/%Y:%H:%M:%S GMT", time.gmtime(ts))


def audit_lines(t=None):
    t = T_LOGIN if t is None else t
    return [
        f'{stamp(t - 5)} ns-gw01 0-PPE-1 : default RESPONDER Message 5601 0 :  "ICA Gateway Login SUCCESS | Client IP: 198.51.100.7 | User: dana | Session ID: 7f3a | OS: Windows 10/11 | Access Type: Client - Citrix Workspace App | Gateway FQDN: gw.example.com | User-Agent: CitrixReceiver/24.2 Windows | Timestamp: x | Note: y"',
        f'{stamp(t)} ns-gw01 0-PPE-1 : default SSLVPN LOGIN 5602 0 : Context dana@198.51.100.7 - SessionId: 41 - User dana - Client_ip 198.51.100.7 - Nat_ip "Mapped Ip" - Vserver {GW_IP}:443 - Browser_type "CitrixReceiver/24.2 Windows" - SSLVPN_client_type ICA - Group(s) "VPN-Users"',
        f'{stamp(t + 300)} ns-gw01 0-PPE-1 : default SSLVPN ICASTART 5610 0 : Source 198.51.100.7:50123 - Destination {VDA}:2598 - customername  - username:domainname dana:CORP - startTime "{stamp(t + 300)}" - applicationName "Notepad++"',
        f'{stamp(t - 7200)} ns-gw01 0-PPE-0 : default SSLVPN LOGIN 5500 0 : Context oren@198.51.100.9 - SessionId: 30 - User oren - Client_ip 198.51.100.9 - Nat_ip "Mapped Ip" - Vserver {GW_IP}:443 - Browser_type "Mozilla/5.0" - SSLVPN_client_type CVPN - Group(s) "N/A"',
        f'{stamp(t - 3600)} ns-gw01 0-PPE-0 : default SSLVPN LOGOUT 5501 0 : Context oren@198.51.100.9 - SessionId: 30 - User oren - Client_ip 198.51.100.9 - Nat_ip "Mapped Ip" - Vserver {GW_IP}:443 - Start_time "{stamp(t - 7200)}" - End_time "{stamp(t - 3600)}" - Duration 01:00:00 - Http_resources_accessed 3 - Total_TCP_connections 9 - Total_bytes_send 1000 - Total_bytes_recv 2000 - LogoutMethod "TimedOut" - Group(s) "N/A"',
        f'{stamp(t - 60)} ns-gw01 0-PPE-0 : default AAA LOGIN_FAILED 5630 0 : User mallory - Client_ip 203.0.113.66 - Failure_reason "Invalid credentials" - Browser "curl/8.0"',
        f'{stamp(t + 10)} ns-gw01 0-PPE-0 : default APPFW APPFW_SQL 5700 0 :  203.0.113.9 3112-PPE0 - Gateway_WAF_Profile https://gw.example.com/nf/auth/doAuthentication.do SQL Keyword check failed for field login="x\' or 1=1"(line 1) <blocked>',
        f'{stamp(t + 20)} ns-gw01 0-PPE-0 : default RESPONDER Message 5701 0 :  "Max login attempts detected from 203.0.113.50 to gw.example.com /nf/auth/doAuthentication.do Possible brute force login attack, The client IP address will be blocked for 10 minutes."',
        f'{stamp(t + 30)} ns-gw01 0-PPE-0 : default TCP CONN_DELINK 5702 0 : nothing to see',
        f'{stamp(t + 40)} ns-gw01 0-PPE-0 : default UI CMD_EXECUTED 5703 0 : User nsroot - Remote_ip 192.0.2.5 - Command "show ns ip" - Status "Success"',
    ]


class FakeNitro:
    """`configured`: the checklist's policies are there (one renamed, one unbound)."""

    def __init__(self, configured=True, down=False):
        self.configured, self.down, self.calls = configured, down, []
        self.extra_hits = 0
        self.lic_mode, self.lic_days, self.grace, self.grace_hours = "LAS (Fixed Bandwidth)", 21, 0, 0

    def _get(self, path, custom_timeout=None):
        self.calls.append(path)
        if self.down:
            raise requests.ConnectionError("node down")
        name = self.resource(path)
        data = self.data()
        if name not in data:
            r = requests.Response()
            r.status_code = 404
            raise requests.HTTPError("404 Client Error: Not Found (errorcode 344, no such resource)", response=r)
        return {"errorcode": 0, "message": "Done", name: data[name]}

    @staticmethod
    def resource(path):
        """/config/<resource>[/<name>] -> <resource>"""
        parts = path.split("?")[0].strip("/").split("/")
        return parts[1] if len(parts) >= 2 and parts[0] in ("config", "stat") else parts[-1]

    def data(self):
        c, x = self.configured, self.extra_hits
        responders = [
            {"name": "Gateway_Login_Attempt_Audit_Responder_Policy", "rule": 'HTTP.REQ.METHOD.EQ("POST") && HTTP.REQ.URL.PATH.CONTAINS("doAuthentication.do")',
             "action": "NOOP", "logaction": "Gateway_Login_Attempt_Audit_Message_Action", "hits": str(120 + 3 * x), "undefhits": "0"},
            {"name": "ICA_Gateway_Login_Audit_Responder_Policy", "rule": 'HTTP.REQ.METHOD.EQ("POST") && HTTP.REQ.URL.PATH.CONTAINS("GetUserName")',
             "action": "NOOP", "logaction": "ICA_Gateway_Login_Audit_Message_Action", "hits": str(80 + 2 * x), "undefhits": "0"},
            {"name": "Error_Login_Block_Responder_Policy", "rule": '(HTTP.REQ.URL.EQ("/nf/auth/doAuthentication.do")) && SYS.CHECK_LIMIT("Check_Failed_Logins_Limit_Identifier")',
             "action": "DROP", "logaction": "Possible_Brute_Force_Login_Attack_Message_Action", "hits": str(7 + x // 3)},
            {"name": "My_Hijack_Guard", "rule": "AAA.USER.NAME.LENGTH.NE(0) && AAA.USER.SOURCEIP.NE(CLIENT.IP.SRC)", "action": "RESET", "hits": str(2 + x // 10)},
            {"name": "Drop_Malicious_IP", "rule": "CLIENT.IP.SRC.IPREP_IS_MALICIOUS", "action": "DROP", "hits": "0"},
            {"name": "unrelated", "rule": "true", "action": "NOOP", "hits": "5"},
        ] if c else [{"name": "unrelated", "rule": "true", "action": "NOOP", "hits": "5"}]
        bind = [{"name": n, "responderpolicy_vpnvserver_binding": [{"name": n, "boundto": "GW_VS", "priority": p, "activepolicy": "1"}]}
                for n, p in (("Gateway_Login_Attempt_Audit_Responder_Policy", 110), ("ICA_Gateway_Login_Audit_Responder_Policy", 120),
                             ("Error_Login_Block_Responder_Policy", 130), ("My_Hijack_Guard", 140))] if c else []
        return {
            "nsversion": {"version": "NetScaler NS14.1: Build 43.56.nc, Date: Jun 1 2026"},
            "nsfeature": {"rep": False, "appfw": True, "responder": True, "rewrite": True},
            "responderpolicy": responders,
            "responderpolicy_binding": bind,
            "appfwpolicy": [{"name": "Gateway_WAF_Policy", "rule": "true", "profilename": "Gateway_WAF_Profile", "hits": str(44 + 5 * x)}] if c else [],
            "appfwpolicy_binding": [{"name": "Gateway_WAF_Policy", "appfwpolicy_vpnvserver_binding": [{"boundto": "GW_VS", "priority": 100}]}] if c else [],
            "appfwsettings": {"ceflogging": "OFF"},
            "rewriteaction": [{"name": "Gateway_CSP_Header_Action", "type": "insert_http_header", "target": "Content-Security-Policy",
                               "stringbuilderexpr": "\"default-src 'self'\""}] if c else [],
            "rewritepolicy": [{"name": "Gateway_CSP_Header_Policy", "rule": "true", "action": "Gateway_CSP_Header_Action", "hits": str(900 + 40 * x)}] if c else [],
            "rewritepolicy_binding": [{"name": "Gateway_CSP_Header_Policy", "rewritepolicy_vpnvserver_binding": [{"boundto": "GW_VS"}]}] if c else [],
            "auditmessageaction": [{"name": "Gateway_Login_Attempt_Audit_Message_Action"}, {"name": "ICA_Gateway_Login_Audit_Message_Action"}] if c else [],
            "auditsyslogparams": {"userdefinedauditlog": "YES" if c else "NO"},
            "auditsyslogaction": [],
            "auditsyslogglobal_auditsyslogpolicy_binding": [],
            "auditsyslogpolicy": [],
            "nslimitidentifier": [{"limitidentifier": "Check_Failed_Logins_Limit_Identifier", "threshold": "10", "timeslice": "600000",
                                   "selectorname": "Check_Failed_Logins_Selector", "hits": "30", "drop": "7"}] if c else [],
            "streamselector": [{"name": "Check_Failed_Logins_Selector_Policy"}] if c else [],
            "aaaparameter": {"httponlycookie": "ENABLED" if c else "DISABLED", "enableenhancedauthfeedback": "NO" if c else "YES",
                             "wafprotection": ["AUTH", "VPN", "PORTAL"] if c else ["DEFAULT"], "defaultcspheader": "DISABLED"},
            "nsparam": {"cookieversion": "1" if c else "0"},
            "nstcpparam": {"ws": "ENABLED", "enhancedisngeneration": "ENABLED" if c else "DISABLED"},
            "nsip": [{"ipaddress": NSIP, "type": "NSIP", "gui": "SECUREONLY" if c else "ENABLED",
                      "restrictaccess": "ENABLED" if c else "DISABLED", "telnet": "DISABLED", "ftp": "DISABLED" if c else "ENABLED"}],
            "sslvserver": [{"vservername": "GW_VS", "ssl3": "DISABLED", "tls1": "DISABLED" if c else "ENABLED",
                            "tls11": "DISABLED" if c else "ENABLED", "tls12": "ENABLED", "tls13": "ENABLED" if c else "DISABLED",
                            "hsts": "DISABLED", "sslprofile": "Gateway_SSL" if c else ""}],
            "sslprofile": [{"name": "Gateway_SSL", "ssl3": "DISABLED", "tls1": "DISABLED", "tls11": "DISABLED", "tls12": "ENABLED",
                            "tls13": "ENABLED", "hsts": "ENABLED", "maxage": 31536000}] if c else [],
            "sslparameter": {"denysslreneg": "NONSECURE" if c else "NO", "defaultprofile": "DISABLED"},
            "nshttpprofile": [{"name": "nshttp_default_profile", "dropinvalreqs": "ENABLED" if c else "DISABLED",
                               "markhttp09inval": "ENABLED" if c else "DISABLED", "markconnreqinval": "DISABLED"}],
            "systemparameter": {"strongpassword": "enableall" if c else "disabled", "minpasswordlen": 8 if c else 4,
                                "forcepasswordchange": "ENABLED" if c else "DISABLED"},
            "ntpserver": [{"serverip": "192.0.2.123"}] if c else [],
            "ntpsync": {"state": "ENABLED" if c else "DISABLED"},
            "vpnvserver": [{"name": "GW_VS", "ipv46": GW_IP, "port": 443}],
            "authenticationvserver": [{"name": "AAA_VS", "ipv46": "0.0.0.0", "port": 0}],
            "csvserver": [],
            "lbvserver": [{"name": "StoreFront_LB", "ipv46": "192.0.2.90", "port": 443, "servicetype": "SSL"}],
            "server": [{"name": "VDA-01", "ipaddress": VDA}],
            "aaasession": [
                {"username": "dana", "groupname": "VPN-Users", "publicip": "198.51.100.7", "publicport": 50100,
                 "ipaddress": GW_IP, "port": 443, "destip": "192.0.2.90", "destport": 443, "intranetip": "0.0.0.0"},
                {"username": "dana", "groupname": "VPN-Users", "publicip": "198.51.100.7", "publicport": 50101,
                 "ipaddress": GW_IP, "port": 443, "destip": "192.0.2.90", "destport": 443},
                {"username": "noa", "publicip": "198.51.100.12", "ipaddress": GW_IP, "port": 443, "intranetip": "172.16.5.5"},
            ],
            "vpnicaconnection": [{"username": "dana", "domain": "CORP", "srcip": "198.51.100.7", "srcport": 50123,
                                  "destip": VDA, "destport": 2598, "transproto": "TCP"}],
            "auditmessages": [{"value": v} for v in audit_lines()],
            "systemuser": [{"username": "nsroot"}, {"username": "dashboardsvc"}],
            "aaauser": [{"username": "eve", "locked": "true"}],
            "nshostname": [{"hostname": "ns-gw01"}],
            "hanode": [],
            "ns": {"cpuusagepcnt": 12.5, "memusagepcnt": 40.1, "httptotrequests": 1000},
            # LAS, fixed bandwidth, 21 days to go
            "nslicense": {"isplatinumlic": True, "isenterpriselic": False, "isstandardlic": False, "modelid": 1000,
                          "licensingmode": self.lic_mode, "daystoexpiration": self.lic_days, "daystolasenforcement": 0,
                          "f_sslvpn_users": 5000},
            "nscapacity": {"bandwidth": 1000, "unit": "Mbps", "edition": "Platinum", "actualbandwidth": 1000,
                           "daystoexpiration": self.lic_days, "vcpu": False},
            "nslicenseserver": [{"servername": "console.example.com", "status": 1, "grace": self.grace,
                                 "gptimeleft": self.grace_hours, "type": "ADM"}] if self.lic_mode != "Local" else [],
        }


SDX_IP = "192.0.2.40"


class FakeSdx:
    """An SDX Management Service (NITRO v2): the platform, its VPX instances, sensors."""

    def __init__(self, down=False, vpx_ip=NSIP):
        self.down, self.calls = down, []
        self.psu_ok, self.vpx_ip = False, vpx_ip

    def _get(self, path, custom_timeout=None):
        self.calls.append(path)
        if self.down:
            raise requests.ConnectionError("management service down")
        name = path.split("?")[0].strip("/").split("/")[1]
        data = self.data()
        if name not in data:
            r = requests.Response()
            r.status_code = 404
            raise requests.HTTPError("404 Client Error: Not Found", response=r)
        return {"errorcode": 0, "message": "Done", name: data[name]}

    def data(self):
        return {
            "mps": [{"hostname": "sdx-dc1", "platform": "NetScaler SDX 15000", "serial": "SN123456", "product": "SDX",
                     "product_version": "14.1", "build_number_short": "43.50", "bios_version": "1.2",
                     "uptime": "42 days, 3:10", "hypervisor_uptime": "42 days, 3:12"}],
            "mps_health": [{"cpu_usage": "7.5", "memory_usage": "38.2", "disk_usage": "21"}],
            "ns": [
                # added to the dashboard: the NetScaler of tests/test_security.py
                {"name": "vpx-gw01", "ip_address": self.vpx_ip, "vm_state": "Running", "instance_state": "Up", "status": "Success",
                 "version": "NetScaler NS14.1: Build 43.56.nc", "ns_cpu_usage": "12", "ns_memory_usage": "40",
                 "throughput": "1000", "ns_rx": "120", "ns_tx": "340", "cpu_core_pe": "2", "vm_memory_total": "4096",
                 "uptime": "10 days", "instance_mode": "Standalone"},
                {"name": "vpx-lb02", "ip_address": "192.0.2.42", "vm_state": "Halted", "instance_state": "Down",
                 "status": "Failed", "reason": "VM halted by admin", "throughput": "500", "cpu_core_pe": "1",
                 "vm_memory_total": "2048"},
            ],
            "xen_health_resource_hw": [
                {"name": "Power Supply 1", "current_value": "OK", "expected_value": "OK", "status": "OK"},
                {"name": "Power Supply 2", "current_value": "OK" if self.psu_ok else "Failed", "expected_value": "OK",
                 "status": "OK" if self.psu_ok else "ERROR", "number_of_failures": 0 if self.psu_ok else 3},
            ],
            "xen_health_monitor": [{"name": "CPU 1 Temp", "current_value": "52", "unit": "degrees C", "status": "OK"},
                                   {"name": "Fan 1", "current_value": "8400", "unit": "RPM", "status": "OK"}],
            "xen_health_interface": [{"port": "10/1", "display_name": "10G 1", "state": "UP", "rx_errors": 0, "tx_errors": 0,
                                      "vf_assigned": 2, "vf_total": 40},
                                     {"port": "10/2", "state": "DOWN", "rx_errors": 4, "tx_errors": 0, "vf_assigned": 0, "vf_total": 40}],
            "sdx_license": [{"platform": "SDX 15000-50G", "max_throughput": "50000", "available_throughput": "48500",
                             "max_number_of_ns_instances": "25", "available_number_of_ns_instances": "23",
                             "license_server_name": "", "is_pooled_license": "false"}],
            "license_expiry_info": [{"feature": "Platform", "expirydays": "12", "expirycount": "1"},
                                    {"feature": "SSL", "expirydays": "400", "expirycount": "1"}],
        }


# ------------------------------------------------------------- stand-alone
_ATTACKS = [
    ("APPFW_SQL", "/nf/auth/doAuthentication.do", 'SQL Keyword check failed for field login="admin\' or 1=1--"', "blocked"),
    ("APPFW_XSS", "/logon/LogonPoint/index.html", "Cross-site script check failed for field q=\"<script>\"", "blocked"),
    ("APPFW_STARTURL", "/vpns/cfg/smb.conf", "Disallow Illegal URL.", "blocked"),
    ("APPFW_BUFFEROVERFLOW_URL", "/vpn/index.html", "URL length (9000) is greater than maximum allowed (1024).", "not blocked"),
    ("APPFW_SIGNATURE_MATCH", "/vpn/../vpns/portal/scripts/newbm.pl", "Signature violation rule ID 999948: web-misc Citrix path traversal", "blocked"),
]
_SOURCES = ["203.0.113.9", "203.0.113.17", "203.0.113.50", "198.51.100.200", "203.0.113.66"]


def _event_line(seq, t):
    kind = random.random()
    ip = random.choice(_SOURCES)
    if kind < 0.6:
        etype, path, msg, act = random.choice(_ATTACKS)
        if random.random() < 0.4:
            return (time.strftime("%b %d %H:%M:%S", time.gmtime(t)) + f" <local0.info> {NSIP} "
                    f"CEF:0|Citrix|NetScaler|NS14.1|APPFW|{etype}|6|src={ip} spt={random.randint(20000, 60000)} method="
                    f"{random.choice(['GET', 'POST'])} request=https://gw.example.com{path} msg={msg} cn1={seq} cn2={seq * 7} "
                    f"cs1=Gateway_WAF_Profile cs2=PPE0 cs3=- cs4=ALERT cs5=2026 cs6=web-misc act={act}")
        return (f"{stamp(t)} ns-gw01 0-PPE-0 : default APPFW {etype} {seq} 0 :  {ip} {seq}-PPE0 - Gateway_WAF_Profile "
                f"https://gw.example.com{path} {msg} <{act}>")
    if kind < 0.75:
        return (f'{stamp(t)} ns-gw01 0-PPE-0 : default RESPONDER Message {seq} 0 :  "Max login attempts detected from {ip} to '
                f'gw.example.com /nf/auth/doAuthentication.do Possible brute force login attack, The client IP address will be blocked for 10 minutes."')
    if kind < 0.85:
        return (f'{stamp(t)} ns-gw01 0-PPE-0 : default RESPONDER Message {seq} 0 :  "Session cookie invalid detected from {ip} to '
                f'gw.example.com /vpn/index.html Possible session cookie hijack attack, the client get session reset."')
    return (f'{stamp(t)} ns-gw01 0-PPE-0 : default AAA LOGIN_FAILED {seq} 0 : User {random.choice(["admin", "test", "mallory"])} '
            f'- Client_ip {ip} - Failure_reason "Invalid credentials" - Browser "python-requests/2.31"')


def _sender(target, fake):
    host, _, port = target.partition(":")
    port = int(port or 514)
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send = lambda line: sk.sendto(("<134> " + line).encode(), (host, port))
    time.sleep(3)
    for line in audit_lines():
        send(line)
    seq = 10000
    for i in range(120):                       # a day of history, a few an hour
        seq += 1
        send(_event_line(seq, NOW - 86400 + i * 700))
    while True:
        time.sleep(random.uniform(2, 6))
        seq += 1
        fake.extra_hits += 1
        send(_event_line(seq, time.time()))


def serve(port, syslog_target=None):
    """NITRO v1 (a NetScaler) and NITRO v2 (an SDX Management Service) on one port.
    FAKE_VPX_IP: the address the SDX lists for its first VPX (this stand-in's own)."""
    import os
    fake = FakeNitro(True)
    sdx = FakeSdx(vpx_ip=os.getenv("FAKE_VPX_IP", NSIP))

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path.startswith("/nitro/v2/"):
                try:
                    return self._send(sdx._get(self.path[len("/nitro/v2"):]))
                except requests.HTTPError:
                    return self._send({"errorcode": 404, "message": "Resource not found"}, 404)
            if not self.path.startswith("/nitro/v1/"):
                return self._send({"error": "not found"}, 404)
            try:
                self._send(fake._get(self.path[len("/nitro/v1"):]))
            except requests.HTTPError:
                self._send({"errorcode": 344, "message": "No such resource", "severity": "ERROR"}, 404)

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self._send({"errorcode": 0, "message": "Done"}, 201)

    if syslog_target:
        threading.Thread(target=_sender, args=(syslog_target, fake), daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8099, sys.argv[2] if len(sys.argv) > 2 else None)
