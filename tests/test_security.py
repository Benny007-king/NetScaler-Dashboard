"""Security tab and Sessions: checklist detection, log-line parsing, the event
store, the syslog receiver, and the sessions built from NITRO and log lines.

    python tests/test_security.py      # needs the app's Python packages; uses a temporary directory

The NetScaler is a stand-in that answers like NITRO: one aaasession entry per
connection, no 'vpnsession' object (an error, as on a real appliance), bulk
binding answers, and audit lines in the formats the appliance writes.
"""
import json
import os
import socket
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.update(DATA_DIR=tempfile.mkdtemp(), APP_SSL="0", SYSLOG_PORT="0", SECURITY_POLL_SECS="0", TZ="UTC")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


ok_n = bad_n = 0


def check(cond, what, extra=""):
    global ok_n, bad_n
    if cond:
        ok_n += 1; print("   ok    " + what)
    else:
        bad_n += 1; print("   FAIL  " + what + (("\n         " + str(extra)[:600]) if extra else ""))


from fake_netscaler import FakeNitro, audit_lines, GW_IP, NSIP, NOW, T_LOGIN   # noqa: E402

import security          # noqa: E402

# ------------------------------------------------------------------ parsing
print("-- log lines")
lines = audit_lines()
evs = [security.parse_line(l, NOW) for l in lines]
kinds = [e["kind"] if e else None for e in evs]
check(kinds == ["login", "vpn_login", "ica_start", "vpn_login", "vpn_logout", "login_failed", "waf", "brute_force", None, None],
      "every line is read as the right kind; other lines are ignored", kinds)
check(evs[0]["fields"].get("os") == "Windows 10/11" and evs[0]["fields"].get("access type") == "Client - Citrix Workspace App"
      and evs[0]["session"] == "7f3a", "login line: OS, access type and AAA session id")
check(evs[1]["session"] == "41" and evs[1]["url"] == f"{GW_IP}:443" and evs[1]["fields"].get("sslvpn_client_type") == "ICA"
      and abs(evs[1]["ts"] - T_LOGIN) < 2, "Gateway LOGIN: session id, virtual server, client type, time (GMT)")
check(evs[2]["message"] == "Notepad++" and evs[2]["username"] == "dana" and evs[2]["client_ip"] == "198.51.100.7",
      "ICASTART: application name, user, client")
check(evs[4]["action"] == "TimedOut" and abs(float(evs[4]["fields"]["start_epoch"]) - (T_LOGIN - 7200)) < 2,
      "LOGOUT: logout method and the session's start time")
check(evs[6]["etype"] == "APPFW_SQL" and evs[6]["action"] == "blocked" and evs[6]["profile"] == "Gateway_WAF_Profile"
      and evs[6]["fields"].get("field") == "login" and evs[6]["session"] == "", "native WAF line: type, action, profile, field")
cef = security.parse_line("Oct 16 10:12:01 <local0.alert> 192.0.2.11 CEF:0|Citrix|NetScaler|NS14.1|APPFW|APPFW_SIGNATURE_MATCH|6|src=203.0.113.9 "
                          "spt=51544 method=GET request=https://gw.example.com/vpn/../vpns/cfg/smb.conf msg=Signature violation rule ID 999948: "
                          "web-misc Citrix path traversal cn1=88231 cn2=4410 cs1=Gateway_WAF_Profile cs2=PPE1 cs3=Rk9P cs4=ALERT cs5=2026 cs6=web-misc act=blocked", NOW)
check(cef and cef["etype"] == "APPFW_SIGNATURE_MATCH" and cef["fields"].get("signature_id") == "999948"
      and cef["fields"].get("method") == "GET" and cef["url"].endswith("smb.conf") and cef["action"] == "blocked",
      "CEF WAF line: signature id, method, URL, action")
check(security.parse_line(lines[6], NOW)["key"] == security.parse_line("<134> " + lines[6], NOW + 30)["key"],
      "the same line by syslog and from the audit log has the same key")
check(security.parse_line("random text", NOW) is None and security.parse_line("", NOW) is None, "junk is ignored")

# ---------------------------------------------------------------- checklist
print("-- checklist")
facts = security.collect_facts(FakeNitro(True))
check(security.ns_version(facts) == "14.1-43.56", "version read from nsversion", security.ns_version(facts))
res = {c["id"]: c for c in security.evaluate(facts, {"node_protocol": "http", "dashboard_addresses": {"192.0.2.200"}})}
st = {k: v["status"] for k, v in res.items()}
check(len(res) == len(security.security_catalog.CHECKS) == 13, "13 checklist entries", len(res))
check(st["login_audit"] == "configured", "login logging: both policies bound, user-defined logging on", res["login_audit"]["evidence"])
check(st["brute_force"] == "partial" and any("selector" in e.lower() for e in res["brute_force"]["evidence"]),
      "brute force: the selector name mismatch of the original commands is found", res["brute_force"]["evidence"])
check(st["cookie_hijack"] == "configured" and "recognised by its rule" in " ".join(res["cookie_hijack"]["evidence"]),
      "hijack policy renamed by the administrator is still recognised", res["cookie_hijack"]["evidence"])
check(st["malicious_ip"] == "partial", "IP reputation: unbound policy and disabled feature -> partial", res["malicious_ip"]["evidence"])
check(st["epa_referer"] == "missing" and st["saml_protection"] == "missing", "absent policies -> missing")
check(st["waf"] == "configured" and all(res["waf"]["scopes"].values()), "built-in WAF protection with AUTH VPN PORTAL",
      res["waf"]["evidence"])
part = {c["id"]: c for c in security.evaluate(dict(facts, aaa_param={"wafprotection": ["AUTH", "VPN"]}), {})}
check(part["waf"]["status"] == "partial" and "PORTAL" in " ".join(part["waf"]["evidence"]), "WAF without PORTAL is partial",
      part["waf"]["evidence"])
off = {c["id"]: c["status"] for c in security.evaluate(dict(facts, aaa_param={"wafprotection": "DISABLED"}), {})}
check(off["waf"] == "missing", "WAF protection DISABLED is not in place")
check(st["csp_header"] == "configured" and st["httponly"] == "configured" and st["cookie_v1"] == "configured"
      and st["tcp_isn"] == "configured", "CSP, HttpOnly, cookie v1 and enhanced ISN generation detected")
check(st["mgmt_secure"] == "configured" and any("HTTPS in Settings" in e for e in res["mgmt_secure"]["evidence"]),
      "secure-only management, with the note that the dashboard itself uses HTTP")
check(st["syslog_dashboard"] == "missing", "no syslog server pointing here -> missing")
check(res["login_audit"]["variants"][res["login_audit"]["variant"]]["label"] == "NetScaler 14.1",
      "the 14.1 commands are preselected on a 14.1 node")
cmds = "\n".join(x["text"] for v in res["brute_force"]["variants"] for x in v["commands"])
check("add stream selector Check_Failed_Logins_Selector HTTP.REQ.URL CLIENT.IP.SRC" in cmds and "\t" not in cmds,
      "brute-force commands carry the corrected selector")
hits = {h["policy"]: h["hits"] for h in security.policy_hits(list(res.values()))}
check(hits.get("Gateway_Login_Attempt_Audit_Responder_Policy") == 120 and hits.get("My_Hijack_Guard") == 2
      and hits.get("Gateway_WAF_Policy") == 44 and "unrelated" not in hits, "policy hit counters, only the checklist's policies (and WAF policies)", hits)

empty = {c["id"]: c["status"] for c in security.evaluate(security.collect_facts(FakeNitro(False)), {})}
check(empty["login_audit"] == "missing" and empty["waf"] == "partial" and empty["httponly"] == "missing"
      and empty["cookie_v1"] == "missing" and empty["tcp_isn"] == "missing" and empty["mgmt_secure"] == "missing",
      "an appliance with nothing in place", empty)
down = security.evaluate(security.collect_facts(FakeNitro(down=True)), {})
check(all(c["status"] in ("unknown", "missing") for c in down) and sum(c["status"] == "unknown" for c in down) >= 10,
      "an unreachable node: unknown, not missing", [c["status"] for c in down])

# -------------------------------------------------------------- the app
print("-- the dashboard")
import app as dash     # noqa: E402
import db              # noqa: E402

fake = FakeNitro(True)
dash.get_nitro = lambda node_key, instance_id=None: fake
cfg = dash.load_nodes_config()
cfg["instances"][0]["primary"].update(ip=NSIP, username="nsapi", password="x", protocol="http", port=80)
dash.save_nodes_config(cfg)
iid = str(dash.get_instance(None)["id"])
c = dash.app.test_client()
with c.session_transaction() as s:
    s.update(logged_in=True, user="admin", username="admin", must_change_password=False, last_activity=time.time())

r = c.get("/api/security/checklist")
j = r.get_json()
check(r.status_code == 200 and len(j["checks"]) == 13 and j["vservers"] == ["GW_VS"] and j["portal_vservers"] == ["StoreFront_LB"],
      "checklist endpoint: entries and the virtual servers for the commands", r.status_code)
r = c.post("/api/security/mark", json={"id": "epa_referer", "state": "irrelevant"})
r2 = c.post("/api/security/mark", json={"id": "saml_protection", "state": "done"})
check(r.status_code == 200 and r2.status_code == 200, "marking entries")
check(c.post("/api/security/mark", json={"id": "nope", "state": "done"}).status_code == 400
      and c.post("/api/security/mark", json={"id": "waf", "state": "hack"}).status_code == 400, "unknown entries and states are refused")
saved = json.load(open(dash.SECURITY_FILE, encoding="utf-8"))
check(saved.get(iid, {}).get("epa_referer", {}).get("state") == "irrelevant" and saved[iid]["saml_protection"]["by"] == "admin",
      "marks are saved with who set them", saved)
j = c.get("/api/security/checklist").get_json()
marks = {x["id"]: (x.get("mark") or {}).get("state") for x in j["checks"]}
check(marks["epa_referer"] == "irrelevant" and marks["saml_protection"] == "done", "marks come back with the checklist")
c.post("/api/security/mark", json={"id": "saml_protection", "state": ""})
check("saml_protection" not in json.load(open(dash.SECURITY_FILE, encoding="utf-8")).get(iid, {}), "a mark can be cleared")
docs = dash._db_documents()
check(docs["security"][1] and "epa_referer" in docs["security"][0].get(iid, {}), "marks are a settings document for the external database")
dash._db_apply_document("security", {iid: {"waf": {"state": "done"}, "bogus": {"state": "done"}, "csp_header": {"state": "x"}}, "x": "y"})
check(dash.SEC_MARKS == {iid: {"waf": {"state": "done", "by": "", "at": ""}}}, "marks from the database are checked before use", dash.SEC_MARKS)

# events: the background poll reads the audit lines; here directly
rows = [security.make_row(e, iid, NSIP) for e in (security.parse_line(l, NOW) for l in audit_lines()) if e]
n1 = db.add_security_events(rows)
n2 = db.add_security_events(rows)
check(n1 == 8 and n2 == 0, "events stored once, however often they are read", (n1, n2))
r = c.get("/api/security/activity?range=24h")
j = r.get_json()
check(r.status_code == 200 and j["kpi"]["waf"] == 1 and j["kpi"]["waf_blocked"] == 1 and j["kpi"]["brute_force"] == 1
      and j["kpi"]["login_failed"] == 1, "activity: counts per kind", j.get("kpi") if j else r.status_code)
check(any(h["policy"] == "Error_Login_Block_Responder_Policy" and h["hits"] == 7 for h in j["hits"]), "activity: policy hit counters")
check(j["summary"]["top_ips"][0]["name"] in ("203.0.113.9", "203.0.113.50", "203.0.113.66"), "activity: top addresses")
r = c.get("/api/security/events?range=24h")
ev = r.get_json()["events"]
check(r.status_code == 200 and {e["kind"] for e in ev} == {"waf", "brute_force", "login_failed"},
      "events table holds the security kinds only (sessions lines go to Sessions)", {e["kind"] for e in ev})
check(len(c.get("/api/security/events?range=24h&q=doAuthentication").get_json()["events"]) == 2, "events can be searched")
check(len(c.get("/api/security/events?range=24h&kind=waf").get_json()["events"]) == 1, "events can be filtered by kind")
check(c.get("/api/security/events?range=24h&q=%25").status_code == 200, "a search for % is harmless")

print("-- sessions")
r = c.get("/api/user-sessions")
j = r.get_json()
check(r.status_code == 200 and j["live"] is True, "sessions are read although the appliance has no 'vpnsession' object", j.get("live"))
check("/config/vpnsession" not in fake.calls, "the non-existent vpnsession object is not asked for")
rows = j["sessions"]
by = {}
for x in rows:
    by.setdefault((x["user"], x["status"]), []).append(x)
dana = by.get(("dana", "Active"), [])
check(len(dana) == 1, "one row for dana, whose two connections are listed separately by NITRO", [x["user"] + "/" + x["status"] for x in rows])
if dana:
    d = dana[0]
    dd = d["detail"]
    check(d["gateway"] == "GW_VS" and dd.get("gateway_address") == f"{GW_IP}:443", "gateway named from the virtual server address", (d["gateway"], dd.get("gateway_address")))
    check(dd.get("connections") == 2 and dd.get("groups") == "VPN-Users", "connections and group")
    check(dd.get("client_os") == "Windows 10/11" and dd.get("access_type") == "Client - Citrix Workspace App"
          and dd.get("gateway_fqdn") == "gw.example.com" and dd.get("aaa_session_id") == "7f3a",
          "OS, access type, Gateway FQDN and AAA session id from the login line", dd)
    check(dd.get("gateway_session_id") == "41" and dd.get("client_type") == "ICA" and d["type"].startswith("Web / Workspace"),
          "Gateway session id and client type from the LOGIN line", (dd.get("gateway_session_id"), d["type"]))
    apps = dd.get("applications") or []
    check(apps and apps[0]["app"] == "Notepad++" and apps[0]["server"] == "VDA-01" and dd.get("resource") == "Notepad++",
          "published application and its server from ICASTART", apps)
    check(dd.get("ica_live") and dd["ica_live"][0]["server"] == "VDA-01" and dd["ica_live"][0]["protocol"] == "ICA (TCP)",
          "live ICA connection with the server's name", dd.get("ica_live"))
    start = dash.parse_dmy(d["start"])
    check(abs(start - (T_LOGIN - 5)) < 3, "start time is the real login time, not when the dashboard first saw it", (d["start"], T_LOGIN))
    check(d["end"] == "Active" and d["duration"].startswith("30 min"), "end 'Active' and the duration since login", (d["end"], d["duration"]))
noa = by.get(("noa", "Active"), [])
check(noa and noa[0]["type"] == "VPN (Full Tunnel)" and noa[0]["detail"]["intranet_ip"] == "172.16.5.5", "full-tunnel VPN user with intranet IP")
oren = by.get(("oren", "Terminated"), [])
check(oren and oren[0]["type"] == "Clientless VPN" and oren[0]["detail"].get("logout_method") == "TimedOut"
      and abs(dash.parse_dmy(oren[0]["end"]) - (T_LOGIN - 3600)) < 3 and oren[0]["duration"] == "1 h 0 min"
      and oren[0]["detail"].get("bytes_sent") == "1000", "an ended session known only from its LOGIN/LOGOUT lines", oren)
fails = by.get(("mallory", "Failed"), [])
check(fails and fails[0]["ip"] == "203.0.113.66" and fails[0]["end"] == "", "failed login from the log: user, address, no end time", fails)
check(by.get(("eve", "Locked")), "locked AAA user")
check(not any(x["user"] in ("nsroot", "dashboardsvc") for x in rows), "management accounts never appear")
check(len({(x["user"], x["status"], x["start"]) for x in rows}) == len(rows), "no duplicate rows", [(x["user"], x["status"], x["start"]) for x in rows])
r = c.get("/api/user-sessions")
check(len(r.get_json()["sessions"]) == len(rows), "polling again does not add rows")
fake.down = True
dash._node_backoff.clear()
r = c.get("/api/user-sessions")
j = r.get_json()
check(r.status_code == 200 and j["live"] is False and any(x["user"] == "dana" for x in j["sessions"]),
      "appliance down: the history is still shown", j.get("live"))
fake.down = False
ica = c.get("/api/session-ica?user=DANA").get_json()["connections"]
check(len(ica) == 1 and ica[0]["server"] == "VDA-01", "live ICA detail for one user (case does not matter)", ica)

print("-- syslog receiver")
sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sk.bind(("127.0.0.1", 0))
port = sk.getsockname()[1]
sk.close()
security.SYSLOG_PORT = security.receiver.port = port
stored = []
security.ingest.start(lambda batch: stored.extend(batch))
security.ingest.store = lambda batch: stored.extend(batch)
security.start_receiver(lambda ip: iid if ip == "127.0.0.1" else None)
check(security.receiver.listening == {"udp": True, "tcp": True}, "listening on UDP and TCP", security.receiver.status())
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.sendto(("<134> " + audit_lines()[6]).encode(), ("127.0.0.1", port))
u.sendto(b"<134> not a security line", ("127.0.0.1", port))
u.close()
t = socket.create_connection(("127.0.0.1", port))
line = ("<134> " + audit_lines()[7]).encode()
t.sendall(b"%d %s" % (len(line), line) + ("<134> " + audit_lines()[5] + "\n").encode())
t.close()
for _ in range(50):
    if len(stored) >= 3:
        break
    time.sleep(0.1)
st = security.receiver.status()
check(len(stored) == 3 and {r["kind"] for r in stored} == {"waf", "brute_force", "login_failed"}, "UDP and TCP (both framings) lines stored",
      [r["kind"] for r in stored])
check(st["not_security"] == 1 and st["senders"].get("127.0.0.1", {}).get("count") == 4, "other lines are counted, not stored", st)
security.receiver.resolve = lambda ip: None
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.sendto(("<134> " + audit_lines()[6]).encode(), ("127.0.0.1", port))
u.close()
time.sleep(0.5)
check(len(stored) == 3 and security.receiver.status()["rejected"][0]["sender"] == "127.0.0.1",
      "a sender that is not a configured node is refused and listed")

print("-- storage housekeeping")
old = [dict(r, ev_key="old%d" % i, ts_epoch=NOW - 30 * 86400) for i, r in enumerate(rows[:1] if False else [security.make_row(evs[6], iid, NSIP)])]
db.add_security_events(old)
res = db.purge(7)
check(res["security_removed"] >= 1, "retention removes old security events", res)
many = [dict(security.make_row(evs[6], iid, NSIP), ev_key="bulk%d" % i, ts_epoch=NOW - i) for i in range(1500)]
db.add_security_events(many)
removed = db._trim_security(db._local, 1000)
left = db._run(db._counts)["security_events"]
check(removed > 0 and left <= 1000, "beyond the cap the oldest events are removed", (removed, left))

print("\npassed %d, failed %d" % (ok_n, bad_n))
sys.exit(1 if bad_n else 0)
