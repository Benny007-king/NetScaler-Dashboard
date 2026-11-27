"""The security review and the TLS test API, against the stand-in NetScaler.

    python tests/test_posture.py

Checks: the applications read from NITRO (Gateway, content switching, load
balancing; non-addressable servers left out), the findings each rule makes, the
CLI that fixes them, scores and grades, exposure and accepted-risk marks (saved,
and copied to the external database as their own document), the hardening
checklist folded in without counting an item twice, and the TLS test: only a
virtual server of this appliance can be tested, it runs in the background and
its result carries the commands for that virtual server.
"""
import datetime
import os
import socket
import ssl
import sys
import tempfile
import threading
import time

os.environ.update(DATA_DIR=tempfile.mkdtemp(), APP_SSL="0", SYSLOG_PORT="0", SECURITY_POLL_SECS="0", HA_POLL_SECS="0")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.dirname(HERE), HERE]
from fake_netscaler import FakeNitro, NSIP  # noqa: E402
from posture import netscaler as ns, review  # noqa: E402

bad = 0


def check(cond, what, extra=None):
    global bad
    print(("ok   " if cond else "FAIL ") + what + ("" if cond or extra is None else f"  -> {extra}"))
    bad += not cond


# ------------------------------------------------------------------ the adapter and the rules
fake = FakeNitro(True)
data = ns.read(fake)
check(not data["errors"], "every source read (a missing bot feature is not an error)", data["errors"])
apps = {a["name"]: a for a in ns.build_apps(data)}
check(set(apps) == {"GW_VS", "CS_Web", "StoreFront_LB", "Exchange_OWA_LB", "Intranet_HTTP_LB"},
      "applications: Gateway, CS and three LBs; the AAA server without an address is left out", sorted(apps))
check(apps["GW_VS"]["exposure"] == "internet" and apps["StoreFront_LB"]["exposure"] == "internal",
      "exposure guessed: the Gateway faces the internet, a private address does not")
sf = apps["StoreFront_LB"]
check(sf["tls"]["protocols"]["SSL 3.0"] and sf["tls"]["certs"][0]["key_bits"] == 1024 and sf["tls"]["certs"][0]["self_signed"],
      "StoreFront: SSL 3.0 on, its certificate (1024-bit, self-signed) read through the binding")
check(apps["GW_VS"]["tls"]["profile"] == "Gateway_SSL" and apps["GW_VS"]["tls"]["hsts"] is True,
      "Gateway: the SSL profile's settings apply, not the virtual server's")
check(apps["Exchange_OWA_LB"]["waf"] == ["OWA_WAF_Policy"], "OWA: the WAF policy bound to it is found")
check(apps["CS_Web"]["waf_partial"] == ["StoreFront_LB"] and apps["CS_Web"]["behind"] == ["Exchange_OWA_LB", "StoreFront_LB"],
      "CS: the servers behind it read; WAF on only one of them", (apps["CS_Web"].get("waf_partial"), apps["CS_Web"].get("behind")))
check(apps["Intranet_HTTP_LB"]["tls"] is None and apps["Intranet_HTTP_LB"]["backend"] == {"total": 1, "up": 0, "plain": 1},
      "plain HTTP LB: no TLS, its back end read")

rules = {n: {f["rule"]: f for f in review.review_app(a)} for n, a in apps.items()}
check({"tls.ssl3", "tls.old", "tls.weak_ciphers", "cert.expiring", "cert.weak_key", "cert.weak_sig", "cert.self_signed",
       "web.no_waf"} <= set(rules["StoreFront_LB"]), "StoreFront: SSL 3.0, old TLS, weak ciphers, certificate problems, no WAF",
      sorted(rules["StoreFront_LB"]))
check(rules["StoreFront_LB"]["tls.ssl3"]["severity"] == "critical" and rules["StoreFront_LB"]["tls.old"]["severity"] == "medium",
      "severities: SSL 3.0 critical; old TLS medium on an internal server")
check("cert.expired" in rules["CS_Web"] and rules["CS_Web"]["cert.expired"]["severity"] == "critical", "CS: expired certificate is critical")
check("http.cleartext" in rules["Intranet_HTTP_LB"] and "avail.down" in rules["Intranet_HTTP_LB"], "HTTP LB: clear text and DOWN")
check("tls.ssl3" not in rules["GW_VS"] and "tls.hsts" not in rules["GW_VS"], "Gateway: TLS 1.2/1.3 and HSTS from its profile - no finding")

# exposure raises severities
sf_int = dict(sf, exposure="internet")
r_int = {f["rule"]: f for f in review.review_app(sf_int)}
check(r_int["tls.old"]["severity"] == "high" and r_int["cert.self_signed"]["severity"] == "high" and r_int["web.no_waf"]["severity"] == "medium",
      "internet-facing: old TLS, self-signed certificate and no WAF rate higher")

# fixes
fx = {f["rule"]: ns.fix(f, sf) for f in review.review_app(sf)}
check(fx["tls.ssl3"] == ["set ssl vserver StoreFront_LB -ssl3 DISABLED -tls1 DISABLED -tls11 DISABLED -tls12 ENABLED -tls13 ENABLED"],
      "fix: protocols on the virtual server", fx["tls.ssl3"])
check(any("unbind ssl vserver StoreFront_LB -cipherName SSL3-RC4-SHA" in x for x in fx["tls.weak_ciphers"]), "fix: unbind the weak cipher")
check(fx["cert.weak_key"] == ["update ssl certKey sf_cert -cert <new-certificate.pem> -key <new-key.pem>"], "fix: the certificate-key pair by name")
check(any(x.startswith("bind lb vserver StoreFront_LB -policyName StoreFront_LB_WAF_Policy") for x in fx["web.no_waf"]), "fix: bind a WAF policy to the LB")
gw_fix = ns.fix({"rule": "tls.hsts", "evidence": []}, apps["GW_VS"])
check(gw_fix == ["set ssl profile Gateway_SSL -HSTS ENABLED -maxage 31536000 -IncludeSubdomains YES"], "fix: on the SSL profile when one applies", gw_fix)

# the whole report
rep = review.build(list(apps.values()), [], fixer=ns.fix)
check(rep["grade"] == "D" and rep["risk"] == "Critical" and rep["counts"]["critical"] == 2, "report: criticals cap the grade at D",
      (rep["grade"], rep["risk"], rep["counts"]))
check(rep["apps"][0]["name"] == "StoreFront_LB" and rep["apps"][0]["grade"] == "F", "report: worst application first")
check(all(f.get("fix") is not None for a in rep["apps"] for f in a["findings"]), "report: every finding has its commands (maybe none)")
key = next(f["key"] for f in rep["apps"][0]["findings"] if f["rule"] == "tls.ssl3")
rep2 = review.build(list(apps.values()), [], fixer=ns.fix, accepted={key: {"by": "ciso", "note": "decommissioned next month"}})
check(rep2["counts"]["critical"] == 1 and rep2["accepted"] == 1, "accepted risk: listed, not counted")

# checklist folded in: items covered per application are left out
checks = [{"id": "tls_versions", "group": "Gateway settings", "title": "x", "status": "missing"},
          {"id": "cookie_hijack", "group": "Gateway protection policies", "title": "Session cookie hijack prevention", "status": "missing",
           "variants": [{"commands": [{"text": "add responder policy ..."}]}], "variant": 0},
          {"id": "mgmt_secure", "group": "Management and platform", "title": "Secure-only management access", "status": "partial"},
          {"id": "ntp", "group": "Management and platform", "title": "NTP", "status": "missing", "mark": {"state": "irrelevant"}},
          {"id": "geo_block", "group": "Gateway protection policies", "title": "Geo", "status": "missing", "optional": True}]
pf = {f["rule"]: f for f in review.checklist_findings(checks)}
check(set(pf) == {"checklist.cookie_hijack", "checklist.mgmt_secure", "checklist.geo_block"},
      "checklist: per-application items and marked items left out", sorted(pf))
check(pf["checklist.cookie_hijack"]["severity"] == "high" and pf["checklist.mgmt_secure"]["severity"] == "medium"
      and pf["checklist.geo_block"]["severity"] == "low" and pf["checklist.mgmt_secure"]["category"] == "Management plane",
      "checklist: severities (partly = one lower, optional = low) and areas")
check(pf["checklist.cookie_hijack"]["fix"] == ["add responder policy ..."], "checklist: the commands come along")

# ------------------------------------------------------------------ the API
import app  # noqa: E402

app.NetScalerAPI = lambda ip, u, p, port=80, protocol="http": fake
cfg = app.load_nodes_config()
cfg["instances"][0]["primary"].update(ip=NSIP, username="nsapi", password="x", protocol="http", port=80)
app.save_nodes_config(cfg)
iid = str(app.get_instance(None)["id"])
app.app.config["TESTING"] = True
c = app.app.test_client()
with c.session_transaction() as s:
    s.update(logged_in=True, user="admin", username="admin", must_change_password=False, last_activity=time.time())

r = c.get("/api/posture/review")
j = r.get_json()
check(r.status_code == 200 and len(j["apps"]) == 5 and j["meta"]["checklist"]["of"] > 0 and j["platform"]["findings"] is not None,
      "GET /api/posture/review: applications, the checklist score and the platform findings", r.status_code)
check(j["meta"]["version"] == "14.1-43.56", "review: firmware version in the report", j["meta"].get("version"))

r = c.post("/api/posture/mark", json={"app": "lb:StoreFront_LB", "exposure": "internet"})
check(r.status_code == 200, "exposure saved")
j = c.get("/api/posture/review").get_json()
sfa = next(a for a in j["apps"] if a["name"] == "StoreFront_LB")
check(sfa["exposure"] == "internet" and sfa["exposure_set"], "exposure applied to the application")
fk = next(f["key"] for f in sfa["findings"] if f["rule"] == "tls.old")
r = c.post("/api/posture/mark", json={"key": fk, "accept": True, "note": "legacy kiosks, until Q1"})
j = c.get("/api/posture/review").get_json()
fa = next(f for a in j["apps"] if a["name"] == "StoreFront_LB" for f in a["findings"] if f["key"] == fk)
check(fa["accepted"]["note"] == "legacy kiosks, until Q1" and fa["accepted"]["by"] == "admin", "accepted with note and who")
check(app._db_documents()["posture"][1] and app._db_documents()["posture"][0][iid]["exposure"]["lb:StoreFront_LB"] == "internet",
      "marks are a settings document for the external database")
r = c.post("/api/posture/mark", json={"app": "nonsense", "exposure": "internet"})
check(r.status_code == 400, "an unknown application is refused")
app._db_apply_document("posture", {iid: {"exposure": {"lb:X": "bogus", "lb:Y": "internal"}, "accepted": {"k": {"by": "x", "note": 5}}}})
check(app.POSTURE_MARKS[iid]["exposure"] == {"lb:Y": "internal"} and app.POSTURE_MARKS[iid]["accepted"]["k"]["note"] == "5",
      "marks from the database are cleaned")

# ------------------------------------------------------------------ TLS test through the API
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

key_ = rsa.generate_private_key(public_exponent=65537, key_size=2048)
nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gw.example.com")])
now = datetime.datetime.now(datetime.timezone.utc)
crt = (x509.CertificateBuilder().subject_name(nm).issuer_name(nm).public_key(key_.public_key()).serial_number(1)
       .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=90))
       .sign(key_, hashes.SHA256()))
d = tempfile.mkdtemp()
open(d + "/c.pem", "wb").write(crt.public_bytes(serialization.Encoding.PEM))
open(d + "/k.pem", "wb").write(key_.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(d + "/c.pem", d + "/k.pem")
srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(50)
port = srv.getsockname()[1]


def loop():
    while True:
        try:
            cl, _ = srv.accept()
        except OSError:
            return
        def h(cl=cl):
            try:
                with ctx.wrap_socket(cl, server_side=True) as t:
                    t.settimeout(2)
                    if t.recv(2048).startswith(b"GET"):
                        t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except Exception:
                pass
        threading.Thread(target=h, daemon=True).start()


threading.Thread(target=loop, daemon=True).start()
real = app.posture_ns.scan_targets
app.posture_ns.scan_targets = lambda data: [dict(t, ip="127.0.0.1", port=port) if t["name"] == "GW_VS" else t for t in real(data)]

j = c.get("/api/posture/tls/targets").get_json()
check([t["key"] for t in j["targets"]][:1] == ["gateway:GW_VS"] and j["targets"][0]["sni"] == "gw.example.com",
      "targets: SSL servers with an address, the Gateway first, SNI from its certificate", j)
r = c.post("/api/posture/tls/scan", json={"key": "lb:Nope"})
check(r.status_code == 400, "a server that is not on this appliance cannot be tested")
r = c.post("/api/posture/tls/scan", json={"key": "gateway:GW_VS", "sni": "bad host name!"})
check(r.status_code == 400, "a bad host name is refused")
r = c.post("/api/posture/tls/scan", json={"key": "gateway:GW_VS", "sni": "gw.example.com"})
jid = r.get_json().get("job")
check(r.status_code == 200 and jid, "the test starts in the background")
for _ in range(60):
    st = c.get(f"/api/posture/tls/job/{jid}").get_json()
    if st["state"] != "running":
        break
    time.sleep(0.5)
check(st["state"] == "done", "the test finishes", st)
res = c.get("/api/posture/tls/result?key=gateway:GW_VS").get_json()
check(res.get("grade") == "T" and res.get("grade_if_trusted") in ("A", "A+", "A-"), "result: self-signed -> T, A if trusted",
      (res.get("grade"), res.get("grade_if_trusted")))
hsts = next((f for f in res["findings"] if f["id"] == "http.hsts"), None)
check(hsts and hsts["fix"] == ["set ssl profile Gateway_SSL -HSTS ENABLED -maxage 31536000 -IncludeSubdomains YES"],
      "result: each finding carries the commands for this virtual server", hsts)
j = c.get("/api/posture/review").get_json()
gw = next(a for a in j["apps"] if a["name"] == "GW_VS")
check(gw["scan"] and gw["scan"]["grade"] == "T", "the review shows the last TLS test")
check(os.path.exists(app.TLS_SCANS_FILE), "the TLS test is kept on disk")

print("\n" + ("all passed" if not bad else f"{bad} FAILED"))
sys.exit(1 if bad else 0)
