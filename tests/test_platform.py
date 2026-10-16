"""License & Capacity, and SDX instances, against stand-ins that answer like NITRO.

    python tests/test_platform.py      # needs the app's Python packages; uses a temporary directory
"""
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.update(DATA_DIR=tempfile.mkdtemp(), APP_SSL="0", SYSLOG_PORT="0", SECURITY_POLL_SECS="0", TZ="UTC")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fake_netscaler import FakeNitro, FakeSdx, NSIP, SDX_IP   # noqa: E402
import app as dash                                             # noqa: E402

ok_n = bad_n = 0


def check(cond, what, extra=""):
    global ok_n, bad_n
    if cond:
        ok_n += 1; print("   ok    " + what)
    else:
        bad_n += 1; print("   FAIL  " + what + (("\n         " + str(extra)[:600]) if extra else ""))


print("-- license")
ns = FakeNitro(True)
lic = dash.license_info(ns)
check(lic["edition"] == "Premium" and lic["mode"] == "LAS - fixed bandwidth" and lic["capacity"] == "1000 Mbps",
      "edition, LAS fixed bandwidth, capacity", lic)
check(lic["days_left"] == 21 and lic["level"] == "warn" and lic["expires_on"]
      and any("21 day" in n for n in lic["notes"]), "21 days to expiry: a warning with the date", lic)
ns.lic_mode, ns.lic_days = "LAS", 200
lic = dash.license_info(ns)
check(lic["mode"] == "LAS - online" and lic["level"] == "ok", "LAS online, far from expiry: no warning", lic)
ns.lic_days = 5
check(dash.license_info(ns)["level"] == "bad", "5 days to expiry: red")
ns.lic_days, ns.grace, ns.grace_hours = 200, 1, 500
lic = dash.license_info(ns)
check(lic["grace"] and lic["grace_hours_left"] == 500 and lic["level"] == "warn" and "20 day(s) 20 h" in lic["notes"][0],
      "grace period: hours left and a warning", lic)
ns.grace_hours = 30
check(dash.license_info(ns)["level"] == "bad", "less than three days of grace: red")
ns.lic_mode, ns.lic_days, ns.grace = "Local", 0, 0
lic = dash.license_info(ns)
check(lic["mode"] == "Local license file" and lic["days_left"] is None and lic["level"] == "ok" and not lic["server"],
      "a local license with no expiry reported", lic)
ns.lic_mode, ns.lic_days = "LAS (Fixed Bandwidth)", 21

print("-- an SDX and the VPX on it")
sdx = FakeSdx()
dash.get_nitro = lambda node_key, instance_id=None: ns
dash.get_sdx = lambda instance_id=None: sdx
cfg = dash.load_nodes_config()
cfg["instances"] = [
    {"id": "gw", "name": "Gateway", "mode": "standalone",
     "primary": {"ip": NSIP, "username": "nsapi", "password": "x", "port": 80, "protocol": "http"}},
    {"id": "sdx1", "name": "SDX DC1", "mode": "sdx",
     "primary": {"ip": SDX_IP, "username": "nsroot", "password": "y", "port": 443, "protocol": "https"}},
]
dash.save_nodes_config(cfg)
c = dash.app.test_client()
with c.session_transaction() as s:
    s.update(logged_in=True, user="admin", username="admin", must_change_password=False, last_activity=time.time())

r = c.get("/api/caps?instance=sdx1")
j = r.get_json()
check(r.status_code == 200 and j["mode"] == "sdx" and list(j["nodes"]) == ["primary"], "caps: an SDX has one node, the Management Service", j)
r = c.get("/api/sdx/overview?instance=sdx1")
d = r.get_json()
check(r.status_code == 200 and d["platform"]["hostname"] == "sdx-dc1" and d["platform"]["version"] == "14.1 43.50"
      and d["platform"]["cpu"] == 7.5, "platform: name, version, Management Service load", d.get("platform"))
check([i["name"] for i in d["instances"]] == ["vpx-gw01", "vpx-lb02"], "the VPX instances", [i["name"] for i in d["instances"]])
gw = d["instances"][0]
check(gw["ok"] and gw["dashboard"] == {"id": "gw", "name": "Gateway", "node": "primary"} and gw["cores"] == 2 and gw["memory_mb"] == 4096,
      "a VPX added to the dashboard links to its instance", gw)
lb = d["instances"][1]
check(not lb["ok"] and lb["dashboard"] is None and lb["reason"] == "VM halted by admin", "a halted VPX, not in the dashboard", lb)
check(len(d["hardware_errors"]) == 1 and d["hardware_errors"][0]["name"] == "Power Supply 2", "a failed power supply is a hardware error")
check(d["license"]["max_throughput"] == 50000 and d["license"]["available_instances"] == 23
      and d["license"]["expiring"][0] == {"feature": "Platform", "days": 12, "count": 1}, "SDX license and what expires first", d["license"])
check(any(x["state"] == "DOWN" and x["rx_errors"] == 4 for x in d["interfaces"]), "interfaces with state and errors")
check("ns" in "".join(sdx.calls) and not any("/nitro/v1" in x for x in sdx.calls), "only the Management Service API is used")

wall = {i["id"]: i for i in c.get("/api/instances-health").get_json()["instances"]}
w = wall["sdx1"]
check(w["status"] == "degraded" and w["sdx"]["hardware_errors"] == 1 and len(w["sdx"]["instances"]) == 2,
      "wall: the SDX card is degraded, with its instances", w)
check(any("Power Supply 2" in x for x in w["warnings"]) and any("vpx-lb02" in x for x in w["warnings"])
      and any("Platform expires in 12" in x for x in w["warnings"]), "wall: power supply, halted VPX, expiring license named", w["warnings"])
g = wall["gw"]
check(any("expires in 21 day" in x for x in g["warnings"]), "wall: the NetScaler's license warning", g["warnings"])
sdx.psu_ok = True
dash._SDX_CACHE.clear()
w = {i["id"]: i for i in c.get("/api/instances-health").get_json()["instances"]}["sdx1"]
check(not any("Power Supply" in x for x in w["warnings"]), "a power supply that is fine again is not reported")

r = c.get("/api/system-stats?instance=gw&node=primary")
j = r.get_json()
check(r.status_code == 200 and j["license"]["mode"] == "LAS - fixed bandwidth" and j["license_type"] == "Premium",
      "overview: license details", j.get("license"))
check(j["hosted_on"] and j["hosted_on"]["sdx_id"] == "sdx1" and j["hosted_on"]["vpx_name"] == "vpx-gw01",
      "overview: a VPX says which SDX it runs on", j.get("hosted_on"))

for path in ("/api/system-stats", "/api/user-sessions", "/api/security/checklist", "/api/certificates", "/api/ha-status"):
    r = c.get(path + "?instance=sdx1&node=primary")
    check(r.status_code == 409 and r.get_json().get("code") == "sdx", f"{path} is refused for an SDX", r.status_code)
check(all(t[0] != "sdx1" for t in dash._security_targets()), "the security poll leaves the SDX alone")
sdx.down = True
dash._SDX_CACHE.clear()
r = c.get("/api/sdx/overview?instance=sdx1")
check(r.status_code == 502 and "could not be read" in r.get_json()["error"], "Management Service down: a clear error", r.get_json())
w = {i["id"]: i for i in c.get("/api/instances-health").get_json()["instances"]}["sdx1"]
check(w["status"] == "down", "...and the wall shows it unreachable")
check(c.get("/api/sdx/overview?instance=gw").status_code == 400, "an SDX view of a NetScaler instance is refused")

r = c.post("/api/settings", json={"instances": [
    {"id": "sdx1", "name": "SDX DC1", "mode": "sdx", "primary": {"ip": SDX_IP, "username": "nsroot", "password": "", "port": 443, "protocol": "https"},
     "secondary": {"ip": "192.0.2.99", "username": "x", "password": "z", "port": 443, "protocol": "https"}}]})
saved = dash.get_instance("sdx1")
check(r.status_code == 200 and saved["mode"] == "sdx" and "secondary" not in saved and saved["primary"]["password"] == "y",
      "settings: an SDX keeps one node, and its stored password", saved)

print("\npassed %d, failed %d" % (ok_n, bad_n))
sys.exit(1 if bad_n else 0)
