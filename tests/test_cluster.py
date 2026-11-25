"""Clusters: every member as a node of its own, the coordinator (CCO) on the
Overview and the All Instances card, cluster events on the Failover tab, and the
CPU counter NetScaler reports as 4294967295 while it has no reading.

    python tests/test_cluster.py      # needs the app's Python packages; uses a temporary directory

The cluster is a stand-in: a cluster IP (CLIP) that answers as the coordinator,
and three members, each answering at its own NSIP.
"""
import os
import sys
import tempfile
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.update(DATA_DIR=tempfile.mkdtemp(), APP_SSL="0", SYSLOG_PORT="0", SECURITY_POLL_SECS="0",
                  HA_POLL_SECS="0", TZ="UTC", NODE_BACKOFF_SECS="0")
sys.path.insert(0, ROOT)

import requests          # noqa: E402

ok_n = bad_n = 0


def check(cond, what, extra=""):
    global ok_n, bad_n
    if cond:
        ok_n += 1; print("   ok    " + what)
    else:
        bad_n += 1; print("   FAIL  " + what + (("\n         " + str(extra)[:700]) if extra else ""))


CLIP = "192.0.2.30"
IPS = {1: "192.0.2.31", 2: "192.0.2.32", 3: "192.0.2.33"}
PREEMPTION = {"on": "DISABLED"}


class Member:
    def __init__(self, nid):
        self.id, self.ip = nid, IPS[nid]
        self.up, self.cco = True, nid == 1
        self.admin, self.op, self.health = "ACTIVE", "ACTIVE", "UP"
        self.priority = nid * 10
        self.cpu, self.pkt = "12.5", "7.0"
        self.pf = ""

    def entry(self, viewer):
        return {"nodeid": self.id, "ipaddress": self.ip, "state": self.admin, "masterstate": self.op,
                "health": self.health, "isconfigurationcoordinator": "true" if self.cco else "false",
                "islocalnode": "true" if viewer is self else "false", "priority": self.priority,
                "operationalsyncstate": "ENABLED", "partialfailifaces": self.pf, "backplane": f"{self.id}/1/1"}


members = {i: Member(i) for i in IPS}


def cco():
    return next((m for m in members.values() if m.cco), None)


class Fake:
    """What answers at one address: a member's NSIP, or the CLIP (the coordinator)."""

    def __init__(self, ip):
        self.ip = ip

    def who(self):
        if self.ip == CLIP:
            m = cco()
            return m if m and m.up else None
        m = next(m for m in members.values() if m.ip == self.ip)
        return m if m.up else None

    def _get(self, path, custom_timeout=None):
        me = self.who()
        if me is None:
            raise requests.ConnectTimeout("timed out")
        if path.startswith("/config/clusternode"):
            return {"clusternode": [m.entry(me) for m in members.values()]}
        if path.startswith("/config/clusterinstance"):
            return {"clusterinstance": [{"clid": 1, "deadinterval": 3, "hellointerval": 200,
                                         "preemption": PREEMPTION["on"], "operationalstate": "ACTIVE"}]}
        if path.startswith("/stat/ns"):
            return {"ns": {"cpuusagepcnt": me.cpu, "pktcpuusagepcnt": me.pkt, "memusagepcnt": "41.0",
                           "httprequestsrate": "5"}}
        if path.startswith("/config/nshostname"):
            return {"nshostname": [{"hostname": f"ns-c{me.id}"}]}
        if path.startswith("/config/nsversion"):
            return {"nsversion": {"version": "NetScaler NS14.1: Build 51.80.nc"}}
        if path.startswith("/config/nsconfig"):
            return {"nsconfig": {"configchanged": "false"}}
        raise requests.HTTPError("404 no such resource")


FAKES = {ip: Fake(ip) for ip in [CLIP] + list(IPS.values())}

import app as dash       # noqa: E402
import db                # noqa: E402
import ha_events         # noqa: E402
import security          # noqa: E402

dash.NetScalerAPI = lambda ip, username, password, port=80, protocol="http": FAKES[ip]
cfg = dash.load_nodes_config()
cfg["instances"][0].update(mode="cluster", name="Cluster")
cfg["instances"][0]["primary"].update(ip=CLIP, username="nsapi", password="x", protocol="http", port=80)
dash.save_nodes_config(cfg)
iid = str(dash.get_instance(None)["id"])
c = dash.app.test_client()
with c.session_transaction() as s:
    s.update(logged_in=True, user="admin", username="admin", must_change_password=False, last_activity=time.time())

# ------------------------------------------------------------------ CPU
print("-- CPU and memory")
check(dash._stat_pct({"cpuusagepcnt": "4294967295", "pktcpuusagepcnt": "7.0"}, dash._CPU_KEYS) == 7.0,
      "4294967295 is no reading: the next counter is used")
check(dash._stat_pct({"cpuusagepcnt": "4294967295"}, dash._CPU_KEYS) is None
      and dash._stat_pct({"cpuusagepcnt": "-1"}, dash._CPU_KEYS) is None, "no real reading at all: none, not a number")
check(dash._stat_pct({"cpuusagepcnt": "0"}, dash._CPU_KEYS) == 0.0 and dash._stat_pct({"cpuusagepcnt": "100"}, dash._CPU_KEYS) == 100.0,
      "0 and 100 are real readings")

# ------------------------------------------------------------------ members as nodes
print("-- members as nodes")
j = c.get("/api/caps").get_json()
check(j["node_order"] == ["primary", "node1", "node2", "node3"], "the node list: the CLIP first, then every member", j.get("node_order"))
check(j["nodes"]["primary"]["name"] == "Cluster IP (CLIP)" and j["nodes"]["node1"]["name"] == "ns-c1 · CCO"
      and j["nodes"]["node2"]["name"] == "ns-c2" and j["nodes"]["node3"]["ip"] == IPS[3],
      "named by hostname, the coordinator marked", {k: v["name"] for k, v in j["nodes"].items()})
check(c.get("/api/system-stats?node=node9").get_json().get("connected") is False and c.get("/api/system-stats?node=nodeX").status_code == 400,
      "an unknown member reads as not connected; a bad key is refused")

r = c.get("/api/system-stats?node=node2").get_json()
check(r["ip"] == IPS[2] and r["ha_role"] == "Member - not the coordinator" and r["cluster"]["op_state"] == "ACTIVE"
      and r["cluster"]["admin_state"] == "ACTIVE" and r["cluster"]["health"] == "UP" and r["cluster"]["id"] == 2,
      "Overview of a member: its address and role, operational and admin state, health", r.get("cluster"))
r = c.get("/api/system-stats?node=node1").get_json()
check(r["ha_role"] == "Configuration coordinator (CCO)" and r["cluster"]["cco"], "the coordinator says so", r["ha_role"])
r = c.get("/api/system-stats?node=primary").get_json()
check(r["ip"] == CLIP and r["ha_role"] == "Cluster IP - reaches the coordinator, node 1" and r["cluster"]["via_clip"],
      "the CLIP says which node it reaches", r["ha_role"])

members[2].cpu = "4294967295"
r = c.get("/api/system-stats?node=node2").get_json()
check(r["cpu"] == 7.0 and r["mem"] == 41.0, "Overview CPU: the packet-engine counter while cpuusagepcnt has no reading", (r["cpu"], r["mem"]))
members[2].pkt = "4294967295"
r = c.get("/api/system-stats?node=node2").get_json()
check(r["cpu"] is None, "Overview CPU: none at all -> no number", r["cpu"])
members[2].cpu, members[2].pkt = "12.5", "7.0"

h = c.get("/api/ha-status").get_json()
check(len(h["hanode"]) == 3 and h["hanode"][0]["cluster"]["cco"] and not h["hanode"][1]["cluster"]["cco"]
      and h["hanode"][1]["name"] == "ns-c2", "the cluster panel: every node, the coordinator, names", h["hanode"])

# ------------------------------------------------------------------ all instances
print("-- all instances")
card = next(i for i in c.get("/api/instances-health").get_json()["instances"] if i["id"] == iid)
check(card["nodes_total"] == 3 and card["nodes_up"] == 3 and card["status"] == "up"
      and [n["state"] for n in card["nodes"]] == ["CCO", "ACTIVE", "ACTIVE"]
      and all(n["cpu"] == 12.5 for n in card["nodes"]), "the card lists all three members with their own load",
      card)
members[3].up = False
members[3].op, members[3].health = "INACTIVE", "NOT UP"
dash._CLUSTER_CACHE.clear()
card = next(i for i in c.get("/api/instances-health").get_json()["instances"] if i["id"] == iid)
check(card["status"] == "degraded" and card["nodes_up"] == 2 and any("unreachable" in w for w in card["warnings"])
      and any("health NOT UP" in w for w in card["warnings"]), "a member down: degraded, and said why", card["warnings"])
members[3].up = True
members[3].op, members[3].health = "ACTIVE", "UP"
dash._CLUSTER_CACHE.clear()

# ------------------------------------------------------------------ logs from members
print("-- logs from members")
dash.cluster_members(iid)
check(dash._syslog_sender(IPS[2]) == iid and dash._syslog_sender("203.0.113.9") is None,
      "syslog from a member's NSIP is accepted for the cluster")
t = dash._security_targets()
check({x[2] for x in t} == {CLIP, *IPS.values()}, "the audit log is read from the CLIP and every member", [x[2] for x in t])
check(dash._security_facts(iid, "node2", IPS[2], FAKES[IPS[2]]) == {}, "the checklist is read once, through the CLIP")

# ------------------------------------------------------------------ failover tab
print("-- failover tab")
check(dash.ha_poll(iid) is None, "the first read records nothing")
members[1].up = False
members[1].cco, members[2].cco = False, True
members[1].op, members[1].health = "UNKNOWN", "NOT UP"
dash._CLUSTER_CACHE.clear()
ev = dash.ha_poll(iid)
d = (ev or {}).get("detail") or {}
check(ev and ev["type"] == "CCO change" and d.get("cluster") and d["old_cco"] == [IPS[1]] and d["new_cco"] == [IPS[2]]
      and ev["ip"] == IPS[2], "the coordinator went down: a CCO change to node 2", ev and ev["type"])
check(ev and f"{IPS[2]} Member → Coordinator" in ev["role_change"] and f"{IPS[1]} Coordinator → Member, ACTIVE → UNKNOWN" in ev["role_change"],
      "which address became what", ev and ev["role_change"])
cause = ha_events.explain(d, [])
check(cause["code"] == "heartbeat" and "cannot reach" in cause["text"] and "node 2" not in cause["title"].lower(),
      "why: the old coordinator stopped answering", cause)
check(d["after"]["nodes"][IPS[1]]["seen_by_cco"]["op_state"] == "UNKNOWN" and not d["after"]["nodes"][IPS[1]]["reachable"]
      and d["after"]["settings"]["dead_interval"] == 3, "the snapshot: the coordinator's view, the dashboard's reach, settings")

j = c.get("/api/failover-history").get_json()
check(j["events"] and j["events"][0]["type"] == "CCO change" and j["events"][0]["detail"]["cluster"]
      and j["events"][0]["cause"]["code"] == "heartbeat", "the Failover tab shows it with the reason", j["events"][:1])

members[1].up = True
members[1].op, members[1].health = "ACTIVE", "UP"
ev = dash.ha_poll(iid)
check(ev and ev["type"] == "Node back" and ha_events.explain(ev["detail"], [])["code"] == "recovered",
      "the old coordinator comes back as a member", ev and ev["type"])

PREEMPTION["on"] = "ENABLED"
members[1].cco, members[2].cco = True, False
ev = dash.ha_poll(iid)
cause = ha_events.explain(ev["detail"], [])
check(ev["type"] == "CCO change" and cause["title"] == "Coordinator taken back (preemption)" and "priority 10" in cause["text"],
      "preemption: the node with the lower priority value takes the role back", cause)

members[3].admin, members[3].op = "PASSIVE", "INACTIVE"
ev = dash.ha_poll(iid)
cause = ha_events.explain(ev["detail"], [])
check(ev["type"] == "Node out of service" and cause["title"] == "Admin state set to PASSIVE",
      "an administrator set a node PASSIVE: out of service, not lost", (ev["type"], cause))
stamp = datetime.now(timezone.utc).strftime("%m/%d/%Y:%H:%M:%S")
line = (f'{stamp} GMT ns-c1 0-PPE-0 : default CLI CMD_EXECUTED 812 0 : User nsroot - Remote_ip 198.51.100.20 - '
        f'Command "set cluster node 3 -state PASSIVE" - Status "Success"')
parsed = security.parse_line(line)
check(parsed and parsed["kind"] == "ha_command", "the cluster command is kept from the log", parsed)
evid = ha_events.evidence_for(time.time(), [{"ts": time.time(), "node": IPS[1], "kind": parsed["kind"], "etype": parsed["etype"],
                                             "username": parsed["username"], "client_ip": parsed["client_ip"],
                                             "action": parsed["action"], "message": parsed["message"], "raw": line,
                                             "detail": parsed["fields"]}])
cause = ha_events.explain(ev["detail"], evid)
check(cause["title"] == "Cluster node changed by nsroot" and "198.51.100.20" in cause["text"], "with the log line: who did it", cause)

members[3].health, members[3].pf = "PARTIAL-FAILURE", "1/2"
members[3].admin, members[3].op = "ACTIVE", "ACTIVE"
ev = dash.ha_poll(iid)
cause = ha_events.explain(ev["detail"], [])
check(ev["type"] == "Health failure" and cause["code"] == "health" and "1/2" in cause["text"], "a partial failure names the interface", (ev and ev["type"], cause))

print(f"\npassed {ok_n}, failed {bad_n}")
sys.exit(1 if bad_n else 0)
