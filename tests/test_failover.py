"""Failover tab: HA changes read from both nodes, which node became what, and why.

    python tests/test_failover.py      # needs the app's Python packages; uses a temporary directory

Two stand-in nodes answer `hanode` and `stat hanode` the way NetScaler does: each
lists itself (id 0) and its peer, and a node the peer no longer hears is UNKNOWN.
"""
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.update(DATA_DIR=tempfile.mkdtemp(), APP_SSL="0", SYSLOG_PORT="0", SECURITY_POLL_SECS="0",
                  HA_POLL_SECS="0", TZ="UTC")
sys.path.insert(0, ROOT)

import requests          # noqa: E402

ok_n = bad_n = 0


def check(cond, what, extra=""):
    global ok_n, bad_n
    if cond:
        ok_n += 1; print("   ok    " + what)
    else:
        bad_n += 1; print("   FAIL  " + what + (("\n         " + str(extra)[:700]) if extra else ""))


A, B = "192.0.2.10", "192.0.2.11"


class Node:
    """One NetScaler of the pair."""

    def __init__(self, ip, nid):
        self.ip, self.id, self.up = ip, nid, True
        self.role, self.health, self.hastatus = "Secondary", "UP", "ENABLED"
        self.master = ""                    # stat hacurmasterstate, when not the role itself
        self.hb_rx, self.pf = 1000, ""
        self.hears_peer = True

    def entry(self, as_self):
        return {"id": 0 if as_self else 1, "ipaddress": self.ip, "state": self.role, "hacurstate": self.health,
                "hastatus": self.hastatus, "hasync": "SUCCESS", "pfifaces": self.pf, "deadinterval": 3,
                "hellointerval": 200, "failsafe": "OFF", "masterstatetime": 3600, "ssl2": "NOT PRESENT"}

    def _get(self, path, custom_timeout=None):
        if not self.up:
            raise requests.ConnectTimeout("timed out")
        peer = pair[B if self.ip == A else A]
        if path.startswith("/config/hanode"):
            if self.hears_peer and peer.up:
                p = peer.entry(False)
            else:
                p = {"id": 1, "ipaddress": peer.ip, "state": "UNKNOWN", "hacurstate": "DOWN", "hastatus": "ENABLED"}
            return {"hanode": [self.entry(True), p]}
        if path.startswith("/stat/hanode"):
            return {"hanode": {"hacurstatus": "YES", "hacurstate": self.health,
                               "hacurmasterstate": self.master or self.role.upper(),
                               "transtime": datetime.now().strftime("%a %b %d %H:%M:%S %Y"),
                               "hatotpktrx": str(self.hb_rx), "hatotpkttx": "2000", "hapktrxrate": "5"}}
        raise requests.HTTPError("404")


pair = {A: Node(A, 0), B: Node(B, 1)}
pair[A].role = "Primary"

import ha_events          # noqa: E402
import security           # noqa: E402

store = {}
targets = [(A, pair[A]), (B, pair[B])]


def poll():
    return ha_events.poll_instance("dc1", "DC1 pair", targets, store, lambda ip: {A: "ns-gw01", B: "ns-gw02"}[ip])


def stamp(t=None):
    return datetime.fromtimestamp(t or time.time(), timezone.utc).strftime("%m/%d/%Y:%H:%M:%S")


# ------------------------------------------------------------------ log lines
print("-- log lines")
force = f'{stamp()} GMT ns-gw01 0-PPE-0 : default GUI CMD_EXECUTED 4410 0 : User nsroot - Remote_ip 198.51.100.20 - Command "force HA failover" - Status "Success"'
ev = security.parse_line(force)
check(ev and ev["kind"] == "ha_command" and ev["username"] == "nsroot" and ev["client_ip"] == "198.51.100.20"
      and ev["message"] == "force HA failover" and ev["fields"]["interface"] == "GUI" and ev["action"] == "Success",
      "force failover command: user, address, GUI/CLI/API, result", ev)
check(security.parse_line(f'{stamp()} GMT ns-gw01 0-PPE-0 : default GUI CMD_EXECUTED 4411 0 : User Dashboard - Remote_ip 192.0.2.99 - Command "show ns ip" - Status "Success"') is None,
      "other commands (the dashboard's own reads) are not kept")
sc = security.parse_line(f'{stamp()} GMT ns-gw02 0-PPE-0 : default EVENT STATECHANGE 4412 0 : Device "remote node {A}" - State "DOWN"')
check(sc and sc["kind"] == "ha_state" and sc["client_ip"] == A and sc["action"] == "DOWN", "STATECHANGE of the remote node", sc)
check(security.parse_line(f'{stamp()} GMT ns-gw02 0-PPE-0 : default EVENT STATECHANGE 4413 0 : Device "server_svc_web1" - State DOWN') is None,
      "a service going down is not an HA line")
sync = security.parse_line('08/24/2026:11:28:44 GMT ns-gw01 0-PPE-0 : default EVENT STATECHANGE 2699590 0 : Device "self node 192.0.2.10" - State "SYNC Failure - Save remote config failed"')
check(sync and sync["fields"]["node"] == "self" and "SYNC Failure" in sync["action"], "self node sync failure", sync)
rb = security.parse_line(f'{stamp()} GMT ns-gw01 0-PPE-0 : default CLI CMD_EXECUTED 4414 0 : User admin1 - Remote_ip 198.51.100.21 - Command "reboot -warm" - Status "Success"')
check(rb and rb["kind"] == "ha_command" and rb["fields"]["interface"] == "CLI", "reboot is kept, from the CLI")

# ------------------------------------------------------------------ changes
print("-- failovers")
check(poll() is None and store == {f"dc1|{A}": "Primary", f"dc1|{B}": "Secondary"}, "first read: nothing to compare, roles kept", store)
check(poll() is None, "no change, no event")

# the primary dies
pair[A].up = False
pair[B].role = "Primary"
e = poll()
d = (e or {}).get("detail") or {}
check(e and e["type"] == "Failover" and d["old_primary"] == [A] and d["new_primary"] == [B] and e["ip"] == B,
      "the primary stopped answering: a failover to the secondary", e and e["type"])
check(e and "192.0.2.11 Secondary → Primary" in e["role_change"] and "192.0.2.10 Primary → Unknown" in e["role_change"],
      "which address became what", e and e["role_change"])
c = ha_events.explain(d, [])
check(c["code"] == "heartbeat" and "3 s" in c["text"] and "cannot reach 192.0.2.10" in c["text"]
      and any("no heartbeat packets" in n for n in c["notes"]), "why: heartbeats lost, the node does not answer the dashboard either", c)
check(d["after"]["nodes"][A]["seen_by_peer"]["role"] == "Unknown" and not d["after"]["nodes"][A]["reachable"]
      and d["after"]["nodes"][A]["error"] == "did not answer in time", "the snapshot: how the peer sees it, why the dashboard cannot", d["after"]["nodes"][A])
check(d["after"]["nodes"][B]["name"] == "ns-gw02" and d["after"]["settings"]["dead_interval"] == 3, "names and HA settings")
check(poll() is None, "still down: no second event")

# it comes back as secondary
pair[A].up, pair[A].role = True, "Secondary"
pair[B].hb_rx += 50
e = poll()
check(e and e["type"] == "Node back" and ha_events.explain(e["detail"], [])["code"] == "recovered",
      "the old primary answers again: node back", e and (e["type"], e["reason"]))

# an administrator forces a failover
pair[A].role, pair[B].role, pair[A].master = "Primary", "Secondary", "FORCE CHANGE"
e = poll()
check(e and e["type"] == "Failover" and ha_events.explain(e["detail"], [])["code"] == "forced",
      "FORCE CHANGE on the new primary: a forced failover", e and e["reason"])
line = dict(security.parse_line(force), ts=time.time(), node=A)
evid = ha_events.evidence_for(time.time(), [{"ts": line["ts"], "node": A, "kind": line["kind"], "etype": line["etype"],
                                            "username": line["username"], "client_ip": line["client_ip"],
                                            "action": line["action"], "message": line["message"], "raw": force,
                                            "detail": line["fields"]}])
c = ha_events.explain(e["detail"], evid)
check(c["code"] == "forced" and c["title"] == "Forced failover by nsroot" and "198.51.100.20" in c["text"] and "GUI" in c["text"],
      "with the log line: who, from where, how", c)
pair[A].master = ""

# a monitored interface fails on the primary
pair[A].role, pair[A].health, pair[A].pf, pair[B].role = "Secondary", "PARTIALFAIL", "1/1", "Primary"
e = poll()
c = ha_events.explain(e["detail"], [])
check(e and e["type"] == "Failover" and c["code"] == "health" and "1/1" in c["text"], "partial failure: the interface is named", c)
pair[A].health, pair[A].pf = "UP", ""
poll()

# the link between them breaks: both primary
pair[A].hears_peer = pair[B].hears_peer = False
pair[A].role = "Primary"
e = poll()
check(e and e["type"] == "Both nodes primary" and ha_events.explain(e["detail"], [])["code"] == "split",
      "both nodes primary: the heartbeat link", e and e["type"])
pair[A].hears_peer = pair[B].hears_peer = True
pair[A].role = "Secondary"
poll()

# the secondary dies: no failover
pair[A].up = False
e = poll()
c = ha_events.explain(e["detail"], [])
check(e and e["type"] == "Node unreachable" and c["code"] == "heartbeat" and "192.0.2.10" in c["text"],
      "the secondary stops answering: node unreachable, no failover", e and (e["type"], c))
pair[A].up = True
poll()

# after a restart of the dashboard: the roles on disk
ha_events.forget()
pair[A].role, pair[B].role = "Primary", "Secondary"
e = poll()
check(e and e["type"] == "Failover" and e["detail"]["before"]["nodes"][B]["role"] == "Primary",
      "a failover while the dashboard was down is found from the stored roles", e and e["type"])

# reached through another address than the NSIP
snap = ha_events.snapshot({"198.51.100.10": {"reachable": True, "hanode": [pair[A].entry(True), pair[B].entry(False)], "stat": {}}},
                          ["198.51.100.10"])
check(sorted(snap["nodes"]) == ["192.0.2.11", "198.51.100.10"] and snap["nodes"]["198.51.100.10"]["role"] == "Primary",
      "a node reached by another address is not listed twice", sorted(snap["nodes"]))

check(ha_events.explain(None, [])["title"] == "Recorded by an older version", "older events say so")

# ------------------------------------------------------------------ the dashboard
print("-- the dashboard")
import app as dash        # noqa: E402
import db                 # noqa: E402

ha_events.forget()
dash.get_nitro = lambda node_key, instance_id=None: pair[A] if node_key == "primary" else pair[B]
cfg = dash.load_nodes_config()
cfg["instances"][0].update(mode="ha")
cfg["instances"][0]["primary"].update(ip=A, username="nsapi", password="x", protocol="http", port=80)
cfg["instances"][0]["secondary"] = dict(ip=B, username="nsapi", password="x", protocol="http", port=80)
dash.save_nodes_config(cfg)
iid = str(dash.get_instance(None)["id"])
c = dash.app.test_client()
with c.session_transaction() as s:
    s.update(logged_in=True, user="admin", username="admin", must_change_password=False, last_activity=time.time())

pair[A].role, pair[B].role, pair[A].health, pair[A].up = "Primary", "Secondary", "UP", True
check(dash.ha_poll(iid) is None, "app: the first read records nothing")
pair[A].role, pair[B].role, pair[B].master = "Secondary", "Primary", "FORCE CHANGE"
rows = [security.make_row(security.parse_line(force), iid, A)]
db.add_security_events(rows)
r = c.get("/api/failover-history")
j = r.get_json()
ev = (j.get("events") or [{}])[0]
check(r.status_code == 200 and len(j["events"]) == 1 and ev["type"] == "Failover" and isinstance(ev.get("detail"), dict),
      "app: the Failover tab reads the change and records it with the nodes' state", j)
check(ev.get("cause", {}).get("code") == "forced" and ev["reason"] == "Forced failover by nsroot"
      and ev["evidence"] and ev["evidence"][0]["user"] == "nsroot", "app: the reason comes from the appliance's log", ev.get("cause"))
check(json.load(open(dash.HA_STATE_FILE, encoding="utf-8")).get(f"{iid}|{B}") == "Primary", "app: roles kept on disk")
check(len(c.get("/api/failover-history").get_json()["events"]) == 1, "app: read again, not recorded twice")
check(c.get("/api/ha-status").status_code == 200, "app: the HA status still answers")

# a database from an older release gets the new column
import sqlalchemy as sa   # noqa: E402
f = os.path.join(tempfile.mkdtemp(), "old.db")
eng = sa.create_engine("sqlite:///" + f.replace("\\", "/"))
with eng.begin() as cx:
    cx.execute(sa.text('CREATE TABLE nsd_failover_events (id INTEGER PRIMARY KEY, ts_epoch FLOAT NOT NULL, timestamp VARCHAR(64) NOT NULL, '
                       'type VARCHAR(64), reason TEXT, role_change VARCHAR(128), ip VARCHAR(64), instance TEXT)'))
    cx.execute(sa.text("INSERT INTO nsd_failover_events (ts_epoch, timestamp, type, reason, role_change, ip, instance) "
                       "VALUES (1, '2026-01-01T00:00:00', 'Role Change', 'Node HA State Shift', 'PRIMARY -> SECONDARY', '192.0.2.10', 'default')"))
b = db._Backend(eng, "nsd_", "old")
db._init(b)
cols = {x["name"] for x in sa.inspect(eng).get_columns("nsd_failover_events")}
old = db._get_failover(b, None, None)
check("detail" in cols and old and old[0]["detail"] is None and old[0]["type"] == "Role Change",
      "an older database gets the detail column; its events still read", (cols, old))

print(f"\npassed {ok_n}, failed {bad_n}")
sys.exit(1 if bad_n else 0)
