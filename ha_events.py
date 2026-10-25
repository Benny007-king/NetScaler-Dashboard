"""High availability: what each node's role, health and settings were before and
after a change, the appliance's own log lines around it, and why it happened.

Every HA_POLL_SECS the dashboard reads `hanode` (both nodes as each node sees
them) and `stat hanode` (the node's own counters) from every node it reaches,
and compares that with the previous read. A change - a failover, a node that
stopped answering heartbeats, a health failure, an HA setting - becomes one
event with both snapshots. The reason is worked out when the event is shown, so
log lines that arrive a little later (the audit log is read once a minute) are
part of it:

  - an administrator's command (`force ha failover`, `set ha node -hastatus`,
    `reboot`, ...) - CMD_EXECUTED lines name the user, the address and GUI/CLI/API
  - the node's health: partial/complete failure, SSL card, route monitor, INIT
  - heartbeats: the peer saw the node as UNKNOWN; whether the dashboard could
    still reach it tells a dead node from a broken link between the nodes
  - STATECHANGE lines the appliance logs for the self and remote node
"""
import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

logger = logging.getLogger(__name__)


def _env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


POLL_SECS = _env_int("HA_POLL_SECS", 15)          # 0: only when the Failover tab is opened

# Log line kinds kept with the security events (not shown on the Security tab).
HA_KINDS = {"ha_state": "HA state (log)", "ha_command": "Administrator command"}

FAIL_HEALTH = ("PARTIALFAIL", "COMPLETEFAIL", "PARTIALFAILSSL", "ROUTEMONITORFAIL")
HEALTH_TEXT = {
    "UP": "Up", "DISABLED": "HA disabled", "INIT": "Starting (INIT)", "DUMB": "Listen only (DUMB)",
    "PARTIALFAIL": "Partial failure", "COMPLETEFAIL": "Complete failure", "PARTIALFAILSSL": "SSL card failure",
    "ROUTEMONITORFAIL": "Route monitor failure", "DOWN": "Down (no heartbeats)",
}

# ============================================================== log lines
_DEVICE = re.compile(r'Device\s+"(?P<dev>[^"]*)"\s*-\s*State\s+"?(?P<state>[^"\r\n]*)', re.S)
_NODE_DEV = re.compile(r"\b(?P<which>self|remote|peer)\s+node\b\s*(?P<ip>[0-9A-Fa-f][0-9A-Fa-f:.]*)?", re.I)
_CMD = re.compile(r'Command\s+"(?P<cmd>.*)"\s*-\s*Status\s+"(?P<status>[^"]*)"', re.S)
# The commands that change HA roles or take a node away; everything else an
# administrator (or this dashboard) runs is not kept.
HA_COMMAND = re.compile(
    r"^\s*(force\s+(ha\s+)?(failover|sync)|(set|unset|add|rm|enable|disable)\s+ha\b|sync\s+ha\b|reboot\b|"
    r"shutdown\b|install\s+ns\b|(set|enable|disable|reset)\s+interface\b|(set|enable|disable)\s+channel\b|"
    r"(enable|disable|set)\s+cluster\b|force\s+cluster\b)", re.I)


def parse_ns(module, event, body):
    """An HA line from the appliance's log (header already split off), or None."""
    ev = str(event or "").upper()
    body = str(body or "")
    if ev == "CMD_EXECUTED":
        cm = _CMD.search(body)
        if not cm or not HA_COMMAND.match(cm.group("cmd")):
            return None
        user = re.search(r"\bUser\s+(\S+)", body)
        rip = re.search(r"\bRemote_ip\s+(\S+)", body)
        cmd, status = cm.group("cmd").strip(), cm.group("status").strip()
        user, rip = (user.group(1) if user else ""), (rip.group(1) if rip else "")
        return {"kind": "ha_command", "etype": "CMD_EXECUTED", "username": user, "client_ip": rip,
                "message": cmd[:500], "action": status,
                "fields": {"interface": str(module or ""), "command": cmd[:500], "status": status, "user": user,
                           "remote_ip": rip}}
    if str(module or "").upper() == "EVENT":
        d = _DEVICE.search(body)
        if d:
            n = _NODE_DEV.search(d.group("dev"))
            if not n:
                return None                       # a service or virtual server going up/down
            state = d.group("state").strip().strip('"')
            ip = n.group("ip") or ""
            return {"kind": "ha_state", "etype": ev, "client_ip": ip, "action": state[:120],
                    "message": f'{d.group("dev").strip()}: {state}'[:500],
                    "fields": {"device": d.group("dev").strip(), "node": n.group("which").lower(), "node_ip": ip,
                               "state": state}}
    if ev.startswith("HA") or re.search(r"\bheart\s?beat", body, re.I):
        return {"kind": "ha_state", "etype": ev, "message": body.strip()[:500], "fields": {}}
    return None


# ============================================================== reading the nodes
def _first(d, key):
    v = (d or {}).get(key)
    if isinstance(v, list):
        return v[0] if v and isinstance(v[0], dict) else {}
    return v if isinstance(v, dict) else {}


def _why_unreachable(e) -> str:
    name = type(e).__name__
    if "Timeout" in name:
        return "did not answer in time"
    if "ConnectionError" in name or "NewConnectionError" in str(e):
        return "could not be reached (no route, refused or reset)"
    resp = getattr(e, "response", None)
    if resp is not None:
        try:
            msg = (resp.json() or {}).get("message")
        except Exception:
            msg = None
        return f"answered HTTP {resp.status_code}" + (f": {msg}" if msg else "")
    return str(e)[:160] or name


def read_node(nitro, timeout=4) -> dict:
    """hanode (both nodes, as this node sees them) and this node's HA counters."""
    out = {"reachable": False, "error": "", "hanode": [], "stat": {}}
    try:
        r = nitro._get("/config/hanode", custom_timeout=timeout) or {}
        out["hanode"] = [n for n in (r.get("hanode") or []) if isinstance(n, dict)]
        out["reachable"] = True
    except Exception as e:
        out["error"] = _why_unreachable(e)
        return out
    try:
        out["stat"] = _first(nitro._get("/stat/hanode", custom_timeout=timeout), "hanode")
    except Exception:
        pass
    return out


def _role(v) -> str:
    s = str(v or "").strip().upper()
    return {"PRIMARY": "Primary", "SECONDARY": "Secondary", "UNKNOWN": "Unknown"}.get(s, s.title() if s else "")


def _ip_of(n) -> str:
    return str(n.get("ipaddress") or n.get("ip") or "").strip()


def _num(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def snapshot(readings: dict, configured: list, name_of=None) -> dict:
    """readings {ip: read_node()} -> {'at', 'nodes': {ip: {...}}, 'settings': {...}}.
    A node's own answer wins; when it cannot be reached, what its peer says of it."""
    ips = list(dict.fromkeys(configured))
    # A node the dashboard reaches by another address than its NSIP: the appliance
    # calls it by the NSIP (its own entry, id 0).
    alias = {}
    for ip in configured:
        mine = (readings.get(ip) or {}).get("hanode") or []
        if mine and not any(_ip_of(n) == ip for n in mine):
            z = next((n for n in mine if str(n.get("id")) == "0"), None)
            if z and _ip_of(z):
                alias[_ip_of(z)] = ip
    for r in readings.values():
        for n in r.get("hanode") or []:
            if _ip_of(n) and _ip_of(n) not in ips and _ip_of(n) not in alias:
                ips.append(_ip_of(n))
    nodes, settings = {}, {}
    for ip in ips:
        own = readings.get(ip) or {}
        mine = own.get("hanode") or []
        selfe = next((n for n in mine if _ip_of(n) == ip), None) or (
            next((n for n in mine if str(n.get("id")) == "0"), None) if ip in configured else None)
        peer = next((n for pip, r in readings.items() if pip != ip for n in (r.get("hanode") or [])
                     if _ip_of(n) == ip or alias.get(_ip_of(n)) == ip), None)
        st = own.get("stat") or {}
        src = selfe or peer or {}
        if selfe and not settings:
            settings = {"dead_interval": selfe.get("deadinterval"), "hello_interval": selfe.get("hellointerval"),
                        "failsafe": selfe.get("failsafe"), "max_flips": selfe.get("maxflips"),
                        "max_flip_time": selfe.get("maxfliptime"), "inc": selfe.get("inc"),
                        "sync_vlan": selfe.get("syncvlan")}
        role = _role(selfe.get("state") or selfe.get("hacurmasterstate")) if selfe else (
            _role(peer.get("state") or peer.get("hacurmasterstate")) if peer else "")
        node = {
            "ip": ip, "name": (name_of(ip) if name_of else "") or str(src.get("name") or ""),
            "id": src.get("id"), "configured": ip in configured,
            "reachable": bool(own.get("reachable")), "error": own.get("error") or "",
            "role": role,
            "master_state": str(st.get("hacurmasterstate") or "") if selfe else "",
            "health": str((selfe or {}).get("hacurstate") or (st.get("hacurstate") if selfe else "")
                          or (peer or {}).get("hacurstate") or "").upper(),
            "ha_status": str(src.get("hastatus") or "").upper(),
            "sync": str(src.get("hasync") or ""),
            "sync_failure": str(src.get("hasyncfailurereason") or ""),
            "ssl_card": str(src.get("ssl2") or ""),
            "route_monitor": str(src.get("routemonitorstate") or ""),
            "failed_ifaces": str(src.get("pfifaces") or ""),
            "no_traffic_ifaces": str(src.get("ifaces") or ""),
            "disabled_ifaces": str(src.get("disifaces") or ""),
            "hb_off_ifaces": str(src.get("haheartbeatifaces") or ""),
            "time_in_state": _num(src.get("masterstatetime")),
            "transition": str(st.get("transtime") or (selfe or {}).get("transtime") or ""),
            "flips": _num(src.get("curflips")),
            "hb_rx": _num(st.get("hatotpktrx")), "hb_tx": _num(st.get("hatotpkttx")),
            "hb_rx_rate": _num(st.get("hapktrxrate")),
            "sync_failures": _num(st.get("haerrsyncfailure")), "prop_timeouts": _num(st.get("haerrproptimeout")),
            "seen_by_peer": ({"role": _role(peer.get("state") or peer.get("hacurmasterstate")),
                              "health": str(peer.get("hacurstate") or "").upper()} if peer else None),
        }
        nodes[ip] = node
    return {"at": time.time(), "nodes": nodes, "settings": settings}


# ============================================================== changes
def _primaries(snap) -> list:
    return sorted(ip for ip, n in (snap.get("nodes") or {}).items() if n.get("role") == "Primary")


def changes(prev, cur) -> list:
    out = []
    pn, cn = prev.get("nodes") or {}, cur.get("nodes") or {}
    for ip in sorted(set(pn) | set(cn)):
        a, b = pn.get(ip) or {}, cn.get(ip) or {}
        for field, label in (("role", "Role"), ("health", "Health"), ("ha_status", "HA status")):
            x, y = a.get(field) or "", b.get(field) or ""
            if x and y and x != y:
                out.append({"ip": ip, "name": b.get("name") or a.get("name") or "", "field": field, "label": label,
                            "from": x, "to": y})
    return out


def kind_of(prev, cur, ch) -> str:
    pp, cp = _primaries(prev), _primaries(cur)
    roles = [c for c in ch if c["field"] == "role"]
    health = [c for c in ch if c["field"] == "health"]
    if len(cp) > 1 and len(pp) <= 1:
        return "Both nodes primary"
    if pp and cp and set(pp) != set(cp):
        return "Failover"
    if any(c["to"] == "Unknown" for c in roles) or any(c["to"] == "DOWN" for c in health):
        return "Node unreachable"
    if any(c["from"] == "Unknown" for c in roles) or any(c["from"] == "DOWN" for c in health):
        return "Node back"
    if any(c["to"] in FAIL_HEALTH for c in health):
        return "Health failure"
    if any(c["from"] in FAIL_HEALTH and c["to"] == "UP" for c in health):
        return "Health recovered"
    if any(c["field"] == "ha_status" for c in ch):
        return "HA setting changed"
    if health:
        return "Health change"
    return "Role change"


def summary(ch) -> str:
    """Which address became what: '192.0.2.11 Secondary → Primary · 192.0.2.10 Primary → Unknown'."""
    roles = [c for c in ch if c["field"] == "role"] or ch
    parts = []
    for c in roles:
        what = "" if c["field"] == "role" else c["label"].lower() + " "
        parts.append(f'{c["ip"]} {what}{c["from"]} → {c["to"]}')
    return " · ".join(parts)


def _parse_transtime(s, tz):
    s = re.sub(r"\s+", " ", str(s or "").strip())
    for fmt in ("%a %b %d %H:%M:%S %Y", "%b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y:%H:%M:%S"):
        try:
            d = datetime.strptime(s, fmt)
            return d.replace(tzinfo=tz) if tz else d.astimezone()
        except ValueError:
            continue
    return None


def make_event(iid, name, prev, cur, ch, tz=None) -> dict:
    kind = kind_of(prev, cur, ch)
    pp, cp = _primaries(prev), _primaries(cur)
    now = datetime.fromtimestamp(cur["at"], tz) if tz else datetime.fromtimestamp(cur["at"]).astimezone()
    when = now
    # The appliance's own time of the last role change is exact; the dashboard only
    # sees it at its next read.
    since = (prev.get("at") or cur["at"]) - 120
    for ip in (cp or [c["ip"] for c in ch]):
        t = _parse_transtime((cur["nodes"].get(ip) or {}).get("transition"), tz)
        if t and since <= t.timestamp() <= cur["at"] + 60:
            when = t
            break
    detail = {
        "version": 1, "kind": kind, "changes": ch, "old_primary": pp, "new_primary": cp,
        "before": {"at": prev.get("at"), "nodes": prev.get("nodes") or {}, "settings": prev.get("settings") or {}},
        "after": {"at": cur["at"], "nodes": cur["nodes"], "settings": cur.get("settings") or {}},
        "detected_at": now.isoformat(timespec="seconds"),
    }
    cause = explain(detail, [])
    return {"timestamp": when.isoformat(timespec="seconds"), "type": kind, "reason": cause["title"],
            "role_change": summary(ch), "ip": (cp[0] if cp else ch[0]["ip"]), "instance": str(iid),
            "instance_name": name, "detail": detail}


# ============================================================== polling
_last = {}                    # instance id -> last snapshot
_lock = threading.Lock()
_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ha-read")


def poll_instance(iid, name, targets, roles_store: dict, name_of=None, tz=None):
    """Read every node of one HA instance, compare with the last read and return
    the event for a change (or None). targets: [(ip, nitro)]. roles_store keeps
    each node's last role across restarts ({'<instance>|<ip>': role}), updated here."""
    targets = [(str(ip), nit) for ip, nit in targets if ip]
    if not targets:
        return None
    readings = dict(zip([ip for ip, _ in targets], _pool.map(lambda t: read_node(t[1]), targets)))
    cur = snapshot(readings, [ip for ip, _ in targets], name_of)
    iid = str(iid)
    with _lock:
        prev = _last.get(iid)
        if prev is None:          # after a restart: the roles kept on disk
            prefix = iid + "|"
            prev = {"at": None, "settings": {},
                    "nodes": {k[len(prefix):]: {"ip": k[len(prefix):], "role": v} for k, v in roles_store.items()
                              if k.startswith(prefix) and isinstance(v, str)}}
        if not any(n.get("role") for n in cur["nodes"].values()):
            return None           # nothing could be read: compare at the next read
        ch = changes(prev, cur)
        ev = make_event(iid, name, prev, cur, ch, tz) if ch else None
        # A node nobody could say anything about keeps its last known state.
        keep = dict(cur, nodes=dict(cur["nodes"]))
        for ip, n in cur["nodes"].items():
            if not n.get("role") and (prev.get("nodes") or {}).get(ip, {}).get("role"):
                keep["nodes"][ip] = prev["nodes"][ip]
        _last[iid] = keep
        for ip, n in keep["nodes"].items():
            if n.get("role"):
                roles_store[f"{iid}|{ip}"] = n["role"]
    return ev


def forget(iid=None):
    with _lock:
        if iid is None:
            _last.clear()
        else:
            _last.pop(str(iid), None)


def start_watcher(poll_all):
    """poll_all(): one pass over every HA instance."""
    if POLL_SECS <= 0:
        return

    def loop():
        time.sleep(10)
        while True:
            start = time.time()
            try:
                poll_all()
            except Exception as e:
                logger.warning(f"HA watch failed: {e}")
            time.sleep(max(3, POLL_SECS - (time.time() - start)))

    threading.Thread(target=loop, name="ha-watch", daemon=True).start()


# ============================================================== why it happened
def evidence_for(ts, lines, before=180, after=90) -> list:
    """The HA log lines stored around one event, oldest first."""
    out = []
    for r in lines:
        t = r.get("ts") or 0
        if ts - before <= t <= ts + after:
            d = r.get("detail") or {}
            out.append({"ts": t, "node": r.get("node") or "", "kind": r.get("kind"), "etype": r.get("etype") or "",
                        "user": r.get("username") or d.get("user") or "", "from": r.get("client_ip") or "",
                        "interface": d.get("interface") or "", "status": r.get("action") or "",
                        "message": r.get("message") or "", "raw": r.get("raw") or ""})
    out.sort(key=lambda x: x["ts"])
    return out[:40]


def _label(nodes, ip) -> str:
    n = (nodes or {}).get(ip) or {}
    return f'{n["name"]} ({ip})' if n.get("name") else ip


def _ok(status) -> bool:
    return not status or re.match(r"(success|done|ok)", status, re.I) is not None


def _who(e) -> str:
    who = e["user"] or "an administrator"
    via = f' over the {e["interface"]}' if e.get("interface") else ""
    frm = f' from {e["from"]}' if e.get("from") else ""
    return f"{who}{frm}{via}"


def explain(detail, evidence) -> dict:
    """{'code', 'title', 'text', 'notes'} - the most likely reason for the event."""
    detail = detail or {}
    evidence = evidence or []
    after = (detail.get("after") or {}).get("nodes") or {}
    before = (detail.get("before") or {}).get("nodes") or {}
    nodes = {**before, **after}
    kind = detail.get("kind") or ""
    ch = detail.get("changes") or []
    old, new = detail.get("old_primary") or [], detail.get("new_primary") or []
    notes = []
    cmds = [e for e in evidence if e["kind"] == "ha_command" and _ok(e["status"])]

    def cmd(rx):
        return next((e for e in reversed(cmds) if re.search(rx, e["message"], re.I)), None)

    e = cmd(r"^\s*force\s+(ha\s+)?failover")
    if e:
        return {"code": "forced", "title": f'Forced failover by {e["user"] or "an administrator"}',
                "text": f'{_who(e)} ran "{e["message"]}"' + (f' on {e["node"]}' if e["node"] else "") + ".",
                "notes": notes}
    e = cmd(r"^\s*(set|unset)\s+ha\s+node\b.*-hastatus|^\s*(disable|enable)\s+ha\b|^\s*(set|unset)\s+ha\b")
    if e:
        return {"code": "admin_ha", "title": f'HA setting changed by {e["user"] or "an administrator"}',
                "text": f'{_who(e)} ran "{e["message"]}"' + (f' on {e["node"]}' if e["node"] else "") + ".",
                "notes": notes}
    e = cmd(r"^\s*(reboot|shutdown|install\s+ns)\b")
    if e:
        what = "upgraded" if re.match(r"\s*install", e["message"], re.I) else (
            "shut down" if re.match(r"\s*shutdown", e["message"], re.I) else "restarted")
        return {"code": "restart", "title": f'Node {what} by {e["user"] or "an administrator"}',
                "text": f'{_who(e)} ran "{e["message"]}"' + (f' on {e["node"]}' if e["node"] else "") + ".",
                "notes": notes}
    e = cmd(r"^\s*(disable|set|reset)\s+(interface|channel)\b")
    if e:
        return {"code": "admin_iface", "title": f'Interface changed by {e["user"] or "an administrator"}',
                "text": f'{_who(e)} ran "{e["message"]}"' + (f' on {e["node"]}' if e["node"] else "")
                        + " - a monitored interface going down makes the node fail over.", "notes": notes}

    # the nodes this is about: the one that lost the role, or the ones that changed
    affected = [ip for ip in old if ip not in new] or list(dict.fromkeys(c["ip"] for c in ch)) or list(after)
    forced = next((ip for ip in new if "FORCE" in str((after.get(ip) or {}).get("master_state")).upper()), None)
    if forced:
        return {"code": "forced", "title": "Forced failover",
                "text": f"{_label(nodes, forced)} took over by a forced change (force ha failover). Who ran it is not in "
                        "the log lines the dashboard received.", "notes": notes}
    for ip in affected:
        n = after.get(ip) or {}
        h = n.get("health") or ((n.get("seen_by_peer") or {}).get("health") or "")
        who = _label(nodes, ip)
        if h == "PARTIALFAIL":
            ifs = n.get("failed_ifaces") or n.get("no_traffic_ifaces")
            return {"code": "health", "title": "Partial failure - a monitored interface failed",
                    "text": f"{who} reports PARTIALFAIL: a monitored interface or its link went down"
                            + (f" ({ifs})" if ifs else "") + ", so the node gave up the primary role.", "notes": notes}
        if h == "COMPLETEFAIL":
            return {"code": "health", "title": "Complete failure - no monitored interface usable",
                    "text": f"{who} reports COMPLETEFAIL: none of its monitored interfaces can be used.", "notes": notes}
        if h == "PARTIALFAILSSL":
            return {"code": "health", "title": "SSL card failure",
                    "text": f"{who} reports PARTIALFAILSSL: its SSL card failed"
                            + (f' (SSL card {n["ssl_card"]})' if n.get("ssl_card") else "") + ".", "notes": notes}
        if h == "ROUTEMONITORFAIL":
            return {"code": "health", "title": "Route monitor failed",
                    "text": f"{who} reports ROUTEMONITORFAIL: a monitored route is down"
                            + (f' (route monitor {n["route_monitor"]})' if n.get("route_monitor") else "") + ".",
                    "notes": notes}
        if h == "INIT":
            return {"code": "restart", "title": "Node restarted",
                    "text": f"{who} is starting up (INIT) - it was restarted or its HA was re-initialised.",
                    "notes": notes}
        if h == "DISABLED":
            return {"code": "admin_ha", "title": "HA disabled on the node",
                    "text": f"HA is disabled on {who} (disable ha node) - it no longer takes part in failover.",
                    "notes": notes}
    hs = next((c for c in ch if c["field"] == "ha_status"), None)
    if hs:
        return {"code": "admin_ha", "title": f'HA status set to {hs["to"]}',
                "text": f'The HA status of {_label(nodes, hs["ip"])} changed from {hs["from"]} to {hs["to"]} '
                        "(set ha node -hastatus). Who changed it is not in the log lines the dashboard received.",
                "notes": notes}

    if kind == "Both nodes primary":
        return {"code": "split", "title": "Both nodes are primary",
                "text": "Each node acts as primary: they do not hear each other's heartbeats while both are running. "
                        "Check the link between them (heartbeat interfaces, VLAN, UDP port 3003).", "notes": notes}
    if kind == "Node back":
        back = next((c["ip"] for c in ch if c["field"] == "role" and c["from"] == "Unknown"), affected[0] if affected else "")
        return {"code": "recovered", "title": "Heartbeats received again",
                "text": f"{_label(nodes, back)} answers heartbeats again"
                        + (f' and is {after[back]["role"]}' if after.get(back, {}).get("role") else "") + ".",
                "notes": notes}

    settings = (detail.get("after") or {}).get("settings") or {}
    dead = settings.get("dead_interval") or 3
    log_down = next((e for e in evidence if e["kind"] == "ha_state" and re.search(r"\bdown\b|unknown", e["status"] or e["message"], re.I)), None)
    for ip in affected:
        n = after.get(ip) or {}
        peer = n.get("seen_by_peer") or {}
        lost = n.get("role") == "Unknown" or peer.get("role") == "Unknown" or peer.get("health") == "DOWN"
        if not lost and not (log_down and ip in (log_down.get("message") or "")):
            continue
        survivor = next((x for x in new if x != ip), None) or next((x for x in after if x != ip), "")
        b_rx = (before.get(survivor) or {}).get("hb_rx")
        a_rx = (after.get(survivor) or {}).get("hb_rx")
        if b_rx is not None and a_rx is not None and a_rx == b_rx:
            notes.append(f"{_label(nodes, survivor)} received no heartbeat packets since the read before "
                         f"(the counter stayed at {a_rx:,}).")
        if log_down:
            notes.append(f'The appliance logged: {log_down["message"]}')
        if not n.get("reachable") and n.get("configured"):
            return {"code": "heartbeat", "title": "Heartbeats lost - the node stopped answering",
                    "text": f"{_label(nodes, survivor) or 'Its peer'} got no heartbeats from {_label(nodes, ip)} for the "
                            f"dead interval ({dead} s)" + (" and took over as primary" if kind == "Failover" else "")
                            + f". The dashboard cannot reach {ip} either ({n.get('error') or 'no answer'}): it was "
                              "powered off, crashed or restarting, or lost its network.", "notes": notes}
        if n.get("reachable"):
            return {"code": "heartbeat_link", "title": "Heartbeats lost between the nodes",
                    "text": f"{_label(nodes, survivor) or 'Its peer'} got no heartbeats from {_label(nodes, ip)} for the "
                            f"dead interval ({dead} s), but the dashboard still reaches both: the link between the nodes "
                            "(heartbeat interfaces or VLAN, UDP 3003) failed, not the node.", "notes": notes}
        return {"code": "heartbeat", "title": "Heartbeats lost",
                "text": f"{_label(nodes, survivor) or 'Its peer'} got no heartbeats from {_label(nodes, ip)} for the dead "
                        f"interval ({dead} s) and reports it as UNKNOWN.", "notes": notes}

    if kind in ("Health recovered",):
        return {"code": "recovered", "title": "Health back to UP", "text": "The node's health is UP again.",
                "notes": notes}
    if not detail.get("changes"):
        return {"code": "unknown", "title": "Recorded by an older version",
                "text": "This event was recorded before the dashboard kept the nodes' state and the reason.",
                "notes": notes}
    return {"code": "unknown", "title": "Reason not recorded by the appliance",
            "text": "Neither node's HA state shows why, and no log line about it reached the dashboard. "
                    "Send the NetScalers' syslog to the dashboard (with INFO level, for the commands) to see who did what.",
            "notes": notes}
