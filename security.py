"""Security tab: hardening checklist, policy hit counters, and security events
(WAF violations, brute-force blocks, hijack resets, login lines).

Where the data comes from:
  * the checklist and the hit counters are read from the NetScaler over NITRO;
  * events arrive by syslog (the NetScaler sends its audit log here - UDP/TCP
    514), and as a fallback the last lines of the appliance's own audit log are
    read once a minute. Both feed the same store, without duplicates.

Everything here only reads from the NetScalers.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import queue
import re
import socket
import socketserver
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import security_catalog

logger = logging.getLogger("security")


def _env_int(name, default, minimum=0):
    try:
        v = int(str(os.getenv(name, default)).strip().strip("\"'") or default)
    except (TypeError, ValueError):
        return default
    return max(minimum, v)


SYSLOG_PORT = _env_int("SYSLOG_PORT", 514)              # 0 = do not listen
POLL_SECS = _env_int("SECURITY_POLL_SECS", 60)          # 0 = no background reading
_QUEUE_MAX = 20000
_FACTS_TTL = 45


# ============================================================ small helpers
def _norm(text) -> str:
    """A policy rule reduced to compare it: lower case, no spaces, plain quotes."""
    return re.sub(r"\s+", "", str(text or "").replace('\\"', '"')).lower()


def _int(v) -> int:
    try:
        return int(float(str(v).strip()))
    except (TypeError, ValueError):
        return 0


def _yes(v) -> bool:
    return str(v or "").strip().upper() in ("YES", "ENABLED", "ON", "TRUE", "1")


def _list(d, key):
    v = (d or {}).get(key) if isinstance(d, dict) else None
    if isinstance(v, dict):
        return [v]
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


# =================================================================== facts
# (name, NITRO path, key in the answer). Read in parallel; each may fail alone.
_FACT_SOURCES = (
    ("version", "/config/nsversion", "nsversion"),
    ("features", "/config/nsfeature", "nsfeature"),
    ("responder", "/config/responderpolicy", "responderpolicy"),
    ("responder_bind", "/config/responderpolicy_binding?bulkbindings=yes", "responderpolicy_binding"),
    ("appfw", "/config/appfwpolicy", "appfwpolicy"),
    ("appfw_bind", "/config/appfwpolicy_binding?bulkbindings=yes", "appfwpolicy_binding"),
    ("appfw_settings", "/config/appfwsettings", "appfwsettings"),
    ("rw_action", "/config/rewriteaction", "rewriteaction"),
    ("rw_policy", "/config/rewritepolicy", "rewritepolicy"),
    ("rw_bind", "/config/rewritepolicy_binding?bulkbindings=yes", "rewritepolicy_binding"),
    ("msg_action", "/config/auditmessageaction", "auditmessageaction"),
    ("syslog_params", "/config/auditsyslogparams", "auditsyslogparams"),
    ("syslog_action", "/config/auditsyslogaction", "auditsyslogaction"),
    ("syslog_global", "/config/auditsyslogglobal_auditsyslogpolicy_binding", "auditsyslogglobal_auditsyslogpolicy_binding"),
    ("syslog_policy", "/config/auditsyslogpolicy", "auditsyslogpolicy"),
    ("limit", "/config/nslimitidentifier", "nslimitidentifier"),
    ("selector", "/config/streamselector", "streamselector"),
    ("aaa_param", "/config/aaaparameter", "aaaparameter"),
    ("ns_param", "/config/nsparam", "nsparam"),
    ("tcp_param", "/config/nstcpparam", "nstcpparam"),
    ("nsip", "/config/nsip", "nsip"),
    ("vpn_vserver", "/config/vpnvserver", "vpnvserver"),
    ("lb_vserver", "/config/lbvserver?attrs=name,ipv46,port,servicetype", "lbvserver"),
)

_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="sec-facts")
_facts_cache = {}
_facts_lock = threading.Lock()


def collect_facts(nitro, cache_key=None, fresh=False) -> dict:
    """Everything the checklist looks at, read from one node. A source that cannot
    be read is left out and named in facts['errors']."""
    now = time.time()
    if cache_key is not None and not fresh:
        with _facts_lock:
            hit = _facts_cache.get(cache_key)
        if hit and now - hit[0] < _FACTS_TTL:
            return hit[1]

    def one(src):
        name, path, key = src
        try:
            d = nitro._get(path, custom_timeout=6) or {}
            v = d.get(key) if isinstance(d, dict) else None
            return name, (v if v is not None else []), None
        except Exception as e:
            return name, None, str(e)[:160]

    facts, errors = {}, {}
    for name, value, err in _pool.map(one, _FACT_SOURCES):
        if err is None:
            facts[name] = value
        else:
            errors[name] = err
    facts["errors"] = errors
    facts["read_at"] = now
    if cache_key is not None:
        with _facts_lock:
            _facts_cache[cache_key] = (now, facts)
    return facts


def ns_version(facts) -> str:
    """'13.1-49.15' from 'NetScaler NS13.1: Build 49.15.nc, Date: ...'."""
    v = facts.get("version")
    text = (v[0] if isinstance(v, list) and v else v) if v else {}
    text = text.get("version", "") if isinstance(text, dict) else str(text or "")
    m = re.search(r"NS(\d+\.\d+)\s*:\s*Build\s+([\d.]+)", text)
    return f"{m.group(1)}-{m.group(2).rstrip('.')}" if m else ""


def _bindings(rows, policy_key="name") -> dict:
    """policy name -> [{'to': ..., 'priority': ..., 'type': ...}] from a bulk
    *_binding answer (one entry per policy, a list per kind of bind point)."""
    out = {}
    for entry in rows if isinstance(rows, list) else []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get(policy_key) or "")
        for k, v in entry.items():
            if not k.endswith("_binding") or not isinstance(v, list):
                continue
            where = k.split("_", 1)[1].rsplit("_binding", 1)[0]      # vpnvserver, responderglobal, ...
            for b in v:
                if not isinstance(b, dict):
                    continue
                to = str(b.get("boundto") or b.get("labelname") or "").strip()
                if "global" in where and not to:
                    to = "Global"
                out.setdefault(name or str(b.get("name") or ""), []).append({
                    "where": where, "to": to or where,
                    "priority": b.get("priority"),
                    "type": b.get("bindpoint") or b.get("type") or b.get("labeltype") or "",
                    "active": str(b.get("activepolicy", "1")) not in ("0", "false", "False"),
                })
    return out


def _find_policies(facts, kind, names, signatures):
    """Policies of this kind ('responder', 'appfw', 'rw_policy') that are the one
    on the checklist: by its usual name, or - renamed - by what its rule does."""
    found, seen = [], set()
    wanted = {n.lower() for n in names or ()}
    for p in facts.get(kind) or []:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or "")
        rule = _norm(p.get("rule")) + "|" + _norm(p.get("action"))
        by_name = name.lower() in wanted
        sig = next((s for s in (signatures or ()) if all(part in rule for part in s)), None)
        if (by_name or sig) and name not in seen:
            seen.add(name)
            found.append({"name": name, "rule": str(p.get("rule") or ""), "action": str(p.get("action") or ""),
                          "logaction": str(p.get("logaction") or ""),
                          "hits": _int(p.get("hits")), "undefhits": _int(p.get("undefhits")),
                          "by": "name" if by_name else "rule"})
    return found


def _with_bindings(found, bind_map):
    for p in found:
        p["bound"] = bind_map.get(p["name"], [])
    return found


def _describe(p) -> str:
    where = ", ".join(f"{b['to']}" + (f" ({b['type']})" if b.get("type") else "") + (f" #{b['priority']}" if b.get("priority") not in (None, "") else "")
                      for b in p.get("bound", [])) or "not bound"
    renamed = "" if p.get("by") == "name" else " (recognised by its rule)"
    return f"{p['name']}{renamed}: {where}; {p['hits']} hit(s)"


def _result(status, evidence, **kw):
    out = {"status": status, "evidence": [e for e in evidence if e]}
    out.update(kw)
    return out


def _unknown(facts, *names):
    missing = [n for n in names if n in facts.get("errors", {})]
    if missing:
        return _result("unknown", ["Could not read %s from the appliance: %s"
                                   % (", ".join(missing), facts["errors"][missing[0]])])
    return None


# ------------------------------------------------------------ detectors
def _detect_responder(check, facts, extra=None):
    u = _unknown(facts, "responder")
    if u:
        return u
    binds = _bindings(facts.get("responder_bind")) if "responder_bind" in facts else {}
    found = _with_bindings(_find_policies(facts, "responder", check.get("policies"), check.get("signatures")), binds)
    if not found:
        return _result("missing", ["No matching responder policy on this node."], policies=[])
    bound = [p for p in found if p["bound"] or p["hits"]]
    ev = [_describe(p) for p in found]
    if "responder_bind" in facts.get("errors", {}):
        ev.append("Bindings could not be read; a policy with hits counts as bound.")
    status = "configured"
    if not bound:
        status = "partial"
        ev.append("The policy exists but is not bound anywhere, so it does nothing.")
    if extra:
        status, more = extra(status, found)
        ev += more
    return _result(status, ev, policies=found)


def _feature_on(facts, short):
    f = facts.get("features")
    f = f[0] if isinstance(f, list) and f else f
    if not isinstance(f, dict):
        return None
    if short in f:
        return _yes(f.get(short)) or f.get(short) is True
    names = {str(x).upper() for x in (f.get("feature") or [])}
    return short.upper() in names if names else None


def detect_responder(check, facts, ctx):
    return _detect_responder(check, facts)


def detect_login_audit(check, facts, ctx):
    def extra(status, found):
        ev = []
        params = facts.get("syslog_params")
        params = params[0] if isinstance(params, list) and params else params
        on = isinstance(params, dict) and _yes(params.get("userdefinedauditlog"))
        on = on or any(_yes(a.get("userdefinedauditlog")) for a in facts.get("syslog_action") or [] if isinstance(a, dict))
        if "syslog_params" not in facts.get("errors", {}) and not on:
            ev.append("User-defined audit messages are switched off (userDefinedAuditlog NO): "
                      "the policies match but nothing is logged.")
            status = "partial"
        names = {str(a.get("name") or "").lower() for a in facts.get("msg_action") or [] if isinstance(a, dict)}
        for p in found:
            if p["logaction"] and names and p["logaction"].lower() not in names:
                ev.append(f"{p['name']} logs to {p['logaction']}, which does not exist.")
                status = "partial"
        if len(found) < 2:
            ev.append("Only one of the two logging policies (attempt / success) is there.")
            status = "partial"
        return status, ev
    return _detect_responder(check, facts, extra)


def detect_brute_force(check, facts, ctx):
    def extra(status, found):
        ev = []
        limits = {str(x.get("limitidentifier") or x.get("name") or "").lower(): x
                  for x in facts.get("limit") or [] if isinstance(x, dict)}
        sels = {str(x.get("name") or "").lower() for x in facts.get("selector") or [] if isinstance(x, dict)}
        for p in found:
            m = re.search(r'check_limit\(\s*\\?"([^"\\]+)', p["rule"], re.I)
            if not m or "limit" in facts.get("errors", {}):
                continue
            lim = limits.get(m.group(1).lower())
            if lim is None:
                ev.append(f"The limit identifier {m.group(1)} it checks does not exist.")
                status = "partial"
                continue
            sel = str(lim.get("selectorname") or "")
            ev.append(f"Limit {m.group(1)}: {lim.get('threshold', '?')} per "
                      f"{_int(lim.get('timeslice')) // 1000 or '?'} s, selector {sel or 'none'}"
                      f"; {_int(lim.get('hits'))} hit(s), {_int(lim.get('drop'))} drop(s)")
            if sel and "selector" not in facts.get("errors", {}) and sel.lower() not in sels:
                ev.append(f"Its selector {sel} does not exist.")
                status = "partial"
        return status, ev
    return _detect_responder(check, facts, extra)


def detect_malicious_ip(check, facts, ctx):
    def extra(status, found):
        on = _feature_on(facts, "rep")
        if on is False:
            return "partial", ["The Reputation feature is not enabled - the policy never matches."]
        return status, []
    return _detect_responder(check, facts, extra)


def _waf_list(v):
    if isinstance(v, list):
        return [str(x).strip().upper() for x in v if str(x).strip()]
    return [x.upper() for x in re.split(r"[\s,]+", str(v or "")) if x]


def detect_waf(check, facts, ctx):
    u = _unknown(facts, "aaa_param")
    if u:
        return u
    p = _one(facts, "aaa_param")
    if "wafprotection" not in p:
        return _result("unknown", ["This build does not report the built-in WAF protection (aaa parameter wafProtection)."])
    have = _waf_list(p.get("wafprotection"))
    ev = ["aaa parameter wafProtection = " + (" ".join(have) or "(empty)")]
    scopes = {s: s.upper() in have for s in ("AUTH", "VPN", "PORTAL")}
    # WAF policies of your own, for their hit counters
    binds = _bindings(facts.get("appfw_bind")) if "appfw_bind" in facts else {}
    policies = [{"name": str(x.get("name") or ""), "rule": str(x.get("rule") or ""), "hits": _int(x.get("hits")),
                 "undefhits": _int(x.get("undefhits")), "bound": binds.get(str(x.get("name") or ""), []), "by": "name"}
                for x in facts.get("appfw") or [] if isinstance(x, dict) and x.get("name")]
    if all(scopes.values()):
        return _result("configured", ev, scopes=scopes, policies=policies)
    if "DISABLED" in have:
        return _result("missing", ev + ["The built-in WAF protection is switched off."], scopes=scopes, policies=policies)
    if "DEFAULT" in have and not any(scopes.values()):
        return _result("partial", ev + ["DEFAULT leaves the choice to the build - list AUTH VPN PORTAL to be sure all three are covered."],
                       scopes=scopes, policies=policies)
    missing = [k for k, on in scopes.items() if not on]
    return _result("partial" if any(scopes.values()) else "missing", ev + ["Not covered: " + ", ".join(missing)],
                   scopes=scopes, policies=policies)


def detect_max_aaa_users(check, facts, ctx):
    u = _unknown(facts, "aaa_param")
    if u:
        return u
    p = _one(facts, "aaa_param")
    if "maxaaausers" not in p:
        return _result("unknown", ["The appliance did not report maxAAAUsers."])
    v = _int(p.get("maxaaausers"))
    return _result("configured" if v >= 4294967295 else "missing", [f"aaa parameter maxAAAUsers = {p.get('maxaaausers')}"])


def detect_csp(check, facts, ctx):
    u = _unknown(facts, "rw_action", "rw_policy")
    if u:
        return u
    actions = [a for a in facts.get("rw_action") or [] if isinstance(a, dict)
               and "content-security-policy" in str(a.get("target") or "").lower()]
    names = {str(a.get("name") or "").lower() for a in actions}
    if not actions:
        return _result("missing", ["No rewrite action sets a Content-Security-Policy header."], policies=[])
    binds = _bindings(facts.get("rw_bind")) if "rw_bind" in facts else {}
    pols = []
    for p in facts.get("rw_policy") or []:
        if isinstance(p, dict) and str(p.get("action") or "").lower() in names:
            name = str(p.get("name") or "")
            pols.append({"name": name, "rule": str(p.get("rule") or ""), "action": str(p.get("action") or ""),
                         "hits": _int(p.get("hits")), "undefhits": _int(p.get("undefhits")),
                         "bound": binds.get(name, []), "by": "rule"})
    ev = [f"Rewrite action {a.get('name')}: {str(a.get('stringbuilderexpr') or '')[:160]}" for a in actions]
    ev += [_describe(p) for p in pols]
    if not pols:
        return _result("partial", ev + ["No rewrite policy uses it."], policies=[])
    if not any(p["bound"] or p["hits"] for p in pols):
        return _result("partial", ev + ["The policy is not bound."], policies=pols)
    if _feature_on(facts, "rewrite") is False:
        return _result("partial", ev + ["The Rewrite feature is not enabled."], policies=pols)
    return _result("configured", ev, policies=pols)


def _one(facts, key):
    v = facts.get(key)
    return v[0] if isinstance(v, list) and v else (v if isinstance(v, dict) else {})


def detect_httponly(check, facts, ctx):
    u = _unknown(facts, "aaa_param")
    if u:
        return u
    p = _one(facts, "aaa_param")
    if "httponlycookie" not in p:
        return _result("unknown", ["This build does not report the HttpOnly setting (it needs 13.1-37 or later)."])
    v = str(p.get("httponlycookie"))
    return _result("configured" if _yes(v) else "missing", [f"aaa parameter httpOnlyCookie = {v}"])


def detect_cookie_v1(check, facts, ctx):
    u = _unknown(facts, "ns_param")
    if u:
        return u
    v = str(_one(facts, "ns_param").get("cookieversion", ""))
    if not v:
        return _result("unknown", ["The appliance did not report cookieversion."])
    return _result("configured" if v.strip() == "1" else "missing", [f"ns param cookieversion = {v}"])


def detect_tcp_isn(check, facts, ctx):
    u = _unknown(facts, "tcp_param")
    if u:
        return u
    p = _one(facts, "tcp_param")
    if "enhancedisngeneration" not in p:
        return _result("unknown", ["This build does not have the enhancedISNgeneration TCP setting."])
    v = str(p.get("enhancedisngeneration"))
    return _result("configured" if _yes(v) else "missing", [f"ns tcpparam enhancedISNgeneration = {v}"])


def detect_mgmt_secure(check, facts, ctx):
    u = _unknown(facts, "nsip")
    if u:
        return u
    rows = [x for x in facts.get("nsip") or [] if isinstance(x, dict)
            and (str(x.get("type") or "").upper() == "NSIP" or _yes(x.get("mgmtaccess")))]
    if not rows:
        return _result("unknown", ["No management address was returned."])
    ev, bad = [], 0
    for x in rows:
        gui = str(x.get("gui") or "").upper()
        ok = gui in ("SECUREONLY", "DISABLED")
        bad += not ok
        ev.append(f"{x.get('ipaddress')} ({x.get('type')}): gui {gui or '?'}")
    if ctx.get("node_protocol", "").lower() == "http":
        ev.append("This dashboard reaches the node over HTTP - switch it to HTTPS in Settings before (or after) "
                  "making management secure-only.")
    return _result("configured" if not bad else "missing", ev)


def detect_syslog(check, facts, ctx):
    ev = []
    mine = ctx.get("dashboard_addresses") or set()
    target = None
    for a in facts.get("syslog_action") or []:
        if not isinstance(a, dict):
            continue
        ip = str(a.get("serverip") or a.get("serverdomainname") or "")
        if ip in mine:
            target = a
            ev.append(f"Syslog action {a.get('name')} sends to {ip}:{a.get('serverport', 514)} "
                      f"({a.get('transport', 'UDP')}, levels {a.get('loglevel', '?')})")
    recv = ctx.get("received") or {}
    if recv.get("last"):
        ev.append(f"Last message from this node received {int(time.time() - recv['last'])} s ago "
                  f"({recv.get('count', 0)} since the dashboard started).")
        return _result("configured", ev)
    if target is not None:
        ev.append("Nothing received from this node yet - check that the syslog policy is bound globally and "
                  "that UDP 514 is open between them.")
        return _result("partial", ev)
    if "syslog_action" in facts.get("errors", {}):
        return _result("unknown", ["Could not read the syslog servers; nothing received from this node yet."])
    return _result("missing", ev + ["No syslog server on this node points at this dashboard."])


DETECTORS = {
    "responder": detect_responder, "login_audit": detect_login_audit, "brute_force": detect_brute_force,
    "malicious_ip": detect_malicious_ip, "waf": detect_waf, "csp": detect_csp, "httponly": detect_httponly,
    "cookie_v1": detect_cookie_v1, "tcp_isn": detect_tcp_isn, "mgmt_secure": detect_mgmt_secure,
    "syslog": detect_syslog, "max_aaa_users": detect_max_aaa_users,
}


def evaluate(facts, ctx=None) -> list:
    """The checklist with what was found on the appliance for each entry."""
    ctx = ctx or {}
    version = ns_version(facts)
    out = []
    for c in security_catalog.CHECKS:
        try:
            r = DETECTORS[c["detect"]](c, facts, ctx)
        except Exception as e:                       # one bad answer must not break the list
            logger.warning(f"Security check {c['id']} failed: {e}")
            r = _result("unknown", [f"Could not be checked: {e}"])
        variants = c.get("variants") or []
        pick = 0
        for i, v in enumerate(variants):
            if v.get("match") and version and re.match(v["match"], version):
                pick = i
                break
        out.append({
            "id": c["id"], "group": c["group"], "title": c["title"], "summary": c["summary"],
            "about": c["about"], "notes": c.get("notes", []), "optional": bool(c.get("optional")),
            "variants": [{"label": v["label"], "commands": [{"title": t, "text": x} for t, x in v["commands"]]}
                         for v in variants],
            "variant": pick, **r,
        })
    return out


def policy_hits(checks) -> list:
    """Hit counters of every policy the checklist found, for the activity view."""
    rows = []
    for c in checks:
        for p in c.get("policies") or []:
            rows.append({"check": c["id"], "title": c["title"], "policy": p["name"], "hits": p.get("hits", 0),
                         "undefhits": p.get("undefhits", 0),
                         "bound": ", ".join(b["to"] for b in p.get("bound") or []) or "not bound"})
    return rows


# ================================================================ events
_NS_STAMP = re.compile(r"(\d{2})/(\d{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([A-Z]{2,5}))?")
_NS_HEAD = re.compile(
    r"(?P<stamp>\d{2}/\d{2}/\d{4}:\d{2}:\d{2}:\d{2})(?:\s+(?P<tz>[A-Z]{2,5}))?\s+(?P<host>\S+)\s+"
    r"(?P<ppe>\d+-PPE-\d+)\s*:\s*(?:(?P<part>[a-z][\w.-]*)\s+)?(?P<module>[A-Z][A-Z0-9_]*)\s+"
    r"(?P<event>[A-Z][A-Za-z0-9_]*)(?:\s+(?P<seq>\d+)\s+(?P<x>\d+))?\s*:\s*(?P<body>.*)$", re.S)
_APPFW_BODY = re.compile(
    r"^(?P<ip>[0-9A-Fa-f:.]+)\s+(?P<tx>\S+)\s+(?P<sess>\S+)\s+(?P<profile>\S+)\s+(?P<url>\S+)\s+"
    r"(?P<msg>.*?)\s*<(?P<act>[^<>]{1,40})>\s*$", re.S)
_CEF = re.compile(r"CEF:\s*\d+\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<ver>[^|]*)\|(?P<module>[^|]*)\|"
                  r"(?P<event>[^|]*)\|(?P<sev>[^|]*)\|(?P<ext>.*)$", re.S)
_CEF_KV = re.compile(r"(\w+)=((?:\\=|[^=])*?)(?=\s+\w+=|\s*$)", re.S)
_SIG = re.compile(r"rule\s+ID\s+(\d+)\s*:?\s*([\w-]+)?", re.I)

KINDS = {
    "waf": "WAF violation", "bot": "Bot", "brute_force": "Brute-force block",
    "cookie_hijack": "Session hijack reset", "login_failed": "Failed login", "lockout": "Account locked",
    "login": "Login", "login_attempt": "Login attempt",
    "vpn_login": "Gateway session start", "vpn_logout": "Gateway session end",
    "ica_start": "Application start", "ica_end": "Application end", "policy": "Policy log",
}
# Shown on the Security tab; the rest describe sessions and feed the Sessions tab.
SECURITY_KINDS = ("waf", "bot", "brute_force", "cookie_hijack", "login_failed", "lockout")
SESSION_KINDS = ("vpn_login", "vpn_logout", "ica_start", "ica_end", "login", "login_attempt",
                 "login_failed", "lockout")

# "Key value - Key value - ..." as the Gateway writes its session lines. A value
# may be quoted, and contain spaces.
_DASH_SPLIT = re.compile(r"\s+-\s+(?=[A-Za-z][\w()]*(?::[\w()]+)?:?\s)")


def _dash_fields(body) -> dict:
    out = {}
    for part in _DASH_SPLIT.split(body.strip()):
        part = part.strip()
        if not part:
            continue
        key, _, value = part.partition(" ")
        key = key.rstrip(":").lower()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        if key and key not in out:
            out[key] = value
    return out


def _gw_time(text, received):
    m = _NS_STAMP.search(str(text or ""))
    return _stamp_epoch(m, received) if m else None


def _session_line(event, body, received):
    """SSLVPN LOGIN / LOGOUT / ICASTART / ICAEND_CONNSTAT and AAA failures."""
    ev = event.upper()
    f = _dash_fields(body)
    user = f.get("user") or ""
    if not user and "username:domainname" in f:
        user = f["username:domainname"].split(":", 1)[0]
    if not user and f.get("context"):
        user = f["context"].rsplit("@", 1)[0]
    client = f.get("client_ip") or (f.get("source") or "").rsplit(":", 1)[0]
    if not client and f.get("context") and "@" in f["context"]:
        client = f["context"].rsplit("@", 1)[1]
    sid = (f.get("sessionid") or "").strip()
    common = {"username": user[:255], "client_ip": client[:64], "session": sid}
    detail = {k: v[:500] for k, v in f.items()}
    if ev == "LOGIN":
        return dict(common, kind="vpn_login", etype="SSLVPN_LOGIN", url=f.get("vserver", ""),
                    message="Gateway session started", fields=detail)
    if ev == "LOGOUT":
        start = _gw_time(f.get("start_time"), received)
        if start:
            detail["start_epoch"] = str(start)
        return dict(common, kind="vpn_logout", etype="SSLVPN_LOGOUT", url=f.get("vserver", ""),
                    action=f.get("logoutmethod", ""), message="Gateway session ended", fields=detail)
    if ev == "ICASTART":
        return dict(common, kind="ica_start", etype="ICA_START", url=f.get("destination", ""),
                    message=f.get("applicationname") or "ICA connection started", fields=detail)
    if ev.startswith("ICAEND"):
        start = _gw_time(f.get("starttime"), received)
        if start:
            detail["start_epoch"] = str(start)
        return dict(common, kind="ica_end", etype="ICA_END", url=f.get("destination", ""),
                    message=f.get("applicationname") or "ICA connection ended", fields=detail)
    low = body.lower()
    if "lock" in ev.lower() or re.search(r"account\s+(?:is\s+|has\s+been\s+)?locked|locked\s*out", low):
        return dict(common, kind="lockout", etype=ev, message=(f.get("failure_reason") or body)[:400], fields=detail)
    if "FAIL" in ev or "failure_reason" in f:
        return dict(common, kind="login_failed", etype=ev, action="refused",
                    message=(f.get("failure_reason") or "Login failed")[:400], fields=detail)
    return None


_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
                                         "Nov", "Dec"), 1)}
_SYSLOG_STAMP = re.compile(r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b")


def _closest(dt, received):
    """A time written without a zone: read as UTC or as local time, whichever is
    nearer to when it arrived; neither within two days -> when it arrived."""
    best = None
    for ts in (dt.replace(tzinfo=timezone.utc).timestamp(), dt.timestamp()):
        if abs(ts - received) < 2 * 86400 and (best is None or abs(ts - received) < abs(best - received)):
            best = ts
    return received if best is None else best


def _syslog_epoch(text, received):
    """The 'Oct 16 10:12:01' header of a syslog line (it has no year)."""
    m = _SYSLOG_STAMP.search(text or "")
    if not m:
        return received
    year = datetime.fromtimestamp(received, timezone.utc).year
    try:
        dt = datetime(year, _MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
    except ValueError:
        return received
    ts = _closest(dt, received)
    if ts == received and m.group(1) == "Dec":       # a line from late December read in January
        try:
            ts = _closest(dt.replace(year=year - 1), received)
        except ValueError:
            pass
    return ts


def _stamp_epoch(m, received):
    """NetScaler writes MM/DD/YYYY by default (DD/MM/YYYY when configured so)."""
    a, b, y, hh, mm, ss = (int(m.group(i)) for i in range(1, 7))
    month, day = (a, b) if a <= 12 else (b, a)
    try:
        dt = datetime(y, month, day, hh, mm, ss)
    except ValueError:
        return received
    tz = (m.group(7) or "").upper()
    if tz in ("GMT", "UTC"):
        ts = dt.replace(tzinfo=timezone.utc).timestamp()
        # a clock far off (or a misread day/month) is less useful than the time it arrived
        return ts if abs(ts - received) < 2 * 86400 else received
    return _closest(dt, received)


def _pipe_fields(text) -> dict:
    out = {}
    for part in re.split(r"\s+\|\s+", text):
        k, sep, v = part.partition(":")
        if sep and 0 < len(k.strip()) <= 30:
            out[k.strip().lower()] = v.strip()
    return out


def _custom(body):
    """The messages written by the checklist's own policies."""
    text = body.strip().strip('"').strip()
    low = text.lower()
    if low.startswith("ica gateway login success"):
        f = _pipe_fields(text)
        return {"kind": "login", "etype": "LOGIN_SUCCESS", "client_ip": f.get("client ip", ""),
                "username": f.get("user", ""), "session": f.get("session id", ""),
                "url": f.get("gateway fqdn", ""), "message": "Successful login (or a refresh of the session)",
                "fields": f}
    if low.startswith("gateway login attempt"):
        f = _pipe_fields(text)
        return {"kind": "login_attempt", "etype": "LOGIN_ATTEMPT", "client_ip": f.get("source ip", ""),
                "username": f.get("username", ""), "url": f.get("gateway", ""), "message": "Login attempt",
                "fields": f}
    m = re.search(r"detected from\s+(\S+)\s+to\s+(\S+)\s+(\S+)", text)
    if "possible brute force" in low:
        return {"kind": "brute_force", "etype": "BRUTE_FORCE_BLOCK", "client_ip": m.group(1) if m else "",
                "url": (m.group(2) + m.group(3)) if m else "", "action": "dropped", "message": text[:400],
                "fields": {"host": m.group(2) if m else "", "path": m.group(3) if m else ""}}
    if "possible session cookie hijack" in low:
        return {"kind": "cookie_hijack", "etype": "COOKIE_HIJACK_RESET", "client_ip": m.group(1) if m else "",
                "url": (m.group(2) + m.group(3)) if m else "", "action": "reset", "message": text[:400],
                "fields": {"host": m.group(2) if m else "", "path": m.group(3) if m else ""}}
    return None


def parse_line(line, received=None):
    """One audit/syslog line -> an event dict, or None for lines that are not
    security events (the appliance sends many other kinds)."""
    received = received or time.time()
    line = str(line or "").strip()
    if not line:
        return None
    c = _CEF.search(line)
    if c:
        ext = {k.lower(): v.replace("\\=", "=").replace("\\|", "|").strip() for k, v in _CEF_KV.findall(c.group("ext"))}
        module, event = c.group("module").strip().upper(), c.group("event").strip()
        if module not in ("APPFW", "BOT"):
            return None
        m = _NS_STAMP.search(line[:c.start()])
        ts = _stamp_epoch(m, received) if m else _syslog_epoch(line[:c.start()], received)
        msg = ext.get("msg", "")
        sig = _SIG.search(msg) if "SIGNATURE" in event.upper() else None
        fields = {"method": ext.get("method", ""), "client_port": ext.get("spt", ""),
                  "geolocation": ext.get("geolocation", ""), "event_id": ext.get("cn1", ""),
                  "transaction_id": ext.get("cn2", ""), "ppe": ext.get("cs2", ""),
                  "severity": ext.get("cs4", "") or c.group("sev"), "signature_category": ext.get("cs6", ""),
                  "product_version": c.group("ver")}
        if sig:
            fields["signature_id"] = sig.group(1)
            fields["signature_category"] = fields["signature_category"] or (sig.group(2) or "")
        return {
            "ts": ts, "kind": "waf" if module == "APPFW" else "bot", "etype": event,
            "client_ip": ext.get("src", ""), "url": ext.get("request", ""), "profile": ext.get("cs1", ""),
            "action": ext.get("act", ""), "message": msg, "session": ext.get("cs3", ""), "username": ext.get("suser", ""),
            "fields": {k: v for k, v in fields.items() if v},
            "key": "cef|%s|%s|%s|%s|%s" % (event, ext.get("cn1", ""), ext.get("cn2", ""), ext.get("cs2", ""),
                                           ext.get("src", "") if not ext.get("cn1") else ""),
            "raw": line[c.start():][:4000],
        }
    h = _NS_HEAD.search(line)
    if not h:
        cust = _custom(line)
        if cust:
            cust.update(ts=received, key="txt|" + hashlib.sha1(line.encode("utf-8", "replace")).hexdigest(), raw=line[:4000])
        return cust
    module, event, body = h.group("module"), h.group("event"), h.group("body")
    ts = _stamp_epoch(_NS_STAMP.match(h.group("stamp") + ((" " + h.group("tz")) if h.group("tz") else "")), received)
    key = "ns|%s|%s|%s|%s|%s" % (h.group("stamp"), h.group("host"), h.group("ppe"), event, h.group("seq"))
    base = {"ts": ts, "key": key, "raw": line[h.start():][:4000],
            "fields": {"appliance": h.group("host"), "ppe": h.group("ppe"), "module": module, "sequence": h.group("seq")}}
    if module in ("APPFW", "BOT"):
        b = _APPFW_BODY.match(body.strip())
        if b:
            msg = b.group("msg").strip()
            sig = _SIG.search(msg) if "SIGNATURE" in event.upper() else None
            fm = re.search(r"\bfield\s+\"?([^\s\"=]+)", msg, re.I)
            fields = {"transaction_id": b.group("tx")}
            if sig:
                fields.update(signature_id=sig.group(1), signature_category=sig.group(2) or "")
            if fm:
                fields["field"] = fm.group(1)
            base["fields"].update(fields)
            sess = b.group("sess")
            base.update(kind="waf" if module == "APPFW" else "bot", etype=event, client_ip=b.group("ip"),
                        url=b.group("url"), profile=b.group("profile"), action=b.group("act").strip(),
                        message=msg[:1000], session="" if sess in ("-", "") else sess)
        else:
            base.update(kind="waf" if module == "APPFW" else "bot", etype=event, message=body.strip()[:1000])
        return base
    if module in ("SSLVPN", "AAA", "AAATM"):
        sl = _session_line(event, body, received)
        if sl is not None:
            fields = dict(base["fields"])
            fields.update(sl.pop("fields", {}))
            base.update(sl)
            base["fields"] = fields
            return base
    cust = _custom(body)
    if cust:
        fields = dict(base["fields"])
        fields.update(cust.pop("fields", {}))
        base.update(cust)
        base["fields"] = fields
        return base
    return None


# ========================================================== event store glue
class _Ingest:
    """Events from every source go through one queue into the store, in batches."""

    def __init__(self):
        self.q = queue.Queue(maxsize=_QUEUE_MAX)
        self.dropped = 0
        self.started = False
        self.store = None                 # callable(list of rows) -> int
        self.lock = threading.Lock()

    def put(self, row):
        try:
            self.q.put_nowait(row)
        except queue.Full:
            self.dropped += 1

    def start(self, store):
        with self.lock:
            self.store = store
            if self.started:
                return
            self.started = True
        threading.Thread(target=self._loop, name="security-store", daemon=True).start()

    def _loop(self):
        while True:
            batch = [self.q.get()]
            deadline = time.time() + 1.0
            while len(batch) < 500:
                left = deadline - time.time()
                if left <= 0:
                    break
                try:
                    batch.append(self.q.get(timeout=left))
                except queue.Empty:
                    break
            try:
                self.store(batch)
            except Exception as e:
                logger.warning(f"Could not store {len(batch)} security event(s): {e}")


ingest = _Ingest()


def make_row(ev, instance, node):
    fields = ev.get("fields") or {}
    key = hashlib.sha1(("%s|%s" % (node, ev.get("key") or ev.get("raw") or "")).encode("utf-8", "replace")).hexdigest()
    return {
        "instance": str(instance), "node": str(node or ""), "ts_epoch": float(ev.get("ts") or time.time()),
        "kind": ev.get("kind") or "policy", "etype": ev.get("etype") or "", "client_ip": ev.get("client_ip") or "",
        "url": ev.get("url") or "", "profile": ev.get("profile") or "", "action": ev.get("action") or "",
        "username": ev.get("username") or "", "session": ev.get("session") or "",
        "message": ev.get("message") or "", "detail": json.dumps(fields, ensure_ascii=False),
        "raw": ev.get("raw") or "", "ev_key": key,
    }


# ================================================================ syslog
class _Receiver:
    def __init__(self):
        self.port = SYSLOG_PORT
        self.listening = {"udp": False, "tcp": False}
        self.error = ""
        self.received = 0
        self.accepted = 0
        self.ignored = 0
        self.rejected = {}                # sender -> [count, last]
        self.by_sender = {}               # sender -> {'count', 'last'}
        self.resolve = lambda ip: None    # sender ip -> instance id
        self.lock = threading.Lock()

    def handle(self, data: bytes, sender: str):
        now = time.time()
        with self.lock:
            self.received += 1
        inst = self.resolve(sender)
        if inst is None:
            with self.lock:
                rec = self.rejected.setdefault(sender, [0, 0])
                rec[0] += 1
                rec[1] = now
                if len(self.rejected) > 50:
                    self.rejected.pop(min(self.rejected, key=lambda k: self.rejected[k][1]))
            return
        with self.lock:
            s = self.by_sender.setdefault(sender, {"count": 0, "last": 0})
            s["count"] += 1
            s["last"] = now
        text = data.decode("utf-8", "replace")
        ev = parse_line(text, now)
        if ev is None:
            with self.lock:
                self.ignored += 1
            return
        with self.lock:
            self.accepted += 1
        ingest.put(make_row(ev, inst, sender))

    def status(self):
        with self.lock:
            return {
                "port": self.port, "listening": dict(self.listening), "error": self.error,
                "received": self.received, "accepted": self.accepted, "not_security": self.ignored,
                "queue_dropped": ingest.dropped,
                "rejected": [{"sender": k, "count": v[0], "last": v[1]}
                             for k, v in sorted(self.rejected.items(), key=lambda kv: -kv[1][1])[:10]],
                "senders": {k: dict(v) for k, v in self.by_sender.items()},
            }


receiver = _Receiver()


class _UDP(socketserver.UDPServer):
    # One thread reads every datagram: handling one is quick (parse, queue), and a
    # thread per datagram would mean thousands of them during an attack.
    allow_reuse_address = True
    max_packet_size = 65535


class _TCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 16


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        receiver.handle(self.request[0], self.client_address[0])


class _TCPHandler(socketserver.StreamRequestHandler):
    timeout = 300

    def handle(self):
        sender = self.client_address[0]
        if receiver.resolve(sender) is None:
            receiver.handle(b"", sender)                  # counted as rejected; do not read from it
            return
        buf = b""
        while True:
            try:
                chunk = self.request.recv(65536)
            except OSError:
                return
            if not chunk:
                break
            buf += chunk
            while True:
                m = re.match(rb"(\d{1,6}) ", buf)         # RFC 6587 octet counting
                if m and len(buf) >= m.end() + int(m.group(1)):
                    n = int(m.group(1))
                    receiver.handle(buf[m.end():m.end() + n], sender)
                    buf = buf[m.end() + n:]
                    continue
                if m:
                    break
                nl = buf.find(b"\n")
                if nl < 0:
                    break
                line, buf = buf[:nl], buf[nl + 1:]
                if line.strip():
                    receiver.handle(line, sender)
            if len(buf) > 65536:
                receiver.handle(buf[:65536], sender)
                buf = b""
        if buf.strip():
            receiver.handle(buf, sender)


def start_receiver(resolve):
    receiver.resolve = resolve
    if not SYSLOG_PORT:
        receiver.error = "turned off (SYSLOG_PORT=0)"
        return
    for proto, cls, handler in (("udp", _UDP, _UDPHandler), ("tcp", _TCP, _TCPHandler)):
        try:
            srv = cls(("0.0.0.0", SYSLOG_PORT), handler)
        except OSError as e:
            receiver.error = f"cannot listen on {proto.upper()} {SYSLOG_PORT}: {e}"
            logger.warning(f"Syslog receiver: {receiver.error}")
            continue
        receiver.listening[proto] = True
        threading.Thread(target=srv.serve_forever, name=f"syslog-{proto}", daemon=True).start()
    if any(receiver.listening.values()):
        logger.info(f"Syslog receiver listening on port {SYSLOG_PORT} "
                    f"({', '.join(p.upper() for p, on in receiver.listening.items() if on)})")


# ================================================== background reading
class _Series:
    """Hit counters sampled over time, per (instance, node, policy). Kept in memory:
    the counters themselves live on the NetScaler; this only adds the trend."""

    def __init__(self, keep=1440):
        self.data = {}
        self.keep = keep
        self.lock = threading.Lock()

    def add(self, instance, node, values: dict, ts=None):
        ts = ts or time.time()
        with self.lock:
            for name, v in values.items():
                d = self.data.setdefault((str(instance), str(node), name), deque(maxlen=self.keep))
                d.append((ts, int(v)))

    def trend(self, instance, names, since):
        """Per policy: increase in each sample interval since `since`, summed over
        nodes. A counter that went down (a reboot, a failover) restarts from it."""
        out = {}
        with self.lock:
            for (inst, node, name), d in self.data.items():
                if inst != str(instance) or name not in names:
                    continue
                pts = list(d)
                series = out.setdefault(name, {})
                for (t0, v0), (t1, v1) in zip(pts, pts[1:]):
                    if t1 < since:
                        continue
                    inc = v1 - v0 if v1 >= v0 else v1
                    bucket = int(t1 // 60) * 60
                    series[bucket] = series.get(bucket, 0) + inc
        return {n: sorted(s.items()) for n, s in out.items()}


series = _Series()


def sample_counts(checks) -> dict:
    vals = {}
    for c in checks:
        for p in c.get("policies") or []:
            vals[p["name"]] = p.get("hits", 0)
    return vals


def read_audit_messages(nitro):
    """The appliance's own recent audit lines (at most 256)."""
    d = nitro._get("/config/auditmessages?args=loglevel:ALL,numofmesgs:256", custom_timeout=8) or {}
    return [str(it.get("value", "")) if isinstance(it, dict) else str(it) for it in (d.get("auditmessages") or [])]


def start_poller(targets, on_facts):
    """targets() -> [(instance_id, node_key, node_ip, nitro)]; on_facts(instance,
    node_key, facts) stores what the checklist needs. Runs every POLL_SECS."""
    if not POLL_SECS:
        return

    def loop():
        time.sleep(15)
        while True:
            start = time.time()
            try:
                for inst, node_key, ip, nitro in targets():
                    try:
                        for line in read_audit_messages(nitro):
                            ev = parse_line(line, time.time())
                            if ev is not None:
                                ingest.put(make_row(ev, inst, ip))
                    except Exception as e:
                        logger.debug(f"audit messages from {ip}: {e}")
                    try:
                        on_facts(inst, node_key, ip, nitro)
                    except Exception as e:
                        logger.debug(f"security counters from {ip}: {e}")
            except Exception as e:
                logger.warning(f"Security poll failed: {e}")
            time.sleep(max(5, POLL_SECS - (time.time() - start)))

    threading.Thread(target=loop, name="security-poll", daemon=True).start()


# ============================================================ aggregates
def summarise(events, since, bucket_secs) -> dict:
    """Counts for the activity charts."""
    by_kind, by_type, by_ip, by_url, by_profile, by_action = {}, {}, {}, {}, {}, {}
    timeline = {}
    for e in events:
        k = e.get("kind") or "policy"
        by_kind[k] = by_kind.get(k, 0) + 1
        if k in ("waf", "bot"):
            by_type[e.get("etype") or "?"] = by_type.get(e.get("etype") or "?", 0) + 1
            if e.get("url"):
                u = str(e["url"]).split("?", 1)[0][:200]
                by_url[u] = by_url.get(u, 0) + 1
            if e.get("profile"):
                by_profile[e["profile"]] = by_profile.get(e["profile"], 0) + 1
            a = (e.get("action") or "?").lower()
            by_action[a] = by_action.get(a, 0) + 1
        if e.get("client_ip") and k not in ("login",):
            by_ip[e["client_ip"]] = by_ip.get(e["client_ip"], 0) + 1
        b = int((e.get("ts") or 0) // bucket_secs) * bucket_secs
        if b >= since - bucket_secs:
            row = timeline.setdefault(b, {})
            row[k] = row.get(k, 0) + 1

    def top(d, n=10):
        return [{"name": k, "count": v} for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:n]]
    return {"by_kind": by_kind, "by_type": top(by_type, 15), "top_ips": top(by_ip), "top_urls": top(by_url),
            "by_profile": top(by_profile), "by_action": by_action,
            "timeline": [{"t": t, **v} for t, v in sorted(timeline.items())], "bucket": bucket_secs}


def own_addresses() -> set:
    """Addresses of this machine, to recognise a syslog server pointing here."""
    out = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            out.add(info[4][0])
    except OSError:
        pass
    try:
        import fcntl
        import struct
        for _, name in socket.if_nameindex():
            if name == "lo":
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                packed = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", name[:15].encode()))
                out.add(socket.inet_ntoa(packed[20:24]))
                s.close()
            except OSError:
                pass
    except Exception:
        pass
    extra = os.getenv("SYSLOG_ADVERTISE_ADDRESS", "").strip()
    if extra:
        out.add(extra)
    return {a for a in out if a and not a.startswith("127.")}


def valid_ip(text) -> bool:
    try:
        ipaddress.ip_address(str(text).strip())
        return True
    except ValueError:
        return False
