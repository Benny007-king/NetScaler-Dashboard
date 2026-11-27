"""The security review: vendor-neutral rules over applications, a score per
application and for the whole estate, and the report a CISO reads.

An application is a dict a vendor adapter builds (see netscaler.build_apps):

    kind        'gateway' | 'lb' | 'cs' | 'aaa'
    name, vip, port, protocol ('SSL', 'HTTP', 'SSL_BRIDGE', 'TCP', ...)
    web         True for HTTP or HTTPS traffic the device understands
    tls         None, or {'protocols': {'TLS 1.2': True, ...}, 'ciphers': [...], 'weak_ciphers': [...],
                          'default_group': bool, 'hsts': bool, 'hsts_max_age': int, 'certs': [...], 'profile': str}
    exposure    'internet' | 'internal'
    state       'UP' | 'DOWN' | 'OUT OF SERVICE' | ...
    waf, bot    names of the protection policies that apply (bound to it, globally, or behind it)
    headers     security response headers the device adds
    redirect_https   an HTTP listener that only sends clients to HTTPS
    http_profile     {'name', 'drop_invalid', 'http09_invalid', 'connect_invalid'} or None
    backend     {'total', 'up', 'plain'} or None
    scan        the last TLS test of this application, or None

A rule returns findings; the adapter adds the commands that fix each one.
"""
from __future__ import annotations

SEVERITIES = ("critical", "high", "medium", "low", "info")
PENALTY = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
CATEGORIES = ("Encryption", "Certificates", "Web protection", "Protocol hygiene", "Availability",
              "Gateway hardening", "Management plane")


def finding(rule, severity, category, title, detail="", impact="", recommendation="", evidence=None):
    return {"rule": rule, "severity": severity, "category": category, "title": title, "detail": detail,
            "impact": impact, "recommendation": recommendation, "evidence": list(evidence or [])}


def _internet(app):
    return app.get("exposure") == "internet"


# ------------------------------------------------------------------ rules
def rule_cleartext(app):
    if not app.get("web") or app.get("tls") is not None or app.get("protocol", "").upper() != "HTTP":
        return []
    if app.get("redirect_https"):
        return []
    return [finding("http.cleartext", "high" if _internet(app) else "medium", "Encryption",
                    "Application served over plain HTTP",
                    f"{app['name']} listens on {app['vip']}:{app['port']} without TLS and does not send clients to HTTPS.",
                    "Passwords, session cookies and data cross the network readable by anyone on the path.",
                    "Serve it over HTTPS and turn this listener into a redirect to HTTPS.")]


def rule_protocols(app):
    t = app.get("tls")
    if not t:
        return []
    p = t.get("protocols") or {}
    out = []
    if p.get("SSL 3.0"):
        out.append(finding("tls.ssl3", "critical", "Encryption", "SSL 3.0 is enabled",
                           "SSL 3.0 is broken (POODLE) and no current client needs it.",
                           "An attacker on the path can decrypt parts of the traffic.",
                           "Disable SSL 3.0."))
    old = [n for n in ("TLS 1.0", "TLS 1.1") if p.get(n)]
    if old:
        out.append(finding("tls.old", "high" if _internet(app) else "medium", "Encryption",
                           f"{' and '.join(old)} enabled",
                           "Deprecated by RFC 8996 and refused by current browsers; fails PCI DSS.",
                           "Weaker cryptography stays available to anyone who asks for it (downgrade).",
                           "Allow TLS 1.2 and TLS 1.3 only."))
    if not p.get("TLS 1.2") and not p.get("TLS 1.3"):
        out.append(finding("tls.no12", "critical", "Encryption", "Neither TLS 1.2 nor TLS 1.3 is enabled",
                           "", "Current clients cannot connect securely.", "Enable TLS 1.2 and TLS 1.3."))
    elif not p.get("TLS 1.3"):
        out.append(finding("tls.no13", "low", "Encryption", "TLS 1.3 is not enabled",
                           "TLS 1.3 removes the legacy options of earlier versions and is faster.", "",
                           "Enable TLS 1.3 next to TLS 1.2."))
    return out


def rule_ciphers(app):
    t = app.get("tls")
    if not t:
        return []
    out = []
    weak = t.get("weak_ciphers") or []
    if weak:
        out.append(finding("tls.weak_ciphers", "high", "Encryption", "Weak cipher suites are allowed",
                           "Bound: " + ", ".join(weak[:10]) + (" ..." if len(weak) > 10 else ""),
                           "RC4, DES / 3DES, export, NULL or MD5 suites can be broken or downgraded to.",
                           "Bind a cipher group with ECDHE + AES-GCM / ChaCha20 (and TLS 1.3 suites) only."))
    elif t.get("default_group"):
        out.append(finding("tls.default_ciphers", "low", "Encryption", "The built-in DEFAULT cipher group is used",
                           "DEFAULT still includes CBC suites and suites without forward secrecy.", "",
                           "Bind a cipher group with ECDHE + AES-GCM / ChaCha20 (and TLS 1.3 suites) only."))
    return out


def rule_hsts(app):
    t = app.get("tls")
    if not t or not app.get("web"):
        return []
    if not t.get("hsts"):
        return [finding("tls.hsts", "medium" if _internet(app) or app.get("kind") == "gateway" else "low", "Encryption",
                        "HSTS is off", "Browsers are not told to use HTTPS only for this site.",
                        "A user typing the address can be intercepted before the redirect to HTTPS (SSL stripping).",
                        "Enable HSTS with a max-age of at least one year.")]
    if (t.get("hsts_max_age") or 0) < 15552000:
        return [finding("tls.hsts_short", "low", "Encryption", "HSTS max-age is short",
                        f"max-age {t.get('hsts_max_age')} seconds.", "", "Use at least 180 days (15552000).")]
    return []


def rule_certs(app):
    t = app.get("tls")
    if not t:
        return []
    certs = [c for c in t.get("certs") or [] if not c.get("ca")]
    if not certs:
        if app.get("protocol", "").upper() in ("SSL", "SSL_TCP", "DTLS"):
            return [finding("cert.none", "high", "Certificates", "No server certificate is bound",
                            "", "The virtual server cannot complete a TLS handshake: it is down for clients.",
                            "Bind a server certificate.")]
        return []
    out = []
    for c in certs:
        name = c.get("name") or c.get("subject") or "certificate"
        days = c.get("days_left")
        if days is not None and days < 0:
            out.append(finding("cert.expired", "critical", "Certificates", f"Certificate {name} has expired",
                               f"Expired {-days} days ago.", "Clients refuse the connection or learn to click through warnings.",
                               "Renew the certificate and update the certificate-key pair.", [name]))
        elif days is not None and days < 30:
            out.append(finding("cert.expiring", "high", "Certificates", f"Certificate {name} expires in {days} days",
                               "", "An outage when it expires.", "Renew it now.", [name]))
        elif days is not None and days < 60:
            out.append(finding("cert.expiring", "medium", "Certificates", f"Certificate {name} expires in {days} days",
                               "", "An outage when it expires.", "Plan the renewal.", [name]))
        bits, ktype = c.get("key_bits") or 0, (c.get("key_type") or "").upper()
        if ktype.startswith("RSA") and bits and bits < 2048:
            out.append(finding("cert.weak_key", "high", "Certificates", f"Certificate {name} has a {bits}-bit RSA key",
                               "", "Keys under 2048 bits can be factored by a well-funded attacker.",
                               "Issue a new certificate with an RSA 2048+ or ECDSA P-256 key.", [name]))
        sig = (c.get("signature") or "").lower()
        if "sha1" in sig or "md5" in sig:
            out.append(finding("cert.weak_sig", "high", "Certificates",
                               f"Certificate {name} is signed with {'SHA-1' if 'sha1' in sig else 'MD5'}",
                               "", "Browsers reject SHA-1 and MD5 signatures.", "Reissue it with SHA-256.", [name]))
        if c.get("self_signed"):
            out.append(finding("cert.self_signed", "high" if _internet(app) else "low", "Certificates",
                               f"Certificate {name} is self-signed", "",
                               "Clients cannot tell this server from an impostor; users learn to ignore warnings.",
                               "Use a certificate from a public CA (internet) or your internal CA.", [name]))
    return out


def rule_waf(app):
    if not app.get("web") or app.get("kind") not in ("lb", "cs") or app.get("redirect_https"):
        return []
    if app.get("waf"):
        return []
    if app.get("waf_partial"):
        return [finding("web.waf_partial", "medium" if _internet(app) else "low", "Web protection",
                        "Only some of the applications behind it have a WAF policy",
                        "Without a WAF: " + ", ".join(app["waf_partial"][:8]),
                        "Requests to those applications reach them unfiltered.",
                        "Bind a Web App Firewall policy to the content switching server or to each of them.")]
    return [finding("web.no_waf", "medium" if _internet(app) else "low", "Web protection",
                    "No Web App Firewall policy", "No WAF policy is bound to it, globally, or behind it.",
                    "SQL injection, cross-site scripting and other attacks reach the application unfiltered.",
                    "Bind a Web App Firewall policy (start with the basic profile in learning mode).")]


def rule_bot(app):
    if not app.get("web") or app.get("kind") not in ("lb", "cs") or not _internet(app) or app.get("redirect_https"):
        return []
    if app.get("bot"):
        return []
    return [finding("web.no_bot", "info", "Web protection", "No bot management policy",
                    "Credential stuffing and scraping are not told apart from users.", "",
                    "Consider a bot management profile for internet-facing logins.")]


def rule_headers(app):
    if not app.get("web") or app.get("tls") is None or app.get("kind") == "gateway" or app.get("redirect_https"):
        return []
    have = {h.lower() for h in app.get("headers") or []}
    scan_headers = ((app.get("scan") or {}).get("http") or {}).get("headers") or {}
    have |= {h.lower() for h in scan_headers}
    want = ("x-frame-options", "x-content-type-options")
    if "content-security-policy" in have:
        want = ("x-content-type-options",)
    miss = [h for h in want if h not in have]
    if not miss:
        return []
    return [finding("web.headers", "low", "Web protection", "Security headers are not added",
                    "Missing: " + ", ".join(miss) + (" (the application may set them itself - run the TLS test "
                                                     "to see the real answer)" if not scan_headers else ""),
                    "Clickjacking and content sniffing protections are left to every application.",
                    "Insert X-Frame-Options / Content-Security-Policy frame-ancestors and X-Content-Type-Options with a rewrite policy.")]


def rule_http_profile(app):
    if not app.get("web"):
        return []
    hp = app.get("http_profile")
    if not hp:
        return []
    off = [lbl for key, lbl in (("drop_invalid", "drop invalid requests"), ("http09_invalid", "mark HTTP/0.9 invalid"),
                                ("connect_invalid", "mark CONNECT invalid")) if hp.get(key) is False]
    if not off:
        return []
    return [finding("web.http_profile", "medium" if "drop invalid requests" in off and _internet(app) else "low",
                    "Protocol hygiene", "Malformed HTTP requests are passed on",
                    f"HTTP profile {hp.get('name') or 'default'}: off - " + ", ".join(off) + ".",
                    "Malformed and unusual requests are the raw material of request smuggling.",
                    "Turn these on in the HTTP profile the virtual server uses.")]


def rule_backend(app):
    b = app.get("backend")
    out = []
    if not b or not b.get("total"):
        return out
    if app.get("tls") and app.get("web") and b.get("plain") and app.get("kind") in ("lb", "cs"):
        out.append(finding("backend.plain", "low", "Encryption", "Traffic is decrypted and forwarded in clear text",
                           f"{b['plain']} of {b['total']} back-end services use plain HTTP.",
                           "Anyone on the server network can read the traffic, credentials included.",
                           "Use SSL services to the back end where the network is not trusted."))
    if b.get("up", 0) < b["total"]:
        out.append(finding("avail.backend", "info", "Availability", "Back-end services are down",
                           f"{b['total'] - b.get('up', 0)} of {b['total']} are not UP."))
    return out


def rule_state(app):
    st = str(app.get("state") or "").upper()
    if not st or st == "UP" or app.get("redirect_https"):
        return []
    return [finding("avail.down", "info", "Availability", f"The virtual server is {st}",
                    "It does not serve clients now.")]


def rule_scan(app):
    s = app.get("scan") or {}
    g = s.get("grade")
    if not g or g in ("-", "A+", "A", "A-"):
        return []
    sev = "high" if g in ("C", "D", "E", "F") else "medium"
    return [finding("scan.grade", sev, "Encryption", f"TLS test grade {g}",
                    "From the last TLS test" + (f" ({s.get('when')})" if s.get("when") else "") + ": "
                    + "; ".join(f["title"] for f in (s.get("findings") or [])[:4]),
                    "", "Open the TLS test for the full result.")]


RULES = (rule_cleartext, rule_protocols, rule_ciphers, rule_hsts, rule_certs, rule_waf, rule_bot,
         rule_headers, rule_http_profile, rule_backend, rule_state, rule_scan)


def review_app(app) -> list:
    out = []
    for r in RULES:
        try:
            out.extend(r(app))
        except Exception as e:                         # one odd object must not break the report
            out.append(finding("review.error", "info", "Availability", f"A rule could not run ({r.__name__})", str(e)[:160]))
    return out


# ------------------------------------------------------------------ checklist items folded in
# The hardening checklist covers the Gateway and the management plane. Items the
# per-application rules already cover are left out so nothing is counted twice.
CHECKLIST_SKIP = {"tls_versions", "hsts", "ciphers", "http_invalid", "http09", "http_connect", "http_extra"}
CHECKLIST_SEVERITY = {
    "cookie_hijack": "high", "brute_force": "high", "waf": "high", "login_lockout": "high",
    "mgmt_secure": "high", "mgmt_services": "high", "sys_passwords": "high", "rpc_nodes": "high", "mgmt_acl": "high",
    "geo_block": "low", "clientless_off": "low", "syslog_dashboard": "low", "ntp": "low", "cookie_v1": "low",
}
CHECKLIST_IMPACT = {
    "Gateway protection policies": "The Gateway is the door to the internal network: these policies stop the attacks seen against it in the wild.",
    "Gateway settings": "Settings that decide how much an attacker can learn or try against the Gateway.",
    "Management and platform": "Whoever controls the management plane controls every application on the appliance.",
}


def checklist_findings(checks) -> list:
    out = []
    for c in checks or []:
        if c.get("id") in CHECKLIST_SKIP:
            continue
        mark = (c.get("mark") or {}).get("state")
        if mark in ("done", "irrelevant") or c.get("status") in ("configured", "unknown"):
            continue
        if c.get("optional") and c.get("status") == "missing":
            sev = "low"
        else:
            sev = CHECKLIST_SEVERITY.get(c["id"], "medium")
            if c.get("status") == "partial" and sev in ("high", "medium"):
                sev = {"high": "medium", "medium": "low"}[sev]
        cat = "Management plane" if c.get("group") == "Management and platform" else "Gateway hardening"
        f = finding("checklist." + c["id"], sev, cat,
                    c["title"] + (" (partly)" if c.get("status") == "partial" else ""),
                    c.get("summary", ""), CHECKLIST_IMPACT.get(c.get("group"), ""),
                    "See the Security tab checklist for what it does and the commands.", (c.get("evidence") or [])[:3])
        f["fix"] = [x["text"] for x in ((c.get("variants") or [{}])[c.get("variant") or 0].get("commands") or [])][:3]
        out.append(f)
    return out


# ------------------------------------------------------------------ scoring
def score(findings) -> tuple:
    live = [f for f in findings if not f.get("accepted")]
    s = max(0, 100 - sum(PENALTY.get(f["severity"], 0) for f in live))
    g = "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"
    if any(f["severity"] == "critical" for f in live) and g in ("A", "B", "C"):
        g = "D"
    return s, g


def counts(findings) -> dict:
    out = {s: 0 for s in SEVERITIES}
    for f in findings:
        if not f.get("accepted"):
            out[f["severity"]] = out.get(f["severity"], 0) + 1
    return out


def risk_level(c) -> str:
    return ("Critical" if c.get("critical") else "High" if c.get("high") else
            "Moderate" if c.get("medium") else "Low")


def build(apps, platform, fixer=None, accepted=None, meta=None) -> dict:
    """The whole review. `platform` are findings that belong to no single
    application (checklist items); `accepted` = {finding key: {by, at, note}}."""
    accepted = accepted or {}
    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    all_f, out_apps = [], []
    for app in apps:
        fs = review_app(app)
        for f in fs:
            f["app"], f["kind"], f["exposure"] = app["name"], app["kind"], app.get("exposure")
            f["key"] = f"{app['kind']}:{app['name']}:{f['rule']}:{','.join(f['evidence'])}"
            if f["key"] in accepted:
                f["accepted"] = accepted[f["key"]]
            if fixer and "fix" not in f:
                try:
                    f["fix"] = fixer(f, app) or []
                except Exception:
                    f["fix"] = []
        fs.sort(key=lambda f: (bool(f.get("accepted")), sev_rank.get(f["severity"], 9)))
        s, g = score(fs)
        t = app.get("tls") or {}
        certs = [c for c in t.get("certs") or [] if not c.get("ca")]
        out_apps.append({
            "name": app["name"], "kind": app["kind"], "vip": app.get("vip"), "port": app.get("port"),
            "protocol": app.get("protocol"), "exposure": app.get("exposure"), "exposure_set": app.get("exposure_set", False),
            "state": app.get("state"), "score": s, "grade": g, "counts": counts(fs), "findings": fs,
            "tls": {"protocols": [n for n, on in (t.get("protocols") or {}).items() if on],
                    "cert_days": min((c["days_left"] for c in certs if c.get("days_left") is not None), default=None),
                    "certs": [c.get("name") for c in certs], "profile": t.get("profile", "")} if app.get("tls") else None,
            "waf": bool(app.get("waf")), "scan": {k: (app.get("scan") or {}).get(k) for k in ("grade", "when")} if app.get("scan") else None,
            "behind": app.get("behind") or [],
        })
        all_f.extend(fs)
    for f in platform:
        f.setdefault("app", "Gateway" if f["category"] == "Gateway hardening" else "Platform")
        f.setdefault("kind", "platform")
        f["key"] = f"platform::{f['rule']}"
        if f["key"] in accepted:
            f["accepted"] = accepted[f["key"]]
    platform.sort(key=lambda f: (bool(f.get("accepted")), sev_rank.get(f["severity"], 9)))
    all_f.extend(platform)
    ps, pg = score(platform)

    # Estate score: the applications (internet-facing ones count twice) and the platform.
    weights = [(a["score"], 2 if a["exposure"] == "internet" else 1) for a in out_apps]
    weights.append((ps, 2))
    total = round(sum(s * w for s, w in weights) / sum(w for _, w in weights)) if weights else 100
    c = counts(all_f)
    worst = min((a["score"] for a in out_apps), default=100)
    grade = "A" if total >= 90 else "B" if total >= 75 else "C" if total >= 60 else "D" if total >= 40 else "F"
    if c["critical"] and grade in ("A", "B", "C"):
        grade = "D"
    live = [f for f in all_f if not f.get("accepted")]
    live.sort(key=lambda f: (sev_rank.get(f["severity"], 9), f.get("exposure") != "internet"))
    top = [f for f in live if f["severity"] in ("critical", "high", "medium")][:8]
    by_cat = {}
    for f in live:
        if f["severity"] == "info":
            continue
        d = by_cat.setdefault(f["category"], {s: 0 for s in SEVERITIES})
        d[f["severity"]] += 1
    out_apps.sort(key=lambda a: (a["score"], a["name"].lower()))
    return {
        "meta": meta or {}, "score": total, "grade": grade, "risk": risk_level(c), "counts": c,
        "accepted": sum(1 for f in all_f if f.get("accepted")),
        "apps": out_apps, "platform": {"score": ps, "grade": pg, "findings": platform, "counts": counts(platform)},
        "top": top, "by_category": by_cat,
        "summary": {
            "apps": len(out_apps), "internet": sum(1 for a in out_apps if a["exposure"] == "internet"),
            "by_kind": {k: sum(1 for a in out_apps if a["kind"] == k) for k in ("gateway", "lb", "cs", "aaa")},
            "tls": sum(1 for a in out_apps if a["tls"]), "plain_http": sum(1 for a in out_apps if a["protocol"] == "HTTP"),
            "waf": sum(1 for a in out_apps if a["waf"]), "worst_score": worst,
            "graded": {g: sum(1 for a in out_apps if a["grade"] == g) for g in "ABCDF"},
        },
    }
