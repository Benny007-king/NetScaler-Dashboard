"""NetScaler adapter for the security review: NITRO -> applications, and the CLI
that fixes a finding. Everything here is read-only on the appliance.

    data = read(nitro)                     # one parallel pass over NITRO
    apps = build_apps(data, exposure={})   # the vendor-neutral applications (posture/review.py)
    fix(finding, app)                      # CLI lines for a finding
"""
from __future__ import annotations

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

VENDOR = "netscaler"

# (name, path, key)
_SOURCES = (
    ("version", "/config/nsversion", "nsversion"),
    ("lb", "/config/lbvserver", "lbvserver"),
    ("cs", "/config/csvserver", "csvserver"),
    ("vpn", "/config/vpnvserver", "vpnvserver"),
    ("aaa", "/config/authenticationvserver", "authenticationvserver"),
    ("ssl_vserver", "/config/sslvserver", "sslvserver"),
    ("ssl_profile", "/config/sslprofile", "sslprofile"),
    ("ssl_param", "/config/sslparameter", "sslparameter"),
    ("certkey", "/config/sslcertkey", "sslcertkey"),
    ("appfw_bind", "/config/appfwpolicy_binding?bulkbindings=yes", "appfwpolicy_binding"),
    ("bot_bind", "/config/botpolicy_binding?bulkbindings=yes", "botpolicy_binding"),
    ("responder", "/config/responderpolicy", "responderpolicy"),
    ("responder_bind", "/config/responderpolicy_binding?bulkbindings=yes", "responderpolicy_binding"),
    ("responder_action", "/config/responderaction", "responderaction"),
    ("rw_policy", "/config/rewritepolicy", "rewritepolicy"),
    ("rw_bind", "/config/rewritepolicy_binding?bulkbindings=yes", "rewritepolicy_binding"),
    ("rw_action", "/config/rewriteaction", "rewriteaction"),
    ("http_profile", "/config/nshttpprofile", "nshttpprofile"),
    ("service", "/config/service", "service"),
    ("servicegroup", "/config/servicegroup", "servicegroup"),
)
# Per virtual server: (name, path prefix, key, owner field)
_PER_VS = (
    ("cert_bind", "/config/sslvserver_sslcertkey_binding", "sslvserver_sslcertkey_binding", "vservername"),
    ("cipher_bind", "/config/sslvserver_sslcipher_binding", "sslvserver_sslcipher_binding", "vservername"),
)
_PER_LB = (
    ("svc_bind", "/config/lbvserver_service_binding", "lbvserver_service_binding", "name"),
    ("sg_bind", "/config/lbvserver_servicegroup_binding", "lbvserver_servicegroup_binding", "name"),
)
_PER_CS = (
    ("cs_pol_bind", "/config/csvserver_cspolicy_binding", "csvserver_cspolicy_binding", "name"),
    ("cs_lb_bind", "/config/csvserver_lbvserver_binding", "csvserver_lbvserver_binding", "name"),
)

_WEAK = re.compile(r"RC4|(^|[-_])3?DES|DES-CBC|EXP|NULL|MD5|ADH|AECDH|ANON|RC2|IDEA", re.I)
_SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options",
                     "x-content-type-options", "referrer-policy", "permissions-policy")


def _rows(d, key):
    v = (d or {}).get(key) if isinstance(d, dict) else None
    if isinstance(v, dict):
        return [v]
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def _yes(v):
    return str(v).strip().upper() in ("ENABLED", "YES", "ON", "TRUE", "1")


def _err(e):
    try:
        from security import nitro_error
        return nitro_error(e)
    except Exception:
        return str(e)[:160]


def read(nitro, pool_size=8) -> dict:
    """Everything the review needs, read in parallel; a source that fails is left
    out and named in data['errors']."""
    data, errors = {}, {}

    def one(src):
        name, path, key = src
        try:
            return name, _rows(nitro._get(path, custom_timeout=8) or {}, key), None
        except Exception as e:
            msg = _err(e)
            # a feature that is not licensed or has nothing configured answers "not found"
            if name in ("bot_bind",) and ("404" in msg or "344" in msg or "258" in msg):
                return name, [], None
            return name, None, msg

    with ThreadPoolExecutor(max_workers=pool_size, thread_name_prefix="posture") as ex:
        for name, rows, err in ex.map(one, _SOURCES):
            if err is None:
                data[name] = rows
            else:
                errors[name] = err

        def per(objects, specs):
            jobs = [(spec, o) for spec in specs for o in objects]

            def get(job):
                (name, prefix, key, _owner), obj = job
                try:
                    return name, obj, _rows(nitro._get(f"{prefix}/{quote(obj, safe='')}", custom_timeout=8) or {}, key), None
                except Exception as e:
                    msg = _err(e)
                    # "no such binding" is just an empty list
                    if "344" in msg or "258" in msg or "404" in msg or "No such resource" in msg:
                        return name, obj, [], None
                    return name, obj, None, msg
            for name, obj, rows, err in ex.map(get, jobs):
                if err:
                    errors.setdefault(name, err)
                data.setdefault(name, {})[obj] = rows or []

        ssl_names = [str(v.get("vservername") or "") for v in data.get("ssl_vserver") or [] if v.get("vservername")]
        lb_names = [str(v.get("name")) for v in data.get("lb") or [] if v.get("name")]
        cs_names = [str(v.get("name")) for v in data.get("cs") or [] if v.get("name")]
        per(ssl_names[:300], _PER_VS)
        per(lb_names[:500], _PER_LB)
        per(cs_names[:200], _PER_CS)
    data["errors"] = errors
    return data


# ------------------------------------------------------------------ helpers
def _bindings(rows):
    try:
        from security import _bindings as b
        return b(rows)
    except Exception:
        return {}


def _by_target(bind_map, active_only=True):
    """{bind point name: [policy names]} plus 'Global' for global bindings."""
    out = {}
    for pol, binds in bind_map.items():
        for b in binds:
            if active_only and not b.get("active", True):
                continue
            to = "Global" if "global" in str(b.get("where", "")) else str(b.get("to") or "")
            out.setdefault(to, []).append(pol)
    return out


def _addressable(ip):
    ip = str(ip or "").strip()
    return bool(ip) and ip not in ("0.0.0.0", "::")


def _exposure_guess(kind, ip):
    if kind == "gateway":
        return "internet"
    try:
        a = ipaddress.ip_address(str(ip))
        return "internal" if (a.is_private or a.is_loopback or a.is_link_local) else "internet"
    except ValueError:
        return "internal"


def _cert_info(row):
    days = row.get("daystoexpiration")
    try:
        days = int(days)
    except (TypeError, ValueError):
        days = None
    subj, iss = str(row.get("subject") or ""), str(row.get("issuer") or "")
    norm = lambda s: re.sub(r"\s+", "", s).lower()
    return {"name": str(row.get("certkey") or ""), "subject": subj, "issuer": iss, "days_left": days,
            "key_type": str(row.get("publickey") or ""), "key_bits": int(row.get("publickeysize") or 0) or None,
            "signature": str(row.get("signaturealg") or ""), "status": str(row.get("status") or ""),
            "self_signed": bool(subj) and norm(subj) == norm(iss)}


def build_apps(data: dict, exposure=None, scans=None) -> list:
    """The applications on this appliance. `exposure` = {app key: 'internet'|'internal'}
    set by the user; `scans` = {app key: last TLS test summary}."""
    exposure, scans = exposure or {}, scans or {}
    ssl_vs = {str(v.get("vservername")): v for v in data.get("ssl_vserver") or []}
    profiles = {str(p.get("name")): p for p in data.get("ssl_profile") or []}
    ssl_param = (data.get("ssl_param") or [{}])[0] if data.get("ssl_param") else {}
    default_profile_on = _yes(ssl_param.get("defaultprofile"))
    certkeys = {str(c.get("certkey")): c for c in data.get("certkey") or []}
    waf_to = _by_target(_bindings(data.get("appfw_bind")))
    bot_to = _by_target(_bindings(data.get("bot_bind")))
    rs_to = _by_target(_bindings(data.get("responder_bind")))
    rw_to = _by_target(_bindings(data.get("rw_bind")))
    rs_pol = {str(p.get("name")): p for p in data.get("responder") or []}
    rs_act = {str(a.get("name")): a for a in data.get("responder_action") or []}
    rw_pol = {str(p.get("name")): p for p in data.get("rw_policy") or []}
    rw_act = {str(a.get("name")): a for a in data.get("rw_action") or []}
    http_prof = {str(p.get("name")): p for p in data.get("http_profile") or []}
    svc = {str(s.get("name")): s for s in data.get("service") or []}
    sgs = {str(s.get("servicegroupname")): s for s in data.get("servicegroup") or []}
    lb_by_name = {str(v.get("name")): v for v in data.get("lb") or []}

    def headers_for(name):
        out = set()
        for pol in rw_to.get(name, []) + rw_to.get("Global", []):
            act = rw_act.get(str((rw_pol.get(pol) or {}).get("action") or ""))
            if act and str(act.get("type", "")).lower() in ("insert_http_header", "replace_http_res", "insert_before_all") \
                    and str(act.get("target", "")).lower() in _SECURITY_HEADERS:
                out.add(str(act["target"]))
        return sorted(out)

    def redirects_https(name, vs):
        if str(vs.get("redirurl") or vs.get("redirecturl") or "").lower().startswith("https"):
            return True
        for pol in rs_to.get(name, []):
            act = rs_act.get(str((rs_pol.get(pol) or {}).get("action") or ""))
            if act and str(act.get("type", "")).lower() in ("redirect",) and "https" in str(act.get("target", "")).lower():
                return True
        return False

    def tls_for(name):
        v = ssl_vs.get(name)
        if v is None:
            return None
        prof = str(v.get("sslprofile") or "") or ("ns_default_ssl_profile_frontend" if default_profile_on else "")
        src = profiles.get(prof) if prof and prof in profiles else v
        protocols = {lbl: _yes(src.get(k)) for k, lbl in (("ssl3", "SSL 3.0"), ("tls1", "TLS 1.0"), ("tls11", "TLS 1.1"),
                                                          ("tls12", "TLS 1.2"), ("tls13", "TLS 1.3"))}
        ciphers = [str(r.get("cipheraliasname") or r.get("ciphername") or "")
                   for r in (data.get("cipher_bind") or {}).get(name, [])]
        ciphers = [c for c in ciphers if c]
        certs = []
        for b in (data.get("cert_bind") or {}).get(name, []):
            ck = str(b.get("certkeyname") or "")
            info = _cert_info(certkeys.get(ck, {"certkey": ck}))
            info["ca"] = _yes(b.get("ca"))
            info["sni"] = _yes(b.get("snicert"))
            certs.append(info)
        try:
            maxage = int(src.get("maxage") or 0)
        except (TypeError, ValueError):
            maxage = 0
        return {"profile": prof if src is not v else "", "protocols": protocols, "ciphers": ciphers,
                "weak_ciphers": [c for c in ciphers if _WEAK.search(c)],
                "default_group": any(c.upper() == "DEFAULT" for c in ciphers), "hsts": _yes(src.get("hsts")),
                "hsts_max_age": maxage, "certs": certs, "sni": _yes(src.get("snienable")),
                "ocsp_stapling": _yes(src.get("ocspstapling"))}

    def http_profile_for(vs):
        pn = str(vs.get("httpprofilename") or "") or "nshttp_default_profile"
        p = http_prof.get(pn)
        if p is None:
            return None
        def flag(k):
            return None if k not in p else _yes(p.get(k))
        return {"name": pn, "drop_invalid": flag("dropinvalreqs"), "http09_invalid": flag("markhttp09inval"),
                "connect_invalid": flag("markconnreqinval")}

    def backend_for(name):
        total = up = plain = 0
        for b in (data.get("svc_bind") or {}).get(name, []):
            s = svc.get(str(b.get("servicename") or ""), {})
            total += 1
            up += str(b.get("curstate") or s.get("svrstate") or "").upper() == "UP"
            plain += str(b.get("servicetype") or s.get("servicetype") or "").upper() == "HTTP"
        for b in (data.get("sg_bind") or {}).get(name, []):
            g = sgs.get(str(b.get("servicegroupname") or ""), {})
            total += 1
            up += str(g.get("servicegroupeffectivestate") or b.get("curstate") or "").upper() == "UP"
            plain += str(g.get("servicetype") or b.get("servicetype") or "").upper() == "HTTP"
        return {"total": total, "up": up, "plain": plain} if total else None

    def cs_targets(name):
        t = []
        for b in (data.get("cs_pol_bind") or {}).get(name, []):
            if b.get("targetlbvserver"):
                t.append(str(b["targetlbvserver"]))
        for b in (data.get("cs_lb_bind") or {}).get(name, []):
            if b.get("lbvserver"):
                t.append(str(b["lbvserver"]))
        return sorted(set(t))

    apps = []

    def add(kind, vs):
        name = str(vs.get("name") or "")
        ip, port = str(vs.get("ipv46") or ""), vs.get("port")
        if not name or not _addressable(ip):
            return
        proto = str(vs.get("servicetype") or ("SSL" if kind == "gateway" else "")).upper()
        key = f"{kind}:{name}"
        tls = tls_for(name) if proto in ("SSL", "SSL_TCP", "DTLS", "SSL_BRIDGE") and proto != "SSL_BRIDGE" else None
        app = {
            "vendor": VENDOR, "key": key, "kind": kind, "name": name, "vip": ip, "port": port, "protocol": proto,
            "web": proto in ("HTTP", "SSL") or kind == "gateway", "tls": tls,
            "state": str(vs.get("curstate") or vs.get("state") or ""),
            "exposure": exposure.get(key) or _exposure_guess(kind, ip), "exposure_set": key in exposure,
            "waf": waf_to.get(name, []) + waf_to.get("Global", []), "bot": bot_to.get(name, []) + bot_to.get("Global", []),
            "headers": headers_for(name), "redirect_https": proto == "HTTP" and redirects_https(name, vs),
            "http_profile": http_profile_for(vs) if proto in ("HTTP", "SSL") else None,
            "backend": backend_for(name) if kind == "lb" else None,
            "scan": scans.get(key),
        }
        if kind == "cs":
            behind = cs_targets(name)
            app["behind"] = behind
            if not app["waf"] and behind:
                with_waf = [b for b in behind if waf_to.get(b)]
                if with_waf and len(with_waf) == len(behind):
                    app["waf"] = ["(on every application behind it)"]
                elif with_waf:
                    app["waf_partial"] = [b for b in behind if not waf_to.get(b)]
            # an SSL CS with plain LB targets behind it
            total = plain = 0
            for b in behind:
                be = backend_for(b)
                if be:
                    total += be["total"]; plain += be["plain"]
            if total:
                app["backend"] = {"total": total, "up": total, "plain": plain}
        apps.append(app)

    for v in data.get("vpn") or []:
        add("gateway", v)
    for v in data.get("cs") or []:
        add("cs", v)
    for v in data.get("lb") or []:
        add("lb", v)
    for v in data.get("aaa") or []:
        add("aaa", v)
    return apps


def scan_targets(data) -> list:
    """The TLS endpoints the TLS test may connect to: SSL virtual servers with an address."""
    out = []
    for kind, src in (("gateway", "vpn"), ("cs", "cs"), ("lb", "lb"), ("aaa", "aaa")):
        for v in data.get(src) or []:
            proto = str(v.get("servicetype") or ("SSL" if kind == "gateway" else "")).upper()
            ip = str(v.get("ipv46") or "")
            if proto in ("SSL", "SSL_TCP") and _addressable(ip) and v.get("name"):
                out.append({"key": f"{kind}:{v['name']}", "kind": kind, "name": str(v["name"]), "ip": ip,
                            "port": int(v.get("port") or 443), "state": str(v.get("curstate") or "")})
    return out


def sni_guess(data, name) -> str:
    """A host name for SNI: the first non-wildcard name of the server certificate."""
    certkeys = {str(c.get("certkey")): c for c in data.get("certkey") or []}
    for b in (data.get("cert_bind") or {}).get(name, []):
        if _yes(b.get("ca")):
            continue
        c = certkeys.get(str(b.get("certkeyname") or ""), {})
        for part in str(c.get("subject") or "").split(","):
            k, _, v = part.strip().partition("=")
            if k.strip().upper() == "CN" and v.strip() and "*" not in v:
                return v.strip()
    return ""


# ------------------------------------------------------------------ fixes
STRONG_GROUP = ("add ssl cipher Strong_Ciphers\n"
                "bind ssl cipher Strong_Ciphers -cipherName TLS1.3-AES256-GCM-SHA384\n"
                "bind ssl cipher Strong_Ciphers -cipherName TLS1.3-AES128-GCM-SHA256\n"
                "bind ssl cipher Strong_Ciphers -cipherName TLS1.3-CHACHA20-POLY1305-SHA256\n"
                "bind ssl cipher Strong_Ciphers -cipherName TLS1.2-ECDHE-RSA-AES256-GCM-SHA384\n"
                "bind ssl cipher Strong_Ciphers -cipherName TLS1.2-ECDHE-RSA-AES128-GCM-SHA256\n"
                "bind ssl cipher Strong_Ciphers -cipherName TLS1.2-ECDHE-ECDSA-AES256-GCM-SHA384\n"
                "bind ssl cipher Strong_Ciphers -cipherName TLS1.2-ECDHE-ECDSA-AES128-GCM-SHA256")


def _vs_cmd(app):
    return {"lb": "lb vserver", "cs": "cs vserver", "gateway": "vpn vserver", "aaa": "authentication vserver"}[app["kind"]]


def _ssl_target(app):
    prof = (app.get("tls") or {}).get("profile")
    return (f"set ssl profile {prof}", f"ssl profile {prof}") if prof else \
        (f"set ssl vserver {app['name']}", f"ssl vserver {app['name']}")


def fix(f, app) -> list:
    """CLI lines that fix finding `f` on `app` (placeholders in <angle brackets>)."""
    r, n = f["rule"], app["name"]
    setter, bindto = _ssl_target(app)
    if r in ("tls.ssl3", "tls.old", "tls.no12", "tls.no13"):
        return [f"{setter} -ssl3 DISABLED -tls1 DISABLED -tls11 DISABLED -tls12 ENABLED -tls13 ENABLED"]
    if r in ("tls.weak_ciphers", "tls.default_ciphers"):
        lines = [STRONG_GROUP]
        for c in (app.get("tls") or {}).get("ciphers") or []:
            lines.append(f"unbind {bindto} -cipherName {c}")
        lines.append(f"bind {bindto} -cipherName Strong_Ciphers")
        return lines
    if r in ("tls.hsts", "tls.hsts_short"):
        return [f"{setter} -HSTS ENABLED -maxage 31536000 -IncludeSubdomains YES"]
    if r in ("cert.expired", "cert.expiring", "cert.weak_key", "cert.weak_sig"):
        ck = (f.get("evidence") or ["<certkey>"])[0]
        return [f"update ssl certKey {ck} -cert <new-certificate.pem> -key <new-key.pem>"]
    if r == "cert.self_signed":
        ck = (f.get("evidence") or ["<certkey>"])[0]
        return ["add ssl certKey <ca-signed-certkey> -cert <certificate.pem> -key <key.pem>",
                f"unbind ssl vserver {n} -certkeyName {ck}",
                f"bind ssl vserver {n} -certkeyName <ca-signed-certkey>"]
    if r == "cert.none":
        return [f"bind ssl vserver {n} -certkeyName <certkey>"]
    if r == "http.cleartext":
        return ["add responder action Redirect_To_HTTPS_Action redirect "
                "'\"https://\" + HTTP.REQ.HOSTNAME.HTTP_URL_SAFE + HTTP.REQ.URL.PATH_AND_QUERY.HTTP_URL_SAFE' "
                "-responseStatusCode 301",
                "add responder policy Redirect_To_HTTPS_Policy true Redirect_To_HTTPS_Action",
                f"bind {_vs_cmd(app)} {n} -policyName Redirect_To_HTTPS_Policy -priority 100 -gotoPriorityExpression END -type REQUEST",
                "# and serve the application on an SSL virtual server on port 443"]
    if r in ("web.no_waf", "web.waf_partial"):
        return [f"add appfw profile {n}_WAF_Profile -defaults basic",
                f"add appfw policy {n}_WAF_Policy true {n}_WAF_Profile",
                f"bind {_vs_cmd(app)} {n} -policyName {n}_WAF_Policy -priority 100 -gotoPriorityExpression END -type REQUEST",
                "# the profile starts in learning mode: review the learned rules before blocking"]
    if r == "web.headers":
        return ['add rewrite action Insert_XFO_Action insert_http_header X-Frame-Options "\\"SAMEORIGIN\\""',
                'add rewrite action Insert_XCTO_Action insert_http_header X-Content-Type-Options "\\"nosniff\\""',
                "add rewrite policy Insert_XFO_Policy true Insert_XFO_Action",
                "add rewrite policy Insert_XCTO_Policy true Insert_XCTO_Action",
                f"bind {_vs_cmd(app)} {n} -policyName Insert_XFO_Policy -priority 100 -gotoPriorityExpression NEXT -type RESPONSE",
                f"bind {_vs_cmd(app)} {n} -policyName Insert_XCTO_Policy -priority 110 -gotoPriorityExpression END -type RESPONSE"]
    if r == "web.http_profile":
        hp = (app.get("http_profile") or {}).get("name") or "nshttp_default_profile"
        return [f"set ns httpProfile {hp} -dropInvalReqs ENABLED -markHttp09Inval ENABLED -markConnReqInval ENABLED"]
    if r == "web.no_bot":
        return [f"add bot profile {n}_Bot_Profile -signature nsbotsignatures",
                f"add bot policy {n}_Bot_Policy -rule true -profileName {n}_Bot_Profile",
                f"bind {_vs_cmd(app)} {n} -policyName {n}_Bot_Policy -priority 100 -type REQUEST"]
    if r == "backend.plain":
        return ["add service <name>_SSL <server> SSL 443   # or set the service group's type to SSL"]
    return []


_SCAN_RULE = {"cipher.export": "tls.weak_ciphers", "cipher.null_anon": "tls.weak_ciphers", "cipher.rc4": "tls.weak_ciphers",
              "cipher.3des": "tls.weak_ciphers", "cipher.no_fs": "tls.weak_ciphers", "cipher.some_no_fs": "tls.weak_ciphers",
              "cipher.no_aead": "tls.weak_ciphers", "cipher.cbc": "tls.weak_ciphers", "cipher.client_order": "tls.weak_ciphers",
              "http.hsts": "tls.hsts", "http.hsts_short": "tls.hsts", "cert.key_weak": "cert.weak_key",
              "cert.sig_weak": "cert.weak_sig", "cert.untrusted": "cert.self_signed", "cert.name": "cert.self_signed",
              "http.headers": "web.headers"}


def scan_fix(f, app) -> list:
    """CLI lines for a TLS test finding on `app` (an application from build_apps)."""
    if not app:
        return []
    fid, n = f.get("id", ""), app["name"]
    setter, _ = _ssl_target(app)
    certs = [c.get("name") for c in (app.get("tls") or {}).get("certs") or [] if not c.get("ca") and c.get("name")]
    if fid == "tls.reneg":
        return ["set ssl parameter -denySSLReneg NONSECURE"]
    if fid == "kx.dh_weak":
        return [f"set ssl vserver {n} -dh ENABLED -dhFile /nsconfig/ssl/dh2048.key   # create it: create ssl dhParam /nsconfig/ssl/dh2048.key 2048 -gen 2",
                "# or unbind the DHE suites and keep ECDHE only"]
    if fid == "tls.ocsp":
        ck = certs[0] if certs else "<certkey>"
        return ["add ssl ocspResponder <CA>_OCSP -url \"<http://ocsp.your-ca.example>\"",
                f"bind ssl certKey {ck} -ocspResponder <CA>_OCSP -priority 10",
                f"{setter} -ocspStapling ENABLED"]
    if fid in ("tls.fallback", "tls.compression"):
        return ["# fixed in current NetScaler builds - upgrade the firmware"]
    rule = _SCAN_RULE.get(fid, fid)
    ev = certs[:1] if rule.startswith("cert.") else []
    return fix({"rule": rule, "evidence": ev}, app)
