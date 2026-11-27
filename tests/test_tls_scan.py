"""The TLS test (posture/tls_scan.py) against local TLS servers.

    python tests/test_tls_scan.py

A modern server (TLS 1.2 + 1.3, ECDHE + AES-GCM, HSTS) must come out as A or A+
with no high finding; one that also allows TLS 1.0 / 1.1 and CBC without forward
secrecy must be capped at B with those named; a closed port is "not reachable".
The certificates are self-signed, so the trust check says T (with the grade if trusted).
"""
import datetime
import os
import socket
import ssl
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from posture import tls_scan  # noqa: E402

bad = 0


def check(cond, what):
    global bad
    print(("ok   " if cond else "FAIL ") + what)
    bad += not cond


def make_cert(days=200):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gw.example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("gw.example.com")]), False)
            .sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cp, kp


def serve(ctx, hsts=True):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(50)

    def handle(c):
        try:
            with ctx.wrap_socket(c, server_side=True) as t:
                t.settimeout(3)
                data = t.recv(4096)
                if data.startswith(b"GET"):
                    extra = "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" if hsts else ""
                    t.sendall(("HTTP/1.1 200 OK\r\n" + extra + "X-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\n"
                               "Content-Length: 2\r\nConnection: close\r\n\r\nok").encode())
        except Exception:
            pass
        finally:
            try: c.close()
            except Exception: pass

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1]


cp, kp = make_cert()

# ---- a modern server
m = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
m.load_cert_chain(cp, kp)
m.minimum_version = ssl.TLSVersion.TLSv1_2
m.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
srv, port = serve(m)
r = tls_scan.scan("127.0.0.1", port, sni="gw.example.com", timeout=3)
on = {p["name"] for p in r["protocols"] if p["supported"]}
print("modern:", r["grade"], r.get("grade_if_trusted"), sorted(on), r["score"], [f["id"] for f in r["findings"]])
check(on == {"TLS 1.2", "TLS 1.3"}, "modern: TLS 1.2 and 1.3 only")
check(all(c["fs"] and c["aead"] for c in r["ciphers"]["TLS 1.2"]), "modern: every TLS 1.2 suite is ECDHE + AEAD")
check(len(r["ciphers"]["TLS 1.3"]) >= 2, "modern: TLS 1.3 suites listed")
check(r["grade"] == "T" and r["grade_if_trusted"] in ("A", "A+"), "modern: self-signed -> T, A or A+ if trusted")
check(not [f for f in r["findings"] if f["severity"] in ("critical", "high") and f["id"] != "cert.untrusted"],
      "modern: no high finding except trust")
check(r["cert"]["key"] == {"type": "RSA", "bits": 2048} and r["cert"]["name_ok"] is True, "modern: certificate read, name matches")
check(r["features"].get("secure_renegotiation") is True and r["features"].get("compression") is False, "modern: features read")
check(r["http"]["hsts"]["present"] and r["http"]["hsts"]["max_age"] == 31536000, "modern: HSTS read")
check(r["kx"].get("TLS 1.2", {}).get("curve") in ("x25519", "P-256", "P-384"), "modern: ECDHE curve read")
srv.close()

# ---- a legacy server: TLS 1.0 / 1.1 and RSA key exchange with CBC
old = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
old.load_cert_chain(cp, kp)
try:
    old.minimum_version = ssl.TLSVersion.TLSv1
    old.maximum_version = ssl.TLSVersion.TLSv1_2
    old.set_ciphers("AES128-SHA:AES256-SHA:ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0")
    legacy_ok = True
except (ssl.SSLError, ValueError) as e:
    print("this OpenSSL cannot serve TLS 1.0:", e)
    legacy_ok = False
if legacy_ok:
    srv, port = serve(old, hsts=False)
    r = tls_scan.scan("127.0.0.1", port, sni="other.example.com", timeout=3)
    on = {p["name"] for p in r["protocols"] if p["supported"]}
    ids = {f["id"] for f in r["findings"]}
    print("legacy:", r["grade"], r.get("grade_if_trusted"), sorted(on), r["score"], sorted(ids))
    if "TLS 1.0" in on:
        check("tls.old" in ids, "legacy: TLS 1.0 / 1.1 named")
        check(r["grade_if_trusted"] in ("B", "C"), "legacy: capped at B or below")
        check(r["features"].get("fallback_scsv") is True, "legacy: TLS_FALLBACK_SCSV honoured (OpenSSL does)")
    else:
        print("note: the local OpenSSL refused TLS 1.0 at run time; protocol caps not checked")
    check("cipher.some_no_fs" in ids or "cipher.no_fs" in ids, "legacy: suites without forward secrecy named")
    check("http.hsts" in ids, "legacy: missing HSTS named")
    check(r["cert"]["name_ok"] is False and "cert.name" in ids, "legacy: name mismatch for another host name")
    check("tls.no13" in ids, "legacy: no TLS 1.3 named")
    srv.close()

# ---- nothing listening
s = socket.socket(); s.bind(("127.0.0.1", 0)); dead = s.getsockname()[1]; s.close()
r = tls_scan.scan("127.0.0.1", dead, timeout=2)
check(r["reachable"] is False and r["grade"] == "-", "closed port: not reachable, no grade")

# ---- suite table sanity
i = tls_scan.suite_info(0xC030)
check(i["fs"] and i["aead"] and i["bits"] == 256 and i["strength"] == "strong", "suite: ECDHE-RSA-AES256-GCM is strong")
check(tls_scan.suite_info(0x000A)["block64"] and tls_scan.suite_info(0x000A)["strength"] == "weak", "suite: 3DES is weak")
check(tls_scan.suite_info(0x0003)["strength"] == "insecure", "suite: export RC4 is insecure")

print("\n" + ("all passed" if not bad else f"{bad} FAILED"))
sys.exit(1 if bad else 0)
