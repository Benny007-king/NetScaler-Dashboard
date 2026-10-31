"""The NITRO client against HTTPS management interfaces like NetScaler's: a
self-signed certificate, and old appliances that offer only TLS 1.2 with a
legacy cipher (AES256-SHA) - which OpenSSL 3 refuses by default.

    python tests/test_nitro_tls.py      # needs the app's Python packages; no network

Written for the library upgrades: requests and urllib3 changed how a custom TLS
context reaches the connection, and that context is what makes these appliances
reachable at all.
"""
import datetime
import json
import os
import ssl
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.update(DATA_DIR=tempfile.mkdtemp(), APP_SSL="0", SYSLOG_PORT="0", SECURITY_POLL_SECS="0",
                  HA_POLL_SECS="0", NODE_BACKOFF_SECS="0")
sys.path.insert(0, ROOT)

from cryptography import x509                                    # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa          # noqa: E402
from cryptography.x509.oid import NameOID                          # noqa: E402

ok_n = bad_n = 0


def check(cond, what, extra=""):
    global ok_n, bad_n
    if cond:
        ok_n += 1; print("   ok    " + what)
    else:
        bad_n += 1; print("   FAIL  " + what + (("\n         " + str(extra)[:600]) if extra else ""))


def self_signed(d):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ns-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    c, k = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    open(c, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(k, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption()))
    return c, k


seen = []


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        seen.append((self.headers.get("X-NITRO-USER"), self.headers.get("X-NITRO-PASS"), (self.request.cipher()[0], self.request.version())))
        if self.path == "/nitro/v1/config/moved":
            self.send_response(302)
            self.send_header("Location", "https://example.invalid/steal")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send({"errorcode": 0, "message": "Done", "nsversion": {"version": "NetScaler NS13.1: Build 50.23.nc"}})

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._send({"errorcode": 0, "message": "Done"}, 200)


def serve(legacy):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*self_signed(tempfile.mkdtemp()))
    if legacy:
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("AES256-SHA:@SECLEVEL=0")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


import requests   # noqa: E402
import app        # noqa: E402

print("-- an old appliance: TLS 1.2, AES256-SHA only, self-signed")
port = serve(legacy=True)
api = app.NetScalerAPI("127.0.0.1", "nsapi", "secret", port, "https")
try:
    j = api._get("/config/nsversion")
    check(j["nsversion"]["version"].startswith("NetScaler NS13.1"), "the NITRO client reads it", j)
except Exception as e:
    check(False, "the NITRO client reads it", repr(e))
check(seen and seen[-1][0] == "nsapi" and seen[-1][1] == "secret", "the NITRO credentials are sent", seen[-1:])
check(seen and seen[-1][2] and seen[-1][2][0] == "AES256-SHA" and seen[-1][2][1] == "TLSv1.2",
      "over TLS 1.2 with the legacy cipher", seen[-1:])
plain = requests.Session()
try:
    plain.get(f"https://127.0.0.1:{port}/nitro/v1/config/nsversion", verify=False, timeout=5)
    print("   note  a default client reaches it too (this OpenSSL still allows AES256-SHA)")
except requests.exceptions.SSLError:
    print("   note  a default client is refused - the dashboard's TLS settings are what reach it")
st = api.unlock_user("dana")
check(st["errorcode"] == 0, "a POST (unlock) goes through", st)
try:
    api._get("/config/moved")
    check(False, "a redirect is refused, the credentials are not sent on")
except requests.RequestException as e:
    check("redirect" in str(e), "a redirect is refused, the credentials are not sent on", e)

print("-- a current appliance: TLS 1.3, self-signed")
port2 = serve(legacy=False)
try:
    j = app.NetScalerAPI("127.0.0.1", "nsapi", "secret", port2, "https")._get("/config/nsversion")
    check(seen[-1][2][1] == "TLSv1.3" and j["errorcode"] == 0, "read over TLS 1.3", seen[-1:])
except Exception as e:
    check(False, "read over TLS 1.3", repr(e))

print("-- certificate verification on (NITRO_VERIFY_SSL=1)")
os.environ["NITRO_VERIFY_SSL"] = "1"
strict = app.NetScalerAPI("127.0.0.1", "nsapi", "secret", port2, "https")
try:
    strict._get("/config/nsversion")
    check(False, "a self-signed certificate is refused")
except requests.exceptions.SSLError:
    check(True, "a self-signed certificate is refused")
except Exception as e:
    check("certificate" in str(e).lower(), "a self-signed certificate is refused", repr(e))
# the same check again: once a connection was refused it stays refused (CVE-2024-35195 was the reverse)
lenient = app.NetScalerAPI("127.0.0.1", "nsapi", "secret", port2, "https")   # still NITRO_VERIFY_SSL=1
try:
    lenient._get("/config/nsversion")
    check(False, "verification stays on for a new client")
except Exception:
    check(True, "verification stays on for a new client")
os.environ["NITRO_VERIFY_SSL"] = "0"

print(f"\npassed {ok_n}, failed {bad_n}")
sys.exit(1 if bad_n else 0)
