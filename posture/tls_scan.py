"""An SSL Labs style test of one TLS endpoint, vendor-neutral.

The protocol and cipher probes are hand-built ClientHello messages, so what is
tested does not depend on what the local OpenSSL still supports: SSL 3.0, export
and RC4 suites are offered as bytes and the server's answer is read. Only the
ServerHello (and, up to TLS 1.2, the certificate, the stapled OCSP answer and the
key exchange) is read; no handshake is finished and nothing is sent after it.
The certificate is checked for trust with Python's ssl module, and one HTTPS
request reads HSTS and the security headers.

    scan("192.0.2.80", 443, sni="gw.example.com") -> dict   (see grade() for the rating)

The rating follows the structure of the SSL Labs rating guide (protocol 30%, key
exchange 30%, cipher strength 40%, then caps for known weaknesses); it is this
dashboard's reading of it, not an SSL Labs result.
"""
from __future__ import annotations

import hashlib
import os
import socket
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor

# ------------------------------------------------------------------ protocols
SSL3, TLS10, TLS11, TLS12, TLS13 = 0x0300, 0x0301, 0x0302, 0x0303, 0x0304
PROTO_NAMES = {SSL3: "SSL 3.0", TLS10: "TLS 1.0", TLS11: "TLS 1.1", TLS12: "TLS 1.2", TLS13: "TLS 1.3"}
PROTO_ORDER = (TLS13, TLS12, TLS11, TLS10, SSL3)

# ------------------------------------------------------------------ cipher suites (IANA)
_SUITES = """
0001 TLS_RSA_WITH_NULL_MD5
0002 TLS_RSA_WITH_NULL_SHA
0003 TLS_RSA_EXPORT_WITH_RC4_40_MD5
0004 TLS_RSA_WITH_RC4_128_MD5
0005 TLS_RSA_WITH_RC4_128_SHA
0006 TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
0007 TLS_RSA_WITH_IDEA_CBC_SHA
0008 TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
0009 TLS_RSA_WITH_DES_CBC_SHA
000A TLS_RSA_WITH_3DES_EDE_CBC_SHA
0011 TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
0012 TLS_DHE_DSS_WITH_DES_CBC_SHA
0013 TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
0014 TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
0015 TLS_DHE_RSA_WITH_DES_CBC_SHA
0016 TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
0017 TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
0018 TLS_DH_anon_WITH_RC4_128_MD5
001A TLS_DH_anon_WITH_DES_CBC_SHA
001B TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
002F TLS_RSA_WITH_AES_128_CBC_SHA
0032 TLS_DHE_DSS_WITH_AES_128_CBC_SHA
0033 TLS_DHE_RSA_WITH_AES_128_CBC_SHA
0034 TLS_DH_anon_WITH_AES_128_CBC_SHA
0035 TLS_RSA_WITH_AES_256_CBC_SHA
0038 TLS_DHE_DSS_WITH_AES_256_CBC_SHA
0039 TLS_DHE_RSA_WITH_AES_256_CBC_SHA
003A TLS_DH_anon_WITH_AES_256_CBC_SHA
003B TLS_RSA_WITH_NULL_SHA256
003C TLS_RSA_WITH_AES_128_CBC_SHA256
003D TLS_RSA_WITH_AES_256_CBC_SHA256
0040 TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
0041 TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
0045 TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
0067 TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
006A TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
006B TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
0084 TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
0088 TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
0096 TLS_RSA_WITH_SEED_CBC_SHA
009C TLS_RSA_WITH_AES_128_GCM_SHA256
009D TLS_RSA_WITH_AES_256_GCM_SHA384
009E TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
009F TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
00A2 TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
00A3 TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
00A6 TLS_DH_anon_WITH_AES_128_GCM_SHA256
00A7 TLS_DH_anon_WITH_AES_256_GCM_SHA384
C002 TLS_ECDH_ECDSA_WITH_RC4_128_SHA
C003 TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
C004 TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
C005 TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
C007 TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
C008 TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
C009 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
C00A TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
C00C TLS_ECDH_RSA_WITH_RC4_128_SHA
C00D TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
C00E TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
C00F TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
C011 TLS_ECDHE_RSA_WITH_RC4_128_SHA
C012 TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
C013 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
C014 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
C016 TLS_ECDH_anon_WITH_RC4_128_SHA
C017 TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
C018 TLS_ECDH_anon_WITH_AES_128_CBC_SHA
C019 TLS_ECDH_anon_WITH_AES_256_CBC_SHA
C023 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
C024 TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
C025 TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
C026 TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
C027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
C028 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
C029 TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
C02A TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
C02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
C02C TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
C02D TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
C02E TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
C02F TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
C030 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
C031 TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
C032 TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
C072 TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
C073 TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
C076 TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
C077 TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
C09C TLS_RSA_WITH_AES_128_CCM
C09D TLS_RSA_WITH_AES_256_CCM
C09E TLS_DHE_RSA_WITH_AES_128_CCM
C09F TLS_DHE_RSA_WITH_AES_256_CCM
C0AC TLS_ECDHE_ECDSA_WITH_AES_128_CCM
C0AD TLS_ECDHE_ECDSA_WITH_AES_256_CCM
CCA8 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
CCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
CCAA TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
"""
_SUITES13 = """
1301 TLS_AES_128_GCM_SHA256
1302 TLS_AES_256_GCM_SHA384
1303 TLS_CHACHA20_POLY1305_SHA256
1304 TLS_AES_128_CCM_SHA256
1305 TLS_AES_128_CCM_8_SHA256
"""
SCSV_RENEG, SCSV_FALLBACK = 0x00FF, 0x5600


def _parse_suites(text):
    out = {}
    for line in text.strip().splitlines():
        code, name = line.split()
        out[int(code, 16)] = name
    return out


SUITES = _parse_suites(_SUITES)
SUITES13 = _parse_suites(_SUITES13)


def suite_info(code: int) -> dict:
    """What a suite is made of: key exchange, cipher and its strength."""
    name = SUITES.get(code) or SUITES13.get(code) or f"0x{code:04X}"
    if code in SUITES13:
        kx, auth, enc = "ECDHE", "", name[4:].rsplit("_", 1)[0]
    elif "_WITH_" in name:
        left, enc = name[4:].split("_WITH_", 1)
        parts = left.split("_")
        kx, auth = parts[0], "_".join(parts[1:])
    else:
        kx, auth, enc = "", "", name
    export = "EXPORT" in name
    anon = "anon" in name
    up = enc.upper()
    if up.startswith("NULL"):
        bits = 0
    elif "DES40" in up or "RC4_40" in up or "RC2_CBC_40" in up:
        bits = 40
    elif "3DES" in up:
        bits = 112
    elif up.startswith("DES"):
        bits = 56
    elif "256" in up or "CHACHA20" in up:
        bits = 256
    else:
        bits = 128
    aead = any(x in up for x in ("GCM", "CCM", "CHACHA20_POLY1305")) or code in SUITES13
    fs = kx in ("DHE", "ECDHE") and not anon
    block64 = any(x in up for x in ("3DES", "DES", "IDEA", "RC2"))
    rc4 = "RC4" in up
    insecure = bits < 112 or export or anon or rc4 or name.endswith("_MD5") and not aead
    weak = not insecure and (block64 or not fs or (not aead and code not in SUITES13))
    return {"code": f"0x{code:04X}", "name": name, "kx": "anon" if anon else kx, "auth": auth, "bits": bits,
            "fs": fs, "aead": aead, "export": export, "rc4": rc4, "block64": block64,
            "strength": "insecure" if insecure else ("weak" if weak else "strong")}


# ------------------------------------------------------------------ ClientHello
def _u8(n): return struct.pack(">B", n)
def _u16(n): return struct.pack(">H", n)
def _u24(n): return struct.pack(">I", n)[1:]
def _vec16(b): return _u16(len(b)) + b
def _ext(t, body): return _u16(t) + _vec16(body)

_GROUPS = (0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x0100, 0x0101)        # x25519, P-256/384/521, x448, ffdhe2048/3072
GROUP_NAMES = {0x001D: "x25519", 0x0017: "P-256", 0x0018: "P-384", 0x0019: "P-521", 0x001E: "x448",
               0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0016: "secp256k1", 0x0015: "secp224r1"}
_SIGALGS = (0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201)
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")


def client_hello(version: int, suites, sni: str = "", compression=False, alpn=None) -> bytes:
    """One ClientHello record offering `suites` at `version` (TLS 1.3 through
    supported_versions, as a real client does)."""
    tls13 = version >= TLS13
    legacy = TLS12 if tls13 else version
    sid = os.urandom(32) if tls13 else b""
    body = _u16(legacy) + os.urandom(32) + _u8(len(sid)) + sid
    codes = list(suites)
    if not tls13 and SCSV_RENEG not in codes:
        codes.append(SCSV_RENEG)
    body += _vec16(b"".join(_u16(c) for c in codes))
    body += b"\x02\x01\x00" if compression else b"\x01\x00"
    ext = b""
    if sni:
        host = sni.encode("idna")
        ext += _ext(0, _vec16(b"\x00" + _vec16(host)))
    ext += _ext(10, _vec16(b"".join(_u16(g) for g in _GROUPS)))
    ext += _ext(11, b"\x01\x00")
    if version >= TLS12:
        ext += _ext(13, _vec16(b"".join(_u16(s) for s in _SIGALGS)))
    ext += _ext(5, b"\x01\x00\x00\x00\x00")                                   # status_request (OCSP stapling)
    ext += _ext(23, b"")                                                    # extended master secret
    ext += _ext(35, b"")                                                    # session ticket
    if alpn:
        names = b"".join(_u8(len(a)) + a.encode() for a in alpn)
        ext += _ext(16, _vec16(names))
    if tls13:
        ext += _ext(43, b"\x02" + _u16(TLS13))                              # supported_versions
        ext += _ext(45, b"\x01\x01")                                        # psk_key_exchange_modes
        ext += _ext(51, _vec16(_u16(0x001D) + _vec16(os.urandom(32))))     # key_share x25519
    else:
        ext += _ext(0xFF01, b"\x00")                                        # renegotiation_info
    body += _vec16(ext)
    hs = b"\x01" + _u24(len(body)) + body
    rec_ver = SSL3 if version == SSL3 else TLS10
    return b"\x16" + _u16(rec_ver) + _vec16(hs)


# ------------------------------------------------------------------ reading the answer
class Answer:
    def __init__(self):
        self.ok = False                 # a ServerHello came back
        self.alert = None               # (level, description) when the server said no
        self.version = None
        self.cipher = None
        self.compression = 0
        self.extensions = {}
        self.hrr = False
        self.certs = []                 # DER, as sent (TLS 1.2 and below)
        self.ocsp = None
        self.kx = {}                    # {'curve': 'x25519'} or {'dh_bits': 2048}
        self.error = ""


def _recv(sock, n, deadline):
    buf = b""
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout("timed out")
        sock.settimeout(left)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def _parse_server_hello(a: Answer, msg: bytes):
    p = 0
    a.version = struct.unpack(">H", msg[p:p + 2])[0]; p += 2
    rnd = msg[p:p + 32]; p += 32
    a.hrr = rnd == HRR_RANDOM
    sl = msg[p]; p += 1 + sl
    a.cipher = struct.unpack(">H", msg[p:p + 2])[0]; p += 2
    a.compression = msg[p]; p += 1
    if p + 2 <= len(msg):
        end = p + 2 + struct.unpack(">H", msg[p:p + 2])[0]; p += 2
        while p + 4 <= end:
            t, ln = struct.unpack(">HH", msg[p:p + 4]); p += 4
            a.extensions[t] = msg[p:p + ln]; p += ln
    sv = a.extensions.get(43)
    if sv and len(sv) >= 2:
        a.version = struct.unpack(">H", sv[:2])[0]
    a.ok = True


def _parse_ske(a: Answer, msg: bytes):
    info = suite_info(a.cipher or 0)
    try:
        if info["kx"] == "ECDHE" and msg[0] == 3:
            cid = struct.unpack(">H", msg[1:3])[0]
            a.kx = {"curve": GROUP_NAMES.get(cid, f"0x{cid:04X}")}
        elif info["kx"] == "DHE":
            plen = struct.unpack(">H", msg[:2])[0]
            prime = msg[2:2 + plen].lstrip(b"\x00")
            a.kx = {"dh_bits": len(prime) * 8}
    except Exception:
        pass


def hello(ip, port, version, suites, sni="", timeout=5.0, compression=False, alpn=None, read_all=True) -> Answer:
    """Send one ClientHello and read the server's first flight."""
    a = Answer()
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(client_hello(version, suites, sni, compression, alpn))
            hs = b""
            while True:
                head = _recv(s, 5, deadline)
                ctype, _rv, ln = head[0], head[1:3], struct.unpack(">H", head[3:5])[0]
                body = _recv(s, ln, deadline)
                if ctype == 21:                                           # alert
                    a.alert = (body[0], body[1]) if len(body) >= 2 else (2, 0)
                    return a
                if ctype != 22:                                           # TLS 1.3 encrypted records, CCS: done
                    return a
                hs += body
                while len(hs) >= 4:
                    mtype, mlen = hs[0], struct.unpack(">I", b"\x00" + hs[1:4])[0]
                    if len(hs) < 4 + mlen:
                        break
                    msg, hs = hs[4:4 + mlen], hs[4 + mlen:]
                    if mtype == 2:
                        _parse_server_hello(a, msg)
                        if not read_all or a.hrr or a.version == TLS13 or (a.version or 0) < version and version < TLS13:
                            return a
                    elif mtype == 11:
                        p, certs = 3, []
                        end = 3 + struct.unpack(">I", b"\x00" + msg[0:3])[0]
                        while p + 3 <= end:
                            cl = struct.unpack(">I", b"\x00" + msg[p:p + 3])[0]; p += 3
                            certs.append(msg[p:p + cl]); p += cl
                        a.certs = certs
                    elif mtype == 22:
                        a.ocsp = msg[4:] if len(msg) > 4 else b""
                    elif mtype == 12:
                        _parse_ske(a, msg)
                    elif mtype == 14:                                     # ServerHelloDone
                        return a
    except (OSError, ConnectionError, socket.timeout, struct.error, IndexError) as e:
        if not a.ok:
            a.error = str(e) or type(e).__name__
    return a


# ------------------------------------------------------------------ probes
class Prober:
    def __init__(self, ip, port, sni="", timeout=5.0, budget=90.0):
        self.ip, self.port, self.sni, self.timeout = ip, int(port), sni, timeout
        self.stop_at = time.monotonic() + budget
        self.connections = 0

    def hello(self, version, suites, **kw):
        if time.monotonic() > self.stop_at:
            a = Answer(); a.error = "time budget used up"; return a
        self.connections += 1
        return hello(self.ip, self.port, version, suites, self.sni, self.timeout, **kw)

    def supports(self, version):
        pool = list(SUITES13) if version == TLS13 else list(SUITES)
        a = self.hello(version, pool, alpn=["h2", "http/1.1"] if version >= TLS12 else None)
        return (a.ok and a.version == version), a

    def enumerate(self, version, first: Answer):
        """Every suite the server takes at this version, in the order it picks them."""
        pool = list(SUITES13) if version == TLS13 else list(SUITES)
        got, ans = [], first
        while ans.ok and ans.version == version and ans.cipher in pool:
            got.append(ans.cipher)
            pool.remove(ans.cipher)
            if not pool:
                break
            ans = self.hello(version, pool, read_all=False)
        return got

    def server_order(self, version, got):
        if len(got) < 2:
            return None
        a = self.hello(version, [got[-1], got[0]], read_all=False)
        if not a.ok:
            return None
        return a.cipher == got[0]


def _cert_details(der_list):
    """Leaf and chain, as the server sent them."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
        from cryptography.x509.oid import NameOID, ExtensionOID
    except Exception:
        return None, []
    out = []
    for der in der_list:
        try:
            c = x509.load_der_x509_certificate(der)
        except Exception:
            continue
        k = c.public_key()
        if isinstance(k, rsa.RSAPublicKey):
            key = {"type": "RSA", "bits": k.key_size}
        elif isinstance(k, ec.EllipticCurvePublicKey):
            key = {"type": "EC", "bits": k.curve.key_size, "curve": k.curve.name}
        elif isinstance(k, dsa.DSAPublicKey):
            key = {"type": "DSA", "bits": k.key_size}
        elif isinstance(k, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key = {"type": "EdDSA", "bits": 256 if isinstance(k, ed25519.Ed25519PublicKey) else 456}
        else:
            key = {"type": "?", "bits": 0}

        def cn(name):
            try:
                v = name.get_attributes_for_oid(NameOID.COMMON_NAME)
                return v[0].value if v else name.rfc4514_string()
            except Exception:
                return ""
        try:
            sans = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            names = [str(x) for x in sans.get_values_for_type(x509.DNSName)] + \
                    [str(x) for x in sans.get_values_for_type(x509.IPAddress)]
        except Exception:
            names = []
        try:
            sig = c.signature_hash_algorithm.name if c.signature_hash_algorithm else "none"
        except Exception:
            sig = "unknown"
        nb = c.not_valid_before_utc
        na = c.not_valid_after_utc
        out.append({
            "subject": cn(c.subject), "subject_dn": c.subject.rfc4514_string(), "issuer": cn(c.issuer),
            "issuer_dn": c.issuer.rfc4514_string(), "san": names, "serial": format(c.serial_number, "X"),
            "not_before": nb.isoformat(), "not_after": na.isoformat(),
            "days_left": int((na.timestamp() - time.time()) // 86400), "not_yet_valid": nb.timestamp() > time.time(),
            "key": key, "signature": sig, "self_signed": c.subject == c.issuer,
            "sha256": c.fingerprint(hashes.SHA256()).hex().upper(),
        })
    return (out[0] if out else None), out


def _name_matches(host, names):
    host = (host or "").lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") >= n.count(".") and host.split(".", 1)[-1] == n[2:]:
            return True
    return False


def _trust(ip, port, sni, timeout):
    """Is the chain trusted by the public CAs (and the name right)? Uses a normal
    verifying handshake - the one place this module completes a handshake."""
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        ctx = ssl.create_default_context()
    ctx.check_hostname = False
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=sni or None):
                return {"trusted": True, "error": ""}
    except ssl.SSLCertVerificationError as e:
        return {"trusted": False, "error": str(getattr(e, "verify_message", "") or e)[:200]}
    except Exception as e:
        return {"trusted": None, "error": str(e)[:200]}


def _tls_chain_fallback(ip, port, sni, timeout):
    """The chain over a normal handshake, for a server that speaks only TLS 1.3."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=sni or None) as t:
                chain = []
                try:
                    for c in t.get_unverified_chain() or []:
                        chain.append(c if isinstance(c, bytes) else c.public_bytes(ssl._ssl.ENCODING_DER))
                except Exception:
                    der = t.getpeercert(binary_form=True)
                    chain = [der] if der else []
                return chain
    except Exception:
        return []


def _http(ip, port, sni, timeout):
    """One GET / over TLS: the status, HSTS and the security headers."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    host = sni or ip
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=sni or None) as t:
                t.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetScaler-Dashboard-TLS-Test\r\n"
                          f"Accept: */*\r\nConnection: close\r\n\r\n".encode())
                buf, deadline = b"", time.monotonic() + timeout
                while b"\r\n\r\n" not in buf and len(buf) < 32768 and time.monotonic() < deadline:
                    chunk = t.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
    except Exception as e:
        return {"error": str(e)[:160]}
    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace").split("\r\n")
    status = head[0] if head else ""
    headers = {}
    for line in head[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.setdefault(k.strip().lower(), v.strip())
    hsts = headers.get("strict-transport-security", "")
    max_age = None
    for part in hsts.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1].strip('"'))
            except ValueError:
                max_age = None
    keep = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options",
            "referrer-policy", "permissions-policy", "server", "x-powered-by", "location", "set-cookie")
    return {"status": status[:120], "headers": {k: headers[k][:300] for k in keep if k in headers},
            "hsts": {"present": bool(hsts), "max_age": max_age, "include_subdomains": "includesubdomains" in hsts.lower(),
                     "preload": "preload" in hsts.lower()}}


# ------------------------------------------------------------------ the scan
def scan(ip: str, port: int = 443, sni: str = "", timeout: float = 5.0, budget: float = 90.0) -> dict:
    t0 = time.time()
    pr = Prober(ip, port, sni, timeout, budget)
    res = {"target": {"ip": ip, "port": int(port), "sni": sni}, "started": t0, "protocols": [], "ciphers": {},
           "server_order": {}, "kx": {}, "features": {}, "cert": None, "chain": [], "trust": {}, "http": {},
           "reachable": True, "error": ""}
    # Can we reach it at all?
    try:
        socket.create_connection((ip, int(port)), timeout=timeout).close()
    except OSError as e:
        res.update(reachable=False, error=f"{ip}:{port} cannot be reached from the dashboard ({e})")
        res["duration"] = round(time.time() - t0, 1)
        res.update(grade(res))
        return res

    with ThreadPoolExecutor(max_workers=5) as ex:
        support = dict(zip(PROTO_ORDER, ex.map(pr.supports, PROTO_ORDER)))
    if not any(ok for ok, _ in support.values()):
        errs = {a.error for _, a in support.values() if a.error}
        res["error"] = "The address answers but no TLS handshake succeeded" + (f" ({'; '.join(sorted(errs))[:200]})" if errs else "")
    first_ok = {}
    for v in PROTO_ORDER:
        ok, a = support[v]
        res["protocols"].append({"name": PROTO_NAMES[v], "supported": ok})
        if ok:
            first_ok[v] = a

    def per_version(v):
        got = pr.enumerate(v, first_ok[v])
        return v, got, pr.server_order(v, got)

    with ThreadPoolExecutor(max_workers=4) as ex:
        for v, got, order in ex.map(per_version, list(first_ok)):
            res["ciphers"][PROTO_NAMES[v]] = [suite_info(c) for c in got]
            res["server_order"][PROTO_NAMES[v]] = order

    # Key exchange per suite family, from the first answers (TLS 1.2 down)
    for v, a in first_ok.items():
        if a.kx:
            res["kx"][PROTO_NAMES[v]] = a.kx
    # DHE strength when DHE suites are taken
    dhe = [c for p in res["ciphers"].values() for c in p if c["kx"] == "DHE"]
    best12 = next((v for v in (TLS12, TLS11, TLS10, SSL3) if v in first_ok), None)
    if dhe and best12:
        codes = [int(c["code"], 16) for c in res["ciphers"].get(PROTO_NAMES[best12], []) if c["kx"] == "DHE"]
        if codes:
            a = pr.hello(best12, codes)
            if a.kx.get("dh_bits"):
                res["kx"]["DHE"] = {"dh_bits": a.kx["dh_bits"]}

    # Features from the best pre-1.3 answer
    a12 = first_ok.get(best12) if best12 else None
    f = res["features"]
    if a12:
        f["secure_renegotiation"] = 0xFF01 in a12.extensions
        f["ocsp_stapling"] = 5 in a12.extensions or a12.ocsp is not None
        f["session_tickets"] = 35 in a12.extensions
        f["extended_master_secret"] = 23 in a12.extensions
        alpn = a12.extensions.get(16)
        f["alpn"] = alpn[3:].decode(errors="replace") if alpn and len(alpn) > 3 else ""
        comp = pr.hello(best12, [int(c["code"], 16) for c in res["ciphers"].get(PROTO_NAMES[best12], [])] or list(SUITES),
                        compression=True, read_all=False)
        f["compression"] = bool(comp.ok and comp.compression == 1)
    # TLS_FALLBACK_SCSV: offer a lower version with the signal; a correct server refuses (alert 86)
    lower = [v for v in (TLS11, TLS10, SSL3) if v in first_ok]
    top = max(first_ok) if first_ok else None
    if lower and top and top > lower[0]:
        codes = [int(c["code"], 16) for c in res["ciphers"].get(PROTO_NAMES[lower[0]], [])] or list(SUITES)
        a = pr.hello(lower[0], codes + [SCSV_FALLBACK], read_all=False)
        f["fallback_scsv"] = (not a.ok) and bool(a.alert) and a.alert[1] == 86
    elif first_ok:
        f["fallback_scsv"] = None                                         # only one protocol: nothing to fall back to

    der = a12.certs if a12 and a12.certs else []
    if not der and first_ok:
        der = _tls_chain_fallback(ip, port, sni, timeout)
    res["cert"], res["chain"] = _cert_details(der)
    if res["cert"]:
        res["cert"]["name_ok"] = _name_matches(sni, res["cert"]["san"] or [res["cert"]["subject"]]) if sni else None
        res["trust"] = _trust(ip, port, sni, timeout)
        res["http"] = _http(ip, port, sni, timeout)
    res["connections"] = pr.connections
    res["duration"] = round(time.time() - t0, 1)
    res.update(grade(res))
    return res


# ------------------------------------------------------------------ the rating
def _finding(fid, severity, title, detail=""):
    return {"id": fid, "severity": severity, "title": title, "detail": detail}


def grade(res: dict) -> dict:
    """A letter grade, the three scores and every finding, from a scan result."""
    if not res.get("reachable") or not any(p["supported"] for p in res.get("protocols", [])):
        return {"grade": "-", "score": {}, "caps": [], "findings": [
            _finding("scan.unreachable", "info", "Not tested", res.get("error") or "No TLS answer")]}
    on = {p["name"] for p in res["protocols"] if p["supported"]}
    all_suites = [c for lst in res["ciphers"].values() for c in lst]
    cert = res.get("cert") or {}
    trust = res.get("trust") or {}
    http = res.get("http") or {}
    feats = res.get("features") or {}
    findings, caps = [], []

    def cap(letter, why):
        caps.append({"grade": letter, "why": why})

    # --- protocol score
    pscore = {"SSL 3.0": 80, "TLS 1.0": 90, "TLS 1.1": 95, "TLS 1.2": 100, "TLS 1.3": 100}
    vals = [pscore[n] for n in on if n in pscore]
    proto = (max(vals) + min(vals)) / 2 if vals else 0
    if "SSL 3.0" in on:
        findings.append(_finding("tls.ssl3", "critical", "SSL 3.0 is enabled",
                                 "Broken by POODLE; no current client needs it."))
        cap("C", "SSL 3.0 is supported")
    old = [n for n in ("TLS 1.0", "TLS 1.1") if n in on]
    if old:
        findings.append(_finding("tls.old", "high", f"{' and '.join(old)} enabled",
                                 "Deprecated (RFC 8996); browsers no longer accept them."))
        cap("B", f"{' and '.join(old)} supported")
    if "TLS 1.2" not in on and "TLS 1.3" not in on:
        findings.append(_finding("tls.no12", "critical", "Neither TLS 1.2 nor TLS 1.3 is offered"))
        cap("C", "No TLS 1.2 or 1.3")
    if "TLS 1.3" not in on:
        findings.append(_finding("tls.no13", "low", "TLS 1.3 is not enabled",
                                 "TLS 1.3 is faster and removes the legacy options of earlier versions."))

    # --- key exchange score (certificate key, then DH/ECDH)
    kbits = (cert.get("key") or {}).get("bits") or 0
    ktype = (cert.get("key") or {}).get("type")
    eq = kbits
    if ktype in ("EC", "EdDSA"):                                          # EC 256 is about RSA 3072
        eq = {256: 3072, 384: 7680, 521: 15360}.get(kbits, kbits * 12)
    kx = 0 if eq == 0 else 20 if eq < 512 else 40 if eq < 1024 else 80 if eq < 2048 else 90 if eq < 4096 else 100
    dh = (res.get("kx") or {}).get("DHE", {}).get("dh_bits")
    if dh:
        kx = min(kx, 20 if dh < 512 else 40 if dh < 1024 else 80 if dh < 2048 else 90 if dh < 4096 else 100)
        if dh < 2048:
            findings.append(_finding("kx.dh_weak", "high" if dh < 1024 else "medium", f"DH parameters of {dh} bits",
                                     "Below 2048 bits (Logjam); prefer ECDHE or use a 2048-bit DH file."))
            cap("F" if dh < 1024 else "B", f"DH parameters {dh} bits")
    if ktype == "RSA" and kbits and kbits < 2048:
        findings.append(_finding("cert.key_weak", "high", f"RSA key of {kbits} bits", "Use 2048 bits or more."))
        cap("F" if kbits < 1024 else "B", f"RSA key {kbits} bits")

    # --- cipher score
    bits = [c["bits"] for c in all_suites]
    cipher = 0
    if bits:
        def s(b): return 0 if b == 0 else 20 if b < 128 else 80 if b < 256 else 100
        cipher = (s(max(bits)) + s(min(bits))) / 2
    names = lambda pred: sorted({c["name"] for c in all_suites if pred(c)})
    exp = names(lambda c: c["export"])
    if exp:
        findings.append(_finding("cipher.export", "critical", "Export-grade cipher suites accepted", ", ".join(exp)))
        cap("F", "Export suites (FREAK / Logjam)")
    null_anon = names(lambda c: c["bits"] == 0 or c["kx"] == "anon")
    if null_anon:
        findings.append(_finding("cipher.null_anon", "critical", "NULL or anonymous cipher suites accepted",
                                 ", ".join(null_anon)))
        cap("F", "NULL or anonymous suites")
    rc4 = names(lambda c: c["rc4"])
    if rc4:
        findings.append(_finding("cipher.rc4", "high", "RC4 cipher suites accepted", ", ".join(rc4)))
        cap("C" if ("TLS 1.1" in on or "TLS 1.2" in on) else "B", "RC4")
    b64 = names(lambda c: c["block64"] and not c["export"])
    if b64:
        findings.append(_finding("cipher.3des", "medium", "64-bit block ciphers (3DES / DES / IDEA) accepted",
                                 "Sweet32; " + ", ".join(b64)))
        cap("C", "64-bit block ciphers (Sweet32)")
    modern = [c for c in all_suites if c["strength"] != "insecure"]
    if modern and not any(c["fs"] for c in modern):
        findings.append(_finding("cipher.no_fs", "high", "No forward secrecy",
                                 "No ECDHE or DHE suite: a stolen key decrypts recorded traffic."))
        cap("B", "No forward secrecy")
    elif any(not c["fs"] for c in modern):
        findings.append(_finding("cipher.some_no_fs", "low", "Suites without forward secrecy accepted",
                                 ", ".join(sorted({c['name'] for c in modern if not c['fs']}))))
    if modern and not any(c["aead"] for c in modern):
        findings.append(_finding("cipher.no_aead", "medium", "No AEAD cipher suite (GCM / ChaCha20)"))
        cap("B", "No AEAD suites")
    cbc = names(lambda c: not c["aead"] and c["strength"] != "insecure" and not c["block64"])
    if cbc:
        findings.append(_finding("cipher.cbc", "low", "CBC cipher suites accepted",
                                 "Not broken with TLS 1.2, but dated; " + ", ".join(cbc[:8]) + (" ..." if len(cbc) > 8 else "")))
    order = res.get("server_order") or {}
    if any(v is False for v in order.values()) and any(c["strength"] != "strong" for c in all_suites):
        findings.append(_finding("cipher.client_order", "low", "The client's cipher order is used",
                                 "With weaker suites enabled, the server should pick its own strongest one."))

    # --- certificate
    if cert:
        if cert.get("days_left", 0) < 0:
            findings.append(_finding("cert.expired", "critical", "The certificate has expired", f"Expired on {cert['not_after'][:10]}"))
            cap("T", "Certificate expired")
        elif cert.get("not_yet_valid"):
            findings.append(_finding("cert.not_yet", "critical", "The certificate is not valid yet"))
            cap("T", "Certificate not yet valid")
        elif cert.get("days_left", 999) < 30:
            findings.append(_finding("cert.expiring", "high", f"The certificate expires in {cert['days_left']} days", cert["not_after"][:10]))
        elif cert.get("days_left", 999) < 60:
            findings.append(_finding("cert.expiring", "medium", f"The certificate expires in {cert['days_left']} days", cert["not_after"][:10]))
        if cert.get("signature") in ("md5", "sha1"):
            findings.append(_finding("cert.sig_weak", "high", f"Certificate signed with {cert['signature'].upper()}"))
            cap("T", f"{cert['signature'].upper()} signature")
        if trust.get("trusted") is False:
            why = trust.get("error") or "not trusted"
            selfsig = cert.get("self_signed")
            findings.append(_finding("cert.untrusted", "high", "Not trusted by the public certificate authorities",
                                     ("Self-signed. " if selfsig and "self-signed" not in why.lower() else "") + why +
                                     " (fine for an internal service whose clients trust your own CA)."))
            cap("T", "Certificate not trusted")
        if cert.get("name_ok") is False:
            findings.append(_finding("cert.name", "high", f"The certificate does not cover {res['target'].get('sni')}",
                                     "Names: " + ", ".join(cert.get("san") or [cert.get("subject", "")])))
            cap("T", "Name mismatch")
    # --- protocol features
    if feats.get("secure_renegotiation") is False:
        findings.append(_finding("tls.reneg", "high", "Secure renegotiation is not supported"))
        cap("C", "No secure renegotiation")
    if feats.get("compression"):
        findings.append(_finding("tls.compression", "high", "TLS compression is enabled (CRIME)"))
        cap("C", "TLS compression")
    if feats.get("fallback_scsv") is False:
        findings.append(_finding("tls.fallback", "low", "No downgrade protection (TLS_FALLBACK_SCSV)",
                                 "The server accepted a lower version with the fallback signal."))
    if feats.get("ocsp_stapling") is False:
        findings.append(_finding("tls.ocsp", "info", "OCSP stapling is off",
                                 "Clients check revocation themselves - slower first connections."))
    # --- HTTP
    hsts = http.get("hsts") or {}
    if http and not http.get("error"):
        if not hsts.get("present"):
            findings.append(_finding("http.hsts", "medium", "No HSTS header",
                                     "Browsers may still try plain HTTP first (SSL stripping)."))
        elif (hsts.get("max_age") or 0) < 15552000:
            findings.append(_finding("http.hsts_short", "low", f"HSTS max-age is short ({hsts.get('max_age')} s)",
                                     "Use at least 180 days (15552000)."))
        hdr = http.get("headers") or {}
        miss = [h for h in ("x-frame-options", "x-content-type-options") if h not in hdr]
        if "content-security-policy" in hdr and "frame-ancestors" in hdr["content-security-policy"].lower() and "x-frame-options" in miss:
            miss.remove("x-frame-options")
        if miss:
            findings.append(_finding("http.headers", "low", "Security headers missing", ", ".join(miss)))

    # --- total
    score = round(proto * 0.3 + kx * 0.3 + cipher * 0.4)
    letter = "A" if score >= 80 else "B" if score >= 65 else "C" if score >= 50 else "D" if score >= 35 else "E" if score >= 20 else "F"
    rank = "A+ A A- B C D E F".split()
    for c in caps:
        if c["grade"] in rank and c["grade"] != "T" and rank.index(c["grade"]) > rank.index(letter):
            letter = c["grade"]
    if letter == "A":
        minus = [f for f in findings if f["id"] in ("tls.no13", "tls.fallback", "cipher.client_order")]
        if minus:
            letter = "A-"
        elif hsts.get("present") and (hsts.get("max_age") or 0) >= 15552000 and not any(
                f["severity"] in ("critical", "high", "medium") for f in findings
                if f["id"] not in ("cert.untrusted", "cert.name", "cert.sig_weak", "cert.expired", "cert.not_yet")):
            letter = "A+"
    trust_cap = any(c["grade"] == "T" for c in caps)
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: sev.get(f["severity"], 9))
    return {"grade": "T" if trust_cap else letter, "grade_if_trusted": letter if trust_cap else None,
            "score": {"protocol": round(proto), "key_exchange": round(kx), "cipher": round(cipher), "total": score},
            "caps": caps, "findings": findings}


def digest(res: dict) -> str:
    """A short fingerprint of what was found, to tell whether two scans differ."""
    keep = (res.get("grade"), [p["supported"] for p in res.get("protocols", [])],
            sorted(c["code"] for lst in res.get("ciphers", {}).values() for c in lst),
            (res.get("cert") or {}).get("sha256"))
    return hashlib.sha256(repr(keep).encode()).hexdigest()[:16]
