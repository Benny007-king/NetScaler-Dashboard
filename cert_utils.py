"""
TLS helpers. On first run the app generates a local CA and issues a server cert
signed by it — install the CA (downloadable from Settings) to get trusted,
warning-free HTTPS. You can also generate a CSR to have the server cert signed by
your own/corporate CA, then upload the signed cert back.

The certificate issued by the local CA is kept current by itself: it names this
host (host name and addresses, plus TLS_SAN) and is issued again at start-up when
those change or when it is about to expire. A certificate you uploaded is never
touched.

Dependency-light: uses `cryptography`, which is portable across Windows/Linux
(the openssl CLI is not present in the slim Docker image).
"""
from __future__ import annotations

import datetime
import ipaddress
import os
import shutil
import socket
import ssl
import sys
import tempfile
from pathlib import Path

_CERT_DIR = os.path.join(os.getenv("DATA_DIR", "data"), "certs")
CERT_FILE = os.getenv("TLS_CERT_FILE") or os.path.join(_CERT_DIR, "server.crt")
KEY_FILE = os.getenv("TLS_KEY_FILE") or os.path.join(_CERT_DIR, "server.key")
CA_CERT_FILE = os.getenv("TLS_CA_CERT_FILE") or os.path.join(_CERT_DIR, "ca.crt")
CA_KEY_FILE = os.getenv("TLS_CA_KEY_FILE") or os.path.join(_CERT_DIR, "ca.key")
# CSR key is parked here until the signed cert is uploaded — the live server key
# is never disturbed just by generating a CSR.
PENDING_KEY_FILE = KEY_FILE + ".pending"

import re
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

LEAF_DAYS = 825
RENEW_BEFORE_DAYS = 30


def _log(msg: str) -> None:
    # Runs in the gunicorn master before the app's logging exists.
    print(f"cert_utils: {msg}", file=sys.stderr, flush=True)


def _present(*paths: str) -> bool:
    return all(os.path.exists(p) for p in paths)


def _write(path: str, data: bytes, secret: bool = False) -> None:
    """Atomically write bytes. Secret files (private keys) are created with 0600
    up-front — no world-readable window and no torn/corrupt file on crash."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    mode = 0o600 if secret else 0o644
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(str(tmp), str(path))
    finally:
        try:
            if os.path.exists(tmp): os.remove(tmp)
        except Exception: pass


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _not_after(cert) -> datetime.datetime:
    v = getattr(cert, "not_valid_after_utc", None)
    return v if v is not None else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def _not_before(cert) -> datetime.datetime:
    v = getattr(cert, "not_valid_before_utc", None)
    return v if v is not None else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)


# ------------------------------------------------------------------------ names

def _clean_name(entry: str):
    """One name for a certificate: ('ip', address) or ('dns', a-label), or None
    when it cannot go into a certificate (a URL, spaces, an empty label...)."""
    e = str(entry or "").strip().strip('"\'').strip()
    if not e:
        return None
    try:
        return ("ip", ipaddress.ip_address(e.strip("[]")))
    except ValueError:
        pass
    if any(c in e for c in "/:@ \t") or len(e) > 253:
        return None
    try:
        labels = []
        for label in e.rstrip(".").split("."):
            if label == "*" and not labels:
                labels.append(label)
                continue
            a = label.encode("idna").decode("ascii").lower()    # non-ASCII names become xn-- labels
            if not _LABEL.fullmatch(a):                         # letters, digits, inner hyphens; 1-63 long
                return None
            labels.append(a)
        return ("dns", ".".join(labels).lower())
    except (UnicodeError, ValueError):
        return None


def _local_names() -> list[str]:
    """What this host is called and the addresses it has - the names an
    administrator actually types into the browser. Set TLS_SAN_AUTO=0 to leave
    them out."""
    if os.getenv("TLS_SAN_AUTO", "1").strip().lower() in ("0", "false", "no"):
        return []
    out = []
    try:
        host = socket.gethostname()
        if host and host.lower() != "localhost":
            out.append(host)
            fq = socket.getfqdn()
            if fq and "." in fq and fq.lower() not in (host.lower(), "localhost.localdomain"):
                out.append(fq)
    except OSError:
        pass
    try:                                  # every interface address (Linux)
        import fcntl
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for _idx, name in socket.if_nameindex():
                try:
                    packed = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", name[:15].encode()))   # SIOCGIFADDR
                    out.append(socket.inet_ntoa(packed[20:24]))
                except OSError:
                    pass
        finally:
            s.close()
    except Exception:
        pass
    try:                                  # the address of the default route (any platform; sends nothing)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.0.2.1", 9))
            out.append(s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass
    return [n for n in out if n and not n.startswith("127.") and n != "0.0.0.0"]


def _san_names(common_name: str, extra: str | None = None, local: bool = True) -> list[tuple]:
    """Ordered, de-duplicated (kind, value) pairs for the SAN extension."""
    raw = [common_name]
    if local:
        raw += ["localhost", "127.0.0.1"] + _local_names()
        raw += os.getenv("TLS_SAN", "").split(",")
    raw += str(extra or "").replace(";", ",").replace("\n", ",").split(",")
    seen, out = set(), []
    for e in raw:
        if not str(e or "").strip():
            continue
        item = _clean_name(e)
        if item is None:
            _log(f"ignoring a name that cannot go into a certificate: {str(e).strip()[:80]!r}")
            continue
        key = (item[0], str(item[1]))
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _san_entries(common_name: str) -> list[str]:
    """Kept for callers that want plain strings."""
    return [str(v) for _k, v in _san_names(common_name)]


def _build_san(names: list[tuple]):
    from cryptography import x509
    return x509.SubjectAlternativeName(
        [x509.IPAddress(v) if k == "ip" else x509.DNSName(v) for k, v in names])


def _subject(common_name: str):
    """The subject for a leaf. A CN is limited to 64 characters; a longer host
    name is carried by the SAN (which is what clients check) and left out here."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    item = _clean_name(common_name)
    cn = str(item[1]) if item else "netscaler-dashboard"
    if len(cn) > 64:
        cn = "netscaler-dashboard"
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _key_pem(key) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _leaf_cn() -> str:
    return os.getenv("TLS_COMMON_NAME", "").strip().strip('"\'') or "netscaler-dashboard"


# --------------------------------------------------------------------------- CA

def ensure_ca(ca_cert: str = CA_CERT_FILE, ca_key: str = CA_KEY_FILE):
    """Create a local root CA if absent. Returns (ca_cert_obj, ca_key_obj)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    if _present(ca_cert, ca_key):
        cert = x509.load_pem_x509_certificate(open(ca_cert, "rb").read())
        key = serialization.load_pem_private_key(open(ca_key, "rb").read(), password=None)
        return cert, key

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    name = x509.Name([
        # an empty or over-long value must not stop the first start
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, (os.getenv("TLS_ORG") or "NetScaler Dashboard").strip()[:64] or "NetScaler Dashboard"),
        x509.NameAttribute(NameOID.COMMON_NAME, (os.getenv("TLS_CA_NAME") or "NetScaler Dashboard Local CA").strip()[:64] or "NetScaler Dashboard Local CA"),
    ])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3652))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    _write(ca_cert, cert.public_bytes(serialization.Encoding.PEM))
    _write(ca_key, _key_pem(key), secret=True)
    return cert, key


def issue_server_cert(cert_path: str = CERT_FILE, key_path: str = KEY_FILE,
                      ca_cert: str = CA_CERT_FILE, ca_key: str = CA_KEY_FILE,
                      common_name: str | None = None) -> tuple[str, str]:
    """Issue a server cert signed by the local CA (creating the CA if needed)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID

    ca_crt, ca_k = ensure_ca(ca_cert, ca_key)
    cn = common_name or _leaf_cn()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_subject(cn))
        .issuer_name(ca_crt.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=LEAF_DAYS))
        .add_extension(_build_san(_san_names(cn)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_k.public_key()), critical=False)
        .sign(ca_k, hashes.SHA256())
    )
    # key first: if the second write fails the old certificate no longer matches,
    # and the next start issues a fresh pair instead of serving a broken one
    _write(key_path, _key_pem(key), secret=True)
    _write(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def _issued_by_local_ca(cert, ca_cert_path: str) -> bool:
    from cryptography import x509
    try:
        ca = x509.load_pem_x509_certificate(open(ca_cert_path, "rb").read())
        cert.verify_directly_issued_by(ca)
        return True
    except Exception:
        return False


def _why_reissue(cert_path: str, key_path: str, ca_cert: str, ca_key: str):
    """A reason to issue the server certificate again, or None to leave it alone."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    try:
        cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
        key = serialization.load_pem_private_key(open(key_path, "rb").read(), password=None)
    except Exception as e:
        return f"the stored certificate or key cannot be read ({e})" if _present(ca_cert, ca_key) else None
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    if (cert.public_key().public_bytes(serialization.Encoding.DER, pub)
            != key.public_key().public_bytes(serialization.Encoding.DER, pub)):
        return "the stored certificate and key do not belong together" if _present(ca_cert, ca_key) else None

    left = (_not_after(cert) - _now()).days
    if not (_present(ca_cert, ca_key) and _issued_by_local_ca(cert, ca_cert)):
        # Somebody's own certificate: never replaced, but say when it runs out.
        if left < 0:
            _log(f"WARNING: the installed certificate expired {-left} day(s) ago - upload a new one in Settings")
        elif left <= RENEW_BEFORE_DAYS:
            _log(f"WARNING: the installed certificate expires in {left} day(s) - upload a new one in Settings")
        return None

    if left <= RENEW_BEFORE_DAYS:
        return f"it expires in {left} day(s)"
    try:
        have = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        have_set = {("ip", str(v)) for v in have.get_values_for_type(x509.IPAddress)} | \
                   {("dns", v.lower()) for v in have.get_values_for_type(x509.DNSName)}
    except x509.ExtensionNotFound:
        have_set = set()
    want_set = {(k, str(v)) for k, v in _san_names(_leaf_cn())}
    if have_set != want_set:
        return "the host's names or addresses changed (%s)" % ", ".join(sorted(v for _k, v in want_set ^ have_set))
    return None


def ensure_signed(cert_path: str = CERT_FILE, key_path: str = KEY_FILE,
                  ca_cert: str = CA_CERT_FILE, ca_key: str = CA_KEY_FILE) -> tuple[str, str]:
    """Start-up path: make sure there is a usable server certificate.

    A certificate from the local CA is issued again when it is about to expire or
    when it no longer names this host. An expired local CA is replaced as well
    (it then has to be installed again on the administrators' machines)."""
    from cryptography import x509
    if _present(cert_path, key_path):
        try:
            why = _why_reissue(cert_path, key_path, ca_cert, ca_key)
        except Exception as e:                    # never let a check stop the start
            _log(f"certificate check skipped: {e}")
            why = None
        if why is None:
            return cert_path, key_path
        _log(f"issuing the server certificate again: {why}")
    if _present(ca_cert, ca_key):
        try:
            ca = x509.load_pem_x509_certificate(open(ca_cert, "rb").read())
            if (_not_after(ca) - _now()).days <= RENEW_BEFORE_DAYS:
                _log("the local CA is expiring: creating a new one - install it again where the old one was trusted")
                for p in (ca_cert, ca_key):
                    os.replace(p, p + ".old")
        except Exception as e:
            _log(f"local CA check skipped: {e}")
    return issue_server_cert(cert_path, key_path, ca_cert, ca_key)


# Back-compat alias: a plain self-signed cert (no CA). Kept for callers/tests.
def ensure_self_signed(cert_path: str = CERT_FILE, key_path: str = KEY_FILE,
                       common_name: str | None = None) -> tuple[str, str]:
    return ensure_signed(cert_path, key_path)


# -------------------------------------------------------------------------- CSR

def generate_csr(pending_key_path: str = PENDING_KEY_FILE, common_name: str | None = None,
                 extra_san: str | None = None) -> bytes:
    """Generate a new key + CSR (for signing by your own CA). The key is parked at
    pending_key_path; the live server key is untouched until save_signed_cert()
    installs the returned CSR's signed certificate. Returns the CSR PEM.

    The request names the host you give (and any extra names) - not this
    container's internal names. Raises ValueError for names that cannot be used."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    cn = (common_name or "").strip() or _leaf_cn()
    item = _clean_name(cn)
    if item is None:
        raise ValueError("The host name is not valid for a certificate (use a DNS name or an IP address).")
    if len(str(item[1])) > 64:
        raise ValueError("The host name is longer than 64 characters, which a certificate's common name cannot hold.")
    for e in str(extra_san or "").replace(";", ",").replace("\n", ",").split(","):
        if e.strip() and _clean_name(e) is None:
            raise ValueError(f"'{e.strip()[:80]}' is not a valid additional name (use DNS names or IP addresses).")
    names = _san_names(cn, extra=extra_san, local=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(_subject(cn))
        .add_extension(_build_san(names), critical=False)
        .sign(key, hashes.SHA256())
    )
    _write(pending_key_path, _key_pem(key), secret=True)
    return csr.public_bytes(serialization.Encoding.PEM)


# ------------------------------------------------------------------ upload/save

def validate_pair(cert_pem: bytes, key_pem: bytes) -> dict:
    """Raise ValueError unless this certificate and key can really be served.
    Returns a short description of the certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        key = serialization.load_pem_private_key(key_pem, password=None)
    except Exception as e:
        raise ValueError(f"Invalid PEM data: {e}")
    cert_pub = cert.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert_pub != key_pub:
        raise ValueError("Certificate and private key do not match")

    now = _now()
    if _not_after(cert) < now:
        raise ValueError(f"This certificate expired on {_not_after(cert):%Y-%m-%d}.")
    if _not_before(cert) > now + datetime.timedelta(minutes=5):
        raise ValueError(f"This certificate is not valid before {_not_before(cert):%Y-%m-%d}.")
    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("This is a CA certificate, not a server certificate. Paste the server "
                             "certificate first, followed by the CA certificates.")
    except x509.ExtensionNotFound:
        pass

    # The real test: can the TLS library the server runs on load exactly these
    # bytes? This is what catches a half-pasted chain or a key that is too weak,
    # which would otherwise take HTTPS down the moment they are saved.
    d = tempfile.mkdtemp(prefix="nsd-cert-")
    try:
        c, k = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        _write(c, cert_pem)
        _write(k, key_pem, secret=True)
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(c, k)
    except ssl.SSLError as e:
        raise ValueError(f"The server cannot use this certificate or key: {getattr(e, 'reason', None) or e}")
    except Exception as e:
        raise ValueError(f"The certificate or key cannot be loaded: {e}")
    finally:
        shutil.rmtree(d, ignore_errors=True)
    # Every block of the chain has to be whole: a half-pasted one is skipped
    # silently by some parsers and breaks the handshake in others.
    incomplete = "One of the certificates in the chain is incomplete or damaged - paste every block in full."
    blocks = cert_pem.count(b"-----BEGIN CERTIFICATE-----")
    if blocks != cert_pem.count(b"-----END CERTIFICATE-----"):
        raise ValueError(incomplete)
    try:
        if len(x509.load_pem_x509_certificates(cert_pem)) != blocks:
            raise ValueError(incomplete)
    except ValueError:
        raise ValueError(incomplete)

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(v) for v in san.get_values_for_type(x509.DNSName)] + \
                [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []
    return {"subject": cert.subject.rfc4514_string(), "names": names[:20],
            "expires": f"{_not_after(cert):%Y-%m-%d}", "days_left": (_not_after(cert) - now).days}


def _keep_previous(cert_path: str, key_path: str) -> None:
    """Keep the pair that is about to be replaced as *.prev (best effort)."""
    for p, secret in ((cert_path, False), (key_path, True)):
        try:
            if os.path.exists(p):
                _write(p + ".prev", open(p, "rb").read(), secret=secret)
        except Exception:
            pass


def save_pair(cert_pem: bytes, key_pem: bytes,
              cert_path: str = CERT_FILE, key_path: str = KEY_FILE) -> dict:
    """Validate, then replace the active cert/key (the old pair is kept as *.prev).
    The new pair is used for new connections straight away."""
    info = validate_pair(cert_pem, key_pem)
    _keep_previous(cert_path, key_path)
    _write(key_path, key_pem, secret=True)
    _write(cert_path, cert_pem)
    return info


def save_signed_cert(cert_pem: bytes, key_path: str = KEY_FILE, cert_path: str = CERT_FILE,
                     pending_key_path: str = PENDING_KEY_FILE) -> dict:
    """Install a cert signed from a CSR we generated: validate it against the
    parked pending key, then promote that key to the live key and write the cert."""
    if not os.path.exists(pending_key_path):
        raise ValueError("No pending CSR key found — generate a CSR first")
    pending_key = open(pending_key_path, "rb").read()
    info = validate_pair(cert_pem, pending_key)
    _keep_previous(cert_path, key_path)
    _write(key_path, pending_key, secret=True)
    _write(cert_path, cert_pem)
    try: os.remove(pending_key_path)
    except Exception: pass
    return info
