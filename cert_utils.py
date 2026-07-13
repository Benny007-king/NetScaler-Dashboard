"""
TLS helpers. On first run the app generates a local CA and issues a server cert
signed by it — install the CA (downloadable from Settings) to get trusted,
warning-free HTTPS. You can also generate a CSR to have the server cert signed by
your own/corporate CA, then upload the signed cert back.

Dependency-light: uses `cryptography`, which is portable across Windows/Linux
(the openssl CLI is not present in the slim Docker image).
"""
from __future__ import annotations

import datetime
import ipaddress
import os
from pathlib import Path

CERT_FILE = os.getenv("TLS_CERT_FILE", "certs/server.crt")
KEY_FILE = os.getenv("TLS_KEY_FILE", "certs/server.key")
CA_CERT_FILE = os.getenv("TLS_CA_CERT_FILE", "certs/ca.crt")
CA_KEY_FILE = os.getenv("TLS_CA_KEY_FILE", "certs/ca.key")
# CSR key is parked here until the signed cert is uploaded — the live server key
# is never disturbed just by generating a CSR.
PENDING_KEY_FILE = KEY_FILE + ".pending"


def _present(*paths: str) -> bool:
    return all(os.path.exists(p) for p in paths)


def _write(path: str, data: bytes, secret: bool = False) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    if secret:
        try: os.chmod(path, 0o600)
        except Exception: pass


def _san_entries(common_name: str) -> list[str]:
    """SAN list: CN, localhost, 127.0.0.1, plus anything in TLS_SAN (comma-sep)."""
    entries = [common_name, "localhost", "127.0.0.1"]
    for e in os.getenv("TLS_SAN", "").split(","):
        e = e.strip()
        if e:
            entries.append(e)
    seen, out = set(), []
    for e in entries:
        if e not in seen:
            seen.add(e); out.append(e)
    return out


def _build_san(common_name: str):
    from cryptography import x509
    gns = []
    for e in _san_entries(common_name):
        try:
            gns.append(x509.IPAddress(ipaddress.ip_address(e)))
        except ValueError:
            gns.append(x509.DNSName(e))
    return x509.SubjectAlternativeName(gns)


def _key_pem(key) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


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
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, os.getenv("TLS_ORG", "NetScaler Dashboard")),
        x509.NameAttribute(NameOID.COMMON_NAME, os.getenv("TLS_CA_NAME", "NetScaler Dashboard Local CA")),
    ])
    now = datetime.datetime.utcnow()
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
        .sign(key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives import serialization as _s
    _write(ca_cert, cert.public_bytes(_s.Encoding.PEM))
    _write(ca_key, _key_pem(key), secret=True)
    return cert, key


def issue_server_cert(cert_path: str = CERT_FILE, key_path: str = KEY_FILE,
                      ca_cert: str = CA_CERT_FILE, ca_key: str = CA_KEY_FILE,
                      common_name: str | None = None) -> tuple[str, str]:
    """Issue a server cert signed by the local CA (creating the CA if needed)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

    ca_crt, ca_k = ensure_ca(ca_cert, ca_key)
    cn = common_name or os.getenv("TLS_COMMON_NAME", "netscaler-dashboard")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_crt.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(_build_san(cn), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_k, hashes.SHA256())
    )
    _write(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    _write(key_path, _key_pem(key), secret=True)
    return cert_path, key_path


def ensure_signed(cert_path: str = CERT_FILE, key_path: str = KEY_FILE) -> tuple[str, str]:
    """Default boot path: ensure a CA-signed server cert exists. Idempotent."""
    if _present(cert_path, key_path):
        return cert_path, key_path
    return issue_server_cert(cert_path, key_path)


# Back-compat alias: a plain self-signed cert (no CA). Kept for callers/tests.
def ensure_self_signed(cert_path: str = CERT_FILE, key_path: str = KEY_FILE,
                       common_name: str | None = None) -> tuple[str, str]:
    return ensure_signed(cert_path, key_path)


# -------------------------------------------------------------------------- CSR

def generate_csr(pending_key_path: str = PENDING_KEY_FILE, common_name: str | None = None) -> bytes:
    """Generate a new key + CSR (for signing by your own CA). The key is parked at
    pending_key_path; the live server key is untouched until save_signed_cert()
    installs the returned CSR's signed certificate. Returns the CSR PEM."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    cn = common_name or os.getenv("TLS_COMMON_NAME", "netscaler-dashboard")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(_build_san(cn), critical=False)
        .sign(key, hashes.SHA256())
    )
    _write(pending_key_path, _key_pem(key), secret=True)
    return csr.public_bytes(serialization.Encoding.PEM)


# ------------------------------------------------------------------ upload/save

def validate_pair(cert_pem: bytes, key_pem: bytes) -> None:
    """Raise ValueError if the PEMs are not a valid, matching cert/key pair."""
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


def save_pair(cert_pem: bytes, key_pem: bytes,
              cert_path: str = CERT_FILE, key_path: str = KEY_FILE) -> None:
    """Validate then replace the active cert/key. Restart applies it."""
    validate_pair(cert_pem, key_pem)
    _write(cert_path, cert_pem)
    _write(key_path, key_pem, secret=True)


def save_signed_cert(cert_pem: bytes, key_path: str = KEY_FILE, cert_path: str = CERT_FILE,
                     pending_key_path: str = PENDING_KEY_FILE) -> None:
    """Install a cert signed from a CSR we generated: validate it against the
    parked pending key, then promote that key to the live key and write the cert."""
    if not os.path.exists(pending_key_path):
        raise ValueError("No pending CSR key found — generate a CSR first")
    pending_key = open(pending_key_path, "rb").read()
    validate_pair(cert_pem, pending_key)
    _write(cert_path, cert_pem)
    _write(key_path, pending_key, secret=True)
    try: os.remove(pending_key_path)
    except Exception: pass
