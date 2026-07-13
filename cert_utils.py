"""
TLS helpers: generate a self-signed cert on first run, validate uploaded PEMs.
Kept dependency-light — uses `cryptography`, which is portable across Windows/Linux
(openssl CLI is not present in the slim Docker image).
"""
from __future__ import annotations

import datetime
import ipaddress
import os
from pathlib import Path

CERT_FILE = os.getenv("TLS_CERT_FILE", "certs/server.crt")
KEY_FILE = os.getenv("TLS_KEY_FILE", "certs/server.key")


def _certs_present(cert_path: str, key_path: str) -> bool:
    return os.path.exists(cert_path) and os.path.exists(key_path)


def ensure_self_signed(cert_path: str = CERT_FILE, key_path: str = KEY_FILE,
                       common_name: str | None = None) -> tuple[str, str]:
    """Generate a self-signed cert/key pair if either file is missing. Idempotent."""
    if _certs_present(cert_path, key_path):
        return cert_path, key_path

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    cn = common_name or os.getenv("TLS_COMMON_NAME", "netscaler-dashboard")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    san = x509.SubjectAlternativeName([
        x509.DNSName(cn),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    Path(cert_path).parent.mkdir(parents=True, exist_ok=True)
    Path(key_path).parent.mkdir(parents=True, exist_ok=True)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass
    return cert_path, key_path


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
    """Validate then atomically replace the active cert/key. Restart applies it."""
    validate_pair(cert_pem, key_pem)
    Path(cert_path).parent.mkdir(parents=True, exist_ok=True)
    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(key_path, "wb") as f:
        f.write(key_pem)
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass
