"""Tests for the built-in certificate and for certificate uploads (cert_utils.py).

    python tests/test_certs.py        # needs the app's Python packages; uses a temporary directory
"""
import os
import ssl
import sys
import tempfile

d = tempfile.mkdtemp()
os.environ.update(DATA_DIR=d, TLS_SAN="dash.example.com, 192.0.2.50")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cert_utils as cu                       # noqa: E402
from cryptography import x509                 # noqa: E402
from cryptography.x509.oid import ExtensionOID  # noqa: E402

ok_n = bad_n = 0


def check(cond, what):
    global ok_n, bad_n
    if cond:
        ok_n += 1; print("   ok    " + what)
    else:
        bad_n += 1; print("   FAIL  " + what)


def leaf():
    return x509.load_pem_x509_certificate(open(cu.CERT_FILE, "rb").read())


def names(c):
    san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return [str(v) for v in san.get_values_for_type(x509.DNSName)] + [str(v) for v in san.get_values_for_type(x509.IPAddress)]


cu.ensure_signed()
c1 = leaf()
n = names(c1)
print("   names in the first certificate:", n)
check("dash.example.com" in n and "192.0.2.50" in n, "TLS_SAN names are in the certificate")
import socket
check(socket.gethostname() in n, "the host's own name is in the certificate (%s)" % socket.gethostname())
check(any(x.count(".") == 3 and not x.startswith("127.") and x != "192.0.2.50" for x in n), "an address of this host is in the certificate")
ext = {e.oid for e in c1.extensions}
check(ExtensionOID.SUBJECT_KEY_IDENTIFIER in ext and ExtensionOID.AUTHORITY_KEY_IDENTIFIER in ext and ExtensionOID.KEY_USAGE in ext,
      "the certificate has key identifiers and key usage")
ca = x509.load_pem_x509_certificate(open(cu.CA_CERT_FILE, "rb").read())
check(ExtensionOID.SUBJECT_KEY_IDENTIFIER in {e.oid for e in ca.extensions}, "a new CA has a subject key identifier")
ctx = ssl.create_default_context(cafile=cu.CA_CERT_FILE)      # Python's default (strict on 3.13) verification
try:
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cu.CERT_FILE, cu.KEY_FILE)
    check(True, "the generated pair loads in the TLS library")
except Exception as e:
    check(False, "the generated pair loads in the TLS library: %s" % e)

cu.ensure_signed()
check(leaf().serial_number == c1.serial_number, "a restart with nothing changed keeps the certificate")

os.environ["TLS_SAN"] = "dash.example.com, 192.0.2.50, new.example.com"
cu.ensure_signed()
c2 = leaf()
check(c2.serial_number != c1.serial_number and "new.example.com" in names(c2), "changing TLS_SAN re-issues it on the next start")

cu.LEAF_DAYS = 20                                  # a certificate close to its end
cu.issue_server_cert()
c3 = leaf()
cu.LEAF_DAYS = 825
cu.ensure_signed()
c4 = leaf()
check(c4.serial_number != c3.serial_number and (cu._not_after(c4) - cu._now()).days > 800, "a certificate with 20 days left is renewed on the next start")

# somebody's own certificate (not from the local CA) is never replaced, even when about to expire
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "own.example.com")])
own = (x509.CertificateBuilder().subject_name(nm).issuer_name(nm).public_key(k.public_key())
       .serial_number(x509.random_serial_number()).not_valid_before(cu._now() - datetime.timedelta(days=300))
       .not_valid_after(cu._now() + datetime.timedelta(days=5))
       .add_extension(x509.SubjectAlternativeName([x509.DNSName("own.example.com")]), critical=False)
       .sign(k, hashes.SHA256()))
info = cu.save_pair(own.public_bytes(serialization.Encoding.PEM), cu._key_pem(k))
check(info["days_left"] <= 5 and os.path.exists(cu.CERT_FILE + ".prev"), "an uploaded certificate is installed, the previous pair is kept as .prev")
cu.ensure_signed()
check(leaf().serial_number == own.serial_number, "an uploaded certificate is never replaced by a restart, even 5 days before it expires")

# a pair that does not belong together is repaired from the local CA
open(cu.KEY_FILE, "wb").write(cu._key_pem(rsa.generate_private_key(public_exponent=65537, key_size=2048)))
cu.ensure_signed()
check(cu._issued_by_local_ca(leaf(), cu.CA_CERT_FILE), "a certificate and key that do not belong together are replaced at start")

for bad in ("a\x00b.example", "has space.example", "https://x.example/", "-bad.example", "x" * 64 + ".example", "a..b"):
    check(cu._clean_name(bad) is None, "name %r is refused" % bad[:30])
check(cu._clean_name("Dash.Example.COM") == ("dns", "dash.example.com") and cu._clean_name("*.example.com") == ("dns", "*.example.com")
      and cu._clean_name("[2001:db8::1]")[0] == "ip", "ordinary names, wildcards and IPv6 addresses are accepted")
print("\npassed %d, failed %d" % (ok_n, bad_n))
sys.exit(1 if bad_n else 0)
