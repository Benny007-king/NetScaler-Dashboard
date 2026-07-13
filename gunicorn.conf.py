"""
Gunicorn config — HTTPS on 443 with a self-signed cert generated on first boot.
Gunicorn auto-loads this file. Replace the cert from the dashboard Settings page
(or drop your own PEMs at TLS_CERT_FILE / TLS_KEY_FILE) and restart to apply.
"""
import os

from cert_utils import CERT_FILE, KEY_FILE, ensure_signed

bind = f"0.0.0.0:{os.getenv('APP_PORT', '443')}"
workers = int(os.getenv("GUNICORN_WORKERS", "4"))
threads = int(os.getenv("GUNICORN_THREADS", "2"))

# Serve TLS directly unless APP_SSL=0 (e.g. when a reverse proxy terminates TLS).
_use_ssl = os.getenv("APP_SSL", "1").lower() in ("1", "true", "yes")
if _use_ssl:
    certfile = CERT_FILE
    keyfile = KEY_FILE


def on_starting(server):
    # Runs once in the master before workers fork — ensure a CA-signed server
    # cert exists (generates the local CA + leaf on first boot).
    if _use_ssl:
        ensure_signed(CERT_FILE, KEY_FILE)
