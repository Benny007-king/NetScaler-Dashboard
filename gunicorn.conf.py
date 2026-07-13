"""
Gunicorn config — HTTPS on 443 with a self-signed cert generated on first boot.
Gunicorn auto-loads this file. Replace the cert from the dashboard Settings page
(or drop your own PEMs at TLS_CERT_FILE / TLS_KEY_FILE) and restart to apply.
"""
import os

from cert_utils import CERT_FILE, KEY_FILE, ensure_self_signed

bind = f"0.0.0.0:{os.getenv('APP_PORT', '443')}"
workers = int(os.getenv("GUNICORN_WORKERS", "4"))
threads = int(os.getenv("GUNICORN_THREADS", "2"))

certfile = CERT_FILE
keyfile = KEY_FILE


def on_starting(server):
    # Runs once in the master before workers fork — ensure TLS material exists.
    ensure_self_signed(CERT_FILE, KEY_FILE)
