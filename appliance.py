"""
Appliance integration: version, health, and upload-based upgrades.

The web app never talks to Docker. An uploaded upgrade bundle (.nsu) is checked
here and parked in the data directory; a host-side agent on the appliance
(appliance/rootfs/opt/ns-appliance/bin/ns-upgrade, started by a systemd path
unit) verifies it again, swaps the container image, health-checks the result and
rolls back if it does not come up. Progress comes back through a status file.

Outside the appliance (a plain `docker compose up`) the upgrade endpoint is
disabled and only the version/health parts are active.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import threading
import time
from datetime import datetime, timezone

from flask import jsonify, request

PRODUCT = "netscaler-dashboard"
BUNDLE_FORMAT = 1
MAX_BUNDLE_BYTES = 2 * 1024 ** 3          # far above a real bundle (~100 MB)
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
# States the host agent moves through; anything else is terminal.
ACTIVE_STATES = ("queued", "verifying", "loading", "restarting")
_STALE_AFTER_SECS = 20 * 60

_upload_lock = threading.Lock()


def app_version() -> str:
    """The running version. The VERSION file ships inside the image, so it always
    matches the code; the build-arg env var is only a fallback."""
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION"), encoding="utf-8") as f:
            v = f.read().strip()
            if v:
                return v
    except OSError:
        pass
    return (os.getenv("APP_VERSION") or "dev").strip()


def is_appliance() -> bool:
    return os.getenv("NS_APPLIANCE", "").lower() in ("1", "true", "yes")


def version_tuple(v: str) -> tuple:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", str(v or ""))
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


class BundleError(ValueError):
    """The uploaded file is not an acceptable upgrade bundle."""


def _sha256_of(fileobj) -> str:
    h = hashlib.sha256()
    for chunk in iter(lambda: fileobj.read(1024 * 1024), b""):
        h.update(chunk)
    return h.hexdigest()


def inspect_bundle(path: str) -> dict:
    """Validate an upgrade bundle without extracting anything, and return its
    manifest. Members are only ever read as streams, so a hostile archive cannot
    write outside the upload directory."""
    try:
        tar = tarfile.open(path, "r:")           # plain tar: no auto-decompression
    except (tarfile.TarError, OSError):
        raise BundleError("This is not a NetScaler Dashboard upgrade file (.nsu).")
    with tar:
        members = {m.name: m for m in tar.getmembers() if m.isfile()}
        mf = members.get("manifest.json")
        if mf is None or mf.size > 64 * 1024:
            raise BundleError("The upgrade file has no manifest - it may be damaged or not an upgrade file.")
        try:
            manifest = json.loads(tar.extractfile(mf).read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise BundleError("The upgrade file's manifest is unreadable.")
        if not isinstance(manifest, dict) or manifest.get("product") != PRODUCT:
            raise BundleError("This upgrade file is for a different product.")
        if manifest.get("format") != BUNDLE_FORMAT:
            raise BundleError("This upgrade file uses a format this version cannot install. "
                              "Upgrade to an intermediate release first.")
        if not _VERSION.fullmatch(str(manifest.get("version", ""))):      # fullmatch: no trailing newline
            raise BundleError("The upgrade file does not state a valid version.")

        parts = [manifest.get("image")] + ([manifest["host"]] if manifest.get("host") else [])
        for part in parts:
            if not isinstance(part, dict):
                raise BundleError("The upgrade file's manifest is incomplete.")
            name, want = str(part.get("file", "")), str(part.get("sha256", "")).lower()
            if not _SAFE_NAME.fullmatch(name) or name not in members:
                raise BundleError("The upgrade file is missing a component - please download it again.")
            if _sha256_of(tar.extractfile(members[name])) != want:
                raise BundleError("The upgrade file is corrupted (checksum mismatch) - please download it again.")
    return manifest


def register(app, login_required, data_dir: str, logger) -> None:
    upgrade_dir = os.path.join(data_dir, "upgrade")
    incoming = os.path.join(upgrade_dir, "incoming.nsu")
    request_flag = os.path.join(upgrade_dir, "request")
    status_file = os.path.join(upgrade_dir, "status.json")

    def write_status(state: str, message: str, to: str = "") -> None:
        os.makedirs(upgrade_dir, exist_ok=True)
        tmp = status_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"state": state, "message": message, "from": app_version(), "to": to,
                       "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}, f)
        os.replace(tmp, status_file)

    def read_status() -> dict:
        try:
            with open(status_file, encoding="utf-8") as f:
                st = json.load(f)
            if not isinstance(st, dict):
                return {}
        except (OSError, ValueError):
            return {}
        # An agent that died mid-run must not leave the UI spinning forever.
        if st.get("state") in ACTIVE_STATES:
            try:
                age = time.time() - os.path.getmtime(status_file)
            except OSError:
                age = 0
            if age > _STALE_AFTER_SECS:
                st = dict(st, state="failed",
                          message="The upgrade did not finish. The previous version is still running; "
                                  "check the appliance console.")
        return st

    @app.route("/healthz")
    def healthz():
        # Unauthenticated on purpose: the appliance's upgrade agent polls it to decide
        # whether a new version came up or needs rolling back.
        return jsonify({"ok": True, "version": app_version()})

    @app.route("/api/appliance/status")
    @login_required
    def api_appliance_status():
        return jsonify({
            "version": app_version(),
            "appliance": is_appliance(),
            "appliance_version": os.getenv("NS_APPLIANCE_VERSION", "") if is_appliance() else "",
            "upgrade": read_status() if is_appliance() else {},
        })

    @app.route("/api/appliance/upgrade", methods=["POST"])
    @login_required
    def api_appliance_upgrade():
        if not is_appliance():
            return jsonify({"success": False,
                            "error": "Upload upgrades are only available on the virtual appliance."}), 400
        if read_status().get("state") in ACTIVE_STATES:
            return jsonify({"success": False, "error": "An upgrade is already in progress."}), 409
        length = request.content_length or 0
        if length <= 0:
            return jsonify({"success": False, "error": "No file was sent."}), 400
        if length > MAX_BUNDLE_BYTES:
            return jsonify({"success": False, "error": "That file is too large to be an upgrade file."}), 413
        if not _upload_lock.acquire(blocking=False):
            return jsonify({"success": False, "error": "Another upload is in progress."}), 409
        part = incoming + ".part"
        try:
            os.makedirs(upgrade_dir, exist_ok=True)
            # The bundle is stored, unpacked by the agent and loaded into Docker.
            if shutil.disk_usage(upgrade_dir).free < length * 4:
                return jsonify({"success": False,
                                "error": "Not enough free disk space on the appliance for this upgrade."}), 507
            received = 0
            with open(part, "wb") as out:
                while True:
                    chunk = request.stream.read(1024 * 1024)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > MAX_BUNDLE_BYTES:
                        raise BundleError("That file is too large to be an upgrade file.")
                    out.write(chunk)
            if received != length:
                raise BundleError("The upload was interrupted - please try again.")

            manifest = inspect_bundle(part)
            new, cur = manifest["version"], app_version()
            if version_tuple(new) < version_tuple(cur):
                raise BundleError(f"This file is version {new}, older than the running {cur}. "
                                  "Downgrades are not supported.")

            os.replace(part, incoming)
            write_status("queued", f"Upgrade to {new} accepted - waiting for the appliance to start it.", new)
            with open(request_flag, "w", encoding="utf-8") as f:   # wakes the host agent
                f.write(new + "\n")
            logger.info(f"Upgrade bundle accepted: {cur} -> {new} ({received} bytes)")
            return jsonify({"success": True, "version": new, "from": cur})
        except BundleError as e:
            return jsonify({"success": False, "error": str(e)}), 400
        except OSError as e:
            logger.error(f"Upgrade upload failed: {e}")
            return jsonify({"success": False, "error": "Could not store the upgrade file on the appliance."}), 500
        finally:
            try:
                os.remove(part)
            except OSError:
                pass
            _upload_lock.release()
