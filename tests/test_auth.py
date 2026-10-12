#!/usr/bin/env python3
"""Tests for the local admin login: the password hash, the default admin/admin
bootstrap with its forced change, and sign-in with a hash written by a release
up to 1.16.0 (unsalted SHA-256), which has to keep working and be replaced.

    python tests/test_auth.py

Each scenario runs in its own process on an empty data directory, because the
app reads its login file once at import. No test framework is needed - the
script exits non-zero on the first failure.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def check(cond, what):
    if not cond:
        raise AssertionError(what)


def sha256(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def start(tmp, auth=None):
    """Import the app on the data directory `tmp`, optionally with a login file
    already in it. Returns (app module, test client, reader of the login file)."""
    os.environ.update(DATA_DIR=tmp, APP_SSL="0")
    for k in ("AUTH_CONFIG_FILE", "DATABASE_URL", "UI_DEFAULT_USERNAME", "UI_DEFAULT_PASSWORD"):
        os.environ.pop(k, None)
    path = os.path.join(tmp, "auth_config.json")
    if auth is not None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(auth, f)
    import app

    def stored():
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return app, app.app.test_client(), stored


def login(c, username, password):
    r = c.post("/login", data={"username": username, "password": password, "auth_source": "local"})
    return r.status_code == 302


def change(c, current, new, confirm=None):
    return c.post("/change-password", data={"current_password": current, "new_password": new,
                                            "confirm_password": new if confirm is None else confirm})


def scenario_fresh(tmp):
    app, c, stored = start(tmp)
    first = stored()
    check(first["username"] == "admin" and first["is_default_password"] is True, "a new install starts on the default admin")
    check(not app.is_legacy_hash(first["password_hash"]) and first["password_hash"].split(":")[0] in ("scrypt", "pbkdf2"),
          "the default password is stored with the new scheme")
    check(sha256("admin") not in json.dumps(first), "no SHA-256 of the password is written")
    check(app.hash_password("admin") != app.hash_password("admin"), "the hash is salted")

    check(not login(c, "admin", "wrong"), "a wrong password is refused")
    check(not login(c, "root", "admin"), "a wrong user name is refused")
    check(not login(c, "admin", ""), "an empty password is refused")
    check(c.get("/").status_code == 302 and "/login" in c.get("/").headers["Location"], "nothing is served without a login")

    check(login(c, "admin", "admin"), "admin/admin signs in")
    r = c.get("/")
    check(r.status_code == 302 and "/change-password" in r.headers["Location"], "the default password has to be changed")
    check(c.get("/api/ldap-settings", json={}).status_code == 403, "and the API says so")

    change(c, "wrong", "New-Pass-123")
    check(stored()["is_default_password"] is True, "a wrong current password changes nothing")
    change(c, "admin", "New-Pass-123", confirm="other")
    check(stored()["is_default_password"] is True, "a mismatched confirmation changes nothing")
    check(change(c, "admin", "New-Pass-123").status_code == 302, "the password can be changed")
    after = stored()
    check(after["is_default_password"] is False and after["last_password_change"], "the forced change is over")
    check(not app.is_legacy_hash(after["password_hash"]) and after["password_hash"] != first["password_hash"],
          "the new password is stored with the new scheme")
    check(set(after) == set(first), "the login document keeps its keys")
    check(c.get("/").status_code == 200, "the dashboard opens")

    c.get("/logout")
    check(not login(c, "admin", "admin"), "the old password no longer works")
    check(login(c, "admin", "New-Pass-123") and c.get("/").status_code == 200, "the new password signs in")


def scenario_legacy(tmp):
    old = {"username": "admin", "password_hash": sha256("Old-Pass-1"), "is_default_password": False,
           "created_at": "2026-01-01T00:00:00+02:00", "last_login": None, "login_attempts": 0,
           "last_password_change": "2026-01-02T00:00:00+02:00"}
    app, c, stored = start(tmp, old)
    check(not login(c, "admin", "wrong"), "a wrong password is refused on an old hash")
    check(stored()["password_hash"] == old["password_hash"], "and a failed sign-in leaves the old hash alone")

    check(login(c, "admin", "Old-Pass-1"), "a hash from an earlier release still signs in")
    new = stored()
    check(not app.is_legacy_hash(new["password_hash"]) and new["password_hash"].split(":")[0] in ("scrypt", "pbkdf2"),
          "the hash is replaced on that sign-in")
    check(new["is_default_password"] is False and set(new) == set(old)
          and new["created_at"] == old["created_at"] and new["last_password_change"] == old["last_password_change"],
          "nothing else in the login document changes")
    check(c.get("/").status_code == 200, "no password change is asked for")

    c.get("/logout")
    check(not login(c, "admin", "wrong"), "a wrong password is refused on the new hash")
    check(login(c, "admin", "Old-Pass-1"), "the same password signs in against the new hash")
    check(stored()["password_hash"] == new["password_hash"], "and the hash is not rewritten again")
    check(change(c, "Old-Pass-1", "Newer-Pass-2").status_code == 302 and app.verify_password("Newer-Pass-2", stored()["password_hash"]),
          "the password can be changed afterwards")


def scenario_legacy_default(tmp):
    old = {"username": "admin", "password_hash": sha256("admin"), "is_default_password": True,
           "created_at": "2026-01-01T00:00:00+02:00", "last_login": None, "login_attempts": 0, "last_password_change": None}
    app, c, stored = start(tmp, old)
    check(login(c, "admin", "admin"), "an old install still on admin/admin signs in")
    check(not app.is_legacy_hash(stored()["password_hash"]) and stored()["is_default_password"] is True,
          "its hash is replaced and the password is still the default one")
    check("/change-password" in c.get("/").headers.get("Location", ""), "so the change is still forced")
    # The current password of the change form is checked against an old hash too.
    app.auth_config["password_hash"] = sha256("admin")
    change(c, "wrong", "New-Pass-123")
    check(app.auth_config["is_default_password"] is True, "a wrong current password is refused against an old hash")
    check(change(c, "admin", "New-Pass-123").status_code == 302 and stored()["is_default_password"] is False
          and not app.is_legacy_hash(stored()["password_hash"]), "the change form accepts an old hash and writes a new one")


def scenario_verify(tmp):
    app, _, _ = start(tmp)
    v = app.verify_password
    check(v("pw", sha256("pw")) and v("pw", sha256("pw").upper()) and not v("pW", sha256("pw")), "old hashes compare by value")
    check(v("סיסמה", app.hash_password("סיסמה")) and v("סיסמה", sha256("סיסמה")), "non-Latin passwords work in both schemes")
    for bad in (None, "", 5, "x", sha256("pw")[:-1], sha256("pw") + "0", "g" * 64, "unknown$salt$hash", "scrypt:1:1:1$$", "$$"):
        check(v("pw", bad) is False and v("", bad) is False, f"a stored value of {bad!r} never signs in")
    check(not app.is_legacy_hash(app.hash_password("a" * 64)), "a new hash is never mistaken for an old one")


SCENARIOS = {
    "fresh": (scenario_fresh, "new install: admin/admin, forced change, sign in again"),
    "legacy": (scenario_legacy, "hash from an earlier release: signs in and is replaced"),
    "legacy-default": (scenario_legacy_default, "earlier release still on admin/admin: replaced, change still forced"),
    "verify": (scenario_verify, "stored values that must never sign in"),
}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        with tempfile.TemporaryDirectory() as tmp:
            SCENARIOS[sys.argv[1]][0](tmp)
        sys.exit(0)
    for name, (_, what) in SCENARIOS.items():
        r = subprocess.run([sys.executable, os.path.abspath(__file__), name], cwd=ROOT, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"   FAIL  {what}\n{r.stdout}{r.stderr}")
            sys.exit(1)
        print(f"   ok    {what}")
    print("all login tests passed")
