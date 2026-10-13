#!/usr/bin/env python3
"""Tests for the storage layer (db.py), run against real databases.

    python tests/test_storage.py                          # built-in store only
    python tests/test_storage.py postgresql://u:p@host/db mysql://u:p@host/db ...

Each URL is a scratch database: the dashboard's tables in it are dropped first.
No test framework is needed - the script exits non-zero on the first failure.
"""
import importlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HEBREW = "בני"            # a non-Latin user name
LONG_ID = "session-" + "x" * 400


def fresh(tmp):
    """A clean data directory and a freshly imported db module."""
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    os.environ["DATA_DIR"] = tmp
    os.environ["DB_RECHECK_SECS"] = "1"
    for k in ("DASHBOARD_DB_FILE", "DB_CONFIG_FILE", "DATABASE_URL"):
        os.environ.pop(k, None)
    return reopen(tmp)


_thread_running = False


def reopen(tmp):
    """Import db again on the same data directory (a process restart). The sync
    thread of the previous import keeps running on the module's new state, so a
    second one is not started."""
    global _thread_running
    import db
    importlib.reload(db)
    db._sync_thread_started = _thread_running
    _thread_running = True
    return db


def check(cond, what):
    if not cond:
        raise AssertionError(what)


def sess(sid, user="alice", ip="192.0.2.10", gateway="gw1", duration="00:01:00", status=None, kind="AAA login"):
    s = {"session_id": sid, "user": user, "type": kind, "ip": ip, "gateway": gateway,
         "start": "12/10/2026 10:00:00", "duration": duration, "detail": {"k": user}}
    if status:
        s["status"] = status
    return s


def history_suite(db, label):
    # --- sessions
    n = db.upsert_sessions("primary", [sess("s1"), sess("s2", user=HEBREW), sess(LONG_ID, user="long"),
                                       sess("f1", user="bob", status="Failed")], instance="a")
    check(n == 4, "4 sessions handled")
    rows = db.get_sessions(days=7, instance="a")
    check(len(rows) == 4, f"4 rows stored, got {len(rows)}")
    check({r["user"] for r in rows} == {"alice", HEBREW, "long", "bob"}, "user names (incl. Unicode) round-trip")
    check(next(r for r in rows if r["user"] == HEBREW)["detail"] == {"k": HEBREW}, "detail JSON round-trips")
    check(next(r for r in rows if r["user"] == "bob")["status"] == "Failed", "Failed status is kept")
    check(next(r for r in rows if r["user"] == "alice")["status"] == "Active", "a fresh session is Active")

    # the same sessions seen again: refreshed in place, good values not overwritten
    db.upsert_sessions("primary", [sess("s1", ip="Unknown", gateway="", duration="00:02:00"),
                                   sess(LONG_ID, user="long", duration="00:05:00")], instance="a")
    rows = db.get_sessions(days=7, instance="a")
    check(len(rows) == 4, f"a refresh adds no rows, got {len(rows)}")
    s1 = next(r for r in rows if r["user"] == "alice")
    check(s1["ip"] == "192.0.2.10" and s1["gateway"] == "gw1", "blank/Unknown never overwrites a good address or gateway")
    check(s1["duration"] == "00:02:00", "duration is refreshed")
    check(next(r for r in rows if r["user"] == "long")["duration"] == "00:05:00", "a long session id still matches itself")

    # ids differing only in case, the same id twice in one poll, other instances
    db.upsert_sessions("primary", [sess("Key"), sess("KEY"), sess("dup"), sess("dup", duration="00:09:00")], instance="b")
    rows_b = db.get_sessions(days=7, instance="b")
    check(len(rows_b) == 3, f"case-different ids are different sessions, duplicates collapse (got {len(rows_b)})")
    check(len(db.get_sessions(days=7, instance="a")) == 4, "instances are separate")
    check(len(db.get_sessions(days=7)) == 7, "no instance filter returns everything")

    # --- failover
    ev = [{"timestamp": "2026-10-12T10:00:00+03:00", "type": "Role Change", "reason": "r", "role_change": "PRIMARY -> SECONDARY", "ip": "192.0.2.1", "instance": "a"},
          {"timestamp": "2026-10-12T10:00:05+03:00", "type": "Role Change", "reason": "r " * 400, "role_change": "SECONDARY -> PRIMARY", "ip": "192.0.2.2", "instance": "a"},
          {"timestamp": "2026-10-12T10:00:05+03:00", "type": "State Change", "reason": HEBREW, "role_change": None, "ip": None, "instance": "b"}]
    check(db.add_failover_events(ev + [ev[0]]) == 3, "3 new failover events, the duplicate ignored")
    check(db.add_failover_events(ev) == 0, "adding them again adds nothing")
    fa = db.get_failover_events(days=36500, instance="a")
    check(len(fa) == 2 and fa[0]["timestamp"].endswith("10:00:05+03:00"), "failover events per instance, newest first")
    check(db.get_failover_events(days=36500, instance="b")[0]["reason"] == HEBREW, "Unicode reason round-trips")

    st = db.stats()
    check(st["sessions"] == 7 and st["failover_events"] == 3, f"stats count rows: {st}")

    # --- retention and cleanup
    check(db.purge_types(("AAA login x",)) == 0, "purge_types leaves other types alone")
    db.upsert_sessions("primary", [sess("m1", kind="Mgmt login")], instance="a")
    check(db.purge_types(("Mgmt login", "Management")) == 1, "purge_types removes the matching type")
    time.sleep(0.3)
    res = db.purge(days=1e-6)                     # everything older than ~0.1 s
    check(res["sessions_removed"] == 7 and res["failover_removed"] == 3, f"purge removes old rows: {res}")
    check(db.get_sessions(days=7) == [] and db.get_failover_events() == [], "nothing left after purge")
    print(f"   ok  {label}: sessions, failover, filters, retention")


def builtin_suite(tmp):
    db = fresh(tmp)
    db.init_db()
    check(db.status()["backend"] == "builtin", "built-in by default")
    history_suite(db, "built-in store")


def legacy_suite(tmp):
    """Database files written by earlier releases keep working."""
    db = fresh(tmp)
    con = sqlite3.connect(os.path.join(tmp, "dashboard.db"))
    con.executescript("""
        CREATE TABLE failover_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_epoch REAL NOT NULL,
            timestamp TEXT NOT NULL, type TEXT, reason TEXT, role_change TEXT, ip TEXT, instance TEXT,
            UNIQUE(timestamp, ip, role_change));
        CREATE INDEX idx_fo_ts ON failover_events(ts_epoch);
        CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, instance TEXT, node TEXT, session_id TEXT,
            username TEXT, type TEXT, ip TEXT, gateway TEXT, start_time TEXT, duration TEXT, detail TEXT, status TEXT,
            first_seen REAL NOT NULL, last_seen REAL NOT NULL, UNIQUE(instance, node, session_id));
        CREATE INDEX idx_sess_last ON sessions(last_seen);
    """)
    now = time.time()
    con.execute("INSERT INTO sessions (instance,node,session_id,username,type,ip,gateway,start_time,duration,detail,status,first_seen,last_seen)"
                " VALUES ('a','primary','old1','carol','AAA login','192.0.2.9','gw','x','y','{}','Active',?,?)", (now - 50, now - 10))
    con.execute("INSERT INTO failover_events (ts_epoch,timestamp,type,reason,role_change,ip,instance) VALUES (?,?,?,?,?,?,NULL)",
                (now, "2026-10-01T00:00:00+03:00", "t", "r", "rc", "192.0.2.1"))
    con.commit(); con.close()
    db.init_db()
    check([r["user"] for r in db.get_sessions(days=7, instance="a")] == ["carol"], "a 1.15 database file is read as it is")
    db.upsert_sessions("primary", [sess("old1", user="carol", duration="new")], instance="a")
    rows = db.get_sessions(days=7, instance="a")
    check(len(rows) == 1 and rows[0]["duration"] == "new", "and its rows are refreshed, not duplicated")
    check(len(db.get_failover_events(instance="zzz")) == 1, "events without an instance still show everywhere")

    db = fresh(tmp)                                # a much older file: sessions without a stable key
    con = sqlite3.connect(os.path.join(tmp, "dashboard.db"))
    con.executescript("CREATE TABLE sessions (id INTEGER PRIMARY KEY, node TEXT, username TEXT, first_seen REAL, last_seen REAL);"
                      "CREATE TABLE failover_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_epoch REAL NOT NULL, timestamp TEXT NOT NULL,"
                      " type TEXT, reason TEXT, role_change TEXT, ip TEXT, UNIQUE(timestamp, ip, role_change));")
    con.commit(); con.close()
    db.init_db()
    db.upsert_sessions("primary", [sess("n1")], instance="a")
    check(len(db.get_sessions(days=7, instance="a")) == 1, "a pre-1.6 sessions table is rebuilt")
    check(db.add_failover_events([{"timestamp": "2026-10-12T10:00:00", "ip": "192.0.2.1", "role_change": "x", "instance": "a"}]) == 1,
          "a failover table without the instance column gains it")
    print("   ok  database files from earlier releases")


def wipe(db, cfg):
    b = db._make_backend(cfg)
    for t in (b.settings, b.sessions, b.failover):
        t.drop(b.engine, checkfirst=True)
    b.engine.dispose()


def tables(db, cfg):
    import sqlalchemy as sa
    b = db._make_backend(cfg)
    names = [t.name for t in (b.failover, b.sessions, b.settings) if sa.inspect(b.engine).has_table(t.name)]
    b.engine.dispose()
    return names


def wait_for(cond, what, secs=15):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return
        time.sleep(0.2)
    raise AssertionError("timed out waiting for: " + what)


def external_suite(tmp, url):
    db = fresh(tmp)
    cfg = db.clean_config({"type": "url", "url": url})
    shown = db._public_config(cfg)["url"]
    check("***" in shown and (db._normalise_url(cfg["url"])[0].password or "") not in shown, "the password is never shown back")
    wipe(db, cfg)

    # settings documents kept by the "application"
    local = {"nodes": ({"instances": [{"id": "a", "name": "Prod " + HEBREW}]}, True),
             "auth": ({"username": "admin", "password_hash": "h1", "is_default_password": False}, True),
             "ldap": (None, False), "ha_state": ({"192.0.2.1": "PRIMARY"}, True)}
    applied = {}
    db.register_documents(lambda: dict(local), lambda name, doc: applied.__setitem__(name, doc))

    db.init_db()
    db.upsert_sessions("primary", [sess("pre1"), sess("pre2", user=HEBREW)], instance="a")
    db.add_failover_events([{"timestamp": "2026-10-12T09:00:00+03:00", "ip": "192.0.2.1", "role_change": "x", "instance": "a"}])

    # test: proves the settings work and leaves nothing behind
    t = db.test_config(cfg)
    check(t["server"] and not t["existing"]["settings"] and t["existing"]["sessions"] == 0, f"test reports an empty database: {t}")
    check(tables(db, cfg) == [], "a test leaves no tables behind")
    try:
        db.test_config(db.clean_config({"type": "url", "url": url.replace("@", "-wrong@", 1)}))
        raise AssertionError("a wrong password was accepted")
    except AssertionError:
        raise
    except Exception as e:
        msg = db.describe_error(e)
        check(msg and "SELECT" not in msg and len(msg) <= 300, "a wrong password gives a short, readable error")

    # connect: history moves over, settings are copied
    r = db.connect_external(cfg, "local")
    label = r["server"]
    check(r["moved"] == {"failover_events": 1, "sessions": 2}, f"existing history is moved: {r}")
    st = db.status()
    check(st["backend"] == "external" and st["connected"] and st["counts"]["sessions"] == 2, f"status after connect: {st}")
    check(st["waiting"]["sessions"] == 0 and st["waiting"]["failover_events"] == 0, "nothing left in the built-in store")
    check(os.path.exists(db.DB_CONFIG_FILE), "the connection is saved")
    remote = db._get_docs(db._ext)
    check(remote["nodes"] == local["nodes"][0] and remote["auth"]["password_hash"] == "h1" and "ldap" not in remote,
          "settings documents are copied, absent ones are not invented")
    check(remote["meta"]["schema"] == db._SCHEMA_VERSION, "a meta document says who wrote them, and in which format")
    check(db.purge(days=36500)["sessions_removed"] == 0, "retention inside the window removes nothing")
    time.sleep(0.3)
    db.purge(days=1e-6)                            # start the history suite from empty

    history_suite(db, label)
    check(db.status()["connected"], "still connected after the history suite")

    # a settings change reaches the database without the caller waiting
    local["auth"] = ({"username": "admin", "password_hash": "h2", "is_default_password": False}, True)
    db.documents_changed()
    wait_for(lambda: db._get_docs(db._ext)["auth"]["password_hash"] == "h2", "the changed settings in the database")

    # test against a database that now holds data
    t = db.test_config(cfg)
    check(t["existing"]["settings"] and t["existing"]["instances"] == ["Prod " + HEBREW], f"test reports the existing settings: {t}")
    check(len(tables(db, cfg)) == 3, "a test never drops tables that were already there")

    # disconnect: history comes back, the database keeps its copy
    db.upsert_sessions("primary", [sess("keep1")], instance="a")
    d = db.disconnect_external()
    check(d["copied"]["sessions"] == 1 and db.status()["backend"] == "builtin", f"disconnect copies history back: {d}")
    check(len(db.get_sessions(days=7, instance="a")) == 1 and not os.path.exists(db.DB_CONFIG_FILE), "built-in again, connection forgotten")

    # a new appliance: nothing configured locally, the database wins
    db = fresh(tmp)
    local2 = {"nodes": (None, False), "auth": ({"username": "admin", "is_default_password": True}, False),
              "ldap": (None, False), "ha_state": (None, False)}
    applied = {}
    db.register_documents(lambda: dict(local2), lambda name, doc: applied.__setitem__(name, doc))
    db.init_db()
    db.connect_external(cfg, "database")
    check(applied.get("nodes") == local["nodes"][0] and applied["auth"]["password_hash"] == "h2",
          f"'use the database' loads its settings: {sorted(applied)}")
    check(len(db.get_sessions(days=7, instance="a")) == 1, "and its history is there")

    # the same appliance restarting: the saved connection is used again
    db = reopen(tmp)
    applied = {}
    db.register_documents(lambda: dict(local), lambda name, doc: applied.__setitem__(name, doc))
    db.init_db()
    st = db.status()
    check(st["backend"] == "external" and st["connected"], f"reconnects at startup: {st}")
    check(applied == {}, "a restart never overwrites settings this dashboard already has")

    # a data directory that lost its settings files (or the admin login was reset
    # from the console): instances come back from the database, the login does not
    db = reopen(tmp)
    applied = {}
    db.register_documents(lambda: dict(local2), lambda name, doc: applied.__setitem__(name, doc))
    db.init_db()
    check(db.status()["connected"] and "nodes" in applied and "auth" not in applied,
          f"missing settings are restored at startup, a reset admin login is not: {sorted(applied)}")
    check(db._get_docs(db._ext)["auth"]["password_hash"] == "h2", "and the copy in the database is left alone until a new password is set")
    db = reopen(tmp)
    applied = {}
    db.register_documents(lambda: dict(local), lambda name, doc: applied.__setitem__(name, doc))
    db.init_db()

    # "keep this dashboard's settings" removes documents the dashboard does not have
    with db._ext.engine.begin() as c:
        c.execute(db._ext.settings.insert(), [{"name": "ldap", "value": json.dumps({"enabled": True}), "updated": 0}])
    db.connect_external(cfg, "local")
    check("ldap" not in db._get_docs(db._ext) and "ldap" not in applied, "local wins: foreign settings are removed, not adopted")

    # an unreachable database: the dashboard keeps working on the built-in store
    good = db._ext
    db._ext = db._make_backend(db.clean_config({"type": "url", "url": dead_url(url)}))
    db.upsert_sessions("primary", [sess("outage1")], instance="a")
    st = db.status()
    check(not st["connected"] and st["error"] and st["waiting"]["sessions"] == 1, f"outage: history waits locally: {st}")
    check([r["user"] for r in db.get_sessions(days=7, instance="a")] == ["alice"], "and is still readable")
    db._ext = good                                  # "the database is back"
    db._wake.set()
    wait_for(lambda: db.status()["connected"], "recovery")
    st = db.status()
    check(st["waiting"]["sessions"] == 0 and st["counts"]["sessions"] == 2, f"after recovery the waiting history is in the database: {st}")

    db.disconnect_external()

    # settings saved by a newer dashboard are never loaded by an older one
    b = db._make_backend(cfg)
    with b.engine.begin() as c:
        c.execute(b.settings.update().where(b.settings.c.name == "meta").values(
            value=json.dumps({"schema": db._SCHEMA_VERSION + 1, "app_version": "9.9.9"})))
    b.engine.dispose()
    t = db.test_config(cfg)
    check(t["existing"]["newer"] and t["existing"]["saved_version"] == "9.9.9", "a test says the settings come from a newer dashboard")
    applied.clear()
    try:
        db.connect_external(cfg, "database")
        raise AssertionError("settings in a newer format were loaded")
    except ValueError as e:
        check("newer dashboard (9.9.9)" in str(e), "loading them is refused with an explanation")
    check(applied == {} and db.status()["backend"] == "builtin", "and nothing was changed or connected")

    wipe(db, cfg)
    print(f"   ok  {label}: test, connect, settings copy, restore, restart, outage and recovery, disconnect")


def dead_url(url):
    """The same URL pointed at a port nothing listens on."""
    import sqlalchemy as sa
    return sa.engine.make_url(url).set(host="127.0.0.1", port=9).render_as_string(hide_password=False)


if __name__ == "__main__":
    tmp = os.path.join(tempfile.gettempdir(), "nsd-storage-test")
    builtin_suite(tmp)
    legacy_suite(tmp)
    for url in sys.argv[1:]:
        external_suite(tmp, url)
    shutil.rmtree(tmp, ignore_errors=True)
    print("All storage tests passed.")
