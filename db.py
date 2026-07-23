"""
Local SQLite store for failover events and session history.

Keeps at least RETENTION_DAYS (default 7) of history; a background retention
thread periodically deletes anything older. SQLite is stdlib — no extra service.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime

logger = logging.getLogger(__name__)

DB_FILE = os.getenv("DASHBOARD_DB_FILE", "dashboard.db")
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "7") or 7)
RETENTION_INTERVAL_SECS = int(os.getenv("RETENTION_INTERVAL_SECS", "3600") or 3600)
# A session counts as "Active" if it was seen within this window.
ACTIVE_WINDOW_SECS = int(os.getenv("SESSION_ACTIVE_WINDOW_SECS", "120") or 120)

_write_lock = threading.Lock()


@contextmanager
def _conn():
    con = sqlite3.connect(DB_FILE, timeout=15)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db() -> None:
    with _conn() as c:
        c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS failover_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_epoch    REAL NOT NULL,
            timestamp   TEXT NOT NULL,
            type        TEXT,
            reason      TEXT,
            role_change TEXT,
            ip          TEXT,
            UNIQUE(timestamp, ip, role_change)
        );
        CREATE INDEX IF NOT EXISTS idx_fo_ts ON failover_events(ts_epoch);

        CREATE TABLE IF NOT EXISTS sessions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            node       TEXT,
            username   TEXT,
            type       TEXT,
            ip         TEXT,
            gateway    TEXT,
            start_time TEXT,
            duration   TEXT,
            first_seen REAL NOT NULL,
            last_seen  REAL NOT NULL,
            UNIQUE(node, username, type, ip, start_time)
        );
        CREATE INDEX IF NOT EXISTS idx_sess_last ON sessions(last_seen);
        """)


def _epoch(ts: str) -> float:
    """Best-effort ISO timestamp -> epoch seconds (falls back to now)."""
    if ts:
        try:
            return datetime.fromisoformat(str(ts)).timestamp()
        except Exception:
            for fmt in ("%a %b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(str(ts), fmt).timestamp()
                except Exception:
                    pass
    return time.time()


# ------------------------------------------------------------------ failover
def add_failover_events(events) -> int:
    """Insert failover events, ignoring duplicates. Returns rows added."""
    if not events:
        return 0
    rows = [(
        _epoch(e.get("timestamp")), str(e.get("timestamp") or ""),
        e.get("type"), e.get("reason"), e.get("role_change"), e.get("ip"),
    ) for e in events if isinstance(e, dict)]
    if not rows:
        return 0
    with _write_lock, _conn() as c:
        before = c.total_changes
        c.executemany(
            "INSERT OR IGNORE INTO failover_events"
            " (ts_epoch, timestamp, type, reason, role_change, ip) VALUES (?,?,?,?,?,?)", rows)
        return c.total_changes - before


def get_failover_events(days: int | None = None) -> list:
    sql = "SELECT timestamp, type, reason, role_change, ip FROM failover_events"
    args = []
    if days:
        sql += " WHERE ts_epoch >= ?"
        args.append(time.time() - days * 86400)
    sql += " ORDER BY ts_epoch DESC"
    with _conn() as c:
        return [dict(r) for r in c.execute(sql, args).fetchall()]


# ------------------------------------------------------------------ sessions
def upsert_sessions(node: str, sessions) -> int:
    """Record/refresh observed sessions. Returns number processed."""
    if not sessions:
        return 0
    now = time.time()
    rows = [(
        node, s.get("user"), s.get("type"), s.get("ip"), s.get("gateway"),
        s.get("start"), s.get("duration"), now, now,
    ) for s in sessions if isinstance(s, dict)]
    if not rows:
        return 0
    with _write_lock, _conn() as c:
        c.executemany("""
            INSERT INTO sessions (node, username, type, ip, gateway, start_time, duration, first_seen, last_seen)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(node, username, type, ip, start_time)
            DO UPDATE SET last_seen=excluded.last_seen, duration=excluded.duration,
                          gateway=excluded.gateway
        """, rows)
    return len(rows)


def get_sessions(days: int | None = None) -> list:
    """Stored sessions in the dashboard's own history, newest first."""
    sql = ("SELECT node, username, type, ip, gateway, start_time, duration,"
           " first_seen, last_seen FROM sessions")
    args = []
    if days:
        sql += " WHERE last_seen >= ?"
        args.append(time.time() - days * 86400)
    sql += " ORDER BY last_seen DESC"
    now = time.time()
    out = []
    with _conn() as c:
        for r in c.execute(sql, args).fetchall():
            active = (now - (r["last_seen"] or 0)) <= ACTIVE_WINDOW_SECS
            out.append({
                "user": r["username"], "type": r["type"], "ip": r["ip"],
                "gateway": r["gateway"], "start": r["start_time"],
                "duration": r["duration"], "node": r["node"],
                "status": "Active" if active else "Terminated",
                "end": "Active" if active else datetime.fromtimestamp(r["last_seen"]).strftime("%d/%m/%Y %H:%M:%S"),
            })
    return out


# ----------------------------------------------------------------- retention
def purge(days: int | None = None) -> dict:
    """Delete data older than the retention window. Returns rows removed."""
    days = days or RETENTION_DAYS
    cutoff = time.time() - days * 86400
    with _write_lock, _conn() as c:
        fo = c.execute("DELETE FROM failover_events WHERE ts_epoch < ?", (cutoff,)).rowcount
        se = c.execute("DELETE FROM sessions WHERE last_seen < ?", (cutoff,)).rowcount
    if fo or se:
        logger.info(f"Retention: removed {fo} failover event(s) and {se} session(s) older than {days} day(s)")
    return {"failover_removed": fo, "sessions_removed": se, "days": days}


def stats() -> dict:
    with _conn() as c:
        fo = c.execute("SELECT COUNT(*) n, MIN(ts_epoch) o FROM failover_events").fetchone()
        se = c.execute("SELECT COUNT(*) n, MIN(last_seen) o FROM sessions").fetchone()
    size = os.path.getsize(DB_FILE) if os.path.exists(DB_FILE) else 0
    def _iso(v):
        return datetime.fromtimestamp(v).isoformat() if v else None
    return {
        "db_file": DB_FILE, "db_size_bytes": size, "retention_days": RETENTION_DAYS,
        "failover_events": fo["n"], "failover_oldest": _iso(fo["o"]),
        "sessions": se["n"], "sessions_oldest": _iso(se["o"]),
    }


def start_retention_thread() -> None:
    """Run purge() now and then every RETENTION_INTERVAL_SECS in the background."""
    def _loop():
        while True:
            try:
                purge()
            except Exception as e:
                logger.warning(f"Retention pass failed: {e}")
            time.sleep(RETENTION_INTERVAL_SECS)

    t = threading.Thread(target=_loop, name="retention", daemon=True)
    t.start()
    logger.info(f"Retention thread started (keep {RETENTION_DAYS}d, every {RETENTION_INTERVAL_SECS}s)")


def migrate_json_failover(path: str) -> int:
    """One-time import of the legacy failover_history.json into the DB."""
    if not os.path.exists(path):
        return 0
    with _conn() as c:
        if c.execute("SELECT COUNT(*) n FROM failover_events").fetchone()["n"]:
            return 0   # already populated
    try:
        import json
        with open(path, "r", encoding="utf-8") as f:
            events = json.load(f)
        n = add_failover_events(events if isinstance(events, list) else [])
        if n:
            logger.info(f"Imported {n} failover event(s) from {path} into {DB_FILE}")
        return n
    except Exception as e:
        logger.warning(f"Could not import {path}: {e}")
        return 0
