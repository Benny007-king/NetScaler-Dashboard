"""
History and settings store.

Two backends sit behind one set of functions:

  built-in   a SQLite file in the data directory. Always present.
  external   PostgreSQL, MySQL / MariaDB or Microsoft SQL Server, set up in
             Settings -> Database (or with the DATABASE_URL environment variable).

When an external database is connected it holds everything: session and failover
history, plus a copy of the dashboard's settings (instances, admin login, LDAP,
HA state) so a new appliance can be pointed at the database and pick them up.

The dashboard must keep working when that database is unreachable, so:

  * History written during an outage goes to the built-in file instead and is
    moved into the database when it answers again.
  * Settings are always read from the local files; the database gets a copy on
    every change. Nothing in the sign-in path waits for the database.

Not stored in the database: the TLS certificate and its CA, the session secret
and the database connection itself. Those belong to one appliance.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import socket
import ssl
import threading
import time
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects import mssql as _mssql
from sqlalchemy.dialects import mysql as _mysql

logger = logging.getLogger(__name__)

DATA_DIR = os.getenv("DATA_DIR", "data")


def _env_int(name, default, minimum=1):
    """A whole number from the environment; anything unusable (text, quotes left
    by an env file, a value below the minimum) gives the default instead of
    stopping the application from starting."""
    raw = str(os.getenv(name, "") or "").strip().strip('"\'').strip()
    try:
        v = int(raw) if raw else default
    except ValueError:
        v = default
    return default if v < minimum else v


DB_FILE = os.getenv("DASHBOARD_DB_FILE") or os.path.join(DATA_DIR, "dashboard.db")
DB_CONFIG_FILE = os.getenv("DB_CONFIG_FILE") or os.path.join(DATA_DIR, "db_config.json")
RETENTION_DAYS = _env_int("RETENTION_DAYS", 7)
RETENTION_INTERVAL_SECS = _env_int("RETENTION_INTERVAL_SECS", 3600, 10)
# Security events (WAF violations, policy hits) can arrive by the thousand during
# an attack; beyond this many the oldest are removed at the next retention pass.
SECURITY_MAX_EVENTS = _env_int("SECURITY_MAX_EVENTS", 200000, 1000)
# A session counts as "Active" if it was seen within this window.
ACTIVE_WINDOW_SECS = _env_int("SESSION_ACTIVE_WINDOW_SECS", 120)
# Tables in an external database carry a prefix: it is somebody else's server and
# "sessions" is too common a name to claim. The built-in file keeps the old names.
TABLE_PREFIX = os.getenv("DB_TABLE_PREFIX", "nsd_")
TIMEOUT_SECS = _env_int("DB_TIMEOUT_SECS", 10)
RECHECK_SECS = _env_int("DB_RECHECK_SECS", 20)

TYPES = {
    "postgresql": {"label": "PostgreSQL", "driver": "postgresql+pg8000", "port": 5432},
    "mysql": {"label": "MySQL / MariaDB", "driver": "mysql+pymysql", "port": 3306},
    "mssql": {"label": "Microsoft SQL Server", "driver": "mssql+pymssql", "port": 1433},
}
# Whatever scheme a pasted URL uses, it is run with the driver this image ships.
_URL_SCHEMES = {
    "postgresql": "postgresql", "postgres": "postgresql", "pg": "postgresql",
    "mysql": "mysql", "mariadb": "mysql",
    "mssql": "mssql", "sqlserver": "mssql",
}
# Settings documents mirrored into the external database.
DOC_NAMES = ("nodes", "auth", "ldap", "ha_state", "security")
_META = "meta"
# Format of the settings documents. Raised when a dashboard starts writing
# something older dashboards cannot read; a dashboard refuses to load settings
# with a higher number than its own instead of ending up unusable.
#   2: the admin login is a salted hash (written from 1.16.1 on)
_SCHEMA_VERSION = 2
_PROBE_TEXT = "unicode בדיקה ✓"

_write_lock = threading.RLock()      # one writer at a time (history + spool moves)
_state_lock = threading.RLock()      # connect / disconnect / recover
_wake = threading.Event()

_local = None                        # _Backend: the built-in file
_ext = None                          # _Backend: the external database, if configured
_ext_cfg = None                      # its connection settings (with the password)
_ext_up = False
_ext_error = ""
_ext_since = 0.0
_ext_server = ""
_ext_note = ""                       # something the administrator should know while it is connected
_ext_counts = None                   # row counts in the external database, refreshed in the background
_ext_counts_at = 0.0
_counts_lock = threading.Lock()
_docs_dirty = False
_docs_provider = None                # () -> {name: (document, present_locally)}
_docs_applier = None                 # (name, document) -> None
_sync_thread_started = False


# ====================================================================== schema
class _Backend:
    """An engine plus the tables, named for that engine."""

    def __init__(self, engine, prefix: str, label: str):
        self.engine = engine
        self.prefix = prefix
        self.label = label
        md = sa.MetaData()
        big = sa.UnicodeText().with_variant(_mysql.LONGTEXT(), "mysql", "mariadb")
        big = big.with_variant(_mssql.NVARCHAR(None), "mssql")          # NVARCHAR(max), not NTEXT
        # Keys compare case-sensitively on every backend. MySQL/MariaDB and SQL
        # Server default to case-insensitive, which would fold two sessions whose
        # ids differ only in case into one row.
        opts = {"mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_bin"}

        def key(width):
            return sa.Unicode(width).with_variant(
                _mssql.NVARCHAR(width, collation="Latin1_General_100_BIN2"), "mssql")
        self.failover = sa.Table(
            prefix + "failover_events", md,
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("ts_epoch", sa.Double, nullable=False),
            sa.Column("timestamp", key(64), nullable=False),
            sa.Column("type", sa.Unicode(64)),
            sa.Column("reason", big),
            sa.Column("role_change", key(128)),
            sa.Column("ip", key(64)),
            sa.Column("instance", sa.Unicode(64)),
            sa.UniqueConstraint("timestamp", "ip", "role_change", name=prefix + "uq_failover"),
            sa.Index(prefix + "idx_fo_ts", "ts_epoch"),
            **opts)
        # One row per real session, keyed on a stable NITRO session id, so repeated
        # polls of the same session refresh one row instead of piling up.
        self.sessions = sa.Table(
            prefix + "sessions", md,
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("instance", key(64)),
            sa.Column("node", key(64)),
            sa.Column("session_id", key(255)),
            sa.Column("username", sa.Unicode(255)),
            sa.Column("type", sa.Unicode(64)),
            sa.Column("ip", sa.Unicode(255)),
            sa.Column("gateway", sa.Unicode(255)),
            sa.Column("start_time", sa.Unicode(64)),
            sa.Column("duration", sa.Unicode(64)),
            sa.Column("detail", big),
            sa.Column("status", sa.Unicode(32)),
            sa.Column("first_seen", sa.Double, nullable=False),
            sa.Column("last_seen", sa.Double, nullable=False),
            sa.UniqueConstraint("instance", "node", "session_id", name=prefix + "uq_session"),
            sa.Index(prefix + "idx_sess_last", "last_seen"),
            **opts)
        # One row per security event (WAF violation, policy log line). ev_key is a
        # hash of where it came from and its sequence number, so the same event
        # received by syslog and read again from the audit log is stored once.
        self.security = sa.Table(
            prefix + "security_events", md,
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("instance", key(64)),
            sa.Column("node", key(64)),
            sa.Column("ts_epoch", sa.Double, nullable=False),
            sa.Column("kind", sa.Unicode(32)),
            sa.Column("etype", sa.Unicode(96)),
            sa.Column("client_ip", sa.Unicode(64)),
            sa.Column("url", big),
            sa.Column("profile", sa.Unicode(255)),
            sa.Column("action", sa.Unicode(64)),
            sa.Column("username", sa.Unicode(255)),
            sa.Column("session", sa.Unicode(255)),
            sa.Column("message", big),
            sa.Column("detail", big),
            sa.Column("raw", big),
            sa.Column("ev_key", key(64), nullable=False),
            sa.UniqueConstraint("instance", "ev_key", name=prefix + "uq_security"),
            sa.Index(prefix + "idx_sec_ts", "ts_epoch"),
            **opts)
        self.settings = sa.Table(
            prefix + "settings", md,
            sa.Column("name", sa.Unicode(64), primary_key=True),
            sa.Column("value", big),
            sa.Column("updated", sa.Double),
            **opts)
        self.metadata = md
        # Declared width of every short text column, per table.
        self.widths = {t.name: {c.name: c.type.length for c in t.columns
                                if isinstance(c.type, sa.Unicode) and c.type.length}
                       for t in (self.failover, self.sessions, self.security, self.settings)}

    @property
    def is_sqlite(self) -> bool:
        return self.engine.dialect.name == "sqlite"

    def fit(self, table, row: dict) -> dict:
        """Make a row storable everywhere: no NUL bytes or unpaired surrogates
        (PostgreSQL refuses the first, every driver chokes on the second), and
        strings trimmed to the column widths (SQLite never cared; servers do)."""
        for name, v in row.items():
            if isinstance(v, str) and _UNSTORABLE.search(v):
                row[name] = _UNSTORABLE.sub("", v)
        for name, width in self.widths[table.name].items():
            v = row.get(name)
            if v is None:
                continue
            if not isinstance(v, str):
                v = row[name] = str(v)
            if len(v) > width:
                row[name] = v[:width]
        return row


_UNSTORABLE = re.compile(r"[\x00\ud800-\udfff]")
_BATCH = 1000                         # rows per step when history is moved between stores


def _is_outage(e: Exception) -> bool:
    """True when an error means "the database is not reachable", as opposed to
    "the database refused this statement"."""
    if isinstance(e, (sa.exc.OperationalError, sa.exc.InterfaceError, sa.exc.TimeoutError,
                      OSError, TimeoutError, EOFError)):
        return True
    return bool(getattr(e, "connection_invalidated", False))


def _insert_rows(c, table, rows: list) -> None:
    """Insert many rows in a few statements. One statement per row costs a round
    trip each on some drivers - two minutes for 50,000 rows on PostgreSQL."""
    if not rows:
        return
    step = max(1, 900 // max(1, len(rows[0])))        # stays below every backend's parameter limit
    for i in range(0, len(rows), step):
        c.execute(sa.insert(table).values(rows[i:i + step]))


def _session_key(value) -> str:
    """A session id that always fits the key column and stays unique."""
    s = str(value or "")
    if len(s) <= 255:
        return s
    return s[:200] + "#" + hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()


def _chunks(seq, n=400):
    seq = list(seq)
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _init(b: _Backend) -> None:
    """Create whatever is missing. On the built-in file, also bring tables from
    older releases up to date."""
    if b.is_sqlite:
        insp = sa.inspect(b.engine)
        if insp.has_table(b.sessions.name):
            cols = {c["name"] for c in insp.get_columns(b.sessions.name)}
            # Older keys were not stable per session. It is 7-day monitoring
            # history that refills on the next poll, so a clean rebuild is simplest.
            if not {"session_id", "instance", "status"} <= cols:
                with b.engine.begin() as c:
                    c.execute(sa.text(f'DROP TABLE "{b.sessions.name}"'))
        if insp.has_table(b.failover.name):
            cols = {c["name"] for c in insp.get_columns(b.failover.name)}
            if "instance" not in cols:
                with b.engine.begin() as c:
                    c.execute(sa.text(f'ALTER TABLE "{b.failover.name}" ADD COLUMN instance TEXT'))
    b.metadata.create_all(b.engine)


def _epoch(ts) -> float:
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


# =========================================================== backend operations
_FO_COLS = ("ts_epoch", "timestamp", "type", "reason", "role_change", "ip", "instance")
_SE_COLS = ("instance", "node", "session_id", "username", "type", "ip", "gateway",
            "start_time", "duration", "detail", "status", "first_seen", "last_seen")
_BLANK = (None, "", "Unknown", "N/A", "—")


def _add_failover(b: _Backend, rows: list) -> int:
    """Insert failover rows that are not there yet. Returns rows added."""
    t = b.failover
    todo, seen = [], set()
    for r in rows:
        r = b.fit(t, {k: r.get(k) for k in _FO_COLS})
        r["timestamp"] = r["timestamp"] or ""
        r["ip"] = r["ip"] or ""
        r["role_change"] = r["role_change"] or ""
        key = (r["timestamp"], r["ip"], r["role_change"])
        if key not in seen:
            seen.add(key)
            todo.append(r)
    if not todo:
        return 0
    try:
        with b.engine.begin() as c:
            have = set()
            for chunk in _chunks({r["timestamp"] for r in todo}):
                for row in c.execute(sa.select(t.c.timestamp, t.c.ip, t.c.role_change)
                                     .where(t.c.timestamp.in_(chunk))):
                    have.add((row[0] or "", row[1] or "", row[2] or ""))
            new = [r for r in todo if (r["timestamp"], r["ip"], r["role_change"]) not in have]
            _insert_rows(c, t, new)
            return len(new)
    except sa.exc.SQLAlchemyError as e:
        if _is_outage(e):
            raise
    # The server compares keys differently than Python does (case, padding),
    # another writer got there first, or it refuses one of the rows. Go row by
    # row: keep what can be stored, skip what exists, drop what it will not take.
    added, refused, last = 0, 0, None
    for r in todo:
        try:
            with b.engine.begin() as c:
                c.execute(sa.insert(t), [r])
            added += 1
        except sa.exc.IntegrityError:
            pass
        except sa.exc.SQLAlchemyError as e:
            if _is_outage(e):
                raise
            refused, last = refused + 1, e
    if refused:
        if refused == len(todo):
            raise last                     # nothing could be written: not a problem with one row
        logger.warning(f"{refused} failover event(s) were refused by the database and dropped: {_explain(last)}")
    return added


_SEC_COLS = ("instance", "node", "ts_epoch", "kind", "etype", "client_ip", "url", "profile", "action",
             "username", "session", "message", "detail", "raw", "ev_key")


def _add_security(b: _Backend, rows: list) -> int:
    """Insert security events that are not stored yet. Returns rows added."""
    t = b.security
    todo, seen = [], set()
    for r in rows:
        r = b.fit(t, {k: r.get(k) for k in _SEC_COLS})
        r["instance"] = str(r["instance"] if r["instance"] is not None else "default")
        r["ev_key"] = str(r["ev_key"] or "")
        if not r["ev_key"] or r["ts_epoch"] is None:
            continue
        key = (r["instance"], r["ev_key"])
        if key not in seen:
            seen.add(key)
            todo.append(r)
    if not todo:
        return 0
    try:
        with b.engine.begin() as c:
            have = set()
            for inst in {r["instance"] for r in todo}:
                for chunk in _chunks([r["ev_key"] for r in todo if r["instance"] == inst]):
                    for row in c.execute(sa.select(t.c.ev_key).where(t.c.instance == inst, t.c.ev_key.in_(chunk))):
                        have.add((inst, row[0]))
            new = [r for r in todo if (r["instance"], r["ev_key"]) not in have]
            _insert_rows(c, t, new)
            return len(new)
    except sa.exc.SQLAlchemyError as e:
        if _is_outage(e):
            raise
    added, refused, last = 0, 0, None
    for r in todo:
        try:
            with b.engine.begin() as c:
                c.execute(sa.insert(t), [r])
            added += 1
        except sa.exc.IntegrityError:
            pass
        except sa.exc.SQLAlchemyError as e:
            if _is_outage(e):
                raise
            refused, last = refused + 1, e
    if refused:
        if refused == len(todo):
            raise last
        logger.warning(f"{refused} security event(s) were refused by the database and dropped: {_explain(last)}")
    return added


def _get_security(b: _Backend, instance, since, until, kinds, text, limit) -> list:
    t = b.security
    q = sa.select(t.c.node, t.c.ts_epoch, t.c.kind, t.c.etype, t.c.client_ip, t.c.url, t.c.profile, t.c.action,
                  t.c.username, t.c.session, t.c.message, t.c.detail, t.c.raw)
    if instance is not None:
        q = q.where(t.c.instance == str(instance))
    if since:
        q = q.where(t.c.ts_epoch >= since)
    if until:
        q = q.where(t.c.ts_epoch <= until)
    if kinds:
        q = q.where(t.c.kind.in_(list(kinds)))
    if text:
        like = "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        q = q.where(sa.or_(*(col.like(like, escape="\\") for col in
                             (t.c.client_ip, t.c.url, t.c.etype, t.c.message, t.c.username, t.c.profile))))
    out = []
    with b.engine.connect() as c:
        for r in c.execute(q.order_by(t.c.ts_epoch.desc()).limit(limit)):
            try:
                detail = json.loads(r.detail) if r.detail else {}
            except Exception:
                detail = {}
            out.append({"node": r.node, "ts": r.ts_epoch, "kind": r.kind, "etype": r.etype,
                        "client_ip": r.client_ip, "url": r.url, "profile": r.profile, "action": r.action,
                        "username": r.username, "session": r.session, "message": r.message,
                        "detail": detail if isinstance(detail, dict) else {}, "raw": r.raw})
    return out


def _trim_security(b: _Backend, keep: int) -> int:
    """Remove the oldest events beyond `keep`."""
    t = b.security
    with b.engine.begin() as c:
        n = c.execute(sa.select(sa.func.count()).select_from(t)).scalar() or 0
        if n <= keep:
            return 0
        cut = c.execute(sa.select(t.c.ts_epoch).order_by(t.c.ts_epoch.desc()).offset(keep).limit(1)).scalar()
        if cut is None:
            return 0
        return max(c.execute(sa.delete(t).where(t.c.ts_epoch <= cut)).rowcount or 0, 0)


def _get_failover(b: _Backend, days, instance) -> list:
    t = b.failover
    q = sa.select(t.c.timestamp, t.c.type, t.c.reason, t.c.role_change, t.c.ip)
    if days:
        q = q.where(t.c.ts_epoch >= time.time() - days * 86400)
    if instance is not None:
        q = q.where(sa.or_(t.c.instance == str(instance), t.c.instance.is_(None)))
    with b.engine.connect() as c:
        return [dict(r._mapping) for r in c.execute(q.order_by(t.c.ts_epoch.desc()))]


def _session_lookup(t):
    return sa.select(t.c.id, t.c.session_id, t.c.ip, t.c.gateway, t.c.first_seen, t.c.last_seen)


def _session_refresh(t):
    return sa.update(t).where(t.c.id == sa.bindparam("b_id")).values(
        last_seen=sa.bindparam("b_last"), first_seen=sa.bindparam("b_first"),
        duration=sa.bindparam("b_duration"), detail=sa.bindparam("b_detail"),
        status=sa.bindparam("b_status"), ip=sa.bindparam("b_ip"), gateway=sa.bindparam("b_gateway"))


def _refreshed(old, new: dict) -> dict:
    """What a stored session becomes when it is seen again: the first-seen time
    is kept, and a blank or "Unknown" address or gateway from a later poll never
    overwrites a good value already captured."""
    firsts = [v for v in (old.first_seen, new["first_seen"]) if v]
    return {
        "b_id": old.id,
        "b_last": max(old.last_seen or 0, new["last_seen"] or 0),
        "b_first": min(firsts) if firsts else time.time(),
        "b_duration": new["duration"], "b_detail": new["detail"], "b_status": new["status"],
        "b_ip": old.ip if new["ip"] in _BLANK else new["ip"],
        "b_gateway": old.gateway if new["gateway"] in _BLANK else new["gateway"],
    }


def _merge_sessions(b: _Backend, rows: list) -> int:
    """Insert new sessions and refresh the ones already stored. Returns rows handled."""
    t = b.sessions
    groups = {}
    for r in rows:
        r = {k: r.get(k) for k in _SE_COLS}
        r["instance"] = str(r["instance"] if r["instance"] is not None else "default")
        r["node"] = str(r["node"] or "")
        r["session_id"] = _session_key(r["session_id"])
        b.fit(t, r)
        groups.setdefault((r["instance"], r["node"]), {})[r["session_id"]] = r   # last one wins
    done = 0
    for (inst, node), by_id in groups.items():
        try:
            with b.engine.begin() as c:
                have = {}
                for chunk in _chunks(by_id):
                    for row in c.execute(_session_lookup(t).where(
                            t.c.instance == inst, t.c.node == node, t.c.session_id.in_(chunk))):
                        have[row.session_id] = row
                inserts = [r for sid, r in by_id.items() if sid not in have]
                updates = [_refreshed(have[sid], r) for sid, r in by_id.items() if sid in have]
                _insert_rows(c, t, inserts)
                if updates:
                    c.execute(_session_refresh(t), updates)
        except sa.exc.SQLAlchemyError as e:
            if _is_outage(e):
                raise
            # A key the server sees differently, or a row it refuses: one by one,
            # so one bad row does not cost the rest.
            refused, last = 0, None
            for r in by_id.values():
                try:
                    _merge_one_session(b, r)
                except sa.exc.SQLAlchemyError as e2:
                    if _is_outage(e2):
                        raise
                    refused, last = refused + 1, e2
            if refused:
                if refused == len(by_id):
                    raise last
                logger.warning(f"{refused} session row(s) were refused by the database and dropped: {_explain(last)}")
        done += len(by_id)
    return done


def _merge_one_session(b: _Backend, r: dict) -> None:
    """Slow path for one row: insert it, or refresh the row the server says exists."""
    t = b.sessions
    try:
        with b.engine.begin() as c:
            c.execute(sa.insert(t), [r])
        return
    except sa.exc.IntegrityError:
        pass
    with b.engine.begin() as c:
        old = c.execute(_session_lookup(t).where(
            t.c.instance == r["instance"], t.c.node == r["node"], t.c.session_id == r["session_id"])).first()
        if old is not None:
            c.execute(_session_refresh(t), [_refreshed(old, r)])


def _get_sessions(b: _Backend, days, instance) -> list:
    t = b.sessions
    q = sa.select(t.c.node, t.c.session_id, t.c.username, t.c.type, t.c.ip, t.c.gateway, t.c.start_time,
                  t.c.duration, t.c.detail, t.c.status, t.c.first_seen, t.c.last_seen)
    if days:
        q = q.where(t.c.last_seen >= time.time() - days * 86400)
    if instance is not None:
        q = q.where(t.c.instance == str(instance))
    now = time.time()
    out = []
    with b.engine.connect() as c:
        for r in c.execute(q.order_by(t.c.last_seen.desc())):
            try:
                detail = json.loads(r.detail) if r.detail else {}
            except Exception:
                detail = {}
            if r.status in ("Failed", "Locked"):
                # A discrete event, not a live connection — keep its status/time as-is.
                status, end = r.status, ""
            else:
                active = (now - (r.last_seen or 0)) <= ACTIVE_WINDOW_SECS
                status = "Active" if active else "Terminated"
                end = "Active" if active else datetime.fromtimestamp(r.last_seen).strftime("%d/%m/%Y %H:%M:%S")
            out.append({
                "user": r.username, "type": r.type, "ip": r.ip,
                "gateway": r.gateway, "start": r.start_time,
                "duration": r.duration, "node": r.node, "detail": detail,
                "status": status, "end": end, "session_id": r.session_id,
                "first_seen": r.first_seen, "last_seen": r.last_seen,
            })
    return out


def _purge(b: _Backend, cutoff: float) -> tuple:
    with b.engine.begin() as c:
        fo = c.execute(sa.delete(b.failover).where(b.failover.c.ts_epoch < cutoff)).rowcount
        se = c.execute(sa.delete(b.sessions).where(b.sessions.c.last_seen < cutoff)).rowcount
        sec = c.execute(sa.delete(b.security).where(b.security.c.ts_epoch < cutoff)).rowcount
    sec = max(sec or 0, 0) + _trim_security(b, SECURITY_MAX_EVENTS)
    return max(fo or 0, 0), max(se or 0, 0), sec


def _purge_types(b: _Backend, types: tuple) -> int:
    with b.engine.begin() as c:
        n = c.execute(sa.delete(b.sessions).where(b.sessions.c.type.in_(types))).rowcount
    return max(n or 0, 0)


def _counts(b: _Backend) -> dict:
    with b.engine.connect() as c:
        fo = c.execute(sa.select(sa.func.count(), sa.func.min(b.failover.c.ts_epoch)).select_from(b.failover)).first()
        se = c.execute(sa.select(sa.func.count(), sa.func.min(b.sessions.c.last_seen)).select_from(b.sessions)).first()
        sec = c.execute(sa.select(sa.func.count()).select_from(b.security)).first()

    def _iso(v):
        return datetime.fromtimestamp(v).isoformat() if v else None
    return {"failover_events": fo[0], "failover_oldest": _iso(fo[1]),
            "sessions": se[0], "sessions_oldest": _iso(se[1]), "security_events": sec[0]}


def _put_docs(b: _Backend, docs: dict, remove=()) -> int:
    """Store settings documents; only rows whose content changed are written."""
    t = b.settings
    changed = 0
    with b.engine.begin() as c:
        have = {r[0]: r[1] for r in c.execute(sa.select(t.c.name, t.c.value))}

        def put(name, val):
            if name in have:
                c.execute(sa.update(t).where(t.c.name == name).values(value=val, updated=time.time()))
            else:
                c.execute(sa.insert(t), [{"name": name, "value": val, "updated": time.time()}])

        for name, obj in docs.items():
            val = json.dumps(obj, sort_keys=True, ensure_ascii=False)
            if have.get(name) != val:
                put(name, val)
                changed += 1
        for name in remove:
            if name in have:
                c.execute(sa.delete(t).where(t.c.name == name))
                changed += 1
        if changed:
            put(_META, json.dumps({
                "schema": _SCHEMA_VERSION, "saved_by": socket.gethostname(),
                "saved_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                "app_version": _app_version()}, sort_keys=True))
    return changed


def _get_docs(b: _Backend) -> dict:
    """The settings documents in a database. Only JSON objects count: anything
    else in a row (somebody else's data, a damaged value) is treated as absent."""
    out = {}
    with b.engine.connect() as c:
        for name, value in c.execute(sa.select(b.settings.c.name, b.settings.c.value)):
            try:
                doc = json.loads(value) if value else None
            except Exception:
                continue
            if isinstance(doc, dict):
                out[name] = doc
    return out


def _transfer(src: _Backend, dst: _Backend, delete_src: bool) -> dict:
    """Copy all history from one backend into another (existing rows are merged,
    never duplicated). With delete_src the copied rows are then removed.

    It works in steps of _BATCH rows and takes the write lock for one step at a
    time, so requests that record history wait for a step, not for the whole move."""
    moved = {"failover_events": 0, "sessions": 0, "security_events": 0}
    for table, key, put in ((src.failover, "failover_events", _add_failover),
                            (src.sessions, "sessions", _merge_sessions),
                            (src.security, "security_events", _add_security)):
        last = 0
        while True:
            with _write_lock:
                with src.engine.connect() as c:
                    rows = [dict(r._mapping) for r in c.execute(
                        sa.select(table).where(table.c.id > last).order_by(table.c.id).limit(_BATCH))]
                if not rows:
                    break
                put(dst, rows)
                last = rows[-1]["id"]
                if delete_src:
                    with src.engine.begin() as c:
                        c.execute(sa.delete(table).where(table.c.id <= last))
                moved[key] += len(rows)
            time.sleep(0.01)               # let a waiting request take the lock between steps
    return moved


# ================================================================== connections
def _app_version() -> str:
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return (os.getenv("APP_VERSION") or "dev").strip()


def _local_backend() -> _Backend:
    os.makedirs(os.path.dirname(os.path.abspath(DB_FILE)), exist_ok=True)
    engine = sa.create_engine("sqlite:///" + DB_FILE.replace("\\", "/"), connect_args={"timeout": 15})

    @sa.event.listens_for(engine, "connect")
    def _pragmas(dbapi_con, _record):
        cur = dbapi_con.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.close()

    return _Backend(engine, "", "Built-in")


def _normalise_url(text):
    try:
        url = sa.engine.make_url(str(text or "").strip())
    except Exception:
        raise ValueError("That is not a valid database URL "
                         "(expected e.g. postgresql://user:password@host:5432/database).")
    kind = _URL_SCHEMES.get(url.drivername.split("+")[0].lower())
    if not kind:
        raise ValueError("Unsupported database type in the URL. Use postgresql://, mysql://, mariadb:// or mssql://.")
    if not url.host or not url.database:
        raise ValueError("The URL needs a server and a database name.")
    if "@" in url.host:
        raise ValueError("The password in the URL contains an @: write it as %40 "
                         "(and other special characters percent-encoded too).")
    return url.set(drivername=TYPES[kind]["driver"]), kind


def _tls_context(cfg: dict):
    mode = cfg.get("tls") or "off"
    if mode == "off":
        return None
    if mode == "verify":
        ca = (cfg.get("ca_pem") or "").strip()
        return ssl.create_default_context(cadata=ca) if ca else ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _make_backend(cfg: dict) -> _Backend:
    if cfg.get("type") == "url":
        url, kind = _normalise_url(cfg.get("url"))
    else:
        kind = cfg["type"]
        url = sa.engine.URL.create(TYPES[kind]["driver"], username=cfg.get("username") or None,
                                   password=cfg.get("password") or None, host=cfg["host"],
                                   port=int(cfg["port"]), database=cfg["database"])
    tls = cfg.get("tls") or "off"
    args = {}
    if kind == "postgresql":
        # pg8000 would otherwise encrypt whenever the server offers it; each mode
        # here does exactly what its label in Settings says.
        ctx = _tls_context(cfg)
        args.update(timeout=TIMEOUT_SECS, application_name="netscaler-dashboard",
                    ssl_context=ctx if ctx is not None else False)
    elif kind == "mysql":
        args.update(connect_timeout=TIMEOUT_SECS, read_timeout=TIMEOUT_SECS * 2,
                    write_timeout=TIMEOUT_SECS * 2, charset="utf8mb4")
        ctx = _tls_context(cfg)
        if ctx is not None:
            args["ssl"] = ctx
        else:
            args["ssl_disabled"] = True        # PyMySQL would otherwise use TLS when offered
    else:
        if tls == "verify":
            raise ValueError("Certificate verification is not available for SQL Server here. "
                             "Choose encryption without verification.")
        args.update(login_timeout=TIMEOUT_SECS, timeout=TIMEOUT_SECS * 2, charset="UTF-8",
                    appname="netscaler-dashboard")
        args["encryption"] = "require" if tls == "on" else "off"
    engine = sa.create_engine(url, connect_args=args, pool_pre_ping=True, pool_recycle=1800,
                              pool_size=4, max_overflow=4, pool_timeout=TIMEOUT_SECS)
    if kind == "mysql":
        @sa.event.listens_for(engine, "do_connect")
        def _login_again(dialect, _record, cargs, cparams):
            # The first password login to MySQL 8 after its restart, without TLS,
            # fails inside PyMySQL ('NoneType' has no attribute ...); the second
            # one works. Without this every MySQL restart costs a failed attempt.
            try:
                return dialect.loaded_dbapi.connect(*cargs, **cparams)
            except AttributeError:
                return dialect.loaded_dbapi.connect(*cargs, **cparams)
    return _Backend(engine, TABLE_PREFIX, TYPES[kind]["label"])


def _server_name(b: _Backend) -> str:
    """Connects, and names the server it reached (e.g. "PostgreSQL 16.4")."""
    for attempt in (1, 2):
        try:
            with b.engine.connect() as c:
                c.execute(sa.select(sa.literal(1)))
            break
        except AttributeError:            # PyMySQL, first caching_sha2 login without TLS
            if attempt == 2:
                raise
            b.engine.dispose()
    d = b.engine.dialect
    name = {"postgresql": "PostgreSQL", "mssql": "Microsoft SQL Server"}.get(d.name)
    if not name:
        name = "MariaDB" if getattr(d, "is_mariadb", False) else "MySQL"
    info = [x for x in (d.server_version_info or ()) if isinstance(x, int)][:2]
    return (name + " " + ".".join(str(x) for x in info)).strip()


def _explain(e: Exception) -> str:
    """One readable line from a driver error - never the statement or a traceback."""
    orig = getattr(e, "orig", None) or e

    def parts(value):
        # Drivers nest their arguments differently: pymssql wraps (code, bytes) in
        # another tuple, PyMySQL passes (code, text), pg8000 a dict or a string.
        if isinstance(value, (tuple, list)):
            for v in value:
                yield from parts(v)
        elif isinstance(value, bytes):
            yield value.decode("utf-8", "replace")
        elif isinstance(value, dict):
            yield str(value.get("M") or value)       # pg8000: the server's message
        elif value not in (None, ""):
            yield value

    found = list(parts(getattr(orig, "args", None) or ()))
    words = [str(v) for v in found if not isinstance(v, int)] or [str(v) for v in found]
    text = " ".join(words) if words else str(orig)
    if "DB-Lib error message" in text:               # FreeTDS repeats itself over many lines
        head = text.split("DB-Lib error message")[0].strip()
        lines = [ln.strip() for ln in re.findall(r"severity \d+:\s*([^\n]+)", text)]
        useful = [ln for ln in lines if not ln.startswith(("General SQL Server error", "TDS server connection failed",
                                                           "Adaptive Server connection failed"))]
        text = head or (useful[0] if useful else
                        "SQL Server refused the connection - check the database name and that this login may use it")
    for marker in ("(Background on this error", "[SQL:", "(timeout is "):
        text = text.split(marker)[0]
    text = " ".join(text.split())
    return text[:300] or orig.__class__.__name__


def clean_config(raw: dict, stored=None) -> dict:
    """Validate connection settings from the UI. A blank password keeps the stored one."""
    if not isinstance(raw, dict):
        raise ValueError("Invalid payload.")
    kind = str(raw.get("type") or "").strip().lower()
    tls = str(raw.get("tls") or "off").lower()
    if tls not in ("off", "on", "verify"):
        tls = "off"
    ca_pem = str(raw.get("ca_pem") or "").strip()
    if ca_pem and "BEGIN CERTIFICATE" not in ca_pem:
        raise ValueError("The CA certificate must be in PEM format.")
    if kind == "url":
        text = str(raw.get("url") or "").strip()
        if not text:
            raise ValueError("Enter the connection URL.")
        url, _ = _normalise_url(text)
        if url.password in (None, "", "***"):
            old = _normalise_url(stored["url"])[0] if stored and stored.get("type") == "url" else None
            # The stored password is reused only for the server and user it was
            # entered for - otherwise it could be sent to any address at all.
            if old is not None and (old.host, old.port, old.username) == (url.host, url.port, url.username):
                url = url.set(password=old.password)
            elif url.password == "***" or old is not None:
                raise ValueError("The server or the user changed - enter the password again.")
        return {"type": "url", "url": url.render_as_string(hide_password=False), "tls": tls, "ca_pem": ca_pem}
    if kind not in TYPES:
        raise ValueError("Choose a database type.")
    host = str(raw.get("host") or "").strip()
    database = str(raw.get("database") or "").strip()
    username = str(raw.get("username") or "").strip()
    if not host:
        raise ValueError("Enter the database server.")
    if not database:
        raise ValueError("Enter the database name.")
    if not username:
        raise ValueError("Enter the database user.")
    try:
        port = int(raw.get("port") or TYPES[kind]["port"])
    except (TypeError, ValueError):
        raise ValueError("The port must be a number.")
    if not 1 <= port <= 65535:
        raise ValueError("The port must be between 1 and 65535.")
    password = raw.get("password") or ""
    if not isinstance(password, str):
        raise ValueError("The password must be text.")
    if not password and stored and stored.get("type") == kind and stored.get("password"):
        # Reused only for the server and user it was entered for - otherwise a
        # test against another address would hand the stored password to it.
        if (stored.get("host"), int(stored.get("port") or 0), stored.get("username")) != (host, port, username):
            raise ValueError("The server, port or user changed - enter the password again.")
        password = stored["password"]
    return {"type": kind, "host": host, "port": port, "database": database,
            "username": username, "password": str(password), "tls": tls, "ca_pem": ca_pem}


def _public_config(cfg):
    if not cfg:
        return None
    if cfg.get("type") == "url":
        try:
            shown = _normalise_url(cfg["url"])[0].render_as_string(hide_password=True)
        except Exception:
            shown = ""
        return {"type": "url", "url": shown, "tls": cfg.get("tls", "off"), "ca_pem": cfg.get("ca_pem", "")}
    return {"type": cfg["type"], "host": cfg["host"], "port": cfg["port"], "database": cfg["database"],
            "username": cfg["username"], "password_set": bool(cfg.get("password")),
            "tls": cfg.get("tls", "off"), "ca_pem": cfg.get("ca_pem", "")}


def _env_config():
    url = (os.getenv("DATABASE_URL") or "").strip()
    if not url:
        return None
    return {"type": "url", "url": url, "tls": (os.getenv("DATABASE_TLS") or "off").lower(), "ca_pem": ""}


def _load_config():
    global _ext_error
    env = _env_config()
    if env:
        return env
    try:
        with open(DB_CONFIG_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
        if isinstance(cfg, dict) and cfg.get("type"):
            return cfg
        raise ValueError("it does not describe a connection")
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        # Not silently: otherwise history quietly goes to the built-in store and
        # nobody knows the external database is no longer in use.
        _ext_error = "The saved database connection could not be read - set it up again in Settings."
        logger.error(f"{DB_CONFIG_FILE} cannot be used ({e}); the external database is NOT in use")
        return None


def _save_config(cfg) -> None:
    if cfg is None:
        try:
            os.remove(DB_CONFIG_FILE)
        except FileNotFoundError:
            pass
        return
    tmp = DB_CONFIG_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, DB_CONFIG_FILE)


def stored_config():
    """The saved connection settings, password included (for filling blanks)."""
    return _ext_cfg


# =============================================================== state changes
def _mark_down(e: Exception) -> None:
    global _ext_up, _ext_error, _ext_since
    if _ext_up:
        logger.warning("External database unreachable, history goes to the built-in store for now: "
                       + _explain(e))
        _ext_since = time.time()
    _ext_up = False
    _ext_error = _explain(e)
    _wake.set()


def _mark_up(server: str) -> None:
    global _ext_up, _ext_error, _ext_since, _ext_server
    if not _ext_up:
        _ext_since = time.time()
    _ext_up, _ext_error, _ext_server = True, "", server


def _run(fn, *args):
    """Run a history operation on the external database, or on the built-in one
    when there is none or it is not usable."""
    ext = _ext
    if ext is not None and _ext_up:
        try:
            return fn(ext, *args)
        except Exception as e:
            # Unreachable, or refusing everything (a dropped table, a revoked
            # right): either way history goes to the built-in store until it works
            # again. A single bad row never gets here - the write functions skip it.
            _mark_down(e)
    return fn(_local, *args)


def _sync_docs(b: _Backend, mode: str = "auto") -> None:
    """Bring the settings copy in a database in line with this dashboard.

      auto      write every document this dashboard has; take from the database
                the ones it does not have yet (a data directory that lost a
                file, or a new container started with DATABASE_URL). The admin
                login is never taken this way: resetting it from the appliance
                console must not be undone by the copy in the database.
      local     this dashboard wins: write what it has, remove the rest
      database  the database wins: take every document it holds

    Settings saved by a newer dashboard are left completely alone unless the
    administrator explicitly chose "local": an older dashboard neither loads them
    nor overwrites them.
    """
    global _ext_note
    provider, applier = _docs_provider, _docs_applier
    if provider is None:
        return
    local = provider()
    remote = _get_docs(b)
    meta = remote.get(_META) or {}
    if _schema_of(meta) > _SCHEMA_VERSION:
        newer = meta.get("app_version") or "unknown version"
        if mode == "database":
            raise ValueError("These settings were saved by a newer dashboard (%s). Upgrade this dashboard before "
                             "loading them." % newer)
        if mode == "auto":
            note = ("The settings stored in the database were saved by a newer dashboard (%s). This dashboard "
                    "leaves them alone and does not store its own there - upgrade it." % newer)
            if _ext_note != note:
                logger.warning(note)
            _ext_note = note
            return
    _ext_note = ""
    push, remove = {}, []
    for name in DOC_NAMES:
        doc, present = local.get(name, (None, False))
        in_db = remote.get(name)
        take = in_db is not None and applier is not None and (
            mode == "database" or (mode == "auto" and not present and name != "auth"))
        if take:
            if in_db != doc:
                applier(name, in_db)
                logger.info(f"Settings '{name}' loaded from the external database")
        elif present and doc is not None:
            push[name] = doc
        elif mode == "local" and in_db is not None:
            remove.append(name)
    if (push or remove) and _put_docs(b, push, remove):
        logger.info("Settings copy in the external database updated")


def _schema_of(meta) -> int:
    try:
        return int((meta or {}).get("schema") or 1)
    except (TypeError, ValueError):
        return 1


def _refresh_counts(b=None) -> None:
    """Row counts for Settings, looked up here in the background so that no web
    request has to wait for the database."""
    global _ext_counts, _ext_counts_at
    b = b or _ext
    if b is None:
        _ext_counts = None
        return
    _ext_counts, _ext_counts_at = _counts(b), time.time()


def _recover() -> bool:
    """Called while the external database is marked down: if it answers, move the
    history collected meanwhile into it and resume."""
    global _ext_error, _docs_dirty, _ext_note
    with _state_lock:
        ext = _ext
        if ext is None or _ext_up:
            return _ext_up
        try:
            server = _server_name(ext)
            _init(ext)
            _docs_dirty = False
            try:
                _sync_docs(ext, "auto")
            except Exception as e:
                if _is_outage(e):
                    raise
                # trouble with the settings copy must not keep history out of the database
                _ext_note = "The settings copy in the database could not be updated: " + _explain(e)
                logger.warning(_ext_note)
            moved = _transfer(_local, ext, delete_src=True)       # in steps; new history keeps going to the spool
            with _write_lock:
                more = _transfer(_local, ext, delete_src=True)    # what arrived meanwhile
                _mark_up(server)
            _refresh_counts(ext)
        except Exception as e:
            _ext_error = _explain(e)
            return False
    n_se, n_fo = moved["sessions"] + more["sessions"], moved["failover_events"] + more["failover_events"]
    if n_se or n_fo:
        logger.info(f"Moved {n_se} session(s) and {n_fo} failover event(s) "
                    f"from the built-in store into the external database")
    logger.info(f"External database connected: {server}")
    return True


def _sync_loop() -> None:
    global _docs_dirty, _ext_note
    while True:
        _wake.wait(RECHECK_SECS)
        _wake.clear()
        try:
            ext = _ext
            if ext is None:
                continue
            if not _ext_up:
                _recover()
                continue
            try:
                with ext.engine.connect() as c:       # notice an outage even without traffic
                    c.execute(sa.select(sa.literal(1)))
                _refresh_counts(ext)
            except Exception as e:
                _mark_down(e)
                continue
            if _docs_dirty:
                _docs_dirty = False
                try:
                    _sync_docs(ext, "auto")
                except Exception as e:
                    if _is_outage(e):
                        _docs_dirty = True
                        _mark_down(e)
                    else:
                        # A problem with the settings copy is not an outage: history
                        # keeps going to the database, and Settings shows the note.
                        _ext_note = "The settings copy in the database could not be updated: " + _explain(e)
                        logger.warning(_ext_note)
        except Exception as e:
            logger.warning(f"Database sync pass failed: {e}")


def start_sync_thread() -> None:
    global _sync_thread_started
    if _sync_thread_started:
        return
    _sync_thread_started = True
    threading.Thread(target=_sync_loop, name="db-sync", daemon=True).start()


def register_documents(provider, applier) -> None:
    """provider() -> {name: (document, present_locally)}; applier(name, document)."""
    global _docs_provider, _docs_applier
    _docs_provider, _docs_applier = provider, applier


def documents_changed() -> None:
    """A settings file was just written: copy it to the external database soon,
    without making the caller wait for it."""
    global _docs_dirty
    if _ext is not None:
        _docs_dirty = True
        _wake.set()


# ============================================================ public: database
def init_db() -> None:
    """Open the built-in store and, if one is configured, the external database."""
    global _local, _ext, _ext_cfg, _ext_error, _ext_since
    with _state_lock:
        if _local is None:
            _local = _local_backend()
        _init(_local)
        cfg = _load_config()
        if cfg and _ext is None:
            try:
                _ext, _ext_cfg = _make_backend(cfg), cfg
                _ext_since = time.time()
            except Exception as e:
                _ext_error = _explain(e)
                logger.error(f"External database settings are not usable: {_ext_error}")
    if _ext is not None and not _recover():
        logger.warning(f"External database not reachable at startup ({_ext_error}); "
                       f"using the built-in store until it is")
    start_sync_thread()


def test_config(cfg: dict) -> dict:
    """Connect with these settings and prove they are usable: sign in, create the
    tables, write, read and delete a row. Tables that did not exist before are
    removed again, so a test leaves nothing behind."""
    b = _make_backend(cfg)
    try:
        server = _server_name(b)
        insp = sa.inspect(b.engine)
        created = [t for t in (b.failover, b.sessions, b.security, b.settings) if not insp.has_table(t.name)]
        _init(b)
        try:
            probe = "__probe_%s__" % os.urandom(4).hex()
            with b.engine.begin() as c:
                c.execute(sa.insert(b.settings), [{"name": probe, "value": _PROBE_TEXT, "updated": time.time()}])
                back = c.execute(sa.select(b.settings.c.value).where(b.settings.c.name == probe)).scalar()
                c.execute(sa.delete(b.settings).where(b.settings.c.name == probe))
            if back != _PROBE_TEXT:
                raise ValueError("This database does not store Unicode text correctly. "
                                 "Create it with a UTF-8 / Unicode character set.")
            docs = _get_docs(b)
            counts = _counts(b)
        finally:
            for t in reversed(created):
                t.drop(b.engine, checkfirst=True)
        meta = docs.get(_META) or {}
        nodes = docs.get("nodes") or {}
        return {
            "server": server,
            "existing": {
                "settings": any(docs.get(n) is not None for n in ("nodes", "auth", "ldap")),
                "instances": [str(i.get("name") or i.get("id"))
                              for i in (nodes.get("instances") if isinstance(nodes.get("instances"), list) else [])
                              if isinstance(i, dict)][:20],
                "saved_by": meta.get("saved_by"), "saved_at": meta.get("saved_at"),
                "saved_version": meta.get("app_version"), "newer": _schema_of(meta) > _SCHEMA_VERSION,
                "sessions": counts["sessions"], "failover_events": counts["failover_events"],
            },
        }
    finally:
        b.engine.dispose()


def connect_external(cfg: dict, settings_from: str = "local") -> dict:
    """Start using an external database.

    This dashboard's history is moved into it. settings_from decides what happens
    to settings the database already holds: "local" replaces them with this
    dashboard's, "database" replaces this dashboard's settings with them.
    """
    global _ext, _ext_cfg, _docs_dirty, _ext_note
    if _env_config():
        raise ValueError("The database is set by the DATABASE_URL environment variable and cannot be changed here.")
    new = _make_backend(cfg)
    try:
        server = _server_name(new)
        _init(new)
        with _state_lock:
            _sync_docs(new, "database" if settings_from == "database" else "local")
            old = _ext
            moved = _transfer(_local, new, delete_src=True)       # in steps, without holding requests up
            with _write_lock:
                more = _transfer(_local, new, delete_src=True)    # what arrived meanwhile
                _ext, _ext_cfg = new, cfg
                _mark_up(server)
            for k in moved:
                moved[k] += more[k]
            _docs_dirty, _ext_note = False, ""
            _save_config(cfg)
            try:
                _refresh_counts(new)
            except Exception:
                pass
    except Exception:
        if _ext is not new:
            new.engine.dispose()
        raise
    if old is not None:
        old.engine.dispose()
    logger.info(f"External database connected: {server}; moved {moved['sessions']} session(s) and "
                f"{moved['failover_events']} failover event(s) into it")
    return {"server": server, "moved": moved}


def disconnect_external() -> dict:
    """Go back to the built-in store. History is copied back when the external
    database is reachable; the external database itself is left as it is."""
    global _ext, _ext_cfg, _ext_up, _ext_error, _ext_server, _ext_note, _ext_counts
    if _env_config():
        raise ValueError("The database is set by the DATABASE_URL environment variable and cannot be changed here.")
    with _state_lock:
        old = _ext
        if old is None:
            return {"copied": None, "reachable": None}
        copied, reachable = None, _ext_up
        with _write_lock:                  # from here on new history goes to the built-in store
            _ext, _ext_cfg, _ext_up, _ext_error, _ext_server = None, None, False, "", ""
            _ext_note, _ext_counts = "", None
        _save_config(None)
        if reachable:
            try:
                copied = _transfer(old, _local, delete_src=False)
            except Exception as e:
                reachable = False
                logger.warning("History could not be copied back from the external database: " + _explain(e))
        old.engine.dispose()
    logger.info("External database disconnected; using the built-in store")
    return {"copied": copied, "reachable": reachable}


def status() -> dict:
    """What Settings -> Database shows. It never waits for the external database:
    its row counts come from the background loop (at most one request refreshes
    them when they are a few seconds old)."""
    ext = _ext
    out = {
        "types": [{"id": k, "label": v["label"], "port": v["port"]} for k, v in TYPES.items()],
        "backend": "external" if ext is not None else "builtin",
        "locked": bool(_env_config()),
        "retention_days": RETENTION_DAYS,
        "config": _public_config(_ext_cfg),
        "connected": bool(ext is not None and _ext_up),
        "server": _ext_server,
        "error": _ext_error,
        "note": _ext_note,
        "since": datetime.fromtimestamp(_ext_since).astimezone().isoformat(timespec="seconds") if _ext_since else None,
        "counts": None, "waiting": None,
    }
    try:
        if ext is None:
            out["counts"] = _counts(_local)
            return out
        out["waiting"] = _counts(_local)              # collected here, not in the database yet
    except Exception as e:
        logger.warning(f"Built-in store could not be read: {e}")
    if ext is not None and _ext_up:
        if time.time() - _ext_counts_at > 3 and _counts_lock.acquire(blocking=False):
            try:
                _refresh_counts(ext)
            except Exception as e:
                _mark_down(e)
                out["connected"], out["error"] = False, _ext_error
            finally:
                _counts_lock.release()
        if out["connected"]:
            out["counts"] = _ext_counts
    return out


def describe_error(e: Exception) -> str:
    return _explain(e)


# ============================================================= public: history
def add_failover_events(events) -> int:
    """Insert failover events, ignoring duplicates. Returns rows added."""
    rows = [{
        "ts_epoch": _epoch(e.get("timestamp")), "timestamp": str(e.get("timestamp") or ""),
        "type": e.get("type"), "reason": e.get("reason"), "role_change": e.get("role_change"),
        "ip": e.get("ip"), "instance": str(e.get("instance") or "default"),
    } for e in (events or []) if isinstance(e, dict)]
    if not rows:
        return 0
    with _write_lock:
        return _run(_add_failover, rows)


def get_failover_events(days=None, instance=None) -> list:
    return _run(_get_failover, days, instance)


def add_security_events(rows) -> int:
    """Store security events (see security.make_row), ignoring ones already stored."""
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    if not rows:
        return 0
    with _write_lock:
        return _run(_add_security, rows)


def get_security_events(instance=None, since=None, until=None, kinds=None, text=None, limit=500) -> list:
    """Stored security events, newest first."""
    limit = max(1, min(int(limit or 500), 100000))
    return _run(_get_security, instance, since, until, tuple(kinds or ()), (text or "").strip()[:200], limit)


def upsert_sessions(node: str, sessions, instance: str = "default") -> int:
    """Record/refresh observed sessions for an instance. Returns number processed."""
    now = time.time()
    rows = [{
        "instance": str(instance), "node": node,
        "session_id": s.get("session_id") or f"{s.get('user')}|{s.get('type')}",
        "username": s.get("user"), "type": s.get("type"), "ip": s.get("ip"), "gateway": s.get("gateway"),
        "start_time": s.get("start"), "duration": s.get("duration"),
        "detail": json.dumps(s.get("detail") or {}), "status": s.get("status") or "Active",
        "first_seen": now, "last_seen": now,
    } for s in (sessions or []) if isinstance(s, dict)]
    if not rows:
        return 0
    with _write_lock:
        return _run(_merge_sessions, rows)


def get_sessions(days=None, instance=None) -> list:
    """Stored sessions in the dashboard's own history, newest first."""
    return _run(_get_sessions, days, instance)


def purge(days=None) -> dict:
    """Delete data older than the retention window. Returns rows removed."""
    days = days or RETENTION_DAYS
    cutoff = time.time() - days * 86400
    with _write_lock:
        fo, se, sec = _purge(_local, cutoff)
        ext = _ext
        if ext is not None and _ext_up:
            try:
                more = _purge(ext, cutoff)
                fo, se, sec = fo + more[0], se + more[1], sec + more[2]
            except Exception as e:
                _mark_down(e)
    if fo or se or sec:
        logger.info(f"Retention: removed {fo} failover event(s), {se} session(s) and {sec} security event(s) "
                    f"older than {days} day(s) (or beyond {SECURITY_MAX_EVENTS} security events)")
    return {"failover_removed": fo, "sessions_removed": se, "security_removed": sec, "days": days}


def purge_types(types) -> int:
    """Delete stored sessions whose `type` matches (used to drop legacy
    management rows once the Sessions tab became AAA-only)."""
    types = tuple(types or ())
    if not types:
        return 0
    with _write_lock:
        n = _purge_types(_local, types)
        ext = _ext
        if ext is not None and _ext_up:
            try:
                n += _purge_types(ext, types)
            except Exception as e:
                _mark_down(e)
    if n:
        logger.info(f"Removed {n} stored session row(s) of type: {', '.join(types)}")
    return n


def stats() -> dict:
    out = {"db_file": DB_FILE, "db_size_bytes": os.path.getsize(DB_FILE) if os.path.exists(DB_FILE) else 0,
           "retention_days": RETENTION_DAYS}
    out.update(_run(_counts))
    out["backend"] = "external" if (_ext is not None and _ext_up) else "builtin"
    return out


def start_retention_thread() -> None:
    """Run purge() now and then every RETENTION_INTERVAL_SECS in the background."""
    def _loop():
        while True:
            try:
                purge()
            except Exception as e:
                logger.warning(f"Retention pass failed: {e}")
            time.sleep(RETENTION_INTERVAL_SECS)

    threading.Thread(target=_loop, name="retention", daemon=True).start()
    logger.info(f"Retention thread started (keep {RETENTION_DAYS}d, every {RETENTION_INTERVAL_SECS}s)")


def migrate_json_failover(path: str) -> int:
    """One-time import of the legacy failover_history.json into the store."""
    if not os.path.exists(path):
        return 0
    try:
        if _run(_counts)["failover_events"]:
            return 0   # already populated
        with open(path, "r", encoding="utf-8") as f:
            events = json.load(f)
        n = add_failover_events(events if isinstance(events, list) else [])
        if n:
            logger.info(f"Imported {n} failover event(s) from {path}")
        return n
    except Exception as e:
        logger.warning(f"Could not import {path}: {e}")
        return 0
