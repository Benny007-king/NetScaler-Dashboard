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
DB_FILE = os.getenv("DASHBOARD_DB_FILE") or os.path.join(DATA_DIR, "dashboard.db")
DB_CONFIG_FILE = os.getenv("DB_CONFIG_FILE") or os.path.join(DATA_DIR, "db_config.json")
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "7") or 7)
RETENTION_INTERVAL_SECS = int(os.getenv("RETENTION_INTERVAL_SECS", "3600") or 3600)
# A session counts as "Active" if it was seen within this window.
ACTIVE_WINDOW_SECS = int(os.getenv("SESSION_ACTIVE_WINDOW_SECS", "120") or 120)
# Tables in an external database carry a prefix: it is somebody else's server and
# "sessions" is too common a name to claim. The built-in file keeps the old names.
TABLE_PREFIX = os.getenv("DB_TABLE_PREFIX", "nsd_")
TIMEOUT_SECS = int(os.getenv("DB_TIMEOUT_SECS", "10") or 10)
RECHECK_SECS = int(os.getenv("DB_RECHECK_SECS", "20") or 20)

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
DOC_NAMES = ("nodes", "auth", "ldap", "ha_state")
_META = "meta"
_SCHEMA_VERSION = 1
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
_docs_dirty = False
_docs_provider = None                # () -> {name: (document, present_locally)}
_docs_applier = None                 # (name, document) -> None
_sync_thread_started = False


# ====================================================================== schema
class _Backend:
    """An engine plus the three tables, named for that engine."""

    def __init__(self, engine, prefix: str, label: str):
        self.engine = engine
        self.prefix = prefix
        self.label = label
        md = sa.MetaData()
        big = sa.UnicodeText().with_variant(_mysql.LONGTEXT(), "mysql", "mariadb")
        big = big.with_variant(_mssql.NVARCHAR(None), "mssql")          # NVARCHAR(max), not NTEXT
        # Case-sensitive keys on MySQL/MariaDB, like every other backend.
        opts = {"mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_bin"}
        self.failover = sa.Table(
            prefix + "failover_events", md,
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("ts_epoch", sa.Double, nullable=False),
            sa.Column("timestamp", sa.Unicode(64), nullable=False),
            sa.Column("type", sa.Unicode(64)),
            sa.Column("reason", big),
            sa.Column("role_change", sa.Unicode(128)),
            sa.Column("ip", sa.Unicode(64)),
            sa.Column("instance", sa.Unicode(64)),
            sa.UniqueConstraint("timestamp", "ip", "role_change", name=prefix + "uq_failover"),
            sa.Index(prefix + "idx_fo_ts", "ts_epoch"),
            **opts)
        # One row per real session, keyed on a stable NITRO session id, so repeated
        # polls of the same session refresh one row instead of piling up.
        self.sessions = sa.Table(
            prefix + "sessions", md,
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("instance", sa.Unicode(64)),
            sa.Column("node", sa.Unicode(64)),
            sa.Column("session_id", sa.Unicode(255)),
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
                       for t in (self.failover, self.sessions, self.settings)}

    @property
    def is_sqlite(self) -> bool:
        return self.engine.dialect.name == "sqlite"

    def fit(self, table, row: dict) -> dict:
        """Trim strings to the column widths (SQLite never cared; real servers do)."""
        for name, width in self.widths[table.name].items():
            v = row.get(name)
            if v is None:
                continue
            if not isinstance(v, str):
                v = row[name] = str(v)
            if len(v) > width:
                row[name] = v[:width]
        return row


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
            if new:
                c.execute(sa.insert(t), new)
            return len(new)
    except sa.exc.IntegrityError:
        # The server compares keys differently than Python does (case, padding)
        # or another writer got there first. Go row by row and skip what exists.
        added = 0
        for r in todo:
            try:
                with b.engine.begin() as c:
                    c.execute(sa.insert(t), [r])
                added += 1
            except sa.exc.IntegrityError:
                pass
        return added


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
                if inserts:
                    c.execute(sa.insert(t), inserts)
                if updates:
                    c.execute(_session_refresh(t), updates)
        except sa.exc.IntegrityError:
            for r in by_id.values():
                _merge_one_session(b, r)
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
    q = sa.select(t.c.node, t.c.username, t.c.type, t.c.ip, t.c.gateway, t.c.start_time,
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
                "status": status, "end": end,
            })
    return out


def _purge(b: _Backend, cutoff: float) -> tuple:
    with b.engine.begin() as c:
        fo = c.execute(sa.delete(b.failover).where(b.failover.c.ts_epoch < cutoff)).rowcount
        se = c.execute(sa.delete(b.sessions).where(b.sessions.c.last_seen < cutoff)).rowcount
    return max(fo or 0, 0), max(se or 0, 0)


def _purge_types(b: _Backend, types: tuple) -> int:
    with b.engine.begin() as c:
        n = c.execute(sa.delete(b.sessions).where(b.sessions.c.type.in_(types))).rowcount
    return max(n or 0, 0)


def _counts(b: _Backend) -> dict:
    with b.engine.connect() as c:
        fo = c.execute(sa.select(sa.func.count(), sa.func.min(b.failover.c.ts_epoch)).select_from(b.failover)).first()
        se = c.execute(sa.select(sa.func.count(), sa.func.min(b.sessions.c.last_seen)).select_from(b.sessions)).first()

    def _iso(v):
        return datetime.fromtimestamp(v).isoformat() if v else None
    return {"failover_events": fo[0], "failover_oldest": _iso(fo[1]),
            "sessions": se[0], "sessions_oldest": _iso(se[1])}


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
    out = {}
    with b.engine.connect() as c:
        for name, value in c.execute(sa.select(b.settings.c.name, b.settings.c.value)):
            try:
                out[name] = json.loads(value) if value else None
            except Exception:
                pass
    return out


def _transfer(src: _Backend, dst: _Backend, delete_src: bool) -> dict:
    """Copy all history from one backend into another (existing rows are merged,
    never duplicated). With delete_src the copied rows are then removed."""
    with src.engine.connect() as c:
        fo = [dict(r._mapping) for r in c.execute(sa.select(src.failover))]
        se = [dict(r._mapping) for r in c.execute(sa.select(src.sessions))]
    moved = {"failover_events": len(fo), "sessions": len(se)}
    if fo:
        _add_failover(dst, fo)
    if se:
        _merge_sessions(dst, se)
    if delete_src and (fo or se):
        with src.engine.begin() as c:
            if fo:
                c.execute(sa.delete(src.failover).where(src.failover.c.id <= max(r["id"] for r in fo)))
            if se:
                c.execute(sa.delete(src.sessions).where(src.sessions.c.id <= max(r["id"] for r in se)))
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
    return _Backend(engine, TABLE_PREFIX, TYPES[kind]["label"])


def _server_name(b: _Backend) -> str:
    """Connects, and names the server it reached (e.g. "PostgreSQL 16.4")."""
    with b.engine.connect() as c:
        c.execute(sa.select(sa.literal(1)))
    d = b.engine.dialect
    name = {"postgresql": "PostgreSQL", "mssql": "Microsoft SQL Server"}.get(d.name)
    if not name:
        name = "MariaDB" if getattr(d, "is_mariadb", False) else "MySQL"
    info = [x for x in (d.server_version_info or ()) if isinstance(x, int)][:2]
    return (name + " " + ".".join(str(x) for x in info)).strip()


def _explain(e: Exception) -> str:
    """One readable line from a driver error - never the statement or a traceback."""
    orig = getattr(e, "orig", None) or e
    args = getattr(orig, "args", None) or ()
    if args and isinstance(args[0], dict):            # pg8000 reports server errors as a dict
        text = str(args[0].get("M") or args[0])
    elif args:
        text = " ".join(a.decode("utf-8", "replace") if isinstance(a, bytes) else str(a)
                        for a in args if a not in (None, ""))
    else:
        text = str(orig)
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
        if url.password in (None, "", "***") and stored and stored.get("type") == "url":
            url = url.set(password=_normalise_url(stored["url"])[0].password)
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
    if not password and stored and stored.get("type") == kind:
        password = stored.get("password") or ""
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
    env = _env_config()
    if env:
        return env
    try:
        with open(DB_CONFIG_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg if isinstance(cfg, dict) and cfg.get("type") else None
    except (OSError, ValueError):
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
    when there is none or it is not answering."""
    ext = _ext
    if ext is not None and _ext_up:
        try:
            return fn(ext, *args)
        except Exception as e:                        # any failure means "not usable right now"
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
    """
    provider, applier = _docs_provider, _docs_applier
    if provider is None:
        return
    local = provider()
    remote = _get_docs(b)
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


def _recover() -> bool:
    """Called while the external database is marked down: if it answers, move the
    history collected meanwhile into it and resume."""
    global _ext_error, _docs_dirty
    with _state_lock:
        ext = _ext
        if ext is None or _ext_up:
            return _ext_up
        try:
            server = _server_name(ext)
            _init(ext)
            _docs_dirty = False
            _sync_docs(ext, "auto")
            with _write_lock:
                moved = _transfer(_local, ext, delete_src=True)
                _mark_up(server)
        except Exception as e:
            _ext_error = _explain(e)
            return False
    if moved["sessions"] or moved["failover_events"]:
        logger.info(f"Moved {moved['sessions']} session(s) and {moved['failover_events']} failover event(s) "
                    f"from the built-in store into the external database")
    logger.info(f"External database connected: {server}")
    return True


def _sync_loop() -> None:
    global _docs_dirty
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
                if _docs_dirty:
                    _docs_dirty = False
                    _sync_docs(ext, "auto")
            except Exception as e:
                _docs_dirty = True
                _mark_down(e)
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
        created = [t for t in (b.failover, b.sessions, b.settings) if not insp.has_table(t.name)]
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
                "instances": [str(i.get("name") or i.get("id")) for i in (nodes.get("instances") or [])
                              if isinstance(i, dict)][:20],
                "saved_by": meta.get("saved_by"), "saved_at": meta.get("saved_at"),
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
    global _ext, _ext_cfg, _docs_dirty
    if _env_config():
        raise ValueError("The database is set by the DATABASE_URL environment variable and cannot be changed here.")
    new = _make_backend(cfg)
    try:
        server = _server_name(new)
        _init(new)
        with _state_lock:
            _sync_docs(new, "database" if settings_from == "database" else "local")
            old = _ext
            with _write_lock:
                moved = _transfer(_local, new, delete_src=True)
                _ext, _ext_cfg = new, cfg
                _mark_up(server)
            _docs_dirty = False
            _save_config(cfg)
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
    global _ext, _ext_cfg, _ext_up, _ext_error, _ext_server
    if _env_config():
        raise ValueError("The database is set by the DATABASE_URL environment variable and cannot be changed here.")
    with _state_lock:
        old = _ext
        if old is None:
            return {"copied": None, "reachable": None}
        copied, reachable = None, _ext_up
        with _write_lock:
            if _ext_up:
                try:
                    copied = _transfer(old, _local, delete_src=False)
                except Exception as e:
                    reachable = False
                    logger.warning("History could not be copied back from the external database: " + _explain(e))
            _ext, _ext_cfg, _ext_up, _ext_error, _ext_server = None, None, False, "", ""
        _save_config(None)
        old.engine.dispose()
    logger.info("External database disconnected; using the built-in store")
    return {"copied": copied, "reachable": reachable}


def status() -> dict:
    """What Settings -> Database shows."""
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
        "since": datetime.fromtimestamp(_ext_since).astimezone().isoformat(timespec="seconds") if _ext_since else None,
        "counts": None, "waiting": None,
    }
    try:
        if ext is None:
            out["counts"] = _counts(_local)
        else:
            out["waiting"] = _counts(_local)          # collected here, not in the database yet
            if _ext_up:
                out["counts"] = _counts(ext)
    except Exception as e:
        if ext is not None:
            _mark_down(e)
            out["connected"], out["error"] = False, _ext_error
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
        fo, se = _purge(_local, cutoff)
        ext = _ext
        if ext is not None and _ext_up:
            try:
                more = _purge(ext, cutoff)
                fo, se = fo + more[0], se + more[1]
            except Exception as e:
                _mark_down(e)
    if fo or se:
        logger.info(f"Retention: removed {fo} failover event(s) and {se} session(s) older than {days} day(s)")
    return {"failover_removed": fo, "sessions_removed": se, "days": days}


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
