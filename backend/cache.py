"""SQLite TTL cache, keyed per (source, type, indicator).

Exists to protect the free-tier quotas: VirusTotal allows ~500 lookups a day,
and re-triaging the same indicator should not spend a second one.
"""

import json
import sqlite3
import threading
import time
from typing import Any

from . import config

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def _connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        config.CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(config.CACHE_PATH, check_same_thread=False)
        _conn.execute(
            "CREATE TABLE IF NOT EXISTS entries ("
            " k TEXT PRIMARY KEY, payload TEXT NOT NULL, expires_at REAL NOT NULL)"
        )
        _conn.commit()
    return _conn


def _key(source: str, ioc_type: str, value: str) -> str:
    return f"{source}|{ioc_type}|{value}"


def get(source: str, ioc_type: str, value: str) -> dict[str, Any] | None:
    with _lock:
        cur = _connect().execute(
            "SELECT payload, expires_at FROM entries WHERE k = ?",
            (_key(source, ioc_type, value),),
        )
        row = cur.fetchone()
    if not row:
        return None
    payload, expires_at = row
    if expires_at < time.time():
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return None


def put(source: str, ioc_type: str, value: str, payload: dict[str, Any], ttl: int | None = None) -> None:
    ttl = config.CACHE_TTL if ttl is None else ttl
    if ttl <= 0:
        return
    with _lock:
        conn = _connect()
        conn.execute(
            "INSERT OR REPLACE INTO entries (k, payload, expires_at) VALUES (?, ?, ?)",
            (_key(source, ioc_type, value), json.dumps(payload), time.time() + ttl),
        )
        conn.commit()


def purge_expired() -> int:
    with _lock:
        conn = _connect()
        cur = conn.execute("DELETE FROM entries WHERE expires_at < ?", (time.time(),))
        conn.commit()
        return cur.rowcount
