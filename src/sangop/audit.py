"""Tamper-evident audit ledger (SQLite WAL + hash chain, optionally keyed with HMAC-SHA256).

Rule: raw PII or secrets are NEVER written here. Only event metadata,
PII *counts by kind*, verdicts, and already-scrubbed text.

Without a key the chain is a plain SHA-256 chain: it shows accidental damage and clumsy edits, but someone who can
write the file can edit rows and recompute every later hash. With a key (``AuditLedger(key=...)`` or the
``SANGOP_LEDGER_KEY`` environment variable, at least 16 characters, kept OUTSIDE the ledger file) every row is an
HMAC-SHA256, which cannot be recomputed without the key. Neither mode can see that the LAST rows were cut off:
copy ``anchor()`` ("id:hash" of the newest row) somewhere the writer cannot reach and pass it to
``verify_report(anchor=...)`` for that.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc    TEXT NOT NULL,
    event     TEXT NOT NULL,
    record    TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL,
    alg       TEXT NOT NULL DEFAULT 'sha256'
);
"""
ALG_PLAIN = "sha256"
ALG_KEYED = "hmac-sha256"
KEY_ENV = "SANGOP_LEDGER_KEY"
MIN_KEY_LEN = 16


def _canonical(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _hash(prev_hash: str, ts: str, event: str, record: str, key: Optional[bytes] = None) -> str:
    data = f"{prev_hash}|{ts}|{event}|{record}".encode()
    if key is not None:
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def _resolve_key(key: Any) -> Optional[bytes]:
    if key is None:
        key = os.environ.get(KEY_ENV) or None
    if key is None:
        return None
    raw = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    if len(raw) < MIN_KEY_LEN:
        raise ValueError(f"ledger key must be at least {MIN_KEY_LEN} characters (use a long random value)")
    return raw


WEAK_KEY_LEN = 32


def weak_key_reason(raw: bytes) -> Optional[str]:
    """Why a ledger key looks weak (short, few different characters, a repeated block, a simple sequence), or None.
    This is advice only: a key that meets MIN_KEY_LEN is still accepted. A random 32-byte value is a good key
    (for example ``python -c "import secrets; print(secrets.token_hex(32))"``)."""
    n = len(raw)
    if n < WEAK_KEY_LEN:
        return f"only {n} characters (use at least {WEAK_KEY_LEN}, random)"
    if len(set(raw)) < 8:
        return f"only {len(set(raw))} different characters"
    for p in range(1, n // 2 + 1):
        if n % p == 0 and raw[:p] * (n // p) == raw:
            return f"a block of {p} character(s) repeated"
    steps = sum(1 for a, b in zip(raw, raw[1:]) if abs(a - b) <= 1)
    if steps >= 0.7 * (n - 1):
        return "mostly a simple sequence (such as 1234... or abcd... or aaaa...)"
    return None


class AuditLedger:
    def __init__(self, path: str, key: Any = None) -> None:
        self.path = path
        self._key = _resolve_key(key)
        self.key_warning: Optional[str] = None
        if self._key is not None:
            self.key_warning = weak_key_reason(self._key)
            if self.key_warning:
                warnings.warn(
                    f"SANGOP_LEDGER_KEY / ledger key looks weak: {self.key_warning}. A weak key lets someone who can "
                    "read the ledger file guess it and rewrite rows undetected. Use a long random value kept outside "
                    "the ledger.", UserWarning, stacklevel=3)
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._lock = threading.Lock()
        # timeout: other processes may hold the write lock for a moment (see append()).
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=30)
        self._init_db(path)

    def _init_db(self, path: str) -> None:
        """Open-time setup that is safe when several processes/threads open the same new file at once.

        Switching to WAL and creating the table need a lock that SQLite's busy timeout does not always cover, so a
        locked database is retried for a few seconds (found by the thread test; it failed once in a full run)."""
        deadline = time.monotonic() + 30
        delay = 0.01
        while True:
            try:
                if path != ":memory:":
                    mode = self._conn.execute("PRAGMA journal_mode").fetchone()[0]
                    if str(mode).lower() != "wal":
                        self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA synchronous=NORMAL")
                self._conn.executescript(_SCHEMA)
                cols = [r[1] for r in self._conn.execute("PRAGMA table_info(events)").fetchall()]
                if "alg" not in cols:               # ledgers written before 0.1.4 have plain SHA-256 rows
                    try:
                        self._conn.execute("ALTER TABLE events ADD COLUMN alg TEXT NOT NULL DEFAULT 'sha256'")
                    except sqlite3.OperationalError as e:
                        if "duplicate column" not in str(e).lower():
                            raise
                return
            except sqlite3.OperationalError as e:
                if "locked" not in str(e).lower() and "busy" not in str(e).lower():
                    raise
                if time.monotonic() > deadline:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 0.25)

    def _last_hash(self) -> str:
        row = self._conn.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def append(self, event: str, record: Dict[str, Any]) -> str:
        ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        body = _canonical(record)
        with self._lock:
            # BEGIN IMMEDIATE takes SQLite's write lock BEFORE the last hash is read, so several processes (or
            # several AuditLedger objects) appending to the same file cannot both chain onto the same previous row.
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                prev = self._last_hash()
                h = _hash(prev, ts, event, body, self._key)
                self._conn.execute(
                    "INSERT INTO events (ts_utc, event, record, prev_hash, hash, alg) VALUES (?,?,?,?,?,?)",
                    (ts, event, body, prev, h, ALG_KEYED if self._key else ALG_PLAIN),
                )
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        return h

    def verify(self) -> Tuple[bool, int, Optional[int]]:
        """Return (ok, rows_checked, first_bad_id). Keyed rows cannot be checked without the key (not ok)."""
        rep = self.verify_report()
        return rep["ok"], rep["rows"], rep["first_bad_id"]

    def anchor(self) -> Optional[str]:
        """"id:hash" of the newest row. Store it where the ledger's writer cannot change it."""
        with self._lock:
            row = self._conn.execute("SELECT id, hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        return f"{row[0]}:{row[1]}" if row else None

    def verify_report(self, anchor: Optional[str] = None) -> Dict[str, Any]:
        """Full check. Keys: ok, rows, first_bad_id, mode ("keyed" | "unkeyed" | "mixed"), message, anchor."""
        prev, n, seen_keyed = GENESIS, 0, False
        keyed_rows = plain_rows = 0
        hashes: Dict[int, str] = {}
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, ts_utc, event, record, prev_hash, hash, alg FROM events ORDER BY id"
            ).fetchall()

        def done(ok: bool, bad: Optional[int], msg: str) -> Dict[str, Any]:
            mode = "keyed" if keyed_rows and not plain_rows else "unkeyed" if not keyed_rows else "mixed"
            if ok and mode == "unkeyed":
                msg += (" Ledger is UNKEYED (plain SHA-256 chain, no SANGOP_LEDGER_KEY): edits that recompute the "
                        "chain and cut-off last rows (truncation) are NOT detected.")
            elif ok and not anchor:
                msg += " Chain alone cannot show that the newest rows were cut off: compare an anchor."
            return {"ok": ok, "rows": n, "first_bad_id": bad, "mode": mode, "message": msg, "anchor": self.anchor()}

        for rid, ts, event, record, prev_hash, h, alg in rows:
            n += 1
            hashes[rid] = h
            if prev_hash != prev:
                return done(False, rid, f"chain broken at id={rid}")
            if alg == ALG_KEYED:
                if self._key is None:
                    return done(False, rid, f"row id={rid} is keyed but no key was given (set {KEY_ENV})")
                ok_row = hmac.compare_digest(_hash(prev, ts, event, record, self._key), h)
                seen_keyed = True
                keyed_rows += 1
            elif alg == ALG_PLAIN:
                if seen_keyed:
                    return done(False, rid, f"unkeyed row id={rid} after keyed rows (downgrade)")
                ok_row = _hash(prev, ts, event, record) == h
                plain_rows += 1
            else:
                return done(False, rid, f"unknown hash algorithm at id={rid}")
            if not ok_row:
                return done(False, rid, f"hash mismatch at id={rid}")
            prev = h
        if anchor:
            try:
                aid, ahash = anchor.split(":", 1)
                aid_i = int(aid)
            except ValueError:
                return done(False, None, "anchor must look like <id>:<hash>")
            if hashes.get(aid_i) != ahash:
                why = "row missing (truncated?)" if aid_i not in hashes else "hash differs (rewritten?)"
                return done(False, aid_i, f"anchor check failed: {why}")
            return done(True, None, f"{n} event(s) checked; anchor matches.")
        return done(True, None, f"{n} event(s) checked.")

    def tail(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, ts_utc, event, record FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{"id": r[0], "ts_utc": r[1], "event": r[2], "record": json.loads(r[3])} for r in rows]

    def close(self) -> None:
        self._conn.close()
