"""SQLite persistence for users, enrolled device certificates and revoked tokens.

All state transitions that matter for security are single atomic statements
(e.g. the TOTP replay guard is a compare-and-set UPDATE), so concurrent requests
cannot race each other into accepting the same one-time code twice."""
from __future__ import annotations

import datetime as dt
import re
import sqlite3
import threading
import time
from dataclasses import dataclass

from .crypto import SecretBox

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username        TEXT PRIMARY KEY,
    totp_secret     BLOB NOT NULL,            -- AES-GCM(nonce||ct), AAD = username
    totp_last_step  INTEGER NOT NULL DEFAULT -1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    REAL NOT NULL DEFAULT 0,
    created_at      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS certificates (
    serial       TEXT PRIMARY KEY,            -- hex
    username     TEXT NOT NULL REFERENCES users(username),
    device       TEXT NOT NULL,
    fingerprint  TEXT NOT NULL UNIQUE,        -- SHA-256 of DER
    key_type     TEXT NOT NULL,
    not_after    REAL NOT NULL,
    issued_at    REAL NOT NULL,
    revoked_at   REAL,
    reason       TEXT
);
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY,
    exp REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS counters (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
"""


class _Result:
    """Materialised cursor so rows are fetched while the lock is held."""

    def __init__(self, cur):
        self.rowcount = cur.rowcount
        self.rows = cur.fetchall()

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows

    def __iter__(self):
        return iter(self.rows)


@dataclass
class User:
    username: str
    totp_secret: str
    totp_last_step: int
    failed_attempts: int
    locked_until: float


@dataclass
class CertRecord:
    serial: str
    username: str
    device: str
    fingerprint: str
    key_type: str
    not_after: float
    issued_at: float
    revoked_at: float | None
    reason: str | None

    @property
    def revoked(self) -> bool:
        return self.revoked_at is not None


class Store:
    LOCK_THRESHOLD = 5

    def __init__(self, path, box: SecretBox, clock=time.time):
        self.db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)
        self.box = box
        self.clock = clock
        self.lock = threading.RLock()

    def _x(self, sql: str, params=()):
        """Every statement runs under one re-entrant lock: a single sqlite3 connection
        is shared across server threads and is not safe for concurrent use."""
        with self.lock:
            return _Result(self.db.execute(sql, params))

    # ------------------------------------------------------------------ users
    def add_user(self, username: str, totp_secret_b32: str) -> None:
        if not USERNAME_RE.match(username):
            raise ValueError("username must be 3-32 chars of a-z 0-9 . _ -")
        blob = self.box.seal(totp_secret_b32.encode(), username.encode())
        with self.lock:
            self._x("INSERT INTO users(username, totp_secret, created_at) VALUES (?,?,?)",
                            (username, blob, self.clock()))

    def get_user(self, username: str) -> User | None:
        row = self._x("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            return None
        secret = self.box.open(row["totp_secret"], username.encode()).decode()
        return User(row["username"], secret, row["totp_last_step"],
                    row["failed_attempts"], row["locked_until"])

    def list_users(self) -> list[str]:
        return [r[0] for r in self._x("SELECT username FROM users ORDER BY username")]

    def consume_totp_step(self, username: str, step: int) -> bool:
        """Atomic replay guard: succeeds only if `step` is newer than any accepted before."""
        with self.lock:
            cur = self._x(
                "UPDATE users SET totp_last_step=?, failed_attempts=0, locked_until=0 "
                "WHERE username=? AND totp_last_step < ?", (step, username, step))
            return cur.rowcount == 1

    def record_failure(self, username: str) -> float:
        """Increment failures; after the threshold, lock with exponential backoff
        (30s, 60s, 120s ... capped at 1h). Returns locked_until."""
        with self.lock:
            row = self._x("SELECT failed_attempts FROM users WHERE username=?",
                                  (username,)).fetchone()
            if not row:
                return 0.0
            fails = row[0] + 1
            locked_until = 0.0
            if fails >= self.LOCK_THRESHOLD:
                locked_until = self.clock() + min(30 * 2 ** (fails - self.LOCK_THRESHOLD), 3600)
            self._x("UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
                            (fails, locked_until, username))
            return locked_until

    # ------------------------------------------------------------------ certificates
    def add_cert(self, serial: int, username: str, device: str, fingerprint: str,
                 key_type: str, not_after: dt.datetime) -> None:
        with self.lock:
            self._x(
                "INSERT INTO certificates(serial, username, device, fingerprint, key_type, "
                "not_after, issued_at) VALUES (?,?,?,?,?,?,?)",
                (format(serial, "x"), username, device, fingerprint, key_type,
                 not_after.timestamp(), self.clock()))

    def _cert(self, row) -> CertRecord | None:
        return CertRecord(**dict(row)) if row else None

    def cert_by_fingerprint(self, fp: str) -> CertRecord | None:
        return self._cert(self._x(
            "SELECT * FROM certificates WHERE fingerprint=?", (fp,)).fetchone())

    def cert_by_serial(self, serial_hex: str) -> CertRecord | None:
        return self._cert(self._x(
            "SELECT * FROM certificates WHERE serial=?", (serial_hex.lower(),)).fetchone())

    def list_certs(self, username: str | None = None) -> list[CertRecord]:
        if username:
            rows = self._x("SELECT * FROM certificates WHERE username=? ORDER BY issued_at",
                                   (username,))
        else:
            rows = self._x("SELECT * FROM certificates ORDER BY issued_at")
        return [self._cert(r) for r in rows]

    def active_cert_count(self, username: str) -> int:
        return self._x(
            "SELECT COUNT(*) FROM certificates WHERE username=? AND revoked_at IS NULL "
            "AND not_after > ?", (username, self.clock())).fetchone()[0]

    def revoke_cert(self, serial_hex: str, reason: str = "unspecified") -> bool:
        with self.lock:
            cur = self._x(
                "UPDATE certificates SET revoked_at=?, reason=? WHERE serial=? AND revoked_at IS NULL",
                (self.clock(), reason, serial_hex.lower()))
            return cur.rowcount == 1

    def revoked_serials(self) -> list[tuple[int, dt.datetime, str]]:
        rows = self._x(
            "SELECT serial, revoked_at, reason FROM certificates WHERE revoked_at IS NOT NULL")
        return [(int(r[0], 16), dt.datetime.fromtimestamp(r[1], dt.timezone.utc), r[2])
                for r in rows]

    # ------------------------------------------------------------------ tokens
    def revoke_jti(self, jti: str, exp: float) -> bool:
        with self.lock:
            self._x("DELETE FROM revoked_tokens WHERE exp < ?", (self.clock(),))
            cur = self._x("INSERT OR IGNORE INTO revoked_tokens VALUES (?,?)", (jti, exp))
            return cur.rowcount == 1          # False => already used (single-use tokens)

    def is_jti_revoked(self, jti: str) -> bool:
        return self._x("SELECT 1 FROM revoked_tokens WHERE jti=?", (jti,)).fetchone() is not None

    # ------------------------------------------------------------------ counters
    def next_counter(self, name: str) -> int:
        with self.lock:
            self._x("INSERT OR IGNORE INTO counters VALUES (?, 1)", (name,))
            self._x("UPDATE counters SET value = value + 1 WHERE name=?", (name,))
            return self._x("SELECT value FROM counters WHERE name=?", (name,)).fetchone()[0]
