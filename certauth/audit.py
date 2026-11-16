"""Tamper-evident audit log.

Each JSON line carries `prev` (the MAC of the previous line) and `mac` =
HMAC-SHA256(audit_key, canonical_json(entry_without_mac)). Editing, deleting,
inserting or reordering any line breaks the chain. Because the chain is keyed,
an attacker with write access to the file but not the key cannot forge a new
consistent chain (a plain hash chain could simply be recomputed)."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path

GENESIS = "0" * 64

# Cross-process exclusive lock (server and admin CLI write the same chain).
if os.name == "nt":                                   # Windows
    import msvcrt

    # Windows byte-range locks are mandatory: locking real content would block readers
    # (e.g. verify-audit). Lock one byte far beyond EOF instead — writers still serialise
    # on it, readers are never blocked.
    _LOCK_OFFSET = 1 << 30                          # 1 GiB: within the CRT's 32-bit _locking range

    def _lock(f):
        f.seek(_LOCK_OFFSET)
        while True:
            try:
                msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
                return
            except OSError:                           # LK_LOCK gives up after ~10s; retry
                time.sleep(0.05)

    def _unlock(f):
        f.seek(_LOCK_OFFSET)
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
else:                                                 # Linux / macOS
    import fcntl

    def _lock(f):
        fcntl.flock(f, fcntl.LOCK_EX)

    def _unlock(f):
        fcntl.flock(f, fcntl.LOCK_UN)


def _canon(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()


class AuditLog:
    def __init__(self, path: Path, key: bytes, clock=time.time):
        self.path, self.key, self.clock = Path(path), key, clock
        self.lock = threading.Lock()

    @staticmethod
    def _tail(f) -> tuple[str, int]:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size == 0:
            return GENESIS, 0
        f.seek(max(0, size - 8192))
        last = json.loads(f.read().splitlines()[-1])
        return last["mac"], last["seq"]

    def log(self, event: str, **fields) -> None:
        # Thread lock + exclusive file lock: the server and the admin CLI are separate
        # processes writing the same chain, so the tail must be re-read under the lock.
        with self.lock, self.path.open("a+b") as f:
            _lock(f)
            try:
                prev, seq = self._tail(f)
                entry = {"seq": seq + 1, "ts": round(self.clock(), 3), "event": event,
                         "prev": prev, **fields}
                entry["mac"] = hmac.new(self.key, _canon(entry), hashlib.sha256).hexdigest()
                f.write((json.dumps(entry, sort_keys=True) + "\n").encode())
                f.flush()
                os.fsync(f.fileno())
            finally:
                _unlock(f)

    @staticmethod
    def verify(path: Path, key: bytes) -> tuple[bool, int, str]:
        prev, n = GENESIS, 0
        for n, line in enumerate(Path(path).read_text(encoding='utf-8').splitlines(), 1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False, n, f"line {n}: not valid JSON"
            mac = entry.pop("mac", "")
            if entry.get("seq") != n:
                return False, n, f"line {n}: sequence gap (expected {n}, got {entry.get('seq')})"
            if entry.get("prev") != prev:
                return False, n, f"line {n}: chain broken (prev mismatch)"
            if not hmac.compare_digest(mac, hmac.new(key, _canon(entry), hashlib.sha256).hexdigest()):
                return False, n, f"line {n}: MAC invalid (entry modified)"
            prev = mac
        return True, n, f"{n} entries, chain intact"
