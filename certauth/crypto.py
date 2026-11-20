from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def create_master_key(path: Path) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(os.urandom(32))


def load_master_key(path: Path) -> bytes:
    key = Path(path).read_bytes()
    if len(key) != 32:
        raise ValueError("master key must be 32 bytes")
    return key


def derive(master: bytes, purpose: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"certauth-v1",
                info=purpose.encode()).derive(master)


class SecretBox:
    def __init__(self, key: bytes):
        self._aead = AESGCM(key)

    def seal(self, plaintext: bytes, aad: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, aad)

    def open(self, blob: bytes, aad: bytes) -> bytes:
        return self._aead.decrypt(blob[:12], blob[12:], aad)
