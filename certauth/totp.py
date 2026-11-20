from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse
from dataclasses import dataclass

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def generate_secret(nbytes: int = 20) -> str:
    return base64.b32encode(secrets.token_bytes(nbytes)).decode().rstrip("=")


def b32decode(secret: str) -> bytes:
    s = secret.upper().replace(" ", "")
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(key: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), ALGORITHMS[algorithm]).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % 10 ** digits).zfill(digits)


def time_step(t: float, period: int = 30, t0: int = 0) -> int:
    return int((t - t0) // period)


def totp(key: bytes, t: float | None = None, period: int = 30, digits: int = 6,
         algorithm: str = "SHA1") -> str:
    return hotp(key, time_step(time.time() if t is None else t, period), digits, algorithm)


@dataclass(frozen=True)
class TOTPResult:
    ok: bool
    step: int | None = None
    replay: bool = False


def verify(key: bytes, code: str, *, t: float | None = None, period: int = 30, digits: int = 6,
           algorithm: str = "SHA1", window: int = 1, last_step: int = -1) -> TOTPResult:
    t = time.time() if t is None else t
    code = (code or "").strip()
    well_formed = code.isdigit() and len(code) == digits
    probe = code if well_formed else "\0" * digits
    current = time_step(t, period)
    matched = None
    for offset in range(-window, window + 1):
        step = max(0, current + offset)
        if hmac.compare_digest(hotp(key, step, digits, algorithm), probe) and matched is None:
            matched = step
    if not well_formed or matched is None:
        return TOTPResult(False)
    if matched <= last_step:
        return TOTPResult(False, matched, replay=True)
    return TOTPResult(True, matched)


def provisioning_uri(secret: str, account: str, issuer: str = "CertAuth") -> str:
    label = urllib.parse.quote(f"{issuer}:{account}")
    q = urllib.parse.urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1",
                                "digits": 6, "period": 30})
    return f"otpauth://totp/{label}?{q}"
