"""Session tokens with certificate binding (proof-of-possession).

Format:  v1.<base64url(JSON claims)>.<base64url(HMAC-SHA256)>

Tokens minted after mTLS carry `cnf: {"x5t#S256": <thumbprint>}` (RFC 8705 §3).
The resource handler compares that thumbprint to the certificate presented on the
*current* TLS connection, so a stolen token is useless without the device's private
key. TOTP-derived tokens cannot be bound to a key, so they are deliberately weak:
short-lived, single-use and limited to the `enroll` scope (step-up model)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

ACR_HIGH = "urn:certauth:acr:mtls"     # possession of a CA-issued device key
ACR_LOW = "urn:certauth:acr:otp"       # knowledge of a current TOTP code only


class TokenError(Exception):
    def __init__(self, message: str, status: int = 401):
        super().__init__(message)
        self.status = status


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def thumbprint_b64(fp_hex: str) -> str:
    return _b64e(bytes.fromhex(fp_hex))


class TokenService:
    def __init__(self, key: bytes, store, issuer: str = "certauth", clock=time.time):
        self.key, self.store, self.issuer, self.clock = key, store, issuer, clock

    def _sign(self, msg: str) -> str:
        return _b64e(hmac.new(self.key, msg.encode(), hashlib.sha256).digest())

    def issue(self, sub: str, *, amr: list[str], acr: str, scope: list[str], ttl: int,
              cert_fp: str | None = None, single_use: bool = False) -> tuple[str, dict]:
        now = int(self.clock())
        claims = {"iss": self.issuer, "sub": sub, "iat": now, "exp": now + ttl,
                  "jti": secrets.token_urlsafe(16), "amr": amr, "acr": acr, "scope": scope}
        if cert_fp:
            claims["cnf"] = {"x5t#S256": thumbprint_b64(cert_fp)}
        if single_use:
            claims["one"] = True
        body = "v1." + _b64e(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
        return f"{body}.{self._sign(body)}", claims

    def verify(self, token: str, presented_fp: str | None, scope: str | None = None) -> dict:
        try:
            ver, payload, sig = token.split(".")
        except ValueError:
            raise TokenError("malformed token")
        if ver != "v1":
            raise TokenError("unsupported token version")
        if not hmac.compare_digest(sig, self._sign(f"{ver}.{payload}")):
            raise TokenError("bad token signature")
        claims = json.loads(_b64d(payload))
        if claims.get("iss") != self.issuer:
            raise TokenError("wrong issuer")
        if self.clock() >= claims["exp"]:
            raise TokenError("token expired")
        if self.store.is_jti_revoked(claims["jti"]):
            raise TokenError("token revoked or already used")
        cnf = claims.get("cnf")
        if cnf:
            if presented_fp is None:
                raise TokenError("token is certificate-bound; present the bound client certificate")
            if not hmac.compare_digest(cnf["x5t#S256"], thumbprint_b64(presented_fp)):
                raise TokenError("token bound to a different certificate")
        if scope and scope not in claims["scope"]:
            raise TokenError(f"insufficient_scope: requires '{scope}'", status=403)
        return claims

    def revoke(self, claims: dict) -> bool:
        return self.store.revoke_jti(claims["jti"], claims["exp"])
