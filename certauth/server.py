"""Authentication server: hand-configured TLS 1.3 with optional client certificates.

No web framework and no TLS terminator — the server owns the `ssl.SSLContext`, does
the handshake itself on raw sockets and parses HTTP/1.1 directly, so every security
decision (trust anchors, revocation, EKU, key binding) is visible in this file.

Two-layer client-certificate validation
  1. TLS layer (OpenSSL): chain to our root only, X509_STRICT, CRL check on the
     whole chain, validity period, EKU/purpose = TLS client.
  2. App layer: certificate must be *enrolled* (fingerprint known), not revoked in
     the DB, and its CN must match the enrolled owner.

Endpoints
  GET  /health
  GET  /pki/ca  /pki/crl           public PKI material
  POST /auth/cert                  passwordless login via the presented certificate
  POST /auth/totp                  fallback: TOTP -> short-lived single-use enroll token
  POST /enroll                     CSR -> device certificate (needs scope 'enroll')
  GET  /me                         profile (needs certificate-bound token)
  GET  /devices                    list own devices
  POST /devices/revoke             revoke one of own devices (CRL regenerated live)
  POST /logout                     revoke current token
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from . import pki, totp
from .audit import AuditLog
from .crypto import SecretBox, derive, load_master_key
from .store import Store
from .tokens import ACR_HIGH, ACR_LOW, TokenError, TokenService

log = logging.getLogger("certauth")

MAX_HEADER = 16 * 1024
MAX_BODY = 64 * 1024
MAX_DEVICES = 5
STATUS_TEXT = {200: "OK", 201: "Created", 400: "Bad Request", 401: "Unauthorized",
               403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
               413: "Payload Too Large", 429: "Too Many Requests", 500: "Internal Server Error"}


class HTTPError(Exception):
    def __init__(self, status: int, error: str, **extra):
        super().__init__(error)
        self.status, self.error, self.extra = status, error, extra


@dataclass
class Config:
    data_dir: Path
    host: str = "127.0.0.1"
    port: int = 8443
    max_connections: int = 64
    cert_ttl: int = 900
    totp_ttl: int = 300
    client_cert_days: int = 30
    totp_window: int = 1
    ip_rate: float = 0.2
    ip_burst: int = 10
    clock: object = field(default=time.time)


class TokenBucket:
    def __init__(self, rate: float, burst: int, clock):
        self.rate, self.burst, self.clock = rate, burst, clock
        self.state: dict[str, tuple[float, float]] = {}
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        with self.lock:
            now = self.clock()
            tokens, last = self.state.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            ok = tokens >= 1
            self.state[key] = (tokens - 1 if ok else tokens, now)
            return ok


@dataclass
class Request:
    method: str
    path: str
    headers: dict
    body: bytes
    ip: str
    cert: x509.Certificate | None
    cert_fp: str | None
    tls: dict

    def json(self) -> dict:
        try:
            data = json.loads(self.body or b"{}")
        except json.JSONDecodeError:
            raise HTTPError(400, "invalid_json")
        if not isinstance(data, dict):
            raise HTTPError(400, "invalid_json")
        return data

    def bearer(self) -> str:
        auth = self.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise HTTPError(401, "missing_token")
        return auth[7:].strip()


class AuthServer:
    def __init__(self, config: Config):
        self.cfg = config
        d = Path(config.data_dir)
        self.paths = pki.PKIPaths(d / "pki")
        master = load_master_key(d / "master.key")
        clock = config.clock
        self.clock = lambda: clock()
        self.store = Store(d / "certauth.db", SecretBox(derive(master, "totp-at-rest")), clock=self.clock)
        self.tokens = TokenService(derive(master, "token-signing"), self.store, clock=self.clock)
        self.audit = AuditLog(d / "audit.log", derive(master, "audit-chain"), clock=self.clock)
        self.ip_limiter = TokenBucket(config.ip_rate, config.ip_burst, self.clock)
        self.ca_key = pki.load_key(self.paths.ca_key)
        self.ca_cert = pki.load_cert(self.paths.ca_crt)
        self._ctx_lock = threading.Lock()
        self._crl_mtime = None
        self._ctx: ssl.SSLContext | None = None
        self._slots = threading.BoundedSemaphore(config.max_connections)
        self._stop = threading.Event()
        self.sock: socket.socket | None = None
        self.regenerate_crl()
        self.routes = {
            ("GET", "/health"): self.h_health,
            ("GET", "/pki/ca"): self.h_ca,
            ("GET", "/pki/crl"): self.h_crl,
            ("POST", "/auth/cert"): self.h_auth_cert,
            ("POST", "/auth/totp"): self.h_auth_totp,
            ("POST", "/enroll"): self.h_enroll,
            ("GET", "/me"): self.h_me,
            ("GET", "/devices"): self.h_devices,
            ("POST", "/devices/revoke"): self.h_revoke,
            ("POST", "/logout"): self.h_logout,
        }

    def build_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.options |= ssl.OP_NO_TICKET | ssl.OP_NO_COMPRESSION | ssl.OP_NO_RENEGOTIATION
        ctx.load_cert_chain(self.paths.server_chain, self.paths.server_key)
        ctx.load_verify_locations(cafile=str(self.paths.root_crt))
        ctx.load_verify_locations(cafile=str(self.paths.root_crl))
        ctx.load_verify_locations(cafile=str(self.paths.ca_crl))
        ctx.verify_flags = (ssl.VERIFY_X509_STRICT | ssl.VERIFY_CRL_CHECK_CHAIN
                            | ssl.VERIFY_X509_TRUSTED_FIRST)
        ctx.verify_mode = ssl.CERT_OPTIONAL
        ctx.set_alpn_protocols(["http/1.1"])
        return ctx

    def context(self) -> ssl.SSLContext:
        """Return the current context, hot-reloading it if the CRL file changed
        (e.g. revocation via the admin CLI while the server is running)."""
        mtime = self.paths.ca_crl.stat().st_mtime_ns
        with self._ctx_lock:
            if self._ctx is None or mtime != self._crl_mtime:
                self._ctx, self._crl_mtime = self.build_context(), mtime
                log.info("TLS context (re)built")
            return self._ctx

    def regenerate_crl(self) -> None:
        number = self.store.next_counter("issuing_crl_number")
        crl = pki.build_crl(self.ca_key, self.ca_cert, self.store.revoked_serials(),
                            number=number, valid_for=dt.timedelta(days=7))
        pki.write_pem(self.paths.ca_crl, crl)
        with self._ctx_lock:
            self._crl_mtime = None
        self.audit.log("pki.crl_published", crl_number=number, revoked=len(crl))

    def start(self) -> int:
        self.sock = socket.create_server((self.cfg.host, self.cfg.port), backlog=128)
        self.sock.settimeout(0.5)
        self.cfg.port = self.sock.getsockname()[1]
        self.context()
        self.audit.log("server.start", port=self.cfg.port)
        threading.Thread(target=self._accept_loop, daemon=True, name="accept").start()
        threading.Thread(target=self._crl_refresher, daemon=True, name="crl").start()
        return self.cfg.port

    def serve_forever(self) -> None:
        self.start()
        try:
            while not self._stop.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        self._stop.set()
        if self.sock:
            self.sock.close()

    def _crl_refresher(self) -> None:
        while not self._stop.wait(3600):
            try:
                crl = x509.load_pem_x509_crl(self.paths.ca_crl.read_bytes())
                if crl.next_update_utc - pki.now() < dt.timedelta(days=2):
                    self.regenerate_crl()
            except Exception:
                log.exception("CRL refresh failed")

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                raw, addr = self.sock.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            if not self._slots.acquire(blocking=False):
                raw.close()
                continue
            threading.Thread(target=self._handle, args=(raw, addr), daemon=True).start()

    def _handle(self, raw: socket.socket, addr) -> None:
        ip = addr[0]
        try:
            raw.settimeout(10)
            try:
                conn = self.context().wrap_socket(raw, server_side=True)
            except ssl.SSLCertVerificationError as e:
                self.audit.log("tls.client_cert_rejected", ip=ip, reason=e.verify_message,
                               code=e.verify_code)
                return
            except (ssl.SSLError, OSError) as e:
                self.audit.log("tls.handshake_failed", ip=ip, reason=getattr(e, "reason", None) or str(e))
                return
            with conn:
                self._serve_one(conn, ip)
        finally:
            self._slots.release()
            try:
                raw.close()
            except OSError:
                pass

    def _serve_one(self, conn: ssl.SSLSocket, ip: str) -> None:
        der = conn.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der) if der else None
        tls = {"version": conn.version(), "cipher": conn.cipher()[0],
               "client_cert": bool(cert)}
        if cert and hasattr(conn, "get_verified_chain"):
            tls["verified_chain"] = [pki.cert_common_name(x509.load_der_x509_certificate(c))
                                     for c in conn.get_verified_chain()]
        try:
            req = self._read_request(conn, ip, cert, tls)
        except HTTPError as e:
            return self._send(conn, e.status, {"error": e.error})
        except (OSError, ValueError):
            return
        try:
            handler = self.routes.get((req.method, req.path))
            if not handler:
                if any(p == req.path for _, p in self.routes):
                    raise HTTPError(405, "method_not_allowed")
                raise HTTPError(404, "not_found")
            status, body, *rest = handler(req)
            self._send(conn, status, body, *(rest or []))
        except HTTPError as e:
            self._send(conn, e.status, {"error": e.error, **e.extra})
        except TokenError as e:
            self.audit.log("token.rejected", ip=ip, path=req.path, reason=str(e))
            self._send(conn, e.status, {"error": str(e)})
        except Exception:
            log.exception("handler crashed")
            self._send(conn, 500, {"error": "internal_error"})

    def _read_request(self, conn, ip, cert, tls) -> Request:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                raise ValueError("client closed")
            buf += chunk
            if len(buf) > MAX_HEADER:
                raise HTTPError(413, "headers_too_large")
        head, body = buf.split(b"\r\n\r\n", 1)
        lines = head.decode("iso-8859-1").split("\r\n")
        try:
            method, target, _ = lines[0].split(" ", 2)
        except ValueError:
            raise HTTPError(400, "bad_request_line")
        headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length", "0") or 0)
        if length < 0 or length > MAX_BODY:
            raise HTTPError(413, "body_too_large")
        while len(body) < length:
            chunk = conn.recv(min(65536, length - len(body)))
            if not chunk:
                raise ValueError("truncated body")
            body += chunk
        return Request(method, target.split("?", 1)[0], headers, body[:length], ip, cert,
                       pki.fingerprint(cert) if cert else None, tls)

    def _send(self, conn, status: int, body, content_type: str = "application/json") -> None:
        data = body if isinstance(body, bytes) else (json.dumps(body, indent=2) + "\n").encode()
        head = (f"HTTP/1.1 {status} {STATUS_TEXT.get(status, '')}\r\n"
                f"Content-Type: {content_type}\r\nContent-Length: {len(data)}\r\n"
                "Connection: close\r\nCache-Control: no-store\r\n"
                "Strict-Transport-Security: max-age=63072000\r\n"
                "X-Content-Type-Options: nosniff\r\n\r\n")
        try:
            conn.sendall(head.encode() + data)
        except OSError:
            pass

    def _require_enrolled_cert(self, req: Request):
        """App-layer checks on top of what OpenSSL already verified."""
        if not req.cert:
            raise HTTPError(401, "client_certificate_required",
                            hint="present your device certificate, or use /auth/totp to enroll")
        try:
            eku = req.cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
                raise HTTPError(401, "certificate_not_for_client_auth")
        except x509.ExtensionNotFound:
            raise HTTPError(401, "certificate_not_for_client_auth")
        rec = self.store.cert_by_fingerprint(req.cert_fp)
        if rec is None:
            self.audit.log("auth.cert_unknown", ip=req.ip, fp=req.cert_fp,
                           cn=pki.cert_common_name(req.cert))
            raise HTTPError(401, "certificate_not_enrolled")
        if rec.revoked:
            self.audit.log("auth.cert_revoked", ip=req.ip, serial=rec.serial, user=rec.username)
            raise HTTPError(401, "certificate_revoked")
        if pki.cert_common_name(req.cert) != rec.username:
            raise HTTPError(401, "certificate_identity_mismatch")
        return rec

    def _auth(self, req: Request, scope: str) -> dict:
        claims = self.tokens.verify(req.bearer(), req.cert_fp, scope)
        if req.cert_fp:
            rec = self.store.cert_by_fingerprint(req.cert_fp)
            if rec and rec.revoked:
                raise TokenError("certificate revoked")
        return claims

    def h_health(self, req):
        return 200, {"status": "ok", "tls": req.tls}

    def h_ca(self, req):
        return 200, self.paths.root_crt.read_bytes(), "application/x-pem-file"

    def h_crl(self, req):
        crl = x509.load_pem_x509_crl(self.paths.ca_crl.read_bytes())
        return 200, crl.public_bytes(serialization.Encoding.DER), "application/pkix-crl"

    def h_auth_cert(self, req):
        rec = self._require_enrolled_cert(req)
        token, claims = self.tokens.issue(
            rec.username, amr=["mtls", "swk"], acr=ACR_HIGH,
            scope=["profile", "devices", "enroll"], ttl=self.cfg.cert_ttl, cert_fp=req.cert_fp)
        self.audit.log("auth.cert_success", ip=req.ip, user=rec.username, serial=rec.serial,
                       device=rec.device, jti=claims["jti"])
        return 200, {"access_token": token, "token_type": "Bearer", "expires_in": self.cfg.cert_ttl,
                     "acr": claims["acr"], "amr": claims["amr"], "cnf": claims["cnf"],
                     "user": rec.username, "device": rec.device, "tls": req.tls}

    def h_auth_totp(self, req):
        if not self.ip_limiter.allow(req.ip):
            self.audit.log("auth.totp_rate_limited", ip=req.ip)
            raise HTTPError(429, "rate_limited")
        data = req.json()
        username, code = str(data.get("username", "")), str(data.get("code", ""))
        user = self.store.get_user(username)
        now = self.clock()
        if user and user.locked_until > now:
            self.audit.log("auth.totp_locked", ip=req.ip, user=username)
            raise HTTPError(429, "account_temporarily_locked",
                            retry_after=int(user.locked_until - now) + 1)
        if user is None:
            totp.verify(b"\0" * 20, code, t=now, window=self.cfg.totp_window)
            self.audit.log("auth.totp_failure", ip=req.ip, user=username, reason="unknown_user")
            raise HTTPError(401, "invalid_credentials")
        result = totp.verify(totp.b32decode(user.totp_secret), code, t=now,
                             window=self.cfg.totp_window, last_step=user.totp_last_step)
        if result.ok and self.store.consume_totp_step(username, result.step):
            token, claims = self.tokens.issue(username, amr=["otp"], acr=ACR_LOW, scope=["enroll"],
                                              ttl=self.cfg.totp_ttl, single_use=True)
            self.audit.log("auth.totp_success", ip=req.ip, user=username, step=result.step,
                           jti=claims["jti"])
            return 200, {"access_token": token, "token_type": "Bearer",
                         "expires_in": self.cfg.totp_ttl, "acr": ACR_LOW, "scope": ["enroll"],
                         "note": "fallback session: single-use, may only enroll a device certificate"}
        locked = self.store.record_failure(username)
        self.audit.log("auth.totp_failure", ip=req.ip, user=username,
                       reason="replay" if (result.replay or result.ok) else "bad_code",
                       locked=bool(locked))
        raise HTTPError(401, "invalid_credentials")

    def h_enroll(self, req):
        claims = self._auth(req, "enroll")
        data = req.json()
        device = str(data.get("device", "")).strip()
        try:
            csr = x509.load_pem_x509_csr(str(data.get("csr", "")).encode())
            key_type = pki.validate_csr(csr)
            if not pki.DEVICE_RE.match(device):
                raise pki.PKIError("invalid device name")
        except (ValueError, pki.PKIError) as e:
            self.audit.log("enroll.rejected", ip=req.ip, user=claims["sub"], reason=str(e))
            raise HTTPError(400, "invalid_csr", detail=str(e))
        if self.store.active_cert_count(claims["sub"]) >= MAX_DEVICES:
            raise HTTPError(403, "device_limit_reached")
        if claims.get("one") and not self.tokens.revoke(claims):
            raise TokenError("token revoked or already used")
        cert = pki.issue_client_cert(self.ca_key, self.ca_cert, csr.public_key(), claims["sub"],
                                     device, days=self.cfg.client_cert_days,
                                     crl_url=f"https://localhost:{self.cfg.port}/pki/crl")
        fp = pki.fingerprint(cert)
        self.store.add_cert(cert.serial_number, claims["sub"], device, fp, key_type,
                            cert.not_valid_after_utc)
        self.audit.log("enroll.issued", ip=req.ip, user=claims["sub"], device=device,
                       serial=format(cert.serial_number, "x"), fp=fp, via=claims["amr"],
                       key_type=key_type)
        return 201, {"certificate_chain": pki.pem(cert, self.ca_cert).decode(),
                     "serial": format(cert.serial_number, "x"), "fingerprint_sha256": fp,
                     "not_after": cert.not_valid_after_utc.isoformat(), "key_type": key_type}

    def h_me(self, req):
        claims = self._auth(req, "profile")
        rec = self.store.cert_by_fingerprint(req.cert_fp)
        return 200, {"user": claims["sub"], "acr": claims["acr"], "amr": claims["amr"],
                     "token_expires_in": int(claims["exp"] - self.clock()),
                     "device": rec.device if rec else None,
                     "certificate": {"serial": rec.serial, "subject": req.cert.subject.rfc4514_string(),
                                     "issuer": req.cert.issuer.rfc4514_string(),
                                     "not_after": req.cert.not_valid_after_utc.isoformat(),
                                     "fingerprint_sha256": req.cert_fp} if rec else None,
                     "tls": req.tls}

    def h_devices(self, req):
        claims = self._auth(req, "devices")
        return 200, {"devices": [{
            "serial": c.serial, "device": c.device, "key_type": c.key_type,
            "issued_at": dt.datetime.fromtimestamp(c.issued_at, dt.timezone.utc).isoformat(),
            "not_after": dt.datetime.fromtimestamp(c.not_after, dt.timezone.utc).isoformat(),
            "revoked": c.revoked, "current": c.fingerprint == req.cert_fp}
            for c in self.store.list_certs(claims["sub"])]}

    def h_revoke(self, req):
        claims = self._auth(req, "devices")
        if claims["acr"] != ACR_HIGH:
            raise HTTPError(403, "step_up_required")
        serial = str(req.json().get("serial", "")).lower()
        rec = self.store.cert_by_serial(serial)
        if not rec or rec.username != claims["sub"]:
            raise HTTPError(404, "no_such_device")
        if not self.store.revoke_cert(serial, "keyCompromise"):
            raise HTTPError(400, "already_revoked")
        self.regenerate_crl()
        if rec.fingerprint == req.cert_fp:
            self.tokens.revoke(claims)
        self.audit.log("device.revoked", ip=req.ip, user=claims["sub"], serial=serial,
                       device=rec.device)
        return 200, {"revoked": serial, "device": rec.device}

    def h_logout(self, req):
        claims = self.tokens.verify(req.bearer(), req.cert_fp)
        self.tokens.revoke(claims)
        self.audit.log("auth.logout", ip=req.ip, user=claims["sub"], jti=claims["jti"])
        return 200, {"logged_out": True}


def main(argv=None):
    ap = argparse.ArgumentParser(description="CertAuth mTLS server")
    ap.add_argument("--data", default=os.environ.get("CERTAUTH_DATA", "./data"))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    srv = AuthServer(Config(Path(a.data), a.host, a.port))
    print(f"CertAuth listening on https://{a.host}:{a.port}  (TLS 1.3, client certs optional)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
