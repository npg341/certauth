"""Browser-based live demonstration of CertAuth.

    python web_demo.py            (in VS Code: open web_demo.py and press Run)
    python -m certauth.webdemo

Starts a real CertAuth mTLS server in the background, then serves a web page on
http://127.0.0.1:8080 that plays each demo scene against it with the real client.
Nothing is simulated: every check, verdict and log line on the page comes from a
real TLS 1.3 handshake and the server's own audit log.

DEMO ONLY: the page shows the current TOTP code (standing in for Alice's phone),
and both servers listen on 127.0.0.1 only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import shutil
import socket
import ssl
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from . import pki, totp
from .audit import AuditLog, _canon
from .client import CertAuthClient
from .crypto import create_master_key
from .server import AuthServer, Config
from .tokens import _b64d, thumbprint_b64

PAGE = Path(__file__).with_name("web") / "demo.html"
ROOT_PASS = b"web demo root passphrase"
MARKER = ".certauth-webdemo"
USER = "alice"


class SceneError(Exception):
    """A scene cannot run yet (e.g. an earlier scene is needed first)."""


def _port_free(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def _short(hexstr: str, n: int = 8) -> str:
    return f"{hexstr[:n]}…{hexstr[-4:]}"


def _date(d: dt.datetime) -> str:
    return d.strftime("%d %b %Y")


def _key_label(pub) -> str:
    kind = pki.check_public_key(pub)
    return {"EC secp256r1": "ECDSA P-256", "EC secp384r1": "ECDSA P-384"}.get(kind, kind)


def cert_card(cert: x509.Certificate) -> dict:
    """What the page shows on a certificate 'ID card'."""
    fp = pki.fingerprint(cert)
    return {
        "name": pki.cert_common_name(cert),
        "issuer": cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
        "serial": format(cert.serial_number, "x"),
        "serial_short": _short(format(cert.serial_number, "x")),
        "valid_from": _date(cert.not_valid_before_utc),
        "valid_until": _date(cert.not_valid_after_utc),
        "days": (cert.not_valid_after_utc - cert.not_valid_before_utc).days,
        "key": _key_label(cert.public_key()),
        "fingerprint": fp,
        "fingerprint_short": _short(fp, 12),
    }


def decode_token(token: str) -> dict:
    return json.loads(_b64d(token.split(".")[1]))


EVENT_TEXT = {
    "server.start": "Server started",
    "pki.crl_published": "Revocation list published",
    "admin.user_added": "Admin registered {user}",
    "auth.totp_success": "Code accepted for {user}",
    "auth.totp_failure": "Code rejected for {user}",
    "auth.totp_locked": "Login blocked: {user} is locked",
    "auth.totp_rate_limited": "Too many tries from one computer",
    "enroll.issued": "Certificate issued: {user}'s {device}",
    "auth.cert_success": "{user} logged in with certificate",
    "auth.cert_unknown": "Unknown certificate refused",
    "auth.cert_revoked": "Revoked certificate refused",
    "token.rejected": "Token refused",
    "tls.client_cert_rejected": "Handshake refused",
    "tls.handshake_failed": "Handshake failed",
    "admin.cert_revoked": "Admin revoked {user}'s certificate",
    "device.revoked": "{user} revoked a device",
    "auth.logout": "{user} logged out",
}


class Demo:
    def __init__(self, base: Path, tls_port: int):
        self.base = Path(base).resolve()
        self.want_port = tls_port
        self.lock = threading.RLock()
        self.server: AuthServer | None = None
        self.reset()

    def _fresh_dir(self) -> Path:
        if self.base.exists() and not (self.base / MARKER).exists() and any(self.base.iterdir()):
            raise SystemExit(f"{self.base} exists and is not a web-demo folder; choose another --data")
        self.base.mkdir(parents=True, exist_ok=True)
        (self.base / MARKER).write_text("created by certauth.webdemo; safe to delete\n")
        for old in self.base.glob("run-*"):
            shutil.rmtree(old, ignore_errors=True)
        run = self.base / f"run-{time.strftime('%Y%m%d-%H%M%S')}-{time.time_ns() % 10**6}"
        run.mkdir()
        return run

    def reset(self) -> None:
        with self.lock:
            if self.server:
                self.server.shutdown()
                try:
                    self.server.store.db.close()
                except Exception:
                    pass
            self.dir = self._fresh_dir()
            pki.init_pki(self.dir / "pki", ROOT_PASS)
            create_master_key(self.dir / "master.key")
            port = self.want_port if _port_free(self.want_port) else 0
            self.server = AuthServer(Config(self.dir, port=port))
            self.port = self.server.start()
            self.ca = self.server.paths.root_crt
            self.secret: str | None = None
            self.devices: dict[str, dict] = {}
            self.current: str | None = None
            self.enroll_code: str | None = None
            self.token: str | None = None
            self.tampered: dict | None = None

    def client(self, ident: dict | None = None) -> CertAuthClient:
        if ident:
            return CertAuthClient("localhost", self.port, self.ca, ident["crt"], ident["key"])
        return CertAuthClient("localhost", self.port, self.ca)

    @property
    def audit_path(self) -> Path:
        return self.dir / "audit.log"

    def events(self) -> list[dict]:
        if not self.audit_path.exists():
            return []
        out = []
        for line in self.audit_path.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({"event": "unreadable", "seq": None})
        return out

    def last_seq(self) -> int:
        ev = self.events()
        return ev[-1].get("seq") or 0 if ev else 0

    def wait_event(self, after: int, prefixes: tuple[str, ...], timeout: float = 3.0) -> dict | None:
        """The server writes its audit line in its own thread, a moment after the client
        sees the result; poll briefly for the event that explains what happened."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            for e in self.events():
                if (e.get("seq") or 0) > after and e.get("event", "").startswith(prefixes):
                    return e
            time.sleep(0.03)
        return None

    def cert_login(self, ident: dict) -> dict:
        """Attempt a passwordless login; report where it stopped and why."""
        before = self.last_seq()
        try:
            status, body = self.client(ident).login_cert()
            return {"handshake": True, "status": status, "body": body}
        except (ssl.SSLError, OSError) as e:
            ev = self.wait_event(before, ("tls.",))
            return {"handshake": False, "client_error": str(getattr(e, "reason", None) or e),
                    "server_reason": ev.get("reason") if ev else None}

    @staticmethod
    def handshake_checks(r: dict) -> tuple[dict, dict]:
        """Map a login attempt to the check rows shown on the page."""
        checks, notes = {}, {}
        if r["handshake"]:
            checks.update({"tls.ca": "pass", "tls.expiry": "pass", "tls.revoked": "pass", "tls.key": "pass"})
            err = r["body"].get("error") if isinstance(r["body"], dict) else None
            if r["status"] == 200:
                checks.update({"app.enrolled": "pass", "app.owner": "pass"})
            elif err == "certificate_not_enrolled":
                checks["app.enrolled"] = "fail"; notes["app.enrolled"] = "not on the register"
            elif err == "certificate_revoked":
                checks["app.enrolled"] = "fail"; notes["app.enrolled"] = "marked revoked"
            else:
                checks["app.enrolled"] = "pass"; checks["app.owner"] = "fail"; notes["app.owner"] = err
            return checks, notes
        reason = (r.get("server_reason") or r.get("client_error") or "").lower()
        if "revoked" in reason:
            checks.update({"tls.ca": "pass", "tls.expiry": "pass", "tls.revoked": "fail"})
            notes["tls.revoked"] = "OpenSSL: certificate revoked"
        elif "expired" in reason:
            checks.update({"tls.ca": "pass", "tls.expiry": "fail"})
            notes["tls.expiry"] = "OpenSSL: certificate has expired"
        else:
            checks["tls.ca"] = "fail"
            notes["tls.ca"] = f"OpenSSL: {r.get('server_reason') or r.get('client_error')}"
        return checks, notes

    def need(self, cond, message: str) -> None:
        if not cond:
            raise SceneError(message)

    def current_ident(self) -> dict:
        self.need(self.current, "Alice has no certificate yet. Run scene 3 first.")
        return self.devices[self.current]

    def phone(self) -> dict:
        if not self.secret:
            return {"ready": False}
        now = time.time()
        return {"ready": True, "account": f"CertAuth ({USER})",
                "code": totp.totp(totp.b32decode(self.secret), now),
                "remaining": 30 - int(now) % 30, "step": totp.time_step(now)}

    def qr_svg(self) -> bytes:
        self.need(self.secret, "Alice is not registered yet.")
        import qrcode
        import qrcode.image.svg
        img = qrcode.make(totp.provisioning_uri(self.secret, USER),
                          image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
        return img.to_string()

    def state(self) -> dict:
        events = self.events()
        ok, n, msg = AuditLog.verify(self.audit_path, self.server.audit.key) if events else (True, 0, "empty")
        root = pki.load_cert(self.server.paths.root_crt)
        return {
            "server": {"port": self.port, "tls": "TLS 1.3 only"},
            "root_fingerprint": _short(pki.fingerprint(root), 16),
            "registered": bool(self.secret),
            "current": self.current,
            "devices": {k: {**v["card"], "revoked": v["revoked"]} for k, v in self.devices.items()},
            "audit": {"ok": ok, "count": len(events), "message": msg,
                      "broken_line": None if ok else n,
                      "events": [self._event_row(e) for e in events[-8:]]},
        }

    @staticmethod
    def _event_row(e: dict) -> dict:
        tmpl = EVENT_TEXT.get(e.get("event", ""), e.get("event", "?"))
        try:
            text = tmpl.format(user=e.get("user", "?"), device=e.get("device", "device"))
        except (KeyError, IndexError):
            text = tmpl
        extra = e.get("reason") or (f"CRL #{e['crl_number']}" if "crl_number" in e else "")
        ts = dt.datetime.fromtimestamp(e.get("ts", 0)).strftime("%H:%M:%S") if e.get("ts") else ""
        return {"seq": e.get("seq"), "text": text, "extra": extra, "time": ts,
                "mac": (e.get("mac") or "")[:10], "event": e.get("event")}

    def scene_register(self, body: dict) -> dict:
        root = pki.load_cert(self.server.paths.root_crt)
        ica = pki.load_cert(self.server.paths.ca_crt)
        srv = x509.load_pem_x509_certificates(self.server.paths.server_chain.read_bytes())[0]
        if not self.secret:
            self.secret = totp.generate_secret()
            self.server.store.add_user(USER, self.secret)
            self.server.audit.log("admin.user_added", user=USER)
        return {
            "view": "setup",
            "verdict": {"kind": "done", "text": "Registered", "caption": "user alice"},
            "headline": "Alice is registered and her phone is set up",
            "plain": ("When the server started, it created its own certificate authority: an office "
                      "that signs digital ID cards. The admin then added Alice. Her phone received a "
                      "secret through the QR code, so it can now show a new 6-digit code every 30 seconds."),
            "pki": [
                {"role": "Root CA", "where": "Kept offline, key locked with a passphrase",
                 "does": "Signs only the Issuing CA", **cert_card(root)},
                {"role": "Issuing CA", "where": "Inside the server",
                 "does": "Signs device ID cards and the revocation list", **cert_card(ica)},
                {"role": "Server certificate", "where": "Shown to every visitor",
                 "does": "Proves this really is our server", **cert_card(srv)},
            ],
            "steps": ["Root CA created (ECDSA P-384)", "Issuing CA created and signed by the root",
                      "Server certificate issued for localhost",
                      "Alice added; TOTP secret encrypted with AES-256-GCM in the database",
                      "Secret delivered to Alice's phone as a QR code"],
            "details": [["Root CA fingerprint (SHA-256)", pki.fingerprint(root)],
                        ["Issuing CA valid until", _date(ica.not_valid_after_utc)],
                        ["Server address", f"https://localhost:{self.port}"],
                        ["TOTP settings", "HMAC-SHA1, 6 digits, 30-second step (RFC 6238)"]],
        }

    def scene_nocert(self, body: dict) -> dict:
        _, health = self.client().request("GET", "/health")
        status, resp = self.client().login_cert()
        return {
            "checks": {"tls.channel": "pass", "tls.server": "pass", "tls.card": "none",
                       "app.enrolled": "fail"},
            "notes": {"tls.card": "none shown", "app.enrolled": "nothing to look up"},
            "verdict": {"kind": "refused", "text": "Not let in", "caption": f"HTTP {status}"},
            "headline": "No ID card, no entry",
            "plain": ("The connection itself works: it is encrypted, and Alice's laptop checked that it "
                      "is talking to the real server. But Alice has no certificate yet, so the server "
                      "has nothing to recognise her by."),
            "details": [["TLS version", health["tls"]["version"]], ["Cipher", health["tls"]["cipher"]],
                        ["Client certificate sent", "No"], ["Server answer", f"{status} {resp.get('error')}"]],
            "raw": resp,
        }

    def _totp_attempt(self, client: CertAuthClient, code: str) -> tuple[int, dict, dict, dict]:
        before = self.last_seq()
        status, body = client.login_totp(USER, code)
        checks, notes = {"tls.channel": "pass", "tls.server": "pass"}, {}
        if status == 200:
            checks.update({"code.lock": "pass", "code.correct": "pass", "code.fresh": "pass"})
            return status, body, checks, notes
        ev = self.wait_event(before, ("auth.totp",)) or {}
        if body.get("error") == "rate_limited" or ev.get("event") == "auth.totp_rate_limited":
            checks["code.lock"] = "fail"; notes["code.lock"] = "too many tries from this computer"
        elif body.get("error") == "account_temporarily_locked":
            checks["code.lock"] = "fail"; notes["code.lock"] = f"locked for {body.get('retry_after')} s"
        elif ev.get("reason") == "replay":
            checks.update({"code.lock": "pass", "code.correct": "pass", "code.fresh": "fail"})
            notes["code.fresh"] = "this code was already used"
        else:
            checks.update({"code.lock": "pass", "code.correct": "fail"})
            notes["code.correct"] = "wrong or expired code"
        return status, body, checks, notes

    def _enroll(self, code: str, device: str) -> dict:
        self.need(self.secret, "Alice is not registered yet. Run scene 1 first.")
        code = "".join(ch for ch in str(code) if ch.isdigit())
        self.need(len(code) == 6, "Type the 6-digit code from Alice's phone first.")
        c = self.client()
        status, body, checks, notes = self._totp_attempt(c, code)
        if status != 200:
            why = next((notes[k] for k in ("code.lock", "code.fresh", "code.correct") if k in notes), "")
            return {"checks": checks, "notes": notes, "code": code,
                    "verdict": {"kind": "refused", "text": "Not let in", "caption": f"HTTP {status}"},
                    "headline": f"The code was refused: {why}",
                    "plain": ("Each code works once and only for about 30 seconds. "
                              "Wait for the phone to show a new code and try again."),
                    "details": [["Server answer", f"{status} {body.get('error')}"]], "raw": body}
        enroll_claims = decode_token(body["access_token"])
        key = ec.generate_private_key(ec.SECP256R1())
        csr = pki.make_csr(key, device)
        status2, res = c.enroll(body["access_token"], pki.pem(csr).decode(), device)
        self.need(status2 == 201, f"Enrollment failed: {res}")
        folder = self.dir / "devices" / device
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "device.crt").write_text(res["certificate_chain"])
        pki.write_key(folder / "device.key", key)
        leaf = x509.load_pem_x509_certificates(res["certificate_chain"].encode())[0]
        self.devices.pop(device, None)
        self.devices[device] = {"crt": folder / "device.crt", "key": folder / "device.key",
                                "card": {**cert_card(leaf), "device": device}, "revoked": False}
        self.current = device
        self.enroll_code = code
        card = self.devices[device]["card"]
        return {"checks": checks, "notes": notes, "code": code, "card": card,
                "steps": [f"Code {code} accepted: Alice gets a pass that can only enroll, once, "
                          f"within {enroll_claims['exp'] - enroll_claims['iat']} seconds",
                          "Her laptop creates its own key pair (ECDSA P-256); the private key never leaves it",
                          f"The laptop sends a certificate request with only the public key "
                          f"({len(pki.pem(csr))} bytes)",
                          f"The CA checks the request and signs a {card['days']}-day ID card for “alice”"],
                "details": [["Pass scope", ", ".join(enroll_claims["scope"])],
                            ["Pass is single-use", "Yes" if enroll_claims.get("one") else "No"],
                            ["Certificate serial", card["serial"]],
                            ["Fingerprint (SHA-256)", card["fingerprint"]],
                            ["Key type", card["key"]], ["Valid until", card["valid_until"]],
                            ["Private key file", f"devices/{device}/device.key (stays on the laptop)"]],
                "raw": {"enroll_pass": enroll_claims, "certificate": card}}

    def scene_enroll(self, body: dict) -> dict:
        r = self._enroll(body.get("code", ""), "laptop")
        if "card" in r:
            r.update(verdict={"kind": "issued", "text": "Card issued", "caption": "HTTP 201"},
                     headline="Alice's laptop now has its own digital ID card",
                     plain=("Alice typed the code once. Her laptop made a private key that never leaves "
                            "it, and the server's CA signed a certificate for it. From now on she will "
                            "never type a password or a code."))
        return r

    def scene_replay(self, body: dict) -> dict:
        self.need(self.enroll_code, "Alice has not used a code yet. Run scene 3 first.")
        code = self.enroll_code
        status, resp, checks, notes = self._totp_attempt(self.client(), code)
        stopped = status != 200
        return {"checks": checks, "notes": notes, "code": code,
                "verdict": {"kind": "stopped" if stopped else "admit",
                            "text": "Stopped" if stopped else "Let in", "caption": f"HTTP {status}"},
                "headline": ("Attack stopped: the stolen code was useless" if stopped
                             else "Unexpected: the code was accepted"),
                "plain": (f"Eve typed {code}, the exact code Alice used. The server remembers the last "
                          "time slot it accepted for Alice and refuses any code from that slot again, "
                          "even when it arrives in the same second."),
                "details": [["Code tried", code], ["Server answer", f"{status} {resp.get('error')}"],
                            ["Server's private reason (audit log)",
                             (notes.get("code.fresh") or notes.get("code.correct") or "")]],
                "raw": resp}

    def scene_login(self, body: dict) -> dict:
        ident = self.current_ident()
        r = self.cert_login(ident)
        checks, notes = self.handshake_checks(r)
        if not (r["handshake"] and r["status"] == 200):
            return {"checks": checks, "notes": notes,
                    "verdict": {"kind": "refused", "text": "Not let in",
                                "caption": "Handshake refused" if not r["handshake"] else f"HTTP {r['status']}"},
                    "headline": "This device can no longer log in",
                    "plain": "The certificate on this device was refused. Use scene 9 to recover.",
                    "raw": r}
        login = r["body"]
        self.token = login["access_token"]
        claims = decode_token(self.token)
        _, me = self.client(ident).request("GET", "/me", token=self.token)
        card = ident["card"]
        bound_ok = claims["cnf"]["x5t#S256"] == thumbprint_b64(card["fingerprint"])
        return {"checks": checks, "notes": notes,
                "verdict": {"kind": "admit", "text": "Let in", "caption": "HTTP 200"},
                "headline": "Alice is in, without typing anything",
                "plain": ("During the TLS handshake her laptop signed the conversation with its private "
                          "key. OpenSSL checked the ID card and the signature, then the server checked "
                          "that this laptop is on its register. Her login pass is locked to this "
                          "certificate."),
                "steps": [f"{login['tls']['version'].replace('TLSv', 'TLS ')} connection, cipher {login['tls']['cipher']}",
                          "Chain checked: " + " → ".join(login["tls"]["verified_chain"]),
                          f"Login pass issued for {login['expires_in'] // 60} minutes, "
                          f"bound to certificate {card['fingerprint_short']}"],
                "details": [["TLS version", login["tls"]["version"]], ["Cipher", login["tls"]["cipher"]],
                            ["Verified chain", " → ".join(login["tls"]["verified_chain"])],
                            ["Assurance level", claims["acr"]], ["Methods", ", ".join(claims["amr"])],
                            ["Pass bound to (cnf.x5t#S256)", claims["cnf"]["x5t#S256"]],
                            ["Matches this certificate", "Yes" if bound_ok else "No"],
                            ["Profile returned by /me", f"user {me.get('user')}, device {me.get('device')}"]],
                "raw": {"token_claims": claims, "me": me}}

    def scene_steal(self, body: dict) -> dict:
        self.need(self.token, "Alice has not logged in yet. Run scene 5 first.")
        status, resp = self.client().request("GET", "/me", token=self.token)
        err = resp.get("error", "") if isinstance(resp, dict) else ""
        checks = {"tls.channel": "pass", "tls.card": "none"}
        notes = {"tls.card": "Eve has no ID card"}
        if "expired" in err:
            checks.update({"tok.sig": "pass", "tok.exp": "fail"}); notes["tok.exp"] = "pass has expired"
        elif "signature" in err:
            checks["tok.sig"] = "fail"
        elif status != 200:
            checks.update({"tok.sig": "pass", "tok.exp": "pass", "tok.bound": "fail"})
            notes["tok.bound"] = "pass is locked to Alice's certificate"
        stopped = status != 200
        return {"checks": checks, "notes": notes,
                "verdict": {"kind": "stopped" if stopped else "admit",
                            "text": "Stopped" if stopped else "Let in", "caption": f"HTTP {status}"},
                "headline": "Attack stopped: the stolen pass only works on Alice's laptop",
                "plain": ("Eve copied Alice's login pass, for example from a log file or malware. The "
                          "pass is genuine and not expired, but it contains the fingerprint of Alice's "
                          "certificate. Eve cannot show that certificate's private key, so the pass is "
                          "worthless to her."),
                "details": [["Server answer", f"{status} {err}"],
                            ["Pass bound to", decode_token(self.token)["cnf"]["x5t#S256"]],
                            ["Certificate Eve showed", "none"]],
                "raw": resp}

    def scene_fake(self, body: dict) -> dict:
        rk, rc = pki.create_root_ca()
        ik, ic = pki.create_issuing_ca(rk, rc)
        key = ec.generate_private_key(ec.SECP256R1())
        fake = pki.issue_client_cert(ik, ic, key.public_key(), USER, "eve-fake")
        folder = self.dir / "devices" / "eve-fake"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "device.crt").write_bytes(pki.pem(fake, ic))
        pki.write_key(folder / "device.key", key)
        r = self.cert_login({"crt": folder / "device.crt", "key": folder / "device.key"})
        checks, notes = self.handshake_checks(r)
        real_root = pki.load_cert(self.server.paths.root_crt)
        stopped = not (r["handshake"] and r.get("status") == 200)
        return {"checks": checks, "notes": notes, "card": {**cert_card(fake), "device": "fake"},
                "verdict": {"kind": "stopped" if stopped else "admit",
                            "text": "Stopped" if stopped else "Let in",
                            "caption": "Handshake refused" if not r["handshake"] else f"HTTP {r.get('status')}"},
                "headline": "Attack stopped: the fake ID card was not signed by our CA",
                "plain": ("Eve built her own certificate authority and even copied our CA's names, then "
                          "made a card that says “alice”. The names look right, but the signature can only "
                          "be made with our CA's private key, which Eve does not have. OpenSSL refused "
                          "the card during the handshake."),
                "details": [["Name on fake card", f"{pki.cert_common_name(fake)} (issued by "
                                                  f"“{pki.cert_common_name(ic)}”)"],
                            ["Our root fingerprint", _short(pki.fingerprint(real_root), 16)],
                            ["Eve's root fingerprint", _short(pki.fingerprint(rc), 16)],
                            ["Server's reason (audit log)", r.get("server_reason") or r.get("client_error")]],
                "raw": r}

    def scene_revoke(self, body: dict) -> dict:
        ident = self.current_ident()
        card = ident["card"]
        if not ident["revoked"]:
            self.server.store.revoke_cert(card["serial"], "keyCompromise")
            self.server.regenerate_crl()
            self.server.audit.log("admin.cert_revoked", serial=card["serial"], user=USER,
                                  reason="keyCompromise")
            ident["revoked"] = True
        crl = x509.load_pem_x509_crl(self.server.paths.ca_crl.read_bytes())
        crl_no = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        r = self.cert_login(ident)
        checks, notes = self.handshake_checks(r)
        stopped = not (r["handshake"] and r.get("status") == 200)
        return {"checks": checks, "notes": notes,
                "verdict": {"kind": "stopped" if stopped else "admit",
                            "text": "Stopped" if stopped else "Let in",
                            "caption": "Handshake refused" if not r["handshake"] else f"HTTP {r.get('status')}"},
                "headline": "Attack stopped: the stolen laptop is locked out",
                "plain": ("Alice reported her laptop stolen and the admin revoked its certificate. The CA "
                          "signed a new revocation list, and the server loaded it immediately. When the "
                          "thief tried to log in, OpenSSL found the card on the list and ended the "
                          "handshake. No restart was needed."),
                "steps": [f"Admin revokes serial {card['serial_short']} (reason: key compromise)",
                          f"Issuing CA signs revocation list #{crl_no} ({len(crl)} revoked)",
                          "Server notices the new list and reloads its TLS settings",
                          "Thief connects with the real laptop, card and key"],
                "details": [["Revoked serial", card["serial"]], ["Revocation list number", str(crl_no)],
                            ["Server's reason (audit log)", r.get("server_reason") or r.get("client_error")]],
                "raw": r}

    def scene_recover(self, body: dict) -> dict:
        self.need(any(d["revoked"] for d in self.devices.values()),
                  "Nothing to recover from yet. Run scene 8 first.")
        r = self._enroll(body.get("code", ""), "new-laptop")
        if "card" not in r:
            return r
        login = self.cert_login(self.devices["new-laptop"])
        checks, notes = self.handshake_checks(login)
        r["checks"].update(checks)
        r["notes"].update(notes)
        ok = login["handshake"] and login["status"] == 200
        if ok:
            self.token = login["body"]["access_token"]
        r.update(verdict={"kind": "admit" if ok else "refused", "text": "Let in" if ok else "Not let in",
                          "caption": "HTTP 200" if ok else "refused"},
                 headline="Alice is back in with a new laptop",
                 plain=("Alice used a fresh code from her phone to enroll a new laptop. The code could do "
                        "only that one thing. The new laptop then logged in with its own certificate, "
                        "while the stolen one stays blocked."))
        r["steps"].append("New laptop logs in with its certificate: both gates pass")
        return r

    def scene_tamper(self, body: dict) -> dict:
        lines = self.audit_path.read_text(encoding="utf-8").splitlines()
        idx = next((i for i, l in enumerate(lines) if f'"user": "{USER}"' in l), None)
        self.need(idx is not None, "The audit log has no entry about Alice yet.")
        before = json.loads(lines[idx])
        lines[idx] = lines[idx].replace(f'"user": "{USER}"', '"user": "mallory"', 1)
        self.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        after = json.loads(lines[idx])
        stored = after.pop("mac")
        recomputed = hmac.new(self.server.audit.key, _canon(after), hashlib.sha256).hexdigest()
        ok, n, msg = AuditLog.verify(self.audit_path, self.server.audit.key)
        self.tampered = {"line": n}
        chain = [{"seq": i + 1, "state": "ok" if i + 1 < n else ("broken" if i + 1 == n else "after")}
                 for i in range(len(lines))]
        return {"view": "ledger",
                "verdict": {"kind": "stopped" if not ok else "admit",
                            "text": "Tampering detected" if not ok else "Not detected",
                            "caption": f"line {n}"},
                "headline": f"Caught: entry {n} of the audit log was changed",
                "plain": ("Someone changed one word in the log: “alice” became “mallory”, to hide who "
                          "logged in. Each entry carries a seal (an HMAC) made with a secret key over its "
                          "contents and the previous entry's seal. The seal no longer matches, so the "
                          "check points to the exact line."),
                "ledger": {"line": n, "message": msg, "chain": chain,
                           "before": {"seq": before.get("seq"), "event": before.get("event"), "user": USER},
                           "after": {"seq": before.get("seq"), "event": before.get("event"), "user": "mallory"},
                           "stored": stored[:16], "recomputed": recomputed[:16]},
                "details": [["Check result", msg], ["Seal stored in the line", stored],
                            ["Seal recomputed from the edited line", recomputed]],
                "raw": {"verify": [ok, n, msg]}}

    SCENES = {"register", "nocert", "enroll", "replay", "login", "steal", "fake",
              "revoke", "recover", "tamper"}

    def run(self, name: str, body: dict) -> dict:
        if name not in self.SCENES:
            raise SceneError(f"unknown scene {name!r}")
        with self.lock:
            result = getattr(self, f"scene_{name}")(body)
            result.setdefault("view", "pipeline")
            result.setdefault("checks", {})
            result.setdefault("notes", {})
            result.setdefault("steps", [])
            result.setdefault("details", [])
            result["ok"] = True
            return result


def make_handler(demo: Demo):
    class Handler(BaseHTTPRequestHandler):
        server_version = "CertAuthDemo/1.0"

        def log_message(self, *args):
            pass

        def _send(self, status: int, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = self.path.split("?")[0]
            try:
                if path in ("/", "/index.html"):
                    return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
                if path == "/api/state":
                    with demo.lock:
                        return self._send(200, demo.state())
                if path == "/api/phone":
                    return self._send(200, demo.phone())
                if path == "/api/qr.svg":
                    return self._send(200, demo.qr_svg(), "image/svg+xml")
                self._send(404, {"error": "not found"})
            except SceneError as e:
                self._send(409, {"ok": False, "error": str(e)})

        def do_POST(self):
            path = self.path.split("?")[0]
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}") if length else {}
            except json.JSONDecodeError:
                body = {}
            try:
                if path == "/api/reset":
                    demo.reset()
                    return self._send(200, {"ok": True})
                if path.startswith("/api/scene/"):
                    return self._send(200, demo.run(path.rsplit("/", 1)[1], body))
                self._send(404, {"error": "not found"})
            except SceneError as e:
                self._send(409, {"ok": False, "error": str(e)})
            except Exception as e:
                self._send(500, {"ok": False, "error": f"{type(e).__name__}: {e}"})

    return Handler


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="CertAuth browser demo")
    ap.add_argument("--port", type=int, default=8080, help="port for the demo web page")
    ap.add_argument("--tls-port", type=int, default=8443, help="port for the real mTLS server")
    ap.add_argument("--data", default=str(Path(__file__).resolve().parent.parent / "web-demo-data"))
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args(argv)
    demo = Demo(Path(a.data), a.tls_port)
    port = a.port
    while not _port_free(port) and port < a.port + 20:
        port += 1
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(demo))
    url = f"http://127.0.0.1:{port}/"
    print("CertAuth browser demo")
    print(f"  real mTLS server : https://localhost:{demo.port} (TLS 1.3, client certificates)")
    print(f"  demo page        : {url}")
    print("  press Ctrl+C to stop")
    if not a.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        demo.server.shutdown()


if __name__ == "__main__":
    main()
