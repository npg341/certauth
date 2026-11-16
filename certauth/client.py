"""CertAuth client library + CLI.

The device key pair is generated locally (P-256 by default) and written with 0600
permissions, optionally passphrase-encrypted. Only the CSR is sent to the server.

    python -m certauth.client enroll --user alice --device laptop      # TOTP once
    python -m certauth.client me                                       # passwordless from now on
    python -m certauth.client devices
    python -m certauth.client revoke <serial>
"""
from __future__ import annotations

import argparse
import getpass
import http.client
import json
import os
import ssl
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from . import pki


class CertAuthClient:
    def __init__(self, host: str, port: int, ca_file, cert_file=None, key_file=None,
                 key_password: bytes | None = None, min_tls=ssl.TLSVersion.TLSv1_3):
        self.host, self.port = host, port
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_file))
        ctx.minimum_version = min_tls
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        if min_tls < ssl.TLSVersion.TLSv1_3:
            ctx.maximum_version = min_tls  # used by tests to simulate a downgrade attempt
        if cert_file:
            ctx.load_cert_chain(str(cert_file), str(key_file), password=key_password)
        self.ctx = ctx

    def request(self, method: str, path: str, body: dict | None = None, token: str | None = None):
        # Connect straight to 127.0.0.1 for "localhost": on Windows, "localhost" tries IPv6
        # (::1) first and waits ~2 s before falling back. The server cert has an IP SAN for
        # 127.0.0.1, so hostname verification still applies.
        host = "127.0.0.1" if self.host == "localhost" else self.host
        conn = http.client.HTTPSConnection(host, self.port, context=self.ctx, timeout=10)
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            conn.request(method, path, body=json.dumps(body) if body is not None else None,
                         headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            ctype = resp.getheader("Content-Type", "")
            return resp.status, (json.loads(raw) if "json" in ctype else raw)
        finally:
            conn.close()

    # convenience wrappers
    def login_cert(self):
        return self.request("POST", "/auth/cert")

    def login_totp(self, username: str, code: str):
        return self.request("POST", "/auth/totp", {"username": username, "code": code})

    def enroll(self, token: str, csr_pem: str, device: str):
        return self.request("POST", "/enroll", {"csr": csr_pem, "device": device}, token)


# ============================================================================ CLI
def _profile(args) -> Path:
    p = Path(args.profile).expanduser()
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p


def _client(args, with_cert=True) -> CertAuthClient:
    prof = _profile(args)
    cert, key = prof / "device.crt", prof / "device.key"
    pw = os.environ.get("CERTAUTH_KEY_PASSPHRASE")
    if with_cert and cert.exists():
        return CertAuthClient(args.host, args.port, args.ca, cert, key, pw.encode() if pw else None)
    return CertAuthClient(args.host, args.port, args.ca)


def _show(status, body):
    print(f"HTTP {status}")
    print(json.dumps(body, indent=2) if isinstance(body, (dict, list)) else body)
    return 0 if status < 400 else 1


def cmd_enroll(args) -> int:
    prof = _profile(args)
    code = args.code or input("TOTP code from your authenticator: ").strip()
    c = _client(args, with_cert=False)
    status, body = c.login_totp(args.user, code)
    if status != 200:
        return _show(status, body)
    print(f"[+] TOTP accepted — got a single-use '{body['scope'][0]}' token ({body['acr']})")
    key = ed25519.Ed25519PrivateKey.generate() if args.ed25519 else ec.generate_private_key(ec.SECP256R1())
    print(f"[+] generated device key locally ({'Ed25519' if args.ed25519 else 'EC P-256'}); "
          "private key never leaves this machine")
    csr = pki.make_csr(key, args.device)
    status, res = c.enroll(body["access_token"], pki.pem(csr).decode(), args.device)
    if status != 201:
        return _show(status, res)
    pw = os.environ.get("CERTAUTH_KEY_PASSPHRASE")
    pki.write_key(prof / "device.key", key, pw.encode() if pw else None)
    (prof / "device.crt").write_text(res["certificate_chain"])
    print(f"[+] certificate issued: serial {res['serial']}, expires {res['not_after']}")
    print(f"[+] SHA-256 fingerprint {res['fingerprint_sha256']}")
    print(f"[+] saved to {prof}/device.crt and device.key (0600)")
    return 0


def cmd_login(args) -> int:
    return _show(*_client(args).login_cert())


def _with_token(args, method, path, body=None) -> int:
    c = _client(args)
    status, login = c.login_cert()
    if status != 200:
        return _show(status, login)
    return _show(*c.request(method, path, body, login["access_token"]))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="certauth-client")
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--ca", default=os.environ.get("CERTAUTH_CA", "./data/pki/root-ca.crt"),
                    help="root CA certificate used to authenticate the server")
    ap.add_argument("--profile", default=os.environ.get("CERTAUTH_PROFILE", "~/.certauth"),
                    help="directory holding this device's key + certificate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll", help="use TOTP once to obtain a device certificate")
    e.add_argument("--user", required=True)
    e.add_argument("--device", required=True)
    e.add_argument("--code")
    e.add_argument("--ed25519", action="store_true")
    sub.add_parser("login", help="passwordless login with the device certificate")
    sub.add_parser("me")
    sub.add_parser("devices")
    r = sub.add_parser("revoke")
    r.add_argument("serial")
    sub.add_parser("logout")
    args = ap.parse_args(argv)
    try:
        return _dispatch(args)
    except (ssl.SSLError, ConnectionError) as e:
        # Linux delivers the server's TLS alert (e.g. certificate_revoked); Windows often
        # only reports a connection reset. Either way, diagnose from public PKI data.
        reason = getattr(e, "reason", None) or e.__class__.__name__
        print(f"TLS handshake refused by server ({reason})")
        print(diagnose_certificate(args))
        return 1


def diagnose_certificate(args) -> str:
    """Explain a rejected handshake by checking our own certificate against the
    server's published CRL (fetched over an anonymous, server-authenticated TLS link)."""
    import datetime as dt
    from cryptography import x509
    crt = _profile(args) / "device.crt"
    if not crt.exists():
        return "no device certificate in this profile — run 'enroll' first"
    leaf = x509.load_pem_x509_certificates(crt.read_bytes())[0]
    if leaf.not_valid_after_utc < dt.datetime.now(dt.timezone.utc):
        return "this device certificate has EXPIRED — re-enroll with TOTP"
    try:
        status, der = _client(args, with_cert=False).request("GET", "/pki/crl")
        crl = x509.load_der_x509_crl(der)
    except Exception as e:
        return f"could not fetch the CRL to diagnose ({e})"
    entry = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    if entry is not None:
        return (f"this device certificate (serial {leaf.serial_number:x}) is REVOKED in CRL "
                f"#{crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number} "
                f"since {entry.revocation_date_utc:%Y-%m-%d %H:%M} UTC — re-enroll with TOTP")
    return "certificate is not revoked or expired — it may not be issued by this server's CA"


def _dispatch(args) -> int:
    if args.cmd == "enroll":
        return cmd_enroll(args)
    if args.cmd == "login":
        return cmd_login(args)
    if args.cmd == "me":
        return _with_token(args, "GET", "/me")
    if args.cmd == "devices":
        return _with_token(args, "GET", "/devices")
    if args.cmd == "revoke":
        return _with_token(args, "POST", "/devices/revoke", {"serial": args.serial})
    if args.cmd == "logout":
        return _with_token(args, "POST", "/logout")
    return 2


if __name__ == "__main__":
    sys.exit(main())
