from __future__ import annotations

import argparse
import datetime as dt
import getpass
import os
import sys
from pathlib import Path

from . import pki, totp
from .audit import AuditLog
from .crypto import SecretBox, create_master_key, derive, load_master_key
from .store import Store


def _store(d: Path) -> Store:
    return Store(d / "certauth.db", SecretBox(derive(load_master_key(d / "master.key"), "totp-at-rest")))


def _root_pass(confirm=False) -> bytes:
    env = os.environ.get("CERTAUTH_ROOT_PASSPHRASE")
    if env:
        return env.encode()
    p = getpass.getpass("Root CA key passphrase: ")
    if confirm and p != getpass.getpass("Confirm: "):
        sys.exit("passphrases differ")
    if len(p) < 12:
        sys.exit("passphrase must be at least 12 characters")
    return p.encode()


def _audit(d: Path) -> AuditLog:
    return AuditLog(d / "audit.log", derive(load_master_key(d / "master.key"), "audit-chain"))


def cmd_init(d: Path, args) -> None:
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    paths = pki.init_pki(d / "pki", _root_pass(confirm=True), tuple(args.hostname))
    create_master_key(d / "master.key")
    _store(d)
    _audit(d).log("admin.init", hostnames=args.hostname)
    root = pki.load_cert(paths.root_crt)
    print(f"[+] Root CA      {root.subject.rfc4514_string()}  (key encrypted, keep offline)")
    print(f"[+] Issuing CA   {pki.load_cert(paths.ca_crt).subject.rfc4514_string()}")
    print(f"[+] Server cert  SAN={args.hostname} + 127.0.0.1, ::1")
    print(f"[+] Root fingerprint (distribute out-of-band): {pki.fingerprint(root)}")
    print(f"[+] Data directory: {d}")


def cmd_add_user(d: Path, args) -> None:
    secret = totp.generate_secret()
    _store(d).add_user(args.username, secret)
    _audit(d).log("admin.user_added", user=args.username)
    uri = totp.provisioning_uri(secret, args.username)
    print(f"[+] user '{args.username}' created")
    print(f"[+] TOTP secret (shown once): {secret}")
    print(f"[+] provisioning URI: {uri}")
    if args.no_qr:
        return
    try:
        import qrcode
        qr = qrcode.QRCode(border=1)
        qr.add_data(uri)
        qr.print_ascii(invert=True)
        print("    scan with Google Authenticator / Aegis / 1Password / Authy")
    except ImportError:
        print("    (pip install qrcode to render a scannable QR here)")


def cmd_list(d: Path, args) -> None:
    s = _store(d)
    for u in s.list_users():
        print(f"{u}")
        for c in s.list_certs(u):
            state = "REVOKED" if c.revoked else ("expired" if c.not_after < dt.datetime.now().timestamp() else "active")
            exp = dt.datetime.fromtimestamp(c.not_after).strftime("%Y-%m-%d")
            print(f"   {state:8} serial={c.serial[:16]}…  device={c.device!r:14} {c.key_type:16} expires {exp}")


def cmd_revoke(d: Path, args) -> None:
    s = _store(d)
    rec = s.cert_by_serial(args.serial)
    if not rec:
        sys.exit("no such certificate")
    if not s.revoke_cert(args.serial, args.reason):
        sys.exit("already revoked")
    paths = pki.PKIPaths(d / "pki")
    n = s.next_counter("issuing_crl_number")
    crl = pki.build_crl(pki.load_key(paths.ca_key), pki.load_cert(paths.ca_crt),
                        s.revoked_serials(), number=n, valid_for=dt.timedelta(days=7))
    pki.write_pem(paths.ca_crl, crl)
    _audit(d).log("admin.cert_revoked", serial=rec.serial, user=rec.username, reason=args.reason,
                  crl_number=n)
    print(f"[+] revoked {rec.serial} ({rec.username}/{rec.device}); CRL #{n} published")


def cmd_verify_audit(d: Path, args) -> None:
    ok, n, msg = AuditLog.verify(d / "audit.log", derive(load_master_key(d / "master.key"), "audit-chain"))
    print(("[OK] " if ok else "[TAMPERED] ") + msg)
    sys.exit(0 if ok else 1)


def cmd_totp_now(d: Path, args) -> None:
    u = _store(d).get_user(args.username)
    print(totp.totp(totp.b32decode(u.totp_secret)))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="certauth-admin")
    ap.add_argument("--data", default=os.environ.get("CERTAUTH_DATA", "./data"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init")
    i.add_argument("--hostname", action="append", default=None)
    a = sub.add_parser("add-user")
    a.add_argument("username")
    a.add_argument("--no-qr", action="store_true")
    sub.add_parser("list")
    r = sub.add_parser("revoke")
    r.add_argument("serial")
    r.add_argument("--reason", default="keyCompromise",
                   choices=["unspecified", "keyCompromise", "affiliationChanged", "superseded",
                            "cessationOfOperation"])
    sub.add_parser("verify-audit")
    t = sub.add_parser("totp-now", help="DEV ONLY: print the current TOTP code for a user")
    t.add_argument("username")
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=8443)
    s.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args(argv)
    d = Path(args.data)
    if args.cmd == "init":
        args.hostname = args.hostname or ["localhost"]
    if args.cmd == "serve":
        from .server import main as serve
        return serve(["--data", str(d), "--port", str(args.port), "--host", args.host])
    {"init": cmd_init, "add-user": cmd_add_user, "list": cmd_list, "revoke": cmd_revoke,
     "verify-audit": cmd_verify_audit, "totp-now": cmd_totp_now}[args.cmd](d, args)


if __name__ == "__main__":
    main()
