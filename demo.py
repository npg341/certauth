from __future__ import annotations

import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "demo-data"


def pick_port(preferred: int = 8443) -> int:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            pass
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


PORT = pick_port()
os.environ.update(CERTAUTH_DATA=str(DATA), CERTAUTH_ROOT_PASSPHRASE="demo root passphrase",
                  CERTAUTH_CA=str(DATA / "pki" / "root-ca.crt"), PYTHONIOENCODING="utf-8")
sys.path.insert(0, str(ROOT))
if os.name == "nt":
    os.system("")

CYAN, DIM, RESET = "\033[1;36m", "\033[2m", "\033[0m"
ALICE = ["--profile", str(DATA / "devices" / "alice-laptop"), "--port", str(PORT)]
EVE = ["--profile", str(DATA / "devices" / "eve"), "--port", str(PORT)]


def banner(text):
    print(f"\n{CYAN}━━ {text}{RESET}", flush=True)


def run(module, *args, capture=False):
    cmd = [sys.executable, "-m", module, *args]
    print(f"{DIM}$ python -m {module} {' '.join(args)}{RESET}", flush=True)
    r = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=capture, encoding="utf-8")
    return r.stdout.strip() if capture else r.returncode


def quiet(module, *args):
    return subprocess.run([sys.executable, "-m", module, *args], cwd=ROOT, text=True,
                          capture_output=True, encoding="utf-8").stdout.strip()


def wait_for_server(server, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if server.poll() is not None:
            sys.exit(f"server stopped:\n{(DATA / 'server.log').read_text(errors='replace')}")
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.2)
    sys.exit(f"server did not start — see {DATA / 'server.log'}")


def main():
    shutil.rmtree(DATA, ignore_errors=True)

    banner("1. Build two-tier PKI (offline root → online issuing CA → server cert)")
    run("certauth.admin", "init")

    banner("2. Register user 'alice' (TOTP seed encrypted at rest with AES-256-GCM)")
    run("certauth.admin", "add-user", "alice")

    banner("3. Start the hand-configured TLS 1.3 server")
    if PORT != 8443:
        print(f"  port 8443 is busy (is web_demo.py still running?), using port {PORT} instead")
    log = open(DATA / "server.log", "w")
    server = subprocess.Popen([sys.executable, "-m", "certauth.server", "--data", str(DATA),
                               "--port", str(PORT)], cwd=ROOT, stdout=log, stderr=log)
    try:
        wait_for_server(server)
        from certauth.client import CertAuthClient
        status, health = CertAuthClient("localhost", PORT, os.environ["CERTAUTH_CA"]).request("GET", "/health")
        print(f"  server up: {health['tls']['version']}  {health['tls']['cipher']}")

        banner("4. Without a certificate, passwordless login is refused")
        run("certauth.client", *ALICE, "login")

        banner("5. Enroll a device: TOTP once → key generated locally → CSR → short-lived cert")
        code = quiet("certauth.admin", "totp-now", "alice")
        print(f"  (authenticator app shows: {code})")
        run("certauth.client", *ALICE, "enroll", "--user", "alice", "--device", "laptop", "--code", code)

        banner("6. Replay the same TOTP code (attacker who shoulder-surfed it)")
        run("certauth.client", *EVE, "enroll", "--user", "alice", "--device", "evil", "--code", code)

        banner("7. Passwordless login: identity proven by the TLS handshake itself")
        run("certauth.client", *ALICE, "me")

        banner("8. Token theft: Eve replays Alice's bearer token without Alice's private key")
        prof = DATA / "devices" / "alice-laptop"
        alice = CertAuthClient("localhost", PORT, os.environ["CERTAUTH_CA"], prof / "device.crt", prof / "device.key")
        token = alice.login_cert()[1]["access_token"]
        eve = CertAuthClient("localhost", PORT, os.environ["CERTAUTH_CA"])
        print(" ", eve.request("GET", "/me", token=token))

        banner("9. Revoke the laptop (admin CLI) — server hot-reloads the CRL")
        serial = sqlite3.connect(DATA / "certauth.db").execute(
            "SELECT serial FROM certificates").fetchone()[0]
        run("certauth.admin", "revoke", serial)
        time.sleep(0.5)
        run("certauth.client", *ALICE, "me")

        banner("10. Verify the tamper-evident audit log, then tamper with it")
        run("certauth.admin", "verify-audit")
        lines = (DATA / "audit.log").read_text(encoding="utf-8").splitlines()
        for line in lines[-4:]:
            e = json.loads(line)
            print(f"   {e['seq']:>3} {e['event']:<26} {e.get('user', '')} {e.get('reason', '')}")
        print("  …editing one entry (alice → mallory)…")
        idx = next(i for i, l in enumerate(lines) if '"user": "alice"' in l)
        lines[idx] = lines[idx].replace('"user": "alice"', '"user": "mallory"')
        (DATA / "audit.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
        run("certauth.admin", "verify-audit")
        banner("Done.")
    finally:
        server.terminate()
        server.wait(5)
        log.close()


if __name__ == "__main__":
    main()
