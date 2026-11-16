#!/usr/bin/env bash
# End-to-end demonstration: PKI setup, TOTP enrollment, passwordless mTLS login,
# token-theft attempt, live revocation, and audit-log integrity check.
set -uo pipefail
cd "$(dirname "$0")"

export CERTAUTH_DATA="${CERTAUTH_DATA:-./demo-data}"
export CERTAUTH_ROOT_PASSPHRASE="${CERTAUTH_ROOT_PASSPHRASE:-demo root passphrase}"
export CERTAUTH_CA="$CERTAUTH_DATA/pki/root-ca.crt"
PORT=8443
ALICE="--profile $CERTAUTH_DATA/devices/alice-laptop --port $PORT"
EVE="--profile $CERTAUTH_DATA/devices/eve --port $PORT"

b() { printf '\n\033[1;36m━━ %s\033[0m\n' "$*"; }
run() { printf '\033[2m$ %s\033[0m\n' "$*"; "$@"; }

rm -rf "$CERTAUTH_DATA"
b "1. Build two-tier PKI (offline root → online issuing CA → server cert)"
run python3 -m certauth.admin init

b "2. Register user 'alice' (TOTP seed encrypted at rest with AES-256-GCM)"
run python3 -m certauth.admin add-user alice --no-qr

b "3. Start the hand-configured TLS 1.3 server"
python3 -m certauth.server --data "$CERTAUTH_DATA" --port $PORT > "$CERTAUTH_DATA/server.log" 2>&1 &
SRV=$!; trap 'kill $SRV 2>/dev/null' EXIT; sleep 1.5
echo "Inspecting the server with openssl s_client:"
echo | openssl s_client -brief -connect 127.0.0.1:$PORT -CAfile "$CERTAUTH_CA" -servername localhost 2>&1 \
  | grep -vE "^DONE|^$" | sed 's/^/  /' 

b "4. Without a certificate, passwordless login is refused"
run python3 -m certauth.client $ALICE login

b "5. Enroll a device: TOTP once → key generated locally → CSR → short-lived cert"
CODE=$(python3 -m certauth.admin totp-now alice)
run python3 -m certauth.client $ALICE enroll --user alice --device laptop --code "$CODE"

b "6. Replay the same TOTP code (attacker who shoulder-surfed it)"
run python3 -m certauth.client $EVE enroll --user alice --device evil --code "$CODE"

b "7. Passwordless login: identity proven by the TLS handshake itself"
run python3 -m certauth.client $ALICE me

b "8. Token theft: Eve replays Alice's bearer token without Alice's private key"
TOKEN=$(python3 - <<EOF
from certauth.client import CertAuthClient
c = CertAuthClient("localhost", $PORT, "$CERTAUTH_CA", "$CERTAUTH_DATA/devices/alice-laptop/device.crt", "$CERTAUTH_DATA/devices/alice-laptop/device.key")
print(c.login_cert()[1]["access_token"])
EOF
)
python3 - <<EOF
from certauth.client import CertAuthClient
print(CertAuthClient("localhost", $PORT, "$CERTAUTH_CA").request("GET", "/me", token="$TOKEN"))
EOF

b "9. Revoke the laptop (admin CLI) — server hot-reloads the CRL"
SERIAL=$(python3 -c "import sqlite3;print(sqlite3.connect('$CERTAUTH_DATA/certauth.db').execute('select serial from certificates').fetchone()[0])")
run python3 -m certauth.admin revoke "$SERIAL"
sleep 0.3
run python3 -m certauth.client $ALICE me

b "10. Verify the tamper-evident audit log, then tamper with it"
run python3 -m certauth.admin verify-audit
tail -n 4 "$CERTAUTH_DATA/audit.log" | python3 -c "import sys,json;[print(' ', (e:=json.loads(l))['seq'], e['event'], e.get('user',''), e.get('reason','')) for l in sys.stdin]"
sed -i '0,/"user": "alice"/s//"user": "mallory"/' "$CERTAUTH_DATA/audit.log"
run python3 -m certauth.admin verify-audit

b "Done."
