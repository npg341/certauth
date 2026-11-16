# Running CertAuth in VS Code (Windows)

## 1. One-time setup

1. Install **Python 3.13** from https://www.python.org/downloads/ (tick **"Add python.exe to PATH"**).
   Python 3.10+ works; 3.13 also shows the verified certificate chain.
2. Unzip `certauth.zip`, then in VS Code: **File → Open Folder… → `certauth`**.
3. Accept the prompt to install the recommended extensions (Python, Python Debugger).
4. **Terminal → Run Task… → "Setup: create venv + install dependencies"**.
5. `Ctrl+Shift+P` → **Python: Select Interpreter** → choose `.venv`.

> If PowerShell blocks the venv with "running scripts is disabled", run once:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

## 2. Run the demo (fastest way to see everything)

Open **Run and Debug** (`Ctrl+Shift+D`) → choose **"▶ Demo: full walkthrough"** → **F5**.

Or in the terminal: `python demo.py`

## 3. Run the tests

Click the **beaker icon** (Testing) in the left bar → ▶ Run All. All 56 tests appear
grouped by file, and each one can be run or debugged on its own.

## 4. Use it step by step (the way you'd present it)

Run these from the **Run and Debug** dropdown, in order:

| # | Configuration | What happens |
|---|---|---|
| 1 | Admin: init PKI | asks for a root-key passphrase (≥ 12 chars), builds the CA hierarchy in `data/` |
| 2 | Admin: add user | prints a **QR code** — scan it with Google Authenticator / Microsoft Authenticator on your phone |
| 3 | Server: start | leave this running (it gets its own terminal) |
| 4 | Client: enroll device | asks for the 6-digit code from your phone, then saves a device certificate |
| 5 | Client: passwordless login → /me | logs in with **no password and no code** |
| 6 | Client: list my devices | shows serials |
| 7 | Admin: revoke a certificate | paste a serial; run #5 again → refused at the TLS handshake |
| 8 | Admin: verify audit log | checks the HMAC chain |

## 5. Debugging tip that impresses

Set a breakpoint in `certauth/server.py` inside `_serve_one`, on the line
`der = conn.getpeercert(binary_form=True)`, start **"3. Server"**, then run **"5. Client"**.
VS Code pauses right after the TLS handshake — hover over `conn` to show the negotiated
TLS version and cipher, and step one line to inspect the client certificate the server
just verified.

## Troubleshooting

| Problem | Fix |
|---|---|
| `Address already in use` / port 8443 busy | stop the other server (trash-can icon on its terminal) |
| `PKI already initialised` | delete the `data` folder and run step 1 again |
| `invalid_credentials` on enroll | the code changes every 30 s and each code works once — wait for the next one; check the PC clock is synced |
| QR code looks garbled | widen the terminal panel; the TOTP secret is printed above it for manual entry |
