# Security Design & Threat Model

## 1. Security goals

1. **G1 — Phishing-resistant, passwordless authentication.** A user is authenticated by
   proving possession of a device private key inside the TLS handshake
   (`CertificateVerify` signs the handshake transcript, so the proof is bound to this
   specific connection and cannot be relayed to a different server).
2. **G2 — Recoverability without weakening G1.** Losing every device must not lock a user
   out forever, but the recovery channel (TOTP) must not become a backdoor equivalent to
   the primary factor.
3. **G3 — Revocation that actually takes effect.** A compromised device must stop working
   at the next connection, not at the next restart or token expiry.
4. **G4 — Accountability.** Security-relevant events are recorded in a log whose
   tampering is detectable.

## 2. Assets

| Asset | Where | Protection |
|---|---|---|
| Root CA key | `pki/root-ca.key` | PKCS#8, encrypted with PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC); never loaded by the server; intended to be moved offline after `init` |
| Issuing CA key | `pki/issuing-ca.key` | file mode 0600; compromise is contained — root can revoke the issuing CA via the root CRL |
| Device private keys | user devices | generated on-device, 0600, optional passphrase; never transmitted |
| TOTP seeds | SQLite | AES-256-GCM, key from HKDF(master, "totp-at-rest"), AAD = username |
| Token / audit keys | derived | HKDF(master, "token-signing"), HKDF(master, "audit-chain") — compromise of one purpose does not reveal another's key |

## 3. Trust boundaries

```
 [ device ] ──TLS 1.3──▶ [ OpenSSL handshake ] ──▶ [ app policy ] ──▶ [ DB / CA key / audit ]
   untrusted              boundary 1: crypto          boundary 2: authorisation
```

Boundary 1 (OpenSSL) answers *"is this a genuine, current, unrevoked certificate from my
CA for TLS client use, and does the peer hold its key?"*. Boundary 2 (application)
answers *"is this certificate one I actually enrolled, for this user, still active?"*.
Keeping both means a mis-issued certificate (e.g. CA key misuse, a bug in issuance)
still cannot log anyone in — it is not in the enrollment table.

## 4. STRIDE analysis

| Threat | Example attack | Mitigation | Test |
|---|---|---|---|
| **S**poofing | Attacker runs own CA, mints `CN=alice` | Trust store contains only our root; `X509_STRICT` | `test_rogue_ca_certificate_rejected_at_handshake` |
| Spoofing | Attacker obtains Alice's certificate (public) | TLS 1.3 `CertificateVerify` requires the private key | `test_cert_without_matching_private_key_fails` |
| Spoofing | Request `CN=admin` in CSR | Server sets subject from authenticated identity, ignores CSR names | `test_csr_identity_fields_ignored` |
| Spoofing | Brute-force 6-digit TOTP (10⁶ space) | 5 tries → lock, backoff 30 s · 2ⁿ (≤ 1 h); per-IP token bucket | `test_bruteforce_lockout_with_backoff`, `test_per_ip_rate_limit` |
| Spoofing | Phish / shoulder-surf a TOTP code and replay it | Per-user last-step stored; atomic CAS `UPDATE … WHERE last_step < ?` | `test_totp_replay_rejected`, `test_totp_replay_race_only_one_wins` |
| **T**ampering | Edit token claims (`sub`, `scope`) | HMAC-SHA256, constant-time compare | `test_token_tamper_detected` |
| Tampering | Rewrite audit history | Keyed chain (HMAC with `prev`), sequence numbers | `test_audit_*` |
| Tampering | Swap encrypted TOTP seeds between DB rows | AEAD with username as AAD | `test_totp_seed_encrypted_and_bound_to_user` |
| **R**epudiation | User denies having logged in | Audit records serial, fingerprint, device, IP, `jti` | `test_audit_trail_records_flow_and_verifies` |
| **I**nformation disclosure | Probe which usernames exist | Identical error body; dummy TOTP work for unknown users | `test_no_user_enumeration` |
| Information disclosure | Network eavesdropping | TLS 1.3 only (AEAD, forward secrecy via (EC)DHE) | `test_tls12_downgrade_refused` |
| **D**enial of service | Flood connections / huge bodies | Bounded connection semaphore, 10 s socket timeout, header 16 KiB / body 64 KiB caps | `test_oversized_and_malformed_requests` |
| **E**levation of privilege | Use TOTP session to read profile / revoke devices | TOTP → `scope=[enroll]`, single-use; revoke requires `acr=mtls` | `test_totp_token_is_low_assurance_and_scoped` |
| Elevation of privilege | Steal bearer token from logs / memory | RFC 8705 `cnf` binding to certificate thumbprint | `test_stolen_token_useless_without_bound_certificate` |
| Elevation of privilege | Revoke someone else's device | Ownership check on serial | `test_cannot_revoke_other_users_device` |

## 5. Key design decisions

**Why `CERT_OPTIONAL` rather than `CERT_REQUIRED`?** The TOTP fallback must be reachable
by a device that has no certificate yet. With `CERT_OPTIONAL`, a client that *does*
present a certificate is still fully verified by OpenSSL (a bad certificate aborts the
handshake); only its absence is tolerated, and the application then restricts what an
anonymous connection may do.

**Why two layers of revocation (CRL + DB)?** The CRL is the standards-based mechanism
OpenSSL enforces in the handshake and that external relying parties can consume
(`/pki/crl`). The DB flag is checked on every request as defence in depth, covering the
window between a DB change and the CRL being re-signed.

**Why short-lived client certificates (30 days)?** They bound the damage of a lost device
that nobody remembers to revoke, and keep CRLs small. Renewal is just a new enrollment
from an existing mTLS session (which already has `enroll` scope).

**Why does the TOTP fallback only allow enrollment?** TOTP is a shared secret (it can be
phished in real time); NIST SP 800-63B does not consider it phishing-resistant. Making
the TOTP session single-use and enrollment-only means a phished code yields at most one
new device certificate — which appears in the user's device list, is audited, and can
be revoked — rather than general account access.

**Why derive all keys from one master key with HKDF?** Operationally there is one secret
to protect/rotate, while cryptographically each purpose (encryption, token MAC, audit
MAC) gets an independent key, preventing cross-protocol misuse.

## 6. Known limitations and future work

- **Software keys.** Device keys live in files (`amr=swk`). In production they belong in
  a TPM, Secure Enclave, smart card or FIDO2 authenticator (PKCS#11), which would raise
  the assurance to NIST AAL3 (`amr=hwk`).
- **Online issuing CA.** The server holds the issuing CA key so it can enroll devices.
  An HSM or a separate, narrowly-scoped signing service would reduce exposure.
- **TOTP seed is server-side.** Unlike public-key credentials, a full DB + master-key
  compromise reveals the seeds. Moving the master key into a KMS/HSM mitigates this.
- **Audit log truncation.** Removing the *last* N entries cannot be detected by the chain
  alone; periodically anchoring the latest MAC externally (e.g. WORM storage, a
  transparency log, or emailing it) closes this gap.
- **No OCSP / OCSP stapling.** CRLs are fine for a single relying party; a larger
  deployment would add OCSP.
- **Single-process state.** Rate-limiter buckets are in memory; a multi-node deployment
  would move them (and the DB) to shared storage such as Redis/PostgreSQL.
- **TLS exporter binding.** Python's `ssl` module does not expose RFC 5705 keying-material
  export, so TOTP sessions cannot be channel-bound; they are compensated for with a
  5-minute TTL and single use.
