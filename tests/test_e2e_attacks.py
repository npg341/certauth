import datetime as dt
import socket
import ssl
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID

from certauth import pki
from conftest import HANDSHAKE_ERRORS


def rejected_reasons(env, timeout=2.0):
    import time
    deadline = time.time() + timeout
    while True:
        reasons = [e.get("reason") for e in env.audit_events() if e["event"].startswith("tls.")]
        if reasons or time.time() > deadline:
            return reasons
        time.sleep(0.02)


def test_full_passwordless_flow(env):
    ident, issued = env.enroll("alice", "laptop")
    c = env.cert_client(ident)
    status, login = c.login_cert()
    assert status == 200
    assert login["acr"] == "urn:certauth:acr:mtls" and "mtls" in login["amr"]
    assert login["tls"]["version"] == "TLSv1.3"
    if "verified_chain" in login["tls"]:
        assert login["tls"]["verified_chain"] == ["alice", "CertAuth Issuing CA 1", "CertAuth Root CA"]
    status, me = c.request("GET", "/me", token=login["access_token"])
    assert status == 200 and me["user"] == "alice" and me["device"] == "laptop"
    assert me["certificate"]["serial"] == issued["serial"]


def test_ed25519_device_key(env):
    ident, issued = env.enroll("alice", "yubikey-sim", key=ed25519.Ed25519PrivateKey.generate())
    assert issued["key_type"] == "Ed25519"
    assert env.cert_client(ident).login_cert()[0] == 200


def test_no_certificate_means_no_passwordless_login(env):
    status, body = env.client().login_cert()
    assert status == 401 and body["error"] == "client_certificate_required"


def test_logout_revokes_token(env):
    c = env.cert_client(env.enroll("alice")[0])
    tok = c.login_cert()[1]["access_token"]
    assert c.request("POST", "/logout", token=tok)[0] == 200
    assert c.request("GET", "/me", token=tok)[0] == 401


def test_totp_token_is_low_assurance_and_scoped(env):
    status, body = env.client().login_totp("alice", env.code("alice"))
    assert status == 200 and body["scope"] == ["enroll"]
    status, err = env.client().request("GET", "/me", token=body["access_token"])
    assert status == 403 and "insufficient_scope" in err["error"]


def test_totp_replay_rejected(env):
    code = env.code("alice")
    assert env.client().login_totp("alice", code)[0] == 200
    assert env.client().login_totp("alice", code)[0] == 401
    assert any(e.get("reason") == "replay" for e in env.audit_events())


def test_totp_replay_race_only_one_wins(env):
    code, results = env.code("alice"), []
    def go():
        results.append(env.client().login_totp("alice", code)[0])
    ts = [threading.Thread(target=go) for _ in range(10)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert results.count(200) == 1
    assert set(results) - {200} <= {401, 429}


def test_enroll_token_is_single_use(env):
    tok = env.totp_token("alice")
    key = ec.generate_private_key(ec.SECP256R1())
    csr = pki.pem(pki.make_csr(key)).decode()
    assert env.client().enroll(tok, csr, "laptop")[0] == 201
    status, body = env.client().enroll(tok, csr, "laptop-2")
    assert status == 401 and "already used" in body["error"]


def test_bruteforce_lockout_with_backoff(env):
    for _ in range(5):
        assert env.client().login_totp("alice", "000000")[0] == 401
    status, body = env.client().login_totp("alice", env.code("alice"))
    assert status == 429 and body["error"] == "account_temporarily_locked"
    env.clock.advance(body["retry_after"])
    assert env.client().login_totp("alice", env.code("alice"))[0] == 200


def test_no_user_enumeration(env):
    a = env.client().login_totp("alice", "123456")
    b = env.client().login_totp("mallory", "123456")
    assert a == b == (401, {"error": "invalid_credentials"})


def test_per_ip_rate_limit(make_env):
    env = make_env(ip_burst=3, ip_rate=0.0)
    codes = [env.client().login_totp("nobody", "111111")[0] for _ in range(5)]
    assert codes == [401, 401, 401, 429, 429]


def test_rogue_ca_certificate_rejected_at_handshake(env):
    rk, rc = pki.create_root_ca()
    ik, ic = pki.create_issuing_ca(rk, rc)
    key = ec.generate_private_key(ec.SECP256R1())
    cert = pki.issue_client_cert(ik, ic, key.public_key(), "alice", "evil")
    ident = env.save_identity("rogue", key, pki.pem(cert, ic))
    with pytest.raises(HANDSHAKE_ERRORS):
        env.cert_client(ident).login_cert()
    assert "unable to get local issuer certificate" in rejected_reasons(env)


def test_expired_certificate_rejected(env):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = pki.issue_client_cert(env.server.ca_key, env.server.ca_cert, key.public_key(), "alice", "old",
                                 not_before=pki.now() - dt.timedelta(days=40),
                                 not_after=pki.now() - dt.timedelta(days=1))
    ident = env.save_identity("expired", key, pki.pem(cert, env.server.ca_cert))
    with pytest.raises(HANDSHAKE_ERRORS):
        env.cert_client(ident).login_cert()
    assert "certificate has expired" in rejected_reasons(env)


def test_wrong_eku_rejected(env):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = pki.issue_client_cert(env.server.ca_key, env.server.ca_cert, key.public_key(), "alice", "srv",
                                 eku=(ExtendedKeyUsageOID.SERVER_AUTH,))
    ident = env.save_identity("eku", key, pki.pem(cert, env.server.ca_cert))
    try:
        status, body = env.cert_client(ident).login_cert()
        assert status == 401
    except HANDSHAKE_ERRORS:
        assert "unsuitable certificate purpose" in rejected_reasons(env)


def test_unenrolled_certificate_rejected(env):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = pki.issue_client_cert(env.server.ca_key, env.server.ca_cert, key.public_key(), "alice", "x")
    ident = env.save_identity("unenrolled", key, pki.pem(cert, env.server.ca_cert))
    status, body = env.cert_client(ident).login_cert()
    assert status == 401 and body["error"] == "certificate_not_enrolled"


def test_cert_without_matching_private_key_fails(env):
    ident, _ = env.enroll("alice")
    other = ec.generate_private_key(ec.SECP256R1())
    pki.write_key(ident[1], other)
    with pytest.raises((ssl.SSLError, ValueError)):
        env.cert_client(ident)


def test_csr_identity_fields_ignored(env):
    key = ec.generate_private_key(ec.SECP256R1())
    tok = env.totp_token("alice")
    status, body = env.client().enroll(tok, pki.pem(pki.make_csr(key, "admin")).decode(), "laptop")
    assert status == 201
    from cryptography import x509
    leaf = x509.load_pem_x509_certificates(body["certificate_chain"].encode())[0]
    assert pki.cert_common_name(leaf) == "alice"


def test_weak_csr_rejected(env):
    from cryptography.hazmat.primitives.asymmetric import rsa
    tok = env.totp_token("alice")
    csr = pki.pem(pki.make_csr(rsa.generate_private_key(65537, 2048))).decode()
    status, body = env.client().enroll(tok, csr, "old-laptop")
    assert status == 400 and "too weak" in body["detail"]


def test_revocation_takes_effect_at_tls_layer_immediately(env):
    ident, issued = env.enroll("alice", "phone")
    c = env.cert_client(ident)
    tok = c.login_cert()[1]["access_token"]
    status, body = c.request("POST", "/devices/revoke", {"serial": issued["serial"]}, tok)
    assert status == 200
    with pytest.raises(HANDSHAKE_ERRORS):
        env.cert_client(ident).login_cert()
    assert "certificate revoked" in rejected_reasons(env)
    from cryptography import x509
    status, der = env.client().request("GET", "/pki/crl")
    crl = x509.load_der_x509_crl(der)
    assert crl.get_revoked_certificate_by_serial_number(int(issued["serial"], 16)) is not None


def test_cannot_revoke_other_users_device(env):
    alice_ident, alice_cert = env.enroll("alice")
    bob = env.cert_client(env.enroll("bob")[0])
    tok = bob.login_cert()[1]["access_token"]
    status, _ = bob.request("POST", "/devices/revoke", {"serial": alice_cert["serial"]}, tok)
    assert status == 404
    assert env.cert_client(alice_ident).login_cert()[0] == 200


def test_device_limit(env):
    for i in range(5):
        env.enroll("alice", f"dev{i}")
    tok = env.totp_token("alice")
    key = ec.generate_private_key(ec.SECP256R1())
    status, body = env.client().enroll(tok, pki.pem(pki.make_csr(key)).decode(), "dev5")
    assert status == 403 and body["error"] == "device_limit_reached"


def test_stolen_token_useless_without_bound_certificate(env):
    alice = env.cert_client(env.enroll("alice")[0])
    bob = env.cert_client(env.enroll("bob")[0])
    stolen = alice.login_cert()[1]["access_token"]
    status, body = env.client().request("GET", "/me", token=stolen)
    assert status == 401 and "certificate-bound" in body["error"]
    status, body = bob.request("GET", "/me", token=stolen)
    assert status == 401 and "different certificate" in body["error"]


def test_expired_session_token(env):
    c = env.cert_client(env.enroll("alice")[0])
    tok = c.login_cert()[1]["access_token"]
    env.clock.advance(901)
    assert c.request("GET", "/me", token=tok) == (401, {"error": "token expired"})


def test_tls12_downgrade_refused(env):
    with pytest.raises(HANDSHAKE_ERRORS):
        env.client(min_tls=ssl.TLSVersion.TLSv1_2).request("GET", "/health")


def test_server_identity_verified_by_client(env):
    ctx = ssl.create_default_context()
    with pytest.raises(ssl.SSLCertVerificationError):
        with socket.create_connection(("127.0.0.1", env.port)) as s:
            ctx.wrap_socket(s, server_hostname="localhost")


def test_oversized_and_malformed_requests(env):
    ctx = ssl.create_default_context(cafile=str(env.ca))
    def raw(payload):
        with socket.create_connection(("127.0.0.1", env.port)) as s, \
             ctx.wrap_socket(s, server_hostname="localhost") as t:
            t.sendall(payload)
            return t.recv(4096).split(b"\r\n")[0]
    assert raw(b"POST /auth/totp HTTP/1.1\r\nContent-Length: 999999\r\n\r\n").endswith(b"413 Payload Too Large")
    assert raw(b"GARBAGE\r\n\r\n").endswith(b"400 Bad Request")
    assert raw(b"POST /auth/totp HTTP/1.1\r\nContent-Length: 5\r\n\r\n[1,2]").endswith(b"400 Bad Request")


def test_audit_trail_records_flow_and_verifies(env):
    from certauth.audit import AuditLog
    from certauth.crypto import derive, load_master_key
    ident, _ = env.enroll("alice")
    env.cert_client(ident).login_cert()
    env.client().login_totp("alice", "000000")
    events = [e["event"] for e in env.audit_events()]
    for expected in ("auth.totp_success", "enroll.issued", "auth.cert_success", "auth.totp_failure"):
        assert expected in events
    key = derive(load_master_key(env.dir / "master.key"), "audit-chain")
    assert AuditLog.verify(env.dir / "audit.log", key)[0]
