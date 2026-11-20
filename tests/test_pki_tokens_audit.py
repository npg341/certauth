import datetime as dt
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.verification import PolicyBuilder, Store as TrustStore

from certauth import pki
from certauth.audit import AuditLog
from certauth.crypto import SecretBox, derive
from certauth.store import Store
from certauth.tokens import TokenError, TokenService


@pytest.fixture(scope="module")
def ca():
    rk, rc = pki.create_root_ca()
    ik, ic = pki.create_issuing_ca(rk, rc)
    return rk, rc, ik, ic


def test_chain_validates_with_independent_verifier(ca):
    """Verify issued certs with cryptography's Rust RFC 5280 path validator,
    independently of OpenSSL."""
    rk, rc, ik, ic = ca
    _, srv = pki.create_server_cert(ik, ic)
    verifier = PolicyBuilder().store(TrustStore([rc])).build_server_verifier(x509.DNSName("localhost"))
    chain = verifier.verify(srv, [ic])
    assert [c.subject for c in chain] == [srv.subject, ic.subject, rc.subject]


def test_client_cert_profile(ca):
    _, _, ik, ic = ca
    cert = pki.issue_client_cert(ik, ic, ec.generate_private_key(ec.SECP256R1()).public_key(),
                                 "alice", "laptop")
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert pki.cert_common_name(cert) == "alice"
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days <= 31
    verifier = PolicyBuilder().store(TrustStore([ca[1]])).build_client_verifier()
    assert verifier.verify(cert, [ic]).chain[-1] == ca[1]


def test_csr_with_forged_signature_rejected():
    k1, k2 = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    good = pki.make_csr(k1).tbs_certrequest_bytes
    forged = (x509.CertificateSigningRequestBuilder().subject_name(pki.make_name("x"))
              .sign(k1, hashes.SHA256()))
    assert forged.is_signature_valid and good
    raw = bytearray(forged.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER))
    raw[-5] ^= 0xFF
    with pytest.raises((pki.PKIError, ValueError)):
        pki.validate_csr(x509.load_der_x509_csr(bytes(raw)))


def test_weak_keys_rejected():
    with pytest.raises(pki.PKIError, match="too weak"):
        pki.validate_csr(pki.make_csr(rsa.generate_private_key(65537, 2048)))
    with pytest.raises(pki.PKIError, match="not allowed"):
        pki.validate_csr(pki.make_csr(ec.generate_private_key(ec.SECP256K1())))


def test_crl_contains_revoked_serial(ca):
    _, _, ik, ic = ca
    crl = pki.build_crl(ik, ic, [(1234, pki.now(), "keyCompromise")], 7, dt.timedelta(days=1))
    assert crl.is_signature_valid(ic.public_key())
    assert crl.get_revoked_certificate_by_serial_number(1234) is not None
    assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 7


@pytest.fixture
def tokens(tmp_path):
    store = Store(tmp_path / "db", SecretBox(b"k" * 32))
    return TokenService(b"s" * 32, store)


def test_token_tamper_detected(tokens):
    tok, _ = tokens.issue("alice", amr=["otp"], acr="x", scope=["enroll"], ttl=60)
    v, payload, sig = tok.split(".")
    from certauth.tokens import _b64d, _b64e
    claims = json.loads(_b64d(payload))
    claims["sub"] = "bob"
    forged = f"{v}.{_b64e(json.dumps(claims).encode())}.{sig}"
    with pytest.raises(TokenError, match="signature"):
        tokens.verify(forged, None)


def test_token_expiry_and_revocation(tokens):
    t = [1000.0]
    tokens.clock = lambda: t[0]
    tok, claims = tokens.issue("alice", amr=["otp"], acr="x", scope=["enroll"], ttl=60)
    assert tokens.verify(tok, None)["sub"] == "alice"
    tokens.revoke(claims)
    with pytest.raises(TokenError, match="revoked"):
        tokens.verify(tok, None)
    tok2, _ = tokens.issue("alice", amr=["otp"], acr="x", scope=["enroll"], ttl=60)
    t[0] += 61
    with pytest.raises(TokenError, match="expired"):
        tokens.verify(tok2, None)


def test_token_cert_binding(tokens):
    tok, _ = tokens.issue("alice", amr=["mtls"], acr="x", scope=["profile"], ttl=60, cert_fp="aa" * 32)
    assert tokens.verify(tok, "aa" * 32, "profile")
    with pytest.raises(TokenError, match="different certificate"):
        tokens.verify(tok, "bb" * 32)
    with pytest.raises(TokenError, match="certificate-bound"):
        tokens.verify(tok, None)
    with pytest.raises(TokenError, match="insufficient_scope") as e:
        tokens.verify(tok, "aa" * 32, "admin")
    assert e.value.status == 403


def test_totp_seed_encrypted_and_bound_to_user(tmp_path):
    s = Store(tmp_path / "db", SecretBox(derive(b"m" * 32, "totp-at-rest")))
    s.add_user("alice", "JBSWY3DPEHPK3PXP")
    s.add_user("bob", "KRSXG5CTMVRXEZLU")
    raw = s.db.execute("SELECT totp_secret FROM users WHERE username='alice'").fetchone()[0]
    assert b"JBSWY3DP" not in raw
    s.db.execute("UPDATE users SET totp_secret=? WHERE username='bob'", (raw,))
    with pytest.raises(Exception):
        s.get_user("bob")


@pytest.fixture
def audit(tmp_path):
    a = AuditLog(tmp_path / "audit.log", b"a" * 32)
    for i in range(5):
        a.log("evt", i=i)
    return a


def test_audit_intact(audit):
    assert AuditLog.verify(audit.path, b"a" * 32) == (True, 5, "5 entries, chain intact")


def _lines(a):
    return a.path.read_text().splitlines()


def test_audit_modification_detected(audit):
    lines = _lines(audit)
    e = json.loads(lines[2]); e["i"] = 99
    lines[2] = json.dumps(e, sort_keys=True)
    audit.path.write_text("\n".join(lines) + "\n")
    ok, n, msg = AuditLog.verify(audit.path, b"a" * 32)
    assert not ok and n == 3 and "MAC" in msg


def test_audit_deletion_and_reorder_detected(audit):
    lines = _lines(audit)
    audit.path.write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    assert not AuditLog.verify(audit.path, b"a" * 32)[0]
    audit.path.write_text("\n".join([lines[1], lines[0]] + lines[2:]) + "\n")
    assert not AuditLog.verify(audit.path, b"a" * 32)[0]


def test_audit_forgery_without_key_detected(audit):
    """An attacker rebuilding the whole chain with a guessed key is still caught."""
    forged = AuditLog(audit.path.with_name("forged.log"), b"x" * 32)
    for i in range(5):
        forged.log("evt", i=i)
    assert not AuditLog.verify(forged.path, b"a" * 32)[0]
