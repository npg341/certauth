"""Two-tier PKI built with `cryptography`.

    Root CA (P-384, offline, passphrase-encrypted key, pathLen=1)
      └── Issuing CA (P-384, online in the server, pathLen=0, EKU-constrained)
            ├── server certificate   (EKU serverAuth, SAN localhost/127.0.0.1)
            └── client certificates  (EKU clientAuth, short-lived, issued from CSRs)

Client private keys are generated on the device and never leave it: the server only
ever sees a CSR, checks its proof-of-possession signature and key strength, and then
issues a certificate whose identity fields are set by the server, not the requester.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ORG = "CertAuth Lab"
UTC = dt.timezone.utc
CLOCK_SKEW = dt.timedelta(minutes=5)
DEVICE_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,40}$")


class PKIError(Exception):
    pass


def now() -> dt.datetime:
    return dt.datetime.now(UTC)


def gen_key(curve: ec.EllipticCurve | None = None) -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(curve or ec.SECP256R1())


def make_name(cn: str, ou: str | None = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG)]
    if ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attrs)


def key_usage(**on: bool) -> x509.KeyUsage:
    fields = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                  data_encipherment=False, key_agreement=False, key_cert_sign=False,
                  crl_sign=False, encipher_only=False, decipher_only=False)
    fields.update(on)
    return x509.KeyUsage(**fields)


def _aki(issuer_cert: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)


def fingerprint(cert: x509.Certificate) -> str:
    """SHA-256 over the DER certificate — the RFC 8705 'x5t#S256' thumbprint (hex form)."""
    return cert.fingerprint(hashes.SHA256()).hex()


def cert_common_name(cert: x509.Certificate) -> str | None:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None


def create_root_ca(days: int = 3650):
    key = gen_key(ec.SECP384R1())
    subject = make_name("CertAuth Root CA", "PKI")
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now() - CLOCK_SKEW).not_valid_after(now() + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(key_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
        .sign(key, hashes.SHA384())
    )
    return key, cert


def create_issuing_ca(root_key, root_cert, days: int = 1825):
    key = gen_key(ec.SECP384R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(make_name("CertAuth Issuing CA 1", "PKI")).issuer_name(root_cert.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now() - CLOCK_SKEW).not_valid_after(now() + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(key_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,
                                              ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(_aki(root_cert), critical=False)
        .sign(root_key, hashes.SHA384())
    )
    return key, cert


def create_server_cert(ca_key, ca_cert, hostnames=("localhost",), ips=("127.0.0.1", "::1"), days=90):
    key = gen_key()
    san = [x509.DNSName(h) for h in hostnames] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (
        x509.CertificateBuilder()
        .subject_name(make_name(hostnames[0], "Servers")).issuer_name(ca_cert.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now() - CLOCK_SKEW).not_valid_after(now() + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage(digital_signature=True), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(_aki(ca_cert), critical=False)
        .sign(ca_key, hashes.SHA384())
    )
    return key, cert


def check_public_key(pub) -> str:
    """Key-strength policy for client keys. Returns a human description or raises."""
    if isinstance(pub, ec.EllipticCurvePublicKey):
        if not isinstance(pub.curve, (ec.SECP256R1, ec.SECP384R1)):
            raise PKIError(f"curve {pub.curve.name} not allowed")
        return f"EC {pub.curve.name}"
    if isinstance(pub, rsa.RSAPublicKey):
        if pub.key_size < 3072:
            raise PKIError(f"RSA-{pub.key_size} too weak (minimum 3072)")
        return f"RSA-{pub.key_size}"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519"
    raise PKIError("unsupported key type")


def validate_csr(csr: x509.CertificateSigningRequest) -> str:
    if not csr.is_signature_valid:
        raise PKIError("CSR signature invalid (no proof of possession)")
    return check_public_key(csr.public_key())


def issue_client_cert(ca_key, ca_cert, public_key, username: str, device: str, *,
                      days: int = 30, not_before=None, not_after=None,
                      eku=(ExtendedKeyUsageOID.CLIENT_AUTH,),
                      crl_url: str = "https://localhost:8443/pki/crl") -> x509.Certificate:
    """Issue a short-lived client certificate. Subject/SAN come from the server's
    view of the identity, never from fields in the CSR."""
    if not DEVICE_RE.match(device):
        raise PKIError("invalid device name")
    check_public_key(public_key)
    nb = not_before or (now() - CLOCK_SKEW)
    na = not_after or (now() + dt.timedelta(days=days))
    san = x509.SubjectAlternativeName([
        x509.UniformResourceIdentifier(f"urn:certauth:user:{username}"),
    ])
    return (
        x509.CertificateBuilder()
        .subject_name(make_name(username, "Users")).issuer_name(ca_cert.subject)
        .public_key(public_key).serial_number(x509.random_serial_number())
        .not_valid_before(nb).not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage(digital_signature=True), critical=True)
        .add_extension(x509.ExtendedKeyUsage(list(eku)), critical=False)
        .add_extension(san, critical=False)
        .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(crl_url)],
            relative_name=None, reasons=None, crl_issuer=None)]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(_aki(ca_cert), critical=False)
        .sign(ca_key, hashes.SHA384())
    )


def build_crl(ca_key, ca_cert, revoked: Iterable[tuple[int, dt.datetime, str | None]],
              number: int, valid_for: dt.timedelta) -> x509.CertificateRevocationList:
    b = (x509.CertificateRevocationListBuilder()
         .issuer_name(ca_cert.subject)
         .last_update(now() - CLOCK_SKEW)
         .next_update(now() + valid_for)
         .add_extension(x509.CRLNumber(number), critical=False)
         .add_extension(_aki(ca_cert), critical=False))
    for serial, when, reason in revoked:
        rb = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when)
        if reason:
            rb = rb.add_extension(x509.CRLReason(x509.ReasonFlags(reason)), critical=False)
        b = b.add_revoked_certificate(rb.build())
    return b.sign(ca_key, hashes.SHA384())


def make_csr(key, cn: str = "device") -> x509.CertificateSigningRequest:
    algo = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return x509.CertificateSigningRequestBuilder().subject_name(make_name(cn)).sign(key, algo)


def _write_secret(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def write_key(path: Path, key, passphrase: bytes | None = None) -> None:
    enc = (serialization.BestAvailableEncryption(passphrase) if passphrase
           else serialization.NoEncryption())
    _write_secret(Path(path), key.private_bytes(serialization.Encoding.PEM,
                                                serialization.PrivateFormat.PKCS8, enc))


def load_key(path: Path, passphrase: bytes | None = None):
    return serialization.load_pem_private_key(Path(path).read_bytes(), passphrase)


def pem(*objs) -> bytes:
    return b"".join(o.public_bytes(serialization.Encoding.PEM) for o in objs)


def write_pem(path: Path, *objs) -> None:
    tmp = Path(str(path) + ".tmp")
    tmp.write_bytes(pem(*objs))
    for attempt in range(50):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 49:
                raise
            time.sleep(0.05)


def load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


@dataclass
class PKIPaths:
    root: Path

    def __post_init__(self):
        self.root = Path(self.root)

    root_crt = property(lambda s: s.root / "root-ca.crt")
    root_key = property(lambda s: s.root / "root-ca.key")
    root_crl = property(lambda s: s.root / "root-ca.crl.pem")
    ca_crt = property(lambda s: s.root / "issuing-ca.crt")
    ca_key = property(lambda s: s.root / "issuing-ca.key")
    ca_crl = property(lambda s: s.root / "issuing-ca.crl.pem")
    server_chain = property(lambda s: s.root / "server-chain.crt")
    server_key = property(lambda s: s.root / "server.key")


def init_pki(directory: Path, root_passphrase: bytes, hostnames=("localhost",)) -> PKIPaths:
    p = PKIPaths(directory)
    p.root.mkdir(parents=True, exist_ok=True)
    if p.root_crt.exists():
        raise PKIError(f"PKI already initialised in {p.root}")
    root_key, root_cert = create_root_ca()
    ca_key, ca_cert = create_issuing_ca(root_key, root_cert)
    srv_key, srv_cert = create_server_cert(ca_key, ca_cert, hostnames)
    root_crl = build_crl(root_key, root_cert, [], number=1, valid_for=dt.timedelta(days=365))
    ca_crl = build_crl(ca_key, ca_cert, [], number=1, valid_for=dt.timedelta(days=7))

    write_key(p.root_key, root_key, root_passphrase)
    write_pem(p.root_crt, root_cert)
    write_pem(p.root_crl, root_crl)
    write_key(p.ca_key, ca_key)
    write_pem(p.ca_crt, ca_cert)
    write_pem(p.ca_crl, ca_crl)
    write_key(p.server_key, srv_key)
    write_pem(p.server_chain, srv_cert, ca_cert)
    return p
