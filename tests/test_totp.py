"""RFC 6238 Appendix B test vectors + cross-check against an independent library."""
import pyotp
import pytest

from certauth import totp

SEEDS = {"SHA1": b"12345678901234567890",
         "SHA256": b"12345678901234567890123456789012",
         "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234"}
VECTORS = [  # time, SHA1, SHA256, SHA512   (RFC 6238 Appendix B, 8 digits)
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


@pytest.mark.parametrize("t,sha1,sha256,sha512", VECTORS)
def test_rfc6238_vectors(t, sha1, sha256, sha512):
    for alg, expected in (("SHA1", sha1), ("SHA256", sha256), ("SHA512", sha512)):
        assert totp.totp(SEEDS[alg], t, digits=8, algorithm=alg) == expected


def test_rfc4226_hotp_vectors():
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    assert [totp.hotp(b"12345678901234567890", i) for i in range(10)] == expected


def test_matches_pyotp():
    s = totp.generate_secret()
    ref = pyotp.TOTP(s)
    for t in (0, 1_700_000_000, 1_800_000_123):
        assert totp.totp(totp.b32decode(s), t) == ref.at(t)


def test_window_and_replay():
    key, t = totp.b32decode(totp.generate_secret()), 1_800_000_000
    prev = totp.totp(key, t - 30)
    assert totp.verify(key, prev, t=t).ok                        # within ±1 step drift
    assert not totp.verify(key, totp.totp(key, t - 90), t=t).ok   # outside window
    r = totp.verify(key, totp.totp(key, t), t=t)
    again = totp.verify(key, totp.totp(key, t), t=t, last_step=r.step)
    assert again.replay and not again.ok


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 456", None])
def test_malformed_codes_rejected(bad):
    assert not totp.verify(b"k" * 20, bad, t=0).ok


def test_provisioning_uri():
    uri = totp.provisioning_uri("ABCDEF", "alice")
    assert uri.startswith("otpauth://totp/CertAuth%3Aalice?") and "secret=ABCDEF" in uri
