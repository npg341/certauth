import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from certauth import pki, totp
from certauth.client import CertAuthClient
from certauth.crypto import create_master_key
from certauth.server import AuthServer, Config

ROOT_PASS = b"test root passphrase"


class Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


@dataclass
class Env:
    dir: Path
    server: AuthServer
    clock: Clock
    secrets: dict = field(default_factory=dict)

    @property
    def port(self):
        return self.server.cfg.port

    @property
    def ca(self):
        return self.server.paths.root_crt

    def client(self, cert=None, key=None, **kw) -> CertAuthClient:
        return CertAuthClient("localhost", self.port, self.ca, cert, key, **kw)

    def code(self, user, offset_steps=0):
        return totp.totp(totp.b32decode(self.secrets[user]), self.clock.t + 30 * offset_steps)

    def next_step(self):
        self.clock.advance(30)

    def totp_token(self, user):
        status, body = self.client().login_totp(user, self.code(user))
        assert status == 200, body
        self.next_step()
        return body["access_token"]

    def enroll(self, user, device="laptop", key=None):
        key = key or ec.generate_private_key(ec.SECP256R1())
        status, body = self.client().enroll(self.totp_token(user), pki.pem(pki.make_csr(key)).decode(), device)
        assert status == 201, body
        return self.save_identity(f"{user}-{device}", key, body["certificate_chain"].encode()), body

    def save_identity(self, name, key, chain_pem: bytes):
        crt, k = self.dir / f"{name}.crt", self.dir / f"{name}.key"
        crt.write_bytes(chain_pem)
        pki.write_key(k, key)
        return crt, k

    def cert_client(self, ident) -> CertAuthClient:
        return self.client(*ident)

    def audit_events(self):
        import json
        return [json.loads(l) for l in (self.dir / "audit.log").read_text().splitlines()]


@pytest.fixture
def make_env(tmp_path):
    servers = []

    def _make(**cfg):
        d = tmp_path / f"srv{len(servers)}"
        d.mkdir()
        pki.init_pki(d / "pki", ROOT_PASS)
        create_master_key(d / "master.key")
        clock = Clock()
        srv = AuthServer(Config(d, port=0, clock=clock, **cfg))
        env = Env(d, srv, clock)
        for u in ("alice", "bob"):
            env.secrets[u] = totp.generate_secret()
            srv.store.add_user(u, env.secrets[u])
        srv.start()
        servers.append(srv)
        return env

    yield _make
    for s in servers:
        s.shutdown()


@pytest.fixture
def env(make_env):
    return make_env()


HANDSHAKE_ERRORS = (ssl.SSLError, ConnectionError, OSError)
