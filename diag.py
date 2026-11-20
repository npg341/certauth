import socket, ssl, sys, tempfile, time, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
out = []
def log(*a):
    out.append(" ".join(str(x) for x in a)); print(*a, flush=True)
from certauth import pki
from certauth.crypto import create_master_key
from certauth.server import AuthServer, Config
d = Path(tempfile.mkdtemp())
pki.init_pki(d / "pki", b"diag passphrase 123")
create_master_key(d / "master.key")
srv = AuthServer(Config(d, port=0)); port = srv.start()
ca = str(srv.paths.root_crt)
for host in ("127.0.0.1", "localhost"):
    t0 = time.perf_counter()
    s = socket.create_connection((host, port))
    t1 = time.perf_counter()
    ctx = ssl.create_default_context(cafile=ca)
    t2 = time.perf_counter()
    t = ctx.wrap_socket(s, server_hostname="localhost")
    t3 = time.perf_counter()
    t.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
    data = b""
    while True:
        c = t.recv(4096)
        if not c: break
        data += c
    t4 = time.perf_counter()
    t.close()
    log(f"{host:10} connect={t1-t0:.3f}s ctx={t2-t1:.3f}s handshake={t3-t2:.3f}s request+response={t4-t3:.3f}s  first-line={data.split(b'\\r\\n')[0]!r}")
from certauth.client import CertAuthClient
for i in range(3):
    t0 = time.perf_counter()
    st, body = CertAuthClient("localhost", port, ca).request("GET", "/health")
    log(f"CertAuthClient /health #{i}: {time.perf_counter()-t0:.3f}s status={st}")
Path("diag-output.txt").write_text("\n".join(out))
srv.shutdown()
