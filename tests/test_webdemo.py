"""The browser demo drives the real server; check every scene gives the expected verdict."""
import json
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from certauth import totp
from certauth.webdemo import Demo, SceneError, make_handler

EXPECT = {"register": "done", "nocert": "refused", "enroll": "issued", "replay": "stopped",
          "login": "admit", "steal": "stopped", "fake": "stopped", "revoke": "stopped",
          "recover": "admit", "tamper": "stopped"}


@pytest.fixture
def demo(tmp_path):
    d = Demo(tmp_path / "web", 0)
    yield d
    d.server.shutdown()


def code_for(demo, steps_ahead=0):
    return totp.totp(totp.b32decode(demo.secret), time.time() + 30 * steps_ahead)


def test_all_scenes_in_order(demo):
    for name in EXPECT:
        body = {}
        if name == "enroll":
            body = {"code": code_for(demo)}
        if name == "recover":            # a code from the next time step: fresh, inside the ±1 window
            body = {"code": code_for(demo, 1)}
        r = demo.run(name, body)
        assert r["verdict"]["kind"] == EXPECT[name], (name, r["headline"])
    assert demo.state()["audit"]["ok"] is False          # the tamper scene broke the chain


def test_scene_checks_match_server_reasons(demo):
    demo.run("register", {})
    demo.run("enroll", {"code": code_for(demo)})
    assert demo.run("replay", {})["checks"]["code.fresh"] == "fail"
    assert demo.run("fake", {})["checks"]["tls.ca"] == "fail"
    assert demo.run("revoke", {})["checks"]["tls.revoked"] == "fail"


def test_scenes_need_their_prerequisites(demo):
    with pytest.raises(SceneError):
        demo.run("login", {})
    with pytest.raises(SceneError):
        demo.run("enroll", {"code": "123456"})          # Alice not registered yet


def test_http_api(demo):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(demo))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        page = urllib.request.urlopen(base + "/").read().decode()
        assert "CertAuth" in page
        req = urllib.request.Request(base + "/api/scene/register", data=b"{}", method="POST",
                                     headers={"Content-Type": "application/json"})
        assert json.loads(urllib.request.urlopen(req).read())["ok"] is True
        phone = json.loads(urllib.request.urlopen(base + "/api/phone").read())
        assert phone["ready"] and len(phone["code"]) == 6
        assert urllib.request.urlopen(base + "/api/qr.svg").read().startswith(b"<")
    finally:
        httpd.shutdown()
