"""IDOR/BOLA authorization probe.

A local app with two accounts and one object endpoint, wired three ways:
  - secure:    only the owner (identity A) may read object 1; B and anon are denied
  - bola:      any *authenticated* user may read object 1; anon is denied
  - open:      anyone (even unauthenticated) may read object 1

Identities are just Cookie headers the fake app checks. Offline/deterministic.
"""

from __future__ import annotations

import http.server
import os
import sys
import threading
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.active.harness import LabContext, Point  # noqa: E402
from celsius.active.verifiers import idor_bola  # noqa: E402
from celsius.audit import AuditLog  # noqa: E402
from celsius.auth import AuthSession  # noqa: E402

_OBJECT = "SECRET-ORDER-1-CONTENTS-owned-by-alice-xxxxxxxxxxxxxxxxxxxxxxxx"


def _app(policy: str):
    """policy in {'secure','bola','open'}. Object id=1 is owned by cookie user=alice."""
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            oid = q.get("id", [""])[0]
            cookie = self.headers.get("Cookie", "")
            user = ""
            if "user=" in cookie:
                user = cookie.split("user=", 1)[1].split(";", 1)[0]
            authed = bool(user)
            owner = (user == "alice")
            allowed = {"secure": owner, "bola": authed, "open": True}[policy]
            if oid == "1" and allowed:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(_OBJECT.encode())
            else:
                self.send_response(200 if authed else 401)
                self.end_headers()
                self.wfile.write(b"denied")

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    return srv, srv.server_address[1]


def _lab(port, cookie="user=alice"):
    return LabContext(host="127.0.0.1", enabled=True, attested=True,
                      audit=AuditLog(path="/tmp/celsius-idor-audit.log"),
                      rate_limit_rps=200, max_requests=50,
                      auth=AuthSession(headers={"Cookie": cookie}, source="A"))


def _point(port):
    return Point(url=f"http://127.0.0.1:{port}/order", method="GET", params={"id": "1"})


_BOB = AuthSession(headers={"Cookie": "user=bob"}, source="B")


def test_bola_confirmed_cross_user():
    srv, port = _app("bola")   # any authed user can read alice's object; anon denied
    try:
        f = idor_bola([_point(port)], _lab(port), second_session=_BOB)
        assert len(f) == 1 and "IDOR / BOLA" in f[0].title
        assert f[0].severity.value == "HIGH"
    finally:
        srv.shutdown()


def test_missing_auth_confirmed():
    srv, port = _app("open")   # anyone, even unauthenticated, can read the object
    try:
        f = idor_bola([_point(port)], _lab(port), second_session=_BOB)
        assert len(f) == 1 and "without authentication" in f[0].title.lower()
    finally:
        srv.shutdown()


def test_secure_endpoint_no_finding():
    srv, port = _app("secure")   # only the owner can read it — correctly enforced
    try:
        assert idor_bola([_point(port)], _lab(port), second_session=_BOB) == []
    finally:
        srv.shutdown()


def test_requires_primary_session():
    srv, port = _app("open")
    try:
        lab = LabContext(host="127.0.0.1", enabled=True, attested=True,
                         audit=AuditLog(path="/tmp/celsius-idor-audit.log"))  # no auth
        assert idor_bola([_point(port)], lab, second_session=_BOB) == []
    finally:
        srv.shutdown()


def test_skips_points_without_object_ref():
    srv, port = _app("open")
    try:
        pt = Point(url=f"http://127.0.0.1:{port}/order", method="GET", params={"q": "search"})
        assert idor_bola([pt], _lab(port), second_session=_BOB) == []   # no id-like param
    finally:
        srv.shutdown()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:  # noqa
            failed += 1
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
