"""Integration test for the IdorProbe plugin through a real ScanContext."""

from __future__ import annotations

import http.server
import os
import sys
import threading
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.audit import AuditLog  # noqa: E402
from celsius.auth import AuthSession  # noqa: E402
from celsius.config import ScanConfig  # noqa: E402
from celsius.models import ScanResult  # noqa: E402
from celsius.plugins.base import ScanContext  # noqa: E402
from celsius.plugins.builtin import IdorProbe  # noqa: E402
from celsius.scope import Scope  # noqa: E402
from celsius.targets import Target  # noqa: E402

_OBJECT = "SECRET-ORDER-1-owned-by-alice-" + "z" * 40


def _bola_app():
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            authed = "user=" in self.headers.get("Cookie", "")
            if q.get("id", [""])[0] == "1" and authed:   # any authed user -> BOLA
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


def _ctx(config, url=None):
    return ScanContext(
        config=config,
        target=Target(raw="127.0.0.1", scheme="http", host="127.0.0.1", port=80, path="/"),
        result=ScanResult(target="127.0.0.1", url=url),
        scope=Scope.permissive_default(),
        audit=AuditLog(path="/tmp/celsius-idor-plugin-audit.log"))


def _cfg(**kw):
    base = dict(target="127.0.0.1", allow_exploit=True, idor=True,
                lab_attestation="I am authorized to actively test this target",
                auth=AuthSession(headers={"Cookie": "user=alice"}, source="A"),
                auth2=AuthSession(headers={"Cookie": "user=bob"}, source="B"),
                persist=False)
    base.update(kw)
    return ScanConfig(**base)


def test_enabled_only_with_lab_and_idor():
    assert IdorProbe().enabled(_ctx(_cfg())) is True
    assert IdorProbe().enabled(_ctx(_cfg(idor=False))) is False
    assert IdorProbe().enabled(_ctx(_cfg(allow_exploit=False))) is False


def test_bola_confirmed_end_to_end():
    srv, port = _bola_app()
    try:
        ctx = _ctx(_cfg(), url=f"http://127.0.0.1:{port}/order?id=1")
        IdorProbe().run(ctx)
        assert [f for f in ctx.result.findings if "BOLA" in f.title]
        assert ctx.result.recon["idor"]["confirmed"] >= 1
    finally:
        srv.shutdown()


def test_requires_primary_auth():
    ctx = _ctx(_cfg(auth=None), url="http://127.0.0.1:1/order?id=1")
    IdorProbe().run(ctx)
    assert not ctx.result.findings
    assert any("primary authenticated session" in e for e in ctx.result.errors)


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
