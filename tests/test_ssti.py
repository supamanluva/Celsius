"""Server-side template injection (SSTI) — evaluated-expression confirmation.

Two local apps:
  - vulnerable: a Jinja-like engine that evaluates {{a*b}} server-side
  - reflect:    echoes the injected value raw (no engine) — must NOT false-positive,
                since the raw expression stays in the response
"""

from __future__ import annotations

import http.server
import os
import re
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.active.harness import LabContext, Point  # noqa: E402
from celsius.active.verifiers import ssti  # noqa: E402
from celsius.audit import AuditLog  # noqa: E402

_EXPR = re.compile(r"\{\{(\d+)\*(\d+)\}\}")   # this fake engine only speaks {{a*b}}


def _app(vulnerable: bool):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            v = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("q", [""])[0]
            rendered = v
            m = _EXPR.search(v)
            if vulnerable and m:
                rendered = v.replace(m.group(0), str(int(m.group(1)) * int(m.group(2))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"<html>Hello, {rendered}!</html>".encode())

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    return srv, srv.server_address[1]


def _lab():
    return LabContext(host="127.0.0.1", enabled=True, attested=True,
                      audit=AuditLog(path="/tmp/celsius-ssti-audit.log"),
                      rate_limit_rps=200, max_requests=80)


def _point(port):
    return Point(url=f"http://127.0.0.1:{port}/hello", method="GET", params={"q": "x"})


def test_ssti_confirmed_when_expression_evaluated():
    srv, port = _app(vulnerable=True)
    try:
        f = ssti([_point(port)], _lab())
        assert len(f) == 1 and "template injection" in f[0].title.lower()
        assert f[0].severity.value == "CRITICAL"
    finally:
        srv.shutdown()


def test_reflection_only_no_finding():
    srv, port = _app(vulnerable=False)   # echoes the raw expression, evaluates nothing
    try:
        assert ssti([_point(port)], _lab()) == []
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
