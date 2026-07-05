"""Blind boolean-based SQL injection (differential, no error / no OOB).

Three local apps, all of which reflect the injected value back (to prove the
probe strips the echo before comparing):
  - vulnerable: an always-false boolean empties the result set (real injection)
  - safe:       parameterized — the appended condition is ignored (same result)
  - reflect:    echoes the value but runs no SQL (must NOT false-positive)
"""

from __future__ import annotations

import http.server
import os
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.active.harness import LabContext, Point  # noqa: E402
from celsius.active.verifiers import blind_sqli_boolean  # noqa: E402
from celsius.audit import AuditLog  # noqa: E402

_ROWS = "Order #1: widget x $9.99 for customer alice; ship 2026-07-05; status shipped"


def _app(kind: str):
    def render(v: str) -> str:
        false_cond = ("AND '1'='2" in v) or ("AND 1=2" in v)
        if kind == "vulnerable":
            rows = "" if false_cond else _ROWS          # false boolean -> no rows
        else:                                           # safe / reflect: condition ignored
            rows = _ROWS
        return f"<html><!-- q={v} -->{rows}</html>"     # value is reflected either way

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            v = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("id", [""])[0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(render(v).encode())

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    return srv, srv.server_address[1]


def _lab():
    return LabContext(host="127.0.0.1", enabled=True, attested=True,
                      audit=AuditLog(path="/tmp/celsius-sqlib-audit.log"),
                      rate_limit_rps=200, max_requests=80)


def _point(port):
    return Point(url=f"http://127.0.0.1:{port}/order", method="GET", params={"id": "1"})


def test_boolean_sqli_confirmed_despite_reflection():
    srv, port = _app("vulnerable")
    try:
        f = blind_sqli_boolean([_point(port)], _lab())
        assert len(f) == 1 and "boolean-based" in f[0].title.lower()
        assert f[0].severity.value == "HIGH"
    finally:
        srv.shutdown()


def test_parameterized_query_no_finding():
    srv, port = _app("safe")     # condition ignored -> true and false identical
    try:
        assert blind_sqli_boolean([_point(port)], _lab()) == []
    finally:
        srv.shutdown()


def test_pure_reflection_no_finding():
    srv, port = _app("reflect")  # echoes the payload but runs no SQL
    try:
        assert blind_sqli_boolean([_point(port)], _lab()) == []
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
