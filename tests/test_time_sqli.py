"""Time-based blind SQLi — confirmation from a delay that SCALES with the payload.

Three local apps:
  - vulnerable:  sleeps for the N in SLEEP(N)/pg_sleep(N) (real time-based SQLi)
  - safe:        ignores the payload (no delay)
  - constant:    always slow by a fixed amount (must NOT false-positive — the delay
                 doesn't scale when the injected sleep is doubled)

Uses a small delay to keep the suite fast; real sleeps make the timing reliable.
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
from celsius.active.verifiers import time_based_sqli  # noqa: E402
from celsius.audit import AuditLog  # noqa: E402

_SLEEP = re.compile(r"(?:SLEEP|pg_sleep)\((\d+(?:\.\d+)?)\)", re.I)
_DELAY = 0.5


def _app(kind: str):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            v = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("id", [""])[0]
            if kind == "constant":
                time.sleep(_DELAY)                      # uniformly slow, regardless of payload
            elif kind == "vulnerable":
                m = _SLEEP.search(v)
                if m:
                    time.sleep(min(float(m.group(1)), 3.0))   # the injected sleep executes
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    return srv, srv.server_address[1]


def _lab():
    return LabContext(host="127.0.0.1", enabled=True, attested=True,
                      audit=AuditLog(path="/tmp/celsius-timesqli-audit.log"),
                      rate_limit_rps=200, max_requests=60)


def _point(port):
    return Point(url=f"http://127.0.0.1:{port}/item", method="GET", params={"id": "1"})


def test_time_based_confirmed_when_delay_scales():
    srv, port = _app("vulnerable")
    try:
        f = time_based_sqli([_point(port)], _lab(), delay=_DELAY)
        assert len(f) == 1 and "time-based" in f[0].title.lower()
        assert f[0].severity.value == "HIGH"
    finally:
        srv.shutdown()


def test_fast_endpoint_no_finding():
    srv, port = _app("safe")
    try:
        assert time_based_sqli([_point(port)], _lab(), delay=_DELAY) == []
    finally:
        srv.shutdown()


def test_constant_slow_endpoint_no_finding():
    srv, port = _app("constant")   # slow but the delay doesn't scale -> not SQLi
    try:
        assert time_based_sqli([_point(port)], _lab(), delay=_DELAY) == []
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
