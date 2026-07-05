"""HTTP response header injection (CRLF / response splitting).

Two local apps that both reflect a parameter into a response header:
  - vulnerable: writes the value raw, so an injected CR/LF splits the header stream
  - safe:       strips CR/LF from the value first (must NOT false-positive)

The vulnerable app writes the raw HTTP response by hand (Python's send_header
would otherwise sanitise it), which is exactly the real-world bug.
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
from celsius.active.verifiers import crlf_injection  # noqa: E402
from celsius.audit import AuditLog  # noqa: E402


def _app(vulnerable: bool):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            v = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("p", [""])[0]
            if vulnerable:
                header_line = f"X-Ref: {v}"          # raw — CR/LF in v splits headers
            else:
                header_line = "X-Ref: " + re.sub(r"[\r\n]", "", v)   # sanitised
            body = b"ok"
            raw = (f"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n{header_line}\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
            self.wfile.write(raw)
            self.wfile.flush()

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    return srv, srv.server_address[1]


def _lab():
    return LabContext(host="127.0.0.1", enabled=True, attested=True,
                      audit=AuditLog(path="/tmp/celsius-crlf-audit.log"),
                      rate_limit_rps=200, max_requests=80)


def _point(port):
    return Point(url=f"http://127.0.0.1:{port}/r", method="GET", params={"p": "home"})


def test_crlf_confirmed_when_header_splits():
    srv, port = _app(vulnerable=True)
    try:
        f = crlf_injection([_point(port)], _lab())
        assert len(f) == 1 and "crlf" in f[0].title.lower()
        assert f[0].severity.value == "HIGH"
    finally:
        srv.shutdown()


def test_sanitized_header_no_finding():
    srv, port = _app(vulnerable=False)
    try:
        assert crlf_injection([_point(port)], _lab()) == []
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
