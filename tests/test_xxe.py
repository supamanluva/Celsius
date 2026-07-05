"""Blind XXE via the OOB canary.

A local endpoint that parses an XML POST body: the vulnerable variant resolves an
external SYSTEM entity (fetching its URL server-side, the XXE bug); the safe one
does not. Confirmation is a canary callback — deterministic, offline.
"""

from __future__ import annotations

import http.server
import os
import re
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.active.canary import OOBCanary  # noqa: E402
from celsius.active.harness import LabContext, Point  # noqa: E402
from celsius.active.verifiers import xxe_oob  # noqa: E402
from celsius.audit import AuditLog  # noqa: E402

_ENTITY = re.compile(r'<!ENTITY\s+\w+\s+SYSTEM\s+"([^"]+)"')


def _app(resolves_entities: bool):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n).decode("utf-8", "replace")
            m = _ENTITY.search(body)
            if resolves_entities and m:                 # vulnerable parser fetches it
                try:
                    urllib.request.urlopen(m.group(1), timeout=2)
                except Exception:
                    pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    return srv, srv.server_address[1]


def _lab():
    return LabContext(host="127.0.0.1", enabled=True, attested=True,
                      audit=AuditLog(path="/tmp/celsius-xxe-audit.log"),
                      rate_limit_rps=200, max_requests=40)


def _point(port):
    return Point(url=f"http://127.0.0.1:{port}/api", method="GET", params={"x": "1"})


def test_xxe_confirmed_when_parser_resolves_entity():
    srv, port = _app(resolves_entities=True)
    try:
        with OOBCanary(host="127.0.0.1") as canary:
            f = xxe_oob([_point(port)], _lab(), canary)
        assert len(f) == 1 and "XXE" in f[0].title
        assert f[0].severity.value == "CRITICAL"
    finally:
        srv.shutdown()


def test_no_finding_when_entities_not_resolved():
    srv, port = _app(resolves_entities=False)
    try:
        with OOBCanary(host="127.0.0.1") as canary:
            assert xxe_oob([_point(port)], _lab(), canary, wait_timeout=0.5) == []
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
