"""OOB canary primitive + the blind-SSRF probe that uses it.

Fully offline and deterministic: a local canary listener, a local "vulnerable"
target that fetches an attacker-supplied ?url= server-side (simulating SSRF), and
a "safe" target that ignores it. No network, no model.
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

from celsius.active.canary import OOBCanary  # noqa: E402
from celsius.active.harness import LabContext, Point  # noqa: E402
from celsius.active.verifiers import ssrf_oob  # noqa: E402
from celsius.audit import AuditLog  # noqa: E402


# ---- a target that IS / ISN'T vulnerable to SSRF ------------------------------

def _make_target(vulnerable: bool):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            url = params.get("url", [None])[0]
            if vulnerable and url:
                try:
                    urllib.request.urlopen(url, timeout=2)  # SSRF: server fetches it
                except Exception:
                    pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/fetch"


def _lab():
    return LabContext(host="127.0.0.1", enabled=True, attested=True,
                      audit=AuditLog(path="/tmp/celsius-canary-test-audit.log"),
                      rate_limit_rps=100, max_requests=20)


# ---- the canary primitive -----------------------------------------------------

def test_canary_records_a_real_callback():
    with OOBCanary(host="127.0.0.1") as c:
        token = c.new_token()
        assert c.was_hit(token) is False
        urllib.request.urlopen(c.url_for(token), timeout=2)   # simulate the callback
        assert c.wait_for_hit(token) is True
        hits = c.hits(token)
        assert len(hits) == 1 and hits[0].src_ip == "127.0.0.1"


def test_canary_ignores_unknown_tokens():
    with OOBCanary(host="127.0.0.1") as c:
        urllib.request.urlopen(c.url_for("deadbeefdeadbeef"), timeout=2)  # never minted
        assert c.was_hit("deadbeefdeadbeef") is False


# ---- the SSRF probe end-to-end ------------------------------------------------

def test_ssrf_confirmed_when_server_fetches_the_canary():
    srv, base = _make_target(vulnerable=True)
    try:
        with OOBCanary(host="127.0.0.1") as canary:
            pt = Point(url=base, method="GET", params={"url": "http://placeholder/"})
            findings = ssrf_oob([pt], _lab(), canary)
        assert len(findings) == 1
        f = findings[0]
        assert "SSRF" in f.title and f.severity.value == "HIGH"
        assert f.exploitability["verdict"] == "confirmed-exploitable"
        assert f.confidence == "high"
    finally:
        srv.shutdown()


def test_ssrf_not_confirmed_when_server_ignores_the_param():
    srv, base = _make_target(vulnerable=False)
    try:
        with OOBCanary(host="127.0.0.1") as canary:
            pt = Point(url=base, method="GET", params={"url": "http://placeholder/"})
            # short wait: the safe server never calls back, so don't stall the suite
            findings = ssrf_oob([pt], _lab(), canary, wait_timeout=0.5)
        assert findings == []
    finally:
        srv.shutdown()


def test_ssrf_skips_non_url_params():
    srv, base = _make_target(vulnerable=True)
    try:
        with OOBCanary(host="127.0.0.1") as canary:
            pt = Point(url=base, method="GET", params={"q": "http://placeholder/"})
            findings = ssrf_oob([pt], _lab(), canary, wait_timeout=0.5)  # "q" isn't URL-ish
        assert findings == []
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
