"""OOB canary primitive + the probes that use it (SSRF / RCE / blind-XSS).

Fully offline and deterministic: a local canary listener and a local "vulnerable
sink" server whose behaviour is parameterised — it extracts a callback URL from
the injected value exactly the way the real sink would (SSRF fetches ?url=, a
shell runs `curl`, an HTML renderer loads `src=`), then fetches it. No network,
no model.
"""

from __future__ import annotations

import http.server
import os
import re
import sys
import threading
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.active.canary import OOBCanary  # noqa: E402
from celsius.active.harness import LabContext, Point  # noqa: E402
from celsius.active.verifiers import (  # noqa: E402
    blind_xss_oob, command_injection_oob, ssrf_oob)
from celsius.audit import AuditLog  # noqa: E402

# How each sink type turns an injected value into the URL it fetches.
_SSRF = lambda raw: (raw if raw.startswith("http") else None)  # noqa: E731
_RCE = lambda raw: (m.group(1) if (m := re.search(r"(?:curl -s|wget -qO-) (http://\S+)", raw)) else None)  # noqa: E731
_XSS = lambda raw: (m.group(1) or m.group(2) if (m := re.search(r'src="(http://[^"]+)"|fetch\(.(http://[^\')]+)', raw)) else None)  # noqa: E731


def _sink_server(extract, *, vulnerable: bool):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            qs = urllib.parse.urlparse(self.path).query
            raw = urllib.parse.unquote_plus(qs.split("=", 1)[1]) if "=" in qs else ""
            url = extract(raw) if vulnerable else None
            if url:
                try:
                    urllib.request.urlopen(url, timeout=2)   # the vulnerable sink fires
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
                      audit=AuditLog(path="/tmp/celsius-canary-test-audit.log"),
                      rate_limit_rps=100, max_requests=50)


def _point(port, param):
    return Point(url=f"http://127.0.0.1:{port}/x", method="GET",
                 params={param: "seed"})


# ---- the canary primitive -----------------------------------------------------

def test_canary_records_a_real_callback():
    with OOBCanary(host="127.0.0.1") as c:
        token = c.new_token()
        assert c.was_hit(token) is False
        urllib.request.urlopen(c.url_for(token), timeout=2)
        assert c.wait_for_hit(token) is True
        assert len(c.hits(token)) == 1 and c.hits(token)[0].src_ip == "127.0.0.1"


def test_canary_ignores_unknown_tokens():
    with OOBCanary(host="127.0.0.1") as c:
        urllib.request.urlopen(c.url_for("deadbeefdeadbeef"), timeout=2)
        assert c.was_hit("deadbeefdeadbeef") is False


# ---- SSRF ---------------------------------------------------------------------

def test_ssrf_confirmed_and_negative():
    srv, port = _sink_server(_SSRF, vulnerable=True)
    try:
        with OOBCanary(host="127.0.0.1") as canary:
            f = ssrf_oob([_point(port, "url")], _lab(), canary)
        assert len(f) == 1 and "SSRF" in f[0].title and f[0].severity.value == "HIGH"
    finally:
        srv.shutdown()

    srv, port = _sink_server(_SSRF, vulnerable=False)
    try:
        with OOBCanary(host="127.0.0.1") as canary:
            assert ssrf_oob([_point(port, "url")], _lab(), canary, wait_timeout=0.5) == []
    finally:
        srv.shutdown()


def test_ssrf_skips_non_url_params():
    srv, port = _sink_server(_SSRF, vulnerable=True)
    try:
        with OOBCanary(host="127.0.0.1") as canary:
            assert ssrf_oob([_point(port, "q")], _lab(), canary, wait_timeout=0.5) == []
    finally:
        srv.shutdown()


# ---- RCE (OS command injection) ----------------------------------------------

def test_command_injection_confirmed():
    srv, port = _sink_server(_RCE, vulnerable=True)   # sink "runs" the injected curl
    try:
        with OOBCanary(host="127.0.0.1") as canary:
            f = command_injection_oob([_point(port, "host")], _lab(), canary)
        assert len(f) == 1 and "command injection" in f[0].title.lower()
        assert f[0].severity.value == "CRITICAL"
    finally:
        srv.shutdown()


def test_command_injection_negative():
    srv, port = _sink_server(_RCE, vulnerable=False)
    try:
        with OOBCanary(host="127.0.0.1") as canary:
            assert command_injection_oob([_point(port, "host")], _lab(), canary,
                                         wait_timeout=0.5) == []
    finally:
        srv.shutdown()


# ---- blind / stored XSS -------------------------------------------------------

def test_blind_xss_confirmed():
    srv, port = _sink_server(_XSS, vulnerable=True)   # sink renders + loads the beacon
    try:
        with OOBCanary(host="127.0.0.1") as canary:
            f = blind_xss_oob([_point(port, "comment")], _lab(), canary)
        assert len(f) == 1 and "injection" in f[0].title.lower()
    finally:
        srv.shutdown()


def test_blind_xss_negative():
    srv, port = _sink_server(_XSS, vulnerable=False)
    try:
        with OOBCanary(host="127.0.0.1") as canary:
            assert blind_xss_oob([_point(port, "comment")], _lab(), canary,
                                 wait_timeout=0.5) == []
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
