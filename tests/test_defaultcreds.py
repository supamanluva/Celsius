"""Tests for curated default-credential checks (defaultcreds).

Stdlib-only: run directly (`python tests/test_defaultcreds.py`) or under pytest.

A tiny in-process HTTP server models an HTTP-Basic-protected panel so the probe
exercises real urllib auth, plus a server that needs creds NOT in our list (to
prove we don't false-positive), and an open server (to prove we never fire creds
at an unprotected endpoint).
"""

from __future__ import annotations

import base64
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import defaultcreds  # noqa: E402


def _basic_server(valid: tuple, realm: str = "Router"):
    """HTTP server that returns 200 only for Basic `valid` (user,pass); else 401."""
    want = "Basic " + base64.b64encode(f"{valid[0]}:{valid[1]}".encode()).decode()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.headers.get("Authorization") == want:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<h1>dashboard</h1>")
            else:
                self.send_response(401)
                self.send_header("WWW-Authenticate", f'Basic realm="{realm}"')
                self.end_headers()

    srv = HTTPServer(("127.0.0.1", 0), H)
    host, port = srv.server_address
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://{host}:{port}/", srv


def _open_server():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    srv = HTTPServer(("127.0.0.1", 0), H)
    host, port = srv.server_address
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://{host}:{port}/", srv


# ---- realm detection ----------------------------------------------------------

def test_realm_detected_on_basic_challenge():
    url, srv = _basic_server(("admin", "admin"), realm="iDRAC6")
    try:
        assert defaultcreds.basic_realm(url) == "iDRAC6"
    finally:
        srv.shutdown()


def test_open_endpoint_is_not_basic_protected():
    url, srv = _open_server()
    try:
        # not protected -> None, and check_http_basic must NOT attempt any creds
        assert defaultcreds.basic_realm(url) is None
        assert defaultcreds.check_http_basic(url) is None
    finally:
        srv.shutdown()


# ---- credential attempts ------------------------------------------------------

def test_default_admin_admin_accepted_is_critical():
    url, srv = _basic_server(("admin", "admin"))
    try:
        r = defaultcreds.check_http_basic(url)
    finally:
        srv.shutdown()
    assert r is not None and r.success is True and r.severity == "CRITICAL"
    assert "admin:admin" in r.evidence


def test_blank_password_default_accepted():
    url, srv = _basic_server(("admin", ""))
    try:
        r = defaultcreds.check_http_basic(url)
    finally:
        srv.shutdown()
    assert r is not None and r.success is True
    assert "<blank>" in r.evidence


def test_non_default_password_is_not_flagged():
    # server wants a strong password not in any curated list -> no false positive
    url, srv = _basic_server(("admin", "Tr0ub4dor&3-unguessable"))
    try:
        r = defaultcreds.check_http_basic(url)
    finally:
        srv.shutdown()
    assert r is None


def test_product_creds_tried_first():
    # Tomcat default tomcat/tomcat is product-specific, not in the universal list
    url, srv = _basic_server(("tomcat", "tomcat"), realm="Tomcat Manager Application")
    try:
        r = defaultcreds.check_http_basic(url, hints="Apache Tomcat")
    finally:
        srv.shutdown()
    assert r is not None and r.success is True
    assert "tomcat:tomcat" in r.evidence


def test_creds_for_orders_product_before_universal():
    creds = defaultcreds._creds_for("iDRAC6", "dell idrac")
    assert ("root", "calvin") in creds
    assert creds.index(("root", "calvin")) < creds.index(("admin", "admin"))
    assert len(creds) <= defaultcreds.MAX_ATTEMPTS


# ---- ftp ----------------------------------------------------------------------

def test_ftp_closed_port_returns_none_never_raises():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    _h, port = s.getsockname()
    s.close()
    assert defaultcreds.check_ftp_anonymous("127.0.0.1", port) is None


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
