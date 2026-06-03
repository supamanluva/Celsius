"""Tests for authenticated scanning: session headers, CSRF-aware form login, and
that the crawler reaches pages gated behind a session cookie.

Spins up a tiny local HTTP server (stdlib). Run directly or under pytest.
"""

from __future__ import annotations

import http.server
import os
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import auth  # noqa: E402
from celsius.recon import crawler  # noqa: E402


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, code, body, hdrs=None):
        self.send_response(code)
        for k, v in (hdrs or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        c = self.headers.get("Cookie", "")
        if self.path == "/login":
            self._send(200, '<form method=post>'
                            '<input type=hidden name=csrf value=TOK123>'
                            '<input name=username><input name=password></form>')
        elif self.path == "/dashboard":
            if "sid=secret-session" in c:
                self._send(200, '<a href="/secret-data">d</a> dashboard')
            else:
                self._send(302, "", {"Location": "/login"})
        elif self.path == "/secret-data":
            self._send(200, 'TOP SECRET internal') if "sid=secret-session" in c \
                else self._send(401, "denied")
        else:
            self._send(200, 'public')

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", 0))
        d = urllib.parse.parse_qs(self.rfile.read(ln).decode())
        if d.get("csrf") == ["TOK123"] and d.get("username") == ["alice"]:
            self._send(302, "", {"Set-Cookie": "sid=secret-session; Path=/",
                                 "Location": "/dashboard"})
        else:
            self._send(403, "bad login")


def _serve():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_from_options_builds_headers():
    s = auth.from_options(cookie="a=1; b=2", bearer="TOK",
                          headers=["X-Api-Key: k", "malformed"])
    assert s.headers["Cookie"] == "a=1; b=2"
    assert s.headers["Authorization"] == "Bearer TOK"
    assert s.headers["X-Api-Key"] == "k"


def test_extract_csrf_tolerates_order_and_quoting():
    page = ('<input value="abc" name="_csrf" type=hidden>'
            "<input type=hidden name=authenticity_token value=XYZ>")
    out = auth._extract_csrf(page)
    assert out.get("_csrf") == "abc"
    assert out.get("authenticity_token") == "XYZ"


def test_form_login_and_authenticated_crawl():
    srv, base = _serve()
    try:
        session, msg = auth.form_login(f"{base}/login",
                                       {"username": "alice", "password": "pw"})
        assert session and "sid" in session.headers.get("Cookie", ""), msg

        anon = crawler.crawl(f"{base}/dashboard", max_pages=5)
        assert not any("TOP SECRET" in b for b in anon.pages.values())

        authed = crawler.crawl(f"{base}/dashboard", max_pages=5, auth=session)
        assert any("TOP SECRET" in b for b in authed.pages.values()), \
            "authenticated crawl should reach the gated page"
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
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
