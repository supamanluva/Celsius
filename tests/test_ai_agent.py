"""Tests for the agentic AI proof loop: payload safety, and a full
plan -> guardrailed-probe -> judge cycle against a local reflecting server with a
stubbed LLM provider (no network, no real model).
"""

from __future__ import annotations

import http.server
import json
import os
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.active.harness import LabContext, discover_points  # noqa: E402
from celsius.ai import agent  # noqa: E402
from celsius.audit import AuditLog  # noqa: E402


class _ReflectHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("q", [""])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(f"<html>results for {q}</html>".encode())  # reflected RAW


def _serve():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _ReflectHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/?q=test"


class _StubProvider:
    """First complete() returns a probe plan; later calls return a judge verdict."""
    name = "stub"
    model = "stub"

    def __init__(self, confirm=True, marker="sScAn<x>marker"):
        self.n = 0
        self.confirm = confirm
        self.marker = marker          # unique per test -> distinct prompts, no cache cross-talk

    def available(self):
        return True, ""

    def complete(self, messages, *, json_mode=False, **kw):
        self.n += 1
        if self.n == 1:
            return json.dumps({"probes": [{
                "point": 0, "param": "q", "technique": "reflected-xss",
                "payload": self.marker, "hypothesis": "reflected XSS in q",
                "look_for": "<x> unescaped"}]})
        return json.dumps({"confirmed": "true" if self.confirm else "false",
                           "severity": "HIGH", "evidence": "<x>marker",
                           "reasoning": "marker reflected unescaped"})


def _lab():
    return LabContext(host="127.0.0.1", enabled=True, attested=True,
                      audit=AuditLog(path="/tmp/celsius-test-audit.log"),
                      rate_limit_rps=50, max_requests=20)


def test_safe_payload_blocks_destructive():
    assert agent._safe_payload("sScAn<x>")
    assert agent._safe_payload("../../../etc/passwd")
    assert not agent._safe_payload("1; DROP TABLE users")
    assert not agent._safe_payload("' OR SLEEP(5)-- ")
    assert not agent._safe_payload("$(rm -rf /)")
    assert not agent._safe_payload("x" * 300)


def test_loop_confirms_reflected_xss():
    srv, base = _serve()
    try:
        lab = _lab()
        points = discover_points(base, lab)
        assert points and "q" in points[0].param_names()
        findings = agent.agentic_verify(
            {"url": base, "findings": [], "recon": {}}, points,
            _StubProvider(confirm=True, marker="sScAnPOS<x>"), lab)
        assert len(findings) == 1
        f = findings[0]
        assert f.confidence == "high"
        assert f.exploitability.get("verdict") == "confirmed-exploitable"
        assert "AI-verified" in f.title
    finally:
        srv.shutdown()


def test_loop_respects_negative_verdict():
    srv, base = _serve()
    try:
        lab = _lab()
        points = discover_points(base, lab)
        findings = agent.agentic_verify(
            {"url": base, "findings": [], "recon": {}}, points,
            _StubProvider(confirm=False, marker="sScAnNEG<x>"), lab)
        assert findings == []  # model judged not-confirmed -> nothing reported
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
