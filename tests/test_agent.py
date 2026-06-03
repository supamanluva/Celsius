"""Offline tests for the AI hypothesis-proving loop (tools + verdict application).

The LLM and the lab harness are faked, so the plan -> tool -> judge -> verdict
flow and the confirm/refute/keep rewriting are exercised without a network.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.ai import agent, verify_tools  # noqa: E402
from celsius.models import Finding, Severity  # noqa: E402


class _Resp:
    def __init__(self, status=200, body="", headers=None, location=None, final_url=""):
        self.status, self.body = status, body
        self.headers = headers or {}
        self.location, self.final_url = location, final_url


class _Lab:
    host = "z.luhn.se"
    _count = 0
    stopped_reason = None

    def can_send(self):
        return (True, "")

    def send(self, url, **_k):
        return _Resp(status=200, body="<title>ZNC - login</title> Please log in",
                     headers={"server": "Caddy"}, final_url=url)


def test_tools_are_host_locked():
    lab = _Lab()
    ok = verify_tools.run_tool("http_get", {"url": "https://z.luhn.se:8443/"}, lab)
    assert ok["status"] == 200 and "ZNC" in ok["title"]
    off = verify_tools.run_tool("http_get", {"url": "https://evil.example/"}, lab)
    assert off.get("error"), "off-scope host must be refused"
    bad = verify_tools.run_tool("tcp_connect", {"host": "evil.example", "port": 22}, lab)
    assert bad.get("error")


def test_apply_verdicts_confirm_refute_keep():
    finds = [
        Finding(title="Missing CSP", severity=Severity.MEDIUM, category="csp"),
        Finding(title="[AI] ZNC default creds", severity=Severity.CRITICAL, category="ai-hypothesis"),
        Finding(title="[AI] Subdomain takeover", severity=Severity.HIGH, category="ai-hypothesis"),
        Finding(title="[AI] IDOR in API", severity=Severity.HIGH, category="ai-hypothesis"),
    ]
    verdicts = [
        {"index": 0, "status": "confirmed", "severity": "HIGH", "tool": "http_get", "evidence": "ZNC login reachable"},
        {"index": 1, "status": "refuted", "tool": "takeover_check", "evidence": "no dangling CNAME"},
        {"index": 2, "status": "needs-manual", "tool": "none"},
    ]
    out, stats = agent.apply_verdicts(finds, verdicts)
    titles = [f.title for f in out]
    # confirmed -> retagged so it counts toward severity, downgraded to HIGH
    conf = next(f for f in out if "ZNC" in f.title)
    assert conf.title.startswith("[AI-verified]") and conf.category == "ai-active-verify"
    assert conf.severity == Severity.HIGH
    # refuted -> dropped
    assert not any("takeover" in t.lower() for t in titles)
    # needs-manual -> kept as a hypothesis, annotated
    idor = next(f for f in out if "IDOR" in f.title)
    assert idor.category == "ai-hypothesis" and "unconfirmed" in idor.description.lower()
    # non-AI finding untouched
    assert any(t == "Missing CSP" for t in titles)
    assert stats == {"confirmed": 1, "refuted": 1, "needs_manual": 1, "untested": 0}


def test_prove_hypotheses_end_to_end():
    responses = [
        '{"plans": [{"hypothesis": 0, "tool": "http_get", "args": {"url": "https://z.luhn.se:8443/"}}]}',
        '{"status": "confirmed", "severity": "HIGH", "evidence": "ZNC login page reachable"}',
    ]
    saved = agent._call
    agent._call = lambda *a, **k: responses.pop(0)
    try:
        verdicts = agent.prove_hypotheses(
            {"url": "https://z.luhn.se", "services": []},
            [{"title": "[AI] ZNC exposed on 8443", "description": "ZNC reachable"}],
            provider=object(), lab=_Lab())
    finally:
        agent._call = saved
    assert len(verdicts) == 1
    assert verdicts[0]["status"] == "confirmed" and verdicts[0]["tool"] == "http_get"


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
