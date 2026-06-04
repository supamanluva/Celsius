"""Offline tests for the AI security advisor (stub provider, no network).

Checks the grounding contract: a clean scan needs no LLM call, and a scan with
confirmed issues returns the model's structured plan.

Stdlib-only: run directly (`python tests/test_advisor.py`) or under pytest.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.ai import analyze  # noqa: E402


class _Stub:
    name, model = "stub", "m"

    def __init__(self, payload="", *, fail=False):
        self._payload, self._fail = payload, fail
        self.calls = 0

    def available(self):
        return True, ""

    def complete(self, messages, json_mode=False):
        self.calls += 1
        if self._fail:
            raise AssertionError("provider should not be called on a clean scan")
        return self._payload


def test_clean_scan_skips_llm():
    clean = {"cves": [], "findings": [{"title": "info", "severity": "INFO", "category": "headers"}]}
    prov = _Stub(fail=True)
    adv = analyze.security_advisor(clean, prov, use_cache=False)
    assert prov.calls == 0                       # no tokens spent on a clean site
    assert adv["steps"] == [] and "No confident" in adv["headline"]


def test_returns_structured_plan_grounded_in_findings():
    payload = json.dumps({
        "headline": "Solid, with two quick header fixes.",
        "steps": [
            {"title": "Add a Content-Security-Policy", "severity": "MEDIUM",
             "why": "Limits XSS blast radius.", "fix": "Content-Security-Policy: default-src 'self'",
             "effort": "quick"},
            {"title": "ignore me", "severity": "LOW"},
        ],
        "doing_well": ["HTTPS enforced", "No exposed secrets"],
    })
    res = {"cves": [], "findings": [
        {"title": "Missing CSP", "severity": "MEDIUM", "category": "csp"}]}
    adv = analyze.security_advisor(res, _Stub(payload), use_cache=False)
    assert adv["headline"].startswith("Solid")
    assert adv["steps"][0]["fix"].startswith("Content-Security-Policy")
    assert adv["doing_well"] == ["HTTPS enforced", "No exposed secrets"]
    assert adv["grade"] and adv["score"] is not None


def test_bad_json_degrades_gracefully():
    res = {"cves": [{"id": "CVE-1", "severity": "HIGH", "confidence": "firm"}], "findings": []}
    adv = analyze.security_advisor(res, _Stub("not json"), use_cache=False)
    assert adv["steps"] == [] and "headline" in adv


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
