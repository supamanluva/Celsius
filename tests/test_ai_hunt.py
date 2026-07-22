"""Tests for the AI hunt planner (ai/hunt.py): context grounding, hypothesis
parsing/capping, and redaction — all with a stubbed provider, no network."""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.ai import hunt  # noqa: E402
from celsius.ai import cache as cache_mod  # noqa: E402
from celsius.models import Severity  # noqa: E402


def _bypass_cache():
    """Force provider.complete() to run (the disk cache would otherwise short-
    circuit it on a re-run). conftest restores cache.get after each test."""
    cache_mod.get = lambda *a, **k: None


class _StubProvider:
    name = "stub"
    model = "stub"

    def __init__(self, reply):
        self.reply = reply
        self.messages = None

    def complete(self, messages, *, json_mode=False, **kw):
        self.messages = messages
        return self.reply


def _result():
    return {
        "target": "example.com", "url": "https://example.com",
        "services": [{"name": "http", "port": 443, "version": "nginx 1.18"}],
        "cves": [{"id": "CVE-2021-41773", "severity": "CRITICAL", "confidence": "firm"}],
        "findings": [{"title": "Missing CSP", "category": "headers", "severity": "MEDIUM"}],
        "recon": {"tech": ["nginx", "PHP"], "subdomains": ["dev.example.com"],
                  "exposed_paths": ["/.git/HEAD"]},
    }


def test_valid_json_becomes_hypothesis_findings():
    _bypass_cache()
    p = _StubProvider(json.dumps({"hypotheses": [
        {"title": "git repo exposed", "category": "debug-endpoint",
         "rationale": "/.git/HEAD found", "suggested_tool": "http_get",
         "severity_guess": "HIGH"}]}))
    out = hunt.generate_hunt_hypotheses(_result(), p)
    assert len(out) == 1
    f = out[0]
    assert f.category == "ai-hypothesis"
    assert f.confidence == "low"
    assert f.title.startswith("[AI hunt] ")
    assert f.severity == Severity.HIGH


def test_malformed_items_dropped_individually():
    _bypass_cache()
    p = _StubProvider(json.dumps({"hypotheses": [
        {"title": ""},                        # empty title -> drop
        {"not_title": 1},                     # garbage -> drop
        {"title": "ok one", "rationale": "r"}]}))
    out = hunt.generate_hunt_hypotheses(_result(), p)
    assert [f.title for f in out] == ["[AI hunt] ok one"]
    assert out[0].severity == Severity.LOW    # no severity_guess -> LOW


def test_cap_enforced():
    _bypass_cache()
    p = _StubProvider(json.dumps({"hypotheses": [
        {"title": f"h{i}"} for i in range(20)]}))
    out = hunt.generate_hunt_hypotheses(_result(), p, max_hypotheses=10)
    assert len(out) == 10


def test_garbage_response_yields_nothing():
    _bypass_cache()
    p = _StubProvider("not json at all")
    assert hunt.generate_hunt_hypotheses(_result(), p) == []


def test_wrong_shape_json_yields_nothing():
    """Valid JSON of the wrong shape must not raise — just zero hypotheses."""
    _bypass_cache()
    # {"hypotheses": 5} — the key exists but is not a list
    p = _StubProvider(json.dumps({"hypotheses": 5}))
    assert hunt.generate_hunt_hypotheses(_result(), p) == []
    # [1, 2, 3] — parses fine but is not an object at all
    p = _StubProvider(json.dumps([1, 2, 3]))
    assert hunt.generate_hunt_hypotheses(_result(), p) == []


def test_context_carries_recon_evidence():
    _bypass_cache()
    p = _StubProvider(json.dumps({"hypotheses": []}))
    hunt.generate_hunt_hypotheses(_result(), p)
    user = next(m.content for m in p.messages if m.role == "user")
    assert "CVE-2021-41773" in user
    assert "dev.example.com" in user
    assert "nginx" in user


def test_redaction_applied_to_model_context():
    _bypass_cache()
    seen = {}
    orig = hunt.redact_obj

    def spy(obj, *, enabled=False):
        seen["enabled"] = enabled
        return orig(obj, enabled=enabled)

    hunt.redact_obj = spy
    try:
        hunt.generate_hunt_hypotheses(_result(), _StubProvider(json.dumps({"hypotheses": []})),
                                      redact_secrets=True)
    finally:
        hunt.redact_obj = orig
    assert seen["enabled"] is True


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
    sys.exit(1 if failed else 0)
