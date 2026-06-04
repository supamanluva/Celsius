"""Offline tests for AI CVE-verification candidate selection.

The LLM/probe loop itself needs a provider + lab and isn't unit-tested here; we
test the pure gate that decides which CVEs are worth an active probe: firm only
(weak/distro-downgraded matches are likely backport FPs), not already verified,
highest severity first, public-PoC first, capped.

Stdlib-only: run directly (`python tests/test_ai_cve_verify.py`) or under pytest.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.ai import agent  # noqa: E402


def _cve(cid, sev="HIGH", confidence="firm", verified=False, poc=False):
    refs = [{"url": "https://github.com/x/poc", "poc": True}] if poc else []
    return {"id": cid, "severity": sev, "confidence": confidence,
            "verified": verified, "references": refs}


def test_skips_weak_and_verified():
    cves = [_cve("CVE-firm"), _cve("CVE-weak", confidence="weak"),
            _cve("CVE-done", verified=True)]
    ids = [c["id"] for c in agent.cve_candidates(cves)]
    assert ids == ["CVE-firm"]


def test_orders_by_severity_then_poc():
    cves = [_cve("CVE-med", sev="MEDIUM"),
            _cve("CVE-crit", sev="CRITICAL"),
            _cve("CVE-high-poc", sev="HIGH", poc=True),
            _cve("CVE-high", sev="HIGH")]
    ids = [c["id"] for c in agent.cve_candidates(cves)]
    # CRITICAL first; among the two HIGHs the one with a public PoC ranks higher
    assert ids[0] == "CVE-crit"
    assert ids.index("CVE-high-poc") < ids.index("CVE-high")
    assert ids[-1] == "CVE-med"


def test_caps_count():
    cves = [_cve(f"CVE-{i}") for i in range(20)]
    assert len(agent.cve_candidates(cves, max_cves=5)) == 5


def test_poc_refs_extracts_only_flagged():
    cve = {"references": [{"url": "https://nvd.nist.gov/x", "poc": False},
                          {"url": "https://exploit-db.com/y", "poc": True},
                          {"url": "", "poc": True}]}
    assert agent._poc_refs(cve) == ["https://exploit-db.com/y"]


def test_empty_when_nothing_firm():
    assert agent.cve_candidates([_cve("CVE-weak", confidence="weak")]) == []
    assert agent.cve_candidates([]) == []


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
