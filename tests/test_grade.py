"""Offline tests for the overall security-health grade.

A clean grade must mean something: only firm CVEs and confirmed (non-INFO,
non-AI-hypothesis) findings count. Stdlib-only: run directly or under pytest.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import grade  # noqa: E402


def _r(cves=None, findings=None):
    return {"cves": cves or [], "findings": findings or []}


def test_clean_is_top_grade():
    a = grade.assess(_r())
    assert a["clean"] is True and a["grade"] == "A+" and a["score"] == 100
    assert a["fix_first"] == []


def test_weak_cves_and_ai_leads_do_not_count():
    a = grade.assess(_r(
        cves=[{"id": "CVE-x", "severity": "CRITICAL", "confidence": "weak"}],
        findings=[{"title": "[AI] guess", "severity": "CRITICAL", "category": "ai-hypothesis"},
                  {"title": "info note", "severity": "INFO", "category": "headers"}]))
    # none of these are confident problems -> still a clean A+
    assert a["clean"] is True and a["grade"] == "A+"


def test_firm_critical_caps_to_F_or_D():
    a = grade.assess(_r(cves=[{"id": "CVE-1", "severity": "CRITICAL", "confidence": "firm"}]))
    assert a["score"] <= 40 and a["grade"] in ("D", "F")
    assert a["counts"]["CRITICAL"] == 1


def test_firm_high_caps_to_C():
    a = grade.assess(_r(findings=[{"title": "TLS mismatch", "severity": "HIGH",
                                    "category": "tls"}]))
    assert a["score"] <= 65 and a["grade"] in ("C", "D", "F")


def test_mediums_lower_but_not_fail():
    a = grade.assess(_r(findings=[
        {"title": "No CSP", "severity": "MEDIUM", "category": "csp"},
        {"title": "No HSTS", "severity": "MEDIUM", "category": "headers"}]))
    assert a["grade"] in ("B", "C") and not a["clean"]


def test_fix_first_orders_verified_then_severity():
    a = grade.assess(_r(
        cves=[{"id": "CVE-hi", "severity": "HIGH", "confidence": "firm", "verified": True},
              {"id": "CVE-crit", "severity": "CRITICAL", "confidence": "firm", "verified": False}]))
    # verified ranks ahead of an unverified higher severity
    assert a["fix_first"][0]["title"] == "CVE-hi"
    assert a["fix_first"][0]["verified"] is True


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
