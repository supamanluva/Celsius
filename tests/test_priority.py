"""Tests for attacker-first risk prioritisation (priority) and its use in grade.

Stdlib-only: run directly (`python tests/test_priority.py`) or under pytest.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import priority, grade  # noqa: E402


# ---- scoring ------------------------------------------------------------------

def test_unauth_exposure_outranks_theoretical_critical():
    # A HIGH exposed/unauth service should beat a CRITICAL with no exploit signal.
    exposed_high, _ = priority.score(
        severity="HIGH",
        exploitability={"verdict": "confirmed-exposed",
                        "signals": {"unauthenticated": True}})
    theoretical_crit, _ = priority.score(severity="CRITICAL")
    assert exposed_high > theoretical_crit


def test_kev_and_epss_boost_and_explain():
    s, why = priority.score(
        severity="HIGH",
        exploitability={"signals": {"kev": True, "epss": 0.7, "public_poc": True}})
    assert s > priority.score(severity="HIGH")[0]
    joined = " ".join(why).lower()
    assert "kev" in joined and "epss 70%" in joined and "public exploit" in joined


def test_default_credentials_is_top_tier():
    s, why = priority.score(
        severity="CRITICAL",
        exploitability={"verdict": "confirmed-exposed",
                        "signals": {"default_credentials": True, "unauthenticated": True}})
    assert s >= 90
    assert "default credentials accepted" in why[0]


def test_weak_confidence_halves_score():
    firm, _ = priority.score(severity="HIGH", confidence="firm")
    weak, why = priority.score(severity="HIGH", confidence="weak")
    assert weak < firm
    assert "unconfirmed match" in " ".join(why)


def test_reason_line_is_compact():
    assert priority.reason_line(["a", "b", "c"]) == "a; b"


# ---- integration with grade.assess -------------------------------------------

def test_assess_orders_attacker_first_and_adds_why():
    result = {
        "cves": [
            # theoretical critical, no exploit context
            {"id": "CVE-THEORY", "severity": "CRITICAL", "confidence": "firm"},
        ],
        "findings": [
            # exposed, unauthenticated HIGH (e.g. open Redis)
            {"title": "Redis reachable without authentication", "severity": "HIGH",
             "category": "exposure", "confidence": "high",
             "exploitability": {"verdict": "confirmed-exposed",
                                "signals": {"unauthenticated": True}}},
        ],
    }
    asmt = grade.assess(result)
    first = asmt["fix_first"][0]
    assert first["title"].startswith("Redis")          # exposure beat theoretical CRITICAL
    assert first["why"]                                 # has an explanation
    assert "unauthenticated" in first["why"]


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
