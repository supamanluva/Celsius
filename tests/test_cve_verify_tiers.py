"""The CVE active-verification tiers: confirmed (proven), reachable (vulnerable
code path active — the oracle tier), and an actionable manual-repro to-do for firm
high-impact CVEs a benign probe can't settle."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.models import CVE, Severity  # noqa: E402
from celsius.plugins.builtin import _cve_verify_finding, _verification_record  # noqa: E402
from celsius.ai import prompts  # noqa: E402

_URL = "https://luhn.se/"


def _cve(sev=Severity.CRITICAL, pocs=True):
    refs = [{"url": "https://github.com/x/poc", "poc": True}] if pocs else []
    return CVE(id="CVE-2026-42945", severity=sev, cvss=9.2, description="heap overflow",
               url="http://nvd/x", affects="nginx 1.29.8 (port 443/tcp)",
               product="nginx", version="1.29.8", references=refs)


def _v(status, **kw):
    return {"cve": "CVE-2026-42945", "status": status, "reasoning": "r", "evidence": "e",
            "curl": "curl -sk https://luhn.se/x", "grounded_in_poc": True, **kw}


def test_confirmed_finding():
    # 'confirmed' earns the proven tier only with an independent deterministic
    # signal in the probe evidence (corroborated=True).
    f = _cve_verify_finding(_cve(), _v("confirmed", corroborated=True), _URL)
    assert f.category == "ai-cve-verify" and "CONFIRMED" in f.title
    assert f.exploitability["verdict"] == "confirmed-exploitable"
    assert f.exploitability["signals"]["corroborated"] is True
    assert f.severity is Severity.CRITICAL


def test_confirmed_without_corroboration_downgraded_to_reachable():
    # A model 'confirmed' with no deterministic proof must NOT mint a proven,
    # confirmed-exploitable CRITICAL — it collapses into the reachable tier.
    f = _cve_verify_finding(_cve(Severity.CRITICAL), _v("confirmed"), _URL)
    assert f.category == "ai-cve-verify" and "reachable" in f.title.lower()
    assert f.exploitability["verdict"] == "likely-exploitable"
    assert f.exploitability["priority"] == 75
    assert f.severity is Severity.HIGH            # not a proven CRITICAL
    assert "verify by hand" in f.description.lower()


def test_reachable_finding_capped_at_high():
    f = _cve_verify_finding(_cve(Severity.CRITICAL), _v("reachable"), _URL)
    assert f.category == "ai-cve-verify" and "reachable" in f.title.lower()
    assert f.exploitability["verdict"] == "likely-exploitable"
    assert f.severity is Severity.HIGH            # CRITICAL capped to HIGH (not proven)


def test_needs_manual_on_high_impact_is_actionable():
    f = _cve_verify_finding(_cve(Severity.CRITICAL, pocs=True), _v("needs-manual"), _URL)
    assert f.category == "ai-cve-manual"
    assert f.severity is Severity.MEDIUM          # to-do, not a confirmed CRITICAL
    rec = f.recommendation
    assert "Target: https://luhn.se/" in rec
    assert "nginx 1.29.8" in rec
    assert "github.com/x/poc" in rec              # the manual repro hands over the PoC


def test_low_impact_unsettled_makes_no_finding():
    assert _cve_verify_finding(_cve(Severity.MEDIUM, pocs=False), _v("needs-manual"), _URL) is None
    assert _cve_verify_finding(_cve(Severity.MEDIUM, pocs=False), _v("inconclusive"), _URL) is None


def test_refuted_makes_no_finding():
    assert _cve_verify_finding(_cve(), _v("refuted"), _URL) is None


def test_verification_record_has_manual_repro():
    rec = _verification_record(_cve(), _v("needs-manual"), _URL)
    assert rec["status"] == "needs-manual" and rec["poc_grounded"] is True
    mr = rec["manual_repro"]
    assert mr["target"] == _URL and "nginx 1.29.8" in mr["matched"]
    assert mr["public_poc"] == ["https://github.com/x/poc"]


def test_schemas_expose_oracle_tier():
    assert "goal" in prompts.CVE_VERIFY_SCHEMA
    assert "reachable" in prompts.CVE_JUDGE_SCHEMA["status"]


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
