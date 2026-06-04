"""The AI triage must not let a hypothesis built on a weak (unconfirmed,
possibly distro-backport-patched) CVE carry a HIGH/CRITICAL headline."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.ai.analyze import _demote_weak_cve_hypotheses  # noqa: E402
from celsius.models import Finding, Severity  # noqa: E402


def _f(title, sev, desc=""):
    return Finding(title=title, severity=sev, category="ai-hypothesis", description=desc,
                   confidence="high")


def test_caps_hypothesis_on_weak_cve():
    cves = [{"id": "CVE-2024-6387", "confidence": "weak"}]
    f = _f("[AI] OpenSSH CVE-2024-6387 (regreSSHion) exploitation", Severity.CRITICAL)
    _demote_weak_cve_hypotheses([f], cves)
    assert f.severity is Severity.MEDIUM
    assert f.confidence == "low"
    assert "severity capped" in f.description and "CVE-2024-6387" in f.description


def test_leaves_firm_cve_hypothesis_untouched():
    cves = [{"id": "CVE-2026-42945", "confidence": "firm"}]
    f = _f("[AI] nginx CVE-2026-42945 exploitation", Severity.CRITICAL)
    _demote_weak_cve_hypotheses([f], cves)
    assert f.severity is Severity.CRITICAL            # firm → not capped


def test_leaves_unrelated_hypothesis_untouched():
    cves = [{"id": "CVE-2024-6387", "confidence": "weak"}]
    f = _f("[AI] IDOR in Express API on port 3000", Severity.HIGH)
    _demote_weak_cve_hypotheses([f], cves)
    assert f.severity is Severity.HIGH                # no weak-CVE id in text → untouched


def test_does_not_touch_below_high():
    cves = [{"id": "CVE-2024-6387", "confidence": "weak"}]
    f = _f("[AI] mentions CVE-2024-6387 in passing", Severity.LOW)
    _demote_weak_cve_hypotheses([f], cves)
    assert f.severity is Severity.LOW                 # only HIGH/CRITICAL get capped


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
