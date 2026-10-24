"""Offline regression tests for exploit-chain correlation.

Stdlib-only: run directly (`python tests/test_correlate.py`) or under pytest.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.correlate import correlate  # noqa: E402
from celsius.models import CVE, Finding, ScanResult, Severity  # noqa: E402


def _cve(cid="CVE-2026-1000", *, confidence="firm", verdict="likely-exploitable",
         reachable=True, kev=False, epss=None, verified=False, priority=90):
    signals = {"reachable": reachable, "kev": kev}
    if epss is not None:
        signals["epss"] = epss
    return CVE(
        id=cid, severity=Severity.HIGH, cvss=8.2, description="test", url="u",
        affects="nginx 1.0 (port 443/tcp)", product="nginx", version="1.0", port=443,
        confidence=confidence, verified=verified,
        exploitability={"verdict": verdict, "priority": priority, "signals": signals},
    )


def _urgent(result):
    return [c for c in correlate(result)
            if c["title"].startswith("Internet-reachable service vulnerable to")]


def test_urgent_chain_rejects_weak_and_unproven_reachability():
    result = ScanResult(target="t", cves=[
        _cve("CVE-2026-1", confidence="weak", kev=True),
        _cve("CVE-2026-2", reachable=False, epss=0.9),
        _cve("CVE-2026-3", reachable=None, epss=0.9),
    ])
    assert _urgent(result) == []


def test_kev_chain_uses_known_exploited_guidance():
    chain = _urgent(ScanResult(target="t", cves=[_cve(kev=True)]))[0]
    assert "CISA KEV" in chain["narrative"]
    assert "exploited in the wild" in chain["narrative"]
    assert "known exploited" in chain["recommendation"]


def test_high_epss_is_not_described_as_known_exploited():
    chain = _urgent(ScanResult(target="t", cves=[_cve(epss=0.91)]))[0]
    text = chain["narrative"] + " " + chain["recommendation"]
    assert "EPSS" in text and "0.910" in text
    assert "probability" in text
    assert "exploited in the wild" not in text
    assert "known exploited" not in text


def test_confirmed_cve_is_included_without_kev_or_likely_verdict():
    cve = _cve(verdict="confirmed-exploitable", epss=0.01)
    chain = _urgent(ScanResult(target="t", cves=[cve]))[0]
    assert "actively verified" in chain["narrative"]
    assert "confirmed vulnerability" in chain["recommendation"]


def test_verified_flag_is_included_and_duplicate_cves_are_deduped():
    cve = _cve(verdict="conditions-needed", verified=True)
    chains = _urgent(ScanResult(target="t", cves=[cve, cve]))
    assert len(chains) == 1
    assert "actively verified" in chains[0]["narrative"]


def test_likely_cve_without_high_epss_uses_generic_signal_language():
    chain = _urgent(ScanResult(target="t", cves=[_cve(epss=0.1)]))[0]
    assert "available signals" in chain["narrative"]
    assert "high EPSS" not in chain["narrative"]


def test_urgent_cap_prioritizes_kev_and_verified_before_generic_epss():
    cves = [
        _cve("CVE-generic-high", epss=0.99, priority=100),
        _cve("CVE-generic-mid", epss=0.95, priority=99),
        _cve("CVE-verified", verdict="confirmed-exploitable", verified=True,
             epss=0.01, priority=10),
        _cve("CVE-kev", kev=True, epss=0.0, priority=5),
        _cve("CVE-generic-low", epss=0.90, priority=98),
    ]
    chains = _urgent(ScanResult(target="t", cves=cves))
    assert len(chains) == 3
    assert [c["nodes"][1] for c in chains] == [
        "CVE-kev", "CVE-verified", "CVE-generic-high"]


def test_assess_and_correlate_default_http_and_verified_portless_cves():
    from celsius import exploitability as ex
    from celsius.models import Service

    default_http = _cve("CVE-default-http")
    default_http.port = None
    verified = _cve("CVE-verified-portless", confidence="weak",
                    verdict="conditions-needed", verified=True)
    verified.port = None
    service = Service(name="nginx", version="1.0", source="http-header:server", port=None)
    result = ScanResult(target="t", services=[service], cves=[default_http, verified])
    ex.assess(result, use_epss=False, use_kev=False)
    assert default_http.exploitability["signals"]["reachable"] is True
    assert verified.exploitability["signals"]["reachable"] is True
    chains = _urgent(result)
    assert {c["nodes"][1] for c in chains} == {"CVE-default-http", "CVE-verified-portless"}
    assert any("actively verified" in c["narrative"] for c in chains)


def test_existing_secret_and_confirmed_finding_chains_are_unchanged():
    findings = [
        Finding(title="Exposed source map recovered", severity=Severity.MEDIUM,
                category="sourcemap"),
        Finding(title="AWS access key exposed", severity=Severity.HIGH,
                category="exposed-secret"),
        Finding(title="Confirmed SQL injection", severity=Severity.HIGH, category="sqli",
                recommendation="Use parameterized queries.",
                exploitability={"verdict": "confirmed-exploitable", "priority": 90}),
    ]
    chains = correlate(ScanResult(target="t", findings=findings))
    titles = {c["title"] for c in chains}
    assert "Source-map disclosure → leaked credentials" in titles
    assert "Confirmed exploitable: Confirmed SQL injection" in titles


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
