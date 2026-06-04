"""Offline tests for the domain rollup report + host parsing."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import report  # noqa: E402
from celsius.store import _host_of  # noqa: E402


def test_host_of_variants():
    assert _host_of("https://luhn.se/path") == "luhn.se"
    assert _host_of("copy.luhn.se") == "copy.luhn.se"
    assert _host_of("http://x.luhn.se:8080/a") == "x.luhn.se"
    assert _host_of("https://user@h.test/") == "h.test"
    assert _host_of("https://[::1]:443/") == "::1"


def _scan(host, cves=None, findings=None, ip="203.0.113.1"):
    return {"target": f"https://{host}", "url": f"https://{host}/", "ip": ip,
            "finished_at": "2026-06-03T18:00:00Z",
            "services": [{"name": "nginx"}],
            "cves": cves or [], "findings": findings or []}


def test_rollup_aggregates_and_excludes_weak():
    scans = [
        _scan("luhn.se",
              cves=[{"id": "CVE-1", "severity": "CRITICAL", "confidence": "firm", "affects": "nginx"},
                    {"id": "CVE-2", "severity": "CRITICAL", "confidence": "weak", "affects": "openssh"}],
              findings=[{"severity": "MEDIUM", "title": "Missing CSP", "category": "csp"}]),
        _scan("api.luhn.se",
              findings=[{"severity": "HIGH", "title": "Exposed .env", "category": "exposure"},
                        {"severity": "CRITICAL", "title": "[AI] Auth bypass", "category": "ai-hypothesis"}]),
    ]
    html = report.domain_rollup_html("luhn.se", scans)
    assert "luhn.se" in html and "api.luhn.se" in html
    # both hosts get a section
    assert html.count("<h2 id='h-") == 2
    # weak CVE excluded from headline counts: 1 CRITICAL (firm), not 2
    assert "CRITICAL 1" in html
    # the weak one surfaces as UNCONFIRMED
    assert "UNCONFIRMED 1" in html
    assert "203.0.113.1" in html and "unique IP" in html
    # AI hypothesis excluded from headline (still 1 CRITICAL from the firm CVE, not 2)
    assert "CRITICAL 1" in html and "AI LEADS 1" in html


def test_rollup_groups_shared_ip_cves_once():
    # two hosts on the same IP share a firm service CVE — it should appear once in
    # a "Shared infrastructure" section listing both hosts, not as two problems.
    cve = [{"id": "CVE-9", "severity": "HIGH", "confidence": "firm", "affects": "OpenSSH"}]
    scans = [_scan("luhn.se", cves=cve, ip="203.0.113.9"),
             _scan("www.luhn.se", cves=cve, ip="203.0.113.9"),
             _scan("other.luhn.se", ip="203.0.113.50")]  # different IP, no CVEs
    html = report.domain_rollup_html("luhn.se", scans)
    assert "Shared infrastructure" in html
    # the shared IP lists both hosts that share it
    import re
    section = re.search(r"Shared infrastructure.*?</table>", html, re.S).group(0)
    assert "luhn.se" in section and "www.luhn.se" in section
    assert "203.0.113.9" in section
    # the lone-IP host (no shared CVEs) is not its own shared row
    assert "203.0.113.50" not in section
    # headline still counts the shared CVE once (deduped per IP)
    assert "HIGH 1" in html


def test_rollup_empty_is_friendly():
    html = report.domain_rollup_html("nothing.test", [])
    assert "No stored scans" in html and "nothing.test" in html


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
