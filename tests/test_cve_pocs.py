"""Offline tests for the trickest/cve public-exploit enrichment."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import cve  # noqa: E402
from celsius.models import CVE, Severity  # noqa: E402

_SAMPLE = """\
### [CVE-2024-TEST](https://nvd.nist.gov/vuln/detail/CVE-2024-TEST)
### Description
A test vulnerability.
### POC
#### Reference
- https://advisory.example/CVE-2024-TEST
#### Github
- https://github.com/alice/poc1
- https://github.com/bob/exploit2
- not-a-url line
"""


def _patch(by_id):
    cve._get_text = lambda url: next((md for cid, md in by_id.items() if cid in url), "")


def test_parses_only_github_section():
    _patch({"CVE-2024-TEST": _SAMPLE})
    pocs = cve.trickest_pocs("CVE-2024-TEST")
    assert pocs == ["https://github.com/alice/poc1", "https://github.com/bob/exploit2"]
    # the Reference-section advisory URL is NOT included
    assert all("advisory.example" not in p for p in pocs)


def test_unknown_cve_is_empty():
    _patch({})  # every fetch returns ""
    assert cve.trickest_pocs("CVE-2024-NONE") == []


def test_bad_id_is_empty():
    assert cve.trickest_pocs("not-a-cve") == []


def test_enrich_firm_only():
    _patch({"CVE-2024-TEST": _SAMPLE})
    firm = CVE(id="CVE-2024-TEST", severity=Severity.HIGH, cvss=8.0, description="", url="",
               confidence="firm")
    weak = CVE(id="CVE-2024-OTHER", severity=Severity.HIGH, cvss=8.0, description="", url="",
               confidence="weak")
    n = cve.enrich_pocs([firm, weak])
    assert n == 1
    assert len(firm.references) == 2 and all(r["poc"] for r in firm.references)
    assert firm.references[0]["source"] == "trickest"
    assert weak.references == []                 # weak skipped entirely


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
