"""Tests for honest scan-coverage reporting.
Stdlib-only: run directly (`python tests/test_completeness.py`) or under pytest.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.completeness import assess_coverage  # noqa: E402
from celsius.config import ScanConfig  # noqa: E402
from celsius.models import ScanResult  # noqa: E402


def test_ip_coverage_distinguishes_ptr_cohost_and_ct_subdomains():
    result = ScanResult(target="192.0.2.10")
    coverage = assess_coverage(result, ScanConfig(target="192.0.2.10", subdomains=True))
    assert "dns" in coverage["checks_run"]
    assert "co-host-discovery" in coverage["checks_run"]
    assert "subdomains" in coverage["checks_skipped"]


def test_domain_coverage_allows_ct_subdomains():
    result = ScanResult(target="example.com")
    coverage = assess_coverage(result, ScanConfig(target="example.com", subdomains=True))
    assert "dns" in coverage["checks_run"]
    assert "co-host-discovery" in coverage["checks_run"]
    assert "subdomains" in coverage["checks_run"]


def test_ip_without_reverse_ip_option_gets_specific_next_step():
    result = ScanResult(target="192.0.2.10")
    coverage = assess_coverage(result, ScanConfig(target="192.0.2.10", subdomains=False))
    assert "enable passive reverse-IP host discovery (--subdomains)" in coverage["next_steps"]


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
