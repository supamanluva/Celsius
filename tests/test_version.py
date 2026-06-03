"""Tests for CPE/semver version-range matching.

Stdlib-only: run directly (`python tests/test_version.py`) or under pytest.

Regression anchor: a CPE version field of '-' (CPE 2.3 "Not Applicable") must
NOT behave like '*' (ANY). Treating '-' as a wildcard made 2008-era IIS ActiveX
CVEs (CVE-2008-4300/4301, whose CPE version is '-') match a detected IIS 8.5 and
surface as a CRITICAL false positive.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import version as vc  # noqa: E402


def test_dash_is_not_a_wildcard():
    # '-' (Not Applicable) must not match a concrete version...
    assert vc.in_range("8.5", exact="-") is False
    assert vc.in_range("1.0.0", exact="-") is False
    # ...while '*' (ANY) still matches everything.
    assert vc.in_range("8.5", exact="*") is True
    assert vc.in_range("1.0.0", exact="*") is True


def test_exact_equality():
    assert vc.in_range("8.5", exact="8.5") is True
    assert vc.in_range("8.5", exact="8.0") is False
    assert vc.in_range("2.4.57", exact="2.4.57") is True


def test_ranges():
    # half-open [start, end)
    assert vc.in_range("1.2.3", start_incl="1.0", end_excl="2.0") is True
    assert vc.in_range("2.0", start_incl="1.0", end_excl="2.0") is False
    assert vc.in_range("0.9", start_incl="1.0", end_excl="2.0") is False
    # inclusive end
    assert vc.in_range("2.0", start_incl="1.0", end_incl="2.0") is True
    # exclusive start
    assert vc.in_range("1.0", start_excl="1.0", end_incl="2.0") is False


def test_unparseable_version_never_matches():
    assert vc.in_range("", exact="*") is False
    assert vc.in_range("notaversion", start_incl="1.0", end_excl="2.0") is False


def test_dash_with_bounds_still_uses_bounds():
    # If a CPE is version '-' but carries range bounds, the bounds govern.
    assert vc.in_range("1.5", exact="-", start_incl="1.0", end_excl="2.0") is True
    assert vc.in_range("2.5", exact="-", start_incl="1.0", end_excl="2.0") is False


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
