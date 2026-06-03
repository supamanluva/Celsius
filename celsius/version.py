"""Minimal version comparison for CVE range matching.

Handles dotted numeric versions (1.29.6, 1.30.1) plus optional trailing
suffixes (1.30.0p1). Good enough for the semver-ish versions used by web
servers; not a full PEP 440 / semver implementation.
"""

from __future__ import annotations

import re
from typing import Optional

_NUM = re.compile(r"\d+")

# sentinel for "*" / unbounded
INF = (10**9,)


def parse(v: str) -> tuple[int, ...]:
    """Turn '1.29.6' into (1, 29, 6). '*' / '-' / '' -> empty tuple."""
    if v is None:
        return ()
    v = v.strip()
    if v in ("*", "-", ""):
        return INF if v == "*" else ()
    parts = _NUM.findall(v)
    return tuple(int(p) for p in parts) if parts else ()


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def lt(a: str, b: str) -> bool:
    return _cmp(parse(a), parse(b)) < 0


def le(a: str, b: str) -> bool:
    return _cmp(parse(a), parse(b)) <= 0


def eq(a: str, b: str) -> bool:
    return _cmp(parse(a), parse(b)) == 0


def in_range(
    version: str,
    *,
    start_incl: Optional[str] = None,
    start_excl: Optional[str] = None,
    end_incl: Optional[str] = None,
    end_excl: Optional[str] = None,
    exact: Optional[str] = None,
) -> bool:
    """True if `version` satisfies the given bounds.

    `exact` (if set, and not '*') requires equality. Otherwise the start/end
    bounds define a half-open or closed interval.
    """
    pv = parse(version)
    if not pv:
        return False

    if exact and exact not in ("*", "-"):
        # An exact CPE version with no range -> equality only.
        if not any([start_incl, start_excl, end_incl, end_excl]):
            return _cmp(pv, parse(exact)) == 0

    if start_incl and _cmp(pv, parse(start_incl)) < 0:
        return False
    if start_excl and _cmp(pv, parse(start_excl)) <= 0:
        return False
    if end_incl and _cmp(pv, parse(end_incl)) > 0:
        return False
    if end_excl and _cmp(pv, parse(end_excl)) >= 0:
        return False
    # If we got here with at least one bound (or a wildcard exact), it matches.
    if any([start_incl, start_excl, end_incl, end_excl]):
        return True
    # CPE 2.3 version semantics: '*' (ANY) matches every version, but '-' (NA,
    # "not applicable") means the product has NO version for this CVE — it must
    # NOT match a concrete detected version. Treating '-' as a wildcard produced
    # CRITICAL false positives (e.g. 2008-era IIS ActiveX CVEs with version '-'
    # matching IIS 8.5). Only '*' is a wildcard.
    if exact == "*":
        return True
    return False
