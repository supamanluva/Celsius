"""Minimal version comparison for CVE range matching.

Handles dotted numeric versions (1.29.6, 1.30.1) plus optional trailing
suffixes (1.30.0p1). Good enough for the semver-ish versions used by web
servers; not a full PEP 440 / semver implementation.
"""

from __future__ import annotations

import re
from typing import Optional

_PARTS = re.compile(r"\d+|[A-Za-z]+")

# Multi-character pre-release words (sort BELOW the matching release). Single
# letters are NOT here — in OpenSSL's scheme a trailing letter is a *post*-release
# patch (1.1.1a comes after 1.1.1), which is the common real-world case.
_PRE = {"rc", "alpha", "beta", "pre", "preview", "dev", "snapshot", "nightly",
        "milestone", "pl"}

# sentinel for "*" / unbounded
INF = (10**9,)


def _letter_ord(s: str) -> int:
    """'a'->1 ... 'z'->26, 'aa'->27 ... — orders OpenSSL letter releases."""
    n = 0
    for ch in s.lower():
        if "a" <= ch <= "z":
            n = n * 26 + (ord(ch) - 96)
    return n


def parse(v: str) -> tuple[int, ...]:
    """Turn '1.29.6' into (1, 29, 6).

    Trailing release letters (OpenSSL '1.1.1w') become an extra ordinal so letter
    releases discriminate correctly — '1.1.1f' < '1.1.1t' — instead of all
    collapsing to (1,1,1) (which made every OpenSSL letter-release CVE a silent
    miss). Pre-release tags ('-rc1', 'beta') sort BELOW the matching release.
    A letter immediately followed by digits (OpenSSH '8.1p1') stays a separator,
    preserving the existing numeric behaviour. '*' -> INF, '-'/'' -> ().
    """
    if v is None:
        return ()
    v = v.strip()
    if v in ("*", "-", ""):
        return INF if v == "*" else ()
    toks = _PARTS.findall(v)
    nums: list[int] = []
    tail = 0  # extra trailing component: <0 pre-release, 0 plain, >0 letter patch
    for idx, tok in enumerate(toks):
        if tok.isdigit():
            nums.append(int(tok))
            continue
        low = tok.lower()
        is_last = idx == len(toks) - 1
        nxt = toks[idx + 1] if not is_last else ""
        if low in _PRE:
            # pre-release: -1000 base keeps every pre-release below the release (0)
            tail = -1000 + (int(nxt) if nxt.isdigit() else 0)
            break
        if is_last and 1 <= len(low) <= 3:
            tail = _letter_ord(low)          # OpenSSL-style post-release letter
        # else: a letter followed by digits (e.g. 'p' in 8.1p1) — a separator
    if not nums:
        return ()
    return tuple(nums) + ((tail,) if tail else ())


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
