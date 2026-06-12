"""Attacker-first risk prioritisation.

Severity alone is a poor sort key: a theoretical CRITICAL with no known exploit
matters less than a HIGH that is internet-exposed, unauthenticated, and on CISA's
known-exploited list. This blends the confident signals Celsius already gathers —
severity, KEV membership, EPSS probability, public-PoC availability, exposure /
unauthenticated access, and active verification — into a single 0-100 risk score
plus a short, human "why" explaining the rank.

Used to order the "fix these first" list and to annotate each item with the
reason it floated to the top.
"""

from __future__ import annotations

from typing import Optional

_SEV_BASE = {"CRITICAL": 55, "HIGH": 40, "MEDIUM": 20, "LOW": 8, "INFO": 0}


def score(*, severity: str, exploitability: Optional[dict] = None,
          confidence: str = "firm", verified: bool = False) -> tuple[int, list[str]]:
    """Return (risk 0-100, reasons) for one CVE/finding.

    The reasons are ordered most-to-least decisive so the first one or two make a
    good one-line explanation."""
    expl = exploitability or {}
    sig = expl.get("signals") or {}
    verdict = expl.get("verdict", "")
    s = float(_SEV_BASE.get(severity, 0))
    why: list[str] = []

    # Exposure / missing auth — the signals from the exposed-services and
    # default-creds checks; an attacker needs no exploit at all here.
    if sig.get("default_credentials"):
        s += 38
        why.append("default credentials accepted")
    if sig.get("unauthenticated"):
        s += 30
        why.append("internet-exposed & unauthenticated")
    elif verdict == "confirmed-exposed":
        s += 24
        why.append("confirmed internet-exposed")

    # Known-exploited (CISA KEV) — strongest CVE signal.
    if sig.get("kev"):
        s += 30
        why.append("actively exploited in the wild (CISA KEV)")

    # EPSS — probability of exploitation in the next 30 days.
    epss = sig.get("epss")
    if isinstance(epss, (int, float)):
        if epss >= 0.5:
            s += 20
            why.append(f"high exploitation probability (EPSS {epss * 100:.0f}%)")
        elif epss >= 0.1:
            s += 10
            why.append(f"elevated exploitation probability (EPSS {epss * 100:.0f}%)")

    if sig.get("public_poc"):
        s += 12
        why.append("public exploit/PoC available")

    # Confirmed-real issues should be actioned ahead of a same-or-one-tier-higher
    # "maybe" — a verified HIGH outranks an unverified CRITICAL.
    if verified or sig.get("actively_verified") or sig.get("verified"):
        s += 18
        why.append("actively verified")
    elif sig.get("reachable"):
        s += 4
        why.append("reachable")

    # Unconfirmed matches shouldn't outrank confirmed problems.
    if confidence == "weak":
        s *= 0.5
        why.append("unconfirmed match")

    return int(min(100, max(0, round(s)))), why


def reason_line(why: list[str], limit: int = 2) -> str:
    """A compact one-line 'why' from the top reasons."""
    return "; ".join(why[:limit])
