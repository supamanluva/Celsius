"""Overall security-health grade for a scan — a trustworthy top-line a site
owner can read at a glance: a letter grade, a 0-100 score, and a prioritized
"fix these first" list.

Only CONFIDENT signals count toward the grade: firm or live-verified CVEs and
confirmed findings (unverified weak matches, AI hypotheses, and INFO items are
excluded). A clean grade therefore means something — it isn't dragged down by maybes.
"""

from __future__ import annotations

from . import priority
from .models import severity_rank

# Per-issue penalty subtracted from 100. A confirmed CRITICAL should dominate, an
# INFO costs nothing. Caps below stop "many small issues" from masking a big one.
_PENALTY = {"CRITICAL": 55, "HIGH": 25, "MEDIUM": 8, "LOW": 2, "INFO": 0}
_GRADE = [(95, "A+"), (85, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]
_SKIP_CATEGORIES = {"ai-hypothesis", "ai-summary"}


def _confident_cve(c: dict) -> bool:
    return c.get("confidence", "firm") != "weak" or bool(c.get("verified"))


def _firm_cves(d: dict) -> list:
    return [c for c in d.get("cves", []) if _confident_cve(c)]


def _real_finding(f: dict) -> bool:
    return f.get("category") not in _SKIP_CATEGORIES and f.get("severity") != "INFO"


def _real_findings(d: dict) -> list:
    return [f for f in d.get("findings", []) if _real_finding(f)]


def _cve_fix(c: dict) -> str:
    prod = c.get("product") or "the affected component"
    ver = f" (currently {c['version']})" if c.get("version") else ""
    return f"Update {prod}{ver} to a fixed release; see {c.get('url', 'the advisory')}."


def assess(result_dict: dict) -> dict:
    """Return {grade, score, clean, counts, fix_first[...]} for one scan.

    `fix_first` items include kind and source_index (the original position in that
    kind's list), plus severity, verification, title, detail, fix, and risk reasons.
    """
    items: list[dict] = []
    for source_index, c in enumerate(result_dict.get("cves", [])):
        if not _confident_cve(c):
            continue
        risk, why = priority.score(
            severity=c.get("severity", "INFO"), exploitability=c.get("exploitability"),
            confidence=c.get("confidence", "firm"), verified=bool(c.get("verified")))
        items.append({
            "kind": "cve", "source_index": source_index,
            "severity": c.get("severity", "INFO"),
            "verified": bool(c.get("verified")),
            "title": c.get("id", "CVE"),
            "detail": (c.get("description") or "")[:160],
            "fix": _cve_fix(c),
            "why": priority.reason_line(why), "_risk": risk,
        })
    for source_index, f in enumerate(result_dict.get("findings", [])):
        if not _real_finding(f):
            continue
        risk, why = priority.score(
            severity=f.get("severity", "INFO"), exploitability=f.get("exploitability"),
            confidence=f.get("confidence", "firm"), verified=f.get("confidence") == "high")
        items.append({
            "kind": "finding", "source_index": source_index,
            "severity": f.get("severity", "INFO"),
            "verified": f.get("confidence") == "high",
            "title": f.get("title", ""),
            "detail": (f.get("description") or "")[:160],
            "fix": f.get("recommendation") or "",
            "why": priority.reason_line(why), "_risk": risk,
        })

    score = max(0, 100 - sum(_PENALTY.get(it["severity"], 0) for it in items))
    sevset = {it["severity"] for it in items}
    # A confident high-impact issue caps the ceiling regardless of the arithmetic.
    if "CRITICAL" in sevset:
        score = min(score, 40)        # at best D
    elif "HIGH" in sevset:
        score = min(score, 65)        # at best C
    grade = next(g for thr, g in _GRADE if score >= thr)

    # Attacker-first ordering: blended risk score, then severity as a tiebreak.
    items.sort(key=lambda it: (it["_risk"], severity_rank(it["severity"])), reverse=True)
    for it in items:
        it.pop("_risk", None)

    return {
        "grade": grade, "score": score, "clean": not items,
        "counts": {s: sum(1 for it in items if it["severity"] == s)
                   for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "fix_first": items[:6],
        "total_actionable": len(items),
    }
