"""Overall security-health grade for a scan — a trustworthy top-line a site
owner can read at a glance: a letter grade, a 0-100 score, and a prioritized
"fix these first" list.

Only CONFIDENT signals count toward the grade: firm CVEs (weak/over-broad and
distro-backported matches are excluded) and confirmed findings (AI hypotheses
are "leads, not facts" and INFO items are not problems). A clean grade therefore
means something — it isn't dragged down by maybes.
"""

from __future__ import annotations

# Per-issue penalty subtracted from 100. A confirmed CRITICAL should dominate, an
# INFO costs nothing. Caps below stop "many small issues" from masking a big one.
_PENALTY = {"CRITICAL": 55, "HIGH": 25, "MEDIUM": 8, "LOW": 2, "INFO": 0}
_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_GRADE = [(95, "A+"), (85, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]
_SKIP_CATEGORIES = {"ai-hypothesis", "ai-summary"}


def _firm_cves(d: dict) -> list:
    return [c for c in d.get("cves", []) if c.get("confidence", "firm") != "weak"]


def _real_findings(d: dict) -> list:
    return [f for f in d.get("findings", [])
            if f.get("category") not in _SKIP_CATEGORIES and f.get("severity") != "INFO"]


def _cve_fix(c: dict) -> str:
    prod = c.get("product") or "the affected component"
    ver = f" (currently {c['version']})" if c.get("version") else ""
    return f"Update {prod}{ver} to a fixed release; see {c.get('url', 'the advisory')}."


def assess(result_dict: dict) -> dict:
    """Return {grade, score, clean, counts, fix_first[...]} for one scan.

    `fix_first` items: {kind, severity, verified, title, detail, fix} ordered
    verified-first, then by severity, then exploit priority — the order a site
    owner should work through.
    """
    items: list[dict] = []
    for c in _firm_cves(result_dict):
        items.append({
            "kind": "cve", "severity": c.get("severity", "INFO"),
            "verified": bool(c.get("verified")),
            "title": c.get("id", "CVE"),
            "detail": (c.get("description") or "")[:160],
            "fix": _cve_fix(c),
            "_priority": (c.get("exploitability") or {}).get("priority", 0),
        })
    for f in _real_findings(result_dict):
        items.append({
            "kind": "finding", "severity": f.get("severity", "INFO"),
            "verified": f.get("confidence") == "high",
            "title": f.get("title", ""),
            "detail": (f.get("description") or "")[:160],
            "fix": f.get("recommendation") or "",
            "_priority": (f.get("exploitability") or {}).get("priority", 0),
        })

    score = max(0, 100 - sum(_PENALTY.get(it["severity"], 0) for it in items))
    sevset = {it["severity"] for it in items}
    # A confident high-impact issue caps the ceiling regardless of the arithmetic.
    if "CRITICAL" in sevset:
        score = min(score, 40)        # at best D
    elif "HIGH" in sevset:
        score = min(score, 65)        # at best C
    grade = next(g for thr, g in _GRADE if score >= thr)

    items.sort(key=lambda it: (it["verified"], _RANK.get(it["severity"], 0), it["_priority"]),
               reverse=True)
    for it in items:
        it.pop("_priority", None)

    return {
        "grade": grade, "score": score, "clean": not items,
        "counts": {s: sum(1 for it in items if it["severity"] == s)
                   for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "fix_first": items[:6],
        "total_actionable": len(items),
    }
