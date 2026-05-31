"""Rendering of ScanResult to the terminal, JSON, and a standalone HTML file."""

from __future__ import annotations

import html
import json
import sys
from typing import Optional

from .models import ScanResult, Severity

# ANSI colors per severity (terminal only).
_COLORS = {
    Severity.CRITICAL: "\033[97;41m",  # white on red
    Severity.HIGH: "\033[91m",          # red
    Severity.MEDIUM: "\033[93m",        # yellow
    Severity.LOW: "\033[94m",           # blue
    Severity.INFO: "\033[90m",          # grey
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


def _sev_tag(sev: Severity, color: bool) -> str:
    label = f"[{sev.value:^8}]"
    if color:
        return f"{_COLORS[sev]}{label}{_RESET}"
    return label


def render_terminal(result: ScanResult, stream=sys.stdout) -> None:
    color = _use_color(stream)
    w = stream.write

    def hr():
        w("─" * 70 + "\n")

    hr()
    title = f" secscan report — {result.target}"
    w((f"{_BOLD}{title}{_RESET}\n" if color else title + "\n"))
    if result.url:
        w(f" URL: {result.url}\n")
    if result.ip:
        w(f" IP:  {result.ip}\n")
    hr()

    # Summary counts
    counts = {s: 0 for s in Severity}
    for c in result.cves:
        counts[c.severity] += 1
    for f in result.findings:
        counts[f.severity] += 1
    summary = "  ".join(
        f"{_sev_tag(s, color)} {counts[s]}"
        for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    )
    w(" Summary: " + summary + "\n")
    hr()

    # Exploit chains (headline — correlated attack paths)
    if result.chains:
        w(f"{_BOLD if color else ''} ⛓  Exploit chains ({len(result.chains)}){_RESET if color else ''}\n")
        for ch in result.chains:
            sev = Severity(ch["severity"]) if ch["severity"] in Severity.__members__ else Severity.INFO
            w(f"   {_sev_tag(sev, color)} {ch['title']}  (priority {ch['priority']})\n")
            w(f"        path: {'  →  '.join(ch['nodes'])}\n")
            narr = ch["narrative"]
            w(f"        {narr[:200]}\n")
            w(f"        ↳ fix: {ch['recommendation']}\n")
        w("\n")

    # Services
    w(f"{_BOLD if color else ''} Detected services ({len(result.services)}){_RESET if color else ''}\n")
    if not result.services:
        w("   (none)\n")
    for s in result.services:
        ver = s.version or "?"
        extra = f"  via {s.source}" if s.source else ""
        w(f"   • {s.name} {ver}"
          + (f"  port {s.port}/{s.protocol}" if s.port else "")
          + extra + "\n")
    w("\n")

    # CVEs (highest severity first)
    w(f"{_BOLD if color else ''} Known CVEs ({len(result.cves)}){_RESET if color else ''}\n")
    if not result.cves:
        w("   (none found for detected versions)\n")
    for c in sorted(result.cves, key=lambda x: (x.severity.rank, x.cvss or 0), reverse=True):
        score = f"{c.cvss:.1f}" if c.cvss is not None else " - "
        vmark = "  ✔ VERIFIED" if getattr(c, "verified", False) else ""
        w(f"   {_sev_tag(c.severity, color)} {c.id}  CVSS {score}  ({c.affects}){vmark}\n")
        ex = c.exploitability or {}
        if ex:
            sig = ex.get("signals", {})
            bits = [ex.get("verdict", "")]
            if sig.get("epss") is not None:
                bits.append(f"EPSS {sig['epss']:.3f}")
            if sig.get("kev"):
                bits.append("CISA-KEV")
            if sig.get("public_poc"):
                bits.append("public-PoC")
            w(f"        → exploitability: {'  '.join(b for b in bits if b)}  (priority {ex.get('priority', 0)})\n")
        poc = c.poc_refs() if hasattr(c, "poc_refs") else []
        for u in poc[:3]:
            w(f"        PoC: {u}\n")
        desc = c.description.strip().replace("\n", " ")
        if len(desc) > 160:
            desc = desc[:157] + "..."
        w(f"        {desc}\n")
        w(f"        {c.url}\n")
    w("\n")

    # Findings (headers, csp, nuclei, ...)
    w(f"{_BOLD if color else ''} Web / config findings ({len(result.findings)}){_RESET if color else ''}\n")
    if not result.findings:
        w("   (none)\n")
    for f in sorted(result.findings, key=lambda x: x.severity.rank, reverse=True):
        w(f"   {_sev_tag(f.severity, color)} {f.title}  [{f.category}]\n")
        ex = f.exploitability or {}
        if ex and ex.get("verdict") not in (None, "informational"):
            w(f"        → exploitability: {ex.get('verdict')}\n")
        if f.description:
            w(f"        {f.description}\n")
        if f.recommendation:
            w(f"        ↳ fix: {f.recommendation}\n")
        if f.evidence:
            ev = f.evidence if len(f.evidence) < 160 else f.evidence[:157] + "..."
            w(f"        evidence: {ev}\n")
    w("\n")

    if result.errors:
        w(f"{_BOLD if color else ''} Notes / errors{_RESET if color else ''}\n")
        for e in result.errors:
            w(f"   ! {e}\n")
        w("\n")

    cov = result.coverage or {}
    if cov.get("next_steps"):
        w(f"{_BOLD if color else ''} Completeness — suggested next steps{_RESET if color else ''}\n")
        for s in cov["next_steps"]:
            w(f"   → {s}\n")
        if cov.get("checks_skipped"):
            w(f"   (skipped: {', '.join(cov['checks_skipped'])})\n")
        w("\n")

    hr()


def write_json(result: ScanResult, path: str) -> None:
    with open(path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)


# ---- SARIF 2.1.0 (CI / IDE ingestion) ----------------------------------------

_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                "LOW": "note", "INFO": "note"}


def write_sarif(result: ScanResult, path: str) -> None:
    from . import __version__
    rules: dict[str, dict] = {}
    results: list[dict] = []

    def add(rule_id, name, severity, message, uri, props=None):
        if rule_id not in rules:
            rules[rule_id] = {"id": rule_id, "name": name,
                              "shortDescription": {"text": name}}
        r = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(severity, "note"),
            "message": {"text": message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri or result.target}}}],
        }
        if props:
            r["properties"] = props
        results.append(r)

    for c in result.cves:
        add(c.id, c.id, c.severity.value,
            f"{c.id} affects {c.affects}. {c.description[:200]}", c.url,
            {"cvss": c.cvss, "exploitability": (c.exploitability or {}).get("verdict"),
             "security-severity": str(c.cvss or 0)})
    for f in result.findings:
        rid = f"secscan/{f.category}/{f.title[:48].replace(' ', '_')}"
        add(rid, f.title, f.severity.value, f.description or f.title,
            result.url or result.target,
            {"category": f.category, "confidence": f.confidence,
             "exploitability": (f.exploitability or {}).get("verdict")})
    for ch in result.chains:
        add(f"chain/{ch['id']}", ch["title"], ch["severity"],
            f"EXPLOIT CHAIN: {ch['narrative']}", result.url or result.target,
            {"priority": ch["priority"], "nodes": ch["nodes"]})

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "secscan", "version": __version__,
                "informationUri": "https://localhost/secscan",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=2)


# ---- Markdown report ---------------------------------------------------------

def write_markdown(result: ScanResult, path: str) -> None:
    from . import completeness  # noqa
    lines: list[str] = []
    w = lines.append
    w(f"# secscan report — {result.target}\n")
    w(f"- **URL:** {result.url or '-'}  ·  **IP:** {result.ip or '-'}")
    w(f"- **Scanned:** {result.started_at} → {result.finished_at}\n")

    counts = {s.value: 0 for s in Severity}
    for c in result.cves:
        counts[c.severity.value] += 1
    for f in result.findings:
        counts[f.severity.value] += 1
    w("**Summary:** " + " · ".join(f"{k} {counts[k]}" for k in
      ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]) + "\n")

    if result.chains:
        w("## ⛓️ Exploit chains\n")
        for ch in result.chains:
            w(f"### [{ch['severity']}] {ch['title']}  _(priority {ch['priority']})_")
            w(f"{ch['narrative']}\n")
            w("**Path:** " + " → ".join(ch["nodes"]))
            w(f"\n**Fix:** {ch['recommendation']}\n")

    if result.cves:
        w("## Known CVEs\n")
        w("| Severity | CVE | CVSS | Exploitability | Affects |")
        w("|---|---|---|---|---|")
        for c in sorted(result.cves, key=lambda x: (x.severity.rank, x.cvss or 0), reverse=True):
            ex = (c.exploitability or {})
            sig = ex.get("signals", {})
            ev = ex.get("verdict", "-")
            if sig.get("kev"):
                ev += " (KEV)"
            w(f"| {c.severity.value} | [{c.id}]({c.url}) | {c.cvss or '-'} | {ev} | {c.affects} |")
        w("")

    if result.findings:
        w("## Findings\n")
        for f in sorted(result.findings, key=lambda x: x.severity.rank, reverse=True):
            ev = (f.exploitability or {}).get("verdict", "")
            tag = f" · _{ev}_" if ev and ev != "informational" else ""
            w(f"- **[{f.severity.value}] {f.title}** `[{f.category}]`{tag}")
            if f.description:
                w(f"  - {f.description}")
            if f.recommendation:
                w(f"  - ↳ _{f.recommendation}_")
        w("")

    if result.coverage:
        cov = result.coverage
        w("## Coverage (completeness)\n")
        w(f"- **Ran:** {', '.join(cov.get('checks_run', []))}")
        w(f"- **Skipped:** {', '.join(cov.get('checks_skipped', [])) or 'none'}")
        if cov.get("next_steps"):
            w("- **Suggested next steps:**")
            for s in cov["next_steps"]:
                w(f"  - {s}")
        w("")

    w("---\n_Generated by secscan. For authorized testing only._")
    with open(path, "w") as fh:
        fh.write("\n".join(lines))


def write_html(result: ScanResult, path: str) -> None:
    e = html.escape

    def sev_badge(sev: Severity) -> str:
        bg = {
            Severity.CRITICAL: "#b30000",
            Severity.HIGH: "#e64500",
            Severity.MEDIUM: "#e6a100",
            Severity.LOW: "#2d7dd2",
            Severity.INFO: "#888",
        }[sev]
        return f'<span class="badge" style="background:{bg}">{sev.value}</span>'

    rows_services = "".join(
        f"<tr><td>{e(s.name)}</td><td>{e(s.version or '?')}</td>"
        f"<td>{s.port or ''}</td><td>{e(s.source)}</td></tr>"
        for s in result.services
    ) or '<tr><td colspan="4">none</td></tr>'

    rows_cves = "".join(
        f"<tr><td>{sev_badge(c.severity)}</td>"
        f'<td><a href="{e(c.url)}" target="_blank">{e(c.id)}</a></td>'
        f"<td>{c.cvss if c.cvss is not None else '-'}</td>"
        f"<td>{e(c.affects)}</td><td>{e(c.description)}</td></tr>"
        for c in sorted(result.cves, key=lambda x: (x.severity.rank, x.cvss or 0), reverse=True)
    ) or '<tr><td colspan="5">none found</td></tr>'

    rows_find = "".join(
        f"<tr><td>{sev_badge(f.severity)}</td><td>{e(f.title)}</td>"
        f"<td>{e(f.category)}</td><td>{e(f.description)}<br><em>{e(f.recommendation)}</em></td></tr>"
        for f in sorted(result.findings, key=lambda x: x.severity.rank, reverse=True)
    ) or '<tr><td colspan="4">none</td></tr>'

    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>secscan — {e(result.target)}</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#1a1a1a;background:#fafafa}}
 h1{{margin-bottom:0}} .meta{{color:#666;margin-bottom:1rem}}
 table{{border-collapse:collapse;width:100%;margin:.5rem 0 2rem;background:#fff}}
 th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}
 th{{background:#f0f0f0}}
 .badge{{color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600}}
 a{{color:#2d7dd2}}
</style></head><body>
<h1>secscan report</h1>
<div class="meta">{e(result.target)} &middot; URL: {e(result.url or '-')} &middot; IP: {e(result.ip or '-')}
 &middot; {e(result.started_at)} → {e(result.finished_at)}</div>
<h2>Detected services</h2>
<table><tr><th>Product</th><th>Version</th><th>Port</th><th>Source</th></tr>{rows_services}</table>
<h2>Known CVEs</h2>
<table><tr><th>Severity</th><th>CVE</th><th>CVSS</th><th>Affects</th><th>Description</th></tr>{rows_cves}</table>
<h2>Web / config findings</h2>
<table><tr><th>Severity</th><th>Title</th><th>Category</th><th>Detail</th></tr>{rows_find}</table>
<p class="meta">Generated by secscan {e(_version())}. For authorized testing only.</p>
</body></html>"""
    with open(path, "w") as f:
        f.write(doc)


def _version() -> str:
    from . import __version__
    return __version__
