"""Rendering of ScanResult to the terminal, JSON, and a standalone HTML file."""

from __future__ import annotations

import html
import json
import sys

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
    title = f" celsius report — {result.target}"
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

    # OS / device fingerprint (nmap -O)
    os_info = (result.recon or {}).get("os")
    if os_info:
        w(f"{_BOLD if color else ''} OS / device fingerprint{_RESET if color else ''}\n")
        types = ", ".join(os_info.get("device_types") or []) or "?"
        vendors = ", ".join(os_info.get("vendors") or []) or "?"
        w(f"   • {os_info.get('best_match')}  ({os_info.get('best_accuracy')}% match)\n")
        w(f"     type: {types}   vendor: {vendors}\n")
        for m in os_info.get("matches", [])[1:4]:
            w(f"     ~ {m['name']} ({m['accuracy']}%)\n")
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
        rid = f"celsius/{f.category}/{f.title[:48].replace(' ', '_')}"
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
                "name": "celsius", "version": __version__,
                "informationUri": "https://localhost/celsius",
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
    w(f"# celsius report — {result.target}\n")
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

    w("---\n_Generated by celsius. For authorized testing only._")
    with open(path, "w") as fh:
        fh.write("\n".join(lines))


_SEV_BG = {
    "CRITICAL": "#b30000", "HIGH": "#e64500", "MEDIUM": "#e6a100",
    "LOW": "#2d7dd2", "INFO": "#888",
}
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _recon_html(recon: dict, e) -> str:
    """Render the full recon / attack-surface section: everything celsius gathered,
    laid out so a report reader gets the complete picture without re-running tools."""
    if not recon:
        return ""
    blocks: list[tuple[str, str]] = []

    def kv_table(pairs) -> str:
        rows = "".join(f"<tr><td>{e(str(k))}</td><td>{e(str(v))}</td></tr>"
                       for k, v in pairs if v not in (None, "", [], {}))
        return f"<table><tr><th>Field</th><th>Value</th></tr>{rows}</table>" if rows else ""

    def list_block(items, cap=200) -> str:
        items = [str(i) for i in (items or [])]
        if not items:
            return ""
        shown = items[:cap]
        more = f" <em>… +{len(items) - cap} more</em>" if len(items) > cap else ""
        return f"<p>{e(', '.join(shown))}{more}</p>"

    # --- Topology (the orientation) ---
    topo = recon.get("topology") or {}
    if topo.get("hosts"):
        _ICON = {"home": "🏠", "vps": "☁️", "saas": "📦", "cdn": "🌐", "unknown": "❔"}
        _KIND = {"home": "home self-host", "vps": "VPS / datacenter",
                 "saas": "managed SaaS", "cdn": "CDN / edge", "unknown": "unknown"}
        rows = "".join(
            f"<tr><td>{_ICON.get(h.get('kind'), '❔')} {e(_KIND.get(h.get('kind'), h.get('kind', '')))}</td>"
            f"<td>{e(h.get('ip', ''))}</td>"
            f"<td>{e(h.get('org') or h.get('isp') or '?')}"
            f"{(' · ' + e(str(h.get('asn')))) if h.get('asn') else ''}</td>"
            f"<td>{e(h.get('ptr') or '-')}</td>"
            f"<td>{e(', '.join(str(p) for p in (h.get('ports') or [])) or '-')}</td>"
            f"<td>{e(', '.join(h.get('hostnames') or []))}</td></tr>"
            for h in topo["hosts"])
        blocks.append((f"🗺️ Infrastructure topology ({topo.get('n_hosts', len(topo['hosts']))} host(s))",
                       f"<table><tr><th>Type</th><th>IP</th><th>Org / ASN</th><th>PTR</th>"
                       f"<th>Ports</th><th>Hostnames</th></tr>{rows}</table>"))

    # --- DNS ---
    rec = (recon.get("dns") or {}).get("records") or {}
    if rec:
        rows = "".join(f"<tr><td>{e(k)}</td><td>{e(', '.join(map(str, v)) if isinstance(v, list) else str(v))}</td></tr>"
                       for k, v in rec.items() if v)
        if rows:
            blocks.append(("DNS records", f"<table><tr><th>Type</th><th>Records</th></tr>{rows}</table>"))

    # --- TLS / certificate ---
    tls = recon.get("tls") or {}
    if tls.get("protocol") or tls.get("issuer"):
        san = tls.get("san") or tls.get("alt_names") or []
        blocks.append(("TLS / certificate", kv_table([
            ("Protocol", tls.get("protocol")), ("Cipher", tls.get("cipher")),
            ("Issuer", tls.get("issuer")), ("Subject", tls.get("subject")),
            ("Expires", tls.get("not_after") or tls.get("expires")),
            ("Days to expiry", tls.get("days_to_expiry")),
            ("Self-signed", tls.get("self_signed")),
            ("SAN", ", ".join(san) if isinstance(san, list) else san),
        ])))

    # --- Platform / hosting ---
    plat = recon.get("platform") or {}
    if any(plat.get(k) for k in ("os", "runtime", "server")) or plat.get("edge"):
        blocks.append(("Platform / hosting", kv_table([
            ("Server", plat.get("server")), ("Runtime", plat.get("runtime")),
            ("OS", plat.get("os")), ("Edge", ", ".join(plat.get("edge") or [])),
            ("Evidence", "; ".join(plat.get("evidence") or [])),
        ])))

    # --- Technologies / fingerprint (+ hostname hint, favicon) ---
    tech = recon.get("tech") or []
    extra = []
    if recon.get("app_hint"):
        extra.append(f"<p><strong>Hostname hint:</strong> likely {e(str(recon['app_hint']))}</p>")
    if recon.get("favicon_hash"):
        extra.append(f"<p><strong>Favicon hash:</strong> {e(str(recon['favicon_hash']))}</p>")
    if recon.get("client_libs"):
        extra.append("<p><strong>Client libraries:</strong> " + e(", ".join(recon["client_libs"])) + "</p>")
    if tech:
        techline = " · ".join(
            e(t.get("name", "") + (" " + t["version"] if t.get("version") else "") + " [" + t.get("category", "") + "]")
            for t in tech)
        blocks.append(("Technologies", f"<p>{techline}</p>" + "".join(extra)))
    elif extra:
        blocks.append(("Technologies", "".join(extra)))

    # --- OS / device fingerprint ---
    os_i = recon.get("os") or {}
    if os_i.get("best_match"):
        alt = " · ".join(f"{e(m.get('name', ''))} ({m.get('accuracy')}%)" for m in (os_i.get("matches") or [])[1:4])
        blocks.append(("OS / device fingerprint", kv_table([
            ("Best match", f"{os_i.get('best_match')} ({os_i.get('best_accuracy')}%)"),
            ("Device type", ", ".join(os_i.get("device_types") or [])),
            ("Vendor", ", ".join(os_i.get("vendors") or [])),
            ("Other guesses", alt),
        ])))

    # --- Co-hosted siblings (same IP) ---
    co = recon.get("cohosted") or {}
    sibs = (co.get("siblings") or []) if isinstance(co, dict) else []
    if sibs:
        blocks.append((f"Co-hosted on {e(str(co.get('ip', '')))} ({len(sibs)})", list_block(sibs)))

    # --- Subdomains ---
    subs = recon.get("subdomains") or []
    if subs:
        blocks.append((f"Subdomains ({len(subs)})", list_block(subs, cap=500)))

    # --- Origin / CDN-bypass ---
    oe = recon.get("origin_exposure") or {}
    if oe:
        parts = [f"<p>Behind <strong>{e(oe.get('cdn', 'a CDN'))}</strong></p>"]
        for x in oe.get("exposed", []):
            parts.append(f"<p>possible origin: <strong>{e(x.get('host', ''))}</strong> → {e(', '.join(x.get('origin_ips') or []))}</p>")
        for v in oe.get("verified", []):
            parts.append(f"<p>origin IP <strong>{e(v.get('ip', ''))}</strong>{' ✓ confirmed' if v.get('matched') else ''}"
                         f"{' · Server: ' + e(v.get('server', '')) if v.get('server') else ''}</p>")
        pivots = " · ".join(f'<a href="{e(p.get("url", ""))}" target="_blank">{e(p.get("engine", ""))}: {e(p.get("label") or p.get("query", ""))}</a>'
                            for p in oe.get("pivots", []))
        if pivots:
            parts.append(f"<p>🔎 Origin hunt: {pivots}</p>")
        blocks.append(("Origin / CDN-bypass", "".join(parts)))

    # --- Crawl + API ---
    cr = recon.get("crawl") or {}
    if cr:
        meta = (f"<p>{cr.get('pages', 0)} page(s) · {cr.get('js_files', 0)} JS file(s) · "
                f"{len(cr.get('endpoints') or [])} endpoint(s) · {len(cr.get('routes') or [])} route(s)"
                f"{' · ' + str(cr['recovered_sources']) + ' recovered source(s)' if cr.get('recovered_sources') else ''}</p>")
        ep = list_block(cr.get("endpoints"), cap=150)
        blocks.append(("Crawl", meta + (f"<p><strong>Endpoints:</strong></p>{ep}" if ep else "")))
    api = recon.get("api") or {}
    if api.get("openapi") or api.get("graphql"):
        bits = []
        if api.get("openapi"):
            bits.append(f"OpenAPI: {e(api['openapi'].get('url', ''))} ({len(api['openapi'].get('paths') or [])} paths)")
        if api.get("graphql"):
            bits.append(f"GraphQL introspection: {e(api['graphql'].get('url', ''))} ({api['graphql'].get('types')} types)")
        blocks.append(("API", f"<p>{' · '.join(bits)}</p>"))

    # --- Exposed sensitive paths ---
    if recon.get("exposed_paths"):
        blocks.append((f"⚠️ Exposed sensitive paths ({len(recon['exposed_paths'])})", list_block(recon["exposed_paths"])))

    # --- robots / sitemap / wayback ---
    for key, label in (("robots_paths", "robots.txt paths"), ("sitemap_urls", "Sitemap URLs"),
                       ("wayback_urls", "Wayback URLs (archive.org)"), ("wayback_params", "Wayback parameters")):
        if recon.get(key):
            blocks.append((f"{label} ({len(recon[key])})", list_block(recon[key], cap=150)))

    # --- AI verification stats ---
    av = recon.get("ai_active_verify") or {}
    if av and av.get("requests_sent"):
        blocks.append(("AI active verification", kv_table([
            ("Injection points", av.get("injection_points")), ("Confirmed", av.get("injection_confirmed")),
            ("Hypotheses tested", av.get("hypotheses")), ("Requests sent", av.get("requests_sent")),
        ])))
    cv = recon.get("ai_cve_verify") or {}
    if cv and cv.get("candidates"):
        vd = cv.get("verdicts") or {}
        blocks.append(("AI CVE verification", kv_table([
            ("Candidates", cv.get("candidates")), ("Confirmed", vd.get("confirmed")),
            ("Reachable", vd.get("reachable")), ("Refuted", vd.get("refuted")),
            ("Inconclusive", vd.get("inconclusive")), ("Requests sent", cv.get("requests_sent")),
        ])))

    if not blocks:
        return ""
    out = ['<h2>🔭 Attack surface / recon</h2>']
    for title, body in blocks:
        out.append(f"<h3>{title if title.startswith(('🗺', '⚠')) else e(title)}</h3>{body}")
    return "\n".join(out)


def html_report(data: dict) -> str:
    """Render a self-contained HTML report from a ScanResult.to_dict() mapping.
    Works equally for a live scan and a scan loaded from the store."""
    e = html.escape

    def sev_badge(sev: str) -> str:
        bg = _SEV_BG.get(sev, "#888")
        return f'<span class="badge" style="background:{bg}">{e(sev)}</span>'

    rows_services = "".join(
        f"<tr><td>{e(s.get('name',''))}</td><td>{e(s.get('version') or '?')}</td>"
        f"<td>{s.get('port') or ''}</td><td>{e(s.get('source',''))}</td></tr>"
        for s in data.get("services", [])
    ) or '<tr><td colspan="4">none</td></tr>'

    rows_cves = "".join(
        f"<tr><td>{sev_badge(c.get('severity','INFO'))}</td>"
        f'<td><a href="{e(c.get("url",""))}" target="_blank">{e(c.get("id",""))}</a></td>'
        f"<td>{c.get('cvss') if c.get('cvss') is not None else '-'}</td>"
        f"<td>{e(c.get('affects',''))}</td><td>{e(c.get('description',''))}</td></tr>"
        for c in sorted(data.get("cves", []),
                        key=lambda x: (_SEV_RANK.get(x.get("severity"), 0), x.get("cvss") or 0),
                        reverse=True)
    ) or '<tr><td colspan="5">none found</td></tr>'

    _all_finds = sorted(data.get("findings", []),
                        key=lambda x: _SEV_RANK.get(x.get("severity"), 0), reverse=True)
    _real_finds = [f for f in _all_finds if f.get("category") != "ai-hypothesis"]
    _ai_finds = [f for f in _all_finds if f.get("category") == "ai-hypothesis"]
    rows_find = "".join(
        f"<tr><td>{sev_badge(f.get('severity','INFO'))}</td><td>{e(f.get('title',''))}</td>"
        f"<td>{e(f.get('category',''))}</td><td>{e(f.get('description',''))}"
        f"<br><em>{e(f.get('recommendation',''))}</em></td></tr>"
        for f in _real_finds
    ) or '<tr><td colspan="4">none</td></tr>'
    rows_ai = "".join(
        f"<tr><td>{sev_badge(f.get('severity','INFO'))}</td>"
        f"<td>{e(f.get('title','').removeprefix('[AI] '))}</td>"
        f"<td>{e(f.get('description',''))}</td></tr>"
        for f in _ai_finds
    )
    ai_section = (f"<h2>🤖 AI hypotheses ({len(_ai_finds)}) — unverified leads, not in severity</h2>"
                  f"<table><tr><th>Severity</th><th>Hypothesis</th><th>Rationale</th></tr>{rows_ai}</table>"
                  if _ai_finds else "")

    from . import grade as _grade
    asmt = _grade.assess(data)
    gcolor = _GRADE_COLOR.get(str(asmt["grade"])[0], "#888")
    if asmt["clean"]:
        fix_html = ("<p style='color:#2e9e44;font-weight:600;margin:.2rem 0'>"
                    "✅ No confident security issues found.</p>")
    else:
        lis = "".join(
            f"<li>{sev_badge(it['severity'])}"
            f"{' <strong style=color:#1a7d33>✔ verified</strong>' if it.get('verified') else ''} "
            f"<strong>{e(it['title'])}</strong>"
            f"{(' <span style=color:#b4540a>— ' + e(it['why']) + '</span>') if it.get('why') else ''}"
            f"{('<br><em>↳ ' + e(it['fix']) + '</em>') if it.get('fix') else ''}</li>"
            for it in asmt["fix_first"])
        fix_html = (f"<p style='font-weight:600;margin:.2rem 0'>Fix these first "
                    f"({asmt['total_actionable']} total):</p><ol class='fixlist'>{lis}</ol>")
    grade_banner = (
        f"<div class='gradebar'><span class='gletter' style='color:{gcolor}'>{e(asmt['grade'])}</span>"
        f"<span class='gscore'>{asmt['score']}<small>/100</small></span></div>{fix_html}")

    adv = (data.get("recon") or {}).get("advisor") or {}
    advisor_html = ""
    if adv.get("headline") or adv.get("steps"):
        steps = "".join(
            f"<li>{sev_badge(s.get('severity', 'LOW'))} <strong>{e(s.get('title', ''))}</strong>"
            f"{(' — <em>' + e(s.get('effort')) + '</em>') if s.get('effort') else ''}"
            f"{('<br>' + e(s.get('why'))) if s.get('why') else ''}"
            f"{('<br><code>' + e(s.get('fix')) + '</code>') if s.get('fix') else ''}</li>"
            for s in adv.get("steps", []))
        well = (f"<p class='adv-well'><strong>Already doing well:</strong> "
                f"{e(' · '.join(adv.get('doing_well', [])))}</p>" if adv.get("doing_well") else "")
        advisor_html = (f"<h2>🛡️ Your action plan <span class='aitag'>AI advisor</span></h2>"
                        f"<p>{e(adv.get('headline', ''))}</p>"
                        f"<ol class='advlist'>{steps}</ol>{well}")

    recon_html = _recon_html(data.get("recon") or {}, e)

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>celsius — {e(data.get('target',''))}</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#1a1a1a;background:#fafafa}}
 h1{{margin-bottom:0}} .meta{{color:#666;margin-bottom:1rem}}
 h3{{margin:1rem 0 .2rem;font-size:1.02rem;color:#333}}
 table{{border-collapse:collapse;width:100%;margin:.5rem 0 2rem;background:#fff}}
 th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}
 th{{background:#f0f0f0}}
 .badge{{color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600}}
 a{{color:#2d7dd2}}
 .gradebar{{display:inline-flex;align-items:baseline;gap:.6rem;margin:.4rem 0 .6rem}}
 .gletter{{font-size:2.6rem;font-weight:800;line-height:1}}
 .gscore{{font-size:1.2rem;color:#444;font-weight:700}} .gscore small{{color:#888;font-weight:400}}
 .fixlist{{margin:.3rem 0 1.2rem}} .fixlist li{{margin:.3rem 0;line-height:1.5}}
 .advlist li{{margin:.4rem 0;line-height:1.5}} .advlist code{{display:block;white-space:pre-wrap;background:#f3f3f3;padding:.4rem .6rem;border-radius:4px;margin-top:.2rem;font-size:13px}}
 .aitag{{font-size:11px;color:#7c5cff;border:1px solid #cdbcff;border-radius:999px;padding:1px 7px;vertical-align:middle}}
 .adv-well{{color:#2e9e44}}
 @media print{{body{{margin:0}}}}
</style></head><body>
<h1>celsius report</h1>
<div class="meta">{e(data.get('target',''))} &middot; URL: {e(data.get('url') or '-')} &middot; IP: {e(data.get('ip') or '-')}
 &middot; {e(data.get('started_at',''))} → {e(data.get('finished_at',''))}</div>
{grade_banner}
{advisor_html}
{recon_html}
<h2>Detected services</h2>
<table><tr><th>Product</th><th>Version</th><th>Port</th><th>Source</th></tr>{rows_services}</table>
<h2>Known CVEs</h2>
<table><tr><th>Severity</th><th>CVE</th><th>CVSS</th><th>Affects</th><th>Description</th></tr>{rows_cves}</table>
<h2>Web / config findings</h2>
<table><tr><th>Severity</th><th>Title</th><th>Category</th><th>Detail</th></tr>{rows_find}</table>
{ai_section}
<p class="meta">Generated by celsius {e(_version())}. For authorized testing only.</p>
</body></html>"""


def write_html(result: ScanResult, path: str) -> None:
    with open(path, "w") as f:
        f.write(html_report(result.to_dict()))


def domain_rollup_html(domain: str, scans: list[dict]) -> str:
    """Aggregate report for one domain across many hosts (the host + subdomains).

    Each item in `scans` is a ScanResult.to_dict() mapping. Low-confidence CVEs
    are excluded from headline counts/worst, matching the rest of the tool.
    """
    from .store import _host_of
    e = html.escape

    def badge(sev: str) -> str:
        return f'<span class="badge" style="background:{_SEV_BG.get(sev, "#888")}">{e(sev)}</span>'

    def firm(d):
        return [c for c in d.get("cves", []) if c.get("confidence", "firm") != "weak"]

    def real_finds(d):  # confirmed findings (AI hypotheses are leads, not facts)
        return [f for f in d.get("findings", []) if f.get("category") != "ai-hypothesis"]

    def ai_finds(d):
        return [f for f in d.get("findings", []) if f.get("category") == "ai-hypothesis"]

    def worst(d) -> str:
        w, r = "NONE", -1
        for it in firm(d) + real_finds(d):
            s = it.get("severity", "INFO")
            if _SEV_RANK.get(s, 0) > r:
                w, r = s, _SEV_RANK.get(s, 0)
        return w

    if not scans:
        body = f"<p>No stored scans found for <strong>{e(domain)}</strong> or its subdomains. " \
               "Scan the host (and queue its subdomains) first.</p>"
        return (f"<!doctype html><html><head><meta charset='utf-8'><title>celsius — {e(domain)}</title>"
                "<style>body{font:14px/1.5 system-ui,sans-serif;margin:2rem}</style></head>"
                f"<body><h1>celsius domain report — {e(domain)}</h1>{body}</body></html>")

    # Totals: CVEs are deduped per IP (a service on one IP is one issue, not one
    # per vhost), findings are host-level, AI hypotheses are counted separately.
    totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    seen_cve: set[tuple] = set()
    seen_weak: set[tuple] = set()
    weak_total = 0
    ai_total = 0
    for d in scans:
        ip = d.get("ip") or _host_of(d.get("url") or d.get("target") or "")
        for c in firm(d):
            key = (ip, c.get("id"))
            if key in seen_cve:
                continue
            seen_cve.add(key)
            totals[c.get("severity", "INFO")] = totals.get(c.get("severity", "INFO"), 0) + 1
        for f in real_finds(d):
            totals[f.get("severity", "INFO")] = totals.get(f.get("severity", "INFO"), 0) + 1
        for c in d.get("cves", []):
            if c.get("confidence") == "weak":
                key = (ip, c.get("id"))
                if key not in seen_weak:
                    seen_weak.add(key)
                    weak_total += 1
        ai_total += len(ai_finds(d))

    ordered = sorted(scans, key=lambda d: _SEV_RANK.get(worst(d), 0), reverse=True)

    chips = " ".join(badge(f"{s} {totals[s]}") for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    if weak_total:
        chips += f' <span class="badge" style="background:#7c5cff">UNCONFIRMED {weak_total}</span>'
    if ai_total:
        chips += f' <span class="badge" style="background:#5b82f7">AI LEADS {ai_total}</span>'

    unique_ips = {d.get("ip") for d in scans if d.get("ip")}

    # Shared-infrastructure view: firm CVEs grouped by IP (a service on one IP is
    # one issue across every vhost it serves), with the hostnames sharing that IP.
    # Stops the same SSH/web-server CVEs reading as N separate problems.
    ip_cves: dict[str, dict] = {}
    ip_hosts: dict[str, set] = {}
    for d in ordered:
        ip = d.get("ip") or "?"
        ip_hosts.setdefault(ip, set()).add(_host_of(d.get("url") or d.get("target") or ""))
        for c in firm(d):
            ip_cves.setdefault(ip, {}).setdefault(c.get("id"), c)
    shared = sorted(ip for ip in ip_cves if ip != "?" and len(ip_hosts.get(ip, ())) > 1 and ip_cves[ip])
    byip_section = ""
    if shared:
        rows = ""
        for ip in shared:
            hosts = ", ".join(sorted(ip_hosts[ip]))
            cves = sorted(ip_cves[ip].values(),
                          key=lambda x: (_SEV_RANK.get(x.get("severity"), 0), x.get("cvss") or 0), reverse=True)
            clist = " ".join(
                f"{badge(c.get('severity', 'INFO'))} "
                f"<a href='{e(c.get('url', ''))}' target='_blank'>{e(c.get('id', ''))}</a>" for c in cves)
            rows += (f"<tr><td><code>{e(ip)}</code></td><td>{e(hosts)}</td>"
                     f"<td>{len(cves)}</td><td>{clist}</td></tr>")
        byip_section = (
            "<h2>Shared infrastructure (CVEs by IP)</h2>"
            "<p class='meta'>These CVEs come from a service on a shared IP — one issue affecting every "
            "listed host, not one per host. The per-host sections below repeat them for completeness.</p>"
            f"<table><tr><th>IP</th><th>Hosts sharing it</th><th>#</th><th>CVEs</th></tr>{rows}</table>")

    overview = ""
    for d in ordered:
        h = _host_of(d.get("url") or d.get("target") or "")
        ip = d.get("ip") or "?"
        svcs = ", ".join(sorted({s.get("name", "") for s in d.get("services", []) if s.get("name")}))
        overview += (
            f"<tr><td><a href='#h-{e(h)}'>{e(h)}</a></td><td><code>{e(ip)}</code></td>"
            f"<td>{badge(worst(d))}</td>"
            f"<td>{len(firm(d))}</td><td>{len(real_finds(d))}</td>"
            f"<td>{len(ai_finds(d)) or '·'}</td>"
            f"<td>{e(svcs[:90]) or '-'}</td>"
            f"<td>{e((d.get('finished_at') or d.get('started_at') or '')[:19])}</td></tr>"
        )

    sections = ""
    for d in ordered:
        h = _host_of(d.get("url") or d.get("target") or "")
        cves = sorted(firm(d), key=lambda x: (_SEV_RANK.get(x.get("severity"), 0), x.get("cvss") or 0), reverse=True)
        finds = sorted(real_finds(d), key=lambda x: _SEV_RANK.get(x.get("severity"), 0), reverse=True)
        ai = sorted(ai_finds(d), key=lambda x: _SEV_RANK.get(x.get("severity"), 0), reverse=True)
        crows = "".join(
            f"<tr><td>{badge(c.get('severity', 'INFO'))}</td>"
            f"<td><a href='{e(c.get('url', ''))}' target='_blank'>{e(c.get('id', ''))}</a></td>"
            f"<td>{e(c.get('affects', ''))}</td></tr>" for c in cves
        ) or '<tr><td colspan="3">none</td></tr>'
        frows = "".join(
            f"<tr><td>{badge(f.get('severity', 'INFO'))}</td><td>{e(f.get('title', ''))}</td>"
            f"<td>{e(f.get('category', ''))}</td></tr>" for f in finds[:60]
        ) or '<tr><td colspan="3">none</td></tr>'
        ai_block = ""
        if ai:
            airows = "".join(
                f"<tr><td>{badge(f.get('severity', 'INFO'))}</td><td>{e(f.get('title', '').removeprefix('[AI] '))}</td></tr>"
                for f in ai[:40])
            ai_block = (f"<details><summary>🤖 AI hypotheses — {len(ai)} unverified lead(s), "
                        "not counted in severity</summary>"
                        f"<table><tr><th>Sev</th><th>Hypothesis (verify before trusting)</th></tr>{airows}</table></details>")
        sections += (
            f"<h2 id='h-{e(h)}'>{e(h)} &middot; <code>{e(d.get('ip') or '?')}</code> "
            f"&middot; {badge(worst(d))} "
            f"<a href='#top' style='font-size:12px'>↑</a></h2>"
            f"<table><tr><th>Sev</th><th>CVE</th><th>Affects</th></tr>{crows}</table>"
            f"<table><tr><th>Sev</th><th>Finding</th><th>Category</th></tr>{frows}</table>"
            f"{ai_block}"
        )

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>celsius domain report — {e(domain)}</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#1a1a1a;background:#fafafa}}
 h1{{margin-bottom:.2rem}} .meta{{color:#666;margin-bottom:1rem}}
 table{{border-collapse:collapse;width:100%;margin:.5rem 0 2rem;background:#fff}}
 th,td{{border:1px solid #ddd;padding:.45rem;text-align:left;vertical-align:top}}
 th{{background:#f0f0f0}}
 .badge{{color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600}}
 a{{color:#2d7dd2}} @media print{{body{{margin:0}}}}
</style></head><body>
<a id="top"></a><h1>celsius domain report — {e(domain)}</h1>
<div class="meta">{len(scans)} host(s) across {len(unique_ips)} unique IP(s) &middot; CVEs deduped per IP &middot; AI hypotheses shown separately (not in severity) &middot; latest scan per host</div>
<div style="margin:.5rem 0 1.5rem">{chips}</div>
<h2>Hosts</h2>
<table><tr><th>Host</th><th>IP</th><th>Worst</th><th>CVEs</th><th>Findings</th><th>AI</th><th>Services</th><th>Scanned</th></tr>{overview}</table>
{byip_section}
{sections}
<p class="meta">Generated by celsius {e(_version())}. For authorized testing only.</p>
</body></html>"""


_MS_COLOR = {"ok": "#2e9e44", "warn": "#e6a100", "bad": "#b30000", "info": "#888"}
_MS_LABEL = {"ok": "OK", "warn": "Fix", "bad": "Issue", "info": "Info"}
_GRADE_COLOR = {"A": "#2e9e44", "B": "#6fbf2e", "C": "#e6a100", "D": "#e64500", "F": "#b30000"}


def mailsec_html_report(info: dict) -> str:
    """Render an HTML report for a mail-security check (mailsec.analyze() info)."""
    e = html.escape
    grade = info.get("grade", "?")
    gcolor = _GRADE_COLOR.get(str(grade)[0], "#888")
    mx = ", ".join(info.get("mx", [])) or "no MX"
    provider = f" · {info['provider']}" if info.get("provider") else ""

    rows = ""
    for c in info.get("checks", []):
        st = c.get("status", "info")
        color = _MS_COLOR.get(st, "#888")
        fix = (f"<br><em style='color:#1a7d33'>↳ {e(c['fix'])}</em>" if c.get("fix") else "")
        val = (f"<br><code>{e(c['value'])}</code>" if c.get("value") else "")
        rows += (
            f"<tr><td><span class='badge' style='background:{color}'>{e(_MS_LABEL.get(st, st))}</span></td>"
            f"<td><strong>{e(c.get('label',''))}</strong></td>"
            f"<td>{e(c.get('detail',''))}{val}{fix}</td></tr>"
        )
    rows = rows or '<tr><td colspan="3">no answers</td></tr>'

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>celsius e-mail security — {e(info.get('domain',''))}</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#1a1a1a;background:#fafafa}}
 h1{{margin-bottom:.2rem}} .meta{{color:#666;margin-bottom:1rem}}
 .grade{{display:inline-block;font-size:2.4rem;font-weight:800;color:{gcolor};margin-right:.6rem;vertical-align:middle}}
 .score{{font-size:1.1rem;color:#666;vertical-align:middle}}
 table{{border-collapse:collapse;width:100%;margin:1rem 0 2rem;background:#fff}}
 th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}
 th{{background:#f0f0f0}}
 .badge{{color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;white-space:nowrap}}
 code{{background:#f3f3f3;padding:1px 4px;border-radius:3px;font-size:12px;word-break:break-all}}
 @media print{{body{{margin:0}}}}
</style></head><body>
<h1>E-mail security — {e(info.get('domain',''))}</h1>
<div><span class="grade">{e(str(grade))}</span><span class="score"><strong>{info.get('score',0)}</strong>/100</span></div>
<div class="meta">Mail server: {e(mx)}{e(provider)}</div>
<table><tr><th>Status</th><th>Check</th><th>Detail &amp; fix</th></tr>{rows}</table>
<p class="meta">Generated by celsius {e(_version())}. For authorized testing only.</p>
</body></html>"""


def _version() -> str:
    from . import __version__
    return __version__
