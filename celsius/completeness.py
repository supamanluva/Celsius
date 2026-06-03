"""Completeness critic + blue-team output.

`assess_coverage` reports what the scan did and did NOT cover, so a clean result
is not mistaken for a complete one (silent gaps read as "all good").

`detection_rules` turns findings into actionable defender artifacts: hardened
config snippets and detection-rule stubs.
"""

from __future__ import annotations

from .config import ScanConfig
from .models import ScanResult


def assess_coverage(result: ScanResult, config: ScanConfig) -> dict:
    ran = []
    skipped = []

    def mark(name, on):
        (ran if on else skipped).append(name)

    mark("web-headers", config.web)
    mark("dns", config.dns and not _is_ip(result))
    mark("tls", config.tls)
    mark("fingerprint", config.fingerprint)
    mark("subdomains", config.subdomains)
    mark("port-scan", config.ports)
    mark("crawl+js", config.crawl)
    mark("api-discovery", config.api_discovery)
    mark("content-discovery", config.content_discovery)
    mark("front-end-secrets", config.web_secrets)
    mark("nuclei", config.nuclei)
    mark("cve-lookup", config.cve)
    mark("exploitability", config.exploitability)
    mark("ai-analysis", config.ai)
    mark("active-verify(lab)", config.allow_exploit)

    unverified = [f.title for f in result.findings
                  if (f.exploitability or {}).get("verdict") in ("unknown", "conditions-needed")
                  and f.category not in ("dns", "fingerprint", "subdomains", "ai-summary")]
    ai_unconfirmed = [f.title for f in result.findings if f.category == "ai-hypothesis"]

    suggestions = []
    if not config.ports:
        suggestions.append("run a port scan (--ports) — only web was assessed")
    if not config.crawl:
        suggestions.append("crawl client code (--crawl) for hidden endpoints/source maps")
    if not config.subdomains:
        suggestions.append("enumerate subdomains (--subdomains) for wider attack surface")
    if not config.content_discovery:
        suggestions.append("probe for exposed files (--content-discovery): .git/.env/backups")
    if not config.ai:
        suggestions.append("add AI analysis (--ai) for business-logic hypotheses")
    if ai_unconfirmed:
        suggestions.append(f"verify {len(ai_unconfirmed)} AI hypothesis(es) — they are leads, not facts")
    if not config.allow_exploit and unverified:
        suggestions.append(f"{len(unverified)} finding(s) need confirmation; lab mode (--lab) can verify some")

    return {
        "checks_run": ran,
        "checks_skipped": skipped,
        "unverified_findings": len(unverified),
        "ai_unconfirmed": len(ai_unconfirmed),
        "next_steps": suggestions,
    }


def _is_ip(result: ScanResult) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address((result.target.split("//")[-1].split("/")[0].split(":")[0]))
        return True
    except ValueError:
        return False


# ---- blue-team detection / remediation ---------------------------------------

def detection_rules(result: ScanResult) -> list[dict]:
    """Generate defender artifacts (config snippets / rule stubs) from findings."""
    rules: list[dict] = []
    cats = {f.category for f in result.findings}
    titles = " ".join(f.title.lower() for f in result.findings)

    if "csp" in cats:
        rules.append({
            "title": "Harden Content-Security-Policy",
            "type": "config",
            "content": "Content-Security-Policy: default-src 'self'; script-src 'self' "
                       "'nonce-<random>'; object-src 'none'; base-uri 'self'; "
                       "frame-ancestors 'self'",
        })
    if "headers" in cats or "hsts" in titles:
        rules.append({
            "title": "Add baseline security headers",
            "type": "config",
            "content": "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                       "X-Content-Type-Options: nosniff\nX-Frame-Options: DENY\n"
                       "Referrer-Policy: strict-origin-when-cross-origin",
        })
    if "exposed-secret" in cats:
        rules.append({
            "title": "Detect secret-bearing responses (egress/CI)",
            "type": "sigma-ish",
            "content": "Alert when build artifacts/JS bundles contain patterns matching "
                       "AKIA[0-9A-Z]{16}, ghp_*, sk_live_*, -----BEGIN PRIVATE KEY-----. "
                       "Gate CI on a secret scanner (gitleaks).",
        })
    if any("sql injection" in t for t in titles.split("|")) or "active-verify" in cats:
        rules.append({
            "title": "WAF/IDS rule for confirmed injection points",
            "type": "detection",
            "content": "Add parameterized queries; deploy a WAF rule flagging SQL "
                       "metacharacters and traversal sequences on the confirmed parameters.",
        })
    return rules
