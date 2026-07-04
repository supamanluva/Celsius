"""Exploit-chain correlation.

Individual findings are often low/medium on their own but compose into a
high-impact attack path. This engine applies rules that connect findings/CVEs
into chains, scores the chain (not just the parts), and explains the path. Most
scanners never do this — it's a core differentiator.

Deterministic rules form the backbone; an optional AI pass can propose additional
chains (clearly labeled, never auto-trusted).
"""

from __future__ import annotations


from .models import ScanResult

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _chain(cid, title, severity, priority, narrative, nodes, recommendation, source="rule"):
    return {
        "id": cid, "title": title, "severity": severity, "priority": priority,
        "narrative": narrative, "nodes": nodes, "recommendation": recommendation,
        "source": source,
    }


def _has(findings, *, category=None, title_contains=None, verdict=None):
    out = []
    for f in findings:
        if category and f.category != category:
            continue
        if title_contains and title_contains.lower() not in f.title.lower():
            continue
        if verdict and (f.exploitability or {}).get("verdict") != verdict:
            continue
        out.append(f)
    return out


def correlate(result: ScanResult) -> list[dict]:
    chains: list[dict] = []
    F = result.findings
    n = 0

    all_secrets = _has(F, category="exposed-secret")
    # Only signature-based secrets are strong enough to claim "leaked credential";
    # high-entropy guesses are low-confidence and over-claim in a chain.
    secrets = [s for s in all_secrets if "high-entropy" not in s.title.lower()]
    weak_secrets = [s for s in all_secrets if "high-entropy" in s.title.lower()]
    sourcemaps = [f for f in F if "source map" in f.title.lower()
                  or ("recovered" in f.title.lower() and "source" in f.title.lower())]
    confirmed = [f for f in F if (f.exploitability or {}).get("verdict") == "confirmed-exploitable"]
    csp_inline = _has(F, category="csp", title_contains="unsafe-inline")
    dom_sinks = _has(F, category="dom-xss")
    graphql = _has(F, title_contains="graphql introspection")
    endpoints = (result.recon.get("crawl", {}) or {}).get("endpoints", []) or []
    api_info = result.recon.get("api", {}) or {}
    kev_cves = [c for c in result.cves
                if (c.exploitability or {}).get("signals", {}).get("kev")]
    likely_cves = [c for c in result.cves
                   if (c.exploitability or {}).get("verdict") == "likely-exploitable"]

    # 1) Source-map disclosure -> leaked credential
    if sourcemaps and secrets:
        n += 1
        chains.append(_chain(
            f"chain-{n}", "Source-map disclosure → leaked credentials", "CRITICAL", 92,
            "An exposed source map reconstructs the original client source, in which "
            "a hardcoded credential was found. An attacker recovers the source and "
            "extracts the secret — no auth required.",
            [sourcemaps[0].title] + [s.title for s in secrets[:3]],
            "Strip source maps from production AND rotate the leaked credential; move "
            "secret-bearing logic server-side."))

    # 2) Leaked credential + reachable API surface
    if secrets and (endpoints or api_info.get("openapi") or api_info.get("graphql")):
        n += 1
        where = "discovered API endpoints" if endpoints else "an exposed API schema"
        chains.append(_chain(
            f"chain-{n}", "Leaked credential + reachable API → unauthorized access", "HIGH", 80,
            f"A credential is exposed in client code and {where} are reachable. If the "
            "credential authenticates to those endpoints, an attacker gains direct API "
            "access.",
            [secrets[0].title] + ([f"{len(endpoints)} client-side endpoints"] if endpoints else
                                  ["exposed API schema"]),
            "Rotate the credential, require server-side auth, and least-privilege the key."))

    # 2b) Only weak/high-entropy "possible" secrets + API surface -> low-priority lead
    if not secrets and weak_secrets and (endpoints or api_info):
        n += 1
        chains.append(_chain(
            f"chain-{n}", "Possible (low-confidence) secret near API surface", "LOW", 30,
            "High-entropy strings were flagged in client code, but these are "
            "LOW-CONFIDENCE guesses (often minified code, hashes, or base64/JWT "
            "blobs — not necessarily credentials). Treat as a lead to verify, not a "
            "confirmed leak.",
            [weak_secrets[0].title] + ([f"{len(endpoints)} client-side endpoints"] if endpoints else []),
            "Manually inspect the flagged strings; only act if they are real, live "
            "credentials."))

    # 3) Confirmed-exploitable issue (lab) -> direct path
    for cf in confirmed:
        n += 1
        chains.append(_chain(
            f"chain-{n}", f"Confirmed exploitable: {cf.title}", cf.severity.value if hasattr(cf.severity, 'value') else str(cf.severity), 88,
            "This issue was actively confirmed (non-destructively) on an authorized "
            "target — it is directly exploitable, not theoretical.",
            [cf.title],
            cf.recommendation or "Remediate the confirmed vulnerability immediately."))

    # 4) Weak CSP + DOM sink -> elevated XSS
    if csp_inline and dom_sinks:
        n += 1
        chains.append(_chain(
            f"chain-{n}", "Weak CSP + DOM sink → elevated XSS risk", "HIGH", 70,
            "The CSP allows 'unsafe-inline' AND a DOM sink (e.g. innerHTML) exists. If "
            "any user-controlled input reaches the sink, the weak CSP does not contain "
            "the resulting XSS.",
            [csp_inline[0].title] + [d.title for d in dom_sinks[:2]],
            "Remove 'unsafe-inline' (use nonces/hashes) and sanitize data into DOM sinks."))

    # 5) GraphQL introspection + (endpoints/secret) -> API attack surface
    if graphql and (endpoints or secrets):
        n += 1
        chains.append(_chain(
            f"chain-{n}", "Exposed GraphQL schema → mapped API attack surface", "MEDIUM", 55,
            "GraphQL introspection reveals the full schema, and other client-side "
            "endpoints/credentials are exposed — together they map a precise attack "
            "surface for authz/IDOR testing.",
            [graphql[0].title] + ([secrets[0].title] if secrets else []),
            "Disable introspection in production; enforce object-level authorization."))

    # 6) KEV / likely-exploitable CVE on a reachable service -> urgent
    for c in (kev_cves or likely_cves)[:3]:
        n += 1
        sig = (c.exploitability or {}).get("signals", {})
        why = "in CISA KEV (exploited in the wild)" if sig.get("kev") else "high EPSS"
        chains.append(_chain(
            f"chain-{n}", f"Internet-reachable service vulnerable to {c.id}", "CRITICAL", 90,
            f"{c.id} affects {c.affects}, which is exposed on the target, and the CVE is "
            f"{why}. This is a prime, real-world exploitation path.",
            [f"{c.affects}", c.id],
            "Patch to the fixed version urgently; it is being exploited in the wild."))

    chains.sort(key=lambda c: c["priority"], reverse=True)
    return chains
