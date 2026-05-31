"""Source-map archaeology.

When a site ships a JavaScript source map (.map) with `sourcesContent`, the
ORIGINAL pre-minification source — comments, internal paths, sometimes secrets —
can be fully reconstructed. Most scanners ignore this; it's a rich seam for
logic bugs and leaked credentials. We recover the sources and run secret + SAST
checks over them.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from ..models import Finding, Severity
from .. import secrets as secret_rules

USER_AGENT = "secscan/0.5 (+authorized security testing)"
TIMEOUT = 10
MAX_BYTES = 5_000_000

_SM_URL = re.compile(r"""//[#@]\s*sourceMappingURL=([^\s'"]+)""")


def _fetch(url: str, insecure: bool) -> str:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        return resp.read(MAX_BYTES).decode("utf-8", errors="replace")


def map_url_for(js_url: str, js_body: str) -> str | None:
    m = _SM_URL.search(js_body or "")
    if m:
        ref = m.group(1)
        if ref.startswith("data:"):
            return ref  # inline map
        return urllib.parse.urljoin(js_url, ref)
    return None


def recover(js_url: str, js_body: str, *, insecure: bool = False
            ) -> tuple[dict[str, str], list[Finding], list[str]]:
    """Recover original sources for one JS file. Returns (sources, findings, errors)."""
    findings: list[Finding] = []
    errors: list[str] = []
    sources: dict[str, str] = {}

    map_url = map_url_for(js_url, js_body)
    if not map_url:
        # opportunistic guess: <js>.map
        map_url = js_url + ".map"

    try:
        if map_url.startswith("data:"):
            # data:application/json;base64,....
            b64 = map_url.split(",", 1)[1]
            import base64
            raw = base64.b64decode(b64).decode("utf-8", errors="replace")
        else:
            raw = _fetch(map_url, insecure)
        data = json.loads(raw)
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError, json.JSONDecodeError):
        return {}, [], []  # no usable map — silent (guesses miss often)

    names = data.get("sources", []) or []
    contents = data.get("sourcesContent", []) or []
    if not contents:
        findings.append(Finding(
            title="Source map exposed (no embedded source)",
            severity=Severity.LOW, category="info-disclosure",
            description=f"A source map is reachable at {map_url} but carries no "
                        "sourcesContent.",
            recommendation="Avoid shipping source maps to production, or restrict access.",
            evidence=map_url,
        ))
        return {}, findings, errors

    for i, content in enumerate(contents):
        if not content:
            continue
        name = names[i] if i < len(names) else f"source_{i}.js"
        name = name.replace("webpack://", "").lstrip("./")
        sources[name] = content

    findings.append(Finding(
        title=f"Original source recovered from source map ({len(sources)} files)",
        severity=Severity.MEDIUM, category="info-disclosure",
        description=f"{map_url} embeds full original source (sourcesContent). "
                    "Internal code, comments, and paths are exposed and were scanned "
                    "for secrets.",
        recommendation="Do not deploy source maps publicly; serve them only to "
                       "authenticated developers or strip them in production builds.",
        evidence=map_url,
    ))
    return sources, findings, errors


def scan_recovered(sources: dict[str, str]) -> list[Finding]:
    """Secret scan over recovered original source."""
    findings: list[Finding] = []
    seen: set[tuple] = set()
    sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
               "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFO": Severity.INFO}
    for name, text in sources.items():
        for sm in secret_rules.scan_text(text):
            key = (sm.rule_id, sm.match)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                title=f"Secret in recovered source: {sm.title}",
                severity=sev_map.get(sm.severity, Severity.MEDIUM),
                category="exposed-secret",
                description=f"Found in reconstructed original source '{name}'.",
                recommendation="Rotate the secret; never ship secrets in client code or maps.",
                evidence=f"{sm.redacted} @ {name}",
            ))
    return findings
