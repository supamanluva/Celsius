"""Scan a live web page (its HTML + linked JavaScript) for exposed secrets.

Front-end bundles frequently leak API keys, tokens, and internal endpoints.
We fetch the page, extract same-origin/CDN <script src> URLs (capped), download
them, and run the secret rules over all of it.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from . import secrets as secret_rules
from .models import Finding, Severity

USER_AGENT = "celsius/0.1 (+authorized security testing)"
TIMEOUT = 12
MAX_SCRIPTS = 15
MAX_BYTES = 3_000_000

_SCRIPT_SRC = re.compile(r"<script[^>]+src=['\"]([^'\"]+)['\"]", re.I)
_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFO": Severity.INFO}


def _fetch(url: str, insecure: bool, auth=None) -> tuple[str, str]:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    hdrs = auth.merge({"User-Agent": USER_AGENT}) if auth else {"User-Agent": USER_AGENT}
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        data = resp.read(MAX_BYTES)
        return data.decode("utf-8", errors="replace"), resp.geturl()


def scan_page(url: str, *, insecure: bool = False, auth=None) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []

    try:
        html, final_url = _fetch(url, insecure, auth)
    except (urllib.error.URLError, ssl.SSLError, OSError) as e:
        return [], [f"secret-scan: could not fetch {url}: {e}"]

    sources = {final_url: html}

    # collect linked scripts
    script_urls: list[str] = []
    for m in _SCRIPT_SRC.finditer(html):
        src = urllib.parse.urljoin(final_url, m.group(1))
        if src.startswith(("http://", "https://")) and src not in script_urls:
            script_urls.append(src)
    for src in script_urls[:MAX_SCRIPTS]:
        try:
            body, _ = _fetch(src, insecure, auth)
            sources[src] = body
        except (urllib.error.URLError, ssl.SSLError, OSError) as e:
            errors.append(f"secret-scan: could not fetch script {src}: {e}")

    seen: set[tuple[str, str]] = set()
    for loc, body in sources.items():
        # Front-end context: rules that are noisy in browser code (JWTs) are
        # softened by the scanner and carry an explanatory note.
        for sm in secret_rules.scan_text(body, context="frontend"):
            key = (sm.rule_id, sm.match)
            if key in seen:
                continue
            seen.add(key)
            description = (f"A credential-shaped string was found in front-end "
                           f"content served at {loc}.")
            if sm.note:
                description += f" {sm.note}"
            findings.append(Finding(
                title=f"Exposed secret in client code: {sm.title}",
                severity=_SEV.get(sm.severity, Severity.MEDIUM),
                category="exposed-secret",
                description=description,
                recommendation="Never ship secrets to the browser. Move calls server-side, "
                               "rotate the exposed value, and scope/limit keys.",
                evidence=f"{sm.redacted}  @ {loc}",
            ))
    return findings, errors
