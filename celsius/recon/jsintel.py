"""Extract intelligence from JavaScript / HTML: API endpoints, client routes,
and dangerous DOM sinks. Secret extraction is handled by websecrets/secrets.

Front-end bundles routinely reveal undocumented API paths and admin routes that
never appear in the rendered HTML — a high-value, under-mined seam.
"""

from __future__ import annotations

import re

from ..models import Finding, Severity

# absolute and root-relative URLs in string literals
_ABS_URL = re.compile(r"""['"`](https?://[^'"`\s]{6,})['"`]""")
_PATH = re.compile(r"""['"`](/(?:api|v\d|rest|graphql|internal|admin|auth|user|account|
                      service|gateway|public|private|webhook|callback|oauth)[^'"`\s]{0,120})['"`]""", re.X | re.I)
_FETCH = re.compile(r"""(?:fetch|axios\.\w+|\.open)\s*\(\s*['"`]([^'"`]+)['"`]""")
# client-side route tables (react-router/vue-router style)
_ROUTE = re.compile(r"""(?:path|route)\s*:\s*['"`]([^'"`]+)['"`]""")

# DOM-XSS / dangerous sinks
_SINKS = [
    ("dom-innerhtml", "innerHTML / outerHTML sink", re.compile(r"\.(inner|outer)HTML\s*=")),
    ("dom-write", "document.write", re.compile(r"document\.write(?:ln)?\s*\(")),
    ("dom-eval", "eval()", re.compile(r"\beval\s*\(")),
    ("dom-function", "Function() constructor", re.compile(r"\bnew\s+Function\s*\(")),
    ("dom-insertadjacent", "insertAdjacentHTML", re.compile(r"insertAdjacentHTML\s*\(")),
    ("dom-srcdoc", "iframe srcdoc assignment", re.compile(r"\.srcdoc\s*=")),
    ("dom-location", "location assignment from variable", re.compile(r"location\s*(?:\.href)?\s*=\s*[a-zA-Z_$]")),
    ("proto-pollution", "possible prototype pollution sink", re.compile(r"__proto__|prototype\[")),
]


def extract_endpoints(text: str) -> set[str]:
    out: set[str] = set()
    for m in _ABS_URL.finditer(text):
        out.add(m.group(1))
    for m in _PATH.finditer(text):
        out.add(m.group(1))
    for m in _FETCH.finditer(text):
        v = m.group(1)
        if v.startswith(("/", "http")):
            out.add(v)
    # trim absurd tokens
    return {e for e in out if 3 < len(e) < 200}


def extract_routes(text: str) -> set[str]:
    return {m.group(1) for m in _ROUTE.finditer(text)
            if m.group(1).startswith("/") and len(m.group(1)) < 100}


def find_dom_sinks(text: str, source_label: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule_id, title, pat in _SINKS:
        if pat.search(text):
            findings.append(Finding(
                title=f"Client-side sink: {title}",
                severity=Severity.LOW, category="dom-xss",
                description=f"A dangerous DOM sink appears in client code ({source_label}). "
                            "If user-controlled data reaches it, DOM-based XSS is possible.",
                recommendation="Trace inputs to this sink; sanitize/encode or use safe APIs "
                               "(textContent, DOMPurify).",
                evidence=rule_id,
            ))
    return findings


def analyze_js(sources: dict[str, str]) -> tuple[set[str], set[str], list[Finding]]:
    """sources: {url_or_label: text}. Returns (endpoints, routes, sink_findings)."""
    endpoints: set[str] = set()
    routes: set[str] = set()
    findings: list[Finding] = []
    seen_sinks: set[str] = set()
    for label, text in sources.items():
        endpoints |= extract_endpoints(text)
        routes |= extract_routes(text)
        for f in find_dom_sinks(text, label):
            if f.evidence not in seen_sinks:      # dedupe sink type across files
                seen_sinks.add(f.evidence)
                findings.append(f)
    return endpoints, routes, findings
