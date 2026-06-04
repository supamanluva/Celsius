"""Extract intelligence from JavaScript / HTML: API endpoints, client routes,
and dangerous DOM sinks. Secret extraction is handled by websecrets/secrets.

Front-end bundles routinely reveal undocumented API paths and admin routes that
never appear in the rendered HTML — a high-value, under-mined seam.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

from ..models import Finding, Severity

# absolute and root-relative URLs in string literals. The char class excludes
# backslash so an escaped closing quote (e.g. "https://x\") is not swallowed into
# the capture as a trailing '\' (which produced duplicate endpoints).
_ABS_URL = re.compile(r"""['"`](https?://[^'"`\s\\]{6,})['"`]""")
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


# static assets — referenced in client code but never "API endpoints"
_STATIC_EXT = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|webp|bmp|avif|css|js|mjs|map|woff2?|ttf|eot|otf|"
    r"mp4|webm|ogg|mp3|wav|pdf|zip|gz)(?:$|[?#])", re.I)
# well-known namespace / schema hosts that look like URLs but never are endpoints
_NOISE_HOST = re.compile(r"(?:^|\.)(?:w3\.org|w3\.org\.|purl\.org|schema\.org)$|"
                         r"ns\.adobe\.com|xmlns", re.I)


def _base_domain(host: Optional[str]) -> str:
    """eTLD+1 approximation: the last two labels (good enough for .com/.se/...)."""
    host = (host or "").split("@")[-1].split(":")[0].strip().strip(".").lower()
    labels = [lbl for lbl in host.split(".") if lbl]
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _clean_endpoint(e: str, base: str) -> Optional[str]:
    """Normalise one raw endpoint and decide whether to keep it.

    Keeps: same-site absolute URLs (host shares the target's base domain) and
    root-relative paths. Drops: third-party URLs, namespace/schema URIs, static
    assets, and malformed/absurd tokens. `base` is the target's base domain
    ('' = unknown, in which case only obvious namespace hosts are dropped).
    """
    e = e.replace("\\/", "/").rstrip("\\").strip()
    if not (3 < len(e) < 200):
        return None
    if e.startswith("http"):
        p = urlparse(e)
        if not p.netloc or _NOISE_HOST.search(p.netloc):
            return None
        if base and _base_domain(p.netloc) != base:
            return None  # external host — not this site's endpoint
        if _STATIC_EXT.search(p.path or ""):
            return None
    else:  # root-relative path
        if _STATIC_EXT.search(e.split("?", 1)[0].split("#", 1)[0]):
            return None
    return e


def scope_endpoints(endpoints: set[str], origin_host: Optional[str] = None) -> set[str]:
    """Filter an existing endpoint set to same-site, non-asset endpoints."""
    base = _base_domain(origin_host) if origin_host else ""
    return {c for e in endpoints if (c := _clean_endpoint(e, base))}


def extract_endpoints(text: str, origin_host: Optional[str] = None) -> set[str]:
    base = _base_domain(origin_host) if origin_host else ""
    raw: set[str] = set()
    for m in _ABS_URL.finditer(text):
        raw.add(m.group(1))
    for m in _PATH.finditer(text):
        raw.add(m.group(1))
    for m in _FETCH.finditer(text):
        v = m.group(1)
        if v.startswith(("/", "http")):
            raw.add(v)
    return {c for e in raw if (c := _clean_endpoint(e, base))}


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


def analyze_js(sources: dict[str, str], origin_host: Optional[str] = None
               ) -> tuple[set[str], set[str], list[Finding]]:
    """sources: {url_or_label: text}. Returns (endpoints, routes, sink_findings).

    `origin_host` scopes discovered endpoints to the target's own base domain,
    so third-party URLs, namespaces and assets in the page aren't miscounted.
    """
    endpoints: set[str] = set()
    routes: set[str] = set()
    findings: list[Finding] = []
    seen_sinks: set[str] = set()
    for label, text in sources.items():
        endpoints |= extract_endpoints(text, origin_host)
        routes |= extract_routes(text)
        for f in find_dom_sinks(text, label):
            if f.evidence not in seen_sinks:      # dedupe sink type across files
                seen_sinks.add(f.evidence)
                findings.append(f)
    return endpoints, routes, findings
