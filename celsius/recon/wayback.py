"""Wayback Machine (archive.org) URL harvesting.

Fully passive w.r.t. the target: we query archive.org's CDX API, not the site
itself. The archive often holds URLs that are no longer linked but still live on
the server — forgotten endpoints, old API versions, debug/admin paths — plus the
query parameters those URLs carried, which are prime candidates for IDOR / LFI /
open-redirect / SSRF testing. References to archived sensitive files are flagged.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

from ..models import Finding, Severity

USER_AGENT = "celsius/0.4 (+authorized security testing)"
TIMEOUT = 25
_LIMIT = 5000          # cap CDX rows pulled
_MAX_URLS = 800        # cap URLs we keep/store
_MAX_PARAMS = 120

# Sensitive file extensions whose archived presence is worth flagging.
_SENSITIVE_EXT = re.compile(
    r"\.(sql|bak|old|save|swp|zip|tar|t?gz|rar|7z|env|git|log|conf|config|ini|"
    r"ya?ml|pem|key|p12|pfx|crt|cer|dump|db|sqlite|backup|csv|xlsx?)(?:$|\?)",
    re.I,
)
# Path keywords that hint at interesting/hidden surface.
_INTERESTING_PATH = re.compile(
    r"/(admin|backup|api|graphql|debug|console|internal|private|old|test|tmp|"
    r"upload|setup|install|config|secret|token|dev|staging|actuator|wp-admin|"
    r"phpmyadmin|\.git|\.env)\b",
    re.I,
)
# Query parameters worth fuzzing.
_INTERESTING_PARAM = re.compile(
    r"^(id|uid|user|file|filename|path|dir|page|url|uri|redirect|return|next|"
    r"continue|dest|target|q|search|query|template|include|inc|load|doc|"
    r"document|cmd|exec|cb|callback|token|key|api_?key|debug|preview|format)$",
    re.I,
)


def _cdx(host: str) -> tuple[list[str], list[str]]:
    """Query the CDX API for `host`. Returns (urls, errors)."""
    qs = urllib.parse.urlencode({
        "url": f"{host}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(_LIMIT),
    })
    url = f"http://web.archive.org/cdx/search/cdx?{qs}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    # The CDX endpoint is frequently overloaded (503/timeout), so retry briefly.
    data = None
    last_err = ""
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            break
        except urllib.error.HTTPError as e:
            last_err = str(e)
            if e.code in (429, 502, 503, 504) and attempt < 2:
                time.sleep(2.0 * (attempt + 1))
                continue
            break
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
            last_err = str(e)
            if attempt < 2:
                time.sleep(2.0 * (attempt + 1))
                continue
            break
    if data is None:
        return [], [f"wayback CDX lookup failed after retries: {last_err}"]
    if not isinstance(data, list) or len(data) < 2:
        return [], []
    # First row is the header (["original"]); the rest are 1-element rows.
    return [row[0] for row in data[1:] if row], []


def harvest(host: str) -> tuple[list[Finding], list[str], list[str], list[str]]:
    """Returns (findings, urls, params, errors)."""
    if not host:
        return [], [], [], []
    host = host.strip().lower()
    urls, errors = _cdx(host)
    if not urls:
        return [], [], [], errors

    seen_urls: list[str] = []
    params: set[str] = set()
    sensitive: list[str] = []
    interesting_paths: set[str] = set()

    for u in urls:
        if len(seen_urls) < _MAX_URLS:
            seen_urls.append(u)
        try:
            parsed = urlparse(u)
        except ValueError:
            continue
        path = parsed.path or ""
        for k, _ in urllib.parse.parse_qsl(parsed.query):
            params.add(k)
        if _SENSITIVE_EXT.search(path) or _SENSITIVE_EXT.search(u):
            if len(sensitive) < 40:
                sensitive.append(u)
        if _INTERESTING_PATH.search(path):
            interesting_paths.add(path)

    juicy_params = sorted(p for p in params if _INTERESTING_PARAM.match(p))

    findings: list[Finding] = []
    if sensitive:
        findings.append(Finding(
            title=f"Wayback: {len(sensitive)} archived reference(s) to sensitive files",
            severity=Severity.LOW,
            category="recon",
            description="; ".join(sensitive[:15]),
            recommendation=("These URLs were archived publicly and may still be live or "
                            "retrievable from the archive. Confirm they are removed and "
                            "rotate any secrets that leaked."),
        ))
    if seen_urls:
        extra = (f" — {len(juicy_params)} parameter(s) worth testing: "
                 + ", ".join(juicy_params[:20])) if juicy_params else ""
        findings.append(Finding(
            title=f"Wayback: {len(urls)} historical URL(s) recovered"
                  + (f", {len(interesting_paths)} interesting path(s)" if interesting_paths else ""),
            severity=Severity.INFO,
            category="recon",
            description=("interesting: " + "; ".join(sorted(interesting_paths)[:15]) + " | "
                         if interesting_paths else "")
                        + "params: " + (", ".join(juicy_params[:25]) or "none") + extra,
            recommendation=("Seed these historical URLs/parameters into your testing — old "
                            "endpoints are often unmaintained, and archived parameters are "
                            "good IDOR/LFI/open-redirect/SSRF candidates (test only in scope)."),
        ))

    return findings, seen_urls, juicy_params[:_MAX_PARAMS], errors
