"""robots.txt and sitemap.xml harvesting.

Passive: fetch the two files a crawler is expected to read and mine them for
disclosed paths. `Disallow` entries frequently point straight at admin / staging
/ backup areas the owner tried to hide, and sitemaps enumerate real URLs — both
are free leads for the rest of the scan (and "security through robots.txt" is an
anti-pattern worth flagging).
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from typing import Optional
from urllib.parse import urljoin, urlparse

from ..models import Finding, Severity

USER_AGENT = "celsius/0.4 (+authorized security testing)"
TIMEOUT = 12
_MAX_SITEMAPS = 5     # cap sitemap (incl. nested index) fetches
_MAX_URLS = 500       # cap harvested sitemap URLs

# Disallowed paths that are notably sensitive get called out specifically.
_INTERESTING = re.compile(
    r"admin|login|logout|backup|\.git|\.env|config|private|internal|staging|"
    r"\bdev\b|\btest\b|api|secret|token|wp-admin|phpmyadmin|debug|console|"
    r"dashboard|upload|setup|install|account|billing|invoice",
    re.I,
)


def _fetch(url: str, insecure: bool, auth) -> tuple[Optional[int], str]:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    hdrs = {"User-Agent": USER_AGENT}
    if auth:
        hdrs = auth.merge(hdrs)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
            return resp.status, resp.read(1_000_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError):
        return None, ""


def _parse_robots(text: str) -> tuple[set[str], set[str]]:
    """Return (disallowed/allowed paths, sitemap URLs)."""
    paths: set[str] = set()
    sitemaps: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        field, _, val = line.partition(":")
        field, val = field.strip().lower(), val.strip()
        if field in ("disallow", "allow") and val and val != "/":
            paths.add(val)
        elif field == "sitemap" and val.startswith("http"):
            sitemaps.add(val)
    return paths, sitemaps


def _parse_sitemap(text: str) -> list[str]:
    """Extract <loc> URLs — works for both <urlset> and <sitemapindex>."""
    return re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.I)


def harvest(base_url: str, *, insecure: bool = False, auth=None
            ) -> tuple[list[Finding], list[str], list[str], list[str]]:
    """Returns (findings, robots_paths, sitemap_urls, errors)."""
    if not base_url:
        return [], [], [], []
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}/"
    findings: list[Finding] = []

    # robots.txt
    paths: set[str] = set()
    sitemaps: set[str] = set()
    status, body = _fetch(urljoin(root, "robots.txt"), insecure, auth)
    if status == 200 and body and "<html" not in body[:200].lower():
        p, s = _parse_robots(body)
        paths |= p
        sitemaps |= s

    # always try the conventional sitemap location too
    sitemaps.add(urljoin(root, "sitemap.xml"))

    # fetch sitemaps, following one level of <sitemapindex>
    sitemap_urls: set[str] = set()
    seen: set[str] = set()
    queue = list(sitemaps)
    while queue and len(seen) < _MAX_SITEMAPS:
        sm = queue.pop(0)
        if sm in seen:
            continue
        seen.add(sm)
        status, body = _fetch(sm, insecure, auth)
        if status != 200 or not body:
            continue
        for loc in _parse_sitemap(body):
            if loc.endswith(".xml") and (len(seen) + len(queue)) < _MAX_SITEMAPS:
                queue.append(loc)          # nested sitemap index
            else:
                sitemap_urls.add(loc)
    sitemap_urls = set(sorted(sitemap_urls)[:_MAX_URLS])

    if paths:
        interesting = sorted(p for p in paths if _INTERESTING.search(p))
        sev = Severity.LOW if interesting else Severity.INFO
        head = ("sensitive: " + "; ".join(interesting[:15]) + " — ") if interesting else ""
        findings.append(Finding(
            title=f"robots.txt discloses {len(paths)} path(s)"
                  + (f" ({len(interesting)} sensitive)" if interesting else ""),
            severity=sev,
            category="recon",
            description=head + "; ".join(sorted(paths)[:30]),
            recommendation=("robots.txt is public — never rely on it to hide sensitive "
                            "areas. Review the disclosed paths for unintended exposure "
                            "and protect them with real authz."),
        ))

    return findings, sorted(paths), sorted(sitemap_urls), []
