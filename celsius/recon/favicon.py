"""Favicon fingerprinting (Shodan-style hash).

Computes the MurmurHash3 (x86_32, signed) of the base64-encoded favicon, the same
value Shodan exposes as ``http.favicon.hash``. Many self-hosted apps and admin
panels ship a default favicon with a known hash, so this identifies the product
even when HTTP headers/body give nothing away — and the hash itself is a pivot
(`http.favicon.hash:<n>` on Shodan/Censys finds the origin behind a CDN and the
org's other instances).

Pure-stdlib: the MurmurHash3 below is implemented locally so the core keeps its
no-third-party guarantee (no `mmh3` dependency).
"""

from __future__ import annotations

import base64
import re
import ssl
import urllib.error
import urllib.request
from typing import Optional
from urllib.parse import urljoin

from ..models import Finding, Service, Severity

USER_AGENT = "celsius/0.4 (+authorized security testing)"
TIMEOUT = 12


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32, returned signed (matches mmh3.hash default / Shodan)."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed
    rounded_end = length & 0xFFFFFFFC
    for i in range(0, rounded_end, 4):
        k1 = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24))
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 = (data[rounded_end + 2]) << 16
    if tail >= 2:
        k1 |= (data[rounded_end + 1]) << 8
    if tail >= 1:
        k1 |= data[rounded_end]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(raw: bytes) -> int:
    """Shodan-style favicon hash: mmh3 of the base64 (with newlines) encoding."""
    return murmur3_32(base64.encodebytes(raw))


# hash -> (product name, is_sensitive_panel). A `True` flag means an exposed
# management/admin interface (worth a finding on its own).
#
# Favicon hashes are version- and brand-specific (a customised favicon, or a new
# release, changes the hash), so this is a best-effort STARTER set of values
# observed from real app instances — extend it as you encounter apps in the
# field. A non-match is never a failure: the raw hash is always reported so it
# can be pivoted on Shodan/Censys (`http.favicon.hash:<n>`).
_KNOWN: dict[int, tuple[str, bool]] = {
    1284217296: ("Grafana", True),       # play.grafana.org
    -1668137428: ("Gitea", False),       # gitea.com
    -1594544491: ("Gitea", False),       # try.gitea.io
    -2015445018: ("Zipline", False),     # file-upload host
}


def _fetch(url: str, insecure: bool, auth) -> tuple[Optional[int], bytes]:
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
            return resp.status, resp.read(200_000)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError):
        return None, b""


_ICON_RE = re.compile(
    r'<link[^>]+rel=["\']?[^"\'>]*icon[^"\'>]*["\']?[^>]*href=["\']?([^"\'> ]+)',
    re.I,
)


def _icon_url(base_url: str, html: Optional[str]) -> str:
    if html:
        m = _ICON_RE.search(html)
        if m:
            return urljoin(base_url, m.group(1))
    return urljoin(base_url, "/favicon.ico")


def analyze(base_url: str, *, html: Optional[str] = None, insecure: bool = False, auth=None
            ) -> tuple[list[Service], list[Finding], Optional[int], list[str]]:
    """Returns (services, findings, favicon_hash, errors)."""
    if not base_url:
        return [], [], None, []
    icon = _icon_url(base_url, html)
    status, raw = _fetch(icon, insecure, auth)
    if status != 200 or not raw or len(raw) < 16:
        return [], [], None, []
    h = favicon_hash(raw)

    services: list[Service] = []
    findings: list[Finding] = []
    match = _KNOWN.get(h)
    if match:
        app, sensitive = match
        services.append(Service(name=app, source="favicon", extra={"favicon_hash": h}))
        if sensitive:
            findings.append(Finding(
                title=f"Exposed {app} interface (favicon match)",
                severity=Severity.MEDIUM,
                category="exposure",
                description=f"The favicon at {icon} matches {app} (hash {h}).",
                recommendation=("Confirm this management/admin interface should be internet-"
                                "reachable; restrict it, and check for default credentials "
                                "and known CVEs for this product."),
            ))
        else:
            findings.append(Finding(
                title=f"{app} identified via favicon",
                severity=Severity.INFO,
                category="fingerprint",
                description=f"favicon hash {h} -> {app}",
                recommendation="",
            ))
    else:
        findings.append(Finding(
            title="Favicon fingerprint",
            severity=Severity.INFO,
            category="fingerprint",
            description=(f"favicon hash {h} (no local match). Pivot: search "
                         f"`http.favicon.hash:{h}` on Shodan/Censys to find the origin "
                         "behind a CDN or other hosts running the same app."),
            recommendation="",
        ))
    return services, findings, h, []
