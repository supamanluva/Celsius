"""Signature-based technology fingerprinting from HTTP headers + HTML body.

Detects CDNs, WAFs, CMSs, frameworks, servers, and JS libraries (with versions
where possible). Versioned detections become Service entries so the CVE engine
can look them up; CDN/WAF detections are recorded so we correctly interpret a
missing Server version (it's hidden behind the edge, not absent).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from ..models import Finding, Service, Severity


@dataclass
class Tech:
    name: str
    category: str            # cdn|waf|cms|framework|server|language|library|analytics
    version: Optional[str] = None
    evidence: str = ""


# Each signature: (name, category, where, pattern). `where` is header name,
# "body", "cookie", or "any-header". Optional named group 'ver' captures version.
_SIGS: list[tuple[str, str, str, re.Pattern]] = [
    # CDNs / edge
    ("Cloudflare", "cdn", "any-header", re.compile(r"\bcloudflare\b", re.I)),
    ("Akamai", "cdn", "any-header", re.compile(r"\bakamai", re.I)),
    ("Fastly", "cdn", "any-header", re.compile(r"\bfastly\b", re.I)),
    ("Amazon CloudFront", "cdn", "any-header", re.compile(r"cloudfront", re.I)),
    ("Vercel", "cdn", "any-header", re.compile(r"\bvercel\b", re.I)),
    ("Sucuri", "waf", "any-header", re.compile(r"sucuri", re.I)),
    # WAFs
    ("Cloudflare WAF", "waf", "server", re.compile(r"cloudflare", re.I)),
    ("AWS WAF/ALB", "waf", "any-header", re.compile(r"\bawselb\b|x-amz", re.I)),
    ("Imperva/Incapsula", "waf", "any-header", re.compile(r"incap_ses|visid_incap|imperva", re.I)),
    ("F5 BIG-IP", "waf", "cookie", re.compile(r"BIGipServer", re.I)),
    # Servers
    ("nginx", "server", "server", re.compile(r"nginx(?:/(?P<ver>[\d.]+))?", re.I)),
    ("Apache httpd", "server", "server", re.compile(r"apache(?:/(?P<ver>[\d.]+))?", re.I)),
    ("Microsoft-IIS", "server", "server", re.compile(r"microsoft-iis(?:/(?P<ver>[\d.]+))?", re.I)),
    ("OpenResty", "server", "server", re.compile(r"openresty(?:/(?P<ver>[\d.]+))?", re.I)),
    # Languages / runtimes
    ("PHP", "language", "any-header", re.compile(r"php/?(?P<ver>[\d.]+)?", re.I)),
    ("ASP.NET", "framework", "any-header", re.compile(r"asp\.net|x-aspnet", re.I)),
    ("Express", "framework", "any-header", re.compile(r"\bexpress\b", re.I)),
    # CMS
    ("WordPress", "cms", "body", re.compile(r"wp-content|wp-includes|<meta name=\"generator\" content=\"WordPress (?P<ver>[\d.]+)", re.I)),
    ("Drupal", "cms", "any-header", re.compile(r"drupal", re.I)),
    ("Joomla", "cms", "body", re.compile(r"joomla", re.I)),
    ("Shopify", "cms", "any-header", re.compile(r"shopify", re.I)),
    ("Ghost", "cms", "body", re.compile(r"content=\"Ghost (?P<ver>[\d.]+)", re.I)),
    # JS frameworks / libraries (versions where exposed)
    ("React", "framework", "body", re.compile(r"data-reactroot|react(?:\.production)?(?:\.min)?\.js", re.I)),
    ("Vue.js", "framework", "body", re.compile(r"vue(?:@(?P<ver>[\d.]+))?(?:\.min)?\.js|data-v-", re.I)),
    ("Angular", "framework", "body", re.compile(r"ng-version=\"(?P<ver>[\d.]+)\"|angular(?:\.min)?\.js", re.I)),
    ("Next.js", "framework", "any-header", re.compile(r"x-powered-by.*next\.js|/_next/", re.I)),
    ("jQuery", "library", "body", re.compile(r"jquery[-.](?P<ver>\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("Bootstrap", "library", "body", re.compile(r"bootstrap[-.](?P<ver>\d+\.\d+\.\d+)(?:\.min)?\.(?:css|js)", re.I)),
    # analytics
    ("Google Analytics", "analytics", "body", re.compile(r"google-analytics\.com|gtag\(", re.I)),
]


def fingerprint(headers: dict[str, str], body: str) -> tuple[list[Tech], list[Service], list[Finding]]:
    """Returns (techs, services_to_cve, findings)."""
    techs: list[Tech] = []
    seen: set[str] = set()
    server = headers.get("server", "")
    cookie = headers.get("set-cookie", "")
    header_blob = " ".join(f"{k}: {v}" for k, v in headers.items())

    for name, cat, where, pat in _SIGS:
        haystack = {
            "server": server,
            "cookie": cookie,
            "body": body,
            "any-header": header_blob,
        }.get(where, headers.get(where, ""))
        if not haystack:
            continue
        m = pat.search(haystack)
        if not m:
            continue
        ver = m.groupdict().get("ver") if m.groupdict() else None
        key = f"{name}:{ver}"
        if key in seen:
            continue
        seen.add(key)
        techs.append(Tech(name=name, category=cat, version=ver,
                          evidence=(m.group(0) or "")[:80]))

    # versioned techs -> Service entries for CVE lookup (servers/cms/libs/langs)
    services: list[Service] = []
    cve_cats = {"server", "cms", "language", "library", "framework"}
    for t in techs:
        if t.version and t.category in cve_cats:
            services.append(Service(name=t.name, version=t.version,
                                    source="fingerprint", extra={"category": t.category}))

    findings: list[Finding] = []
    cdn_waf = [t for t in techs if t.category in ("cdn", "waf")]
    if cdn_waf:
        names = ", ".join(sorted({t.name for t in cdn_waf}))
        findings.append(Finding(
            title=f"Edge/WAF detected: {names}",
            severity=Severity.INFO, category="fingerprint",
            description="A CDN/WAF sits in front of the origin. Server versions and "
                        "some checks reflect the edge, not the backend.",
            recommendation="Account for the edge when interpreting results; test the "
                           "origin directly only if authorized and reachable.",
            evidence=names,
        ))
    techlist = [t for t in techs if t.category not in ("cdn", "waf")]
    if techlist:
        findings.append(Finding(
            title=f"Technologies detected ({len(techlist)})",
            severity=Severity.INFO, category="fingerprint",
            description="; ".join(f"{t.name}{' ' + t.version if t.version else ''}" for t in techlist),
            recommendation="Versioned components are checked against the CVE database.",
        ))
    return techs, services, findings
