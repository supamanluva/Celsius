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

from .. import eol as eol_mod
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
    ("Vercel", "hosting", "any-header", re.compile(r"x-vercel-id|x-vercel-cache|\bvercel\b", re.I)),
    ("Sucuri", "waf", "any-header", re.compile(r"sucuri", re.I)),
    # Node/PaaS hosting platforms (named so the edge isn't reported as "unknown")
    ("Netlify", "hosting", "any-header", re.compile(r"x-nf-request-id|\bnetlify\b", re.I)),
    ("Railway", "hosting", "any-header", re.compile(r"x-railway-|railway\.app|server:\s*railway", re.I)),
    ("Render", "hosting", "any-header", re.compile(r"x-render-origin-server|server:\s*render", re.I)),
    ("Fly.io", "hosting", "any-header", re.compile(r"\bfly-request-id\b|server:\s*fly\b", re.I)),
    ("Heroku", "hosting", "any-header", re.compile(r"heroku-router|\bvegur\b|server:\s*cowboy", re.I)),
    ("GitHub Pages", "hosting", "any-header", re.compile(r"x-github-request-id|server:\s*github\.com", re.I)),
    # CouchDB leaks identifying headers even behind a CDN (Server stripped): the
    # x-couchdb-* request headers and the Basic-auth realm give it away.
    ("CouchDB", "server", "any-header", re.compile(r"x-couch(?:db)?-|realm=[\"']?couchdb", re.I)),
    ("GitLab Pages", "hosting", "any-header", re.compile(r"server:\s*gitlab", re.I)),
    ("DigitalOcean App Platform", "hosting", "any-header", re.compile(r"x-do-app-origin|\bdo-app\b", re.I)),
    ("Microsoft Azure", "hosting", "any-header", re.compile(r"x-azure-ref|x-msedge-ref|azurewebsites\.net", re.I)),
    ("Google Cloud", "hosting", "any-header", re.compile(r"\bgoogle frontend\b|x-cloud-trace-context|\bgse\b", re.I)),
    ("Firebase Hosting", "hosting", "any-header", re.compile(r"x-firebase|firebaseapp\.com", re.I)),
    ("Squarespace", "hosting", "any-header", re.compile(r"\bsquarespace\b", re.I)),
    ("Wix", "hosting", "any-header", re.compile(r"x-wix-request-id|\bpepyaka\b", re.I)),
    ("WP Engine", "hosting", "any-header", re.compile(r"x-wpengine|wp engine", re.I)),
    ("Kinsta", "hosting", "any-header", re.compile(r"x-kinsta", re.I)),
    ("Pantheon", "hosting", "any-header", re.compile(r"x-pantheon|server:\s*pantheon", re.I)),
    # CDNs
    ("Bunny CDN", "cdn", "any-header", re.compile(r"\bbunnycdn\b", re.I)),
    ("KeyCDN", "cdn", "any-header", re.compile(r"\bkeycdn\b", re.I)),
    ("StackPath", "cdn", "any-header", re.compile(r"\bstackpath\b", re.I)),
    # WAFs / load balancers
    ("Cloudflare WAF", "waf", "server", re.compile(r"cloudflare", re.I)),
    ("AWS WAF/ALB", "waf", "any-header", re.compile(r"\bawselb\b|x-amz", re.I)),
    ("Imperva/Incapsula", "waf", "any-header", re.compile(r"incap_ses|visid_incap|imperva", re.I)),
    # F5 BIG-IP: default BIGipServer cookie, renamed *LTM cookie, or the
    # "=!<long base64>" encrypted persistence-cookie value.
    ("F5 BIG-IP", "lb", "cookie", re.compile(r"BIGipServer|[A-Za-z0-9]*LTM=!|=!\S{60,}", re.I)),
    # Servers
    ("nginx", "server", "server", re.compile(r"nginx(?:/(?P<ver>[\d.]+))?", re.I)),
    ("Apache httpd", "server", "server", re.compile(r"apache(?:/(?P<ver>[\d.]+))?", re.I)),
    ("Microsoft-IIS", "server", "server", re.compile(r"microsoft-iis(?:/(?P<ver>[\d.]+))?", re.I)),
    ("OpenResty", "server", "server", re.compile(r"openresty(?:/(?P<ver>[\d.]+))?", re.I)),
    ("Caddy", "server", "server", re.compile(r"\bcaddy(?:/(?P<ver>[\d.]+))?", re.I)),
    ("LiteSpeed", "server", "server", re.compile(r"litespeed(?:/(?P<ver>[\d.]+))?", re.I)),
    ("OpenSSL", "library", "server", re.compile(r"openssl/(?P<ver>[\d.]+[a-z]?)", re.I)),
    ("Apache Tomcat", "server", "any-header", re.compile(r"tomcat(?:/(?P<ver>[\d.]+))?|apache-coyote", re.I)),
    # Application servers (also tell us the backend language)
    ("Gunicorn", "language", "server", re.compile(r"gunicorn(?:/(?P<ver>[\d.]+))?", re.I)),
    ("uWSGI", "language", "server", re.compile(r"\buwsgi\b", re.I)),
    ("Werkzeug", "language", "server", re.compile(r"werkzeug(?:/(?P<ver>[\d.]+))?", re.I)),
    ("Puma", "language", "server", re.compile(r"\bpuma(?:[ /](?P<ver>[\d.]+))?", re.I)),
    ("Unicorn", "language", "server", re.compile(r"\bunicorn(?:[ /](?P<ver>[\d.]+))?", re.I)),
    ("Phusion Passenger", "server", "any-header",
     re.compile(r"phusion[ _]?passenger(?:/(?P<ver>[\d.]+))?", re.I)),
    ("Kestrel", "framework", "server", re.compile(r"\bkestrel\b", re.I)),
    # Languages / runtimes (incl. session-cookie tells)
    ("PHP", "language", "any-header", re.compile(r"php/?(?P<ver>[\d.]+)?", re.I)),
    ("PHP", "language", "cookie", re.compile(r"PHPSESSID", re.I)),
    ("Java servlet", "language", "cookie", re.compile(r"JSESSIONID", re.I)),
    ("ASP.NET", "framework", "any-header", re.compile(r"asp\.net|x-aspnet", re.I)),
    ("ASP.NET", "framework", "cookie", re.compile(r"ASP\.NET_SessionId|\.AspNetCore", re.I)),
    ("Express", "framework", "any-header", re.compile(r"\bexpress\b", re.I)),
    # CMS
    ("WordPress", "cms", "body", re.compile(r"wp-content|wp-includes|<meta name=\"generator\" content=\"WordPress (?P<ver>[\d.]+)", re.I)),
    ("SiteVision", "cms", "any-header", re.compile(r"sitevision", re.I)),
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


_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW, "INFO": Severity.INFO}

# Categories that sit in front of / host the origin (CDN, WAF, load balancer, PaaS).
_EDGE_CATS = ("cdn", "waf", "lb", "hosting")

_OS_HINT = re.compile(
    r"\((win(?:32|64|dows)?|ubuntu|debian|centos|red ?hat|rhel|fedora|"
    r"suse|alpine|unix|freebsd|openbsd|darwin)\b[^)]*\)", re.I)


def infer_platform(headers: dict[str, str], body: str, techs: list[Tech]) -> dict:
    """Best-effort passive guess of OS family + server-side runtime from headers,
    cookies and detected tech. No active probing; confidence is explicit."""
    server = headers.get("server", "")
    cookie = headers.get("set-cookie", "")
    xpb = headers.get("x-powered-by", "")
    names = {t.name for t in techs}
    evidence: list[str] = []
    os_name: Optional[str] = None
    os_conf: Optional[str] = None
    runtime: Optional[str] = None

    # Strong OS signal: an OS named in a verbose Server header.
    mo = _OS_HINT.search(server)
    if mo:
        tok = mo.group(1).lower().replace(" ", "")
        if tok.startswith("win"):
            os_name, os_conf = "Windows", "high"
        elif tok in ("unix", "freebsd", "openbsd", "darwin"):
            os_name, os_conf = tok.capitalize(), "high"
        else:
            os_name, os_conf = "Linux", "high"
        evidence.append(f"Server header: {mo.group(0)}")

    # Windows / .NET
    if "Microsoft-IIS" in names or re.search(r"ASP\.NET_SessionId", cookie, re.I) \
            or "asp.net" in (xpb + server).lower():
        os_name, os_conf = "Windows", "high"
        runtime = runtime or "ASP.NET / IIS"
        evidence.append("IIS/ASP.NET signature")

    # Java servlet stack
    if re.search(r"JSESSIONID", cookie, re.I) or "Apache Tomcat" in names or "SiteVision" in names:
        runtime = runtime or "Java (servlet / Tomcat)"
        if not os_name:
            os_name, os_conf = "Linux", "medium"
        evidence.append("JSESSIONID / Java servlet")

    # PHP
    if "PHP" in names or re.search(r"PHPSESSID", cookie, re.I):
        runtime = runtime or "PHP"
        if not os_name:
            os_name, os_conf = "Linux", "low"
        evidence.append("PHP signature")

    # Python app servers
    if names & {"Gunicorn", "uWSGI", "Werkzeug"}:
        runtime = runtime or "Python (WSGI)"
        if not os_name:
            os_name, os_conf = "Linux", "low"
        evidence.append("Python app server")

    # Ruby app servers
    if names & {"Puma", "Unicorn", "Phusion Passenger"}:
        runtime = runtime or "Ruby"
        if not os_name:
            os_name, os_conf = "Linux", "low"
        evidence.append("Ruby app server")

    # .NET (Kestrel runs on Linux or Windows -> runtime only, no OS claim)
    if "Kestrel" in names:
        runtime = runtime or ".NET (Kestrel)"
        evidence.append("Kestrel (.NET)")

    # Node.js
    if "Express" in names or "Next.js" in names:
        runtime = runtime or "Node.js"
        evidence.append("Node.js signature")

    # Weak fallback: when nothing pinned the OS, lean on the fact that nginx/
    # OpenResty and Node.js are overwhelmingly Linux in production. Low confidence.
    if not os_name:
        sl = server.lower()
        if "openresty" in sl:
            os_name, os_conf = "Linux", "low"
            evidence.append("OpenResty (Linux-typical)")
        elif "nginx" in sl:
            os_name, os_conf = "Linux", "low"
            evidence.append("nginx (Linux-typical)")
        elif "caddy" in sl or "litespeed" in sl:
            os_name, os_conf = "Linux", "low"
            evidence.append(f"{'Caddy' if 'caddy' in sl else 'LiteSpeed'} (Linux-typical)")
        elif runtime == "Node.js":
            os_name, os_conf = "Linux", "low"
            evidence.append("Node.js (Linux-typical in production)")
        elif any(t.category == "hosting" for t in techs):
            os_name, os_conf = "Linux", "low"
            evidence.append("managed hosting platform (Linux-based)")

    edge = sorted({t.name for t in techs if t.category in _EDGE_CATS})
    return {
        "os": os_name, "os_confidence": os_conf, "runtime": runtime,
        "server": server or None, "edge": edge, "evidence": evidence,
    }


def _eol_finding(v: dict) -> Finding:
    eol = v["status"] == "eol"
    label = f"{v['product']} {v['version']}".strip()
    return Finding(
        title=("End-of-life software: " if eol else "Software nearing end-of-life: ") + label,
        severity=_SEV.get(v["severity"], Severity.MEDIUM), category="eol",
        description=v["note"],
        recommendation="Upgrade to a vendor-supported release that still receives security "
                       "patches; EOL software accrues unpatched vulnerabilities.",
        evidence=f"EOL {v['eol_date']}",
    )


def _platform_finding(p: dict) -> Optional[Finding]:
    bits = []
    if p["os"]:
        bits.append(f"OS: {p['os']} ({p['os_confidence']} confidence)")
    if p["runtime"]:
        bits.append(f"runtime: {p['runtime']}")
    if p["server"]:
        bits.append(f"server: {p['server']}")
    if p["edge"]:
        bits.append(f"edge/LB: {', '.join(p['edge'])}")
    if not bits:
        return None
    desc = " · ".join(bits)
    if p["edge"]:
        desc += (". Origin OS may be masked by the edge/load balancer; this reflects "
                 "the visible stack, not necessarily the backend.")
    return Finding(
        title="Platform (passive inference)", severity=Severity.INFO, category="platform",
        description=desc,
        recommendation="Use as a lead; confirm the origin OS with an authorized active scan "
                       "(sudo … --ports --os-detect) if you need certainty.",
        evidence="; ".join(p["evidence"])[:160],
    )


def fingerprint(headers: dict[str, str],
                body: str) -> tuple[list[Tech], list[Service], list[Finding], dict]:
    """Returns (techs, services_to_cve, findings, platform)."""
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
    cdn_waf = [t for t in techs if t.category in _EDGE_CATS]
    if cdn_waf:
        names = ", ".join(sorted({t.name for t in cdn_waf}))
        findings.append(Finding(
            title=f"Edge/WAF detected: {names}",
            severity=Severity.INFO, category="fingerprint",
            description="A CDN/WAF/load balancer/host sits in front of the origin. Server "
                        "versions and some checks reflect the edge, not the backend.",
            recommendation="Account for the edge when interpreting results; test the "
                           "origin directly only if authorized and reachable.",
            evidence=names,
        ))
    techlist = [t for t in techs if t.category not in _EDGE_CATS]
    if techlist:
        findings.append(Finding(
            title=f"Technologies detected ({len(techlist)})",
            severity=Severity.INFO, category="fingerprint",
            description="; ".join(f"{t.name}{' ' + t.version if t.version else ''}" for t in techlist),
            recommendation="Versioned components are checked against the CVE database.",
        ))

    # passive OS/platform inference
    platform = infer_platform(headers, body, techs)
    pf = _platform_finding(platform)
    if pf:
        findings.append(pf)

    # end-of-life / outdated platform components
    for t in techs:
        if t.version:
            verdict = eol_mod.check_eol(t.name, t.version)
            if verdict:
                findings.append(_eol_finding(verdict))
    distro_eol = eol_mod.check_os_distro(server)
    if distro_eol:
        findings.append(_eol_finding(distro_eol))

    return techs, services, findings, platform
