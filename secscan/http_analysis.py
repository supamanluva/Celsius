"""HTTP/web analysis: fetch headers, detect server software/versions, and audit
security headers (CSP, HSTS, X-Frame-Options, etc.).

Stdlib only (urllib + ssl). We deliberately do a single GET, follow redirects,
and never send a body or auth.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from typing import Optional

from .models import Finding, Service, Severity
from .targets import Target

USER_AGENT = "secscan/0.1 (+authorized security testing)"
TIMEOUT = 12

# product-name patterns we can pull out of Server / X-Powered-By style headers.
# Each: regex with a 'ver' named group (optional).
_SERVER_PATTERNS = [
    ("nginx", re.compile(r"nginx(?:/(?P<ver>[\d.]+))?", re.I)),
    ("Apache httpd", re.compile(r"apache(?:/(?P<ver>[\d.]+))?", re.I)),
    ("Microsoft-IIS", re.compile(r"microsoft-iis(?:/(?P<ver>[\d.]+))?", re.I)),
    ("OpenResty", re.compile(r"openresty(?:/(?P<ver>[\d.]+))?", re.I)),
    ("LiteSpeed", re.compile(r"litespeed(?:/(?P<ver>[\d.]+))?", re.I)),
    ("Caddy", re.compile(r"caddy(?:/(?P<ver>[\d.]+))?", re.I)),
    ("Jetty", re.compile(r"jetty(?:[/(](?P<ver>[\d.]+))?", re.I)),
    ("Apache Tomcat", re.compile(r"tomcat(?:/(?P<ver>[\d.]+))?", re.I)),
    ("PHP", re.compile(r"php(?:/(?P<ver>[\d.]+))?", re.I)),
    ("OpenSSL", re.compile(r"openssl(?:/(?P<ver>[\w.]+))?", re.I)),
]


MAX_BODY = 600_000  # cap captured HTML body


class HttpResult:
    def __init__(self, url: str, status: int, headers: dict[str, str], final_url: str,
                 body: str = ""):
        self.url = url
        self.status = status
        self.headers = headers  # lower-cased keys
        self.final_url = final_url
        self.body = body        # decoded HTML (capped), for fingerprinting


def _headers_dict(msg) -> dict[str, str]:
    """Lower-cased header dict that preserves *all* Set-Cookie values. A plain dict
    comprehension keeps only the last of repeated headers, which would drop earlier
    cookies (e.g. JSESSIONID) that fingerprinting relies on."""
    out = {k.lower(): v for k, v in msg.items()}
    cookies = msg.get_all("set-cookie") if hasattr(msg, "get_all") else None
    if cookies:
        out["set-cookie"] = "\n".join(cookies)
    return out


def fetch(url: str, *, insecure: bool = False) -> HttpResult:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPRedirectHandler(),
    )
    with opener.open(req, timeout=TIMEOUT) as resp:
        headers = _headers_dict(resp.headers)
        body = ""
        ctype = headers.get("content-type", "")
        if any(t in ctype for t in ("html", "json", "javascript", "text", "xml")) or not ctype:
            try:
                body = resp.read(MAX_BODY).decode("utf-8", errors="replace")
            except (OSError, ValueError):
                body = ""
        return HttpResult(url, resp.status, headers, resp.geturl(), body)


def analyze(target: Target, *, insecure: bool = False) -> tuple[
    Optional[HttpResult], list[Service], list[Finding], list[str]
]:
    """Returns (http_result, detected_services, findings, errors)."""
    errors: list[str] = []
    result: Optional[HttpResult] = None

    # Try the requested/derived URL, then fall back http<->https.
    candidates = [target.web_url()]
    if target.scheme is None:
        # also try plain http if https fails
        http_fallback = target.web_url().replace("https://", "http://", 1)
        candidates.append(http_fallback)

    for url in candidates:
        try:
            result = fetch(url, insecure=insecure)
            break
        except urllib.error.HTTPError as e:
            # An HTTP error still gives us headers — keep it.
            headers = _headers_dict(e.headers) if e.headers else {}
            result = HttpResult(url, e.code, headers, url)
            break
        except (urllib.error.URLError, ssl.SSLError, OSError) as e:
            errors.append(f"HTTP fetch failed for {url}: {e}")
            continue

    if result is None:
        return None, [], [], errors

    services = detect_services(result)
    findings = audit_security_headers(result)
    return result, services, findings, errors


def detect_services(result: HttpResult) -> list[Service]:
    services: list[Service] = []
    seen: set[str] = set()

    candidate_headers = ["server", "x-powered-by", "via", "x-aspnet-version"]
    for hname in candidate_headers:
        value = result.headers.get(hname)
        if not value:
            continue
        for name, pat in _SERVER_PATTERNS:
            m = pat.search(value)
            if not m:
                continue
            version = m.groupdict().get("ver")
            key = f"{name}:{version}"
            if key in seen:
                continue
            seen.add(key)
            services.append(
                Service(
                    name=name,
                    version=version,
                    source=f"http-header:{hname}",
                    extra={"raw": value},
                )
            )
    return services


# ---- Security header auditing -------------------------------------------------

def audit_security_headers(result: HttpResult) -> list[Finding]:
    h = result.headers
    findings: list[Finding] = []

    # Content-Security-Policy
    csp = h.get("content-security-policy")
    if not csp:
        findings.append(Finding(
            title="Missing Content-Security-Policy",
            severity=Severity.MEDIUM,
            category="csp",
            description="No CSP header. The page has no policy restricting where "
                        "scripts, styles, frames, etc. may load from, increasing XSS impact.",
            recommendation="Add a Content-Security-Policy header, starting with a "
                           "restrictive default-src 'self' and tightening from there.",
        ))
    else:
        findings.extend(_audit_csp(csp))

    # HSTS — only meaningful over https
    over_https = result.final_url.startswith("https://")
    hsts = h.get("strict-transport-security")
    if over_https and not hsts:
        findings.append(Finding(
            title="Missing HSTS (Strict-Transport-Security)",
            severity=Severity.MEDIUM,
            category="headers",
            description="HTTPS is served but Strict-Transport-Security is absent, "
                        "so browsers may downgrade to HTTP and be MITM'd.",
            recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        ))
    elif hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 15552000:  # < 180 days
            findings.append(Finding(
                title="Weak HSTS max-age",
                severity=Severity.LOW,
                category="headers",
                description=f"HSTS max-age is low ({m.group(1)}s).",
                recommendation="Use max-age of at least 15552000 (180 days), ideally 31536000.",
                evidence=hsts,
            ))

    # X-Frame-Options / frame-ancestors
    xfo = h.get("x-frame-options")
    csp_has_frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())
    if not xfo and not csp_has_frame_ancestors:
        findings.append(Finding(
            title="No clickjacking protection",
            severity=Severity.LOW,
            category="headers",
            description="Neither X-Frame-Options nor CSP frame-ancestors is set; the "
                        "page can be framed by other origins (clickjacking).",
            recommendation="Set X-Frame-Options: DENY (or SAMEORIGIN) or CSP frame-ancestors 'self'.",
        ))

    # X-Content-Type-Options
    if h.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(Finding(
            title="Missing X-Content-Type-Options: nosniff",
            severity=Severity.LOW,
            category="headers",
            description="Browsers may MIME-sniff responses, enabling some XSS vectors.",
            recommendation="Add X-Content-Type-Options: nosniff.",
        ))

    # Referrer-Policy
    if not h.get("referrer-policy"):
        findings.append(Finding(
            title="Missing Referrer-Policy",
            severity=Severity.INFO,
            category="headers",
            description="No Referrer-Policy; full URLs may leak to third parties via Referer.",
            recommendation="Add Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
        ))

    # Information disclosure: verbose Server / X-Powered-By with versions
    server = h.get("server", "")
    if re.search(r"\d+\.\d+", server):
        findings.append(Finding(
            title="Server version disclosed",
            severity=Severity.INFO,
            category="info-disclosure",
            description="The Server header reveals an exact version, helping attackers "
                        "match known CVEs.",
            recommendation="Consider hiding the version (e.g. nginx: server_tokens off).",
            evidence=f"Server: {server}",
        ))
    if h.get("x-powered-by"):
        findings.append(Finding(
            title="X-Powered-By disclosed",
            severity=Severity.INFO,
            category="info-disclosure",
            description="X-Powered-By reveals backend technology/version.",
            recommendation="Remove the X-Powered-By header.",
            evidence=f"X-Powered-By: {h['x-powered-by']}",
        ))

    # Cookies without flags
    set_cookie = h.get("set-cookie", "")
    if set_cookie:
        low = set_cookie.lower()
        if over_https and "secure" not in low:
            findings.append(Finding(
                title="Cookie without Secure flag",
                severity=Severity.LOW,
                category="cookies",
                description="A cookie is set over HTTPS without the Secure attribute.",
                recommendation="Add the Secure attribute to cookies.",
                evidence=set_cookie[:200],
            ))
        if "httponly" not in low:
            findings.append(Finding(
                title="Cookie without HttpOnly flag",
                severity=Severity.LOW,
                category="cookies",
                description="A cookie is set without HttpOnly, exposing it to JS/XSS theft.",
                recommendation="Add the HttpOnly attribute to session cookies.",
                evidence=set_cookie[:200],
            ))

    return findings


def _audit_csp(csp: str) -> list[Finding]:
    findings: list[Finding] = []
    low = csp.lower()

    if "unsafe-inline" in low:
        findings.append(Finding(
            title="CSP allows 'unsafe-inline'",
            severity=Severity.MEDIUM,
            category="csp",
            description="'unsafe-inline' permits inline scripts/styles, largely defeating "
                        "CSP's XSS protection.",
            recommendation="Remove 'unsafe-inline'; use nonces or hashes instead.",
            evidence=csp[:300],
        ))
    if "unsafe-eval" in low:
        findings.append(Finding(
            title="CSP allows 'unsafe-eval'",
            severity=Severity.LOW,
            category="csp",
            description="'unsafe-eval' permits eval()-style execution, expanding XSS surface.",
            recommendation="Remove 'unsafe-eval' and refactor code that relies on it.",
            evidence=csp[:300],
        ))
    # wildcard sources in script/default-src
    if re.search(r"(default-src|script-src)[^;]*\*", low):
        findings.append(Finding(
            title="CSP uses wildcard source",
            severity=Severity.MEDIUM,
            category="csp",
            description="A wildcard (*) in default-src/script-src lets scripts load from any origin.",
            recommendation="Replace * with an explicit allow-list of trusted origins.",
            evidence=csp[:300],
        ))
    if "default-src" not in low:
        findings.append(Finding(
            title="CSP has no default-src",
            severity=Severity.LOW,
            category="csp",
            description="Without default-src, unlisted directives fall back to allowing everything.",
            recommendation="Define a restrictive default-src 'self' (or 'none').",
            evidence=csp[:300],
        ))
    return findings
