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

USER_AGENT = "celsius/0.1 (+authorized security testing)"
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

# A default nginx/OpenResty/Apache error page ends with a footer like
# "<hr><center>nginx/1.25.3</center>" — the exact version, emitted by the server
# core rather than the app. Many hosts strip the `Server` header on normal 200s
# yet leave `server_tokens on`, so a crafted request that forces a default error
# page recovers the version the header hides. (If server_tokens is off, the footer
# is just "nginx"/"openresty" with no number and this recovers nothing — by design.)
_ERRPAGE_VER = re.compile(r"\b(?P<name>nginx|openresty|apache)/(?P<ver>\d+(?:\.\d+)+)", re.I)
_ERRPAGE_PRODUCT = {"nginx": "nginx", "openresty": "OpenResty", "apache": "Apache httpd"}


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


def fetch(url: str, *, insecure: bool = False, auth=None) -> HttpResult:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    hdrs = auth.merge({"User-Agent": USER_AGENT}) if auth else {"User-Agent": USER_AGENT}
    req = urllib.request.Request(url, headers=hdrs, method="GET")
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


def analyze(target: Target, *, insecure: bool = False, auth=None) -> tuple[
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
            result = fetch(url, insecure=insecure, auth=auth)
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
    findings += reconcile_server_identity(result, services)
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


def _fetch_body(url: str, *, method: str = "GET", insecure: bool = False,
                auth=None) -> tuple[Optional[int], str]:
    """One request; return (status, body) capturing error-response bodies too.
    urllib raises on 4xx/5xx, but the error page IS what we want, so read it."""
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    hdrs = auth.merge({"User-Agent": USER_AGENT}) if auth else {"User-Agent": USER_AGENT}
    req = urllib.request.Request(url, headers=hdrs, method=method)
    # No redirect handler: an error page is emitted at the origin; following a
    # 3xx would just take us to the app's normal content.
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read(MAX_BODY).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, (e.read(MAX_BODY).decode("utf-8", errors="replace") if e.fp else "")
        except (OSError, ValueError):
            return e.code, ""
    except (urllib.error.URLError, ssl.SSLError, OSError):
        return None, ""


def probe_server_version(base_url: str, *, insecure: bool = False,
                         auth=None) -> tuple[Optional[tuple[str, str]], list[str]]:
    """Actively coax the origin into emitting a default error page whose footer
    leaks an exact nginx/OpenResty/Apache version, even when the Server header
    hides it. Returns ((product, version), notes). None if nothing was recovered.

    Sends a handful of crafted-but-benign requests (an over-long URI, an unknown
    method, a random 404 path). Safe-active: no payloads, no writes, no auth."""
    import secrets

    base = base_url.rstrip("/")
    notes: list[str] = []
    # Ordered by how hard the page is to customize: the 414 (over-long request
    # line) and an unknown method are handled by nginx core before any per-location
    # error_page directive, so they leak most reliably; a 404 may hit a custom page.
    probes = [
        ("414 over-long URI", "GET", f"{base}/{'a' * 14000}"),
        ("unknown method", "QUACK", f"{base}/"),
        ("404 random path", "GET", f"{base}/{secrets.token_hex(16)}"),
    ]
    for label, method, url in probes:
        status, body = _fetch_body(url, method=method, insecure=insecure, auth=auth)
        if not body:
            continue
        m = _ERRPAGE_VER.search(body)
        if m:
            product = _ERRPAGE_PRODUCT[m.group("name").lower()]
            version = m.group("ver")
            notes.append(f"recovered {product}/{version} from the {label} error page "
                         f"(HTTP {status}) — the Server header hid it but the error "
                         f"footer did not")
            return (product, version), notes
    notes.append("error-page probes did not leak a version (server_tokens off, a CDN "
                 "served the error, or custom error pages) — version stays unknown")
    return None, notes


def _fronting_proxy(result: HttpResult) -> Optional[str]:
    """Name of a reverse proxy / CDN sitting in front of the origin, if the headers
    betray one (a Via header, or a CDN's signature header). None if direct."""
    via = result.headers.get("via")
    if via:
        for name, pat in _SERVER_PATTERNS:
            if pat.search(via):
                return name
        tok = via.split(",")[0].split()        # "1.1 vegur" -> "vegur"
        return tok[-1] if tok else "a proxy"
    if result.headers.get("cf-ray"):
        return "Cloudflare"
    if result.headers.get("x-served-by") or result.headers.get("fastly-debug-digest"):
        return "Fastly"
    return None


def reconcile_server_identity(result: HttpResult, services: list[Service]) -> list[Finding]:
    """A reverse proxy/CDN in front of the origin means the ``Server`` header version
    may belong to an upstream behind it — or be a spoofed/pass-through value — rather
    than the software that actually terminates the connection. Flag the ambiguity so
    version-based CVEs on that origin aren't read as confirmed-exploitable on the
    reachable edge. Annotates the origin service in place; returns 0/1 findings."""
    proxy = _fronting_proxy(result)
    if not proxy:
        return []
    origin = next((s for s in services if s.source == "http-header:server"), None)
    if origin is None or origin.name == proxy:        # direct, or proxy IS the origin
        return []
    origin.extra["behind_proxy"] = proxy
    ver = f" {origin.version}" if origin.version else ""
    return [Finding(
        title=f"Server identity ambiguous — {origin.name}{ver} behind {proxy}",
        severity=Severity.LOW,
        category="fingerprint",
        description=(
            f"The edge answers via {proxy} (Via/CDN header), but the Server header "
            f"advertises {origin.name}{ver}. That version may belong to an upstream "
            f"behind {proxy}, or be a spoofed/pass-through header — so version-based "
            f"CVEs for {origin.name} are NOT confirmed exploitable on the reachable edge."),
        recommendation=(
            f"Confirm what actually terminates the connection (e.g. compare an nmap -sV "
            f"of ports 80/443 against the Server header) before trusting {origin.name} "
            f"CVEs; if {origin.name} is a real upstream, verify it's reachable through {proxy}."),
        confidence="medium",
    )]


# ---- Security header auditing -------------------------------------------------

def audit_security_headers(result: HttpResult) -> list[Finding]:
    h = result.headers
    findings: list[Finding] = []

    # Content-Security-Policy — presence only. Directive *quality* (unsafe-inline,
    # wildcards, missing directives, ...) is evaluated exactly once, by
    # webchecks.analyze_csp, which is the single authoritative CSP evaluator.
    csp = h.get("content-security-policy")
    if not csp:
        ctype = h.get("content-type", "")
        if _is_api_response(ctype):
            findings.append(Finding(
                title="Missing Content-Security-Policy (API response)",
                severity=Severity.INFO,
                category="csp",
                description=f"The response is an API payload (Content-Type: {ctype or 'unknown'}), "
                            "not HTML — CSP only governs document browsing contexts, so it does "
                            "not apply here.",
                recommendation="No action needed for pure API responses; ensure any HTML-serving "
                               "endpoints on the same origin do send a CSP.",
            ))
        else:
            findings.append(Finding(
                title="Missing Content-Security-Policy",
                severity=Severity.MEDIUM,
                category="csp",
                description="No CSP header. The page has no policy restricting where "
                            "scripts, styles, frames, etc. may load from, increasing XSS impact.",
                recommendation="Add a Content-Security-Policy header, starting with a "
                               "restrictive default-src 'self' and tightening from there.",
            ))

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

    # Cookies without flags — each Set-Cookie header is audited individually so
    # one well-flagged cookie can't mask a bad one, and non-session cookies
    # don't trigger session-cookie severities.
    set_cookie = h.get("set-cookie", "")
    if set_cookie:
        findings.extend(_audit_cookies(set_cookie, over_https=over_https))

    return findings


# Content types for API payloads: CSP only governs document browsing contexts,
# so a missing CSP on these is informational, not a MEDIUM.
_API_CONTENT_TYPES = ("application/json", "application/xml", "text/xml")


def _is_api_response(content_type: str) -> bool:
    """True for JSON/XML-style API payloads (incl. +json/+xml structured suffixes)."""
    c = content_type.lower().split(";", 1)[0].strip()
    return c in _API_CONTENT_TYPES or c.endswith("+json") or c.endswith("+xml")


# Cookie names that look session/identity-ish; missing flags on these are worse.
_SESSIONISH_COOKIE = re.compile(r"session|sess|auth|token|sid|jwt", re.I)


def _audit_cookies(set_cookie: str, *, over_https: bool) -> list[Finding]:
    """Audit each Set-Cookie header on its own (they are stored joined by
    newlines — see _headers_dict). Missing Secure/HttpOnly is MEDIUM for
    session-ish cookies and LOW otherwise; a session-ish cookie without an
    explicit SameSite attribute is LOW."""
    findings: list[Finding] = []
    for raw in set_cookie.split("\n"):
        raw = raw.strip()
        if not raw or "=" not in raw:
            continue
        name = raw.split("=", 1)[0].strip()
        attrs = {p.split("=", 1)[0].strip().lower() for p in raw.split(";")[1:]}
        sessionish = bool(_SESSIONISH_COOKIE.search(name))
        sev = Severity.MEDIUM if sessionish else Severity.LOW
        ev = raw[:200]
        if over_https and "secure" not in attrs:
            findings.append(Finding(
                title=f"Cookie '{name}' without Secure flag",
                severity=sev,
                category="cookies",
                description=f"The cookie '{name}' is set over HTTPS without the Secure "
                            "attribute, so a browser may send it over plaintext HTTP.",
                recommendation="Add the Secure attribute to cookies.",
                evidence=ev,
            ))
        if "httponly" not in attrs:
            findings.append(Finding(
                title=f"Cookie '{name}' without HttpOnly flag",
                severity=sev,
                category="cookies",
                description=f"The cookie '{name}' is set without HttpOnly, exposing it "
                            "to JS/XSS theft.",
                recommendation="Add the HttpOnly attribute to session cookies.",
                evidence=ev,
            ))
        if sessionish and "samesite" not in attrs:
            findings.append(Finding(
                title=f"Cookie '{name}' without SameSite attribute",
                severity=Severity.LOW,
                category="cookies",
                description=f"The session-ish cookie '{name}' sets no explicit SameSite "
                            "attribute, leaving CSRF hardening to the browser default.",
                recommendation="Set SameSite=Lax or SameSite=Strict on session cookies.",
                evidence=ev,
            ))
    return findings
