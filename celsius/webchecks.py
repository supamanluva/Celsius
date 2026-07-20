"""Breadth web-security checks: CSP deep evaluation, JWT analysis, CORS
misconfiguration probing, and security.txt presence.

CSP and JWT are passive (they analyse the already-fetched response). security.txt
is a passive well-known fetch. CORS sends a few benign requests with crafted
Origin headers (safe-active) — nothing is mutated.
"""

from __future__ import annotations

import base64
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .models import Finding, Severity

# ---- shared client-side rate limit (scope.rate_limit_rps) ---------------------
# Active checks here (CORS, takeover, security.txt) share one throttle so the
# scanner never exceeds the operator-configured request rate against a target.
# Set once per scan by the engine; 0 disables (no throttle).
_rate_lock = threading.Lock()
_min_interval = 0.0
_last_request = [0.0]


def set_rate_limit(rps: "float | int | None") -> None:
    global _min_interval
    _min_interval = (1.0 / rps) if rps and rps > 0 else 0.0


def _throttle() -> None:
    if _min_interval <= 0:
        return
    with _rate_lock:
        wait = _last_request[0] + _min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _last_request[0] = time.monotonic()

USER_AGENT = "celsius/1.1 (+authorized security testing)"
TIMEOUT = 10
_EVIL_ORIGIN = "https://celsius-cors-probe.example"


# ---- CSP deep evaluation (passive) -------------------------------------------

def _parse_csp(policy: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for directive in policy.split(";"):
        parts = directive.split()
        if parts:
            out[parts[0].lower()] = [p.lower() for p in parts[1:]]
    return out


def analyze_csp(headers: dict) -> list[Finding]:
    """Evaluate the *content* of a Content-Security-Policy; flag policies that
    don't actually stop XSS. This is the single authoritative CSP evaluator —
    http_analysis only reports a missing header, and this returns [] when the
    header is absent so nothing is double-reported."""
    policy = headers.get("content-security-policy")
    if not policy:
        return []
    csp = _parse_csp(policy)
    findings: list[Finding] = []
    script = csp.get("script-src", csp.get("default-src", []))

    def add(title, sev, desc, rec):
        findings.append(Finding(title=title, severity=sev, category="csp",
                                description=desc, recommendation=rec, evidence=policy[:300]))

    if "'unsafe-inline'" in script:
        add("CSP allows 'unsafe-inline' scripts", Severity.HIGH,
            "script-src/default-src includes 'unsafe-inline', so injected inline scripts "
            "still execute — the CSP gives little XSS protection.",
            "Remove 'unsafe-inline'; use nonces or hashes for legitimate inline scripts.")
    if "'unsafe-eval'" in script:
        add("CSP allows 'unsafe-eval'", Severity.MEDIUM,
            "script-src allows 'unsafe-eval', enabling eval()/Function()-based payloads.",
            "Remove 'unsafe-eval' and refactor code that relies on dynamic evaluation.")
    if "*" in script:
        add("CSP script-src uses a wildcard", Severity.HIGH,
            "A wildcard source lets scripts load from any origin, defeating the policy.",
            "Restrict script-src to specific trusted origins (or 'self').")
    if any(s.startswith("data:") for s in script):
        add("CSP allows data: in script-src", Severity.MEDIUM,
            "data: URIs in script-src let attackers smuggle inline script as a data URL.",
            "Remove data: from script-src.")
    if "default-src" not in csp and "object-src" not in csp:
        add("CSP missing object-src/default-src", Severity.LOW,
            "Without object-src 'none' (or a default-src fallback), plugins/objects can be injected.",
            "Add object-src 'none' and a restrictive default-src.")
    if "base-uri" not in csp:
        add("CSP missing base-uri", Severity.LOW,
            "No base-uri directive; a <base> tag injection can hijack relative URLs.",
            "Add base-uri 'none' (or 'self').")
    if "frame-ancestors" not in csp:
        add("CSP missing frame-ancestors", Severity.LOW,
            "No frame-ancestors directive; clickjacking protection relies on X-Frame-Options only.",
            "Add frame-ancestors 'none' or 'self'.")
    return findings


# ---- JWT analysis (passive) ---------------------------------------------------

_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")


def _b64url(seg: str) -> dict:
    pad = "=" * (-len(seg) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(seg + pad))
    except (ValueError, json.JSONDecodeError):
        return {}


def analyze_jwt(headers: dict, body: str) -> list[Finding]:
    """Find JWTs in Set-Cookie / response body and flag weak ones."""
    blob = (headers.get("set-cookie", "") or "") + "\n" + (body or "")
    findings: list[Finding] = []
    seen: set[str] = set()
    for tok in _JWT.findall(blob):
        head_seg = tok.split(".")[0]
        payload_seg = tok.split(".")[1]
        head = _b64url(head_seg)
        if not head:
            continue
        key = tok[:24]
        if key in seen:
            continue
        seen.add(key)
        alg = str(head.get("alg", "")).lower()
        payload = _b64url(payload_seg)
        masked = tok[:12] + "…" + tok[-6:]
        if alg == "none":
            findings.append(Finding(
                title="JWT with alg=none (unsigned token)", severity=Severity.CRITICAL,
                category="jwt",
                description="A JSON Web Token using alg=none is unsigned — anyone can forge "
                            "arbitrary claims (e.g. escalate to admin).",
                recommendation="Reject alg=none server-side; require a strong signature (RS256/ES256).",
                evidence=masked))
        elif alg.startswith("hs"):
            findings.append(Finding(
                title=f"JWT uses symmetric {alg.upper()} (HMAC)", severity=Severity.LOW,
                category="jwt",
                description="The token is signed with a shared HMAC secret. If the secret is weak "
                            "or leaked, tokens can be forged.",
                recommendation="Use a long random secret, or prefer asymmetric RS256/ES256.",
                evidence=masked))
        if payload and "exp" not in payload:
            findings.append(Finding(
                title="JWT without an expiry (exp) claim", severity=Severity.LOW, category="jwt",
                description="The token has no exp claim, so a stolen token never expires.",
                recommendation="Add a short exp; rotate/refresh tokens.",
                evidence=masked))
    return findings


# ---- security.txt (passive well-known fetch) ----------------------------------

def _get(url: str, insecure: bool, auth=None, origin: str = ""):
    _throttle()
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    hdrs = {"User-Agent": USER_AGENT}
    if origin:
        hdrs["Origin"] = origin
    if auth:
        hdrs = auth.merge(hdrs)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, \
                resp.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, ""
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError):
        return None, {}, ""


def check_security_txt(base_url: str, *, insecure: bool = False, auth=None) -> list[Finding]:
    root = "{0.scheme}://{0.netloc}".format(urllib.parse.urlparse(base_url))
    for path in ("/.well-known/security.txt", "/security.txt"):
        status, _h, body = _get(root + path, insecure, auth)
        if status == 200 and ("contact:" in body.lower() or "-----begin" in body.lower()):
            return []  # present — good, no finding
    return [Finding(
        title="No security.txt", severity=Severity.INFO, category="hardening",
        description="No /.well-known/security.txt was found; researchers have no documented "
                    "way to report vulnerabilities.",
        recommendation="Publish /.well-known/security.txt with a Contact: field (RFC 9116).",
    )]


# ---- CORS misconfiguration (safe-active) --------------------------------------

# Paths that look like API surface — worth a CORS probe beyond the site root.
_APIISH = re.compile(r"/(api|graphql|gql|rest|rpc)(/|$)|/v\d+(/|$)", re.I)


def cors_candidate_paths(recon: dict) -> list[str]:
    """Derive up to 3 API-ish paths for the CORS probe beyond the site root,
    from recon data: crawler-surfaced endpoints/routes and apidisco results
    (OpenAPI paths, the GraphQL endpoint URL)."""
    crawl = recon.get("crawl") or {}
    api = recon.get("api") or {}
    cands = (list(crawl.get("endpoints") or []) + list(crawl.get("routes") or [])
             + list(api.get("endpoints") or []))
    gql = api.get("graphql") or {}
    if isinstance(gql, dict) and gql.get("url"):
        cands.insert(0, gql["url"])  # an introspectable endpoint is the juiciest target
    out: list[str] = []
    for cand in cands:
        path = urllib.parse.urlparse(str(cand)).path
        if path and path != "/" and _APIISH.search(path) and path not in out:
            out.append(path)
            if len(out) >= 3:
                break
    return out


def _cors_probe(url: str, insecure: bool, auth) -> "tuple[bool, list[Finding]]":
    """Probe one URL with crafted Origin headers. Returns (reachable, findings)."""
    findings: list[Finding] = []
    # 1) reflected arbitrary origin
    status, h, _b = _get(url, insecure, auth, origin=_EVIL_ORIGIN)
    if status is None:
        return False, findings
    acao = h.get("access-control-allow-origin", "")
    acac = (h.get("access-control-allow-credentials", "") or "").lower() == "true"
    if acao == _EVIL_ORIGIN:
        sev = Severity.HIGH if acac else Severity.MEDIUM
        findings.append(Finding(
            title="CORS reflects arbitrary Origin" + (" with credentials" if acac else ""),
            severity=sev, category="cors",
            description=f"The server echoed our attacker Origin in Access-Control-Allow-Origin "
                        f"({acao})" + (" together with Allow-Credentials: true, so a malicious "
                        "site can read authenticated responses." if acac else "."),
            recommendation="Validate Origin against an allowlist; never reflect it. Don't pair "
                           "credentials with a permissive ACAO.",
            evidence=f"GET {url}: ACAO={acao}; ACAC={acac}"))
    # 2) null origin trust
    status, h, _b = _get(url, insecure, auth, origin="null")
    acao = h.get("access-control-allow-origin", "")
    acac = (h.get("access-control-allow-credentials", "") or "").lower() == "true"
    if acao == "null":
        findings.append(Finding(
            title="CORS trusts the 'null' origin", severity=Severity.MEDIUM, category="cors",
            description="Access-Control-Allow-Origin: null is returned; sandboxed iframes and "
                        "some attacker contexts present Origin: null and would be trusted"
                        + (" with credentials." if acac else "."),
            recommendation="Never allow the literal 'null' origin.",
            evidence=f"GET {url}: ACAO=null; ACAC={acac}"))
    return True, findings


def check_cors(base_url: str, *, insecure: bool = False, auth=None,
               paths: "list[str] | None" = None) -> list[Finding]:
    """Probe the site root — plus up to 3 extra API-ish `paths` when given (see
    cors_candidate_paths) — with crafted Origin headers. Every request goes
    through `_get`, i.e. the shared scope rate limit."""
    urls = [base_url]
    if paths:
        root = "{0.scheme}://{0.netloc}".format(urllib.parse.urlparse(base_url))
        urls.extend(root + p for p in paths[:3] if p.startswith("/"))
    findings: list[Finding] = []
    seen: set[str] = set()  # one finding per misconfiguration, not per probed path
    for url in urls:
        reachable, found = _cors_probe(url, insecure, auth)
        if url == base_url and not reachable:
            return []  # target unreachable — no point probing deeper paths
        for f in found:
            if f.title not in seen:
                seen.add(f.title)
                findings.append(f)
    return findings


# ---- subdomain takeover (safe-active) -----------------------------------------

# (cname substring, response fingerprint, service) for dangling-CNAME takeovers.
# Fingerprints follow the community-maintained can-i-take-over-xyz list
# (https://github.com/EdOverflow/can-i-take-over-xyz) — only entries with a
# documented dangling-CNAME takeover path and a distinctive unclaimed-resource
# body string. The dangling-CNAME precondition (a live CNAME pointing at the
# provider domain) is the real FP guard; the body match confirms it.
_TAKEOVER_SIGS = [
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    ("herokuapp.com", "No such app", "Heroku"),
    ("herokudns.com", "no-such-app", "Heroku"),
    ("s3.amazonaws.com", "NoSuchBucket", "AWS S3"),
    ("amazonaws.com", "NoSuchBucket", "AWS S3"),
    ("azurewebsites.net", "404 Web Site not found", "Azure"),
    ("trafficmanager.net", "404 Web Site not found", "Azure"),
    ("cloudapp.net", "404 Web Site not found", "Azure"),
    ("azure-api.net", "404 Web Site not found", "Azure"),
    ("azureedge.net", "404 Web Site not found", "Azure"),
    ("core.windows.net", "The resource you are looking for has been removed", "Azure Storage"),
    ("fastly.net", "Fastly error: unknown domain", "Fastly"),
    ("myshopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
    ("surge.sh", "project not found", "Surge.sh"),
    ("bitbucket.io", "Repository not found", "Bitbucket"),
    ("pantheonsite.io", "The gods are wise", "Pantheon"),
    ("zendesk.com", "Help Center Closed", "Zendesk"),
    ("readthedocs.io", "unknown to Read the Docs", "Read the Docs"),
    ("netlify.app", "Not Found - Request ID", "Netlify"),
    ("vercel.app", "DEPLOYMENT_NOT_FOUND", "Vercel"),
    ("firebaseapp.com", "Site Not Found", "Firebase"),
    ("squarespace.com", "No Such Account", "Squarespace"),
    ("tumblr.com", "Whatever you were looking for", "Tumblr"),
    ("wordpress.com", "Do you want to register", "WordPress.com"),
    ("ghost.io", "The thing you were looking for is no longer here", "Ghost"),
    ("fly.dev", "404 Not Found", "Fly.io"),
    ("freshdesk.com", "There is no helpdesk here", "Freshdesk"),
    ("helpscoutdocs.com", "No settings were found for this company", "Help Scout"),
    ("custom.intercom.help", "Uh oh. That page doesn't exist", "Intercom"),
    ("statuspage.io", "You are being redirected", "Statuspage"),
    ("hubspot.net", "Domain not configured", "HubSpot"),
    ("unbouncepages.com", "The requested URL was not found on this server", "Unbounce"),
    ("s.strikinglydns.com", "But if you're looking to build your own website", "Strikingly"),
    ("proxy.webflow.com", "The page you are looking for doesn't exist or has been moved", "Webflow"),
    ("kinsta.cloud", "No Site For Domain", "Kinsta"),
    ("smartjobboard.com", "This job board website is either expired or its domain name is invalid",
     "SmartJobBoard"),
    ("worksites.net", "Hello! Sorry, but the website you", "Worksites"),
    ("cargocollective.com", "If you're moving your domain away from Cargo", "Cargo"),
    ("tilda.ws", "Please go to the site settings", "Tilda"),
    ("myjetbrains.com", "is not a registered InCloud YouTrack", "JetBrains YouTrack"),
    ("agilecrm.com", "Sorry, this page is no longer available", "Agile CRM"),
    ("ideas.aha.io", "There is no portal here", "Aha!"),
    ("createsend.com", "Trying to access your account?", "Campaign Monitor"),
    ("acquia-sites.com", "The site you are looking for could not be found", "Acquia"),
    ("gr8.com", "With GetResponse Landing Pages", "GetResponse"),
    ("launchrock.com", "It looks like you may have taken a wrong turn", "LaunchRock"),
    ("ngrok.io", "ngrok.io not found", "Ngrok"),
    ("stats.pingdom.com", "Sorry, couldn't find the status page", "Pingdom"),
    ("readme.io", "The creators of this project are still working on making everything perfect",
     "Readme.io"),
    ("uservoice.com", "This UserVoice subdomain is currently available", "UserVoice"),
]


def _cname(host: str) -> str:
    params = urllib.parse.urlencode({"name": host, "type": "CNAME"})
    req = urllib.request.Request(f"https://dns.google/resolve?{params}",
                                 headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
        for ans in data.get("Answer", []) or []:
            if ans.get("type") == 5:  # CNAME
                return ans.get("data", "").rstrip(".").lower()
    except (urllib.error.URLError, OSError, ValueError):
        pass
    return ""


def check_takeover(hosts: list[str], *, insecure: bool = False, limit: int = 40) -> list[Finding]:
    """For each subdomain, look for a dangling CNAME to a known service whose
    unclaimed-resource fingerprint appears in the response (subdomain takeover)."""
    findings: list[Finding] = []
    for host in hosts[:limit]:
        cn = _cname(host)
        if not cn:
            continue
        sig = next((s for s in _TAKEOVER_SIGS if s[0] in cn), None)
        if not sig:
            continue
        for scheme in ("https", "http"):
            status, _h, body = _get(f"{scheme}://{host}/", insecure)
            if body and sig[1].lower() in body.lower():
                findings.append(Finding(
                    title=f"Possible subdomain takeover: {host} ({sig[2]})",
                    severity=Severity.HIGH, category="takeover",
                    description=f"{host} has a dangling CNAME to {cn} ({sig[2]}) and the service "
                                f"returns its unclaimed-resource page — an attacker may be able to "
                                f"claim it and serve content from your subdomain.",
                    recommendation=f"Remove the dangling DNS record or reclaim the {sig[2]} resource.",
                    evidence=f"CNAME {cn}; fingerprint matched"))
                break
    return findings
