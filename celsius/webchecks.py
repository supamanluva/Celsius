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
import urllib.error
import urllib.parse
import urllib.request

from .models import Finding, Severity

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
    """Evaluate the *content* of a Content-Security-Policy (presence is checked
    elsewhere); flag policies that don't actually stop XSS."""
    policy = headers.get("content-security-policy")
    if not policy:
        return []
    csp = _parse_csp(policy)
    findings: list[Finding] = []
    script = csp.get("script-src", csp.get("default-src", []))
    fetch_dirs = {**csp}

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

def check_cors(base_url: str, *, insecure: bool = False, auth=None) -> list[Finding]:
    findings: list[Finding] = []
    # 1) reflected arbitrary origin
    status, h, _b = _get(base_url, insecure, auth, origin=_EVIL_ORIGIN)
    if status is None:
        return findings
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
            evidence=f"ACAO={acao}; ACAC={acac}"))
    # 2) null origin trust
    status, h, _b = _get(base_url, insecure, auth, origin="null")
    acao = h.get("access-control-allow-origin", "")
    acac = (h.get("access-control-allow-credentials", "") or "").lower() == "true"
    if acao == "null":
        findings.append(Finding(
            title="CORS trusts the 'null' origin", severity=Severity.MEDIUM, category="cors",
            description="Access-Control-Allow-Origin: null is returned; sandboxed iframes and "
                        "some attacker contexts present Origin: null and would be trusted"
                        + (" with credentials." if acac else "."),
            recommendation="Never allow the literal 'null' origin.",
            evidence=f"ACAO=null; ACAC={acac}"))
    return findings


# ---- subdomain takeover (safe-active) -----------------------------------------

# (cname substring, response fingerprint, service) for dangling-CNAME takeovers.
_TAKEOVER_SIGS = [
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    ("herokuapp.com", "No such app", "Heroku"),
    ("herokudns.com", "no-such-app", "Heroku"),
    ("s3.amazonaws.com", "NoSuchBucket", "AWS S3"),
    ("amazonaws.com", "NoSuchBucket", "AWS S3"),
    ("azurewebsites.net", "404 Web Site not found", "Azure"),
    ("trafficmanager.net", "404 Web Site not found", "Azure"),
    ("cloudapp.net", "404 Web Site not found", "Azure"),
    ("fastly.net", "Fastly error: unknown domain", "Fastly"),
    ("myshopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
    ("surge.sh", "project not found", "Surge.sh"),
    ("bitbucket.io", "Repository not found", "Bitbucket"),
    ("pantheonsite.io", "The gods are wise", "Pantheon"),
    ("zendesk.com", "Help Center Closed", "Zendesk"),
    ("readthedocs.io", "unknown to Read the Docs", "Read the Docs"),
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
