"""WordPress-specific safe-active checks.

Runs only when the fingerprint pass already identified WordPress — every probe
here is a plain GET of a well-known WordPress path, nothing a browser or a
legitimate plugin scanner wouldn't request:

  * `readme.html`              — core version disclosure
  * homepage meta generator    — version disclosure (reuses the already-fetched
                                 body; no extra request)
  * `/wp-json/wp/v2/users`     — author/username enumeration via the REST API
  * `xmlrpc.php`               — XML-RPC endpoint enabled (brute-force
                                 amplification / pingback abuse)
  * `/wp-content/uploads/`     — directory listing of uploaded files

Each check requires a content signature in the response body, so a soft-404 /
SPA catch-all that answers 200 to everything does not produce findings.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from typing import Optional
from urllib.parse import urljoin

from ..models import Finding, Severity

USER_AGENT = "celsius/0.7 (+authorized security testing)"
TIMEOUT = 12
_READ = 200_000  # bytes — uploads listing / user JSON can be long; readme is small

_README_VER = re.compile(r"Version\s+([0-9]+(?:\.[0-9]+){0,3})", re.I)
_GENERATOR = re.compile(
    r"""<meta\s+name=["']generator["']\s+content=["']WordPress\s+([0-9]+(?:\.[0-9]+){0,3})["']""",
    re.I)
_XMLRPC_BANNER = re.compile(r"XML-RPC server accepts POST requests only", re.I)
_DIR_LISTING = re.compile(r"<title>Index of /|Index of /wp-content/uploads", re.I)


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
            return resp.status, resp.read(_READ).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError):
        return None, ""


def _rest_users(base: str, insecure: bool, auth) -> list[str]:
    """User slugs exposed by /wp-json/wp/v2/users ([] when not enumerable)."""
    status, body = _fetch(urljoin(base, "wp-json/wp/v2/users"), insecure, auth)
    if status != 200 or not body:
        return []
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    slugs = [str(u.get("slug")) for u in data
             if isinstance(u, dict) and u.get("slug")]
    return sorted(set(slugs))


def check(base_url: str, *, html: str = "", insecure: bool = False, auth=None
          ) -> tuple[list[Finding], dict, list[str]]:
    """Run the WordPress checks. Returns (findings, info, errors).

    `html` is the already-fetched homepage body (for the meta-generator check);
    `info` carries {"version": ..., "users": [...]} for whatever was confirmed.
    """
    if not base_url:
        return [], {}, []
    base = base_url if base_url.endswith("/") else base_url + "/"
    findings: list[Finding] = []
    info: dict = {}
    errors: list[str] = []

    # -- version disclosure: readme.html --------------------------------------
    status, body = _fetch(urljoin(base, "readme.html"), insecure, auth)
    m = _README_VER.search(body) if status == 200 else None
    if m:
        version = m.group(1)
        info["version"] = version
        findings.append(Finding(
            title=f"WordPress version disclosed: {version} (readme.html)",
            severity=Severity.LOW, category="wordpress",
            description=("The default readme.html is publicly readable and names the exact "
                         f"WordPress core version ({version}) — enough to target "
                         "version-specific exploits."),
            recommendation=("Remove or deny access to readme.html, and keep WordPress core "
                            "updated; the disclosed version feeds the CVE lookup."),
            evidence=f"GET readme.html → Version {version}", confidence="firm"))

    # -- version disclosure: meta generator (body already fetched) ------------
    gm = _GENERATOR.search(html or "")
    if gm:
        version = gm.group(1)
        info.setdefault("version", version)
        findings.append(Finding(
            title=f"WordPress version disclosed: {version} (meta generator)",
            severity=Severity.LOW, category="wordpress",
            description=("Every page carries a <meta name=\"generator\"> tag naming the exact "
                         f"WordPress version ({version})."),
            recommendation=("Strip the generator meta tag (many security plugins do this) "
                            "and keep WordPress core updated."),
            evidence=f'<meta name="generator" content="WordPress {version}">',
            confidence="firm"))

    # -- author enumeration via the REST API ----------------------------------
    slugs = _rest_users(base, insecure, auth)
    if slugs:
        info["users"] = slugs[:50]
        findings.append(Finding(
            title=f"WordPress author enumeration via REST API ({len(slugs)} user(s))",
            severity=Severity.MEDIUM, category="wordpress",
            description=("/wp-json/wp/v2/users lists author usernames unauthenticated: "
                         + ", ".join(slugs[:15]) + (" …" if len(slugs) > 15 else "")
                         + ". Valid usernames halve the work of a password-guessing attack."),
            recommendation=("Restrict the users endpoint (a security plugin or a small "
                            "must-use plugin can require authentication for it), and enforce "
                            "strong passwords / 2FA on the exposed accounts."),
            evidence="GET /wp-json/wp/v2/users → " + ", ".join(slugs[:10]),
            confidence="firm"))

    # -- xmlrpc.php enabled ----------------------------------------------------
    status, body = _fetch(urljoin(base, "xmlrpc.php"), insecure, auth)
    if status == 200 and _XMLRPC_BANNER.search(body):
        info["xmlrpc"] = True
        findings.append(Finding(
            title="WordPress XML-RPC endpoint enabled (xmlrpc.php)",
            severity=Severity.MEDIUM, category="wordpress",
            description=("xmlrpc.php answers requests. It is a common amplifier for "
                         "credential brute-force (system.multicall batches hundreds of "
                         "password attempts per request) and pingback abuse."),
            recommendation=("Disable XML-RPC if nothing needs it (deny xmlrpc.php at the "
                            "web server or via a security plugin)."),
            evidence="GET xmlrpc.php → \"XML-RPC server accepts POST requests only.\"",
            confidence="firm"))

    # -- directory listing on uploads ------------------------------------------
    status, body = _fetch(urljoin(base, "wp-content/uploads/"), insecure, auth)
    if status == 200 and _DIR_LISTING.search(body):
        info["uploads_listing"] = True
        findings.append(Finding(
            title="WordPress directory listing enabled (/wp-content/uploads/)",
            severity=Severity.LOW, category="wordpress",
            description=("/wp-content/uploads/ returns an autoindex listing — every uploaded "
                         "file (including ones never linked) is enumerable."),
            recommendation=("Disable autoindex for the uploads tree (Options -Indexes on "
                            "Apache, autoindex off on nginx)."),
            evidence="GET /wp-content/uploads/ → \"Index of /wp-content/uploads\"",
            confidence="firm"))

    return findings, info, errors
