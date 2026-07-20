"""Curated default-credential checks (opt-in, safe-active).

The single most common way an exposed appliance / admin panel is taken over is a
documented vendor default login (admin/admin on routers & cameras, tomcat/tomcat
on the Tomcat Manager, root/calvin on Dell iDRAC, anonymous FTP, …). This module
tries ONLY documented defaults, capped and lockout-aware:

  * curated lists, never a generic wordlist spray;
  * product-specific creds chosen from the auth realm / fingerprint when known;
  * at most a handful of attempts per endpoint, and we STOP on the first success;
  * we only attempt where authentication is actually required (an unauth request
    was challenged), so a 200-with-creds genuinely means the creds worked.

Authentication attempts are intrusive — this runs only when the operator opts in
(`default_creds`). Stdlib-only (urllib / ftplib / base64).
"""

from __future__ import annotations

import base64
import ftplib
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

TIMEOUT = 6.0
MAX_ATTEMPTS = 6           # per endpoint — small; Basic auth is stateless, but cap anyway
_UA = "celsius-defaultcreds"


@dataclass
class CredResult:
    target: str            # the URL / host:port tested
    success: bool          # True = a default credential WORKED
    severity: str          # "CRITICAL" | "HIGH"
    title: str
    detail: str
    evidence: str = ""


# Documented universal HTTP Basic-auth defaults (routers, cameras, printers, BMCs).
_BASIC_UNIVERSAL = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("admin", "1234"), ("root", "root"),
]

# Product-specific defaults, matched on the auth realm or a fingerprint hint.
# Keep tiny — the documented vendor default only.
_PRODUCT_CREDS = {
    "tomcat":  [("tomcat", "tomcat"), ("admin", "admin"), ("tomcat", "s3cret"), ("role1", "role1")],
    "idrac":   [("root", "calvin")],
    "dell":    [("root", "calvin")],
    "jenkins": [("admin", "admin")],
    "grafana": [("admin", "admin")],
    "gitlab":  [("root", "5iveL!fe")],
    "zabbix":  [("Admin", "zabbix")],
    "axis":    [("root", "pass")],            # Axis IP cameras
    "hikvision": [("admin", "12345")],
}


def _ctx(insecure: bool) -> Optional[ssl.SSLContext]:
    if insecure:
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        return c
    return None


def basic_realm(url: str, *, insecure: bool = False) -> Optional[str]:
    """If `url` answers an unauthenticated request with an HTTP Basic challenge,
    return its realm (or '' when none). Returns None when it is NOT Basic-protected
    — so we never fire credential attempts at an open endpoint."""
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx(insecure))
        return None                                   # 200 without creds — not protected
    except urllib.error.HTTPError as e:
        if e.code != 401:
            return None
        chal = e.headers.get("WWW-Authenticate", "") or ""
        if "basic" not in chal.lower():
            return None                               # Digest/NTLM/Bearer — out of scope here
        m = re.search(r'realm="?([^",]+)', chal, re.I)
        return (m.group(1) if m else "").strip()
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _basic_status(url: str, user: str, pw: str, *, insecure: bool) -> Optional[int]:
    tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
    req = urllib.request.Request(url, headers={"User-Agent": _UA,
                                               "Authorization": f"Basic {tok}"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx(insecure)) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _creds_for(realm: str, hints: str) -> list[tuple[str, str]]:
    """Product creds (by realm/fingerprint hint) first, then universal — deduped."""
    blob = f"{realm} {hints}".lower()
    creds: list[tuple[str, str]] = []
    for key, pairs in _PRODUCT_CREDS.items():
        if key in blob:
            creds.extend(pairs)
    for pair in _BASIC_UNIVERSAL:
        if pair not in creds:
            creds.append(pair)
    return creds[:MAX_ATTEMPTS]


def check_http_basic(url: str, *, insecure: bool = False, hints: str = "") -> Optional[CredResult]:
    """Try curated default creds against an HTTP-Basic-protected URL. Stops on the
    first credential that yields 200. Returns None if the URL isn't Basic-protected."""
    realm = basic_realm(url, insecure=insecure)
    if realm is None:
        return None
    for user, pw in _creds_for(realm, hints):
        if _basic_status(url, user, pw, insecure=insecure) == 200:
            shown = pw if pw else "<blank>"
            return CredResult(
                url, True, "CRITICAL",
                "Default credentials accepted (HTTP Basic auth)",
                f"The protected endpoint accepted the well-known default login "
                f"'{user}:{shown}'"
                + (f" (realm: {realm})" if realm else "")
                + ". Anyone can log in with publicly documented credentials — change "
                "them immediately and restrict the interface to trusted networks.",
                f"{user}:{shown} -> HTTP 200")
    return None


def check_ftp_anonymous(host: str, port: int = 21) -> Optional[CredResult]:
    """Anonymous FTP login."""
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=TIMEOUT)
        ftp.login()                      # defaults to anonymous / anonymous
    except ftplib.all_errors:            # already includes OSError / EOFError
        return None
    finally:
        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass
    return CredResult(
        f"{host}:{port}", True, "HIGH",
        "Anonymous FTP login allowed",
        "The FTP server accepted an anonymous login — files served over FTP are "
        "readable (and possibly writable) without credentials. Disable anonymous "
        "access or restrict the service to trusted networks.",
        "anonymous login -> 230")
