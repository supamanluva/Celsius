"""Content discovery — probe for exposed sensitive files and paths.

Safe-active: plain GETs of a curated, high-signal path list (no destructive
payloads, no fuzzing). Two guards keep false positives down on sites that return
200 for everything (SPA catch-alls / soft 404s):

  1. a baseline request to nonsense paths detects a catch-all, and
  2. each candidate carries a content signature; a 200 only counts when the body
     actually looks like the artefact (a `.git/config` must contain `[core]`,
     an `.env` must have `KEY=` lines, etc.).
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Pattern
from urllib.parse import urljoin

from ..models import Finding, Severity

USER_AGENT = "celsius/0.4 (+authorized security testing)"
TIMEOUT = 12
_READ = 4096  # bytes — enough to confirm a signature without pulling whole dumps

# (path, severity, signature, title). Signature is matched against the body to
# confirm the response is the real artefact and not an HTML error / SPA shell.
_CANDIDATES: list[tuple[str, Severity, Optional[Pattern], str]] = [
    (".git/config", Severity.HIGH, re.compile(r"\[core\]", re.I), "Exposed Git repository (.git/config)"),
    (".git/HEAD", Severity.HIGH, re.compile(r"(?m)^ref:\s"), "Exposed Git repository (.git/HEAD)"),
    (".env", Severity.HIGH, re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}="), "Exposed .env file (secrets/credentials)"),
    (".env.local", Severity.HIGH, re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}="), "Exposed .env.local file"),
    (".env.production", Severity.HIGH, re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}="), "Exposed .env.production file"),
    (".env.bak", Severity.HIGH, re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}="), "Exposed .env backup"),
    (".aws/credentials", Severity.HIGH, re.compile(r"aws_secret_access_key", re.I), "Exposed AWS credentials"),
    (".ssh/id_rsa", Severity.HIGH, re.compile(r"PRIVATE KEY-----"), "Exposed SSH private key"),
    (".svn/wc.db", Severity.MEDIUM, re.compile(r"SQLite format 3"), "Exposed Subversion working copy (.svn/wc.db)"),
    (".hg/requires", Severity.MEDIUM, re.compile(r"revlog|dotencode|store|fncache"), "Exposed Mercurial metadata (.hg)"),
    (".DS_Store", Severity.LOW, re.compile(r"Bud1", re.S), "Exposed .DS_Store (filename/directory leak)"),
    ("server-status", Severity.MEDIUM, re.compile(r"Apache Server Status", re.I), "Apache server-status exposed"),
    ("server-info", Severity.MEDIUM, re.compile(r"Apache Server Information", re.I), "Apache server-info exposed"),
    ("phpinfo.php", Severity.MEDIUM, re.compile(r"phpinfo\(\)|<title>PHP ", re.I), "phpinfo() exposed"),
    ("info.php", Severity.MEDIUM, re.compile(r"phpinfo\(\)|<title>PHP ", re.I), "phpinfo() exposed"),
    ("actuator", Severity.MEDIUM, re.compile(r'"_links"\s*:'), "Spring Boot Actuator index exposed"),
    ("actuator/env", Severity.HIGH, re.compile(r'"propertySources"|"systemProperties"'), "Spring Actuator /env exposed (config/secrets)"),
    ("actuator/health", Severity.LOW, re.compile(r'"status"\s*:'), "Spring Actuator /health exposed"),
    ("wp-config.php.bak", Severity.HIGH, re.compile(r"DB_PASSWORD|DB_NAME", re.I), "Exposed WordPress config backup"),
    (".npmrc", Severity.MEDIUM, re.compile(r"_authToken|//.+/:_", re.I), "Exposed .npmrc (registry token)"),
    (".vscode/sftp.json", Severity.HIGH, re.compile(r'"password"|"privateKeyPath"', re.I), "Exposed VS Code SFTP config (credentials)"),
    ("docker-compose.yml", Severity.LOW, re.compile(r"(?m)^services:|^version:\s*['\"]?\d"), "Exposed docker-compose.yml"),
    ("Dockerfile", Severity.LOW, re.compile(r"(?m)^FROM\s+\S"), "Exposed Dockerfile"),
    ("backup.sql", Severity.HIGH, re.compile(r"CREATE TABLE|INSERT INTO|DROP TABLE", re.I), "Exposed SQL database dump"),
    ("dump.sql", Severity.HIGH, re.compile(r"CREATE TABLE|INSERT INTO|DROP TABLE", re.I), "Exposed SQL database dump"),
    ("database.sql", Severity.HIGH, re.compile(r"CREATE TABLE|INSERT INTO|DROP TABLE", re.I), "Exposed SQL database dump"),
]


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


def _is_catchall(base: str, insecure: bool, auth) -> bool:
    """True if the server answers 200 to obviously non-existent paths."""
    for p in ("celsius-probe-nonexistent-aaaa", "zzzz-not-here-9182/index.html"):
        status, _ = _fetch(urljoin(base, p), insecure, auth)
        if status == 200:
            return True
    return False


def discover(
    base_url: str, *, insecure: bool = False, auth=None, max_workers: int = 8
) -> tuple[list[Finding], list[str], list[str]]:
    """Probe for exposed sensitive files. Returns (findings, paths, errors)."""
    if not base_url:
        return [], [], []
    base = base_url if base_url.endswith("/") else base_url + "/"
    catchall = _is_catchall(base, insecure, auth)

    def probe(cand):
        path, sev, sig, title = cand
        status, body = _fetch(urljoin(base, path), insecure, auth)
        if status != 200 or not body:
            return None
        # The signature is the real confirmation; on a catch-all server it's the
        # ONLY thing we trust. (All candidates carry one, so catch-all sites just
        # need the body to actually match.)
        if sig is None:
            if catchall:
                return None
        elif not sig.search(body):
            return None
        finding = Finding(
            title=title,
            severity=sev,
            category="exposure",
            description=f"{urljoin(base, path)} is publicly readable.",
            recommendation=(
                "Deny access to this path at the web server, or remove the file "
                "from the web root. If it leaked secrets, rotate them."
            ),
            evidence=re.sub(r"\s+", " ", body).strip()[:160],
        )
        return path, finding

    findings: list[Finding] = []
    paths: list[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for res in ex.map(probe, _CANDIDATES):
            if res is not None:
                path, finding = res
                paths.append(path)
                findings.append(finding)
    return findings, sorted(paths), []
