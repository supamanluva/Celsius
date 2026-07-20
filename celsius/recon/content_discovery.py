"""Content discovery — probe for exposed sensitive files and paths.

Safe-active: plain GETs of a curated, high-signal path list (no destructive
payloads, no fuzzing). Two guards keep false positives down on sites that return
200 for everything (SPA catch-alls / soft 404s):

  1. a baseline request to nonsense paths detects a catch-all, and
  2. each candidate carries a content signature; a 200 only counts when the body
     actually looks like the artefact (a `.git/config` must contain `[core]`,
     an `.env` must have `KEY=` lines, etc.).

`.git/config` gets a third guard on top: a matching config alone is weak proof
(decoys and partial blocks exist), so a confirmation step fetches `.git/HEAD`
and a ref (`.git/packed-refs` or the ref HEAD points at). Only when HEAD parses
AND a ref is fetchable is it reported HIGH as recoverable; otherwise it is a
MEDIUM metadata exposure with the caveat recorded.
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
# Every candidate carries one — on a catch-all server the signature is the ONLY
# thing trusted, so keep them tight (anchored where possible, specific enough
# that a generic login page or SPA shell cannot match).
#
# Binary artefacts: the body is decoded UTF-8 "replace", so the zip magic
# (PK\x03\x04) survives verbatim, but bytes >= 0x80 become U+FFFD — the gzip
# magic (\x1f\x8b) is therefore matched as \x1f followed by U+FFFD.
_ENV_SIG = re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}=")
_SQL_SIG = re.compile(r"CREATE TABLE|INSERT INTO|DROP TABLE", re.I)
_PHPINFO_SIG = re.compile(r"phpinfo\(\)|<title>PHP ", re.I)
_CRED_YAML_SIG = re.compile(r"(?im)^\s{0,4}(password|passwd|secret|api[_-]?key|access[_-]?key|token)\s*:")
_CANDIDATES: list[tuple[str, Severity, Optional[Pattern], str]] = [
    (".git/config", Severity.HIGH, re.compile(r"\[core\]", re.I), "Exposed Git repository (.git/config)"),
    (".git/HEAD", Severity.HIGH, re.compile(r"(?m)^ref:\s"), "Exposed Git repository (.git/HEAD)"),
    (".env", Severity.HIGH, _ENV_SIG, "Exposed .env file (secrets/credentials)"),
    (".env.local", Severity.HIGH, _ENV_SIG, "Exposed .env.local file"),
    (".env.production", Severity.HIGH, _ENV_SIG, "Exposed .env.production file"),
    (".env.development", Severity.HIGH, _ENV_SIG, "Exposed .env.development file"),
    (".env.bak", Severity.HIGH, _ENV_SIG, "Exposed .env backup"),
    (".env.old", Severity.HIGH, _ENV_SIG, "Exposed .env backup (.env.old)"),
    (".env.save", Severity.HIGH, _ENV_SIG, "Exposed .env backup (.env.save)"),
    (".env.backup", Severity.HIGH, _ENV_SIG, "Exposed .env backup (.env.backup)"),
    (".aws/credentials", Severity.HIGH, re.compile(r"aws_secret_access_key", re.I), "Exposed AWS credentials"),
    (".ssh/id_rsa", Severity.HIGH, re.compile(r"PRIVATE KEY-----"), "Exposed SSH private key"),
    (".htpasswd", Severity.HIGH, re.compile(r"(?m)^[\w.-]+:(\$apr1\$|\{SHA\}|\$2[aby]\$|\$argon2)"), "Exposed .htpasswd (password hashes)"),
    (".dockercfg", Severity.HIGH, re.compile(r'"auth"\s*:\s*"[A-Za-z0-9+/=]{8,}"'), "Exposed Docker registry credentials (.dockercfg)"),
    (".svn/wc.db", Severity.MEDIUM, re.compile(r"SQLite format 3"), "Exposed Subversion working copy (.svn/wc.db)"),
    (".svn/entries", Severity.MEDIUM, re.compile(r"<wc-entries|\A\d+\s*\n\s*dir\b"), "Exposed Subversion metadata (.svn/entries)"),
    (".hg/requires", Severity.MEDIUM, re.compile(r"revlog|dotencode|store|fncache"), "Exposed Mercurial metadata (.hg)"),
    (".hg/store/00manifest.i", Severity.MEDIUM, re.compile("\x00\x00\x00[\x00\x01]"), "Exposed Mercurial repository store (.hg)"),
    (".bzr/README", Severity.LOW, re.compile(r"Bazaar control directory", re.I), "Exposed Bazaar metadata (.bzr)"),
    (".DS_Store", Severity.LOW, re.compile(r"Bud1", re.S), "Exposed .DS_Store (filename/directory leak)"),
    ("server-status", Severity.MEDIUM, re.compile(r"Apache Server Status", re.I), "Apache server-status exposed"),
    ("server-info", Severity.MEDIUM, re.compile(r"Apache Server Information", re.I), "Apache server-info exposed"),
    ("nginx_status", Severity.MEDIUM, re.compile(r"Active connections:\s*\d+"), "nginx stub_status exposed (nginx_status)"),
    ("phpinfo.php", Severity.MEDIUM, _PHPINFO_SIG, "phpinfo() exposed"),
    ("info.php", Severity.MEDIUM, _PHPINFO_SIG, "phpinfo() exposed"),
    ("test.php", Severity.MEDIUM, _PHPINFO_SIG, "PHP test/info page exposed"),
    ("actuator", Severity.MEDIUM, re.compile(r'"_links"\s*:'), "Spring Boot Actuator index exposed"),
    ("actuator/env", Severity.HIGH, re.compile(r'"propertySources"|"systemProperties"'), "Spring Actuator /env exposed (config/secrets)"),
    ("actuator/health", Severity.LOW, re.compile(r'"status"\s*:'), "Spring Actuator /health exposed"),
    ("actuator/heapdump", Severity.HIGH, re.compile("JAVA PROFILE"), "Spring Actuator /heapdump exposed (JVM memory dump)"),
    ("metrics", Severity.MEDIUM, re.compile(r"(?m)^#\s*(HELP|TYPE)\s+[a-zA-Z_:]"), "Prometheus metrics endpoint exposed"),
    ("api/v1/namespaces", Severity.HIGH, re.compile(r'"kind"\s*:\s*"NamespaceList"'), "Kubernetes API exposed (namespaces listable)"),
    ("debug/vars", Severity.MEDIUM, re.compile(r'"memstats"\s*:|"cmdline"\s*:'), "Go expvar endpoint exposed (debug/vars)"),
    ("debug/pprof/", Severity.MEDIUM, re.compile(r"goroutine|/debug/pprof/", re.I), "Go pprof endpoint exposed (debug/pprof)"),
    ("elmah.axd", Severity.HIGH, re.compile(r"ELMAH|Error log for", re.I), "ELMAH error log exposed (elmah.axd)"),
    ("trace.axd", Severity.MEDIUM, re.compile(r"Application Trace|Trace Information|Request Details", re.I), "ASP.NET trace exposed (trace.axd)"),
    ("console/", Severity.HIGH, re.compile(r"Interactive Console|__debugger__", re.I), "Werkzeug debugger console exposed (RCE risk)"),
    ("_profiler/", Severity.MEDIUM, re.compile(r"/_profiler/|Symfony Profiler", re.I), "Symfony profiler exposed (_profiler)"),
    ("phpmyadmin/", Severity.MEDIUM, re.compile(r"phpMyAdmin", re.I), "phpMyAdmin exposed"),
    ("adminer.php", Severity.MEDIUM, re.compile(r"Adminer", re.I), "Adminer database manager exposed"),
    ("graphql", Severity.LOW, re.compile(r'"errors"\s*:\s*\[\s*\{|"__schema"'), "GraphQL endpoint exposed"),
    ("wp-config.php.bak", Severity.HIGH, re.compile(r"DB_PASSWORD|DB_NAME", re.I), "Exposed WordPress config backup"),
    ("config.php", Severity.HIGH, re.compile(r"<\?php"), "Exposed config.php (served as source)"),
    ("settings.py", Severity.HIGH, re.compile(r"(?m)^(SECRET_KEY|DATABASES|DEBUG|ALLOWED_HOSTS)\s*="), "Exposed settings.py (Django config/secrets)"),
    ("config.yml", Severity.MEDIUM, _CRED_YAML_SIG, "Exposed config.yml (may contain credentials)"),
    ("config.yaml", Severity.MEDIUM, _CRED_YAML_SIG, "Exposed config.yaml (may contain credentials)"),
    ("application.properties", Severity.MEDIUM, re.compile(r"(?im)^[\w.-]*(password|secret|token|api[_-]?key|datasource)[\w.-]*\s*="), "Exposed application.properties (may contain credentials)"),
    (".npmrc", Severity.MEDIUM, re.compile(r"_authToken|//.+/:_", re.I), "Exposed .npmrc (registry token)"),
    (".vscode/sftp.json", Severity.HIGH, re.compile(r'"(password|privateKeyPath)"\s*:', re.I), "Exposed VS Code SFTP config (credentials)"),
    (".gitlab-ci.yml", Severity.LOW, re.compile(r"(?m)^\s*(stages:|before_script:|after_script:)"), "Exposed .gitlab-ci.yml (CI pipeline config)"),
    ("Jenkinsfile", Severity.LOW, re.compile(r"pipeline\s*\{|node\s*\{|stage\s*\("), "Exposed Jenkinsfile (CI pipeline config)"),
    ("docker-compose.yml", Severity.LOW, re.compile(r"(?m)^services:|^version:\s*['\"]?\d"), "Exposed docker-compose.yml"),
    ("Dockerfile", Severity.LOW, re.compile(r"(?m)^FROM\s+\S"), "Exposed Dockerfile"),
    ("backup.sql", Severity.HIGH, _SQL_SIG, "Exposed SQL database dump"),
    ("dump.sql", Severity.HIGH, _SQL_SIG, "Exposed SQL database dump"),
    ("database.sql", Severity.HIGH, _SQL_SIG, "Exposed SQL database dump"),
    ("db.sql", Severity.HIGH, _SQL_SIG, "Exposed SQL database dump (db.sql)"),
    ("backup.zip", Severity.HIGH, re.compile("PK\x03\x04"), "Exposed backup archive (backup.zip)"),
    ("site.tar.gz", Severity.HIGH, re.compile("\x1f\ufffd"), "Exposed backup archive (site.tar.gz)"),
    (".well-known/security.txt", Severity.LOW, re.compile(r"(?im)^contact:\s*\S"), "security.txt published (.well-known/security.txt)"),
    (".well-known/change-password", Severity.LOW, re.compile(r'(?is)(current|old|new)[-_ ]password|type="password".{0,500}type="password"'), "Change-password endpoint exposed (.well-known/change-password)"),
    (".well-known/openid-configuration", Severity.LOW, re.compile(r'"issuer"\s*:\s*"https?://'), "OpenID Connect configuration exposed"),
    ("config.json", Severity.MEDIUM, re.compile(r'"(api[_-]?key|secret|password|token|database)"\s*:', re.I), "Exposed config.json (may contain credentials)"),
    (".htaccess", Severity.MEDIUM, re.compile(r"(?im)^(RewriteEngine|Require\s|Order\s|Deny\s|Allow\s|AuthType|Options\s|DirectoryIndex)"), "Exposed .htaccess (server config)"),
]

# A git HEAD is either a symbolic ref ("ref: refs/heads/main") or a detached
# 40-hex commit id; both are single-line bodies.
_GIT_HEAD_RE = re.compile(r"^ref:\s*(refs/\S+)$|^[0-9a-f]{40}$", re.I)
_GIT_SHA_RE = re.compile(r"\b[0-9a-f]{40}\b", re.I)
_GIT_PACKED_REFS_RE = re.compile(r"(?m)^[0-9a-f]{40}\s+refs/", re.I)


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


def _git_certainty(base: str, insecure: bool, auth) -> tuple[Severity, str, str]:
    """Two-stage confirmation for an exposed `.git/config`.

    A matching config alone is weak proof (decoy configs and partial directory
    blocks both happen), so fetch `.git/HEAD` plus a ref before claiming the
    repository is recoverable. Returns (severity, title, explanation): HIGH
    only when HEAD parses as a real git HEAD AND at least one ref is fetchable
    (the ref HEAD points at, or `.git/packed-refs`); MEDIUM otherwise, with the
    reason recovery could not be confirmed.
    """
    status, body = _fetch(urljoin(base, ".git/HEAD"), insecure, auth)
    m = _GIT_HEAD_RE.match(body.strip()) if status == 200 else None
    if not m:
        return (Severity.MEDIUM, "Exposed Git metadata (.git/config)",
                ".git/HEAD is missing or does not parse as a git HEAD, so full "
                "repository recovery was not confirmed.")
    ref = m.group(1)
    if ref:
        status, body = _fetch(urljoin(base, ref), insecure, auth)
        if status == 200 and _GIT_SHA_RE.search(body):
            return (Severity.HIGH, "Exposed Git repository (recoverable)",
                    f"Confirmed: .git/HEAD points at {ref} and that ref is "
                    "fetchable; the repository can likely be reconstructed "
                    "(e.g. with git-dumper).")
    status, body = _fetch(urljoin(base, ".git/packed-refs"), insecure, auth)
    if status == 200 and _GIT_PACKED_REFS_RE.search(body):
        return (Severity.HIGH, "Exposed Git repository (recoverable)",
                "Confirmed: .git/HEAD parses and .git/packed-refs exposes refs; "
                "the repository can likely be reconstructed (e.g. with git-dumper).")
    return (Severity.MEDIUM, "Exposed Git metadata (.git/config)",
            ".git/HEAD parses but no refs could be fetched (neither the ref it "
            "points at nor .git/packed-refs), so full repository recovery was "
            "not confirmed.")


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
        desc = f"{urljoin(base, path)} is publicly readable."
        if path == ".git/config":
            # Upgrade/downgrade by certainty: HIGH only if HEAD + refs confirm
            # the repo is actually recoverable, else MEDIUM metadata exposure.
            sev, title, note = _git_certainty(base, insecure, auth)
            desc += " " + note
        finding = Finding(
            title=title,
            severity=sev,
            category="exposure",
            description=desc,
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
