"""Probe well-known self-hosted app version endpoints.

Many self-hosted apps expose their EXACT version on an unauthenticated status/health
endpoint — Overseerr `/api/v1/status`, Gitea `/api/v1/version`, Nextcloud
`/status.php`, Grafana `/api/health`, … These are readable even behind a CDN that
strips the `Server` header, so they recover a version (-> CVE matching) the normal
header/fingerprint path can't see. The disclosure is itself worth flagging.

Pure stdlib (urllib + json + re).
"""

from __future__ import annotations

import concurrent.futures
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

USER_AGENT = "celsius-scanner/1.1 (+https://github.com/supamanluva/celsius)"

# (app, path, json_field [dotted] | None, regex | None) — first match wins per path.
PROBES = [
    ("Overseerr/Jellyseerr", "/api/v1/status", "version", None),
    ("Gitea/Forgejo", "/api/v1/version", "version", None),
    ("Grafana", "/api/health", "version", None),
    ("Jellyfin/Emby", "/System/Info/Public", "Version", None),
    ("Nextcloud", "/status.php", "versionstring", None),
    ("Prometheus", "/api/v1/status/buildinfo", "data.version", None),
    ("Portainer", "/api/system/version", "ServerVersion", None),
    ("Home Assistant", "/api/config", "version", None),
    ("Uptime Kuma", "/api/entry-page", "version", None),
    ("Immich", "/api/server-info/version", None,
     r'"major":\s*(\d+).*?"minor":\s*(\d+).*?"patch":\s*(\d+)'),
    ("Plex", "/identity", None, r'\bversion="([^"]+)"'),
    # Vaultwarden's /api/version body is ONLY the version (e.g. "1.30.1") — anchor to
    # the whole body so a generic 200 from another app can't false-positive.
    ("Vaultwarden", "/api/version", None, r'^\s*"?([0-9]+\.[0-9]+\.[0-9]+)"?\s*$'),
]

_VER = re.compile(r"\d+\.\d+")


def _dig(field: str, data) -> Optional[object]:
    for part in field.split("."):
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data


def extract_version(body: str, field: Optional[str], regex: Optional[str]) -> Optional[str]:
    """Pull a version string out of a response body via a JSON field or a regex."""
    if field:
        try:
            v = _dig(field, json.loads(body))
        except (json.JSONDecodeError, ValueError):
            v = None
        if v is not None and _VER.search(str(v)):
            return str(v).strip()[:40]
    if regex:
        m = re.search(regex, body, re.S)
        if m:
            v = ".".join(g for g in m.groups() if g) if m.groups() else m.group(0)
            if _VER.search(v):
                return v.strip()[:40]
    return None


def _fetch(url: str, *, insecure: bool, auth, timeout: int = 8) -> tuple[Optional[int], str]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json, text/xml, */*"}
    if auth is not None and getattr(auth, "headers", None):
        headers.update(auth.headers)
    ctx = ssl._create_unverified_context() if insecure else None
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError:
        return None, ""
    except (urllib.error.URLError, OSError, ValueError):
        return None, ""


def probe(base_url: str, *, insecure: bool = False, auth=None) -> list[dict]:
    """GET each known app version endpoint on base_url (concurrently); return
    [{app, version, path}] for those that disclose a version. The base is normalised
    to its origin (scheme://host) so a redirected /login path doesn't break the paths."""
    u = urllib.parse.urlsplit(base_url or "")
    base = f"{u.scheme}://{u.netloc}" if u.scheme and u.netloc else (base_url or "").rstrip("/")
    if not base:
        return []

    def one(pr):
        app, path, field, regex = pr
        status, body = _fetch(base + path, insecure=insecure, auth=auth)
        if status != 200 or not body:
            return None
        ver = extract_version(body, field, regex)
        return {"app": app, "version": ver, "path": path} if ver else None

    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        for r in ex.map(one, PROBES):
            if r:
                out.append(r)
    return out
