"""Subdomain enumeration.

Passive: query several Certificate Transparency / passive-DNS sources (crt.sh,
certspotter, hackertarget, rapiddns, AlienVault OTX) and merge them — no contact
with the target. Each is keyless. Using more than one source means a transient
crt.sh outage (its 502s/timeouts are common) no longer yields an empty result,
and passive-DNS sources catch names that never got their own CT cert. Results are
cached briefly, and a total live failure falls back to the last cached set.

Optional safe-active: resolve a small built-in wordlist against the apex domain
(only DNS lookups, still non-intrusive).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

USER_AGENT = "celsius/0.4 (+authorized security testing)"
TIMEOUT = 20
_CACHE_DIR = Path(os.path.expanduser("~/.cache/celsius/subdomains"))
_CACHE_TTL = 6 * 3600  # treat a cached set younger than this as fresh

# small high-signal wordlist for optional resolution — corporate/infra names
COMMON = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp",
    "secure", "vpn", "api", "dev", "staging", "test", "portal", "admin", "m",
    "shop", "ftp", "cpanel", "webdisk", "autodiscover", "app", "git", "gitlab",
    "jenkins", "jira", "confluence", "demo", "beta", "cdn", "static", "assets",
    "dashboard", "internal", "intranet", "vpn2", "owa", "exchange", "db", "sql",
]

# self-hosted app subdomains — this tool's audience names hosts after the app
# (e.g. request.<domain> = Overseerr). These often sit under a wildcard cert, so
# they carry no per-host CT entry and are invisible to crt.sh — DNS brute-force is
# the way to catch them.
SELF_HOSTED = [
    "request", "requests", "overseerr", "jellyseerr", "ombi",
    "plex", "jellyfin", "emby", "media", "tv", "movies",
    "radarr", "sonarr", "lidarr", "readarr", "prowlarr", "bazarr", "tautulli",
    "qbittorrent", "qbit", "deluge", "transmission", "sabnzbd", "nzbget", "jdownloader",
    "vikunja", "tasks", "todo", "kanban", "planka",
    "readeck", "wallabag", "linkding", "bookmarks", "hoarder", "freshrss", "miniflux", "rss",
    "obsidian", "notes", "memos", "trilium", "outline", "bookstack", "wiki",
    "nextcloud", "cloud", "files", "drop", "drive", "seafile", "syncthing", "filebrowser",
    "immich", "photos", "photoprism",
    "navidrome", "music", "audiobookshelf", "audiobooks", "podcast", "podcasts",
    "calibre", "books", "kavita", "komga",
    "grafana", "prometheus", "uptime", "status", "metrics",
    "vaultwarden", "vault", "bitwarden", "passwords",
    "home", "homeassistant", "hass", "ha", "nodered",
    "gitea", "forgejo", "code",
    "paperless", "docs",
    "pihole", "adguard", "traefik", "npm", "proxy",
    "auth", "sso", "authelia", "authentik", "keycloak",
    "homer", "heimdall", "dashy",
]

# Default brute-force set: corporate + self-hosted, deduped.
DEFAULT_WORDLIST = sorted(set(COMMON) | set(SELF_HOSTED))


def apex_domain(host: str) -> str:
    """Best-effort registrable domain (last two labels). Imperfect for ccTLDs."""
    labels = host.strip(".").split(".")
    if len(labels) <= 2:
        return host
    return ".".join(labels[-2:])


# ---- fetch helpers ------------------------------------------------------------

def _fetch(url: str, *, retries: int = 1) -> tuple[str | None, str]:
    """GET text with a short retry/backoff. Returns (body or None, last_error)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_err = ""
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace"), ""
        except (urllib.error.URLError, OSError) as e:
            last_err = str(e)
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    return None, last_err


def _keep(name: str, domain: str) -> str | None:
    name = name.strip().lower().lstrip("*.")
    if name.endswith(domain) and name != domain and "@" not in name:
        return name
    return None


# ---- passive sources (each returns (subdomains, errors)) ----------------------

def from_crtsh(domain: str, *, retries: int = 2) -> tuple[set[str], list[str]]:
    """crt.sh CT-log lookup. Frequently 502s under load, so retry briefly."""
    url = f"https://crt.sh/?q={urllib.parse.quote('%.' + domain)}&output=json"
    body, err = _fetch(url, retries=retries)
    if body is None:
        return set(), [f"crt.sh lookup failed after retries: {err}"]
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return set(), ["crt.sh returned non-JSON (likely an error page)"]
    subs = {k for entry in data for line in str(entry.get("name_value", "")).splitlines()
            if (k := _keep(line, domain))}
    return subs, []


def from_certspotter(domain: str) -> tuple[set[str], list[str]]:
    """certspotter issuances API (free tier, no key needed for light use)."""
    url = ("https://api.certspotter.com/v1/issuances?"
           + urllib.parse.urlencode({"domain": domain, "include_subdomains": "true",
                                     "expand": "dns_names"}))
    body, err = _fetch(url)
    if body is None:
        return set(), [f"certspotter lookup failed: {err}"]
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return set(), []  # rate-limited / error object — not fatal
    if not isinstance(data, list):
        return set(), []
    subs = {k for entry in data for name in (entry.get("dns_names") or [])
            if (k := _keep(name, domain))}
    return subs, []


def from_hackertarget(domain: str) -> tuple[set[str], list[str]]:
    """hackertarget hostsearch (CSV text; free tier is rate-limited)."""
    url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
    body, err = _fetch(url)
    if body is None:
        return set(), [f"hackertarget lookup failed: {err}"]
    low = body.lower()
    if "api count exceeded" in low or "error" in low and "," not in body:
        return set(), []  # rate-limited — not fatal
    subs = {k for line in body.splitlines() if (k := _keep(line.split(",")[0], domain))}
    return subs, []


def from_rapiddns(domain: str) -> tuple[set[str], list[str]]:
    """rapiddns.io passive subdomain database (HTML table; no key needed)."""
    url = f"https://rapiddns.io/subdomain/{urllib.parse.quote(domain)}?full=1"
    body, err = _fetch(url)
    if body is None:
        return set(), [f"rapiddns lookup failed: {err}"]
    subs = {k for m in re.findall(r'[A-Za-z0-9_.\-]+\.' + re.escape(domain), body)
            if (k := _keep(m, domain))}
    return subs, []


def from_otx(domain: str) -> tuple[set[str], list[str]]:
    """AlienVault OTX passive DNS (JSON; no key needed)."""
    url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
           f"{urllib.parse.quote(domain)}/passive_dns")
    body, err = _fetch(url)
    if body is None:
        return set(), [f"otx lookup failed: {err}"]
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return set(), []
    subs = {k for rec in (data.get("passive_dns") or [])
            if (k := _keep(rec.get("hostname", ""), domain))}
    return subs, []


_SOURCES = (from_crtsh, from_certspotter, from_hackertarget, from_rapiddns, from_otx)


# ---- cache --------------------------------------------------------------------

def _cache_file(domain: str) -> Path:
    return _CACHE_DIR / (hashlib.sha256(domain.encode()).hexdigest() + ".json")


def _cache_read(domain: str, *, max_age: float | None) -> set[str] | None:
    f = _cache_file(domain)
    try:
        if not f.exists():
            return None
        if max_age is not None and (time.time() - f.stat().st_mtime) > max_age:
            return None
        return set(json.loads(f.read_text()))
    except (OSError, json.JSONDecodeError):
        return None


def _cache_write(domain: str, subs: set[str]) -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_file(domain).write_text(json.dumps(sorted(subs)))
    except OSError:
        pass


# ---- safe-active wordlist -----------------------------------------------------

# Labels that should never exist — if they resolve, the zone has a wildcard
# (*.domain) and brute-force can't tell a real host from the catch-all.
_WILDCARD_PROBES = ("zz-no-such-host-9x7q", "definitely-not-real-4k2p3", "wildcard-probe-8h3v")


def detect_wildcard(domain: str) -> set[str]:
    """Resolve a few random non-existent labels. Any IPs returned are a wildcard
    catch-all — a non-empty result means brute-force results are unreliable."""
    ips: set[str] = set()
    for label in _WILDCARD_PROBES:
        try:
            ips.add(socket.gethostbyname(f"{label}.{domain}"))
        except (socket.gaierror, OSError):
            pass
    return ips


def resolve_wordlist(domain: str, words=DEFAULT_WORDLIST) -> set[str]:
    """Safe-active: which <word>.<domain> resolve. DNS only."""
    found: set[str] = set()

    def check(w):
        host = f"{w}.{domain}"
        try:
            socket.gethostbyname(host)
            return host
        except (socket.gaierror, OSError):
            return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        for r in ex.map(check, words):
            if r:
                found.add(r)
    return found


# ---- public API ---------------------------------------------------------------

def enumerate_subdomains(host: str, *, bruteforce: bool = False) -> tuple[list[str], list[str]]:
    """Returns (sorted_subdomains, errors).

    Queries several passive sources in parallel and merges them; a fresh cache
    hit short-circuits the network entirely, and if every live source fails we
    fall back to the last cached set so a crt.sh outage doesn't blank the result.
    """
    domain = apex_domain(host)
    errors: list[str] = []

    fresh = _cache_read(domain, max_age=_CACHE_TTL)
    if fresh is not None:
        subs = set(fresh)
    else:
        subs = set()
        with ThreadPoolExecutor(max_workers=len(_SOURCES)) as ex:
            for found, errs in ex.map(lambda fn: fn(domain), _SOURCES):
                subs |= found
                errors.extend(errs)
        if subs:
            _cache_write(domain, subs)
        else:
            stale = _cache_read(domain, max_age=None)
            if stale:
                subs = set(stale)
                errors.append("all live CT sources failed — used subdomains cached from an earlier scan")

    if bruteforce:
        wildcard = detect_wildcard(domain)
        if wildcard:
            errors.append(
                f"wildcard DNS detected (*.{domain} → {', '.join(sorted(wildcard))}) — "
                "brute-force skipped (it would match every name); CT / passive-DNS "
                "results are still reliable")
        else:
            subs |= resolve_wordlist(domain)
    return sorted(subs), errors
