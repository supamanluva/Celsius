"""Subdomain enumeration.

Passive: query crt.sh Certificate Transparency logs (no auth, no contact with the
target). Optional safe-active: resolve a small built-in wordlist against the apex
domain (only DNS lookups, still non-intrusive).
"""

from __future__ import annotations

import json
import socket
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

USER_AGENT = "celsius/0.4 (+authorized security testing)"
TIMEOUT = 20

# small high-signal wordlist for optional resolution
COMMON = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp",
    "secure", "vpn", "api", "dev", "staging", "test", "portal", "admin", "m",
    "shop", "ftp", "cpanel", "webdisk", "autodiscover", "app", "git", "gitlab",
    "jenkins", "jira", "confluence", "demo", "beta", "cdn", "static", "assets",
    "dashboard", "internal", "intranet", "vpn2", "owa", "exchange", "db", "sql",
]


def apex_domain(host: str) -> str:
    """Best-effort registrable domain (last two labels). Imperfect for ccTLDs."""
    labels = host.strip(".").split(".")
    if len(labels) <= 2:
        return host
    return ".".join(labels[-2:])


def from_crtsh(domain: str, *, retries: int = 2) -> tuple[set[str], list[str]]:
    """Passive CT-log lookup. Returns (subdomains, errors).

    crt.sh frequently returns transient 502s under load, so we retry briefly.
    """
    url = f"https://crt.sh/?q={urllib.parse.quote('%.' + domain)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    data = None
    last_err = ""
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            break
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
            last_err = str(e)
            if attempt < retries:
                time.sleep(2.0 * (attempt + 1))
    if data is None:
        return set(), [f"crt.sh lookup failed after retries: {last_err}"]

    subs: set[str] = set()
    for entry in data:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain) and name != domain and "@" not in name:
                subs.add(name)
    return subs, []


def resolve_wordlist(domain: str, words=COMMON) -> set[str]:
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


def enumerate_subdomains(host: str, *, bruteforce: bool = False) -> tuple[list[str], list[str]]:
    """Returns (sorted_subdomains, errors)."""
    domain = apex_domain(host)
    subs, errors = from_crtsh(domain)
    if bruteforce:
        subs |= resolve_wordlist(domain)
    return sorted(subs), errors
