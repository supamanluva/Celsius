"""Origin-exposure / CDN-bypass discovery.

When a target is fronted by a CDN (Cloudflare etc.) the origin server is hidden —
you see the CDN edge, not the real host/version. But subdomains and mail hosts are
frequently left *un-proxied*: they resolve straight to the origin IP. Resolve the
known hostnames and flag any that point at a non-CDN public address — those are
candidate origins you can scan directly (and, defensively, a leak to firewall
behind the CDN's published ranges).

Pure stdlib: IP classification via `ipaddress`, resolution via the DoH helper.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from . import dns as dns_mod

# Published CDN/proxy IPv4 ranges (stable) — to tell a CDN edge IP from a subdomain
# pointing straight at the (un-proxied) origin. Cloudflare is by far the common one.
_CDN_RANGES = {
    "Cloudflare": [
        # IPv4 (https://www.cloudflare.com/ips-v4)
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        # IPv6 (https://www.cloudflare.com/ips-v6) — without these, CF IPv6 edges
        # (e.g. 2a06:98c1::) look like a non-CDN origin and false-positive.
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    ],
    "Fastly": ["151.101.0.0/16", "199.232.0.0/16", "2a04:4e40::/32", "2a04:4e42::/32"],
}
_NETS = {name: [ipaddress.ip_network(c) for c in cidrs]
         for name, cidrs in _CDN_RANGES.items()}


def cdn_for_ip(ip: str) -> Optional[str]:
    """Name of the CDN owning `ip`, or None if it isn't in a known CDN range."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, nets in _NETS.items():
        if any(addr in n for n in nets):
            return name
    return None


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# Tailscale's address space (CGNAT IPv4 + ULA IPv6) — leaked if seen in PUBLIC DNS.
_TAILSCALE = [ipaddress.ip_network("100.64.0.0/10"),
              ipaddress.ip_network("fd7a:115c:a1e0::/48")]


def internal_kind(ip: str) -> Optional[str]:
    """Classify an internal/VPN address that should never appear in PUBLIC DNS:
    'Tailscale', 'private' (RFC1918/ULA), 'loopback', or 'link-local'. None if a
    normal public address."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if any(a in n for n in _TAILSCALE):
        return "Tailscale"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link-local"
    if a.is_private:            # RFC1918 / fc00::/7 ULA (Tailscale matched above)
        return "private"
    return None


def _classify_internal(host: str) -> Optional[dict]:
    a = dns_mod._query(host, "A") + dns_mod._query(host, "AAAA")
    cname = dns_mod._query(host, "CNAME")
    kinds = {k for k in (internal_kind(ip) for ip in a) if k}
    ts_net = [c.rstrip(".") for c in cname if ".ts.net" in c.lower()]
    if not kinds and not ts_net:
        return None
    kind = "Tailscale" if ("Tailscale" in kinds or ts_net) else sorted(kinds)[0]
    return {"host": host, "kind": kind, "ips": a, "ts_net": ts_net}


def find_internal_leaks(hosts, *, max_hosts: int = 150) -> list[dict]:
    """Hosts whose PUBLIC DNS exposes an internal/VPN address (RFC1918, Tailscale
    CGNAT) or a *.ts.net CNAME — an infrastructure leak. [{host, kind, ips, ts_net}].
    Only what's in public DNS is seen, so tailnet-only names never appear."""
    uniq, seen = [], set()
    for h in hosts:
        h = (h or "").strip().lower().rstrip(".").lstrip("*.")
        if h and h not in seen:
            seen.add(h)
            uniq.append(h)
    uniq = uniq[:max_hosts]
    if not uniq:
        return []
    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for r in ex.map(_classify_internal, uniq):
            if r:
                out.append(r)
    out.sort(key=lambda r: r["host"])
    return out


def mx_hosts(dns_records: dict) -> list[str]:
    """Hostnames from MX records ('10 mail.example.com.' -> 'mail.example.com')."""
    out = []
    for raw in (dns_records or {}).get("MX", []) or []:
        parts = str(raw).split()
        if parts:
            out.append(parts[-1].rstrip("."))
    return out


def resolve(host: str) -> list[str]:
    """A/AAAA addresses for `host` via DoH."""
    return dns_mod._query(host, "A") + dns_mod._query(host, "AAAA")


def _classify(host: str) -> Optional[dict]:
    ips = resolve(host)
    if not ips:
        return None
    origin_ips = [ip for ip in ips if _is_public(ip) and not cdn_for_ip(ip)]
    if not origin_ips:
        return None
    cdn_ips = {ip: cdn_for_ip(ip) for ip in ips if cdn_for_ip(ip)}
    return {"host": host, "ips": ips, "origin_ips": origin_ips, "cdn_ips": cdn_ips}


def find_exposed_origins(hosts, *, max_hosts: int = 150) -> list[dict]:
    """Resolve each host (concurrently) and return those pointing at a non-CDN public
    IP — candidate origins behind the CDN. [{host, ips, origin_ips, cdn_ips}]."""
    uniq, seen = [], set()
    for h in hosts:
        h = (h or "").strip().lower().rstrip(".").lstrip("*.")
        if h and h not in seen:
            seen.add(h)
            uniq.append(h)
    uniq = uniq[:max_hosts]
    if not uniq:
        return []
    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for r in ex.map(_classify, uniq):
            if r:
                out.append(r)
    out.sort(key=lambda r: r["host"])
    return out


# ---- origin hunt: pivots + Shodan lookup + Host-header verification -----------

def pivot_queries(domain: str, *, favicon_hash: Optional[int] = None,
                  sans: Optional[list] = None) -> list[dict]:
    """Ready-to-run Shodan/Censys searches that find an IP serving the same
    cert/favicon directly — i.e. the origin behind the CDN. Returns
    [{engine, label, query, url}]."""
    out: list[dict] = []

    def shodan(q: str, label: str) -> None:
        out.append({"engine": "Shodan", "label": label, "query": q,
                    "url": "https://www.shodan.io/search?query=" + urllib.parse.quote(q)})

    def censys(q: str, label: str) -> None:
        out.append({"engine": "Censys", "label": label, "query": q,
                    "url": "https://search.censys.io/search?resource=hosts&q=" + urllib.parse.quote(q)})

    if favicon_hash is not None:
        shodan(f"http.favicon.hash:{favicon_hash}", "same favicon")
    shodan(f'ssl.cert.subject.CN:"{domain}"', "cert subject CN")
    shodan(f'ssl:"{domain}"', "cert mentions domain")
    censys(f"services.tls.certificates.leaf_data.subject.common_name: {domain}", "cert subject CN")
    names = [s for s in (sans or []) if s and "*" not in s][:1]
    if names:
        censys(f"services.tls.certificates.leaf_data.names: {names[0]}", "cert SAN")
    return out


def shodan_search(query: str, api_key: str, *, limit: int = 25) -> tuple[list[str], Optional[str]]:
    """Run a Shodan host search; return (candidate_ips, error). Needs a paid-tier
    key for filters — degrade gracefully on any error."""
    if not api_key:
        return [], "no SHODAN_API_KEY"
    url = ("https://api.shodan.io/shodan/host/search?key=" + urllib.parse.quote(api_key)
           + "&query=" + urllib.parse.quote(query))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": dns_mod.USER_AGENT})
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return [], f"Shodan HTTP {e.code} ({'search needs a paid plan' if e.code == 403 else 'error'})"
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        return [], f"Shodan request failed: {e}"
    ips: list[str] = []
    for m in data.get("matches", []) or []:
        ip = m.get("ip_str")
        if ip and ip not in ips:
            ips.append(ip)
        if len(ips) >= limit:
            break
    return ips, None


def censys_search(query: str, pat: str, org_id: str, *,
                  limit: int = 25) -> tuple[list[str], Optional[str]]:
    """Run a Censys Platform v3 host search; return (candidate_ips, error). Needs a
    Personal Access Token + organization ID — the FREE tier can only search via the
    web UI (the pivot link), not the API (403)."""
    if not (pat and org_id):
        return [], "no CENSYS_PAT/CENSYS_ORG_ID"
    url = "https://api.platform.censys.io/v3/global/search/query"
    body = json.dumps({"query": query, "page_size": 50}).encode()
    try:
        req = urllib.request.Request(url, data=body, method="POST", headers={
            "User-Agent": dns_mod.USER_AGENT, "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {pat}", "X-Organization-ID": org_id})
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.loads(e.read().decode()).get("detail", "")
        except Exception:
            pass
        return [], f"Censys HTTP {e.code}{(': ' + detail) if detail else ''}"
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        return [], f"Censys request failed: {e}"
    hits = (data.get("result") or {}).get("hits") or data.get("hits") or []
    ips: list[str] = []
    for h in hits:
        ip = (h.get("ip") or (h.get("resource") or {}).get("ip")
              or (h.get("host") or {}).get("ip"))
        if ip and ip not in ips:
            ips.append(ip)
        if len(ips) >= limit:
            break
    return ips, None


_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def _fetch_via_ip(ip: str, host: str, path: str = "/", *, port: int = 443,
                  timeout: int = 8) -> tuple[Optional[int], dict, bytes]:
    """GET `path` from `ip` while presenting Host (and TLS SNI) = `host`, cert
    unverified. HTTP/1.0 so the body needs no de-chunking. (status, headers, body)."""
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None, {}, b""
    sock = raw
    try:
        if port == 443:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(raw, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall((f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
                      "User-Agent: celsius-origin-check/1.0\r\nAccept: */*\r\n\r\n").encode())
        buf = b""
        while len(buf) < 200_000:
            try:
                b = sock.recv(16384)
            except (socket.timeout, OSError):
                break
            if not b:
                break
            buf += b
    finally:
        try:
            sock.close()
        except OSError:
            pass
    head, _, body = buf.partition(b"\r\n\r\n")
    try:
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split()[1])
    except (ValueError, IndexError):
        return None, {}, b""
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


def verify_origin(ip: str, host: str, *, expected_favicon: Optional[int] = None,
                  timeout: int = 8) -> dict:
    """Connect to `ip` presenting Host=`host` and see whether it IS the origin: it
    exposes the real Server header (the CDN hid it), and a matching favicon proves
    it serves the same site. Returns {ip, reachable, status, server, title, matched,
    how}."""
    for port in (443, 80):
        status, headers, body = _fetch_via_ip(ip, host, "/", port=port, timeout=timeout)
        if status is None:
            continue
        m = _TITLE.search(body or b"")
        title = (m.group(1).decode("utf-8", "replace").strip()[:120] if m else "")
        matched, how = False, f"responds (HTTP {status})"
        if expected_favicon is not None:
            fstatus, _fh, fbody = _fetch_via_ip(ip, host, "/favicon.ico", port=port, timeout=timeout)
            if fstatus == 200 and fbody and len(fbody) >= 16:
                from . import favicon as favicon_mod
                if favicon_mod.favicon_hash(fbody) == expected_favicon:
                    matched, how = True, "favicon hash matches the CDN-fronted site"
        return {"ip": ip, "reachable": True, "port": port, "status": status,
                "server": headers.get("server", ""), "title": title,
                "matched": matched, "how": how}
    return {"ip": ip, "reachable": False, "matched": False, "how": "no response on 443/80"}
