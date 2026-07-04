"""IP topology / infrastructure mapping.

Resolves the target and its subdomains to IPs, then enriches each distinct IP with
reverse-DNS, Shodan host data (org / ISP / ASN / ports / tags), and an RDAP fallback,
to classify each host as a VPS/datacenter, a residential/home self-host, a managed
SaaS, or a CDN — and groups the hostnames behind each. The result is a map of *where*
a domain's services actually run: e.g. the apps self-hosted at home behind a Pangolin
tunnel on a VPS, with mail on a managed provider and uptime on a SaaS monitor.

Fully passive — DNS, Shodan's database, and RDAP. Never touches the target hosts.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request

# Datacenter / hosting orgs -> a VPS or cloud instance.
_DC = (
    "netcup", "ovh", "hetzner", "digitalocean", "linode", "vultr", "contabo", "amazon",
    "aws", "google", "gcp", "azure", "microsoft", "leaseweb", "scaleway", "oracle",
    "choopa", "datacamp", "hostinger", "ionos", "upcloud", "gandi", "quickpacket",
    "m247", "frantech", "buyvm", "datacenter", "data center", "hosting", "colocation",
    "colo", "dedicated", "vps", "server", "cloud",
)
# Consumer-ISP orgs -> a residential line, i.e. something self-hosted at home.
_RES = (
    "telia", "comhem", "com hem", "bahnhof", "bredband", "tele2", "telenor", "telenet",
    "ownit", "residential", "broadband", "comcast", "charter", "spectrum", "verizon",
    "at&t", "cox", "centurylink", "virgin media", "sky broadband", "deutsche telekom",
    "vodafone", "orange", "bouygues", "kabel", "xfinity", "fios", "dsl", "cable", "fiber",
)
# CDN / edge networks.
_CDN = (
    "cloudflare", "fastly", "akamai", "cloudfront", "incapsula", "sucuri", "bunny",
    "stackpath", "cdn77", "keycdn", "edgecast", "limelight",
)
# PTR substrings that betray a managed third-party SaaS (mail, status, etc.).
_SAAS_PTR = (
    "mxrouting", "hetrixtools", "sendgrid", "mailgun", "sparkpost", "mandrill", "zoho",
    "protonmail", "proton.me", "fastmail", "mailchannels", "sendinblue", "postmark",
    "statuspage", "betteruptime", "uptimerobot", "pingdom", "statuscake", "freshping",
    "github.io", "githubusercontent", "netlify", "vercel", "pages.dev", "wpengine",
    "shopify", "squarespace", "wixdns", "fly.dev", "herokuapp", "fly.io",
)

_KIND_LABEL = {
    "vps": "VPS / datacenter", "home": "residential / home self-host",
    "saas": "managed SaaS / third-party", "cdn": "CDN / edge", "unknown": "unknown",
}


def _label(name: str) -> str:
    """Leftmost label for a hostname; the whole string for an IP literal."""
    if ":" in name or name.replace(".", "").isdigit():
        return name
    return name.split(".")[0]


def _resolve(name: str) -> set[str]:
    """All A + AAAA addresses for a name."""
    out: set[str] = set()
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(name, None):
            if fam in (socket.AF_INET, socket.AF_INET6):
                out.add(str(sa[0]).split("%")[0])  # strip IPv6 scope id
    except (socket.gaierror, OSError):
        pass
    return out


def _ptr(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def _shodan_host(ip: str, key: str, timeout: int) -> tuple[dict, bool, str | None]:
    """(data, in_shodan, error). in_shodan=False on a clean 404 (not indexed)."""
    url = f"https://api.shodan.io/shodan/host/{ip}?key={urllib.parse.quote(key)}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r), True, None
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {}, False, None  # genuinely not in Shodan — a signal, not an error
        return {}, True, f"shodan {ip}: HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 — network best-effort
        return {}, True, f"shodan {ip}: {e}"


def _rdap(ip: str, timeout: int) -> tuple[str, str]:
    """(org, handle) from RDAP — a free, keyless fallback for org/netname."""
    try:
        with urllib.request.urlopen(f"https://rdap.org/ip/{ip}", timeout=timeout) as r:
            d = json.load(r)
    except Exception:  # noqa: BLE001
        return "", ""
    org = d.get("name") or ""
    for ent in d.get("entities", []) or []:
        for arr in (ent.get("vcardArray") or [])[1:]:
            for field in arr:
                if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                    if not org or len(str(field[3])) > len(org):
                        org = str(field[3])
    return org, (d.get("handle") or "")


def _classify(org: str, isp: str, ptr: str, in_shodan: bool) -> tuple[str, str]:
    """Return (kind, reason)."""
    s = f"{org} {isp}".lower()
    p = ptr.lower()
    if any(k in p for k in _SAAS_PTR):
        return "saas", f"PTR {ptr} is a known managed provider"
    if any(k in s for k in _CDN) or any(k in p for k in _CDN):
        return "cdn", "CDN/edge network"
    if any(k in s for k in _RES):
        return "home", f"consumer-ISP allocation ({org or isp})"
    if any(k in s for k in _DC):
        return "vps", f"datacenter/hosting org ({org or isp})"
    if not in_shodan and (org or isp):
        return "home", f"public IP not indexed by Shodan + non-hosting org ({org or isp})"
    if not in_shodan:
        return "unknown", "public IP not indexed by Shodan (possible home/residential)"
    return "unknown", f"unrecognised org ({org or isp or 'n/a'})"


def map_topology(
    host: str, subdomains: list[str], *, shodan_key: str = "",
    max_hosts: int = 80, max_ips: int = 40, timeout: int = 12,
) -> tuple[dict, list[str]]:
    """Map target+subdomains to distinct IPs and classify each. Returns (info, errors)."""
    errors: list[str] = []
    names = [host] + [s for s in subdomains if s and s != host]
    seen, ordered = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            ordered.append(n)
    capped = ordered[:max_hosts]
    if len(ordered) > max_hosts:
        errors.append(f"topology: capped at {max_hosts} hostnames (had {len(ordered)})")

    ip_names: dict[str, set[str]] = {}
    for n in capped:
        for ip in _resolve(n):
            ip_names.setdefault(ip, set()).add(n)
    if not ip_names:
        return {"hosts": [], "n_hosts": 0, "summary": ""}, errors

    ips = sorted(ip_names, key=lambda i: (-len(ip_names[i]), i))[:max_ips]
    if len(ip_names) > max_ips:
        errors.append(f"topology: capped at {max_ips} IPs (had {len(ip_names)})")

    hosts = []
    for ip in ips:
        ptr = _ptr(ip)
        org = isp = asn = country = ""
        ports: list[int] = []
        tags: list[str] = []
        in_shodan = False
        if shodan_key:
            data, in_shodan, err = _shodan_host(ip, shodan_key, timeout)
            if err:
                errors.append(err)
            if data:
                org = data.get("org") or ""
                isp = data.get("isp") or ""
                asn = data.get("asn") or ""
                country = data.get("country_name") or ""
                ports = sorted(set(data.get("ports") or []))
                tags = data.get("tags") or []
        if not org:  # no key, 404, or sparse Shodan record -> RDAP fallback
            org, handle = _rdap(ip, timeout)
            asn = asn or handle
        kind, reason = _classify(org, isp, ptr, in_shodan)
        hosts.append({
            "ip": ip, "version": 6 if ":" in ip else 4,
            "org": org, "isp": isp, "asn": asn, "country": country,
            "ptr": ptr, "ports": ports, "tags": tags, "in_shodan": in_shodan,
            "kind": kind, "reason": reason,
            "hostnames": sorted(ip_names[ip]),
        })

    # Order the map by kind so the picture reads vps -> home -> saas -> cdn.
    rank = {"home": 0, "vps": 1, "saas": 2, "cdn": 3, "unknown": 4}
    hosts.sort(key=lambda h: (rank.get(h["kind"], 9), -len(h["hostnames"]), h["ip"]))

    lines = [f"{len(hosts)} distinct host(s) behind {host}:"]
    for h in hosts:
        short = [_label(n) for n in h["hostnames"]]
        loc = h["org"] or h["isp"] or "?"
        port_s = f" ports {h['ports']}" if h["ports"] else ""
        ptr_s = f" PTR={h['ptr']}" if h["ptr"] else ""
        lines.append(
            f"  {h['ip']} [{_KIND_LABEL[h['kind']]}] {loc}"
            f"{' ' + h['asn'] if h['asn'] else ''}{ptr_s}{port_s} "
            f"— {', '.join(short[:10])}{' …' if len(short) > 10 else ''}")
    summary = "\n".join(lines)
    return {"hosts": hosts, "n_hosts": len(hosts), "summary": summary}, errors
