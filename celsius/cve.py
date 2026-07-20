"""CVE lookup against authoritative sources (NVD + MITRE CNA records).

Why this is more than a single API call: freshly published CVEs sit in NVD as
"Awaiting Analysis" with NO CPE configuration for days/weeks, and their
descriptions rarely contain the exact affected version. A naive
`cpeName=`/keyword query therefore MISSES recent, high-impact CVEs (exactly the
ones you care about). So we:

  1. Discover candidate CVEs for a product via NVD keyword search (paginated —
     NVD caps resultsPerPage at 2000 — cached, and capped at NVD_MAX_RESULTS so
     the client-side matching pass stays bounded).
  2. Version-match each candidate CLIENT-SIDE:
       a. against NVD's CPE version ranges, when the CVE is enriched; else
       b. against the MITRE CNA record's structured `affected[].versions`
          semver ranges (available immediately on publication).

Only authoritative data — never search-engine results, which today are polluted
with AI-invented "CVEs".
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

from . import version as vercmp
from .models import CVE, Service, Severity

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CNA_BASE = "https://cveawg.mitre.org/api/cve/"
CACHE_DIR = Path(os.path.expanduser("~/.cache/celsius/nvd"))
CACHE_TTL = 24 * 3600
USER_AGENT = "celsius/0.1 (+authorized security testing)"

# detected product (lower-cased) -> mapping describing how to find its CVEs.
#   vendor, product : CPE 2.3 fields used to match NVD-enriched configurations.
#   keyword         : NVD keyword search term used to DISCOVER candidate CVEs.
#   accept          : regex a MITRE CNA "<vendor> <product>" string must match
#                     for an un-enriched CVE to count (guards against unrelated
#                     products the keyword search drags in).
#   reject          : optional regex that disqualifies a CNA product (e.g. the
#                     separate "ingress-nginx" project).
class _Map:
    __slots__ = ("vendor", "product", "keyword", "accept", "reject")

    def __init__(self, vendor, product, keyword, accept, reject=None):
        self.vendor = vendor
        self.product = product
        self.keyword = keyword
        self.accept = re.compile(accept, re.I)
        self.reject = re.compile(reject, re.I) if reject else None


_PRODUCT_MAP: dict[str, _Map] = {
    "nginx": _Map("f5", "nginx", "nginx", r"\bnginx\b", reject=r"ingress|unit|njs|amplify|controller"),
    "apache httpd": _Map("apache", "http_server", "apache http server", r"http server|httpd|apache$"),
    "apache http server": _Map("apache", "http_server", "apache http server", r"http server|httpd"),
    "httpd": _Map("apache", "http_server", "apache http server", r"http server|httpd"),
    "openssh": _Map("openbsd", "openssh", "openssh", r"openssh"),
    "openssl": _Map("openssl", "openssl", "openssl", r"openssl"),
    "microsoft-iis": _Map("microsoft", "internet_information_services",
                          "internet information services", r"internet information|iis"),
    "apache tomcat": _Map("apache", "tomcat", "apache tomcat", r"tomcat"),
    "tomcat": _Map("apache", "tomcat", "apache tomcat", r"tomcat"),
    "php": _Map("php", "php", "php", r"\bphp\b"),
    "openresty": _Map("openresty", "openresty", "openresty", r"openresty"),
    "litespeed": _Map("litespeed_technologies", "litespeed_web_server", "litespeed", r"litespeed"),
    "lighttpd": _Map("lighttpd", "lighttpd", "lighttpd", r"lighttpd"),
    "caddy": _Map("caddyserver", "caddy", "caddy", r"\bcaddy\b"),
    "exim": _Map("exim", "exim", "exim", r"\bexim\b"),
    "postfix": _Map("postfix", "postfix", "postfix", r"postfix"),
    "vsftpd": _Map("vsftpd_project", "vsftpd", "vsftpd", r"vsftpd"),
    "proftpd": _Map("proftpd", "proftpd", "proftpd", r"proftpd"),
    "mysql": _Map("oracle", "mysql", "mysql", r"\bmysql\b"),
    "mariadb": _Map("mariadb", "mariadb", "mariadb", r"mariadb"),
    "postgresql": _Map("postgresql", "postgresql", "postgresql", r"postgresql"),
    "redis": _Map("redis", "redis", "redis", r"\bredis\b"),
    "bind": _Map("isc", "bind", "isc bind", r"\bbind\b"),
    "dovecot": _Map("dovecot", "dovecot", "dovecot", r"dovecot"),
    "pure-ftpd": _Map("pureftpd", "pure-ftpd", "pure-ftpd", r"pure.?ftpd"),
    # --- CMS ---
    "wordpress": _Map("wordpress", "wordpress", "wordpress", r"\bwordpress\b"),
    "drupal": _Map("drupal", "drupal", "drupal", r"\bdrupal\b"),
    # NVD's CPE 2.3 formatted string escapes the "!": cpe:2.3:a:joomla:joomla\!
    "joomla": _Map("joomla", "joomla\\!", "joomla", r"\bjoomla\b"),
    "ghost": _Map("tryghost", "ghost", "ghost", r"\bghost\b"),
    # --- self-hosted apps (recon/fingerprint.py + recon/appversion.py probes) ---
    "grafana": _Map("grafana", "grafana", "grafana", r"\bgrafana\b"),
    "nextcloud": _Map("nextcloud", "nextcloud_server", "nextcloud", r"\bnextcloud\b"),
    "owncloud": _Map("owncloud", "owncloud", "owncloud", r"\bowncloud\b"),
    "gitea": _Map("go-gitea", "gitea", "gitea", r"\bgitea\b", reject=r"forgejo"),
    "forgejo": _Map("codeberg", "forgejo", "forgejo", r"\bforgejo\b"),
    "gitlab": _Map("gitlab", "gitlab", "gitlab", r"\bgitlab\b"),
    "jellyfin": _Map("jellyfin", "jellyfin", "jellyfin", r"\bjellyfin\b"),
    # Emby's CPE is emby:emby_server; the keyword covers CNA-only records too.
    "emby": _Map("emby", "emby_server", "emby media server", r"\bemby\b"),
    # Vaultwarden has no NVD CPE (its CVEs ship via GitHub advisories) — keyword
    # discovery + CNA semver matching still applies; enriched CPE matches won't.
    "vaultwarden": _Map("vaultwarden", "vaultwarden", "vaultwarden",
                        r"vaultwarden|bitwarden_rs"),
    "immich": _Map("immich", "immich", "immich", r"\bimmich\b"),
    "plex": _Map("plex", "plex_media_server", "plex media server", r"\bplex\b"),
    "keycloak": _Map("keycloak", "keycloak", "keycloak", r"\bkeycloak\b"),
    "minio": _Map("minio", "minio", "minio", r"\bminio\b"),
    "prometheus": _Map("prometheus", "prometheus", "prometheus", r"\bprometheus\b"),
    "portainer": _Map("portainer", "portainer", "portainer", r"\bportainer\b"),
    "home assistant": _Map("home-assistant", "home-assistant", "home assistant",
                           r"home.?assistant"),
    "mastodon": _Map("joinmastodon", "mastodon", "mastodon", r"\bmastodon\b"),
    "synapse": _Map("matrix", "synapse", "matrix synapse", r"\bsynapse\b"),
    "phpmyadmin": _Map("phpmyadmin", "phpmyadmin", "phpmyadmin", r"phpmyadmin"),
    "roundcube": _Map("roundcube", "webmail", "roundcube", r"\broundcube\b"),
    # No confirmed NVD CPE for these — keyword discovery only (CNA fallback still
    # matches via accept; an enriched CPE config simply won't match the product).
    "uptime kuma": _Map("uptime_kuma_project", "uptime_kuma", "uptime kuma",
                        r"uptime.?kuma"),
    "gotify": _Map("gotify", "gotify", "gotify", r"\bgotify\b"),
    "miniflux": _Map("miniflux", "miniflux", "miniflux", r"\bminiflux\b"),
    "overseerr": _Map("overseerr", "overseerr", "overseerr", r"\boverseerr\b"),
    "jellyseerr": _Map("jellyseerr", "jellyseerr", "jellyseerr", r"\bjellyseerr\b"),
    "mealie": _Map("mealie", "mealie", "mealie", r"\bmealie\b"),
    "audiobookshelf": _Map("audiobookshelf", "audiobookshelf", "audiobookshelf",
                           r"\baudiobookshelf\b"),
    "readeck": _Map("readeck", "readeck", "readeck", r"\breadeck\b"),
    "vikunja": _Map("vikunja", "vikunja", "vikunja", r"\bvikunja\b"),
    "linkding": _Map("linkding", "linkding", "linkding", r"\blinkding\b"),
    # --- frameworks / libraries with detectable versions (fingerprint.py) ---
    "gunicorn": _Map("gunicorn", "gunicorn", "gunicorn", r"\bgunicorn\b"),
    "werkzeug": _Map("palletsprojects", "werkzeug", "werkzeug", r"\bwerkzeug\b"),
    "jquery": _Map("jquery", "jquery", "jquery", r"\bjquery\b"),
    "bootstrap": _Map("getbootstrap", "bootstrap", "bootstrap", r"\bbootstrap\b"),
    "angular": _Map("angular", "angular", "angular", r"\bangular\b"),
    "vue.js": _Map("vuejs", "vue.js", "vue.js", r"\bvue\b"),
    "znc": _Map("znc", "znc", "znc", r"\bznc\b"),
    "phusion passenger": _Map("phusion", "passenger", "phusion passenger", r"passenger"),
}


def _resolve_mapping(name: str) -> Optional[_Map]:
    """Map a detected product/service name to a CVE mapping, tolerating the
    decorations nmap adds. nmap reports e.g. "ISC BIND", "Exim smtpd",
    "Dovecot imapd" — an exact key lookup misses, so fall back to matching a
    single-word map key that appears as a whole token in the name.
    """
    key = (name or "").strip().lower()
    if not key:
        return None
    if key in _PRODUCT_MAP:
        return _PRODUCT_MAP[key]
    tokens = {t for t in re.split(r"[^a-z0-9.+-]+", key) if t}
    for mk, mapping in _PRODUCT_MAP.items():
        if " " not in mk and mk in tokens:
            return mapping
    return None


# ---- HTTP + cache -------------------------------------------------------------

def _cache_get(key: str) -> Optional[dict]:
    f = CACHE_DIR / (hashlib.sha256(key.encode()).hexdigest() + ".json")
    if not f.exists():
        return None
    try:
        if (time.time() - f.stat().st_mtime) > CACHE_TTL:
            return None
        return json.loads(f.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _cache_put(key: str, data: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        f = CACHE_DIR / (hashlib.sha256(key.encode()).hexdigest() + ".json")
        f.write_text(json.dumps(data))
    except OSError:
        pass


def _get_json(url: str, *, api_key: Optional[str] = None, retries: int = 3,
              force_refresh: bool = False) -> Optional[dict]:
    if not force_refresh:
        cached = _cache_get(url)
        if cached is not None:
            return cached
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key
    delay = 6.0 if not api_key else 0.8
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                _cache_put(url, data)
                return data
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503) and attempt < retries:
                time.sleep(delay * (attempt + 1))
                continue
            return None
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            if attempt < retries:
                time.sleep(delay)
                continue
            return None
    return None


# NVD caps resultsPerPage at 2000; high-volume keywords (php, mysql, wordpress)
# exceed that, so discovery paginates with startIndex. NVD_MAX_RESULTS bounds the
# client-side matching pass (and the polite inter-page delay keeps us inside the
# 5-requests-per-30s unauthenticated rate limit).
NVD_PAGE_SIZE = 2000
NVD_MAX_RESULTS = 6000


def _nvd_search(keyword: str, *, api_key: Optional[str] = None,
                force_refresh: bool = False) -> tuple[Optional[list[dict]], bool]:
    """Fetch candidate CVEs for an NVD keyword search, paginating with startIndex.

    Returns (vulns, truncated): `truncated` is True when NVD reported more results
    than we fetched (page cap hit, or a later page failed mid-pagination). Returns
    (None, False) when the FIRST page request fails — the caller reports that as a
    lookup failure rather than a partial result.
    """
    vulns: list[dict] = []
    while True:
        qs = urllib.parse.urlencode({
            "keywordSearch": keyword,
            "resultsPerPage": str(NVD_PAGE_SIZE),
            "startIndex": str(len(vulns)),
        })
        data = _get_json(f"{NVD_BASE}?{qs}", api_key=api_key, force_refresh=force_refresh)
        if data is None:
            return (None, False) if not vulns else (vulns, True)
        page = data.get("vulnerabilities", [])
        vulns.extend(page)
        total = data.get("totalResults", len(vulns))
        if not page or len(vulns) >= total or len(vulns) >= NVD_MAX_RESULTS:
            return vulns, total > len(vulns)
        # Respect NVD rate limits between page requests.
        time.sleep(6.0 if not api_key else 0.8)


# ---- Public exploit / PoC enrichment (trickest/cve) ---------------------------

TRICKEST_BASE = "https://raw.githubusercontent.com/trickest/cve/main"


def _get_text(url: str) -> Optional[str]:
    """Cached GET returning text. A 404 (CVE not in the DB) is cached as a miss."""
    cached = _cache_get(url)
    if cached is not None:
        return cached.get("text", "")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as resp:
            text = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            _cache_put(url, {"text": ""})
        return ""
    except (urllib.error.URLError, OSError):
        return None
    _cache_put(url, {"text": text})
    return text


def trickest_pocs(cve_id: str) -> list[str]:
    """Public exploit/PoC repo URLs for a CVE from the trickest/cve database.

    Parses the markdown's `#### Github` section — a curated list of GitHub repos
    holding a working PoC/exploit for the CVE.
    """
    parts = cve_id.split("-")
    if len(parts) < 3 or not parts[1].isdigit():
        return []
    text = _get_text(f"{TRICKEST_BASE}/{parts[1]}/{cve_id}.md")
    if not text:
        return []
    pocs: list[str] = []
    seen: set[str] = set()
    in_github = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("####"):
            in_github = "github" in s.lower()
            continue
        if s.startswith("###"):
            in_github = False
            continue
        if in_github and s.startswith("- ") and s[2:].strip().startswith("http"):
            url = s[2:].strip()
            if url not in seen:
                seen.add(url)
                pocs.append(url)
    return pocs[:15]


def enrich_pocs(cves: list[CVE], *, max_fetch: int = 40) -> int:
    """Append public-exploit references (from trickest/cve) to FIRM CVEs.

    Weak (low-confidence) CVEs are skipped — they're likely false positives and
    don't warrant exploit links. Returns the number of CVEs enriched.
    """
    ids: list[str] = []
    seen: set[str] = set()
    for c in cves:
        if c.confidence != "weak" and c.id not in seen:
            seen.add(c.id)
            ids.append(c.id)
    ids = ids[:max_fetch]
    if not ids:
        return 0
    poc_map: dict[str, list[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for cid, pocs in zip(ids, ex.map(trickest_pocs, ids)):
            if pocs:
                poc_map[cid] = pocs
    enriched = 0
    for c in cves:
        if c.confidence == "weak":
            continue
        pocs = poc_map.get(c.id)
        if not pocs:
            continue
        existing = {r.get("url") for r in c.references}
        added = False
        for u in pocs:
            if u not in existing:
                c.references.append({"url": u, "tags": ["Exploit"], "poc": True, "source": "trickest"})
                added = True
        if added:
            enriched += 1
    return enriched


# ---- PoC write-up content (for grounding AI verification) ---------------------

_GH_REPO = re.compile(r"https?://github\.com/([^/\s]+)/([^/\s#?]+)", re.I)


def _poc_readme(url: str) -> str:
    """Fetch a GitHub PoC repo's README — the exploit write-up that explains HOW the
    CVE is triggered. Cached (via _get_text). '' if `url` is not a GitHub repo or
    has no reachable README."""
    m = _GH_REPO.match(url.strip())
    if not m:
        return ""
    owner, repo = m.group(1), m.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    if owner.lower() in ("sponsors", "marketplace", "topics", "search", "about"):
        return ""
    for ref, name in (("HEAD", "README.md"), ("main", "README.md"),
                      ("master", "README.md"), ("HEAD", "readme.md")):
        txt = _get_text(f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{name}")
        if txt:
            return txt
    return ""


def poc_technique(url: str, *, max_chars: int = 1200) -> str:
    """A short, cleaned excerpt of a PoC's write-up describing how the CVE is
    exploited — to ground an AI in the real technique. Fenced code blocks (the raw
    exploit itself) are dropped on purpose: we want the model to understand the
    trigger and craft a BENIGN detection probe, not to replay a destructive script.
    '' if no write-up is available."""
    readme = _poc_readme(url)
    if not readme:
        return ""
    text = re.sub(r"```[\s\S]*?```", " ", readme)        # drop fenced code (the raw exploit)
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", text)     # images
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # keep link text, drop URL
    text = re.sub(r"[#>*`_|]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_chars]


def poc_techniques(cve, *, max_pocs: int = 3) -> list[dict]:
    """For a CVE (dict or CVE object), fetch up to `max_pocs` PoC write-up excerpts
    from its enriched (poc=True) references — the exploit technique the AI uses to
    plan a benign confirmation probe. Returns [{"url", "technique"}], [] if none."""
    refs = cve.get("references") if isinstance(cve, dict) else getattr(cve, "references", [])
    urls = [r.get("url") for r in (refs or []) if r.get("poc") and r.get("url")]
    out: list[dict] = []
    for u in urls:
        if len(out) >= max_pocs:
            break
        tech = poc_technique(u)
        if tech:
            out.append({"url": u, "technique": tech})
    return out


# ---- CVSS extraction ----------------------------------------------------------

def _extract_cvss(metrics: dict) -> tuple[Optional[float], Severity]:
    """Prefer CVSS v4.0 (newest standard / CNA headline), then v3.1, v3.0, v2."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            score = data.get("baseScore")
            sev = data.get("baseSeverity")
            return score, Severity[sev] if sev in Severity.__members__ else Severity.from_cvss(score)
    if metrics.get("cvssMetricV2"):
        data = metrics["cvssMetricV2"][0]["cvssData"]
        score = data.get("baseScore")
        return score, Severity.from_cvss(score)
    return None, Severity.INFO


# ---- Version matching ---------------------------------------------------------

def _matches_nvd_config(vuln: dict, product: str, version: str) -> Optional[str]:
    """Match `version` against the CVE's NVD CPE configuration.

    Returns:
      * ``None``   — no configuration (caller should fall back to the CNA record)
      * ``""``     — has configuration(s) but `version` does not match (not vuln)
      * ``"firm"`` — matched via a real version constraint (concrete or a range)
      * ``"weak"`` — matched ONLY via a bare ``*`` (ANY) with no version range.
                     NVD over-models legacy CVEs this way ("all versions ever"),
                     which is the main source of false positives like a 2008 CVE
                     hitting OpenSSH 9.6 — so it's reported but kept low-confidence.
    """
    configs = vuln.get("cve", {}).get("configurations")
    if not configs:
        return None
    result = ""
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable", True):
                    continue
                criteria = m.get("criteria", "")
                parts = criteria.split(":")
                # cpe:2.3:a:<vendor>:<product>:<version>:...
                if len(parts) < 6 or parts[4].lower() != product.lower():
                    continue
                cpe_version = parts[5]
                bounds = (
                    m.get("versionStartIncluding"),
                    m.get("versionStartExcluding"),
                    m.get("versionEndIncluding"),
                    m.get("versionEndExcluding"),
                )
                if vercmp.in_range(
                    version,
                    start_incl=bounds[0],
                    start_excl=bounds[1],
                    end_incl=bounds[2],
                    end_excl=bounds[3],
                    exact=cpe_version,
                ):
                    # A concrete exact version or any real range bound is firm;
                    # a bare "*" with no bounds is the weak "all versions" case.
                    if any(bounds) or cpe_version not in ("*", "-"):
                        return "firm"
                    result = "weak"
    return result


def _matches_cna(cve_id: str, version: str, mapping: "_Map") -> bool:
    """Fetch the MITRE CNA record and match `version` against its semver ranges.

    Only considers `affected[]` entries whose product passes the mapping's
    accept/reject filter, so unrelated products dragged in by the keyword search
    (e.g. ingress-nginx, WordPress plugins) cannot produce false positives.
    """
    data = _get_json(CNA_BASE + cve_id)
    if not data:
        return False
    cna = data.get("containers", {}).get("cna", {})
    for affected in cna.get("affected", []):
        ident = f"{affected.get('vendor', '')} {affected.get('product', '')}".strip()
        if not mapping.accept.search(ident):
            continue
        if mapping.reject and mapping.reject.search(ident):
            continue
        for v in affected.get("versions", []):
            if v.get("status") != "affected":
                continue
            base = (v.get("version") or "").strip()
            less_than = v.get("lessThan")
            less_eq = v.get("lessThanOrEqual")
            # A version field carrying an operator (e.g. "< 1.2.11") or that is
            # non-numeric (e.g. NGINX Plus "R36") is unreliable as a lower bound.
            base_is_clean = bool(vercmp.parse(base)) and not re.search(r"[<>=]", base)
            if not base_is_clean and not (less_than or less_eq):
                continue  # nothing we can match against reliably
            if vercmp.in_range(
                version,
                start_incl=base if (base_is_clean and base != "0") else None,
                end_excl=less_than,
                end_incl=less_eq,
                exact=base if (base_is_clean and not (less_than or less_eq)) else None,
            ):
                return True
    return False


# ---- Public API ---------------------------------------------------------------

# reference hosts that indicate a public exploit / PoC
_POC_HOSTS = ("exploit-db.com", "packetstormsecurity", "github.com", "gitlab.com",
              "metasploit", "0day.today", "seclists.org", "huntr.dev")


def _extract_references(c: dict) -> list[dict]:
    """Capture references, flagging those that point to a public exploit/PoC."""
    refs: list[dict] = []
    for r in c.get("references", []) or []:
        url = r.get("url", "")
        if not url:
            continue
        tags = r.get("tags", []) or []
        is_poc = ("Exploit" in tags) or any(h in url.lower() for h in _POC_HOSTS)
        refs.append({"url": url, "tags": tags, "poc": is_poc})
    # keep PoCs first, cap to keep payloads small
    refs.sort(key=lambda r: not r["poc"])
    return refs[:12]


# A version string carrying a distro suffix (e.g. "9.6p1 Ubuntu 3ubuntu13.16",
# "1.18.0-6.1+deb12u3", "...el9") comes from a distribution package whose
# maintainers backport security fixes WITHOUT bumping the upstream version. So
# an upstream-version CVE match is unreliable — the fix may already be applied.
_DISTRO_RE = re.compile(
    r"(?i)(?:\bubuntu\b|\bdebian\b|[-+~]deb\d|\bel[5-9]\b|\.el\d|\bfc\d\d|"
    r"\bamzn\d|\braspbian\b|ubuntu[\d.]|deb\d+u\d)"
)


def _distro_build(version: str) -> bool:
    return bool(_DISTRO_RE.search(version or ""))


def _confidence(match_kind: str, distro: bool) -> tuple[str, str]:
    """Map a match kind + distro-build flag to (confidence, caveat)."""
    if distro:
        return "weak", (
            "Matched on the upstream version of a distribution package; the distro "
            "likely backported the fix without changing the version. Verify against "
            "the distribution's security tracker before treating as exploitable."
        )
    if match_kind == "weak":
        return "weak", (
            "NVD lists no affected version range for this product (matches every "
            "version), which is frequently over-broad for legacy CVEs. Verify the "
            "advisory applies to this version."
        )
    return "firm", ""


def _build_cve(
    vuln: dict, svc: Service, *, confidence: str = "firm", caveat: str = ""
) -> Optional[CVE]:
    c = vuln.get("cve", {})
    cid = c.get("id")
    if not cid:
        return None
    descs = c.get("descriptions", [])
    desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
    score, sev = _extract_cvss(c.get("metrics", {}))
    return CVE(
        id=cid,
        severity=sev,
        cvss=score,
        description=desc,
        url=f"https://nvd.nist.gov/vuln/detail/{cid}",
        published=c.get("published"),
        affects=svc.label(),
        product=svc.product or svc.name,
        version=svc.version or "",
        port=svc.port,
        references=_extract_references(c),
        confidence=confidence,
        caveat=caveat,
    )


def lookup_for_service(
    svc: Service, *, api_key: Optional[str] = None, max_cna_fetch: int = 60,
    force_refresh: bool = False
) -> tuple[list[CVE], Optional[str]]:
    """Find CVEs affecting one detected service version. Returns (cves, note).

    `force_refresh` bypasses the NVD discovery cache so a re-evaluation picks up
    CVEs published since the entry was cached (used by `celsius recheck`)."""
    if not svc.version:
        return [], "no version detected — skipped CVE lookup (would be too noisy)"

    mapping = _resolve_mapping(svc.product or svc.name or "")
    if not mapping:
        return [], (f"unknown product '{svc.name}' — no CPE/keyword mapping; "
                    "verify manually at nvd.nist.gov")

    product = mapping.product
    vulns, truncated = _nvd_search(mapping.keyword, api_key=api_key,
                                   force_refresh=force_refresh)
    if vulns is None:
        return [], "NVD request failed (rate limit or network)"

    matched: list[CVE] = []
    cna_candidates: list[dict] = []
    distro = _distro_build(svc.version)

    for vuln in vulns:
        decision = _matches_nvd_config(vuln, product, svc.version)
        if decision in ("firm", "weak"):
            conf, caveat = _confidence(decision, distro)
            cve = _build_cve(vuln, svc, confidence=conf, caveat=caveat)
            if cve:
                matched.append(cve)
        elif decision is None:
            cna_candidates.append(vuln)  # un-enriched -> check CNA

    # Resolve un-enriched candidates via CNA records (parallel, capped).
    notes: list[str] = []
    if truncated:
        notes.append(f"keyword search returned more than {len(vulns)} CVEs; "
                     f"only the first {len(vulns)} were evaluated")
    if cna_candidates:
        if len(cna_candidates) > max_cna_fetch:
            notes.append(f"{len(cna_candidates)} un-enriched CVEs; checked first "
                         f"{max_cna_fetch} via CNA records")
            cna_candidates = cna_candidates[:max_cna_fetch]

        def check(vuln):
            cid = vuln.get("cve", {}).get("id", "")
            return vuln if cid and _matches_cna(cid, svc.version or "", mapping) else None

        # CNA matches use real semver ranges, so they're firm unless the service
        # is a distro package (backport caveat still applies).
        conf, caveat = _confidence("firm", distro)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            for vuln in ex.map(check, cna_candidates):
                if vuln:
                    cve = _build_cve(vuln, svc, confidence=conf, caveat=caveat)
                    if cve:
                        matched.append(cve)

    return _dedupe(matched), "; ".join(notes) if notes else None


def _dedupe(cves: list[CVE]) -> list[CVE]:
    seen: set[str] = set()
    out: list[CVE] = []
    for c in sorted(cves, key=lambda x: (x.severity.rank, x.cvss or 0), reverse=True):
        if c.id in seen:
            continue
        seen.add(c.id)
        out.append(c)
    return out


def lookup_all(
    services: list[Service], *, api_key: Optional[str] = None, progress=None,
    force_refresh: bool = False
) -> tuple[list[CVE], list[str]]:
    """Look up CVEs for every versioned service. Returns (cves, notes).

    `force_refresh` bypasses the NVD discovery cache (for re-evaluation)."""
    all_cves: list[CVE] = []
    notes: list[str] = []
    cache: dict[str, list[CVE]] = {}

    for svc in services:
        if not svc.version:
            continue
        key = f"{(svc.product or svc.name).lower()}:{svc.version}"
        if key in cache:
            for c in cache[key]:
                clone = CVE(
                    id=c.id, severity=c.severity, cvss=c.cvss, description=c.description,
                    url=c.url, published=c.published, affects=svc.label(),
                    product=svc.product or svc.name, version=svc.version, port=svc.port,
                    references=c.references, confidence=c.confidence, caveat=c.caveat,
                )
                all_cves.append(clone)
            continue
        if progress:
            progress(f"  querying NVD for {svc.label()} ...")
        cves, note = lookup_for_service(svc, api_key=api_key, force_refresh=force_refresh)
        cache[key] = cves
        all_cves.extend(cves)
        if note:
            notes.append(f"{svc.label()}: {note}")

    return _dedupe(all_cves), notes
