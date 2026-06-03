"""CVE lookup against authoritative sources (NVD + MITRE CNA records).

Why this is more than a single API call: freshly published CVEs sit in NVD as
"Awaiting Analysis" with NO CPE configuration for days/weeks, and their
descriptions rarely contain the exact affected version. A naive
`cpeName=`/keyword query therefore MISSES recent, high-impact CVEs (exactly the
ones you care about). So we:

  1. Discover candidate CVEs for a product via NVD keyword search (one cached
     request returns the product's whole history).
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
}


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


def _get_json(url: str, *, api_key: Optional[str] = None, retries: int = 3) -> Optional[dict]:
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
        version=svc.version,
        port=svc.port,
        references=_extract_references(c),
        confidence=confidence,
        caveat=caveat,
    )


def lookup_for_service(
    svc: Service, *, api_key: Optional[str] = None, max_cna_fetch: int = 60
) -> tuple[list[CVE], Optional[str]]:
    """Find CVEs affecting one detected service version. Returns (cves, note)."""
    if not svc.version:
        return [], "no version detected — skipped CVE lookup (would be too noisy)"

    name_key = (svc.product or svc.name or "").strip().lower()
    mapping = _PRODUCT_MAP.get(name_key)
    if not mapping:
        return [], (f"unknown product '{svc.name}' — no CPE/keyword mapping; "
                    "verify manually at nvd.nist.gov")

    product = mapping.product
    url = f"{NVD_BASE}?{urllib.parse.urlencode({'keywordSearch': mapping.keyword, 'resultsPerPage': '2000'})}"
    data = _get_json(url, api_key=api_key)
    if data is None:
        return [], "NVD request failed (rate limit or network)"

    vulns = data.get("vulnerabilities", [])
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
    note: Optional[str] = None
    if cna_candidates:
        if len(cna_candidates) > max_cna_fetch:
            note = (f"{len(cna_candidates)} un-enriched CVEs; checked first "
                    f"{max_cna_fetch} via CNA records")
            cna_candidates = cna_candidates[:max_cna_fetch]

        def check(vuln):
            cid = vuln.get("cve", {}).get("id", "")
            return vuln if cid and _matches_cna(cid, svc.version, mapping) else None

        # CNA matches use real semver ranges, so they're firm unless the service
        # is a distro package (backport caveat still applies).
        conf, caveat = _confidence("firm", distro)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            for vuln in ex.map(check, cna_candidates):
                if vuln:
                    cve = _build_cve(vuln, svc, confidence=conf, caveat=caveat)
                    if cve:
                        matched.append(cve)

    return _dedupe(matched), note


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
    services: list[Service], *, api_key: Optional[str] = None, progress=None
) -> tuple[list[CVE], list[str]]:
    """Look up CVEs for every versioned service. Returns (cves, notes)."""
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
        cves, note = lookup_for_service(svc, api_key=api_key)
        cache[key] = cves
        all_cves.extend(cves)
        if note:
            notes.append(f"{svc.label()}: {note}")

    return _dedupe(all_cves), notes
