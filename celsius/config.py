"""Scan configuration. Kept in its own module so the plugin layer and the engine
can both import it without a circular dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .auth import AuthSession


@dataclass
class ScanConfig:
    target: str

    # phase/check toggles
    web: bool = True
    cve: bool = True
    cve_pocs: bool = True             # link CVEs to public exploits/PoCs (trickest/cve)
    web_secrets: bool = True
    ports: bool = False
    nuclei: bool = False
    service_probe: bool = True        # safe-active: test open ports for unauthenticated exposed services
    default_creds: bool = False       # safe-active (opt-in): try curated vendor default logins (lockout-safe)

    # M1: recon / attack surface
    dns: bool = True
    tls: bool = True
    robots: bool = True               # harvest robots.txt + sitemap.xml (passive)
    favicon: bool = True              # favicon hash fingerprint (passive, 1 request)
    mailsec: bool = False              # e-mail security (SPF/DKIM/DMARC/MTA-STS/DNSSEC) — opt-in
    fingerprint: bool = True
    subdomains: bool = False          # crt.sh CT lookup (opt-in; can be large/slow)
    wayback: bool = False             # archive.org CDX URL/param harvest (opt-in; passive)
    subdomain_bruteforce: bool = False  # also resolve a wordlist (safe-active)
    topology: bool = False            # map IP topology of target+subdomains (Shodan/RDAP, passive)
    diff: bool = True                 # compare vs the last stored scan

    # M3: crawler / client-side intelligence
    crawl: bool = False               # static crawl + JS intel + source-map recovery
    crawl_max_pages: int = 40
    sourcemaps: bool = True           # within crawl: recover & scan exposed .map sources
    api_discovery: bool = False       # OpenAPI/Swagger probe + GraphQL introspection (safe-active)
    content_discovery: bool = False   # probe for exposed sensitive files/paths (safe-active)
    dynamic: bool = False             # use Playwright if installed

    # port scan
    top_ports: int = 100
    port_range: Optional[str] = None
    udp: bool = False                 # also run a UDP service scan (needs root; slow)
    os_detect: bool = False           # nmap -O OS/device fingerprint (needs root)

    # nuclei
    nuclei_tags: Optional[str] = None       # None -> fast default groups; "" -> all
    nuclei_full: bool = False               # run the entire template set

    # cve
    nvd_api_key: Optional[str] = None

    # M4: exploitability assessment (EPSS + CISA KEV)
    exploitability: bool = True
    cve_verify: bool = False   # confirm detected CVEs with matching nuclei templates (safe-active)

    # transport
    insecure: bool = False
    auth: "Optional[AuthSession]" = None    # authenticated scans (or None)

    # M0: governance
    scope_file: Optional[str] = None        # path to scope.yml (None -> permissive)
    persist: bool = True                    # store the scan in SQLite
    allow_active: bool = True               # safe-active checks permitted (CLI gate)
    allow_exploit: bool = False             # M5: lab-mode active verification

    # M5: lab-mode controls (only matter when allow_exploit and scope EXPLOIT)
    lab_attestation: Optional[str] = None   # per-run authorization statement (required)
    dry_run: bool = False                   # preview payloads without sending
    exploit_rate_limit: float = 5.0         # requests/sec cap for active checks
    exploit_max_requests: int = 200         # hard cap on active requests
    ssrf_oob: bool = False                  # lab-mode: blind-SSRF probe via an OOB canary
    rce_oob: bool = False                   # lab-mode: OS command-injection probe via an OOB canary
    blind_xss_oob: bool = False             # lab-mode: blind/stored-XSS beacon via an OOB canary
    xxe_oob: bool = False                   # lab-mode: blind-XXE probe via an OOB canary
    oob_callback_host: Optional[str] = None  # address the target calls back to (None -> auto-detect)
    oob_domain: Optional[str] = None        # use a DNS canary on this delegated domain (egress-filtered targets)
    oob_dns_port: int = 53                  # UDP port for the DNS canary (53 needs root)
    idor: bool = False                      # lab-mode: IDOR/BOLA authorization probe (needs an auth session)
    auth2: "Optional[AuthSession]" = None   # a second identity, for cross-user BOLA testing
    time_sqli: bool = False                 # lab-mode: time-based blind SQLi (DELIBERATELY delays the DB — opt-in)
    time_sqli_delay: float = 3.0            # seconds the injected SQL sleep should pause for

    # M2: AI layer
    ai: bool = False                        # run AI triage/analysis
    ai_provider: str = "deepseek"           # deepseek|openai|anthropic|kimi|local|mock
    ai_model: Optional[str] = None          # None -> provider default
    ai_base_url: Optional[str] = None
    ai_api_key: Optional[str] = None        # None -> provider env var
    ai_redact: bool = True                  # mask secrets before send (default ON; --ai-no-redact opts out)
    ai_hunt: bool = True                    # lab mode: AI proposes recon-grounded hunt hypotheses

    extra: dict = field(default_factory=dict)
