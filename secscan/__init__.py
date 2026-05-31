"""secscan — a lightweight vulnerability scanner.

Detects running services and versions on web pages / public IPs, looks up known
CVEs for those versions against the NVD, and inspects HTTP security headers
(CSP, HSTS, etc.). Wraps nmap (service/version detection) and, optionally,
nuclei (web vulnerability templates).

Stdlib-only: the core needs no third-party packages. nmap and nuclei are called
as external binaries when present.
"""

__version__ = "1.1.0"
