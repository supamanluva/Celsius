"""End-of-life (EOL) knowledge base for passively fingerprinted software.

Given a product name + version (as surfaced by the fingerprinter or nmap), decide
whether that release is past its vendor end-of-life — i.e. no longer receiving
security patches. Dates are curated and conservative; update them over time.

`check_eol()` handles versioned runtimes/servers/CMSs (PHP, IIS→Windows, Apache
httpd, Tomcat, OpenSSL, nginx, Caddy, Drupal). `check_os_distro()` flags EOL OS distributions named in a
verbose Server header (e.g. "Apache/2.4.6 (CentOS)").
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Optional


def _today() -> date:
    return datetime.now().date()


def _ver(s: str) -> tuple[int, ...]:
    """Parse a leading dotted version ('8.5.93' -> (8,5,93)); non-numeric tail ignored."""
    nums = re.findall(r"\d+", s or "")
    return tuple(int(n) for n in nums[:4]) or (0,)


def _branch(version: str) -> str:
    v = _ver(version)
    return ".".join(str(x) for x in v[:2]) if len(v) >= 2 else (str(v[0]) if v else "0")


# Branch -> EOL date (ISO). A version on a branch is EOL once that date has passed.
_PHP_EOL = {
    "5.4": "2015-09-03", "5.5": "2016-07-21", "5.6": "2018-12-31",
    "7.0": "2019-01-10", "7.1": "2019-12-01", "7.2": "2020-11-30",
    "7.3": "2021-12-06", "7.4": "2022-11-28",
    "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31",
    "8.3": "2027-12-31", "8.4": "2028-12-31",
}

_TOMCAT_EOL = {
    "6.0": "2016-12-31", "7.0": "2021-03-31", "8.0": "2018-06-30",
    "8.5": "2024-03-31", "9.0": "2027-12-31", "10.0": "2022-10-31",
    "10.1": "2028-12-31", "11.0": "2029-12-31",
}

_OPENSSL_EOL = {
    "0.9.8": "2015-12-31", "1.0.0": "2015-12-31", "1.0.1": "2016-12-31",
    "1.0.2": "2019-12-31", "1.1.0": "2019-09-11", "1.1.1": "2023-09-11",
    "3.0": "2026-09-07", "3.1": "2025-03-14", "3.2": "2025-11-23",
    "3.3": "2026-04-09", "3.4": "2026-10-22", "3.5": "2030-04-08",
}

# nginx stable branches: date each was superseded by a newer stable. Security
# fixes land on current stable + mainline, so older branches stop getting them
# upstream — though Linux distros frequently backport (hence MEDIUM, not HIGH).
_NGINX_EOL = {
    "1.14": "2019-04-23", "1.16": "2020-04-21", "1.18": "2021-05-25",
    "1.20": "2022-05-24", "1.22": "2023-05-23", "1.24": "2024-05-29",
    "1.26": "2025-04-23",
}

# IIS version -> (Windows Server release, that OS's EOL date).
_IIS_WINDOWS = {
    "6.0": ("Windows Server 2003", "2015-07-14"),
    "7.0": ("Windows Server 2008", "2020-01-14"),
    "7.5": ("Windows Server 2008 R2", "2020-01-14"),
    "8.0": ("Windows Server 2012", "2023-10-10"),
    "8.5": ("Windows Server 2012 R2", "2023-10-10"),
    "10.0": ("Windows Server 2016/2019/2022", "2027-01-12"),
}

# Drupal major -> EOL date (10.x/11.x still supported; only dead majors listed).
_DRUPAL_EOL = {
    "7": "2025-01-05", "8": "2021-11-02", "9": "2023-11-01",
}


def _verdict(product: str, version: str, eol_iso: str, *,
             extra: str = "", eol_severity: str = "HIGH",
             today: Optional[date] = None) -> Optional[dict]:
    """Build a verdict if the release is EOL or nearing EOL; else None.
    `eol_severity` lets callers soften the rating (e.g. distro-backported servers)."""
    today = today or _today()
    try:
        eol = date.fromisoformat(eol_iso)
    except ValueError:
        return None
    days = (eol - today).days
    if days < 0:
        status, sev = "eol", eol_severity
    elif days <= 180:
        status, sev = "soon", "MEDIUM"
    else:
        return None
    note = (f"{product} {version} reached end-of-life on {eol_iso}"
            if status == "eol" else
            f"{product} {version} reaches end-of-life on {eol_iso} (within 6 months)")
    if extra:
        note += f". {extra}"
    return {"product": product, "version": version, "status": status,
            "eol_date": eol_iso, "severity": sev, "note": note}


def check_eol(name: str, version: str, *, today: Optional[date] = None) -> Optional[dict]:
    """Return an EOL verdict for a fingerprinted (name, version), or None if it's
    still supported / unknown."""
    if not version:
        return None
    n = name.lower()
    branch = _branch(version)

    if "php" in n:
        eol = _PHP_EOL.get(branch)
        return _verdict("PHP", version, eol, today=today) if eol else (
            _verdict("PHP", version, "2018-12-31", today=today) if _ver(version) < (7,) else None)

    if "tomcat" in n:
        eol = _TOMCAT_EOL.get(branch)
        if not eol and _ver(version) < (6,):
            eol = "2016-12-31"
        return _verdict("Apache Tomcat", version, eol, today=today) if eol else None

    if "openssl" in n:
        eol = _OPENSSL_EOL.get(branch) or _OPENSSL_EOL.get(".".join(map(str, _ver(version)[:3])))
        return _verdict("OpenSSL", version, eol, today=today) if eol else None

    if "iis" in n:
        info = _IIS_WINDOWS.get(branch)
        if info:
            os_name, eol = info
            return _verdict("Microsoft IIS", version, eol,
                            extra=f"Implies {os_name}, which is end-of-life", today=today)
        return None

    if "apache" in n and "tomcat" not in n:  # Apache httpd
        if _ver(version) < (2, 4):
            return _verdict("Apache httpd", version, "2017-12-31",
                            extra="Apache httpd 2.2 and older are end-of-life", today=today)
        return None

    if "caddy" in n:
        if _ver(version) < (2,):
            return _verdict("Caddy", version, "2020-05-04",
                            extra="Caddy 1.x is end-of-life; upgrade to Caddy 2", today=today)
        return None

    if n == "nginx" or n.endswith("nginx"):
        eol = _NGINX_EOL.get(branch)
        # Anything older than the oldest tracked stable branch is definitely EOL.
        if not eol and _ver(version) < (1, 14):
            eol = "2018-01-01"
        if eol:
            return _verdict("nginx", version, eol, eol_severity="MEDIUM",
                            extra="Older nginx stable branch; note many distros backport "
                                  "security fixes — confirm with your vendor",
                            today=today)
        return None

    if "drupal" in n:
        eol = _DRUPAL_EOL.get(str(_ver(version)[0]))
        return _verdict("Drupal", version, eol, today=today) if eol else None

    return None


# OS distributions whose *entire* line is EOL, detectable by name alone.
_DISTRO_EOL = {
    "centos": ("CentOS Linux", "2024-06-30",
               "CentOS Linux is fully end-of-life; migrate to a maintained RHEL/Alma/Rocky."),
}


def check_os_distro(server_header: str, *, today: Optional[date] = None) -> Optional[dict]:
    """Flag an EOL OS distribution named in a Server header (e.g. '(CentOS)')."""
    s = (server_header or "").lower()
    for needle, (label, eol_iso, advice) in _DISTRO_EOL.items():
        if needle in s:
            today = today or _today()
            try:
                if (date.fromisoformat(eol_iso) - today).days < 0:
                    return {"product": label, "version": "", "status": "eol",
                            "eol_date": eol_iso, "severity": "HIGH",
                            "note": f"{label} reached end-of-life on {eol_iso}. {advice}"}
            except ValueError:
                pass
    return None
