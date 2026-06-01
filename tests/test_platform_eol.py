"""Tests for passive OS/platform inference and the EOL knowledge base.

Pinned against the real example.com stack (Java/Tomcat + SiteVision behind an F5
BIG-IP) and a curated set of EOL/ supported versions. Stdlib-only: run directly
(`python tests/test_platform_eol.py`) or under pytest.
"""

from __future__ import annotations

import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secscan import eol  # noqa: E402
from secscan.recon import fingerprint as fp  # noqa: E402

REF = date(2026, 6, 1)  # fixed "today" for deterministic EOL assertions


# ---- EOL knowledge base ------------------------------------------------------

def test_eol_flags_unsupported_versions():
    eol_cases = [
        ("PHP", "7.4.33"), ("PHP", "8.1.20"),
        ("Microsoft-IIS", "8.5"), ("Apache httpd", "2.2.15"),
        ("Apache Tomcat", "8.5.50"), ("OpenSSL", "1.1.1k"),
    ]
    for name, ver in eol_cases:
        v = eol.check_eol(name, ver, today=REF)
        assert v and v["status"] == "eol", f"{name} {ver} should be EOL, got {v}"
        assert v["severity"] == "HIGH"


def test_eol_passes_supported_versions():
    ok_cases = [
        ("PHP", "8.3.4"), ("Microsoft-IIS", "10.0"), ("Apache httpd", "2.4.58"),
        ("Apache Tomcat", "10.1.5"), ("OpenSSL", "3.5.0"), ("nginx", "1.27.0"),
    ]
    for name, ver in ok_cases:
        assert eol.check_eol(name, ver, today=REF) is None, f"{name} {ver} should be supported"


def test_iis_eol_names_the_windows_release():
    v = eol.check_eol("Microsoft-IIS", "8.5", today=REF)
    assert "Windows Server 2012 R2" in v["note"]


def test_centos_distro_flagged_eol():
    v = eol.check_os_distro("Apache/2.4.6 (CentOS)", today=REF)
    assert v and v["status"] == "eol"
    assert eol.check_os_distro("Apache/2.4.58 (Ubuntu)", today=REF) is None


# ---- passive platform inference ----------------------------------------------

def _platform(headers, body=""):
    techs, _services, _findings, platform = fp.fingerprint(headers, body)
    return techs, platform


def test_example_stack_inferred():
    headers = {
        "set-cookie": "JSESSIONID=ABC123; Path=/; Secure; HttpOnly; "
                      "SiteVisionLTM=!HUu/dEtzhiF0X9hc/EGK4Up6bd4mG9dqrg6/WJfzQVjJxkdb30HQ==; path=/",
        "link": "</sitevision/system-resource/abc/css/portlets.css>; rel=preload",
    }
    techs, platform = _platform(headers, "<html>sitevision</html>")
    names = {t.name for t in techs}
    assert "F5 BIG-IP" in names, "renamed/encrypted F5 LTM cookie must be detected"
    assert platform["os"] == "Linux"
    assert "Java" in (platform["runtime"] or "")
    assert "F5 BIG-IP" in platform["edge"]


def test_windows_iis_inferred():
    _techs, platform = _platform({"server": "Microsoft-IIS/10.0",
                                  "set-cookie": "ASP.NET_SessionId=xyz"})
    assert platform["os"] == "Windows"
    assert platform["os_confidence"] == "high"


def test_server_header_os_hint():
    _techs, platform = _platform({"server": "Apache/2.4.41 (Ubuntu)"})
    assert platform["os"] == "Linux"
    assert platform["os_confidence"] == "high"


def test_nodejs_openresty_weak_linux():
    # secop.se shape: Next.js behind OpenResty, no cookies / OS hint -> low-conf Linux
    _techs, platform = _platform({"server": "openresty", "x-powered-by": "Next.js"})
    assert platform["runtime"] == "Node.js"
    assert platform["os"] == "Linux"
    assert platform["os_confidence"] == "low"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
