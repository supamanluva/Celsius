"""Offline tests for CVE product-name resolution (no network).

Regression anchor: nmap reports service names with decorations — "ISC BIND",
"Exim smtpd", "Dovecot imapd" — which missed the exact _PRODUCT_MAP keys, so CVE
lookup was silently skipped for versioned services that have real CVEs. The
resolver must map these to their canonical product without false matches.

Stdlib-only: run directly (`python tests/test_cve.py`) or under pytest.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import cve  # noqa: E402


def _prod(name):
    m = cve._resolve_mapping(name)
    return m.product if m else None


def test_resolves_nmap_decorated_names():
    assert _prod("ISC BIND") == "bind"
    assert _prod("Exim smtpd") == "exim"
    assert _prod("Dovecot imapd") == "dovecot"
    assert _prod("Dovecot DirectAdmin pop3d") == "dovecot"
    assert _prod("Pure-FTPd") == "pure-ftpd"


def test_exact_names_still_resolve():
    assert _prod("nginx") == "nginx"
    assert _prod("Apache httpd") == "http_server"
    assert _prod("OpenSSH") == "openssh"


def test_no_false_substring_match():
    # "bind" must match only as a whole token, not inside another word
    assert _prod("rebind-helper") is None
    assert _prod("something-else") is None
    assert _prod("") is None


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
