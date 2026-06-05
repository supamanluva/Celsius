"""Reverse-IP cohosting is noise behind a shared CDN (the resolved IP is an edge
serving thousands of unrelated tenants) — detect the CDN and skip it; cert-SAN
siblings still count."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.plugins.builtin import _fronting_cdn  # noqa: E402
from celsius.recon import cohost  # noqa: E402


def test_detects_cloudflare_cdn():
    recon = {"tech": [{"name": "Cloudflare", "category": "cdn"},
                      {"name": "nginx", "category": "server"}]}
    assert _fronting_cdn(recon) == "Cloudflare"


def test_detects_cloudflare_waf():
    recon = {"tech": [{"name": "Cloudflare WAF", "category": "waf"}]}
    assert _fronting_cdn(recon) == "Cloudflare WAF"


def test_no_cdn_returns_none():
    recon = {"tech": [{"name": "nginx", "category": "server"},
                      {"name": "WordPress", "category": "cms"}]}
    assert _fronting_cdn(recon) is None
    assert _fronting_cdn({}) is None


def test_discover_without_reverse_ip_keeps_only_san_siblings():
    # do_reverse_ip=False -> no network, only cert-SAN siblings (the related ones)
    info = cohost.discover("geek.nu", "188.114.97.1",
                           ["snaptrack.geek.nu", "geek.nu"], do_reverse_ip=False)
    assert info["from_reverse_ip"] == []
    assert "snaptrack.geek.nu" in info["siblings"]
    assert "geek.nu" not in info["siblings"]            # the scanned host itself is excluded


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
