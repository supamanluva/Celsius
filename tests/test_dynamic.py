"""Tests for the dynamic SPA analyzer's pure logic and graceful degradation.

The browser-driving path needs Playwright + a provisioned Chromium and isn't
exercised in CI; the URL/endpoint/route logic below is pure and fully tested.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secscan.recon import dynamic as D  # noqa: E402


def test_extract_endpoints_same_host_api_only():
    reqs = [
        ("GET", "https://app.example.com/api/users", "xhr"),
        ("POST", "https://app.example.com/graphql", "fetch"),
        ("GET", "https://app.example.com/static/main.js", "script"),   # not an endpoint
        ("GET", "https://cdn.other.com/api/x", "xhr"),                 # other host
        ("GET", "https://app.example.com/v2/orders?id=1", "xhr"),
    ]
    eps = D.extract_endpoints(reqs, "app.example.com")
    assert "GET https://app.example.com/api/users" in eps
    assert "POST https://app.example.com/graphql" in eps
    assert "GET https://app.example.com/v2/orders?id=1" in eps
    assert not any("other.com" in e for e in eps)
    assert not any("main.js" in e for e in eps)


def test_looks_like_endpoint():
    assert D._looks_like_endpoint("https://x/anything", "xhr")
    assert D._looks_like_endpoint("https://x/api/orders", "document")
    assert not D._looks_like_endpoint("https://x/styles.css", "stylesheet")


def test_extract_routes_includes_hash_routes():
    routes = D.extract_routes([
        "https://app/", "https://app/dashboard",
        "https://app/spa#/settings", "https://app/dashboard",  # dup
    ])
    assert routes == ["/", "/dashboard", "/spa#/settings"]


def test_crawl_degrades_without_playwright():
    if D.is_available():
        return  # Playwright present in this env — skip the degradation assertion
    info, errors = D.crawl("https://example.com")
    assert info == {}
    assert errors and "playwright" in errors[0].lower()


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
