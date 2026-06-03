"""Tests for JS/HTML endpoint extraction and same-site scoping.

Regression anchor: scanning a content-heavy site (e.g. a news aggregator) used
to report hundreds of "API endpoints" that were really third-party links, XML
namespaces, image URLs and backslash-duplicated tokens. Endpoints must be scoped
to the target's own base domain and exclude namespaces/assets.

Stdlib-only: run directly (`python tests/test_jsintel.py`) or under pytest.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import jsintel as j  # noqa: E402


def test_same_site_scoping_and_subdomains():
    text = '''
      <a href="https://example.com/about">x</a>
      var a = "https://example.com/api/users";
      fetch("https://api.example.com/v1/orders");          // same base domain
      img.src = "https://www.youtube.com/watch?v=abc";      // third-party -> drop
      ns = "http://www.w3.org/2000/svg";                    // namespace -> drop
    '''
    eps = j.extract_endpoints(text, origin_host="example.com")
    assert "https://example.com/api/users" in eps
    assert "https://api.example.com/v1/orders" in eps          # subdomain kept
    assert not any("youtube.com" in e for e in eps)            # third-party gone
    assert not any("w3.org" in e for e in eps)                 # namespace gone


def test_backslash_duplicates_collapse():
    # an escaped closing quote must not yield a separate '\'-suffixed endpoint
    text = r'''x = "https://example.com/feed/\"; y = "https://example.com/feed/";'''
    eps = j.extract_endpoints(text, origin_host="example.com")
    assert eps == {"https://example.com/feed/"}


def test_static_assets_excluded():
    text = '''
      "https://example.com/logo.png" "https://example.com/app.css"
      "https://example.com/bundle.js" "/img/hero.jpg" "/api/data"
    '''
    eps = j.extract_endpoints(text, origin_host="example.com")
    assert "/api/data" in eps
    assert not any(e.endswith((".png", ".css", ".js", ".jpg")) for e in eps)


def test_root_relative_api_paths_kept():
    text = '"/api/internal/secrets" "/v2/accounts" "/admin/users" "/static/x.css"'
    eps = j.extract_endpoints(text, origin_host="example.com")
    assert {"/api/internal/secrets", "/v2/accounts", "/admin/users"} <= eps
    assert "/static/x.css" not in eps


def test_scope_endpoints_filters_existing_set():
    raw = {"https://example.com", "https://evil.com/x", "http://www.w3.org/svg",
           "https://sub.example.com/api", "https://example.com\\"}
    kept = j.scope_endpoints(raw, "example.com")
    assert kept == {"https://example.com", "https://sub.example.com/api"}


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
