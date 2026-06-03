"""Offline tests for robots.txt / sitemap harvesting."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import robots as R  # noqa: E402


def test_parse_robots_paths_and_sitemaps():
    txt = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /tmp\n"
        "Allow: /public\n"
        "Disallow: /\n"               # bare root is ignored (not a lead)
        "# a comment\n"
        "Sitemap: https://x.test/sitemap.xml\n"
    )
    paths, sitemaps = R._parse_robots(txt)
    assert "/admin/" in paths and "/tmp" in paths and "/public" in paths
    assert "/" not in paths
    assert "https://x.test/sitemap.xml" in sitemaps


def test_parse_sitemap_locs():
    xml = ("<urlset><url><loc>https://x.test/a</loc></url>"
           "<url><loc> https://x.test/b </loc></url></urlset>")
    locs = R._parse_sitemap(xml)
    assert locs == ["https://x.test/a", "https://x.test/b"]


def _patch(by_suffix):
    def fake(url, insecure, auth):
        for suffix, body in by_suffix.items():
            if url.endswith(suffix):
                return 200, body
        return 404, ""
    R._fetch = fake


def test_harvest_flags_sensitive_and_collects_urls():
    _patch({
        "robots.txt": "User-agent: *\nDisallow: /admin\nDisallow: /static\n",
        "sitemap.xml": "<urlset><url><loc>https://x.test/home</loc></url></urlset>",
    })
    findings, paths, sitemap_urls, _ = R.harvest("https://x.test")
    assert "/admin" in paths and "/static" in paths
    assert "https://x.test/home" in sitemap_urls
    assert findings and "sensitive" in findings[0].title.lower()  # /admin matched
    assert findings[0].severity.value == "LOW"


def test_harvest_no_robots_is_quiet():
    _patch({})  # everything 404
    findings, paths, sitemap_urls, _ = R.harvest("https://x.test")
    assert findings == [] and paths == [] and sitemap_urls == []


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
