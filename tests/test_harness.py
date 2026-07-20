"""Offline tests for crawl-aware lab point discovery.

`discover_points` must fold the passively collected attack surface (crawl
endpoints/routes, wayback URLs + parameter names, sitemap URLs) into the points
lab verifiers test — same-host only, deduped, and capped so the extra surface
can't exhaust the request budget. `LabContext.send` is replaced with a stub, so
no network is touched.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.active.harness import (  # noqa: E402
    _MAX_RECON_POINTS, LabContext, Response, discover_points)
from celsius.audit import AuditLog  # noqa: E402

_BASE = "https://example.test/"


def _lab(body: str = "<html><title>home</title></html>") -> LabContext:
    lab = LabContext(host="example.test", enabled=True, attested=True,
                     audit=AuditLog(path="/tmp/celsius-test-harness-audit.log"),
                     rate_limit_rps=50, max_requests=50)

    def fake_send(url, **kw):
        return Response(200, {}, body, None, url)
    lab.send = fake_send  # type: ignore[assignment]
    return lab


def _by_origin(points, origin):
    return [p for p in points if p.origin == origin]


def test_recon_endpoints_with_queries_become_points():
    recon = {"crawl": {"endpoints": ["/search?q=celsius", "/api/user?id=1", "/plain"]},
             "wayback_urls": ["https://example.test/old?page=2"],
             "sitemap_urls": ["https://example.test/doc?ref=nav"]}
    points = discover_points(_BASE, _lab(), recon=recon)
    got = {(p.url, tuple(p.param_names())) for p in _by_origin(points, "recon")}
    assert ("https://example.test/search", ("q",)) in got, got
    assert ("https://example.test/api/user", ("id",)) in got, got
    assert ("https://example.test/old", ("page",)) in got, got
    assert ("https://example.test/doc", ("ref",)) in got, got
    # query-less endpoint alone yields no point
    assert all(p.url != "https://example.test/plain" for p in points)


def test_recon_points_stay_on_target_host():
    recon = {"crawl": {"endpoints": ["https://evil.test/x?a=1", "//cdn.test/lib.js?v=1"]},
             "wayback_urls": ["https://other.test/y?b=2"]}
    points = discover_points(_BASE, _lab(), recon=recon)
    assert all("example.test" in p.url for p in points), points


def test_wayback_params_replayed_onto_base_and_bare_endpoints():
    recon = {"wayback_params": ["id", "page"],
             "crawl": {"endpoints": ["/item", "/search?q=x"]}}
    points = discover_points(_BASE, _lab(), recon=recon)
    wb = _by_origin(points, "wayback-params")
    urls = {p.url for p in wb}
    assert "https://example.test/" in urls or "https://example.test" in urls, urls
    assert "https://example.test/item" in urls, urls
    assert all(set(p.param_names()) == {"id", "page"} for p in wb)


def test_recon_points_are_capped():
    recon = {"crawl": {"endpoints": [f"/e{i}?a={i}" for i in range(3 * _MAX_RECON_POINTS)]}}
    points = discover_points(_BASE, _lab(), recon=recon)
    assert len(_by_origin(points, "recon")) <= _MAX_RECON_POINTS


def test_recon_points_dedup_against_page_discovery():
    body = '<html><a href="/search?q=celsius">s</a></html>'
    recon = {"crawl": {"endpoints": ["/search?q=celsius"]}}
    points = discover_points(_BASE, _lab(body), recon=recon)
    matches = [p for p in points if p.url == "https://example.test/search"]
    assert len(matches) == 1, points


def test_no_recon_behaves_as_before():
    body = ('<html><form action="/go" method="post"><input name="q"></form>'
            '<a href="/x?a=1">x</a></html>')
    points = discover_points("https://example.test/?seed=1", _lab(body))
    origins = {p.origin for p in points}
    assert origins == {"target-url", "form", "link"}, origins


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
