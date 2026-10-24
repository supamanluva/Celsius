"""When a reverse proxy/CDN fronts the origin, the Server-header version is not a
confirmed edge identity — reconcile_server_identity must flag the ambiguity."""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.http_analysis import (  # noqa: E402
    HttpResult, detect_services, reconcile_server_identity,
)
from celsius.models import ScanResult, Service  # noqa: E402
from celsius.plugins import builtin  # noqa: E402


def _res(headers):
    return HttpResult("https://x/", 200, headers, "https://x/")


def test_via_caddy_fronting_nginx_is_flagged():
    # the luhn.se case: Server says nginx, Via says Caddy
    r = _res({"server": "nginx/1.29.8", "via": "1.1 Caddy"})
    svcs = detect_services(r)
    finds = reconcile_server_identity(r, svcs)
    assert len(finds) == 1
    assert "behind Caddy" in finds[0].title and "nginx" in finds[0].title
    origin = next(s for s in svcs if s.source == "http-header:server")
    assert origin.extra.get("behind_proxy") == "Caddy"


def test_direct_origin_not_flagged():
    r = _res({"server": "nginx/1.29.8"})            # no proxy header
    assert reconcile_server_identity(r, detect_services(r)) == []


def test_proxy_equals_origin_not_flagged():
    # Caddy in front AND Caddy is the origin → no ambiguity
    r = _res({"server": "Caddy", "via": "1.1 Caddy"})
    assert reconcile_server_identity(r, detect_services(r)) == []


def test_cloudflare_cf_ray_detected():
    r = _res({"server": "nginx/1.25.0", "cf-ray": "abc-LHR"})
    finds = reconcile_server_identity(r, detect_services(r))
    assert len(finds) == 1 and "Cloudflare" in finds[0].title


def test_real_fastly_cache_node_detected():
    # Fastly's X-Served-By carries a cache-node id
    r = _res({"server": "nginx/1.25.0",
              "x-served-by": "cache-iad-kiad7000027, cache-lga21931-LGA"})
    finds = reconcile_server_identity(r, detect_services(r))
    assert len(finds) == 1 and "Fastly" in finds[0].title


def test_fastly_star_header_detected():
    r = _res({"server": "nginx/1.25.0", "fastly-debug-digest": "deadbeef"})
    finds = reconcile_server_identity(r, detect_services(r))
    assert len(finds) == 1 and "Fastly" in finds[0].title


def test_vanity_x_served_by_is_not_fastly():
    # the internets.nu case: a site sets X-Served-By to its own name — not a CDN.
    r = _res({"server": "openresty", "x-served-by": "internets.nu"})
    svcs = detect_services(r)
    finds = reconcile_server_identity(r, svcs)
    assert finds == []
    origin = next(s for s in svcs if s.source == "http-header:server")
    assert "behind_proxy" not in origin.extra


def _probe_ctx(services):
    result = ScanResult(target="t", url="https://x/", services=services)
    result.recon["tech"] = [{"name": "OpenResty"}, {"name": "nginx"}]
    return SimpleNamespace(
        result=result, http_result=None,
        config=SimpleNamespace(insecure=False, auth=None),
        target=SimpleNamespace(web_url=lambda: "https://x/"),
    )


def _mock_recovery(product, version):
    builtin.http_analysis.probe_server_version = (
        lambda *args, **kwargs: ((product, version), ["offline recovery"]))


def test_openresty_origin_gets_separate_linked_nginx_core():
    origin = Service(name="OpenResty", source="http-header:server", port=443, protocol="tcp")
    ctx = _probe_ctx([origin])
    _mock_recovery("nginx", "1.25.3")
    builtin.ServerVersionProbe().run(ctx)
    assert origin.version is None
    assert origin.extra["core"] == "nginx 1.25.3"
    cores = [s for s in ctx.result.services if s.name == "nginx"]
    assert len(cores) == 1
    core = cores[0]
    assert core.version == "1.25.3"
    assert core.source == "error-page"
    assert core.extra["layer"] == "origin"
    assert core.extra["version_source"] == "error-page"
    assert core.extra["core_of"] == "OpenResty"
    assert (core.port, core.protocol) == (443, "tcp")
    tech = {t["name"]: t.get("version") for t in ctx.result.recon["tech"]}
    assert tech == {"OpenResty": None, "nginx": "1.25.3"}
    assert len(ctx.result.findings) == 1
    assert "the origin" in ctx.result.findings[0].description


def test_openresty_reuses_existing_core_without_duplicates():
    origin = Service(name="OpenResty", source="http-header:server")
    existing = Service(name="nginx", source="fingerprint")
    ctx = _probe_ctx([origin, existing])
    _mock_recovery("nginx", "1.25.3")
    probe = builtin.ServerVersionProbe()
    probe.run(ctx)
    probe.run(ctx)
    cores = [s for s in ctx.result.services if s.name == "nginx"]
    assert cores == [existing]
    assert existing.version == "1.25.3"
    assert existing.source == "error-page"
    assert existing.extra["core_of"] == "OpenResty"


def test_same_product_recovery_still_updates_origin():
    origin = Service(name="nginx", source="http-header:server")
    ctx = _probe_ctx([origin])
    _mock_recovery("nginx", "1.27.0")
    builtin.ServerVersionProbe().run(ctx)
    assert origin.version == "1.27.0"
    assert origin.extra["version_source"] == "error-page"
    assert len(ctx.result.services) == 1
    assert len(ctx.result.findings) == 1


def test_openresty_fronting_proxy_attribution_is_preserved():
    origin = Service(name="OpenResty", source="http-header:server",
                     extra={"behind_proxy": "Caddy"})
    ctx = _probe_ctx([origin])
    _mock_recovery("nginx", "1.25.3")
    builtin.ServerVersionProbe().run(ctx)
    assert origin.version is None and "core" not in origin.extra
    assert len(ctx.result.services) == 2
    edge = next(s for s in ctx.result.services if s.name == "nginx")
    assert edge.extra["layer"] == "Caddy"
    assert "not the OpenResty origin" in edge.extra["note"]
    assert "Caddy" in ctx.result.findings[0].description


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
