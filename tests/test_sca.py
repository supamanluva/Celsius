"""Offline tests for SCA manifest parsing and OSV result handling.

The live OSV.dev query is not exercised here (network-dependent); these cover the
parsers, version cleaning, severity mapping and fixed-version extraction.
"""

from __future__ import annotations

import os
import sys
import tempfile
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import sca  # noqa: E402


def _write(d: str, name: str, content: str) -> None:
    with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
        fh.write(content)


def test_clean_versions():
    assert sca._clean("^4.17.4") == "4.17.4"
    assert sca._clean("~1.2") == "1.2"
    assert sca._clean(">=1.0,<2.0") == "1.0"
    assert sca._clean("v2.7.6") == "2.7.6"


def test_discover_npm_lock_and_pypi():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "package-lock.json",
               '{"lockfileVersion":3,"packages":{'
               '"":{"name":"x"},'
               '"node_modules/lodash":{"version":"4.17.4"},'
               '"node_modules/express":{"version":"4.21.2"}}}')
        _write(d, "requirements.txt", "Django==2.2.0\nrequests>=2.31.0\n# comment\n")
        deps = {(x.ecosystem, x.name, x.version) for x in sca.discover_deps(d)}
        assert ("npm", "lodash", "4.17.4") in deps
        assert ("npm", "express", "4.21.2") in deps
        assert ("PyPI", "Django", "2.2.0") in deps


def test_lockfile_suppresses_loose_manifest():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "package-lock.json",
               '{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}')
        _write(d, "package.json", '{"dependencies":{"a":"^1.0.0","b":"^2.0.0"}}')
        names = {x.name for x in sca.discover_deps(d)}
        # package.json must be skipped when a lockfile exists -> only the locked dep
        assert names == {"a"}


def test_composer_and_gemfile_and_cargo():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "composer.lock", '{"packages":[{"name":"monolog/monolog","version":"2.9.1"}]}')
        _write(d, "Gemfile.lock", "GEM\n  specs:\n    rails (7.0.4)\n    rack (2.2.4)\n")
        _write(d, "Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0.130"\n')
        deps = {(x.ecosystem, x.name, x.version) for x in sca.discover_deps(d)}
        assert ("Packagist", "monolog/monolog", "2.9.1") in deps
        assert ("RubyGems", "rails", "7.0.4") in deps
        assert ("crates.io", "serde", "1.0.130") in deps


def test_severity_and_fixed_from_osv_vuln():
    vuln = {
        "id": "GHSA-test", "aliases": ["CVE-2021-23337"],
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "lodash"},
                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
    }
    assert sca._severity_of(vuln) == "HIGH"
    assert sca._fixed_versions(vuln, "lodash") == ["4.17.21"]
    # CVSS-only fallback
    cvss = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/.../9.8"}]}
    assert sca._severity_of(cvss) == "CRITICAL"


def _dep(name="a", manifest="package-lock.json"):
    return sca.Dep("npm", name, "1.0.0", manifest)


def _batch_result(ids, token=None):
    result = {"vulns": [{"id": vid} for vid in ids]}
    if token is not None:
        result["next_page_token"] = token
    return result


def _detail(vid, package="a", fixed="1.1.0", alias=None):
    return {
        "id": vid, "aliases": [alias] if alias else [],
        "summary": f"Advisory {vid}", "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": package}, "ranges": [{
            "events": [{"introduced": "0"}, {"fixed": fixed}],
        }]}],
    }


def test_audit_follows_pages_dedupes_ids_and_uses_aliases_and_fixes():
    real_post, real_get = sca._post, sca._get
    posts, gets = [], []

    def fake_post(url, payload):
        posts.append(payload)
        token = payload["queries"][0].get("page_token")
        if token is None:
            return {"results": [_batch_result(["GHSA-1", "GHSA-1"], "page-2")]}
        assert token == "page-2"
        return {"results": [_batch_result(["GHSA-2", "GHSA-1"])]}

    def fake_get(url):
        vid = url.rsplit("/", 1)[-1]
        gets.append(vid)
        if vid == "GHSA-1":
            return _detail(vid, fixed="1.1.0", alias="CVE-2026-1")
        return _detail(vid, fixed="1.2.0", alias="CVE-2026-2")

    try:
        sca._post, sca._get = fake_post, fake_get
        findings, errors = sca.audit_deps([_dep()])
        assert errors == []
        assert len(posts) == 2
        assert posts[1]["queries"][0]["page_token"] == "page-2"
        assert sorted(gets) == ["GHSA-1", "GHSA-2"]
        assert len(findings) == 1
        finding = findings[0]
        assert "2 known vulnerabilities" in finding["title"]
        assert finding["rule_id"] == "CVE-2026-1"
        assert "CVE-2026-1" in finding["evidence"]
        assert "CVE-2026-2" in finding["evidence"]
        assert finding["severity"] == "HIGH"
        assert "1.1.0, 1.2.0 or later" in finding["recommendation"]
    finally:
        sca._post, sca._get = real_post, real_get


def test_audit_retains_results_when_a_later_page_fails():
    real_post, real_get = sca._post, sca._get

    def fake_post(url, payload):
        if payload["queries"][0].get("page_token") == "broken":
            raise urllib.error.URLError("later page boom")
        return {"results": [_batch_result(["GHSA-1"], "broken")]}

    try:
        sca._post = fake_post
        sca._get = lambda url: _detail(url.rsplit("/", 1)[-1])
        findings, errors = sca.audit_deps([_dep()])
        assert len(findings) == 1
        assert "GHSA-1" in findings[0]["evidence"] or "CVE" in findings[0]["evidence"]
        assert "later page failed" in findings[0]["evidence"]
        assert "incomplete" in findings[0]["recommendation"]
        assert any("page 2 failed" in e and "earlier results were retained" in e
                   for e in errors)
    finally:
        sca._post, sca._get = real_post, real_get


def test_audit_retains_successes_when_a_later_batch_fails():
    real_post, real_get = sca._post, sca._get
    deps = [_dep(f"p{i}") for i in range(101)]

    def fake_post(url, payload):
        queries = payload["queries"]
        if len(queries) == 1:
            raise urllib.error.URLError("later chunk boom")
        assert len(queries) == 100
        return {"results": [_batch_result(["GHSA-good"])] + [{} for _ in range(99)]}

    try:
        sca._post = fake_post
        sca._get = lambda url: _detail("GHSA-good", package="p0", fixed="2.0.0")
        findings, errors = sca.audit_deps(deps)
        assert len(findings) == 1 and findings[0]["title"].startswith(
            "Vulnerable dependency: p0@1.0.0")
        assert any("101-101" in e and "retained" in e for e in errors)
    finally:
        sca._post, sca._get = real_post, real_get


def test_audit_marks_failed_missing_and_capped_details():
    real_post, real_get = sca._post, sca._get
    real_cap = sca.MAX_DETAIL_FETCH
    gets = []

    def fake_get(url):
        vid = url.rsplit("/", 1)[-1]
        gets.append(vid)
        if vid == "GHSA-fail":
            raise urllib.error.URLError("detail boom")
        if vid == "GHSA-missing":
            return {}
        return _detail(vid, alias="CVE-2026-good")

    try:
        sca.MAX_DETAIL_FETCH = 3
        sca._post = lambda url, payload: {"results": [_batch_result(
            ["GHSA-good", "GHSA-fail", "GHSA-missing", "GHSA-cap"])]}
        sca._get = fake_get
        findings, errors = sca.audit_deps([_dep()])
        evidence = findings[0]["evidence"]
        assert set(gets) == {"GHSA-good", "GHSA-fail", "GHSA-missing"}
        assert "GHSA-cap" not in gets
        assert "detail failed: GHSA-fail" in evidence
        assert "details missing: GHSA-missing" in evidence
        assert "details not fetched (cap): GHSA-cap" in evidence
        assert "4 known vulnerabilities" in findings[0]["title"]
        assert any("detail failed for GHSA-fail" in e for e in errors)
        assert any("detail missing for GHSA-missing" in e for e in errors)
        assert any("1 advisories not detailed (cap 3): GHSA-cap" in e for e in errors)
    finally:
        sca._post, sca._get = real_post, real_get
        sca.MAX_DETAIL_FETCH = real_cap


def test_audit_bounds_per_dependency_pagination():
    real_post, real_get = sca._post, sca._get
    real_page_cap = sca.MAX_QUERY_PAGES
    posts = []

    def fake_post(url, payload):
        posts.append(payload)
        page = len(posts)
        return {"results": [_batch_result([f"GHSA-{page}"], f"page-{page + 1}")]}

    try:
        sca.MAX_QUERY_PAGES = 2
        sca._post = fake_post
        sca._get = lambda url: _detail(url.rsplit("/", 1)[-1])
        findings, errors = sca.audit_deps([_dep()])
        assert len(posts) == 2
        assert "2 known vulnerabilities" in findings[0]["title"]
        assert "page cap reached" in findings[0]["evidence"]
        assert any("page cap 2 reached" in e for e in errors)
    finally:
        sca._post, sca._get = real_post, real_get
        sca.MAX_QUERY_PAGES = real_page_cap


def test_audit_fetches_unique_details_with_bounded_executor_and_stable_order():
    real_post, real_get = sca._post, sca._get
    real_workers = sca.MAX_DETAIL_WORKERS
    real_executor = sca.concurrent.futures.ThreadPoolExecutor
    gets, worker_counts = [], []

    def recording_executor(*args, **kwargs):
        worker_counts.append(kwargs.get("max_workers", args[0] if args else None))
        return real_executor(*args, **kwargs)

    def fake_post(url, payload):
        return {"results": [
            _batch_result(["GHSA-1", "GHSA-2", "GHSA-1"]),
            _batch_result(["GHSA-2", "GHSA-3"]),
        ]}

    def fake_get(url):
        vid = url.rsplit("/", 1)[-1]
        gets.append(vid)
        return _detail(vid)

    try:
        sca.MAX_DETAIL_WORKERS = 2
        sca.concurrent.futures.ThreadPoolExecutor = recording_executor
        sca._post, sca._get = fake_post, fake_get
        findings, errors = sca.audit_deps([_dep("a", "first"), _dep("b", "second")])
        assert errors == []
        assert worker_counts == [2]
        assert sorted(gets) == ["GHSA-1", "GHSA-2", "GHSA-3"]
        assert len(gets) == len(set(gets))
        assert [f["file"] for f in findings] == ["first", "second"]
        assert "2 known vulnerabilities" in findings[0]["title"]
        assert "2 known vulnerabilities" in findings[1]["title"]
    finally:
        sca._post, sca._get = real_post, real_get
        sca.MAX_DETAIL_WORKERS = real_workers
        sca.concurrent.futures.ThreadPoolExecutor = real_executor


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
