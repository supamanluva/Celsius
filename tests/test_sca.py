"""Offline tests for SCA manifest parsing and OSV result handling.

The live OSV.dev query is not exercised here (network-dependent); these cover the
parsers, version cleaning, severity mapping and fixed-version extraction.
"""

from __future__ import annotations

import os
import sys
import tempfile

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
