"""Offline tests for client-side library detection (no OSV/network).

Detects known JS libraries + versions from CDN URLs, versioned filenames and
script-body banners, mapping to OSV npm names; ignores non-library bundle names.

Stdlib-only: run directly (`python tests/test_clientsca.py`) or under pytest.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import clientsca  # noqa: E402


def _libs(urls=None, sources=None, pages=None):
    deps = clientsca.detect_libraries(set(urls or []), sources or {}, pages=pages or {})
    return sorted({(d.name, d.version) for d in deps})


def test_jsdelivr_unpkg_npm_paths():
    assert _libs(["https://cdn.jsdelivr.net/npm/jquery@1.12.4/dist/jquery.min.js"]) == [("jquery", "1.12.4")]
    assert _libs(["https://unpkg.com/vue@2.6.14/dist/vue.min.js"]) == [("vue", "2.6.14")]


def test_cdnjs_and_bootstrapcdn_and_filename():
    assert ("lodash", "4.17.10") in _libs(
        ["https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.10/lodash.min.js"])
    assert ("bootstrap", "3.4.1") in _libs(
        ["https://stackpath.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"])
    assert ("jquery", "3.5.1") in _libs(["https://code.jquery.com/jquery-3.5.1.min.js"])


def test_body_banner_detection():
    assert ("jquery", "1.12.4") in _libs(sources={"a": "/*! jQuery JavaScript Library v1.12.4 */"})
    assert ("bootstrap", "4.6.0") in _libs(sources={"b": "Bootstrap v4.6.0 (https://getbootstrap.com/)"})


def test_ignores_non_library_bundles():
    # app bundle names and unrelated versioned paths must not be reported
    got = _libs(["https://example.com/static/app-2.1.0.js",
                 "https://site/api/v2/1.2.3/data.js",
                 "https://site/main.bundle.js"])
    assert got == []


def test_maps_to_npm_names():
    # alternate CDN names normalise to the canonical npm package
    assert ("angular", "1.8.2") in _libs(
        ["https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js"])


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
