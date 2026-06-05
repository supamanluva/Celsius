"""App-version probe: pull a version from a status/health body via JSON field or
regex, and don't false-positive on a generic 200."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import appversion as av  # noqa: E402

_VW = next(p for p in av.PROBES if p[0] == "Vaultwarden")[3]


def test_json_field_and_nested():
    assert av.extract_version('{"version":"3.3.0","commitTag":"3.3.0"}', "version", None) == "3.3.0"
    assert av.extract_version('{"data":{"version":"2.50.1"}}', "data.version", None) == "2.50.1"


def test_regex_plex_and_immich():
    assert av.extract_version('<MediaContainer version="1.32.5.7349">', None,
                              r'\bversion="([^"]+)"') == "1.32.5.7349"
    assert av.extract_version('{"major":1,"minor":95,"patch":1}', None,
                              r'"major":\s*(\d+).*?"minor":\s*(\d+).*?"patch":\s*(\d+)') == "1.95.1"


def test_vaultwarden_strict_whole_body():
    assert av.extract_version('"1.30.1"', None, _VW) == "1.30.1"        # the whole body IS the version
    assert av.extract_version('<html>build 5.343.371 x</html>', None, _VW) is None  # generic page -> no FP


def test_no_version_returns_none():
    assert av.extract_version('{"status":"ok"}', "version", None) is None
    assert av.extract_version("not json", "version", None) is None


def test_probes_well_formed():
    for app, path, field, regex in av.PROBES:
        assert app and path.startswith("/")
        assert field or regex


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
