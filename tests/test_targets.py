"""Target parsing — in particular that a URL's query string is preserved, so the
params a user puts in the scan URL actually get tested (regression: they were
dropped, and lab mode reported 'no injectable parameters')."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.targets import parse_target  # noqa: E402


def test_query_string_is_preserved_in_web_url():
    t = parse_target("http://app.test:8080/search?q=x&id=5")
    assert t.path == "/search" and t.query == "q=x&id=5"
    assert t.web_url() == "http://app.test:8080/search?q=x&id=5"


def test_no_query_is_clean():
    t = parse_target("https://example.com/")
    assert t.query == ""
    assert t.web_url() == "https://example.com/"


def test_bare_host_defaults():
    t = parse_target("example.com")
    assert t.host == "example.com" and t.query == "" and t.web_url() == "https://example.com/"


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
