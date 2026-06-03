"""Offline tests for Wayback (archive.org) URL harvesting."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import wayback as W  # noqa: E402


def _patch(urls):
    W._cdx = lambda host: (urls, [])


def _titles(findings):
    return " || ".join(f.title for f in findings)


def test_extracts_params_and_flags_sensitive():
    _patch([
        "https://x.test/index.php?id=1",
        "https://x.test/download?file=report.pdf&debug=1",
        "https://x.test/admin/panel",
        "https://x.test/db/backup.sql",
        "https://x.test/style.css?v=2",   # 'v' is not an interesting param
    ])
    findings, urls, params, _ = W.harvest("x.test")
    assert "id" in params and "file" in params and "debug" in params
    assert "v" not in params                    # noise filtered out
    assert any("sensitive files" in t for t in [f.title for f in findings])  # backup.sql
    assert len(urls) == 5
    # interesting path /admin flagged in the summary finding
    assert "interesting path" in _titles(findings)


def test_empty_archive_is_quiet():
    _patch([])
    findings, urls, params, _ = W.harvest("x.test")
    assert findings == [] and urls == [] and params == []


def test_no_juicy_params_still_reports_urls():
    _patch(["https://x.test/a", "https://x.test/b/c"])
    findings, urls, params, _ = W.harvest("x.test")
    assert params == []
    assert any("historical URL" in f.title for f in findings)


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
