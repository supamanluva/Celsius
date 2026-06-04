"""Tests for crawler politeness: Retry-After parsing + 429/503 backoff-retry.

No real network or sleeps — urlopen and time.sleep are monkeypatched.
Stdlib-only: run directly (`python tests/test_crawler.py`) or under pytest.
"""

from __future__ import annotations

import email.message
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import crawler  # noqa: E402


def _http_error(code, retry_after=None):
    hdrs = email.message.Message()
    if retry_after is not None:
        hdrs["Retry-After"] = str(retry_after)
    return urllib.error.HTTPError("http://t/", code, "err", hdrs, None)


class _Resp:
    status = 200

    def __enter__(self): return self
    def __exit__(self, *a): return False
    headers = email.message.Message()
    def read(self, *a): return b"<html>ok</html>"
    def geturl(self): return "http://t/"


def _patch(monkeypatch_calls, urlopen):
    crawler.urllib.request.urlopen = urlopen
    crawler.time.sleep = lambda s: monkeypatch_calls.append(s)


def test_retry_after_parsing():
    assert crawler._retry_after_seconds("3", 1.0) == 3.0
    assert crawler._retry_after_seconds("", 1.5) == 1.5
    assert crawler._retry_after_seconds(None, 2.0) == 2.0
    assert crawler._retry_after_seconds("Wed, 21 Oct", 2.0) == 2.0     # date form -> fallback
    assert crawler._retry_after_seconds("9999", 1.0) == crawler._MAX_BACKOFF  # capped


def test_retries_then_succeeds_on_429():
    real_urlopen, real_sleep = urllib.request.urlopen, crawler.time.sleep
    try:
        calls = {"n": 0}
        slept = []
        def fake(req, **kw):
            calls["n"] += 1
            if calls["n"] <= 2:
                raise _http_error(429, retry_after=1)
            return _Resp()
        _patch(slept, fake)
        status, body, _ = crawler._fetch("http://t/", False, retries=2)
        assert status == 200 and "ok" in body
        assert calls["n"] == 3            # 2 failures + 1 success
        assert slept == [1.0, 1.0]        # backed off before each retry
    finally:
        urllib.request.urlopen, crawler.time.sleep = real_urlopen, real_sleep


def test_non_retryable_raises_immediately():
    real_urlopen, real_sleep = urllib.request.urlopen, crawler.time.sleep
    try:
        calls = {"n": 0}
        def fake(req, **kw):
            calls["n"] += 1
            raise _http_error(404)
        _patch([], fake)
        raised = False
        try:
            crawler._fetch("http://t/", False, retries=2)
        except urllib.error.HTTPError as e:
            raised = (e.code == 404)
        assert raised and calls["n"] == 1   # no retry on 404
    finally:
        urllib.request.urlopen, crawler.time.sleep = real_urlopen, real_sleep


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
