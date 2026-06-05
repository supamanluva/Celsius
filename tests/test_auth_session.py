"""The shared auth.build_session() — used by both the CLI and the web UI — turns
cookie/bearer/header inputs into an AuthSession (form login needs network, not
covered here)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import auth  # noqa: E402


def test_cookie():
    s = auth.build_session(cookie="session=abc; csrf=xyz")
    assert s and s.headers["Cookie"] == "session=abc; csrf=xyz"
    assert "cookie" in s.source


def test_bearer():
    s = auth.build_session(bearer="tok123")
    assert s.headers["Authorization"] == "Bearer tok123"


def test_extra_headers():
    s = auth.build_session(headers=["X-Api-Key: k3y", "X-Env: staging"])
    assert s.headers.get("X-Api-Key") == "k3y" and s.headers.get("X-Env") == "staging"


def test_combined_cookie_and_bearer():
    s = auth.build_session(cookie="a=b", bearer="t")
    assert s.headers["Cookie"] == "a=b" and s.headers["Authorization"] == "Bearer t"


def test_nothing_supplied_is_none():
    assert auth.build_session() is None


def test_log_callback_invoked():
    msgs = []
    auth.build_session(cookie="a=b", log=msgs.append)
    assert any("auth:" in m for m in msgs)


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
