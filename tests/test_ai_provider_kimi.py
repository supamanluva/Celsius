"""Tests for the Kimi (Moonshot) AI provider: registration, env-key fallback,
request shape, and base-url safety validation. No network."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.ai import provider as prov  # noqa: E402


def _clean_env():
    for k in ("KIMI_API_KEY", "MOONSHOT_API_KEY"):
        os.environ.pop(k, None)


def test_kimi_registered_with_defaults():
    assert "kimi" in prov.available_providers()
    p = prov.get_provider("kimi", api_key="sk-test")
    assert p.name == "kimi"
    assert p.model == "kimi-k2-0711-preview"
    assert p.base_url == "https://api.moonshot.ai/v1"


def test_kimi_env_key_fallback_order():
    _clean_env()
    try:
        os.environ["MOONSHOT_API_KEY"] = "sk-moon"
        assert prov.get_provider("kimi").api_key == "sk-moon"
        os.environ["KIMI_API_KEY"] = "sk-kimi"
        assert prov.get_provider("kimi").api_key == "sk-kimi"  # primary wins
    finally:
        _clean_env()


def test_kimi_unavailable_without_key():
    _clean_env()
    ok, why = prov.get_provider("kimi").available()
    assert not ok
    assert "KIMI_API_KEY" in why


def test_empty_primary_env_var_falls_back_to_moonshot():
    """A set-but-empty KIMI_API_KEY must not block the MOONSHOT_API_KEY fallback."""
    _clean_env()
    try:
        os.environ["KIMI_API_KEY"] = ""
        os.environ["MOONSHOT_API_KEY"] = "sk-moon"
        assert prov.get_provider("kimi").api_key == "sk-moon"
    finally:
        _clean_env()


def test_whitespace_primary_env_var_counts_as_unset():
    _clean_env()
    try:
        os.environ["KIMI_API_KEY"] = "  "
        ok, _why = prov.get_provider("kimi").available()
        assert not ok
    finally:
        _clean_env()


def test_kimi_openai_compat_request_shape():
    calls = {}

    def fake_post(url, payload, headers, timeout):
        calls.update(url=url, payload=payload, headers=headers)
        return {"choices": [{"message": {"content": "{}"}}]}

    orig = prov._post_json
    prov._post_json = fake_post
    try:
        p = prov.get_provider("kimi", api_key="sk-test")
        out = p.complete([prov.Message("user", "hi")], json_mode=True)
    finally:
        prov._post_json = orig
    assert out == "{}"
    assert calls["url"] == "https://api.moonshot.ai/v1/chat/completions"
    assert calls["headers"]["Authorization"] == "Bearer sk-test"
    assert calls["payload"]["model"] == "kimi-k2-0711-preview"
    assert calls["payload"]["response_format"] == {"type": "json_object"}


def test_kimi_plain_http_base_url_rejected():
    try:
        prov.get_provider("kimi", api_key="sk", base_url="http://evil.example.com/v1")
        raise AssertionError("expected AIError for plain-http non-local base_url")
    except prov.AIError:
        pass


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
    sys.exit(1 if failed else 0)
