"""High-entropy values that are PUBLIC by design (VAPID public push key, public
keys, Next.js buildId, CSP nonce) must not be reported as exposed secrets — but
real apiKey/token/secret values still must."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import secrets  # noqa: E402

_TOK = "ZkR9vQ2xL7pN4wT8mB1cF6yH3jK0sD5aG8eU2iO7nP4qX9rW6tY1zV3bM5kC0lJhTdY"  # high entropy


def _flagged(text):
    return bool(secrets.scan_text(text))


def test_public_by_design_keys_skipped():
    for key in ("vapidPublic", "vapidPublicKey", "publicKey", "public_key",
                "buildId", "nonce", "contentHash", "revision", "csrfToken"):
        assert not _flagged(f'{{"{key}":"{_TOK}"}}'), key


def test_unquoted_minified_js_keys_skipped():
    # minified JS bundles carry these as unquoted object keys / assignments
    assert not _flagged(f'a={{vapidPublic:"{_TOK}",b:1}}')
    assert not _flagged(f'window.__d.buildId="{_TOK}";')


def test_real_secrets_still_flagged():
    for key in ("apiKey", "token", "secret", "password", "client_secret"):
        assert _flagged(f'{{"{key}":"{_TOK}"}}'), key


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
