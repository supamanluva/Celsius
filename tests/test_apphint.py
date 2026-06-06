"""Hostname->app hints fill the gap when a service is auth-gated/down, and the
SSO / self-hosted fingerprints (Authelia, MinIO, …) identify the gate itself."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import apphint  # noqa: E402
from celsius.recon import fingerprint as fp  # noqa: E402


def test_hint_from_hostname_matches_convention():
    assert apphint.hint_from_hostname("cloud.gotlandia.net") == "Nextcloud"
    assert apphint.hint_from_hostname("s3.example.com").startswith("MinIO")
    assert apphint.hint_from_hostname("ZNC.example.com") == "ZNC (IRC bouncer)"  # case-insensitive
    assert "Authelia" in apphint.hint_from_hostname("auth.example.com")


def test_hint_none_for_unknown_label():
    assert apphint.hint_from_hostname("totallyrandom.example.com") is None
    assert apphint.hint_from_hostname("") is None


def test_fingerprint_detects_authelia_gate():
    techs, _, _, _ = fp.fingerprint(
        {"set-cookie": "authelia_session=abc; Secure"}, "<title>Login - Authelia</title>")
    assert any(t.name == "Authelia" and t.category == "auth" for t in techs)


def test_fingerprint_detects_selfhosted_apps():
    techs, _, _, _ = fp.fingerprint({"server": "MinIO"}, "")
    assert any(t.name == "MinIO" for t in techs)
    techs, _, _, _ = fp.fingerprint({}, "<title>Uptime Kuma</title>")
    assert any(t.name == "Uptime Kuma" for t in techs)


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
