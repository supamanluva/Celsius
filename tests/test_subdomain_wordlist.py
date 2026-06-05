"""The brute-force wordlist must cover self-hosted app subdomains (request, radarr,
…) — those sit under wildcard certs and are invisible to crt.sh, so DNS
brute-force is the only way to catch them."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import subdomains as subs  # noqa: E402


def test_self_hosted_names_present():
    for w in ("request", "overseerr", "radarr", "sonarr", "vikunja", "immich",
              "vaultwarden", "jellyfin", "nextcloud"):
        assert w in subs.DEFAULT_WORDLIST, w


def test_corporate_names_still_present():
    for w in ("www", "admin", "api", "vpn", "mail"):
        assert w in subs.DEFAULT_WORDLIST, w


def test_default_wordlist_is_union_and_deduped():
    assert set(subs.DEFAULT_WORDLIST) == set(subs.COMMON) | set(subs.SELF_HOSTED)
    assert len(subs.DEFAULT_WORDLIST) == len(set(subs.DEFAULT_WORDLIST))


def test_resolve_wordlist_defaults_to_combined():
    import inspect
    assert inspect.signature(subs.resolve_wordlist).parameters["words"].default is subs.DEFAULT_WORDLIST


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
