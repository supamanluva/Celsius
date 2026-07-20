"""Offline tests for CLI argparse ergonomics: profiles, --full, help layout."""

from __future__ import annotations

import contextlib
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import cli  # noqa: E402


def _parse(*argv):
    return cli.build_parser().parse_args(["scan", "example.com", *argv])


def test_profile_quick_minimal():
    args = _parse("--profile", "quick")
    cli._apply_profile(args)
    # quick trims the passive extras down to headers/TLS/CVEs
    assert args.no_secrets and args.no_robots and args.no_favicon
    assert args.no_fingerprint and args.no_cve_pocs
    assert args.no_exploitability and args.no_diff
    # and turns nothing extra on
    assert args.subdomains is False and args.crawl is False and args.ports is False


def test_profile_standard():
    args = _parse("--profile", "standard")
    cli._apply_profile(args)
    assert args.subdomains is True and args.crawl is True
    assert args.content_discovery is True
    # ...but not the heavier active/long-running checks
    assert args.ports is False and args.nuclei is False and args.wayback is False
    assert args.no_secrets is False  # everyday defaults untouched


def test_profile_deep_is_full_minus_root():
    args = _parse("--profile", "deep")
    cli._apply_profile(args)
    for attr in ("ports", "nuclei", "subdomains", "wayback", "crawl",
                 "api_discovery", "content_discovery", "mail", "cve_verify"):
        assert getattr(args, attr) is True, attr
    assert not args.os_detect  # root-requiring check stays out of the bundle


def test_no_profile_keeps_defaults():
    args = _parse()
    cli._apply_profile(args)
    assert args.subdomains is False and args.crawl is False and args.mail is False
    assert args.no_secrets is False and args.no_diff is False


def test_explicit_flag_beats_profile():
    # quick would never turn crawl on — an explicit --crawl must survive
    args = _parse("--profile", "quick", "--crawl")
    cli._apply_profile(args)
    assert args.crawl is True
    args = _parse("--profile", "standard", "--nuclei")
    cli._apply_profile(args)
    assert args.nuclei is True


def test_full_non_root_warns_and_skips_os_detect():
    args = _parse("--full")
    msgs: list[str] = []
    real = os.geteuid
    os.geteuid = lambda: 1000  # type: ignore[assignment]
    try:
        cli._apply_full(args, warn=msgs.append)
    finally:
        os.geteuid = real  # type: ignore[assignment]
    assert args.os_detect is False
    assert any("root" in m for m in msgs)
    # the rest of the battery is still enabled
    assert args.ports and args.nuclei and args.crawl and args.mail


def test_full_root_enables_os_detect():
    args = _parse("--full")
    real = os.geteuid
    os.geteuid = lambda: 0  # type: ignore[assignment]
    try:
        cli._apply_full(args, warn=lambda _m: None)
    finally:
        os.geteuid = real  # type: ignore[assignment]
    assert args.os_detect is True


def test_full_respects_explicit_os_detect():
    # explicitly requested --os-detect is left alone even without root
    args = _parse("--full", "--os-detect")
    real = os.geteuid
    os.geteuid = lambda: 1000  # type: ignore[assignment]
    try:
        cli._apply_full(args, warn=lambda _m: None)
    finally:
        os.geteuid = real  # type: ignore[assignment]
    assert args.os_detect is True


def test_scan_help_groups_and_epilog():
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            cli.main(["scan", "--help"])
    except SystemExit:
        pass
    out = buf.getvalue()
    for group in ("scan profiles", "recon (passive)", "discovery",
                  "active scanning", "lab mode", "AI", "output", "general"):
        assert group in out, group
    assert "examples:" in out and "--profile deep" in out
    assert "testsites" in out  # points at the curated legal practice targets


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
