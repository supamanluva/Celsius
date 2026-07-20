"""Offline tests for CVE product-name resolution + NVD pagination (no network).

Regression anchor: nmap reports service names with decorations — "ISC BIND",
"Exim smtpd", "Dovecot imapd" — which missed the exact _PRODUCT_MAP keys, so CVE
lookup was silently skipped for versioned services that have real CVEs. The
resolver must map these to their canonical product without false matches. The
second anchor: NVD caps resultsPerPage at 2000, so high-volume keywords (php,
mysql) silently dropped CVEs until startIndex pagination was added.

Stdlib-only: run directly (`python tests/test_cve.py`) or under pytest.
"""

from __future__ import annotations

import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import cve  # noqa: E402
from celsius.models import Service  # noqa: E402


def _prod(name):
    m = cve._resolve_mapping(name)
    return m.product if m else None


def test_resolves_nmap_decorated_names():
    assert _prod("ISC BIND") == "bind"
    assert _prod("Exim smtpd") == "exim"
    assert _prod("Dovecot imapd") == "dovecot"
    assert _prod("Dovecot DirectAdmin pop3d") == "dovecot"
    assert _prod("Pure-FTPd") == "pure-ftpd"


def test_exact_names_still_resolve():
    assert _prod("nginx") == "nginx"
    assert _prod("Apache httpd") == "http_server"
    assert _prod("OpenSSH") == "openssh"


def test_no_false_substring_match():
    # "bind" must match only as a whole token, not inside another word
    assert _prod("rebind-helper") is None
    assert _prod("something-else") is None
    assert _prod("") is None


def test_cms_and_selfhosted_mappings():
    # Products detected by recon/fingerprint.py and recon/appversion.py must map
    # to their canonical NVD CPE vendor/product (not fall through to "unknown").
    expected = {
        "WordPress": ("wordpress", "wordpress"),
        "Drupal": ("drupal", "drupal"),
        "Joomla": ("joomla", "joomla\\!"),  # NVD escapes "!": joomla:joomla\!
        "Ghost": ("tryghost", "ghost"),
        "Grafana": ("grafana", "grafana"),
        "Nextcloud": ("nextcloud", "nextcloud_server"),
        "ownCloud": ("owncloud", "owncloud"),
        "Vaultwarden": ("vaultwarden", "vaultwarden"),  # no NVD CPE: keyword only
        "Immich": ("immich", "immich"),
        "Plex": ("plex", "plex_media_server"),
        "phpMyAdmin": ("phpmyadmin", "phpmyadmin"),
        "Roundcube": ("roundcube", "webmail"),
        "Keycloak": ("keycloak", "keycloak"),
        "MinIO": ("minio", "minio"),
        "Prometheus": ("prometheus", "prometheus"),
        "GitLab": ("gitlab", "gitlab"),
        "Home Assistant": ("home-assistant", "home-assistant"),
        "Mastodon": ("joinmastodon", "mastodon"),
    }
    for name, (vendor, product) in expected.items():
        m = cve._resolve_mapping(name)
        assert m is not None, f"{name}: no mapping"
        assert (m.vendor, m.product) == (vendor, product), \
            f"{name}: got {m.vendor}:{m.product}"


def test_appversion_probe_names_resolve():
    # appversion.py PROBES use composite names like "Gitea/Forgejo" — the
    # single-word token fallback must resolve them.
    m = cve._resolve_mapping("Gitea/Forgejo")
    assert m is not None and m.product == "gitea"
    m = cve._resolve_mapping("Jellyfin/Emby")
    assert m is not None and m.product == "jellyfin"
    m = cve._resolve_mapping("Matrix/Synapse")
    assert m is not None and m.product == "synapse"
    m = cve._resolve_mapping("Overseerr/Jellyseerr")
    assert m is not None and m.product == "overseerr"
    assert _prod("Uptime Kuma") == "uptime_kuma"
    assert _prod("Audiobookshelf") == "audiobookshelf"


def _fake_nvd(total, per_page=cve.NVD_PAGE_SIZE):
    """A fake NVD keyword-search endpoint honouring startIndex/resultsPerPage."""
    calls = []

    def fake_get_json(url, *, api_key=None, retries=3, force_refresh=False):
        calls.append(url)
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        start = int(q.get("startIndex", "0"))
        per = int(q.get("resultsPerPage", str(per_page)))
        vulns = [{"cve": {"id": f"CVE-2024-{i}"}}
                 for i in range(start, min(start + per, total))]
        return {"totalResults": total, "vulnerabilities": vulns}

    return fake_get_json, calls


def _silence_sleep():
    cve.time.sleep = lambda *_a, **_k: None


def test_nvd_search_paginates_until_total():
    fake, calls = _fake_nvd(4500)
    cve._get_json = fake
    _silence_sleep()
    vulns, truncated = cve._nvd_search("php")
    assert len(vulns) == 4500                    # 2000 + 2000 + 500
    assert truncated is False
    assert len(calls) == 3
    # startIndex advances by accumulated results
    starts = [dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(u).query))["startIndex"]
              for u in calls]
    assert starts == ["0", "2000", "4000"]


def test_nvd_search_caps_at_max_results():
    fake, calls = _fake_nvd(50_000)
    cve._get_json = fake
    _silence_sleep()
    vulns, truncated = cve._nvd_search("mysql")
    assert len(vulns) == cve.NVD_MAX_RESULTS
    assert truncated is True
    assert len(calls) == cve.NVD_MAX_RESULTS // cve.NVD_PAGE_SIZE


def test_nvd_search_first_page_failure_returns_none():
    cve._get_json = lambda *a, **k: None
    _silence_sleep()
    vulns, truncated = cve._nvd_search("php")
    assert vulns is None and truncated is False


def test_nvd_search_late_failure_keeps_partial_and_flags_truncated():
    real, _ = _fake_nvd(5000)
    state = {"n": 0}

    def flaky(url, **kw):
        state["n"] += 1
        return real(url, **kw) if state["n"] < 3 else None

    cve._get_json = flaky
    _silence_sleep()
    vulns, truncated = cve._nvd_search("php")
    assert vulns is not None and len(vulns) == 4000  # two full pages, third failed
    assert truncated is True


def test_lookup_for_service_reports_truncation():
    fake, _ = _fake_nvd(50_000)
    cve._get_json = fake
    _silence_sleep()
    svc = Service(name="PHP", version="8.1.0")
    _cves, note = cve.lookup_for_service(svc)
    assert note is not None
    assert str(cve.NVD_MAX_RESULTS) in note and "evaluated" in note


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
