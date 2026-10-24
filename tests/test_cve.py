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
from celsius.models import CVE, Service, Severity  # noqa: E402


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


def test_httpd_suffix_does_not_override_product_vendor():
    assert _prod("Microsoft IIS httpd") == "internet_information_services"
    assert _prod("Microsoft HTTPAPI httpd") is None
    assert _prod("IBM HTTP Server httpd") is None
    assert _prod("Apache httpd (Windows)") == "http_server"
    assert _prod("httpd") == "http_server"

    svc = Service(name="Microsoft HTTPAPI httpd", product="Microsoft HTTPAPI httpd", version="2.0")
    matches, note = cve.lookup_for_service(
        svc, discovery_cache={"apache http server": ([], False)})
    assert matches == []
    assert note and "unknown product" in note


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
        "Gitea": ("gitea", "gitea"),
        "Forgejo": ("forgejo", "forgejo"),
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


def _config_vuln(vendor, product, version="1.25.0"):
    return {"cve": {"configurations": [{"nodes": [{"cpeMatch": [{
        "criteria": f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
        "vulnerable": True,
    }]}]}]}}


def test_nvd_config_requires_vendor_and_product():
    mapping = cve._resolve_mapping("nginx")
    assert mapping is not None
    assert cve._matches_nvd_config(_config_vuln("f5", "nginx"), mapping, "1.25.0") == "firm"
    assert cve._matches_nvd_config(_config_vuln("openresty", "nginx"), mapping, "1.25.0") == ""
    assert cve._matches_nvd_config(_config_vuln("f5", "nginx_plus"), mapping, "1.25.0") == ""


def test_gitea_and_forgejo_match_canonical_nvd_vendors_only():
    cases = (
        ("gitea", "CVE-2022-30781", "1.16.7", "go-gitea", "forgejo"),
        ("forgejo", "CVE-2023-49946", "1.20.5", "codeberg", "gitea"),
    )
    for product, cid, version, old_vendor, other_product in cases:
        mapping = cve._resolve_mapping(product)
        other_mapping = cve._resolve_mapping(other_product)
        assert mapping is not None and other_mapping is not None
        vuln = _config_vuln(product, product, version)
        vuln["cve"]["id"] = cid
        assert cve._matches_nvd_config(vuln, mapping, version) == "firm"
        assert cve._matches_nvd_config(vuln, other_mapping, version) == ""
        wrong_vendor = _config_vuln(old_vendor, product, version)
        wrong_vendor["cve"]["id"] = cid
        assert cve._matches_nvd_config(wrong_vendor, mapping, version) == ""


def _duplicate(cid, confidence, affects, references, *, verified=False,
               severity=Severity.HIGH, cvss=8.0):
    return CVE(id=cid, severity=severity, cvss=cvss, description="d", url="u",
               affects=affects, references=references, confidence=confidence,
               verified=verified)


def test_dedupe_prefers_firm_and_merges_labels_and_exploit_references():
    shared = "https://exploit.test/shared"
    weak = _duplicate("CVE-2026-1", "weak", "nginx 1.0 (port 80/tcp)", [
        {"url": shared, "poc": True, "tags": ["Exploit"]},
        {"url": "https://exploit.test/weak-only", "poc": True},
    ])
    firm = _duplicate("CVE-2026-1", "firm", "nginx 1.0 (port 443/tcp)", [
        {"url": shared, "poc": False},
        {"url": "https://exploit.test/firm-only", "poc": True},
    ])
    other = _duplicate("CVE-2026-2", "firm", "nginx 1.0", [],
                       severity=Severity.MEDIUM, cvss=5.0)
    out = cve._dedupe([weak, other, firm])
    assert [c.id for c in out] == ["CVE-2026-1", "CVE-2026-2"]
    merged = out[0]
    assert merged is firm and merged.confidence == "firm"
    assert merged.affects == "nginx 1.0 (port 443/tcp); nginx 1.0 (port 80/tcp)"
    refs = {r["url"]: r for r in merged.references}
    assert set(refs) == {shared, "https://exploit.test/weak-only",
                         "https://exploit.test/firm-only"}
    assert refs[shared]["poc"] is True
    assert refs[shared]["tags"] == ["Exploit"]


def test_dedupe_firm_base_merges_verified_weak_evidence():
    firm = _duplicate("CVE-2026-1", "firm", "nginx 1.0", [])
    firm.exploitability = {
        "verdict": "likely-exploitable", "priority": 70,
        "signals": {"reachable": None, "epss": 0.2},
        "remediation": {"fixed": "1.2.3"},
    }
    verified = _duplicate("CVE-2026-1", "weak", "nginx 1.0 (port 443/tcp)", [
        {"url": "https://exploit.test/verified", "poc": True},
    ], verified=True)
    verified.exploitability = {
        "verdict": "confirmed-exploitable", "priority": 96,
        "signals": {"reachable": True, "actively_verified": True},
        "verification": {"status": "confirmed", "evidence": "live marker"},
    }
    merged = cve._dedupe([verified, firm])[0]
    assert merged is firm and merged.confidence == "firm"
    assert merged.verified is True
    assert merged.exploitability["verdict"] == "confirmed-exploitable"
    assert merged.exploitability["priority"] == 96
    assert merged.exploitability["signals"]["actively_verified"] is True
    assert merged.exploitability["signals"]["reachable"] is True
    assert merged.exploitability["signals"]["epss"] == 0.2
    assert merged.exploitability["verification"]["status"] == "confirmed"
    assert merged.exploitability["remediation"] == {"fixed": "1.2.3"}
    assert "nginx 1.0" in merged.affects and "port 443/tcp" in merged.affects
    assert merged.references[0]["url"] == "https://exploit.test/verified"


def test_lookup_all_shares_forced_refresh_keyword_cache_within_one_run_only():
    real_search = cve._nvd_search
    calls = []

    def fake_search(keyword, **kwargs):
        calls.append((keyword, kwargs.get("force_refresh")))
        return [], False

    services = [Service(name="nginx", version="1.25.0"),
                Service(name="nginx", version="1.26.0")]
    try:
        cve._nvd_search = fake_search
        cve.lookup_all(services, force_refresh=True)
        assert calls == [("nginx", True)]
        cve.lookup_all(services, force_refresh=True)
        assert calls == [("nginx", True), ("nginx", True)]
    finally:
        cve._nvd_search = real_search


def test_discovery_failure_is_cached_for_the_run():
    real_search = cve._nvd_search
    calls = []

    def fake_search(keyword, **kwargs):
        calls.append(keyword)
        return None, False

    try:
        cve._nvd_search = fake_search
        shared = {}
        first = cve.lookup_for_service(
            Service(name="nginx", version="1.25.0"), force_refresh=True,
            discovery_cache=shared)
        second = cve.lookup_for_service(
            Service(name="nginx", version="1.26.0"), force_refresh=True,
            discovery_cache=shared)
        assert calls == ["nginx"]
        assert first[0] == second[0] == []
        assert "NVD request failed" in first[1]
        assert "NVD request failed" in second[1]
    finally:
        cve._nvd_search = real_search


def test_cna_candidates_are_newest_first_before_cap():
    real_search = cve._nvd_search
    real_matches = cve._matches_cna
    vulns = [
        {"cve": {"id": "CVE-2024-1", "published": "2024-01-01T00:00:00Z"}},
        {"cve": {"id": "CVE-2026-1", "published": "2026-01-01T00:00:00Z"}},
        {"cve": {"id": "CVE-2025-1", "published": "2025-01-01T00:00:00+00:00"}},
        {"cve": {"id": "CVE-invalid", "published": "not-a-timestamp"}},
    ]
    checked = []

    def fake_search(keyword, **kwargs):
        return list(vulns), False

    def fake_matches(cid, version, mapping):
        checked.append(cid)
        return True

    try:
        cve._nvd_search = fake_search
        cve._matches_cna = fake_matches
        found, note = cve.lookup_for_service(
            Service(name="nginx", version="1.25.0"), max_cna_fetch=2)
        assert [c.id for c in found] == ["CVE-2026-1", "CVE-2025-1"]
        assert set(checked) == {"CVE-2026-1", "CVE-2025-1"}
        assert "checked newest 2" in note
    finally:
        cve._nvd_search = real_search
        cve._matches_cna = real_matches


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
