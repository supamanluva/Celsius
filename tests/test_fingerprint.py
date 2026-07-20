"""Tests for the signature-based technology fingerprinter.

Pure unit tests: fingerprint() takes headers + body dicts directly, so no
network mocking is needed. Covers the framework/CMS/admin-panel signatures
(Laravel, Django, Rails, Spring Boot, phpMyAdmin, Roundcube, TYPO3, Magento,
PrestaShop, Strapi, Prometheus, Alertmanager, Kibana, Jenkins) and the Drupal
version -> EOL finding chain. Stdlib-only: run directly
(`python tests/test_fingerprint.py`) or under pytest.
"""

from __future__ import annotations

import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import eol  # noqa: E402
from celsius.recon import fingerprint as fp  # noqa: E402

REF = date(2026, 6, 1)  # fixed "today" for deterministic EOL assertions


def _detect(headers=None, body=""):
    techs, services, findings, _platform = fp.fingerprint(headers or {}, body)
    return {t.name: t for t in techs}, services, findings


def test_laravel_cookie_and_powered_by():
    techs, _svc, _f = _detect({"set-cookie": "laravel_session=abc123; HttpOnly"})
    assert "Laravel" in techs
    techs, _svc, _f = _detect({"x-powered-by": "Laravel"})
    assert "Laravel" in techs


def test_django_csrftoken():
    techs, _svc, _f = _detect({"set-cookie": "csrftoken=xyz; Path=/"})
    assert "Django" in techs


def test_rails_cookie_and_x_runtime():
    techs, _svc, _f = _detect({"set-cookie": "_myapp_session_id=abc; HttpOnly"})
    assert "Ruby on Rails" in techs
    techs, _svc, _f = _detect({"x-runtime": "0.0123", "x-request-id": "req-1"})
    assert "Ruby on Rails" in techs


def test_spring_boot_header_and_whitelabel():
    techs, _svc, _f = _detect({"x-application-context": "shop:prod:8080"})
    assert "Spring Boot" in techs
    techs, _svc, _f = _detect({}, "<html><body>Whitelabel Error Page</body></html>")
    assert "Spring Boot" in techs


def test_phpmyadmin_cookie_and_title():
    techs, _svc, _f = _detect({"set-cookie": "phpMyAdmin=token; HttpOnly"})
    assert "phpMyAdmin" in techs
    techs, _svc, _f = _detect({}, "<html><head><title>phpMyAdmin</title></head>")
    assert "phpMyAdmin" in techs


def test_roundcube_cookie():
    techs, _svc, _f = _detect({"set-cookie": "roundcube_sessid=deadbeef; HttpOnly"})
    assert "Roundcube" in techs


def test_typo3_body():
    techs, _svc, _f = _detect({}, '<link rel="stylesheet" href="/typo3conf/ext/site/style.css">')
    assert "TYPO3" in techs


def test_magento_header_and_body():
    techs, _svc, _f = _detect({"x-magento-cache-debug": "MISS"})
    assert "Magento" in techs
    techs, _svc, _f = _detect({}, "<script>Mage.Cookies.path = '/';</script>")
    assert "Magento" in techs


def test_prestashop_cookie_and_body():
    techs, _svc, _f = _detect({"set-cookie": "PrestaShop-a1b2c3d4=abc; path=/"})
    assert "PrestaShop" in techs
    techs, _svc, _f = _detect({}, "<html><body>Powered by PrestaShop</body></html>")
    assert "PrestaShop" in techs


def test_strapi_powered_by():
    techs, _svc, _f = _detect({"x-powered-by": "Strapi <strapi.io>"})
    assert "Strapi" in techs


def test_monitoring_panels_by_title():
    for name in ("Prometheus", "Alertmanager"):
        techs, _svc, _f = _detect({}, f"<html><head><title>{name} Time Series</title></head>")
        assert name in techs, f"{name} not detected"


def test_kibana_version_from_header():
    techs, _svc, _f = _detect({"kbn-name": "kibana", "kbn-version": "7.17.0"})
    assert "Kibana" in techs
    assert techs["Kibana"].version == "7.17.0"


def test_jenkins_version_from_header():
    techs, _svc, _f = _detect({"x-jenkins": "2.401.1", "x-hudson": "1.395"})
    assert "Jenkins" in techs
    assert techs["Jenkins"].version == "2.401.1"


def test_drupal_x_generator_version_and_eol():
    techs, services, findings = _detect({"x-generator": "Drupal 7 (https://www.drupal.org)"})
    assert "Drupal" in techs
    assert techs["Drupal"].version == "7"
    # versioned CMS -> CVE service entry + EOL finding (Drupal 7 EOL 2025-01-05)
    assert any(s.name == "Drupal" and s.version == "7" for s in services)
    assert any(f.category == "eol" and "Drupal 7" in f.title for f in findings)


def test_drupal_body_sites_default():
    techs, _svc, _f = _detect({}, '<img src="/sites/default/files/logo.png">')
    assert "Drupal" in techs


def test_drupal_eol_table():
    assert eol.check_eol("Drupal", "7.100", today=REF)["status"] == "eol"
    assert eol.check_eol("Drupal", "8.9.20", today=REF)["status"] == "eol"
    assert eol.check_eol("Drupal", "9.5.0", today=REF)["status"] == "eol"
    assert eol.check_eol("Drupal", "10.2.5", today=REF) is None
    assert eol.check_eol("Drupal", "11.0.0", today=REF) is None


def test_express_still_detected():
    techs, _svc, _f = _detect({"x-powered-by": "Express"})
    assert "Express" in techs


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
