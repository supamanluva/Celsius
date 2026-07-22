#!/usr/bin/env python3
"""Dev-only UI smoke check: load the app, exercise the main tabs, fail on any
console error. Usage: .venv/bin/python scripts/ui_smoke.py [base_url] [--shot prefix]

Requires the `dynamic` extra (playwright) plus a Chromium build
(`playwright install chromium`). Dev-only — NOT part of CI.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _server_up(base: str) -> bool:
    try:
        with urllib.request.urlopen(base + "/api/scans?limit=1", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Dev-only Celsius UI smoke check (playwright).")
    ap.add_argument("base_url", nargs="?", default="http://127.0.0.1:8000")
    ap.add_argument("--shot", metavar="PREFIX", default=None,
                    help="save screenshots as PREFIX-light.png, PREFIX-dark.png, PREFIX-<tab>-dark.png")
    args = ap.parse_args()
    base = args.base_url.rstrip("/")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ui_smoke needs the dynamic extra: install playwright and run "
              "`playwright install chromium` first.", file=sys.stderr)
        return 1

    # Reuse a running server, or start one ourselves on the requested host:port.
    server = None
    if not _server_up(base):
        u = urllib.parse.urlparse(base)
        host = u.hostname or "127.0.0.1"
        port = u.port or 8000
        print(f"[*] no server on {base} — starting `celsius serve --host {host} --port {port}`")
        server = subprocess.Popen(
            [sys.executable, "-m", "celsius", "serve", "--host", host, "--port", str(port)],
            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            if _server_up(base):
                break
            if server.poll() is not None:
                print("[!] server process exited during startup", file=sys.stderr)
                return 1
            time.sleep(0.5)
        else:
            print("[!] server did not come up within 30s", file=sys.stderr)
            server.terminate()
            return 1

    errors: list[str] = []
    failures: list[str] = []

    def check(cond: bool, msg: str) -> None:
        if not cond:
            failures.append(msg)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            page.on("console", lambda m: errors.append(f"console.error: {m.text}")
                    if m.type == "error" else None)
            page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))

            scan_posts: list[str] = []

            def on_request(req) -> None:
                if req.method == "POST" and urllib.parse.urlparse(req.url).path == "/api/scan":
                    scan_posts.append(req.url)

            page.on("request", on_request)
            page.goto(base + "/", wait_until="networkidle")

            # ── dashboard is the default landing view and renders (Task 3) ──
            dash_tab = page.locator('.tab[data-tab="dashboard"]')
            check(dash_tab.count() == 1, "dashboard tab button missing")
            check("active" in (dash_tab.get_attribute("class") or ""),
                  "dashboard tab is not the default active tab")
            check(page.locator("#tab-dashboard").is_visible(),
                  "dashboard panel not visible on load")
            try:
                page.wait_for_selector("#dashHero .hero, #dashHero .dash-empty",
                                       timeout=8000)
            except Exception:
                pass
            check((page.locator("#dashHero").inner_html() or "").strip() != "",
                  "#dashHero is empty — neither hero nor empty state rendered")
            check(page.locator("#dashHero .hero, #dashHero .dash-empty").count() == 1,
                  "#dashHero shows neither the hero nor the empty state")

            # ── switch to the host tab for the scan-form checks below ──
            page.locator('.tab[data-tab="host"]').click()
            page.wait_for_timeout(200)

            # ── authorization gate: submitting without the checkbox must NOT scan ──
            check(not page.locator("#authorized").is_checked(),
                  "#authorized should start unchecked")
            page.fill("#target", "https://example.com")
            page.click("#scanBtn")
            page.wait_for_timeout(700)
            check(not scan_posts, "POST /api/scan fired without authorization — gate broken")
            check(page.locator(".toast.toast-error").count() >= 1,
                  "no error toast shown for an unauthorized submit")
            check(page.locator("#authbar.attention").count() == 1,
                  "authbar did not get .attention after an unauthorized submit")

            # …and after checking the box the gate opens (empty target still no-ops).
            page.check("#authorized")
            page.wait_for_timeout(200)
            check("ok" in (page.locator("#authbar").get_attribute("class") or ""),
                  "authbar did not get .ok after the checkbox was ticked")
            page.fill("#target", "")
            page.click("#scanBtn")
            page.wait_for_timeout(400)
            check(not scan_posts, "POST /api/scan fired with an empty target")

            # ── click through every tab ──
            tabs = page.locator(".tab").all()
            names = [t.get_attribute("data-tab") for t in tabs]
            for t in tabs:
                t.click()
                page.wait_for_timeout(350)
                name = t.get_attribute("data-tab")
                check(page.locator(f"#tab-{name}").is_visible(),
                      f"panel #tab-{name} not visible after clicking its tab")
            page.locator('.tab[data-tab="host"]').click()
            page.wait_for_timeout(200)

            # ── mock scan renders results with the charts row (Task 4) ──
            mock_scan = {
                "target": "https://example.com",
                "url": "https://example.com",
                "ip": "93.184.216.34",
                "assessment": {"grade": "D", "score": 42, "clean": False},
                "services": [
                    {"name": "nginx", "version": "1.18", "port": 443,
                     "protocol": "tcp", "source": "http-header"},
                ],
                "recon": {
                    "subdomains": ["www.example.com", "api.example.com"],
                    "crawl": {"pages": 3, "js_files": 1,
                              "endpoints": ["/login", "/api/v1/users"],
                              "routes": ["/app"]},
                    "tech": [{"name": "nginx", "version": "1.18",
                              "category": "web-server"}],
                },
                "cves": [
                    {"id": "CVE-2021-0001", "severity": "CRITICAL", "cvss": 9.8,
                     "affects": "nginx 1.18", "description": "mock firm CVE",
                     "confidence": "firm",
                     "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-0001"},
                    {"id": "CVE-2021-0002", "severity": "HIGH", "cvss": 7.5,
                     "affects": "openssl 1.1.1", "description": "mock weak CVE",
                     "confidence": "weak", "caveat": "distro backport",
                     "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-0002"},
                ],
                "findings": [
                    {"severity": "HIGH", "category": "headers",
                     "title": "Missing Content-Security-Policy",
                     "description": "mock finding", "recommendation": "add a CSP",
                     "evidence": "https://example.com/login returns 200 without a CSP"},
                    {"severity": "MEDIUM", "category": "headers",
                     "title": "Missing HSTS", "description": "mock finding"},
                    {"severity": "LOW", "category": "tls",
                     "title": "TLS 1.0 enabled", "description": "mock finding"},
                    {"severity": "INFO", "category": "ai-hypothesis",
                     "title": "AI lead (excluded from counts)",
                     "description": "mock finding"},
                ],
            }
            page.evaluate("(scan) => window.CELSIUS.loadScan(scan)", mock_scan)
            page.wait_for_timeout(700)
            check(page.locator("#results .hero").count() == 1,
                  "mock scan did not render the results hero")
            check("hidden" not in (page.locator("#chartsRow").get_attribute("class") or ""),
                  "#chartsRow stayed hidden after the mock scan rendered")
            check(page.locator("#chartsRow svg *").count() > 0,
                  "#chartsRow has no SVG children after the mock scan rendered")
            check(page.locator("#chartDonut svg *").count() > 0,
                  "#chartDonut has no SVG children")
            check(page.locator("#chartCats svg *").count() > 0,
                  "#chartCats has no SVG children")
            # 1 firm CRITICAL CVE + 3 real findings (weak CVE + AI lead excluded)
            check((page.locator("#chartDonut .chart-donut-total").text_content() or "") == "4",
                  "#chartDonut center total is not 4 (exclusion convention broken)")

            # ── attack-surface graph view (Task 6) ──
            check(page.locator("#resultsToggle").is_visible(),
                  "results view toggle not shown after the mock scan rendered")
            page.click("#viewSurface")
            page.wait_for_timeout(600)
            check(not page.locator("#results").is_visible(),
                  "#results still visible in the Attack surface view")
            check(page.locator("#surfaceView").is_visible(),
                  "#surfaceView not visible after toggling Attack surface")
            check(page.locator("#surfaceGraph svg").count() == 1,
                  "#surfaceGraph svg missing after toggling Attack surface")
            n_nodes = page.locator("#surfaceGraph svg .sg-node").count()
            check(n_nodes >= 1, f"#surfaceGraph has no nodes (got {n_nodes})")
            # mock: target + 2 hosts + 1 service + 3 endpoints + 3 finding pills
            check(page.locator('#surfaceGraph svg .sg-node[data-kind="host"]').count() == 2,
                  "subdomain host nodes missing from the surface graph")
            check(page.locator('#surfaceGraph svg .sg-node[data-kind="endpoint"]').count() == 3,
                  "crawl endpoint nodes missing from the surface graph")
            check(page.locator('#surfaceGraph svg .sg-node[data-kind="finding"]').count() == 3,
                  "finding pills missing from the surface graph (AI lead should be excluded)")
            # CSP finding's evidence mentions /login → pill pinned to that endpoint
            check(page.evaluate(
                "() => { const g = window.CELSIUS.surface.buildGraph(window.CELSIUS.state.currentScan.result);"
                " const ep = g.nodes.find(n => n.kind === 'endpoint' && n.label === '/login');"
                " return g.nodes.some(n => n.kind === 'finding' && n.attach === ep.id); }"),
                "finding with /login evidence was not pinned to the /login endpoint node")
            # click a node → detail pane fills; then toggle back to the findings view
            page.locator('#surfaceGraph svg .sg-node[data-kind="target"]').click()
            page.wait_for_timeout(200)
            check("example.com" in (page.locator("#surfaceDetail").inner_html() or ""),
                  "detail pane did not render after clicking the target node")
            if args.shot:
                page.screenshot(path=f"{args.shot}-surface-light.png", full_page=True)
            page.click("#viewFindings")
            page.wait_for_timeout(300)
            check(page.locator("#results").is_visible(),
                  "#results not visible after toggling back to Findings")

            # ── jobs queue drawer: opens, renders (empty state OK), closes (Task 5) ──
            check(page.locator("#jobsBtn").count() == 1, "jobs appbar button missing")
            check(page.locator("#jobsBadge").count() == 1, "jobs badge missing")
            check("hidden" in (page.locator("#jobsBadge").get_attribute("class") or ""),
                  "jobs badge should start hidden with 0 running jobs")
            page.click("#jobsBtn")
            page.wait_for_timeout(400)
            check("open" in (page.locator("#jobsDrawer").get_attribute("class") or ""),
                  "jobs drawer did not open on button click")
            try:
                page.wait_for_selector("#jobsList .jobs-row, #jobsList .jobs-empty",
                                       timeout=6000)
            except Exception:
                pass
            check((page.locator("#jobsList").inner_html() or "").strip() != "",
                  "#jobsList is empty — neither job rows nor the empty state rendered")
            check(page.locator("#jobsList .jobs-row, #jobsList .jobs-empty").count() >= 1,
                  "#jobsList shows neither job rows nor the empty state")
            page.keyboard.press("Escape")
            page.wait_for_timeout(400)
            check("open" not in (page.locator("#jobsDrawer").get_attribute("class") or ""),
                  "jobs drawer did not close on Escape")

            # ── screenshots (light + dark) ──
            if args.shot:
                prefix = Path(args.shot)
                prefix.parent.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=f"{prefix}-light.png", full_page=True)
                page.click("#themeToggle")
                page.wait_for_timeout(250)
                check(page.evaluate("document.documentElement.getAttribute('data-theme')") == "dark",
                      "theme toggle did not switch to dark")
                page.screenshot(path=f"{prefix}-dark.png", full_page=True)
                for name in names:
                    if name == "host":
                        continue
                    page.locator(f'.tab[data-tab="{name}"]').click()
                    page.wait_for_timeout(350)
                    page.screenshot(path=f"{prefix}-{name}-dark.png", full_page=True)
                print(f"[*] screenshots saved with prefix {prefix}")

            browser.close()
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()

    for e in errors:
        print(f"[console] {e}")
    for f in failures:
        print(f"[FAIL] {f}")
    if errors or failures:
        print(f"[!] ui_smoke FAILED — {len(errors)} console error(s), "
              f"{len(failures)} assertion failure(s)")
        return 1
    print("[✓] ui_smoke OK — dashboard home, tabs, authorization gate, results charts, "
          "attack-surface graph, jobs drawer, theme toggle; zero console errors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
