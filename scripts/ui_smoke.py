#!/usr/bin/env python3
"""Dev-only UI smoke check: load the app, exercise the main tabs, fail on any
console error. Usage: .venv/bin/python scripts/ui_smoke.py [base_url] [--shot prefix]

Requires the `dynamic` extra (playwright) plus a Chromium build
(`playwright install chromium`). Dev-only — NOT part of CI.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _rgb(color: str) -> tuple[float, float, float]:
    color = color.strip()
    if re.fullmatch(r"#[0-9a-fA-F]{6}", color):
        values = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    else:
        match = re.fullmatch(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)(?:\s*,[^)]*)?\)", color)
        if not match:
            raise ValueError(f"unsupported computed color: {color}")
        values = [int(v) / 255 for v in match.groups()]
    return tuple(v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
                 for v in values)


def _contrast(first: str, second: str) -> float:
    def luminance(color):
        red, green, blue = _rgb(color)
        return 0.2126 * red + 0.7152 * green + 0.0722 * blue

    light, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


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
                    help="save screenshots as PREFIX-light.png, PREFIX-dark.png, PREFIX-<tab>-dark.png, "
                         "PREFIX-dashboard-light.png, PREFIX-surface-{light,dark}.png, PREFIX-jobsdrawer.png")
    args = ap.parse_args()
    base = args.base_url.rstrip("/")
    if args.shot:
        Path(args.shot).parent.mkdir(parents=True, exist_ok=True)

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
    expected_500 = [0]  # resource-load errors from deliberately mocked HTTP failures

    def on_console(m) -> None:
        if m.type != "error":
            return
        # Expected mocked HTTP failures each log one "Failed to load resource".
        if expected_500[0] > 0 and "Failed to load resource" in m.text:
            expected_500[0] -= 1
            return
        errors.append(f"console.error: {m.text}")

    def check(cond: bool, msg: str) -> None:
        if not cond:
            failures.append(msg)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            page.on("console", on_console)
            page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))

            scan_posts: list[str] = []
            scan_list_requests: list[str] = []

            def on_request(req) -> None:
                path = urllib.parse.urlparse(req.url).path
                if req.method == "POST" and path == "/api/scan":
                    scan_posts.append(req.url)
                if req.method == "GET" and path == "/api/scans":
                    scan_list_requests.append(req.url)

            page.on("request", on_request)

            # ── screenshot privacy: EVERY capture below runs against mocked, ──
            # ── sanitized API data — never the real scan store. Hosts are    ──
            # ── example.com/.org only; IPs are RFC 5737 documentation ranges ──
            # ── (plus example.com's well-known public IP).                   ──
            mock_detail = {
                "target": "https://example.com",
                "url": "https://example.com",
                "ip": "93.184.216.34",
                "assessment": {"grade": "F", "score": 21, "clean": False},
                "services": [
                    {"name": "nginx", "version": "1.18.0", "port": 443,
                     "protocol": "tcp", "source": "http-header"},
                    {"name": "OpenSSH", "version": "8.9p1", "port": 22,
                     "protocol": "tcp", "source": "banner"},
                ],
                "recon": {
                    "subdomains": ["www.example.com", "api.example.com",
                                   "dev.example.com"],
                    "crawl": {"pages": 12, "js_files": 4,
                              "endpoints": ["/login", "/api/v1/users", "/search"],
                              "routes": ["/app", "/admin"]},
                    "tech": [{"name": "nginx", "version": "1.18.0",
                              "category": "web-server"},
                             {"name": "PHP", "version": "8.1",
                              "category": "language"}],
                    "dns": {"a": ["93.184.216.34"], "mx": ["mail.example.com"]},
                },
                "cves": [
                    {"id": "CVE-2021-0001", "severity": "CRITICAL", "cvss": 9.8,
                     "affects": "nginx 1.18.0", "description": "mock CVE (demo data)",
                     "confidence": "firm", "verified": True,
                     "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-0001"},
                    {"id": "CVE-2021-0002", "severity": "HIGH", "cvss": 7.5,
                     "affects": "HTTP/2", "description": "mock CVE (demo data)",
                     "confidence": "firm",
                     "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-0002"},
                ],
                "findings": [
                    {"severity": "CRITICAL", "category": "exposure",
                     "title": "Exposed .git directory",
                     "description": "mock finding", "recommendation": "block dotfiles",
                     "evidence": "https://example.com/.git/HEAD returns 200",
                     "verified": True},
                    {"severity": "HIGH", "category": "headers",
                     "title": "Missing Content-Security-Policy",
                     "description": "mock finding", "recommendation": "add a CSP",
                     "evidence": "https://example.com/login returns 200 without a CSP",
                     "exploitability": {"verdict": "confirmed-exposed", "priority": 90,
                                        "signals": {"actively_verified": True}}},
                    {"severity": "MEDIUM", "category": "headers",
                     "title": "Missing HSTS", "description": "mock finding",
                     "exploitability": {"verdict": "likely-exploitable",
                                        "signals": {"actively_verified": True,
                                                    "corroborated": False}}},
                    {"severity": "MEDIUM", "category": "tls",
                     "title": "Weak TLS cipher suite accepted",
                     "description": "mock finding"},
                    {"severity": "LOW", "category": "tls",
                     "title": "TLS 1.0 enabled", "description": "mock finding"},
                    {"severity": "INFO", "category": "headers",
                     "title": "Server header discloses version",
                     "description": "mock finding"},
                    {"severity": "CRITICAL", "category": "ai-hypothesis",
                     "title": "Unverified AI lead (excluded from verified count)",
                     "description": "mock finding",
                     "exploitability": {"verdict": "confirmed-exploitable",
                                        "signals": {"actively_verified": True}}},
                ],
                "errors": [], "chains": [], "coverage": {},
                "started_at": "2026-07-22T09:38:00Z",
                "finished_at": "2026-07-22T09:41:00Z",
            }
            mock_hist_rows = [
                {"id": "scan-demo01", "target": "https://example.com",
                 "url": "https://example.com", "ip": "93.184.216.34",
                 "started_at": "2026-07-22T09:38:00Z",
                 "finished_at": "2026-07-22T09:41:00Z",
                 "n_findings": 6, "n_cves": 2, "worst": "CRITICAL",
                 "grade": "F", "score": 21},
                {"id": "scan-demo02", "target": "https://app.example.com",
                 "url": "https://app.example.com", "ip": "192.0.2.10",
                 "started_at": "2026-07-21T15:58:00Z",
                 "finished_at": "2026-07-21T16:05:00Z",
                 "n_findings": 4, "n_cves": 1, "worst": "MEDIUM",
                 "grade": "B+", "score": 84},
                {"id": "scan-demo03", "target": "https://example.org",
                 "url": "https://example.org", "ip": "198.51.100.23",
                 "started_at": "2026-07-20T11:20:00Z",
                 "finished_at": "2026-07-20T11:26:00Z",
                 "n_findings": 1, "n_cves": 0, "worst": "LOW",
                 "grade": "A", "score": 96},
                {"id": "scan-demo04", "target": "https://example.com",
                 "url": "https://example.com", "ip": "93.184.216.34",
                 "started_at": "2026-07-15T08:05:00Z",
                 "finished_at": "2026-07-15T08:12:00Z",
                 "n_findings": 5, "n_cves": 2, "worst": "CRITICAL",
                 "grade": "F", "score": 24},
                {"id": "scan-demo05", "target": "http://203.0.113.7",
                 "url": "http://203.0.113.7", "ip": "203.0.113.7",
                 "started_at": "2026-07-10T14:41:00Z",
                 "finished_at": "2026-07-10T14:48:00Z",
                 "n_findings": 3, "n_cves": 1, "worst": "MEDIUM",
                 "grade": "B+", "score": 82},
                {"id": "scan-demo06", "target": "https://app.example.com",
                 "url": "https://app.example.com", "ip": "192.0.2.10",
                 "started_at": "2026-07-02T09:55:00Z",
                 "finished_at": "2026-07-02T10:02:00Z",
                 "n_findings": 2, "n_cves": 0, "worst": "LOW",
                 "grade": "A", "score": 95},
            ]

            def mock_scans_api(route):
                req = route.request
                path = urllib.parse.urlparse(req.url).path
                if req.method == "GET" and path == "/api/scans":
                    route.fulfill(json={"scans": mock_hist_rows})
                elif req.method == "GET" and re.fullmatch(r"/api/scans/[^/]+", path):
                    route.fulfill(json=dict(mock_detail))
                else:
                    route.continue_()

            # regex route (globs miss query strings like /api/scans?limit=8);
            # stays active for every screenshot — the tiles/View test below
            # registers its own route later, which takes precedence while active.
            page.route(re.compile(r".*/api/scans(/[^?]*)?"), mock_scans_api)

            poc_payloads = []

            def mock_poc_api(route):
                payload = route.request.post_data_json or {}
                poc_payloads.append(payload)
                route.fulfill(json={"title": "Mock reproduction steps",
                                    "steps": ["Review the sanitized mock evidence."],
                                    "note": "Mock data only.", "references": []})

            page.route(re.compile(r".*/api/poc$"), mock_poc_api)

            page.goto(base + "/", wait_until="networkidle")

            # ── landmarks, complete tab semantics and one initial dashboard load ──
            check(len(scan_list_requests) == 1,
                  f"initial semantics caused duplicate dashboard/history loads: {scan_list_requests}")
            check(page.locator('.skip-link[href="#main-content"]').count() == 1 and
                  page.locator('main#main-content[tabindex="-1"]').count() == 1,
                  "skip link or focusable main landmark is missing")
            page.locator(".skip-link").focus()
            page.keyboard.press("Enter")
            check(page.evaluate("() => document.activeElement.id") == "main-content",
                  "skip link did not move focus to the main landmark")

            tab_semantics = page.locator(".tabs > .tab").evaluate_all("""tabs => tabs.map(t => {
                const panel = document.getElementById(t.getAttribute('aria-controls'));
                return {id: t.id, selected: t.getAttribute('aria-selected'), tabIndex: t.tabIndex,
                        controls: t.getAttribute('aria-controls'), panelExists: !!panel,
                        labelledBy: panel && panel.getAttribute('aria-labelledby')};
            })""")
            check(all(t["id"] and t["controls"] and t["panelExists"] and
                      t["labelledBy"] == t["id"] for t in tab_semantics),
                  f"main tab/tabpanel relationships are incomplete: {tab_semantics}")
            check(sum(t["selected"] == "true" and t["tabIndex"] == 0
                      for t in tab_semantics) == 1 and
                  sum(t["tabIndex"] == 0 for t in tab_semantics) == 1,
                  "main tabs do not have exactly one selected, tabbable item")
            check(page.locator("#scanProgress").get_attribute("role") is None and
                  page.locator("#scanProgress").get_attribute("aria-live") is None and
                  page.locator("#scanLog").get_attribute("aria-live") is None and
                  page.locator("#progElapsed").get_attribute("aria-live") is None,
                  "elapsed/log or the whole progress card is still a live region")
            check(page.locator("#scanProgressStatus.visually-hidden").get_attribute("role")
                  == "status" and
                  page.locator("#scanProgressStatus").get_attribute("aria-live") == "polite" and
                  page.locator("#scanProgressStatus").get_attribute("aria-atomic") == "true" and
                  page.locator("#scanLog").get_attribute("tabindex") == "0",
                  "dedicated progress status or on-demand log semantics are missing")

            # ── dashboard is the default landing view and renders (Task 3) ──
            dash_tab = page.locator('.tab[data-tab="dashboard"]')
            check(dash_tab.count() == 1, "dashboard tab button missing")
            check("active" in (dash_tab.get_attribute("class") or ""),
                  "dashboard tab is not the default active tab")
            check(page.locator("#tab-dashboard").is_visible(),
                  "dashboard panel not visible on load")

            dash_tab.focus()
            page.keyboard.press("ArrowRight")
            check(page.evaluate("() => document.activeElement.id") == "tab-btn-host" and
                  page.locator("#tab-host").is_visible(),
                  "ArrowRight did not select/focus the next main tab")
            page.keyboard.press("ArrowDown")
            check(page.evaluate("() => document.activeElement.id") == "tab-btn-mail",
                  "ArrowDown did not move through the main tabs")
            page.keyboard.press("ArrowUp")
            check(page.evaluate("() => document.activeElement.id") == "tab-btn-host",
                  "ArrowUp did not move back through the main tabs")
            page.keyboard.press("ArrowLeft")
            check(page.evaluate("() => document.activeElement.id") == "tab-btn-dashboard",
                  "ArrowLeft did not return to Dashboard")
            before_history_keys = len(scan_list_requests)
            page.keyboard.press("End")
            page.wait_for_selector("#historyTable", timeout=6000)
            check(page.evaluate("() => document.activeElement.id") == "tab-btn-history" and
                  len(scan_list_requests) == before_history_keys + 1,
                  "End did not select History exactly once")
            page.keyboard.press("Home")
            check(page.evaluate("() => document.activeElement.id") == "tab-btn-dashboard" and
                  page.locator("#tab-dashboard").is_visible(),
                  "Home did not return to the first main tab")

            # Changed tokens must meet AA on their actual surfaces in both themes.
            def token(name):
                return page.evaluate(
                    "name => getComputedStyle(document.documentElement).getPropertyValue(name).trim()",
                    name)

            for theme in ("light", "dark"):
                page.evaluate("theme => document.documentElement.dataset.theme = theme", theme)
                for surface in ("--bg", "--surface", "--surface-2", "--surface-3"):
                    ratio = _contrast(token("--faint"), token(surface))
                    check(ratio >= 4.5,
                          f"{theme} --faint contrast on {surface} is {ratio:.2f}:1")
                for name in ("crit", "high", "med", "low", "info", "ok"):
                    ratio = _contrast(token("--on-" + name), token("--" + name))
                    check(ratio >= 4.5,
                          f"{theme} solid {name} foreground contrast is {ratio:.2f}:1")
                for name in ("high", "med", "ok"):
                    for surface in ("--surface", "--surface-2"):
                        ratio = _contrast(token("--" + name), token(surface))
                        check(ratio >= 4.5,
                              f"{theme} {name} text contrast on {surface} is {ratio:.2f}:1")
                check(_contrast(token("--on-grade-b"), "#65a30d") >= 4.5,
                      f"{theme} grade-B badge foreground is below AA")
                check(_contrast(token("--on-accent"), token("--accent")) >= 4.5,
                      f"{theme} accent foreground is below AA")
            page.evaluate("document.documentElement.dataset.theme = 'light'")
            try:
                page.wait_for_selector("#dashHero .hero, #dashHero .dash-empty",
                                       timeout=8000)
            except Exception:
                pass
            check((page.locator("#dashHero").inner_html() or "").strip() != "",
                  "#dashHero is empty — neither hero nor empty state rendered")
            check(page.locator("#dashHero .hero, #dashHero .dash-empty").count() == 1,
                  "#dashHero shows neither the hero nor the empty state")
            page.wait_for_function(
                "() => document.querySelectorAll('#dashTiles .tile').length === 6",
                timeout=6000)
            dash_labels = [(t.text_content() or "").strip()
                           for t in page.locator("#dashTiles .tile .label").all()]
            dash_metrics = [t.inner_text().strip()
                            for t in page.locator("#dashTiles .tile .metric").all()]
            check(dash_labels[5] == "Verified",
                  f"dashboard verification tile should be named Verified (got {dash_labels[5]})")
            check(dash_metrics[5] == "2",
                  "Verified tile must count c.verified + confirmed findings, excluding "
                  f"f.verified and AI leads (got {dash_metrics[5]})")
            check("target-confirmed" in page.locator("#dashTiles .tile").nth(5).inner_text(),
                  "Verified tile subtext does not explain target confirmation")
            if args.shot:
                page.screenshot(path=f"{args.shot}-dashboard-light.png", full_page=True)

            # Dashboard review only prefills/focuses; it must not start a scan.
            check(page.locator("#dashRescan").inner_text().strip() == "Review & rescan",
                  "dashboard rescan action is not labelled Review & rescan")
            before_review_posts = len(scan_posts)
            page.click("#dashRescan")
            check(page.locator("#tab-host").is_visible() and
                  page.input_value("#target") == "https://example.com" and
                  page.evaluate("() => document.activeElement.id") == "target" and
                  len(scan_posts) == before_review_posts,
                  "dashboard Review & rescan did not prefill/focus without scanning")

            # ── switch to the host tab for the scan-form checks below ──
            page.locator('.tab[data-tab="host"]').click()
            page.wait_for_timeout(200)

            # ── authorization gate: submitting without the checkbox must NOT scan ──
            check(not page.locator("#authorized").is_checked(),
                  "#authorized should start unchecked")
            check(page.locator("#authState").inner_text().strip() == "Authorization required",
                  "authorization required state copy is missing")
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
            check(page.locator("#authState").inner_text().strip() == "Authorization confirmed",
                  "authorization confirmed state copy is missing")
            page.evaluate("""() => document.querySelector('#results').innerHTML =
                '<p id=\"rejectedResultSentinel\">existing sanitized result</p>'""")
            page.fill("#target", "")
            page.click("#scanBtn")
            page.wait_for_timeout(400)
            check(not scan_posts, "POST /api/scan fired with an empty target")
            check(page.locator("#targetError").is_visible() and
                  page.get_attribute("#target", "aria-invalid") == "true" and
                  page.locator("#rejectedResultSentinel").count() == 1,
                  "empty target lacks an associated error or cleared existing results")

            page.fill("#target", "https://example.com:bad/")
            page.click("#scanBtn")
            check(page.locator("#targetError").is_visible() and
                  page.input_value("#target") == "https://example.com:bad/" and
                  page.locator("#rejectedResultSentinel").count() == 1 and
                  not scan_posts,
                  "invalid target did not preserve input/results without a POST")
            page.fill("#target", "https://example.com")
            check(page.get_attribute("#target", "aria-invalid") == "false" and
                  page.locator("#targetError").is_hidden(),
                  "editing a target did not clear its invalid state")

            def active_preset():
                return page.locator(".preset.active").get_attribute("data-preset")

            page.locator('.preset[data-preset="standard"]').focus()
            page.keyboard.press("ArrowRight")
            check(active_preset() == "deep" and
                  page.evaluate("() => document.activeElement.dataset.preset") == "deep",
                  "preset ArrowRight did not select/focus Deep")
            page.keyboard.press("End")
            check(active_preset() == "custom" and
                  page.locator("#advancedOpts").get_attribute("open") is not None,
                  "preset End did not select Custom/open advanced options")
            page.keyboard.press("Home")
            check(active_preset() == "quick", "preset Home did not select Quick")
            page.keyboard.press("ArrowDown")
            check(active_preset() == "standard" and
                  page.evaluate("() => document.activeElement.dataset.preset") == "standard",
                  "preset ArrowDown did not select Standard")
            preset_states = page.locator(".preset").evaluate_all(
                "presets => presets.map(p => ({checked: p.getAttribute('aria-checked'), tab: p.tabIndex}))")
            check(sum(p["checked"] == "true" and p["tab"] == 0 for p in preset_states) == 1 and
                  sum(p["tab"] == 0 for p in preset_states) == 1,
                  "scan preset radiogroup does not have one checked, tabbable radio")

            # AI/auth configuration is not scan depth; real depth fields are.
            page.locator("#advancedOpts").evaluate("(el) => { el.open = true; }")
            if page.locator("#aiForm").is_hidden():
                page.click("#aiConfigureBtn")
            page.evaluate("localStorage.removeItem('celsius_ai_key')")
            page.select_option("#opt-ai-provider", "mock")
            page.check("#opt-ai")
            page.fill("#opt-ai-model", "smoke-model")
            page.fill("#opt-ai-base", "http://127.0.0.1:11434/v1")
            page.fill("#opt-ai-key", "smoke-not-a-real-key")
            page.dispatch_event("#opt-ai-key", "change")
            check(active_preset() == "standard" and
                  page.evaluate("localStorage.getItem('celsius_ai_key')") is None and
                  not page.locator("#opt-ai-remember").is_checked(),
                  "AI changes altered the preset or persisted a key without opt-in")
            page.check("#opt-ai-remember")
            check(page.evaluate("localStorage.getItem('celsius_ai_key')") == "smoke-not-a-real-key",
                  "explicit remember opt-in did not save the mock key")
            page.uncheck("#opt-ai-remember")
            check(page.evaluate("localStorage.getItem('celsius_ai_key')") is None,
                  "remember opt-out did not remove the saved key")
            check(active_preset() == "standard", "AI key storage changed the depth preset")

            check(page.locator("#authscan .auth-field").count() == 8,
                  "authenticated fields no longer have persistent labels")
            page.locator("#authscan").evaluate("(el) => { el.open = true; }")
            page.fill("#opt-cookie", "session=smoke-only")
            page.fill("#opt-login-user", "smoke-user")
            check(active_preset() == "standard", "authenticated fields changed the depth preset")
            page.fill("#opt-cookie", "")
            page.fill("#opt-login-user", "")

            page.uncheck("#opt-web")
            check(active_preset() == "custom", "a real depth checkbox did not select Custom")
            page.click('.preset[data-preset="standard"]')
            page.click('.preset[data-preset="deep"]')
            page.fill("#opt-portrange", "22,80")
            check(active_preset() == "custom", "port range did not select Custom")
            page.click('.preset[data-preset="deep"]')
            page.fill("#opt-nucleitags", "cve,exposure")
            check(active_preset() == "custom", "nuclei tags did not select Custom")

            # Parent/dependent controls explain disabling and are reapplied by presets.
            page.click('.preset[data-preset="standard"]')
            for dependent in ("opt-udp", "opt-osdetect", "opt-portrange",
                              "opt-nucleifull", "opt-nucleitags"):
                check(page.locator("#" + dependent).is_disabled() and
                      page.locator("#" + dependent + "-dependency").is_visible(),
                      f"{dependent} is not disabled/explained without its parent")
            check(not page.locator("#opt-subbrute").is_disabled() and
                  not page.locator("#opt-dynamic").is_disabled(),
                  "standard preset did not re-enable subdomain/dynamic dependencies")
            page.click('.preset[data-preset="deep"]')
            check(all(not page.locator("#" + dependent).is_disabled()
                      for dependent in ("opt-udp", "opt-osdetect", "opt-portrange",
                                        "opt-nucleifull", "opt-nucleitags")),
                  "deep preset did not enable port/nuclei dependents")
            page.check("#opt-udp")
            page.uncheck("#opt-ports")
            check(page.locator("#opt-udp").is_disabled() and
                  not page.locator("#opt-udp").is_checked(),
                  "disabling ports left an ineffective UDP selection")
            page.check("#opt-cveverify")
            page.uncheck("#opt-cve")
            check(page.locator("#opt-cveverify").is_disabled() and
                  not page.locator("#opt-cveverify").is_checked(),
                  "CVE verification did not follow the CVE parent")
            page.click('.preset[data-preset="quick"]')
            check(page.locator("#opt-subbrute").is_disabled() and
                  page.locator("#opt-dynamic").is_disabled(),
                  "subdomain brute-force/dynamic do not require their parents")
            page.click('.preset[data-preset="standard"]')
            check(not scan_posts, "setup-only interactions unexpectedly started a scan")

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

            # ── associated code/mail validation, pending guards and result errors ──
            page.locator('.tab[data-tab="mail"]').click()
            page.evaluate("document.querySelector('#mailResults').textContent = 'existing mail result'")
            page.fill("#mailDomain", "   ")
            page.click("#mailBtn")
            check(page.locator("#mailDomainError").is_visible() and
                  page.get_attribute("#mailDomain", "aria-invalid") == "true" and
                  page.input_value("#mailDomain") == "   " and
                  page.locator("#mailResults").inner_text() == "existing mail result",
                  "empty mail submission did not preserve its input/result with inline validation")

            page.locator('.tab[data-tab="code"]').click()
            page.evaluate("document.querySelector('#codeResults').textContent = 'existing code result'")
            page.fill("#codeText", "   ")
            page.click("#codeTextBtn")
            check(page.locator("#codeTextError").is_visible() and
                  page.get_attribute("#codeText", "aria-invalid") == "true" and
                  page.input_value("#codeText") == "   " and
                  page.locator("#codeResults").inner_text() == "existing code result",
                  "empty snippet submission did not preserve its input/result")
            page.locator("#codeForm").evaluate("(el) => { el.closest('details').open = true; }")
            page.fill("#codePath", "   ")
            page.click("#codeBtn")
            check(page.locator("#codePathError").is_visible() and
                  page.get_attribute("#codePath", "aria-invalid") == "true" and
                  page.input_value("#codePath") == "   " and
                  page.locator("#codeResults").inner_text() == "existing code result",
                  "empty code-path submission did not preserve its input/result")

            aux_requests: list[str] = []
            held_aux = []

            def hold_aux(route):
                aux_requests.append(urllib.parse.urlparse(route.request.url).path)
                held_aux.append(route)

            aux_pattern = re.compile(r".*/api/(code|mailsec)$")
            page.route(aux_pattern, hold_aux)
            try:
                page.fill("#codeText", "password = 'smoke-only'")
                with page.expect_request("**/api/code"):
                    page.click("#codeTextBtn")
                check(page.locator("#codeTextBtn").is_disabled() and
                      page.locator("#codeBtn").is_disabled(),
                      "code controls were not disabled while a request was pending")
                page.evaluate("document.querySelector('#codeTextBtn').click()")
                page.wait_for_timeout(200)
                check(aux_requests == ["/api/code"],
                      "duplicate code submission fired while pending")
                held_aux.pop(0).fulfill(json={
                    "files_scanned": 1, "tools_used": [], "findings": [],
                    "errors": ["mock code tool failure (sanitized)"],
                })
                page.wait_for_selector("#codeResults .result-problems", timeout=6000)
                check("mock code tool failure" in page.locator("#codeResults").inner_text() and
                      "err" in (page.locator("#codeStatus").get_attribute("class") or "") and
                      page.locator("#codeResults .empty-good").count() == 0 and
                      not page.locator("#codeTextBtn").is_disabled(),
                      "code errors were reported as clean or left controls pending")

                page.locator('.tab[data-tab="mail"]').click()
                page.fill("#mailDomain", "example.org")
                with page.expect_request("**/api/mailsec"):
                    page.click("#mailBtn")
                check(page.locator("#mailBtn").is_disabled(),
                      "mail button was not disabled while pending")
                page.evaluate("document.querySelector('#mailForm').requestSubmit()")
                page.wait_for_timeout(200)
                check(aux_requests == ["/api/code", "/api/mailsec"],
                      "duplicate mail submission fired while pending")
                held_aux.pop(0).fulfill(json={
                    "domain": "example.org", "grade": "A", "score": 100,
                    "provider": "mock provider", "mx": [],
                    "checks": [{"status": "ok", "label": "SPF",
                                "detail": "sanitized mock check", "value": "", "fix": ""}],
                    "errors": ["mock DNS check failure (sanitized)"],
                })
                page.wait_for_selector("#mailResults .result-problems", timeout=6000)
                check("mock DNS check failure" in page.locator("#mailResults").inner_text() and
                      "err" in (page.locator("#mailStatus").get_attribute("class") or "") and
                      not page.locator("#mailBtn").is_disabled(),
                      "mail errors were hidden or left the button pending")
            finally:
                for held in held_aux:
                    held.fulfill(status=400, json={"detail": "smoke cleanup"})
                page.unroute(aux_pattern)
            page.locator('.tab[data-tab="host"]').click()

            # ── mock scan renders results with the charts row (Task 4) ──
            mock_scan = {
                "target": "https://example.com",
                "url": "https://example.com",
                "ip": "93.184.216.34",
                "assessment": {
                    "grade": "D", "score": 42, "clean": False,
                    "total_actionable": 4,
                    "fix_first": [
                        {"kind": "cve", "severity": "CRITICAL", "verified": True,
                         "title": "CVE-2021-0001", "why": "mock confirmed risk",
                         "fix": "Update nginx"},
                        {"kind": "finding", "severity": "HIGH", "verified": False,
                         "title": "Missing Content-Security-Policy",
                         "why": "mock defense gap", "fix": "add a CSP"},
                    ],
                },
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
                    "cohosted": {
                        "ip": "93.184.216.34", "siblings": [],
                        "from_san": [], "from_ptr": [], "from_reverse_ip": [],
                        "error": None,
                        "checked": {"certificate_san": True, "reverse_dns": True,
                                    "reverse_ip": True},
                    },
                },
                "cves": [
                    {"id": "CVE-2021-0001", "severity": "CRITICAL", "cvss": 9.8,
                     "affects": "nginx 1.18", "product": "nginx",
                     "description": ("mock firm CVE with a complete sanitized description. " * 6)
                                    + "FULL_DESCRIPTION_TOKEN",
                     "published": "2025-01-15T00:00:00Z", "confidence": "firm",
                     "references": [{"url": "https://example.org/security/CVE-2021-0001-poc",
                                     "poc": True}],
                     "exploitability": {
                         "verdict": "confirmed-exploitable", "priority": 95,
                         "signals": {"verified": True, "kev": True, "public_poc": True,
                                     "poc_urls": ["https://example.org/security/CVE-2021-0001-poc"],
                                     "epss": 0.8}},
                     "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-0001"},
                    {"id": "CVE-2021-0002", "severity": "HIGH", "cvss": 7.5,
                     "affects": "openssl 1.1.1", "product": "openssl",
                     "description": "mock weak CVE with an openssl backport caveat",
                     "published": "2026-01-15T00:00:00Z",
                     "confidence": "weak", "caveat": "distro backport",
                     "exploitability": {"verdict": "conditions-needed", "priority": 40,
                                        "signals": {"kev": False, "public_poc": False,
                                                    "epss": 0.1}},
                     "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-0002"},
                ],
                "findings": [
                    {"severity": "HIGH", "category": "headers",
                     "title": "Missing Content-Security-Policy",
                     "description": "mock finding", "recommendation": "add a CSP",
                     "evidence": "https://example.com/login returns 200 without a CSP",
                     "exploitability": {"verdict": "conditions-needed", "priority": 49,
                                        "signals": {"reachable": True}}},
                    {"severity": "MEDIUM", "category": "headers",
                     "title": "Missing HSTS", "description": "mock finding",
                     "exploitability": {"verdict": "confirmed-exploitable", "priority": 90,
                                        "signals": {"actively_verified": True}}},
                    {"severity": "LOW", "category": "tls",
                     "title": "TLS 1.0 enabled", "description": "mock finding",
                     "exploitability": {"verdict": "unknown", "priority": 20,
                                        "signals": {"reachable": True}}},
                    {"severity": "INFO", "category": "ai-hypothesis",
                     "title": "AI lead (excluded from counts)",
                     "description": "mock finding",
                     "exploitability": {"verdict": "unknown", "priority": 30}},
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
            cohost_card = page.locator("#results .cohost-status")
            cohost_text = cohost_card.inner_text().lower()
            check(cohost_card.count() == 1 and
                  "co-hosted hostname candidates (0)" in cohost_text and
                  "no public hostnames found in the checked sources." in cohost_text and
                  all(source in cohost_text for source in
                      ("certificate sans", "ptr", "reverse-ip")),
                  f"empty co-host state or checked sources are not visible: {cohost_text}")
            service_table = page.locator("#results table.svc")
            check(service_table.locator("caption").inner_text().strip()
                  == "Detected services for https://example.com" and
                  service_table.locator("thead th").count() == 4 and
                  service_table.locator('thead th:not([scope="col"])').count() == 0,
                  "generated service table lacks a useful caption or column scopes")
            check(page.get_attribute("#viewFindings", "aria-controls") == "results" and
                  page.get_attribute("#viewSurface", "aria-controls") == "surfaceView" and
                  page.get_attribute("#results", "aria-labelledby") == "viewFindings" and
                  page.get_attribute("#surfaceView", "aria-labelledby") == "viewSurface",
                  "Findings/Attack surface tab relationships are incomplete")
            operational_sizes = page.locator(
                "#results .badge, #results .verdict, #results .triage-label").evaluate_all(
                    "els => els.map(el => parseFloat(getComputedStyle(el).fontSize))")
            check(operational_sizes and min(operational_sizes) >= 12,
                  f"operational badge/verdict/triage text is still too small: {operational_sizes}")

            # ── CVE / finding triage: combined filters, sorting and stable identities ──
            def triage_count(kind):
                return page.locator(
                    f'[data-triage-root="{kind}"] [data-triage-count]').inner_text().strip()

            def triage_keys(kind):
                return page.locator(
                    f'[data-triage-root="{kind}"] .triage-card').evaluate_all(
                        "(cards) => cards.map(c => c.dataset.triageKey)")

            def close_poc():
                page.click("#pocClose")
                page.locator("#pocModal").wait_for(state="hidden", timeout=6000)

            cve_cards = page.locator('[data-triage-root="cve"] .triage-card')
            finding_cards = page.locator('[data-triage-root="finding"] .triage-card')
            check(triage_count("cve") == "2 of 2",
                  f"CVE triage should initially show 2 of 2 (got {triage_count('cve')})")
            check(triage_keys("cve") == ["CVE-2021-0001", "CVE-2021-0002"],
                  f"default CVE risk order is wrong (got {triage_keys('cve')})")
            check(page.locator('label[for="cveTriageSearch"].triage-label').text_content()
                  == "Search CVEs" and page.get_by_label("Search CVEs", exact=True).count() == 1,
                  "CVE search does not have a persistent accessible label")
            check(page.locator('label[for="findingTriageSearch"].triage-label').text_content()
                  == "Search findings" and
                  page.get_by_label("Search findings", exact=True).count() == 1,
                  "finding search does not have a persistent accessible label")

            first_cve = page.locator('[data-triage-key="CVE-2021-0001"]')
            check("2025-01-15" in first_cve.locator("time").inner_text(),
                  "CVE publication date is not rendered")
            long_desc = first_cve.locator(".cve-description")
            check(long_desc.count() == 1 and
                  "FULL_DESCRIPTION_TOKEN" in (long_desc.text_content() or ""),
                  "long CVE description is still permanently truncated")
            long_desc.locator("summary").click()
            check(long_desc.get_attribute("open") is not None and
                  long_desc.locator(".cve-desc-full").is_visible(),
                  "full CVE description disclosure did not expand")
            long_desc.locator("summary").click()

            hero_handle = page.locator("#results .hero").element_handle()
            page.select_option("#cveTriageSort", "newest")
            check(triage_keys("cve") == ["CVE-2021-0002", "CVE-2021-0001"],
                  f"newest-publication CVE sort is wrong (got {triage_keys('cve')})")
            check(page.evaluate(
                "() => window.CELSIUS.state.currentScan.result.cves.map(c => c.id)")
                == ["CVE-2021-0001", "CVE-2021-0002"],
                "CVE sorting mutated the source scan order")

            previous_pocs = len(poc_payloads)
            poc_trigger = cve_cards.nth(0).locator(".pocBtn")
            poc_trigger_key = poc_trigger.get_attribute("data-item-key")
            poc_trigger.click()
            page.locator("#pocModal:not(.hidden)").wait_for(timeout=6000)
            page.wait_for_function(
                "() => document.querySelector('#pocContent').getAttribute('aria-busy') === 'false'",
                timeout=6000)
            check(len(poc_payloads) == previous_pocs + 1 and
                  poc_payloads[-1].get("data", {}).get("id") == "CVE-2021-0002",
                  "How to check opened the wrong CVE after newest-first reordering")
            check(page.get_attribute("#pocModal", "aria-labelledby") == "pocTitle" and
                  page.locator("#pocTitle").inner_text().strip() == "Mock reproduction steps" and
                  page.get_attribute("#pocModal", "aria-modal") == "true",
                  "PoC dialog is not labelled by its loaded title")
            check(page.evaluate(
                "() => document.querySelector('main').inert && "
                "document.querySelector('.appbar').inert && "
                "!document.querySelector('#pocModal').inert"),
                "PoC dialog did not make the background inert")
            page.keyboard.press("Tab")
            check(page.evaluate("() => document.activeElement.id") == "pocClose",
                  "PoC focus trap escaped the dialog")
            close_poc()
            check(page.evaluate(
                "() => !document.querySelector('main').inert && "
                "!document.querySelector('.appbar').inert"),
                "PoC close did not restore background interactivity")
            check(page.evaluate("() => document.activeElement.dataset.itemKey") == poc_trigger_key,
                  "PoC close did not return focus to the initiating triage action")

            page.fill("#cveTriageSearch", "nginx")
            page.select_option("#cveTriageSeverity", "CRITICAL")
            page.select_option("#cveTriageConfidence", "firm")
            page.select_option("#cveTriageEvidence", "verified")
            check(triage_count("cve") == "1 of 2" and
                  triage_keys("cve") == ["CVE-2021-0001"],
                  "combined CVE search/severity/confidence/verified filters failed")
            page.select_option("#cveTriageEvidence", "kev")
            check(triage_count("cve") == "1 of 2", "CISA KEV evidence filter failed")
            page.select_option("#cveTriageEvidence", "poc")
            check(triage_count("cve") == "1 of 2", "public PoC evidence filter failed")
            check(page.evaluate(
                "(hero) => hero === document.querySelector('#results .hero')", hero_handle),
                "CVE filtering re-rendered the entire result hero")
            check((page.locator("#chartDonut .chart-donut-total").text_content() or "") == "4",
                  "CVE filtering changed the whole-scan chart total")

            page.fill("#cveTriageSearch", "no CVE matches this text")
            check(triage_count("cve") == "0 of 2" and
                  page.locator('[data-triage-root="cve"] .triage-empty').is_visible(),
                  "CVE no-match state is missing")
            page.click('[data-triage-root="cve"] .triage-empty-reset')
            check(triage_count("cve") == "2 of 2" and
                  triage_keys("cve") == ["CVE-2021-0001", "CVE-2021-0002"],
                  "CVE no-match reset did not restore the risk-sorted list")
            check(page.input_value("#cveTriageSearch") == "" and
                  page.input_value("#cveTriageSeverity") == "all" and
                  page.input_value("#cveTriageConfidence") == "all" and
                  page.input_value("#cveTriageEvidence") == "all" and
                  page.input_value("#cveTriageSort") == "risk",
                  "CVE reset did not restore every toolbar control")

            check(triage_count("finding") == "3 of 3",
                  "finding triage total should exclude the AI hypothesis")
            category_values = page.locator("#findingTriageCategory option").evaluate_all(
                "(options) => options.map(o => o.value)")
            check(category_values == ["all", "headers", "tls"],
                  f"finding categories should be dynamic and exclude AI (got {category_values})")
            check("Missing HSTS" in finding_cards.nth(0).locator(".title").inner_text(),
                  "default finding risk order does not prioritize confirmed/priority findings")
            page.select_option("#findingTriageSort", "severity")
            check("Missing Content-Security-Policy" in
                  finding_cards.nth(0).locator(".title").inner_text(),
                  "finding severity sort did not put HIGH first")
            page.fill("#findingTriageSearch", "HSTS")
            page.select_option("#findingTriageSeverity", "MEDIUM")
            page.select_option("#findingTriageCategory", "headers")
            page.select_option("#findingTriageVerdict", "confirmed-exploitable")
            page.select_option("#findingTriageSort", "priority")
            check(triage_count("finding") == "1 of 3" and
                  "Missing HSTS" in finding_cards.nth(0).locator(".title").inner_text(),
                  "combined finding search/severity/category/verdict filters failed")

            previous_pocs = len(poc_payloads)
            finding_cards.nth(0).locator(".pocBtn").click()
            page.locator("#pocModal:not(.hidden)").wait_for(timeout=6000)
            page.wait_for_function(
                "() => document.querySelector('#pocContent').getAttribute('aria-busy') === 'false'",
                timeout=6000)
            check(len(poc_payloads) == previous_pocs + 1 and
                  poc_payloads[-1].get("data", {}).get("title") == "Missing HSTS",
                  "How to check opened the wrong finding after filtering/reordering")
            close_poc()

            page.fill("#findingTriageSearch", "no finding matches this text")
            check(triage_count("finding") == "0 of 3" and
                  page.locator('[data-triage-root="finding"] .triage-empty').is_visible(),
                  "finding no-match state is missing")
            check(page.locator("[data-ai-hypotheses] .triage-card").count() == 1,
                  "finding filters disturbed the separate AI hypothesis block")
            page.click('[data-triage-root="finding"] .triage-empty-reset')
            check(triage_count("finding") == "3 of 3" and
                  page.input_value("#findingTriageSearch") == "" and
                  page.input_value("#findingTriageSeverity") == "all" and
                  page.input_value("#findingTriageCategory") == "all" and
                  page.input_value("#findingTriageVerdict") == "all" and
                  page.input_value("#findingTriageSort") == "risk",
                  "finding no-match reset did not restore every toolbar control")

            check(page.locator(".fix-jump").count() == 2,
                  "Fix these first entries are not actionable")
            page.fill("#cveTriageSearch", "openssl")
            page.fill("#findingTriageSearch", "HSTS")
            check(triage_keys("cve") == ["CVE-2021-0002"],
                  "test setup could not hide the fix-first CVE")
            page.click('.fix-jump[data-fix-kind="cve"]')
            check(page.input_value("#cveTriageSearch") == "" and
                  page.evaluate("() => document.activeElement.dataset.triageKey")
                  == "CVE-2021-0001",
                  "fix-first CVE jump did not reset filters and focus the matching card")
            page.click('.fix-jump[data-fix-kind="finding"]')
            check(page.input_value("#findingTriageSearch") == "" and
                  page.evaluate("() => document.activeElement.dataset.triageKey")
                  == "finding:0:Missing Content-Security-Policy",
                  "fix-first finding jump did not reset filters and focus the matching card")

            def minimal_result(target):
                return {
                    "target": target, "url": target, "ip": "192.0.2.10",
                    "assessment": {"grade": "A", "score": 100, "clean": True,
                                   "fix_first": [], "total_actionable": 0},
                    "services": [], "cves": [], "findings": [], "recon": {},
                    "errors": [], "chains": [], "coverage": {},
                }

            # Hostile advisor/chain severities must become INFO, never HTML attributes.
            xss_payload = ('HIGH" onmouseover="window.__advisorXss=1" '
                           'data-x=""><img src=x onerror=window.__advisorXss=2>')
            advisor_scan = minimal_result("https://advisor.example.org")
            advisor_scan["recon"] = {"advisor": {
                "headline": "Sanitized advisor test",
                "steps": [{"severity": xss_payload, "title": "Hostile severity",
                           "why": xss_payload, "fix": "review sanitized evidence"}],
                "doing_well": [xss_payload],
            }}
            advisor_scan["chains"] = [{
                "severity": xss_payload, "title": "Adjacent chain", "priority": xss_payload,
                "nodes": [xss_payload], "narrative": "sanitized", "recommendation": "review",
            }]
            page.evaluate("""scan => {
                window.__advisorXss = 0;
                window.CELSIUS.loadScan(scan);
            }""", advisor_scan)
            advisor_badge = page.locator("#results .advisor .badge")
            check(advisor_badge.count() == 1 and
                  advisor_badge.inner_text().strip() == "INFO" and
                  "sev-INFO" in (advisor_badge.get_attribute("class") or ""),
                  "advisor severity was not normalized to the enum")
            check(page.locator("#results .advisor [onmouseover], #results .advisor [onerror], "
                               "#results .advisor [data-x], #results .advisor img").count() == 0 and
                  page.locator("#results .card [onmouseover], #results .card [onerror]").count() == 0,
                  "advisor/chain severity injected an event handler or element")
            page.locator("#results .advisor").dispatch_event("mouseover")
            check(page.evaluate("window.__advisorXss") == 0,
                  "advisor payload executed script")
            chain_badge = page.locator("#results .card .badge").first
            check(chain_badge.inner_text().strip() == "INFO" and
                  "sev-INFO" in (chain_badge.get_attribute("class") or ""),
                  "adjacent exploit-chain severity was not normalized")

            # Legacy verified+weak CVEs are confirmed, not contradictory/excluded.
            legacy_scan = minimal_result("https://legacy.example.org")
            legacy_scan["assessment"] = {"grade": "C", "score": 60, "clean": False,
                                         "fix_first": [], "total_actionable": 2}
            legacy_scan["cves"] = [
                {"id": "CVE-LEGACY-VERIFIED", "severity": "HIGH", "confidence": "weak",
                 "verified": True, "affects": "legacy component", "description": "verified legacy",
                 "url": "https://example.org/CVE-LEGACY-VERIFIED"},
                {"id": "CVE-LEGACY-WEAK", "severity": "CRITICAL", "confidence": "weak",
                 "verified": False, "affects": "unknown component", "description": "weak legacy",
                 "url": "https://example.org/CVE-LEGACY-WEAK"},
            ]
            page.evaluate("(scan) => window.CELSIUS.loadScan(scan)", legacy_scan)
            verified_legacy = page.locator('[data-triage-key="CVE-LEGACY-VERIFIED"]')
            weak_legacy = page.locator('[data-triage-key="CVE-LEGACY-WEAK"]')
            check("VERIFIED" in verified_legacy.locator(".title").inner_text() and
                  "UNCONFIRMED" not in verified_legacy.locator(".title").inner_text() and
                  "weak" not in (verified_legacy.get_attribute("class") or "").split() and
                  "UNCONFIRMED" in weak_legacy.locator(".title").inner_text(),
                  "legacy verified weak CVE still looks unconfirmed")
            check(page.locator("#results .hero .chip.sev-HIGH").inner_text().strip() == "HIGH 1" and
                  page.locator("#results .hero .chip.sev-CRITICAL").count() == 0 and
                  page.locator("#results .hero .chip.sev-UNCONFIRMED").inner_text().strip().lower()
                  == "unconfirmed 1" and
                  page.locator("#chartDonut .chart-donut-total").text_content() == "1",
                  "legacy verified weak CVE was excluded from result/chart counts")
            check("CVEs (1 + 1 unconfirmed)" in page.locator(
                "#results h2.section").filter(has_text="Known vulnerabilities").inner_text(),
                  "CVE section counts still call a verified legacy record unconfirmed")

            legacy_row = {"id": "legacy-weak", "target": legacy_scan["target"],
                          "url": legacy_scan["url"], "grade": "C", "score": 60,
                          "worst": "CRITICAL", "n_findings": 0, "n_cves": 2,
                          "finished_at": "2026-07-22T09:41:00Z"}
            legacy_dash_pattern = re.compile(r".*/api/scans(?:/legacy-weak)?(?:\?.*)?$")

            def mock_legacy_dashboard(route):
                path = urllib.parse.urlparse(route.request.url).path
                if path == "/api/scans":
                    route.fulfill(json={"scans": [legacy_row]})
                elif path == "/api/scans/legacy-weak":
                    route.fulfill(json=legacy_scan)
                else:
                    route.continue_()

            page.route(legacy_dash_pattern, mock_legacy_dashboard)
            try:
                page.evaluate("() => window.CELSIUS.dashboard.refresh()")
                legacy_metrics = [el.inner_text().strip()
                                  for el in page.locator("#dashTiles .tile .metric").all()]
                check(legacy_metrics[0] == "0" and legacy_metrics[1] == "1" and
                      legacy_metrics[5] == "1" and
                      page.locator("#dashHero .chip.sev-HIGH").inner_text().strip() == "HIGH 1" and
                      page.locator("#dashHero .chip.sev-CRITICAL").count() == 0,
                      f"dashboard excluded legacy verified weak CVE: {legacy_metrics}")
            finally:
                page.unroute(legacy_dash_pattern)

            # Duplicate title/severity: source_index selects the exact second record.
            duplicate_scan = minimal_result("https://duplicates.example.org")
            duplicate_scan["assessment"] = {
                "grade": "C", "score": 60, "clean": False, "total_actionable": 2,
                "fix_first": [{"kind": "finding", "source_index": 1, "severity": "HIGH",
                               "title": "Same finding", "why": "second source", "fix": "fix second"}],
            }
            duplicate_scan["findings"] = [
                {"severity": "HIGH", "category": "test", "title": "Same finding",
                 "description": "first description", "evidence": "FIRST_SOURCE_EVIDENCE"},
                {"severity": "HIGH", "category": "test", "title": "Same finding",
                 "description": "second description", "evidence": "SECOND_SOURCE_EVIDENCE"},
            ]
            page.evaluate("(scan) => window.CELSIUS.loadScan(scan)", duplicate_scan)
            page.locator(".fix-jump").click()
            check(page.evaluate("() => document.activeElement.dataset.triageKey")
                  == "finding:1:Same finding" and
                  "SECOND_SOURCE_EVIDENCE" in page.evaluate(
                      "() => document.activeElement.textContent") and
                  "FIRST_SOURCE_EVIDENCE" not in page.evaluate(
                      "() => document.activeElement.textContent"),
                  "fix-first source_index did not select the second duplicate source record")

            empty_scan = {
                "target": "https://example.org", "url": "https://example.org",
                "assessment": {"grade": "A", "score": 100, "clean": True},
                "services": [], "recon": {}, "cves": [], "findings": [],
                "errors": [], "chains": [], "coverage": {},
            }
            page.evaluate("(scan) => window.CELSIUS.loadScan(scan)", empty_scan)
            check(triage_count("cve") == "0 of 0" and
                  "No known CVEs" in page.locator(
                      '[data-triage-root="cve"] .empty-good').inner_text(),
                  "true-empty CVE messaging is not honest")
            check(triage_count("finding") == "0 of 0" and
                  "No findings" in page.locator(
                      '[data-triage-root="finding"] .empty-good').inner_text(),
                  "true-empty finding messaging is not honest")
            page.evaluate("(scan) => window.CELSIUS.loadScan(scan)", mock_scan)
            page.wait_for_timeout(300)

            # Held and failed PoC requests: loading state, checked HTTP errors and cleanup.
            poc_trigger = page.locator('[data-triage-key="CVE-2021-0001"] .pocBtn')
            held_poc = []
            poc_pattern = re.compile(r".*/api/poc$")
            page.route(poc_pattern, lambda route: held_poc.append(route))
            try:
                poc_trigger.click()
                page.wait_for_selector("#pocContent .poc-loading", timeout=6000)
                check(poc_trigger.is_disabled() and
                      poc_trigger.get_attribute("aria-busy") == "true" and
                      poc_trigger.inner_text().strip() == "Loading…" and
                      page.get_attribute("#pocContent", "aria-busy") == "true",
                      "PoC request lacks a loading/disabled state")
                check(page.evaluate("() => document.querySelector('main').inert"),
                      "loading PoC did not inert the background")
                check(len(held_poc) == 1, "held PoC request was not issued exactly once")
                held_poc.pop(0).fulfill(json={
                    "title": "Held mock reproduction steps",
                    "steps": ["Sanitized delayed response."], "note": "", "references": [],
                })
                page.wait_for_function(
                    "() => document.querySelector('#pocContent').getAttribute('aria-busy') === 'false'",
                    timeout=6000)
                check(not poc_trigger.is_disabled() and
                      poc_trigger.inner_text().strip() == "How to check" and
                      page.locator("#pocTitle").inner_text() == "Held mock reproduction steps",
                      "successful PoC did not clear its loading state")
                close_poc()
            finally:
                for held in held_poc:
                    held.fulfill(json={"title": "Cleanup", "steps": [], "references": []})
                page.unroute(poc_pattern)

            def fail_poc(route):
                route.fulfill(status=500, json={"detail": "mock PoC unavailable (sanitized)"})

            page.route(poc_pattern, fail_poc)
            try:
                expected_500[0] += 1
                poc_trigger.click()
                page.wait_for_selector("#pocContent .poc-error", timeout=6000)
                check(page.locator("#pocTitle").inner_text() == "Reproduction steps unavailable" and
                      "mock PoC unavailable" in page.locator("#pocContent .poc-error").inner_text() and
                      page.get_attribute("#pocContent", "aria-busy") == "false" and
                      not poc_trigger.is_disabled(),
                      "failed PoC response lacked a useful error or stuck its trigger")
                close_poc()
                check(page.evaluate(
                    "() => !document.querySelector('main').inert && "
                    "document.activeElement.dataset.itemKey === 'CVE-2021-0001'"),
                    "failed PoC did not restore inertness/focus")
            finally:
                page.unroute(poc_pattern)

            def wait_for_routes(routes, count):
                for _ in range(120):
                    if len(routes) >= count:
                        return True
                    page.wait_for_timeout(50)
                return False

            # Closing/reopening supersedes PoC A with B; reverse fulfillment stays on B.
            held_overlap = []
            page.route(poc_pattern, lambda route: held_overlap.append(route))
            poc_a = page.locator('[data-triage-key="CVE-2021-0001"] .pocBtn')
            poc_b = page.locator('[data-triage-key="CVE-2021-0002"] .pocBtn')
            try:
                poc_a.click()
                page.wait_for_selector("#pocContent .poc-loading", timeout=6000)
                check(wait_for_routes(held_overlap, 1), "first overlapping PoC was not requested")
                close_poc()
                page.wait_for_function(
                    "() => !document.querySelector('[data-triage-key=\"CVE-2021-0001\"] "
                    ".pocBtn').disabled", timeout=6000)
                poc_b.click()
                check(wait_for_routes(held_overlap, 2), "second overlapping PoC was not requested")
                held_overlap.pop(1).fulfill(json={
                    "title": "Latest PoC B", "steps": ["latest response"], "references": [],
                })
                page.wait_for_function(
                    "() => document.querySelector('#pocTitle').textContent === 'Latest PoC B' && "
                    "document.querySelector('#pocContent').getAttribute('aria-busy') === 'false'",
                    timeout=6000)
                held_overlap.pop(0).fulfill(json={
                    "title": "Stale PoC A", "steps": ["stale response"], "references": [],
                })
                page.wait_for_timeout(250)
                check(page.locator("#pocTitle").inner_text() == "Latest PoC B" and
                      "stale response" not in page.locator("#pocContent").inner_text() and
                      page.get_attribute("#pocContent", "aria-busy") == "false",
                      "older PoC response replaced newer content/busy state")
                check(not poc_a.is_disabled() and not poc_b.is_disabled() and
                      poc_a.inner_text().strip() == "How to check" and
                      poc_b.inner_text().strip() == "How to check" and
                      poc_a.get_attribute("aria-busy") is None and
                      poc_b.get_attribute("aria-busy") is None,
                      "overlapping PoC requests did not each restore their trigger")
                close_poc()
            finally:
                for held in held_overlap:
                    held.fulfill(json={"title": "Cleanup", "steps": [], "references": []})
                page.unroute(poc_pattern)

            # Long targets and expanded evidence must wrap instead of widening the shell.
            long_target = "https://example.com/" + "unbroken-segment-" * 70
            long_scan = minimal_result(long_target)
            long_scan["assessment"] = {"grade": "C", "score": 60, "clean": False,
                                       "fix_first": [], "total_actionable": 1}
            long_scan["cves"] = [{
                "id": "CVE-LONG-0001", "severity": "HIGH", "confidence": "firm",
                "affects": long_target, "description": long_target,
                "url": "https://example.org/CVE-LONG-0001",
            }]
            long_scan["findings"] = [{
                "severity": "HIGH", "category": "evidence", "title": "Long expanded evidence",
                "description": long_target, "evidence": long_target,
                "recommendation": "Review the sanitized long evidence.",
            }]
            page.evaluate("(scan) => window.CELSIUS.loadScan(scan)", long_scan)
            page.locator('[data-triage-root="finding"] .f-sec').first.locator("summary").click()
            page.locator('[data-triage-root="cve"] .cve-description > summary').click()
            check("unbroken-segment" in page.locator(
                '[data-triage-root="finding"] .f-sec .meta').inner_text() and
                page.locator('[data-triage-root="finding"] .f-sec').first.get_attribute("open")
                is not None,
                "long evidence was not expanded for the overflow test")

            for width in (320, 375, 720):
                page.set_viewport_size({"width": width, "height": 900})
                for theme in ("light", "dark"):
                    page.evaluate("theme => document.documentElement.dataset.theme = theme", theme)
                    check(page.evaluate("() => document.documentElement.scrollWidth <= innerWidth + 1"),
                          f"results shell overflows at {width}px in {theme}")
                    token_box = page.locator("#accessToken").bounding_box()
                    check(token_box and token_box["x"] >= -1 and
                          token_box["x"] + token_box["width"] <= width + 1,
                          f"access token overflows at {width}px in {theme}: {token_box}")
                    for kind in ("cve", "finding"):
                        dimensions = page.locator(
                            f'[data-triage-root="{kind}"] .triage-toolbar').evaluate(
                                "(el) => ({scroll: el.scrollWidth, client: el.clientWidth})")
                        check(dimensions["scroll"] <= dimensions["client"] + 1,
                              f"{kind} toolbar overflows at {width}px in {theme}: {dimensions}")
                    search_height = page.locator("#cveTriageSearch").evaluate(
                        "(el) => el.getBoundingClientRect().height")
                    check(search_height >= 44,
                          f"CVE search is not touch-friendly at {width}px ({search_height}px)")
                    check(page.evaluate("""() => {
                        const target = document.querySelector('#results .hero-target');
                        const evidence = document.querySelector(
                            '[data-triage-root="finding"] .f-sec .meta');
                        return getComputedStyle(target).overflowWrap === 'anywhere' &&
                               getComputedStyle(evidence).overflowWrap === 'anywhere';
                    }"""), f"long target/evidence lacks anywhere wrapping at {width}px in {theme}")
            page.evaluate("document.documentElement.dataset.theme = 'light'")
            page.set_viewport_size({"width": 1280, "height": 900})
            page.evaluate("(scan) => window.CELSIUS.loadScan(scan)", mock_scan)
            page.wait_for_timeout(300)

            page.emulate_media(reduced_motion="reduce")
            check(page.evaluate("() => window.CELSIUS.scrollBehavior()") == "auto",
                  "reduced-motion preference did not disable smooth scrolling")
            scroll_behaviors = page.evaluate("""() => {
                const seen = [];
                const original = Element.prototype.scrollIntoView;
                Element.prototype.scrollIntoView = function (options) { seen.push(options); };
                window.CELSIUS.scrollIntoView(document.querySelector('#target'), {block: 'center'});
                Element.prototype.scrollIntoView = original;
                return seen;
            }""")
            check(len(scroll_behaviors) == 1 and scroll_behaviors[0].get("behavior") == "auto",
                  f"scroll helper ignored reduced motion: {scroll_behaviors}")
            page.emulate_media(reduced_motion="no-preference")
            check(page.evaluate("() => window.CELSIUS.scrollBehavior()") == "smooth",
                  "default scroll helper did not retain smooth behavior")

            # ── attack-surface graph view (Task 6) ──
            check(page.locator("#resultsToggle").is_visible(),
                  "results view toggle not shown after the mock scan rendered")
            page.locator("#viewFindings").focus()
            page.keyboard.press("ArrowRight")
            check(page.evaluate("() => document.activeElement.id") == "viewSurface" and
                  page.get_attribute("#viewSurface", "aria-selected") == "true" and
                  page.get_attribute("#viewSurface", "tabindex") == "0" and
                  page.get_attribute("#viewFindings", "tabindex") == "-1",
                  "result tabs do not support ArrowRight/roving tabindex")
            page.keyboard.press("Home")
            check(page.locator("#results").is_visible() and
                  page.evaluate("() => document.activeElement.id") == "viewFindings",
                  "result-tab Home did not restore Findings")
            page.keyboard.press("End")
            page.wait_for_timeout(600)
            check(page.evaluate("() => document.activeElement.id") == "viewSurface" and
                  page.locator("#surfaceView").is_visible(),
                  "result-tab End did not select Attack surface")
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
            followup_copy = page.locator("#results .followup .note").inner_text()
            check("authorization and scope are not verified" in followup_copy and
                  "In-scope" not in followup_copy,
                  "discovered-host copy implies authorization/scope verification")

            # History review also leaves options alone and never starts immediately.
            page.locator('.tab[data-tab="history"]').click()
            page.wait_for_selector("#historyList [data-rescan]", timeout=6000)
            history_table = page.locator("#historyTable")
            check("Stored scan history" in history_table.locator("caption").inner_text() and
                  history_table.locator("thead th").count() == 7 and
                  history_table.locator('thead th:not([scope="col"])').count() == 0,
                  "History table lacks its caption, seven headers or column scopes")
            history_labels = history_table.locator("tbody tr").first.locator("td").evaluate_all(
                "cells => cells.map(c => c.dataset.label)")
            check(history_labels == ["When", "Target", "Grade", "Worst", "CVEs", "Findings", "Actions"],
                  f"History cells lack narrow-screen data labels: {history_labels}")

            for width in (320, 375, 720, 1280):
                page.set_viewport_size({"width": width, "height": 900})
                if width == 320:
                    page.evaluate("""() => {
                        document.querySelector('.tabs').scrollLeft = 0;
                        window.CELSIUS.showTab('history');
                    }""")
                    page.wait_for_timeout(500)
                for theme in ("light", "dark"):
                    page.evaluate("theme => document.documentElement.dataset.theme = theme", theme)
                    check(page.evaluate("() => document.documentElement.scrollWidth <= innerWidth + 1"),
                          f"history shell overflows at {width}px in {theme}")
                    token_box = page.locator("#accessToken").bounding_box()
                    check(token_box and token_box["x"] >= -1 and
                          token_box["x"] + token_box["width"] <= width + 1,
                          f"history token overflows at {width}px in {theme}: {token_box}")
                    if width <= 720:
                        strip = page.locator(".tabs").evaluate(
                            "el => ({overflow: getComputedStyle(el).overflowX, scroll: el.scrollWidth, client: el.clientWidth})")
                        check(strip["overflow"] in ("auto", "scroll"),
                              f"mobile main tab strip is not scrollable at {width}px: {strip}")
                        selected_visible = page.evaluate("""() => {
                            const nav = document.querySelector('.tabs');
                            const tab = document.querySelector('.tabs > .tab[aria-selected="true"]');
                            const nr = nav.getBoundingClientRect(), tr = tab.getBoundingClientRect();
                            return tr.left >= nr.left - 1 && tr.right <= nr.right + 1;
                        }""")
                        check(selected_visible,
                              f"programmatically selected tab is outside the {width}px scroll strip")
                        if width <= 375:
                            check(strip["scroll"] > strip["client"],
                                  f"narrow tab strip did not contain its overflow at {width}px: {strip}")
                        check(history_table.evaluate("el => getComputedStyle(el).display") == "block" and
                              history_table.locator("tbody tr").first.evaluate(
                                  "el => getComputedStyle(el).display") == "grid",
                              f"History did not become cards at {width}px")
                        action_heights = history_table.locator(
                            "tbody tr").first.locator("button.actbtn, summary.actbtn").evaluate_all(
                                "els => els.map(el => el.getBoundingClientRect().height)")
                        check(len(action_heights) == 4 and min(action_heights) >= 44,
                              f"History row actions are not touch targets at {width}px: {action_heights}")
                        check(page.locator("#historyFilter").evaluate(
                            "el => el.getBoundingClientRect().height") >= 44 and
                            page.locator("#refreshHistory").evaluate(
                                "el => el.getBoundingClientRect().height") >= 44,
                            f"History filter controls are not touch-friendly at {width}px")
                    else:
                        check(history_table.evaluate("el => getComputedStyle(el).display") == "table" and
                              history_table.locator("thead").evaluate(
                                  "el => getComputedStyle(el).position") == "static",
                              "desktop History no longer uses a proper table/header")

                    export = history_table.locator("tbody tr").first.locator("details.exportmenu")
                    export.locator("summary").click()
                    menu = export.locator(".exportmenu-list")
                    check(export.get_attribute("open") is not None and
                          menu.locator("a").count() == 4 and menu.locator("a").first.is_visible(),
                          f"History export menu is unusable at {width}px in {theme}")
                    menu_box = menu.bounding_box()
                    check(menu_box and menu_box["x"] >= -1 and
                          menu_box["x"] + menu_box["width"] <= width + 1 and
                          page.evaluate("() => document.documentElement.scrollWidth <= innerWidth + 1"),
                          f"export menu causes overflow at {width}px in {theme}: {menu_box}")
                    if width <= 720:
                        check(menu.locator("a").first.evaluate(
                            "el => el.getBoundingClientRect().height") >= 44,
                            f"export links are not touch targets at {width}px")
                    export.locator("summary").click()
                    if args.shot and ((width == 320 and theme == "light") or
                                      (width == 375 and theme == "dark") or
                                      (width == 1280)):
                        page.evaluate("""() => {
                            window.scrollTo(0, 0);
                            if (document.activeElement) document.activeElement.blur();
                            document.querySelector('#toasts').replaceChildren();
                        }""")
                        page.wait_for_timeout(50)
                        page.screenshot(path=f"{args.shot}-history-{width}-{theme}.png",
                                        full_page=True)
            page.evaluate("document.documentElement.dataset.theme = 'light'")
            page.set_viewport_size({"width": 1280, "height": 900})
            page.wait_for_timeout(200)
            check(page.locator("#historyList [data-rescan]").first.inner_text().strip()
                  == "Review & rescan", "history action is not Review & rescan")
            before_history_review = len(scan_posts)
            wayback_before = page.locator("#opt-wayback").is_checked()
            page.locator("#historyList [data-rescan]").first.click()
            check(page.locator("#tab-host").is_visible() and
                  page.input_value("#target") == "https://example.com" and
                  page.evaluate("() => document.activeElement.id") == "target" and
                  page.locator("#opt-wayback").is_checked() == wayback_before and
                  len(scan_posts) == before_history_review,
                  "history Review & rescan started a job or changed options")

            # Stored result: partial coverage, actual errors and auth fallback stay visible.
            coverage_scan = {
                "target": "https://stored.example.org", "url": "https://stored.example.org",
                "ip": "198.51.100.23",
                "assessment": {"grade": "A+", "score": 100, "clean": True,
                               "fix_first": [], "total_actionable": 0},
                "services": [], "cves": [], "recon": {}, "chains": [],
                "findings": [
                    {"title": "Mock unverified one", "severity": "INFO", "category": "headers",
                     "description": "sanitized", "exploitability": {"verdict": "unknown"}},
                    {"title": "Mock unverified two", "severity": "INFO", "category": "tls",
                     "description": "sanitized",
                     "exploitability": {"verdict": "conditions-needed"}},
                    {"title": "Mock AI lead", "severity": "INFO", "category": "ai-hypothesis",
                     "description": "sanitized", "exploitability": {}},
                ],
                "coverage": {
                    "checks_run": ["web-headers", "tls"],
                    "checks_skipped": ["port-scan"],
                    "unverified_findings": 2, "ai_unconfirmed": 1,
                    "next_steps": ["run a port scan (smoke suggestion)"],
                },
                "errors": [
                    "AUTH_FALLBACK: authenticated session setup failed; the scan continued "
                    "unauthenticated and may miss authenticated-only coverage.",
                    "web-headers error: mock check failure (sanitized)",
                    "nuclei: skipped (safe-active checks disabled)",
                    "note: 198.51.100.23 is a documentation address (smoke note).",
                ],
                "started_at": "2026-07-22T09:38:00Z",
                "finished_at": "2026-07-22T09:41:00Z",
            }
            coverage_pattern = re.compile(r".*/api/scans/scan-coverage$")
            page.route(coverage_pattern, lambda route: route.fulfill(json=coverage_scan))
            try:
                page.evaluate("window.CELSIUS.loadScan('scan-coverage')")
                page.wait_for_selector("#results .coverage-summary", timeout=6000)
                check(page.locator("#results .hero + .coverage-summary").count() == 1,
                      "coverage summary is not prominent next to the result hero")
                check(page.locator("#results .hero-verdict").inner_text().strip()
                      == "No confident issues found in the checks that ran.",
                      "clean wording overstates coverage")
                coverage_text = page.locator("#results .coverage-summary").inner_text()
                check(all(text in coverage_text for text in
                          ("2 checks ran", "1 intentionally disabled", "2 unverified findings",
                           "1 unconfirmed AI leads", "4 scan notes", "1 check errors")),
                      f"coverage counts are incomplete: {coverage_text}")
                check(page.locator("#results .auth-fallback-banner").is_visible() and
                      "unauthenticated" in page.locator(
                          "#results .auth-fallback-banner").inner_text().lower(),
                      "stored auth fallback did not render a persistent warning")
                page.locator("#results .coverage-details > summary").click()
                details_text = page.locator("#results .coverage-details").inner_text()
                check("Intentionally disabled by scan options" in details_text and
                      "not a tool failure" in details_text and
                      "Skipped by scan mode or scope" in details_text and
                      "mock check failure" in details_text,
                      "coverage details do not distinguish disabled checks from errors")
                section_titles = page.locator("#results h2.section").all_inner_texts()
                check("Notes" not in section_titles and
                      "Want deeper coverage?" not in page.locator("#results .metafoot").inner_text(),
                      "coverage notes were duplicated at the bottom")
                check("scan-coverage" in page.locator("#results .metafoot-line").inner_text(),
                      "stored coverage result lost its scan identity")
            finally:
                page.unroute(coverage_pattern)

            # Stored result generations: newer B renders even when older A finishes last.
            held_stored = []
            stored_pattern = re.compile(r".*/api/scans/stored-(old|new)$")
            page.route(stored_pattern, lambda route: held_stored.append(route))
            try:
                page.evaluate("() => { window.CELSIUS.loadScan('stored-old'); }")
                check(wait_for_routes(held_stored, 1), "older stored result was not requested")
                page.evaluate("() => { window.CELSIUS.loadScan('stored-new'); }")
                check(wait_for_routes(held_stored, 2), "newer stored result was not requested")
                held_stored.pop(1).fulfill(
                    json=minimal_result("https://stored-new.example.org"))
                page.wait_for_function(
                    "() => window.CELSIUS.state.currentScan && "
                    "window.CELSIUS.state.currentScan.result.target === "
                    "'https://stored-new.example.org'", timeout=6000)
                held_stored.pop(0).fulfill(
                    json=minimal_result("https://stored-old.example.org"))
                page.wait_for_timeout(250)
                check(page.evaluate("window.CELSIUS.state.currentScan.result.target")
                      == "https://stored-new.example.org" and
                      "stored-new.example.org" in page.locator("#results .hero-target").inner_text() and
                      "stored-old.example.org" not in page.locator("#results").inner_text(),
                      "reversed stored responses replaced the newer scan")
            finally:
                for held in held_stored:
                    held.fulfill(json=minimal_result("https://cleanup.example.org"))
                page.unroute(stored_pattern)

            # Trend generations guard both response order and the live card identity.
            held_trends = []
            trend_pattern = re.compile(r".*/api/scans\?target=trend-(old|new)\.example\.org.*")
            page.route(trend_pattern, lambda route: held_trends.append(route))
            try:
                page.evaluate("(scan) => window.CELSIUS.loadScan(scan)",
                              minimal_result("https://trend-old.example.org"))
                page.evaluate("(scan) => window.CELSIUS.loadScan(scan)",
                              minimal_result("https://trend-new.example.org"))
                check(wait_for_routes(held_trends, 2), "both trend requests were not issued")
                trend_b = next(route for route in held_trends
                               if "trend-new.example.org" in route.request.url)
                held_trends.remove(trend_b)
                trend_b.fulfill(json={"scans": [{"n_cves": 7}]})
                page.wait_for_function(
                    "() => document.querySelector('#chartTrend .chart-title') && "
                    "document.querySelector('#chartTrend .chart-title').textContent.includes("
                    "'trend-new.example.org')", timeout=6000)
                trend_a = held_trends.pop(0)
                trend_a.fulfill(json={"scans": [{"n_cves": 1}]})
                page.wait_for_timeout(250)
                check("trend-new.example.org" in
                      page.locator("#chartTrend .chart-title").text_content() and
                      "latest 7" in page.locator("#chartTrend").text_content() and
                      "trend-old.example.org" not in page.locator("#chartTrend").text_content(),
                      "older trend response replaced the current card")
            finally:
                for held in held_trends:
                    held.fulfill(json={"scans": []})
                page.unroute(trend_pattern)
            page.evaluate("(scan) => window.CELSIUS.loadScan(scan)", coverage_scan)

            # ── jobs queue drawer: opens, renders (empty state OK), closes (Task 5) ──
            check(page.locator("#jobsBtn").count() == 1, "jobs appbar button missing")
            check(page.locator("#jobsBadge").count() == 1, "jobs badge missing")
            check(page.get_attribute("#jobsBtn", "aria-controls") == "jobsDrawer" and
                  page.get_attribute("#jobsBtn", "aria-expanded") == "false" and
                  page.get_attribute("#jobsDrawer", "aria-labelledby") == "jobsDrawerTitle" and
                  page.locator("#jobsDrawerTitle").inner_text() == "Scan jobs",
                  "jobs button/dialog relationships are incomplete")
            check("hidden" in (page.locator("#jobsBadge").get_attribute("class") or ""),
                  "jobs badge should start hidden with 0 running jobs")
            page.click("#jobsBtn")
            page.wait_for_timeout(400)
            check("open" in (page.locator("#jobsDrawer").get_attribute("class") or ""),
                  "jobs drawer did not open on button click")
            check(page.get_attribute("#jobsBtn", "aria-expanded") == "true" and
                  page.get_attribute("#jobsDrawer", "aria-hidden") == "false" and
                  page.get_attribute("#jobsDrawer", "aria-modal") == "false" and
                  page.evaluate("() => document.activeElement.id") == "jobsClose" and
                  page.evaluate("() => !document.querySelector('main').inert && "
                                "!document.querySelector('.appbar').inert"),
                  "desktop jobs drawer is modal or did not expose its state/receive focus")
            try:
                page.wait_for_selector("#jobsList .jobs-row, #jobsList .jobs-empty",
                                       timeout=6000)
            except Exception:
                pass
            check((page.locator("#jobsList").inner_html() or "").strip() != "",
                  "#jobsList is empty — neither job rows nor the empty state rendered")
            check(page.locator("#jobsList .jobs-row, #jobsList .jobs-empty").count() >= 1,
                  "#jobsList shows neither job rows nor the empty state")
            if args.shot:
                page.screenshot(path=f"{args.shot}-jobsdrawer.png", full_page=True)
            page.keyboard.press("Escape")
            page.wait_for_timeout(400)
            check("open" not in (page.locator("#jobsDrawer").get_attribute("class") or "") and
                  page.get_attribute("#jobsBtn", "aria-expanded") == "false" and
                  page.evaluate("() => document.activeElement.id") == "jobsBtn",
                  "jobs drawer did not close on Escape/restore trigger focus")

            page.evaluate("document.querySelector('footer').inert = true")
            page.set_viewport_size({"width": 720, "height": 900})
            page.click("#jobsBtn")
            page.wait_for_timeout(350)
            check(page.get_attribute("#jobsDrawer", "aria-modal") == "true" and
                  page.evaluate("() => document.querySelector('main').inert && "
                                "document.querySelector('.appbar').inert && "
                                "document.querySelector('footer').inert") and
                  page.evaluate("() => document.activeElement.id") == "jobsClose",
                  "mobile drawer did not become modal/inert covered siblings")
            page.keyboard.press("Tab")
            check(page.evaluate("() => document.activeElement.id") == "jobsClose",
                  "mobile drawer Tab escaped its only focusable control")
            page.keyboard.press("Shift+Tab")
            check(page.evaluate("() => document.activeElement.id") == "jobsClose",
                  "mobile drawer Shift+Tab escaped its only focusable control")
            page.keyboard.press("Escape")
            page.wait_for_timeout(400)
            check(page.evaluate("() => document.activeElement.id") == "jobsBtn" and
                  page.evaluate("() => !document.querySelector('main').inert && "
                                "!document.querySelector('.appbar').inert && "
                                "document.querySelector('footer').inert && "
                                "!document.activeElement.closest('#jobsDrawer')") and
                  page.get_attribute("#jobsDrawer", "aria-modal") == "false" and
                  page.get_attribute("#jobsDrawer", "aria-hidden") == "true",
                  "mobile drawer close left hidden focus or failed prior-inert restoration")
            page.evaluate("document.querySelector('footer').inert = false")
            page.set_viewport_size({"width": 1280, "height": 900})

            # ── active-job lifecycle: snapshots, isolation, retry, cancel and 401/404 ──
            def job_result(target, errors=None):
                return {
                    "target": target, "url": target, "ip": "192.0.2.10",
                    "assessment": {"grade": "A+", "score": 100, "clean": True,
                                   "fix_first": [], "total_actionable": 0},
                    "services": [], "cves": [], "findings": [], "recon": {}, "chains": [],
                    "errors": errors or [],
                    "coverage": {"checks_run": ["web-headers"], "checks_skipped": [],
                                 "unverified_findings": 0, "ai_unconfirmed": 0,
                                 "next_steps": []},
                    "started_at": "2026-07-22T09:38:00Z",
                    "finished_at": "2026-07-22T09:41:00Z",
                }

            job_states = {}
            job_http: dict[str, int] = {}
            job_posts = []
            job_polls: dict[str, int] = {}
            held_deletes = []
            reject_next = [False]
            hold_cancel = [False]
            job_sequence = [0]

            def add_mock_job(job_id, target):
                job_states[job_id] = {
                    "target": target, "status": "running",
                    "log": [job_id + " sanitized running log"], "result": None,
                }

            def mark_job_done(job_id, errors=None):
                state = job_states[job_id]
                state["status"] = "done"
                state["result"] = job_result(state["target"], errors)

            def mock_job_api(route):
                req = route.request
                path = urllib.parse.urlparse(req.url).path
                if path == "/api/jobs":
                    rows = [{"job_id": jid, "target": state["target"],
                             "status": state["status"], "started_at": "2026-07-22T09:38:00Z",
                             "progress": {"phase": "recon", "plugin": "Mock check",
                                          "index": 1, "total": 3, "elapsed": 1},
                             "error": None}
                            for jid, state in job_states.items()]
                    route.fulfill(json={"jobs": rows})
                    return
                if path == "/api/scan" and req.method == "POST":
                    if reject_next[0]:
                        reject_next[0] = False
                        route.fulfill(status=400, json={"detail": "mock rejected target"})
                        return
                    job_sequence[0] += 1
                    jid = f"job-live{job_sequence[0]}"
                    payload = req.post_data_json or {}
                    job_posts.append((jid, payload))
                    add_mock_job(jid, payload.get("target", "https://example.com"))
                    route.fulfill(json={"job_id": jid})
                    return
                if path.startswith("/api/scan/"):
                    jid = urllib.parse.unquote(path.rsplit("/", 1)[-1])
                    if req.method == "DELETE":
                        if jid == "job-live3" and hold_cancel[0]:
                            held_deletes.append(route)
                            return
                        if jid in job_states:
                            job_states[jid]["status"] = "cancelled"
                        route.fulfill(json={"job_id": jid, "status": "cancelling"})
                        return
                    job_polls[jid] = job_polls.get(jid, 0) + 1
                    if jid in job_http:
                        status = job_http[jid]
                        if status == 500:
                            del job_http[jid]  # one transient failure, then recover
                        route.fulfill(status=status,
                                      json={"detail": f"mock HTTP {status} (sanitized)"})
                        return
                    state = job_states.get(jid)
                    if state is None:
                        route.fulfill(status=404, json={"detail": "Unknown mock job"})
                        return
                    status = state["status"]
                    route.fulfill(json={
                        "job_id": jid, "target": state["target"], "status": status,
                        "started_at": "2026-07-22T09:38:00Z", "log": state["log"],
                        "progress": {"phase": "recon", "plugin": "Mock check",
                                     "index": 1, "total": 3, "elapsed": 1},
                        "result": state["result"],
                        "scan_id": "stored-" + jid if status == "done" else None,
                        "error": None,
                    })
                    return
                route.continue_()

            job_pattern = re.compile(r".*/api/(scan(?:/[^/]+)?|jobs)$")
            page.route(job_pattern, mock_job_api)
            try:
                # A server rejection must not clear the currently viewed result.
                reject_next[0] = True
                expected_500[0] += 1  # expected mocked 400 resource-load message
                page.fill("#target", "https://reject.example.com")
                with page.expect_request("**/api/scan"):
                    page.click("#scanBtn")
                page.wait_for_function(
                    "() => document.querySelector('#scanStatus').textContent.includes('Could not start')",
                    timeout=6000)
                check(page.input_value("#target") == "https://reject.example.com" and
                      page.evaluate("window.CELSIUS.state.currentScan.result.target")
                      == "https://stored.example.org" and
                      page.evaluate("window.CELSIUS.state.activeJob") is None,
                      "rejected scan POST cleared the result/input or created active state")

                # First poll fails transiently; the watcher must retain and recover the job.
                job_http["job-live1"] = 500
                expected_500[0] += 1
                page.fill("#target", "https://one.example.com")
                with page.expect_request("**/api/scan"):
                    page.click("#scanBtn")
                page.wait_for_function(
                    "() => window.CELSIUS.state.activeJob && "
                    "window.CELSIUS.state.activeJob.id === 'job-live1'")
                page.wait_for_function(
                    "() => document.querySelector('#scanStatus').textContent.includes('Retrying')",
                    timeout=6000)
                check(page.evaluate("window.CELSIUS.state.activeJob.id") == "job-live1" and
                      page.locator("#reconnectJobBtn").is_visible(),
                      "transient poll failure abandoned the active job")
                check("Connection interrupted" in page.locator("#scanProgressStatus").inner_text(),
                      "transient connection state was not announced in the dedicated status")
                page.wait_for_function(
                    "() => window.CELSIUS.state.activeJob && "
                    "document.querySelector('#reconnectJobBtn').classList.contains('hidden')",
                    timeout=8000)
                check("job-live1 sanitized running log" in page.locator("#scanLog").inner_text(),
                      "polling did not recover after a transient 500")
                progress_notice = page.locator("#scanProgressStatus").inner_text()
                check("Connection restored" in progress_notice and
                      "Mapping the attack surface" in progress_notice and
                      "sanitized running log" not in progress_notice and
                      "Mock check" not in progress_notice and "0:01" not in progress_notice,
                      f"progress status announced raw activity instead of phase/connection: {progress_notice}")

                # Opening a stored result must not hide progress or allow done to replace it.
                stored_during_active = job_result("https://stored.example.org")
                page.evaluate(
                    "(scan) => window.CELSIUS.loadScan(Object.assign({}, scan, "
                    "{scan_id: 'stored-active-view'}))", stored_during_active)
                check(page.locator("#scanProgress").is_visible() and
                      page.locator("#cancelBtn").is_visible() and
                      page.evaluate("window.CELSIUS.state.activeJob.id") == "job-live1" and
                      page.evaluate("window.CELSIUS.state.currentScan.result.target")
                      == "https://stored.example.org",
                      "stored-result view detached running progress/Cancel")
                mark_job_done("job-live1", ["mock note one", "mock note two"])
                page.wait_for_function(
                    "() => document.querySelector('#progPhase').textContent === 'Complete' && "
                    "window.CELSIUS.state.activeJob === null", timeout=8000)
                check(page.evaluate("window.CELSIUS.state.currentScan.result.target")
                      == "https://stored.example.org" and
                      "stored.example.org" in page.locator("#results .hero-target").inner_text() and
                      "2 scan notes" in page.locator("#scanStatus").inner_text(),
                      "later job completion overwrote the stored result or hid note count")
                check("Scan of https://one.example.com complete" in
                      page.locator("#scanProgressStatus").inner_text(),
                      "job completion was not announced in the dedicated progress status")

                # Job 2 and queued job 3 prove options are captured at queue time.
                page.click('.preset[data-preset="deep"]')
                page.fill("#opt-portrange", "22,80")
                page.fill("#opt-ai-model", "snapshot-model-A")
                page.fill("#opt-cookie", "session=snapshot-A")
                page.fill("#target", "https://two.example.com")
                with page.expect_request("**/api/scan"):
                    page.click("#scanBtn")
                page.wait_for_function(
                    "() => window.CELSIUS.state.activeJob && "
                    "window.CELSIUS.state.activeJob.id === 'job-live2'")
                second_options = job_posts[1][1]
                check(second_options.get("port_range") == "22,80" and
                      second_options.get("ai_model") == "snapshot-model-A" and
                      second_options.get("auth_cookie") == "session=snapshot-A",
                      "accepted job did not receive its full current option snapshot")
                page.wait_for_function(
                    "() => document.querySelector('#scanLog').textContent.includes('job-live2')",
                    timeout=6000)
                page.evaluate("""() => {
                    window._smokeProgressMutations = 0;
                    window._smokeProgressObserver = new MutationObserver(
                        () => { window._smokeProgressMutations += 1; });
                    window._smokeProgressObserver.observe(
                        document.querySelector('#scanProgressStatus'),
                        {childList: true, characterData: true, subtree: true});
                }""")
                page.wait_for_timeout(1300)
                progress_mutations = page.evaluate("""() => {
                    window._smokeProgressObserver.disconnect();
                    return window._smokeProgressMutations;
                }""")
                check(progress_mutations == 0,
                      "routine elapsed/log polling mutated the dedicated live status")

                page.fill("#opt-portrange", "443")
                page.fill("#opt-ai-model", "snapshot-model-B")
                page.fill("#opt-cookie", "session=snapshot-B")
                page.fill("#opt-nucleitags", "cve")
                page.uncheck("#opt-nuclei")
                page.fill("#target", "https://three.example.com")
                page.click("#scanBtn")
                page.wait_for_timeout(200)
                check(len(job_posts) == 2 and
                      page.evaluate("window.CELSIUS.state.activeJob.id") == "job-live2",
                      "queued target started before the active job finished")
                page.fill("#opt-portrange", "65535")
                page.fill("#opt-ai-model", "mutated-after-queue")
                page.fill("#opt-cookie", "session=mutated-after-queue")
                with page.expect_response("**/api/scan", timeout=10000):
                    mark_job_done("job-live2")
                page.wait_for_function(
                    "() => window.CELSIUS.state.activeJob && "
                    "window.CELSIUS.state.activeJob.id === 'job-live3'")
                third_options = job_posts[2][1]
                check(third_options.get("port_range") == "443" and
                      third_options.get("ai_model") == "snapshot-model-B" and
                      third_options.get("auth_cookie") == "session=snapshot-B" and
                      third_options.get("auth_cookie") != "session=mutated-after-queue",
                      "queued job read mutated options at start instead of its snapshot")
                check(third_options.get("nuclei") is False and
                      third_options.get("nuclei_tags") is None and
                      third_options.get("nuclei_full") is False,
                      "payload normalization submitted ineffective nuclei options")
                check(page.evaluate("localStorage.getItem('celsius_ai_key')") is None and
                      page.evaluate("() => !('options' in window.CELSIUS.state.activeJob)"),
                      "credentials/options were persisted or retained in public active state")

                # Cancel remains pending/disabled until the held DELETE is released.
                page.wait_for_function(
                    "() => document.querySelector('#scanLog').textContent.includes('job-live3')")
                hold_cancel[0] = True
                with page.expect_request(lambda req: req.method == "DELETE" and
                                         req.url.endswith("/api/scan/job-live3")):
                    page.click("#cancelBtn")
                check(page.locator("#cancelBtn").is_disabled() and
                      page.locator("#cancelBtn").inner_text().strip() == "Cancelling…",
                      "Cancel did not enter its pending disabled state")
                job_states["job-live3"]["status"] = "cancelled"
                held_deletes.pop(0).fulfill(json={"job_id": "job-live3", "status": "cancelling"})
                page.wait_for_function(
                    "() => document.querySelector('#progPhase').textContent === 'Cancelled'",
                    timeout=8000)
                check("job-live3 sanitized running log" in page.locator("#scanLog").inner_text() and
                      page.locator("#cancelBtn").is_hidden() and
                      page.evaluate("window.CELSIUS.state.activeJob") is None,
                      "cancelled progress/log was discarded")
                check("cancelled" in page.locator("#scanProgressStatus").inner_text().lower(),
                      "cancellation was not announced in the dedicated progress status")

                # Open progress from the drawer; 401 pauses with token help, then reconnects.
                add_mock_job("job-auth", "https://auth.example.com")
                job_http["job-auth"] = 401
                page.evaluate("window.CELSIUS.jobs.refresh()")
                page.click("#jobsBtn")
                page.wait_for_selector('#jobsList .jobs-open[data-job="job-auth"]', timeout=6000)
                check(page.evaluate("typeof window.CELSIUS.watchJob === 'function'"),
                      "public C.watchJob is missing")
                open_action = page.locator('#jobsList .jobs-open[data-job="job-auth"]')
                open_action.focus()
                page.wait_for_timeout(2300)
                check(page.evaluate(
                    "() => document.activeElement.dataset.job === 'job-auth' && "
                    "document.activeElement.dataset.action === 'open'"),
                    "drawer refresh lost the focused job/action identity")
                expected_500[0] += 1
                open_action.click()
                page.wait_for_function(
                    "() => document.querySelector('#scanStatus').textContent.includes('HTTP 401')",
                    timeout=6000)
                check(page.evaluate("window.CELSIUS.state.activeJob.id") == "job-auth" and
                      page.locator("#reconnectJobBtn").is_visible() and
                      "Access token" in page.locator("#scanStatus").inner_text() and
                      "celsius serve" in page.locator("#scanStatus").inner_text(),
                      "401 lacked token guidance or dropped the active job")
                check("access token required" in
                      page.locator("#scanProgressStatus").inner_text().lower(),
                      "401 connection state was not announced in the dedicated status")
                del job_http["job-auth"]
                page.click("#reconnectJobBtn")
                page.wait_for_function(
                    "() => window.CELSIUS.state.activeJob && "
                    "document.querySelector('#reconnectJobBtn').classList.contains('hidden')",
                    timeout=8000)
                check("job-auth sanitized running log" in page.locator("#scanLog").inner_text(),
                      "Reconnect did not resume the authorized job")
                check("Connection restored" in page.locator("#scanProgressStatus").inner_text(),
                      "reconnection was not announced in the dedicated status")

                job_http["job-auth"] = 404
                expected_500[0] += 1
                page.wait_for_function(
                    "() => document.querySelector('#scanStatus').textContent.includes('not found (404)') && "
                    "window.CELSIUS.state.activeJob === null", timeout=8000)
                check("server may have restarted" in page.locator("#scanStatus").inner_text() and
                      page.locator("#progPhase").inner_text().strip() == "Not found",
                      "404 did not produce a clear terminal state")
                final_auth_polls = job_polls["job-auth"]
                page.wait_for_timeout(1100)
                check(job_polls["job-auth"] == final_auth_polls,
                      "polling continued after terminal 404")

                # A→external B with queued C: A/C finish in background, then B renders.
                queue_a = f"job-live{job_sequence[0] + 1}"
                queue_c = f"job-live{job_sequence[0] + 2}"
                page.fill("#target", "https://queue-a.example.com")
                with page.expect_request("**/api/scan"):
                    page.click("#scanBtn")
                page.wait_for_function(
                    "(jid) => window.CELSIUS.state.activeJob && "
                    "window.CELSIUS.state.activeJob.id === jid", arg=queue_a, timeout=6000)
                page.fill("#target", "https://queue-c.example.com")
                page.click("#scanBtn")
                page.wait_for_timeout(200)
                check(job_sequence[0] == int(queue_a.rsplit("live", 1)[1]) and
                      page.evaluate("window.CELSIUS.state.activeJob.id") == queue_a,
                      "queued C started before A completed")

                add_mock_job("job-external-b", "https://external-b.example.com")
                page.evaluate("window.CELSIUS.jobs.refresh()")
                page.set_viewport_size({"width": 720, "height": 900})
                page.click("#jobsBtn")
                page.wait_for_selector('#jobsList .jobs-open[data-job="job-external-b"]',
                                       timeout=6000)
                check(page.get_attribute("#jobsDrawer", "aria-modal") == "true" and
                      page.evaluate("() => document.querySelector('main').inert"),
                      "populated mobile drawer was not modal")
                page.keyboard.press("Shift+Tab")
                check(page.evaluate("""() => {
                    const buttons = [...document.querySelectorAll(
                        '#jobsDrawer button:not(:disabled)')].filter(
                            el => el.getClientRects().length);
                    return document.activeElement === buttons[buttons.length - 1];
                }"""), "mobile Shift+Tab did not wrap to the last job action")
                page.keyboard.press("Tab")
                check(page.evaluate("() => document.activeElement.id") == "jobsClose",
                      "mobile Tab did not wrap back to drawer Close")
                page.locator('#jobsList .jobs-open[data-job="job-external-b"]').click()
                page.wait_for_function(
                    "() => window.CELSIUS.state.activeJob && "
                    "window.CELSIUS.state.activeJob.id === 'job-external-b'", timeout=6000)
                check(page.evaluate("() => document.activeElement.id") == "scanProgress" and
                      page.evaluate("() => !document.activeElement.closest('#jobsDrawer') && "
                                    "!document.querySelector('main').inert && "
                                    "!document.querySelector('.appbar').inert") and
                      page.get_attribute("#jobsDrawer", "aria-hidden") == "true",
                      "Open left focus in the hidden drawer or kept siblings inert")
                page.set_viewport_size({"width": 1280, "height": 900})

                external_polls = job_polls.get("job-external-b", 0)
                page.evaluate("""() => {
                    for (let i = 0; i < 5; i++) {
                        window.CELSIUS.watchJob('job-external-b', {});
                    }
                }""")
                page.wait_for_timeout(150)
                check(job_polls.get("job-external-b", 0) <= external_polls + 1,
                      "same-job Open accumulated duplicate external pollers")
                page.evaluate(f"""() => {{
                    window.CELSIUS.watchJob('{queue_a}', {{}});
                    window.CELSIUS.watchJob('job-external-b', {{}});
                }}""")
                check(page.evaluate("window.CELSIUS.state.activeJob.id") == "job-external-b",
                      "same-job re-entry did not restore the explicitly selected B")

                with page.expect_response("**/api/scan", timeout=10000):
                    mark_job_done(queue_a)
                check(job_posts[-1][0] == queue_c and
                      page.evaluate("window.CELSIUS.state.activeJob.id") == "job-external-b" and
                      page.evaluate("window.CELSIUS.state.currentScan") is None and
                      "external-b.example.com" in page.locator("#progTitle").inner_text(),
                      "background A completion/C start stole B or lost queue ownership")
                queue_a_posts = sum(payload.get("target") == "https://queue-a.example.com"
                                    for _, payload in job_posts)
                queue_c_posts = sum(payload.get("target") == "https://queue-c.example.com"
                                    for _, payload in job_posts)
                page.wait_for_timeout(1000)
                check(queue_a_posts == 1 and queue_c_posts == 1 and
                      sum(payload.get("target") == "https://queue-a.example.com"
                          for _, payload in job_posts) == queue_a_posts and
                      sum(payload.get("target") == "https://queue-c.example.com"
                          for _, payload in job_posts) == queue_c_posts,
                      "terminal queue job advanced more than once")
                mark_job_done(queue_c)
                page.wait_for_function(
                    "() => [...document.querySelectorAll('.toast')].some(t => "
                    "t.textContent.includes('Scan of https://queue-c.example.com finished.'))",
                    timeout=8000)
                check(page.evaluate("window.CELSIUS.state.activeJob.id") == "job-external-b" and
                      page.evaluate("window.CELSIUS.state.currentScan") is None,
                      "background C completion replaced external B state")
                mark_job_done("job-external-b")
                page.wait_for_function(
                    "() => window.CELSIUS.state.currentScan && "
                    "window.CELSIUS.state.currentScan.result.target === "
                    "'https://external-b.example.com'", timeout=8000)
                check(page.evaluate("window.CELSIUS.state.activeJob") is None and
                      page.locator("#progPhase").inner_text().strip() == "Complete" and
                      "external-b.example.com" in page.locator("#results .hero-target").inner_text(),
                      "explicitly opened external B did not render on successful completion")

                # A pending stored load cannot replace a newly accepted job state.
                held_pending = []
                pending_pattern = re.compile(r".*/api/scans/pending-new-scan$")
                page.route(pending_pattern, lambda route: held_pending.append(route))
                queue_a2 = f"job-live{job_sequence[0] + 1}"
                queue_c2 = f"job-live{job_sequence[0] + 2}"
                try:
                    page.evaluate("() => { window.CELSIUS.loadScan('pending-new-scan'); }")
                    check(wait_for_routes(held_pending, 1), "pending stored load was not issued")
                    page.fill("#target", "https://queue-stored-a.example.com")
                    with page.expect_request("**/api/scan"):
                        page.click("#scanBtn")
                    page.wait_for_function(
                        "(jid) => window.CELSIUS.state.activeJob && "
                        "window.CELSIUS.state.activeJob.id === jid", arg=queue_a2, timeout=6000)
                    held_pending.pop(0).fulfill(
                        json=job_result("https://stale-pending.example.org"))
                    page.wait_for_timeout(250)
                    check(page.evaluate("window.CELSIUS.state.currentScan") is None and
                          page.evaluate("window.CELSIUS.state.activeJob.id") == queue_a2 and
                          "stale-pending.example.org" not in page.locator("#results").inner_text(),
                          "pending stored response overwrote newly started job state")
                finally:
                    for held in held_pending:
                        held.fulfill(json=job_result("https://cleanup.example.org"))
                    page.unroute(pending_pattern)

                page.fill("#target", "https://queue-stored-c.example.com")
                page.click("#scanBtn")
                page.wait_for_timeout(200)
                page.evaluate("(scan) => window.CELSIUS.loadScan(scan)",
                              job_result("https://selected-stored.example.org"))
                with page.expect_response("**/api/scan", timeout=10000):
                    mark_job_done(queue_a2)
                check(job_posts[-1][0] == queue_c2 and
                      page.evaluate("window.CELSIUS.state.activeJob") is None and
                      page.evaluate("window.CELSIUS.state.currentScan.result.target")
                      == "https://selected-stored.example.org" and
                      "selected-stored.example.org" in
                      page.locator("#results .hero-target").inner_text(),
                      "queued successor stole the explicitly selected stored view")
                mark_job_done(queue_c2)
                page.wait_for_function(
                    "() => [...document.querySelectorAll('.toast')].some(t => "
                    "t.textContent.includes('Scan of https://queue-stored-c.example.com finished.'))",
                    timeout=8000)
                check(page.evaluate("window.CELSIUS.state.currentScan.result.target")
                      == "https://selected-stored.example.org",
                      "background queued successor replaced the stored result")
                page.wait_for_timeout(100)
                check(expected_500[0] == 0, "not all expected mocked HTTP errors reached the console")
            finally:
                for held in held_deletes:
                    held.fulfill(json={"status": "cancelling"})
                page.unroute(job_pattern)

            # ── final-review fixes: jobs-drawer View keeps scan_id (export links);
            #    dashboard tiles show "–" when the scan-detail fetch fails ──
            job_id, scan_id = "job-smoke1", "scan-smoke1"
            job_payload = {"job_id": job_id, "target": "https://example.com",
                           "status": "done", "scan_id": scan_id,
                           "result": dict(mock_scan)}
            hist_row = {"id": scan_id, "target": "https://example.com",
                        "url": "https://example.com", "grade": "D", "score": 42,
                        "worst": "CRITICAL", "n_findings": 3, "n_cves": 2,
                        "finished_at": "2026-07-22T00:00:00Z"}

            def mock_api(route):
                path = urllib.parse.urlparse(route.request.url).path
                if path == "/api/jobs":
                    route.fulfill(json={"jobs": [job_payload]})
                elif path == "/api/scan/" + job_id:
                    route.fulfill(json=job_payload)
                elif path == "/api/scans":
                    route.fulfill(json={"scans": [hist_row]})
                elif path == "/api/scans/" + scan_id:
                    route.fulfill(status=500, body="detail fetch broken")
                else:
                    route.continue_()

            # note: glob patterns did not match these URLs (query strings), so one regex route
            api_mock = re.compile(r".*/api/(jobs|scan/" + job_id + r"|scans(/" + scan_id + r")?)")
            page.route(api_mock, mock_api)
            try:
                # dash tiles: list OK but detail 500 → "–", not misleading 0s
                expected_500[0] = 1  # the mocked detail 500 logs one resource-load error
                page.locator('.tab[data-tab="dashboard"]').click()
                page.wait_for_function(
                    "() => { const m = document.querySelectorAll('#dashTiles .tile .metric');"
                    " return m.length === 6 && m[0].textContent.trim() === '–'; }",
                    timeout=6000)
                metrics = [t.inner_text().strip()
                           for t in page.locator("#dashTiles .tile .metric").all()]
                check(metrics[:4] == ["–"] * 4,
                      f"severity tiles should show – on detail-fetch failure (got {metrics[:4]})")
                check(metrics[4] == "2",
                      f"CVE tile should fall back to the history-row count (got {metrics[4]})")
                check(metrics[5] == "–",
                      f"Verified tile should show – on detail-fetch failure (got {metrics[5]})")

                # jobs drawer View → result renders with export links + scan id meta
                page.set_viewport_size({"width": 720, "height": 900})
                page.click("#jobsBtn")
                page.wait_for_selector(f'#jobsList .jobs-view[data-job="{job_id}"]', timeout=6000)
                page.click(f'#jobsList .jobs-view[data-job="{job_id}"]')
                page.wait_for_function(
                    "(sid) => { const el = document.querySelector('#results .metafoot-line');"
                    " return el && el.textContent.includes(sid); }",
                    arg=scan_id, timeout=6000)
                check(scan_id in (page.locator("#results .metafoot-line").inner_text() or ""),
                      "result from jobs-drawer View is missing the 'scan {id}' meta line")
                check(page.locator("#results .exports a.reportlink").count() >= 5,
                      "export links (HTML/json/md/sarif) missing after jobs-drawer View")
                check(page.evaluate("() => document.activeElement.id") == "results" and
                      page.evaluate("() => !document.activeElement.closest('#jobsDrawer') && "
                                    "!document.querySelector('main').inert && "
                                    "!document.querySelector('.appbar').inert") and
                      page.get_attribute("#jobsDrawer", "aria-hidden") == "true" and
                      page.get_attribute("#jobsDrawer", "aria-modal") == "false",
                      "View left focus in the hidden mobile drawer or failed inert restoration")
                page.set_viewport_size({"width": 1280, "height": 900})
            finally:
                page.unroute(api_mock)

            # A failed history request is not an empty scan store; Retry reloads it.
            dashboard_failure = re.compile(r".*/api/scans(?:\?.*)?$")

            def fail_dashboard_history(route):
                route.fulfill(status=500, json={"detail": "mock history unavailable (sanitized)"})

            page.route(dashboard_failure, fail_dashboard_history)
            try:
                expected_500[0] += 1
                page.locator('.tab[data-tab="dashboard"]').click()
                page.wait_for_selector("#dashHero .dash-empty-title", timeout=6000)
                check(page.locator("#dashHero .dash-empty-title").inner_text()
                      == "History unavailable" and
                      page.locator("#dashEmptyCta").inner_text() == "Retry",
                      "dashboard load failure was presented as 'No scans yet' or lacked Retry")
            finally:
                page.unroute(dashboard_failure)
            page.click("#dashEmptyCta")
            page.wait_for_selector("#dashHero .hero", timeout=6000)
            check(page.locator("#dashHero .dash-empty-title").count() == 0,
                  "dashboard Retry did not reload available history")
            page.wait_for_timeout(100)
            check(expected_500[0] == 0, "not all expected mocked HTTP errors reached the console")

            # Dashboard generations cover reversed list/detail responses and stale errors.
            def dashboard_row(scan_id, target):
                return {"id": scan_id, "target": target, "url": target,
                        "ip": "192.0.2.10", "grade": "A", "score": 90,
                        "worst": "NONE", "n_findings": 0, "n_cves": 0,
                        "finished_at": "2026-07-22T09:41:00Z"}

            held_dash_lists = []
            dash_list_pattern = re.compile(r".*/api/scans\?limit=8$")
            page.route(dash_list_pattern, lambda route: held_dash_lists.append(route))
            try:
                page.evaluate("() => { window.CELSIUS.dashboard.refresh(); }")
                check(wait_for_routes(held_dash_lists, 1), "first dashboard list was held")
                page.evaluate("() => { window.CELSIUS.dashboard.refresh(); }")
                check(wait_for_routes(held_dash_lists, 2), "second dashboard list was held")
                held_dash_lists.pop(1).fulfill(json={"scans": [
                    dashboard_row("dash-list-new", "https://dash-list-new.example.org")]})
                page.wait_for_function(
                    "() => document.querySelector('#dashHero .hero-verdict') && "
                    "document.querySelector('#dashHero .hero-verdict').textContent.includes("
                    "'dash-list-new.example.org')", timeout=6000)
                held_dash_lists.pop(0).fulfill(json={"scans": [
                    dashboard_row("dash-list-old", "https://dash-list-old.example.org")]})
                page.wait_for_timeout(250)
                check("dash-list-new.example.org" in
                      page.locator("#dashHero .hero-verdict").inner_text() and
                      "dash-list-old.example.org" not in page.locator("#dashHero").inner_text(),
                      "older dashboard list replaced the newer refresh")

                page.evaluate("() => { window.CELSIUS.dashboard.refresh(); }")
                check(wait_for_routes(held_dash_lists, 1), "third dashboard list was held")
                page.evaluate("() => { window.CELSIUS.dashboard.refresh(); }")
                check(wait_for_routes(held_dash_lists, 2), "fourth dashboard list was held")
                held_dash_lists.pop(1).fulfill(json={"scans": [
                    dashboard_row("dash-list-final", "https://dash-list-final.example.org")]})
                page.wait_for_function(
                    "() => document.querySelector('#dashHero .hero-verdict').textContent.includes("
                    "'dash-list-final.example.org')", timeout=6000)
                expected_500[0] += 1
                held_dash_lists.pop(0).fulfill(
                    status=500, json={"detail": "stale dashboard list failure"})
                page.wait_for_timeout(250)
                check("dash-list-final.example.org" in
                      page.locator("#dashHero .hero-verdict").inner_text() and
                      page.locator("#dashHero .dash-empty-title").count() == 0,
                      "stale dashboard list error replaced newer data")
            finally:
                for held in held_dash_lists:
                    held.fulfill(json={"scans": []})
                page.unroute(dash_list_pattern)

            def dashboard_detail(score):
                result = minimal_result("https://example.com")
                result["assessment"] = {"grade": "A", "score": score, "clean": True,
                                        "fix_first": [], "total_actionable": 0}
                return result

            held_dash_details = []
            dash_detail_pattern = re.compile(r".*/api/scans/scan-demo01$")
            page.route(dash_detail_pattern, lambda route: held_dash_details.append(route))
            try:
                page.evaluate("() => { window.CELSIUS.dashboard.refresh(); }")
                check(wait_for_routes(held_dash_details, 1), "first dashboard detail was held")
                page.evaluate("() => { window.CELSIUS.dashboard.refresh(); }")
                check(wait_for_routes(held_dash_details, 2), "second dashboard detail was held")
                held_dash_details.pop(1).fulfill(json=dashboard_detail(99))
                page.wait_for_function(
                    "() => document.querySelector('#dashHero .hero-score strong') && "
                    "document.querySelector('#dashHero .hero-score strong').textContent.trim() === '99'",
                    timeout=6000)
                held_dash_details.pop(0).fulfill(json=dashboard_detail(11))
                page.wait_for_timeout(250)
                check(page.locator("#dashHero .hero-score strong").inner_text().strip() == "99",
                      "older dashboard detail replaced the newer detail")

                page.evaluate("() => { window.CELSIUS.dashboard.refresh(); }")
                check(wait_for_routes(held_dash_details, 1), "third dashboard detail was held")
                page.evaluate("() => { window.CELSIUS.dashboard.refresh(); }")
                check(wait_for_routes(held_dash_details, 2), "fourth dashboard detail was held")
                held_dash_details.pop(1).fulfill(json=dashboard_detail(88))
                page.wait_for_function(
                    "() => document.querySelector('#dashHero .hero-score strong').textContent.trim() === '88'",
                    timeout=6000)
                expected_500[0] += 1
                held_dash_details.pop(0).fulfill(
                    status=500, json={"detail": "stale dashboard detail failure"})
                page.wait_for_timeout(250)
                check(page.locator("#dashHero .hero-score strong").inner_text().strip() == "88" and
                      page.locator("#dashHero .dash-empty-title").count() == 0,
                      "stale dashboard detail error replaced newer data")
            finally:
                for held in held_dash_details:
                    held.fulfill(json=dashboard_detail(0))
                page.unroute(dash_detail_pattern)
            page.wait_for_timeout(100)
            check(expected_500[0] == 0, "stale dashboard errors did not reach expected console count")
            page.evaluate("(scan) => window.CELSIUS.loadScan(scan)", mock_scan)
            page.wait_for_timeout(300)

            # ── screenshots (light + dark) ──
            if args.shot:
                prefix = args.shot
                page.screenshot(path=f"{prefix}-light.png", full_page=True)
                page.click("#themeToggle")
                page.wait_for_timeout(250)
                check(page.evaluate("document.documentElement.getAttribute('data-theme')") == "dark",
                      "theme toggle did not switch to dark")
                page.screenshot(path=f"{prefix}-dark.png", full_page=True)
                # attack-surface graph in dark mode (mock scan still loaded)
                page.click("#viewSurface")
                page.wait_for_timeout(500)
                page.screenshot(path=f"{prefix}-surface-dark.png", full_page=True)
                page.click("#viewFindings")
                page.wait_for_timeout(300)
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
    print("[✓] ui_smoke OK — setup validation, triage, coverage/auth fallback, "
          "active-job lifecycle, charts/surface/jobs/dashboard/theme, keyboard/focus/modal "
          "accessibility, contrast/reduced-motion/responsive history; zero console errors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
