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
    print("[✓] ui_smoke OK — tabs, authorization gate, theme toggle; zero console errors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
