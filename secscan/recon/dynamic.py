"""Optional dynamic crawler via Playwright (headless Chromium).

Used only when Playwright is installed AND browsers are provisioned:
    pip install playwright && playwright install chromium

It renders SPAs and captures the network requests the page actually makes —
surfacing XHR/fetch endpoints that never appear in static HTML. If anything is
missing we degrade silently and the static crawler covers the basics.
"""

from __future__ import annotations


def is_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def crawl(url: str, *, timeout_ms: int = 15000) -> tuple[dict, list[str]]:
    """Render `url`, capture requested URLs + final HTML. Returns (info, errors).

    info = {"requests": [...], "html": "...", "endpoints": [...]}.
    """
    errors: list[str] = []
    if not is_available():
        return {}, ["playwright not installed"]
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {}, ["playwright import failed"]

    requests: list[str] = []
    html = ""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(user_agent="secscan/0.5 (+authorized security testing)")
            page.on("request", lambda req: requests.append(req.url))
            page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            html = page.content()
            browser.close()
    except Exception as e:  # playwright raises many runtime errors (no browser, nav, ...)
        return {}, [f"playwright crawl failed: {e}"]

    # endpoints = same-host XHR/fetch-looking requests
    import urllib.parse
    host = urllib.parse.urlparse(url).netloc
    endpoints = sorted({
        r for r in requests
        if urllib.parse.urlparse(r).netloc == host
        and any(seg in r for seg in ("/api", "/graphql", "/v1", "/v2", "/rest"))
    })
    return {"requests": sorted(set(requests))[:300], "html": html, "endpoints": endpoints}, errors
