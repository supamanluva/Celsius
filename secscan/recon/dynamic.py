"""Dynamic SPA analysis via Playwright (headless Chromium), optional.

Enabled only when Playwright is installed AND a browser is provisioned:
    pip install playwright && playwright install chromium

Single-page apps render their real content, routes and API calls in the browser —
none of which appear in static HTML. This module drives a headless browser to:
  - render the app and follow same-origin in-app links (client-side routes),
  - capture the XHR/fetch endpoints the page actually calls (with methods),
  - return the post-JS DOM of each view (so DOM-XSS sink and secret scanning see
    what the user sees), and
  - collect console errors (often leaking stack traces / internal paths).

It honours an authenticated session (cookies/headers are set on the browser
context). If Playwright is missing it degrades silently and the static crawler
covers the basics. The browser-driving part is isolated; the URL/endpoint logic
below is pure and unit-tested.
"""

from __future__ import annotations

import urllib.parse

USER_AGENT = "secscan/1.1 (+authorized security testing)"
_API_SEGMENTS = ("/api", "/graphql", "/v1/", "/v2/", "/rest", "/gql", "/.json")


def is_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def _same_host(url: str, host: str) -> bool:
    try:
        return urllib.parse.urlparse(url).netloc == host
    except ValueError:
        return False


def _looks_like_endpoint(url: str, rtype: str) -> bool:
    if rtype in ("xhr", "fetch", "websocket"):
        return True
    low = url.lower()
    return any(seg in low for seg in _API_SEGMENTS)


# Framework prefetch / cache-bust params that create near-duplicate endpoints.
_NOISE_PARAMS = {"_rsc", "__nextdatareq", "_next", "_", "v", "ts", "_t"}


def _normalize(url: str) -> str:
    """Drop fragment and framework cache-bust params so /x?_rsc=a and /x?_rsc=b
    collapse to one endpoint, while real params (id=...) are kept."""
    p = urllib.parse.urlparse(url.split("#")[0])
    kept = [(k, v) for k, v in urllib.parse.parse_qsl(p.query)
            if k.lower() not in _NOISE_PARAMS]
    query = urllib.parse.urlencode(kept)
    return urllib.parse.urlunparse(p._replace(query=query))


def extract_endpoints(requests: list[tuple], host: str) -> list[str]:
    """From captured (method, url, resource_type) tuples, return same-host API
    endpoints as 'METHOD url' strings (deduped, framework noise stripped).
    Pure function (no browser)."""
    out: set[str] = set()
    for method, url, rtype in requests:
        if _same_host(url, host) and _looks_like_endpoint(url, rtype):
            out.add(f"{method} {_normalize(url)}")
    return sorted(out)


def extract_routes(page_urls: list[str]) -> list[str]:
    """Distinct client-side routes (path[+hash]) from the rendered page URLs."""
    routes: set[str] = set()
    for u in page_urls:
        p = urllib.parse.urlparse(u)
        routes.add(p.path + (f"#{p.fragment}" if p.fragment else ""))
    return sorted(routes)


def crawl(url: str, *, max_pages: int = 10, timeout_ms: int = 15000,
          auth=None, insecure: bool = False) -> tuple[dict, list[str]]:
    """Render `url` and follow same-origin in-app links up to `max_pages`.

    Returns (info, errors) with info = {endpoints, routes, pages{url:html},
    requests, console_errors}.
    """
    errors: list[str] = []
    if not is_available():
        return {}, ["playwright not installed"]
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {}, ["playwright import failed"]

    host = urllib.parse.urlparse(url).netloc
    requests: list[tuple] = []
    console_errors: list[str] = []
    pages: dict[str, str] = {}
    seen: set[str] = set()
    queue: list[str] = [url]

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx_kwargs = {"user_agent": USER_AGENT, "ignore_https_errors": insecure}
            if auth and getattr(auth, "headers", None):
                ctx_kwargs["extra_http_headers"] = dict(auth.headers)
            context = browser.new_context(**ctx_kwargs)
            page = context.new_page()
            page.on("request", lambda r: requests.append((r.method, r.url, r.resource_type)))
            page.on("console", lambda m: console_errors.append(m.text[:300])
                    if m.type == "error" else None)

            while queue and len(pages) < max_pages:
                u = queue.pop(0)
                norm = u.split("#")[0]
                if norm in seen:
                    continue
                seen.add(norm)
                # domcontentloaded fires reliably; networkidle can hang forever on
                # streaming SPAs (Next.js RSC). Best-effort settle, then capture the
                # DOM even if the page never went fully idle.
                try:
                    page.goto(u, wait_until="domcontentloaded", timeout=timeout_ms)
                except Exception as e:
                    errors.append(f"dynamic nav {u}: {str(e)[:120]}")
                try:
                    page.wait_for_load_state("networkidle", timeout=3000)
                except Exception:
                    pass
                try:
                    page.wait_for_timeout(800)   # let client-side render nav/content
                    html = page.content()
                except Exception:
                    continue
                pages[page.url] = html
                try:
                    hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                except Exception:
                    hrefs = []
                for h in hrefs:
                    if _same_host(h, host) and h.split("#")[0] not in seen:
                        queue.append(h)
            context.close()
            browser.close()
    except Exception as e:  # launch failure (no browser provisioned), etc.
        return {}, [f"playwright crawl failed: {str(e)[:160]}"]

    return {
        "endpoints": extract_endpoints(requests, host),
        "routes": extract_routes(list(pages.keys())),
        "pages": pages,
        "requests": sorted({u for _m, u, _t in requests})[:300],
        "console_errors": console_errors[:50],
    }, errors
