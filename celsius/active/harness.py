"""Safety harness for lab-mode active verification.

`LabContext` is the single chokepoint through which every active request flows.
It enforces: lab-mode enabled, per-run attestation, request cap, rate limit, a
kill-switch file, dry-run preview, and an audit record for every request.

`discover_points` finds injectable parameters (base-URL query, page forms, and
links with query strings) so verifiers have somewhere to test. When handed the
scan's recon dict it also folds in the attack surface the passive phase already
collected (crawl endpoints/routes, wayback URLs + parameter names, sitemap
URLs) — capped so the extra points can't blow the request budget.
"""

from __future__ import annotations

import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Optional

from ..auth import AuthSession   # lightweight, cycle-free (auth imports no celsius)

if TYPE_CHECKING:
    from ..audit import AuditLog

USER_AGENT = "celsius/0.7 (+authorized lab testing)"
TIMEOUT = 10
KILLSWITCH = os.path.expanduser("~/.celsius-stop")

# Sentinel: "use the context's default auth". Distinct from None, which means
# "send this request with NO auth" (needed by the IDOR/BOLA probe to replay the
# same request as a different identity or anonymously).
_KEEP_AUTH = object()


@dataclass
class Response:
    status: int
    headers: dict
    body: str
    location: Optional[str]
    final_url: str


@dataclass
class Point:
    """An injectable request point."""
    url: str                       # base URL (without the injected value)
    method: str                    # GET | POST
    params: dict                   # all params (param -> current value)
    origin: str = ""               # where it was discovered

    def param_names(self) -> list[str]:
        return list(self.params.keys())


@dataclass
class LabContext:
    host: str
    enabled: bool
    attested: bool
    audit: "AuditLog"
    dry_run: bool = False
    rate_limit_rps: float = 5.0
    max_requests: int = 200
    insecure: bool = False
    log: Optional[Callable[[str], None]] = None
    auth: Optional["AuthSession"] = None   # authenticated active checks
    _count: int = 0
    _last_ts: float = 0.0
    preview: list = field(default_factory=list)
    stopped_reason: str = ""

    # ---- gating ----
    def ready(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "lab mode not enabled"
        if not self.attested:
            return False, "no per-run attestation provided"
        return True, ""

    def _killed(self) -> bool:
        return os.path.exists(KILLSWITCH)

    def can_send(self) -> tuple[bool, str]:
        if self.stopped_reason:
            return False, self.stopped_reason
        if self._killed():
            self.stopped_reason = f"kill-switch present ({KILLSWITCH})"
            return False, self.stopped_reason
        if self._count >= self.max_requests:
            self.stopped_reason = f"request cap reached ({self.max_requests})"
            return False, self.stopped_reason
        return True, ""

    def _throttle(self) -> None:
        if self.rate_limit_rps <= 0:
            return
        min_gap = 1.0 / self.rate_limit_rps
        dt = time.time() - self._last_ts
        if dt < min_gap:
            time.sleep(min_gap - dt)
        self._last_ts = time.time()

    # ---- the only way to make an active request ----
    def send(self, url: str, *, method: str = "GET", data: Optional[dict] = None,
             purpose: str = "", follow: bool = False, payload: bool = True,
             headers: Optional[dict] = None, auth_override=_KEEP_AUTH,
             raw_body: Optional[bytes] = None) -> Optional[Response]:
        """Make a gated request. `payload=False` marks a benign discovery fetch
        (a plain page GET) that is still performed under --dry-run, since dry-run
        only suppresses the actual probe payloads. `headers` adds extra request
        headers (e.g. Origin/Authorization) for read-only probes."""
        ok, why = self.can_send()
        if not ok:
            if self.log:
                self.log(f"lab: halted ({why})")
            return None
        # audit EVERY active request, including dry-run
        self.audit.event("lab_request", host=self.host, purpose=purpose,
                         method=method, url=url[:300], dry_run=self.dry_run, payload=payload)
        if self.dry_run and payload:
            self.preview.append({"purpose": purpose, "method": method, "url": url})
            return None
        self._throttle()
        self._count += 1
        return self._raw(url, method, data, follow, headers, auth_override, raw_body)

    def _raw(self, url, method, data, follow, extra_headers=None,
             auth_override=_KEEP_AUTH, raw_body=None) -> Optional[Response]:
        ctx = ssl.create_default_context()
        if self.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        body_bytes = None
        session = self.auth if auth_override is _KEEP_AUTH else auth_override
        headers = (session.merge({"User-Agent": USER_AGENT})
                   if isinstance(session, AuthSession) and session
                   else {"User-Agent": USER_AGENT})
        if extra_headers:
            for k, v in extra_headers.items():
                if isinstance(k, str) and isinstance(v, str):
                    headers[k] = v
        if raw_body is not None:
            # arbitrary body (e.g. an XML document for XXE); the caller supplies the
            # Content-Type via `headers`, else default to octet-stream.
            body_bytes = raw_body if isinstance(raw_body, bytes) else str(raw_body).encode()
            headers.setdefault("Content-Type", "application/octet-stream")
        elif method == "POST" and data is not None:
            body_bytes = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPSHandler(context=ctx)]
        if not follow:
            handlers.append(_NoRedirect())
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
        try:
            with opener.open(req, timeout=TIMEOUT) as resp:
                h = {k.lower(): v for k, v in resp.headers.items()}
                return Response(resp.status, h, resp.read(400_000).decode("utf-8", "replace"),
                                h.get("location"), resp.geturl())
        except urllib.error.HTTPError as e:
            h = {k.lower(): v for k, v in (e.headers or {}).items()}
            try:
                body = e.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            return Response(e.code, h, body, h.get("location"), url)
        except (urllib.error.URLError, ssl.SSLError, OSError, ValueError):
            return None


# ---- injectable-point discovery ----------------------------------------------

_FORM = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_ACTION = re.compile(r"""action\s*=\s*['"]([^'"]+)['"]""", re.I)
_METHOD = re.compile(r"""method\s*=\s*['"]([^'"]+)['"]""", re.I)
_INPUT = re.compile(r"""<(?:input|textarea|select)\b[^>]*\bname\s*=\s*['"]([^'"]+)['"]""", re.I)
_HREF = re.compile(r"""href\s*=\s*['"]([^'"#]+\?[^'"#]+)['"]""", re.I)

# Cap on points derived from passive recon (crawl/wayback/sitemap) so lab
# verifiers can't be steered into burning the whole request budget on surface
# that was already seen passively.
_MAX_RECON_POINTS = 50
# Cap on archived parameter names folded into a single point.
_MAX_RECON_PARAMS = 20
_PARAM_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")


def discover_points(base_url: str, lab: LabContext,
                    recon: Optional[dict] = None) -> list[Point]:
    points: list[Point] = []
    seen: set[str] = set()

    def add(url: str, method: str, params: dict, origin: str) -> bool:
        if not params:
            return False
        key = f"{method}:{url}:{','.join(sorted(params))}"
        if key not in seen:
            seen.add(key)
            points.append(Point(url=url, method=method, params=params, origin=origin))
            return True
        return False

    # base URL's own query params
    p = urllib.parse.urlparse(base_url)
    if p.query:
        params = {k: (v[0] if v else "") for k, v in urllib.parse.parse_qs(p.query).items()}
        add(base_url.split("?")[0], "GET", params, "target-url")

    # fetch the page to find forms + parameterized links (benign GET, not a payload)
    resp = lab.send(base_url, purpose="discover", follow=True, payload=False)
    if resp and resp.body:
        host = urllib.parse.urlparse(base_url).netloc
        for fm in _FORM.finditer(resp.body):
            tag = fm.group(0)
            action = _ACTION.search(tag)
            mm = _METHOD.search(tag)
            method = mm.group(1).upper() if mm else "GET"
            url = urllib.parse.urljoin(resp.final_url, action.group(1)) if action else resp.final_url
            names = _INPUT.findall(fm.group(1))
            if urllib.parse.urlparse(url).netloc in ("", host):
                add(url.split("?")[0], method, {n: "celsius" for n in names}, "form")
        for m in _HREF.finditer(resp.body):
            link = urllib.parse.urljoin(resp.final_url, m.group(1))
            lp = urllib.parse.urlparse(link)
            if lp.netloc != host:
                continue
            params = {k: (v[0] if v else "") for k, v in urllib.parse.parse_qs(lp.query).items()}
            add(link.split("?")[0], "GET", params, "link")

    # fold in the attack surface the passive phase already collected (no extra
    # requests needed — this data is already in ctx.result.recon)
    if recon:
        _add_recon_points(base_url, recon, add)

    return points


def _add_recon_points(base_url: str, recon: dict, add: Callable[..., bool]) -> None:
    """Turn passive-recon URLs/params into GET points (capped, same-host only).

    Crawled endpoints/routes and archived/sitemap URLs with query strings are
    tested with their own parameters; the parameter names the wayback harvest
    flagged as interesting are replayed against the base URL and against
    crawled endpoints that carried no query of their own.
    """
    host = urllib.parse.urlparse(base_url).netloc
    crawl = recon.get("crawl") or {}
    urls = (list(crawl.get("endpoints") or []) + list(crawl.get("routes") or [])
            + list(recon.get("wayback_urls") or [])
            + list(recon.get("sitemap_urls") or []))
    wb_params = [p for p in (recon.get("wayback_params") or [])
                 if _PARAM_NAME.match(str(p))][:_MAX_RECON_PARAMS]

    added = 0
    bare: list[str] = []          # same-host recon URLs with no query of their own
    for u in urls:
        if added >= _MAX_RECON_POINTS:
            break
        link = urllib.parse.urljoin(base_url, str(u))
        lp = urllib.parse.urlparse(link)
        if lp.netloc != host:
            continue
        if lp.query:
            params = {k: (v[0] if v else "") for k, v in urllib.parse.parse_qs(lp.query).items()}
            if add(link.split("?")[0], "GET", params, "recon"):
                added += 1
        else:
            bare.append(link.split("#")[0])

    if not wb_params:
        return
    # archived params -> base URL plus a sample of the query-less endpoints
    candidates = [base_url.split("?")[0]] + sorted(set(bare))
    for url in candidates:
        if added >= _MAX_RECON_POINTS:
            break
        if add(url, "GET", {p: "celsius" for p in wb_params}, "wayback-params"):
            added += 1


def build_url(base: str, params: dict) -> str:
    return base + "?" + urllib.parse.urlencode(params)
