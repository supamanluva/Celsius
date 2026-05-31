"""Safety harness for lab-mode active verification.

`LabContext` is the single chokepoint through which every active request flows.
It enforces: lab-mode enabled, per-run attestation, request cap, rate limit, a
kill-switch file, dry-run preview, and an audit record for every request.

`discover_points` finds injectable parameters (base-URL query, page forms, and
links with query strings) so verifiers have somewhere to test.
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
from typing import Optional

USER_AGENT = "secscan/0.7 (+authorized lab testing)"
TIMEOUT = 10
KILLSWITCH = os.path.expanduser("~/.secscan-stop")


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
    audit: object
    dry_run: bool = False
    rate_limit_rps: float = 5.0
    max_requests: int = 200
    insecure: bool = False
    log: object = None
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
             purpose: str = "", follow: bool = False, payload: bool = True) -> Optional[Response]:
        """Make a gated request. `payload=False` marks a benign discovery fetch
        (a plain page GET) that is still performed under --dry-run, since dry-run
        only suppresses the actual probe payloads."""
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
        return self._raw(url, method, data, follow)

    def _raw(self, url, method, data, follow) -> Optional[Response]:
        ctx = ssl.create_default_context()
        if self.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        body_bytes = None
        headers = {"User-Agent": USER_AGENT}
        if method == "POST" and data is not None:
            body_bytes = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        handlers = [urllib.request.HTTPSHandler(context=ctx)]
        if not follow:
            handlers.append(_NoRedirect)
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


def discover_points(base_url: str, lab: LabContext) -> list[Point]:
    points: list[Point] = []
    seen: set[str] = set()

    def add(url: str, method: str, params: dict, origin: str):
        if not params:
            return
        key = f"{method}:{url}:{','.join(sorted(params))}"
        if key not in seen:
            seen.add(key)
            points.append(Point(url=url, method=method, params=params, origin=origin))

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
            method = (_METHOD.search(tag).group(1).upper() if _METHOD.search(tag) else "GET")
            url = urllib.parse.urljoin(resp.final_url, action.group(1)) if action else resp.final_url
            names = _INPUT.findall(fm.group(1))
            if urllib.parse.urlparse(url).netloc in ("", host):
                add(url.split("?")[0], method, {n: "secscan" for n in names}, "form")
        for m in _HREF.finditer(resp.body):
            link = urllib.parse.urljoin(resp.final_url, m.group(1))
            lp = urllib.parse.urlparse(link)
            if lp.netloc != host:
                continue
            params = {k: (v[0] if v else "") for k, v in urllib.parse.parse_qs(lp.query).items()}
            add(link.split("?")[0], "GET", params, "link")

    return points


def build_url(base: str, params: dict) -> str:
    return base + "?" + urllib.parse.urlencode(params)
