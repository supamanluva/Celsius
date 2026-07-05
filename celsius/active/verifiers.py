"""Non-destructive active verifiers.

Each turns a *suspicion* into a confirmed/refuted result against an authorized
lab target. Payloads are deliberately benign:
  - reflected XSS: a unique marker with a few HTML metacharacters; we only check
    whether it comes back UNescaped (proof of reflection context) — no live exploit.
  - open redirect: a canary URL; we only check whether the server would redirect
    off-host. We never follow it.
  - path traversal: a read-only canary; we look for a passwd-style signature.
  - SQLi: a single quote; we look for a database error signature.
All run through LabContext.send (caps, rate-limit, dry-run, kill-switch, audit).
"""

from __future__ import annotations

import re

from ..models import Finding, Severity
from .canary import OOBCanary
from .harness import LabContext, Point, build_url

# A unique, benign marker. Contains metacharacters so we can tell escaped from raw.
_XSS_MARKER = "sScAn7Zq'\"<x>"
_XSS_RAW = re.compile(re.escape("<x>"))           # raw, unescaped reflection
_REDIRECT_CANARY = "https://celsius-canary.example/redir"
_TRAVERSAL = "../../../../../../etc/passwd"
_PASSWD_SIG = re.compile(r"root:.*?:0:0:")
_SQL_ERRORS = re.compile(
    r"SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite/JDBC|"
    r"Unclosed quotation mark|quoted string not properly terminated|"
    r"you have an error in your sql", re.I)


def _confirm(title, sev, point, param, payload, detail, evidence) -> Finding:
    return Finding(
        title=title, severity=sev, category="active-verify",
        description=detail,
        recommendation="Confirmed via a benign active probe on an authorized lab "
                       "target. Remediate the input handling.",
        evidence=f"{point.method} {point.url} param={param} payload={payload!r} :: {evidence}"[:300],
        confidence="high",
        exploitability={"verdict": "confirmed-exploitable", "priority": 90,
                        "signals": {"reachable": True, "actively_verified": True}},
    )


def _send_with(point: Point, param: str, value: str, lab: LabContext, purpose: str):
    params = dict(point.params)
    params[param] = value
    if point.method == "POST":
        return lab.send(point.url, method="POST", data=params, purpose=purpose)
    return lab.send(build_url(point.url, params), method="GET", purpose=purpose,
                    follow=False)


def reflected_xss(points: list[Point], lab: LabContext) -> list[Finding]:
    out = []
    for pt in points:
        for param in pt.param_names():
            r = _send_with(pt, param, _XSS_MARKER, lab, "xss-reflect")
            if r is None or not r.body:
                continue
            if _XSS_RAW.search(r.body):
                out.append(_confirm(
                    "Reflected XSS confirmed (unescaped marker)", Severity.HIGH,
                    pt, param, _XSS_MARKER,
                    "A unique marker containing <x> was reflected UNescaped in the "
                    "response, proving an HTML-injection context (reflected XSS).",
                    "marker reflected raw"))
    return out


def open_redirect(points: list[Point], lab: LabContext) -> list[Finding]:
    out = []
    hint = re.compile(r"^(url|redirect|next|return|returnurl|dest|destination|continue|to|r|u)$", re.I)
    for pt in points:
        for param in pt.param_names():
            if not hint.match(param):
                continue
            r = _send_with(pt, param, _REDIRECT_CANARY, lab, "open-redirect")
            if r is None:
                continue
            loc = (r.location or "")
            if r.status in (301, 302, 303, 307, 308) and "celsius-canary.example" in loc:
                out.append(_confirm(
                    "Open redirect confirmed", Severity.MEDIUM, pt, param,
                    _REDIRECT_CANARY,
                    f"The server issued a {r.status} redirect to an attacker-supplied "
                    "external URL (canary). Usable for phishing/token theft.",
                    f"Location: {loc[:120]}"))
    return out


def path_traversal(points: list[Point], lab: LabContext) -> list[Finding]:
    out = []
    hint = re.compile(r"(file|path|page|name|doc|template|include|load|read)", re.I)
    for pt in points:
        for param in pt.param_names():
            if not hint.search(param):
                continue
            r = _send_with(pt, param, _TRAVERSAL, lab, "path-traversal")
            if r is None or not r.body:
                continue
            if _PASSWD_SIG.search(r.body):
                out.append(_confirm(
                    "Path traversal confirmed (file read)", Severity.HIGH, pt, param,
                    _TRAVERSAL,
                    "A traversal payload returned a passwd-style signature, proving "
                    "arbitrary file read.", "root:...:0:0: in response"))
    return out


def sqli_error(points: list[Point], lab: LabContext) -> list[Finding]:
    out = []
    for pt in points:
        for param in pt.param_names():
            base = pt.params.get(param) or "1"
            r = _send_with(pt, param, base + "'", lab, "sqli-error")
            if r is None or not r.body:
                continue
            if _SQL_ERRORS.search(r.body):
                out.append(_confirm(
                    "SQL injection indicated (database error)", Severity.HIGH, pt, param,
                    base + "'",
                    "Appending a single quote triggered a database error, indicating "
                    "the parameter is concatenated into a SQL query.",
                    "SQL error signature in response"))
    return out


# Parameter names that plausibly carry a URL/host the server fetches — the SSRF
# surface. A substring match keeps it broad; the probe only *confirms* on a real
# out-of-band callback, so a loose hint costs a wasted request, not a false report.
_SSRF_HINT = re.compile(
    r"url|uri|link|src|source|dest|target|redirect|redir|feed|rss|webhook|"
    r"callback|fetch|proxy|forward|host|domain|site|image|img|remote|load|"
    r"open|reference|ref|continue|return|preview|resource|endpoint|avatar|upload",
    re.I)


def ssrf_oob(points: list[Point], lab: LabContext, canary: OOBCanary,
             *, wait_timeout: float = 3.0) -> list[Finding]:
    """Blind-SSRF probe: inject a unique OOB callback URL into URL-ish params and
    confirm ONLY if the target actually fetches it (a recorded canary hit).

    The proof is deterministic and independent of the response the target returns —
    a hit means something on the target's side made an outbound request to a URL we
    minted, which is exactly what SSRF is. Runs through LabContext.send (scope,
    caps, rate-limit, attestation, kill-switch, audit); the canary URL is benign
    (a plain GET target that just records the hit). `wait_timeout` bounds how long
    to wait for a (possibly slightly delayed) server-side fetch per probe."""
    out: list[Finding] = []
    for pt in points:
        for param in pt.param_names():
            if not _SSRF_HINT.search(param):
                continue
            ok, _why = lab.can_send()
            if not ok:
                return out
            token = canary.new_token()
            payload = canary.url_for(token)
            _send_with(pt, param, payload, lab, "ssrf-oob")
            if not canary.wait_for_hit(token, timeout=wait_timeout):
                continue
            src = (canary.hits(token)[0].src_ip if canary.hits(token) else "?")
            out.append(_confirm(
                "Blind SSRF confirmed (out-of-band callback)", Severity.HIGH,
                pt, param, payload,
                "The server made an outbound request to a unique attacker-controlled "
                "URL injected into this parameter — proving server-side request "
                "forgery. Reachable internal services / cloud metadata may be exposed.",
                f"canary callback received from {src}"))
    return out


def run_ssrf_oob(points: list[Point], lab: LabContext, *,
                 host: str | None = None, bind: str = "127.0.0.1",
                 port: int = 0) -> list[Finding]:
    """Convenience wrapper that owns the canary lifecycle. `host` is the address the
    target should call back to (a LAN/public IP the target can route to); it
    defaults to the bind address, which only works when the target is local."""
    with OOBCanary(host=host or bind, bind=bind, port=port) as canary:
        return ssrf_oob(points, lab, canary)


ALL_VERIFIERS = [
    ("reflected-xss", reflected_xss),
    ("open-redirect", open_redirect),
    ("path-traversal", path_traversal),
    ("sqli-error", sqli_error),
]


def run_all(points: list[Point], lab: LabContext) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    ran: list[str] = []
    for name, fn in ALL_VERIFIERS:
        ok, _ = lab.can_send()
        if not ok:
            break
        findings.extend(fn(points, lab))
        ran.append(name)
    return findings, ran
