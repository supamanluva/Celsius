"""Agentic active verification: an AI-driven prove-it loop.

The model is the *brain* — it reads the live attack surface and picks which
parameter to probe, with which benign detection payload, and what would prove the
bug. The lab *harness* is the guardrailed *hands* — every request goes through
LabContext (scope, attestation, request cap, rate-limit, kill-switch, audit). The
model then judges the real response; only proven issues become `verified`
findings. The AI never sends a request directly and never sees a way to mutate data.
"""

from __future__ import annotations

import re
from typing import Optional

from ..models import Finding, Severity
from . import cache as cache_mod
from . import prompts
from .analyze import _call, _to_sev, parse_json
from .provider import LLMProvider, Message

# Reject anything that could change state or be a heavy/blind payload — the loop
# is detection-only. (The harness also caps/rate-limits, this is defence in depth.)
_DESTRUCTIVE = re.compile(
    r"\b(drop|delete|truncate|insert\s+into|update\s+\w+\s+set|alter\s+table|"
    r"exec(\s|\()|shutdown|sleep\s*\(|benchmark\s*\(|pg_sleep|waitfor\s+delay|"
    r"load_file|outfile|dumpfile)\b|rm\s+-rf|\$\(|`",
    re.I,
)
_TECH_SEV = {"sqli-error": Severity.HIGH, "path-traversal": Severity.HIGH,
             "reflected-xss": Severity.HIGH, "ssrf": Severity.HIGH,
             "idor": Severity.HIGH, "open-redirect": Severity.MEDIUM}


def _safe_payload(p) -> bool:
    return isinstance(p, str) and 0 < len(p) <= 256 and not _DESTRUCTIVE.search(p)


def _plan(result_dict: dict, points, provider, budget, audit) -> list[dict]:
    context = {
        "url": result_dict.get("url") or result_dict.get("target"),
        "tech": (result_dict.get("recon") or {}).get("tech", []),
        "points": [{"point": i, "url": p.url, "method": p.method,
                    "params": p.param_names(), "origin": p.origin}
                   for i, p in enumerate(points)],
        "findings": [{"title": f.get("title"), "category": f.get("category")}
                     for f in result_dict.get("findings", [])][:40],
    }
    messages = [Message("system", prompts.AGENT_PLAN_SYSTEM),
                Message("user", prompts.plan_user_prompt(context))]
    resp = _call(provider, messages, json_mode=True, budget=budget, use_cache=True, audit=audit)
    data = parse_json(resp) or {}
    return data.get("probes", []) or []


def _execute(probe: dict, points, lab):
    """Build the request from the model's plan and send it through the harness."""
    try:
        pt = points[int(probe.get("point"))]
    except (ValueError, TypeError, IndexError):
        return None
    param = probe.get("param")
    payload = probe.get("payload")
    if param not in pt.params or not _safe_payload(payload):
        return None
    from ..active.harness import build_url
    params = dict(pt.params)
    params[param] = payload
    if pt.method == "POST":
        return lab.send(pt.url, method="POST", data=params,
                        purpose=f"ai:{probe.get('technique', 'probe')}")
    return lab.send(build_url(pt.url, params), method="GET", follow=False,
                    purpose=f"ai:{probe.get('technique', 'probe')}")


def _judge(probe: dict, resp, provider, budget, audit) -> dict:
    response = {"status": resp.status, "location": resp.location,
                "body_snippet": (resp.body or "")[:4000]}
    messages = [Message("system", prompts.AGENT_JUDGE_SYSTEM),
                Message("user", prompts.judge_user_prompt(probe, response))]
    out = _call(provider, messages, json_mode=True, budget=budget, use_cache=True, audit=audit)
    return parse_json(out) or {}


def agentic_verify(result_dict: dict, points, provider: LLMProvider, lab, *,
                   budget: Optional[cache_mod.Budget] = None, audit=None,
                   log=lambda _m: None, max_probes: int = 8) -> list[Finding]:
    """Plan -> execute (guardrailed) -> judge. Returns confirmed `verified` findings."""
    if not points:
        return []
    probes = _plan(result_dict, points, provider, budget, audit)
    log(f"ai-verify: model proposed {len(probes)} probe(s)")
    findings: list[Finding] = []
    for probe in probes[:max_probes]:
        ok, _why = lab.can_send()
        if not ok:
            break
        if not _safe_payload(probe.get("payload")):
            continue
        resp = _execute(probe, points, lab)
        if resp is None:
            continue
        verdict = _judge(probe, resp, provider, budget, audit)
        if str(verdict.get("confirmed")).lower() not in ("true", "1", "yes"):
            continue
        tech = probe.get("technique", "other")
        sev = _to_sev(verdict.get("severity")) if verdict.get("severity") else \
            _TECH_SEV.get(tech, Severity.MEDIUM)
        findings.append(Finding(
            title=f"[AI-verified] {tech}: {probe.get('hypothesis', 'vulnerability')}"[:140],
            severity=sev, category="ai-active-verify",
            description=(verdict.get("reasoning", "") + " "
                         + "Confirmed by an AI-planned, benign active probe on an authorized "
                           "lab target (response judged to prove the issue)."),
            recommendation="Treat as verified — remediate the input handling for "
                           f"parameter '{probe.get('param')}'.",
            evidence=f"{tech} payload={probe.get('payload')!r} :: {verdict.get('evidence', '')}"[:300],
            confidence="high",
            exploitability={"verdict": "confirmed-exploitable", "priority": 90,
                            "signals": {"reachable": True, "actively_verified": True,
                                        "ai_planned": True}},
        ))
        log(f"ai-verify: CONFIRMED {tech} on param '{probe.get('param')}'")
    return findings
