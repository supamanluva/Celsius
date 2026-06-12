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


_SQL_ERR = re.compile(
    r"SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*?ERROR|psql:|SQLite3::|"
    r"System\.Data\.SQLite|Unclosed quotation mark|quoted string not properly "
    r"terminated|syntax error at or near|Microsoft OLE DB", re.I)
_FILE_LEAK = re.compile(r"root:.*?:0:0:|\[(?:fonts|extensions|boot loader)\]", re.I)


def _corroborated(probe: dict, resp) -> bool:
    """Deterministic backstop before a model verdict is trusted as `verified`.

    The judge sees target-controlled response content, so a confirmation must be
    independently grounded in the real response — the exact payload reflected, a
    SQL error signature, a file-leak marker, or the payload driving a redirect —
    otherwise an injected/hallucinated 'confirmed' could mint a false verified
    finding. Returns True only when such proof is present.
    """
    body = resp.body or ""
    tech = (probe.get("technique") or "").lower()
    payload = str(probe.get("payload") or "").strip()
    if payload and len(payload) >= 4 and payload in body:
        return True                                  # reflection (XSS/SSTI/etc.)
    if "sql" in tech and _SQL_ERR.search(body):
        return True
    if ("travers" in tech or "lfi" in tech or "file" in tech) and _FILE_LEAK.search(body):
        return True
    if "redirect" in tech and payload and payload in (resp.location or ""):
        return True
    return False


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
        # The model judged this confirmed off target-controlled content. Require
        # deterministic proof in the real response before minting a *verified*
        # finding; otherwise keep it as an unverified lead (never priority-90).
        if not _corroborated(probe, resp):
            findings.append(Finding(
                title=f"[AI lead — unconfirmed] {tech}: {probe.get('hypothesis', 'potential issue')}"[:140],
                severity=Severity.LOW, category="ai-hypothesis",
                description=(verdict.get("reasoning", "") + " "
                             "The model judged this confirmed, but the response carried no "
                             "deterministic proof (payload reflection / error signature), so it "
                             "is recorded as an unverified lead — verify manually."),
                recommendation=f"Manually verify parameter '{probe.get('param')}' before acting.",
                evidence=f"{tech} payload={probe.get('payload')!r}"[:300],
                confidence="low",
            ))
            log(f"ai-verify: UNCORROBORATED {tech} on '{probe.get('param')}' — kept as a lead")
            continue
        sev = _to_sev(verdict.get("severity")) if verdict.get("severity") else \
            _TECH_SEV.get(tech, Severity.MEDIUM)
        findings.append(Finding(
            title=f"[AI-verified] {tech}: {probe.get('hypothesis', 'vulnerability')}"[:140],
            severity=sev, category="ai-active-verify",
            description=(verdict.get("reasoning", "") + " "
                         + "Confirmed by an AI-planned, benign active probe on an authorized "
                           "lab target (response independently corroborated the issue)."),
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


def prove_hypotheses(result_dict: dict, hypotheses: list[dict], provider: LLMProvider,
                     lab, *, budget: Optional[cache_mod.Budget] = None, audit=None,
                     log=lambda _m: None, max_calls: int = 10) -> list[dict]:
    """Tool-using loop: prove/refute each AI hypothesis with safe read-only tools.

    `hypotheses` is a list of finding dicts (category 'ai-hypothesis'). The model
    picks a tool per hypothesis, the dispatcher runs it (host-locked, guardrailed),
    and the model judges the evidence. Returns verdicts:
    {"index", "status": confirmed|refuted|inconclusive|needs-manual,
     "severity", "reasoning", "evidence", "tool"}.
    """
    from . import verify_tools
    if not hypotheses:
        return []
    hyp_view = [{"index": i, "title": h.get("title", ""), "detail": (h.get("description") or "")[:300]}
                for i, h in enumerate(hypotheses)]
    context = {
        "url": result_dict.get("url") or result_dict.get("target"),
        "host": getattr(lab, "host", ""),
        "services": [{"name": s.get("name"), "port": s.get("port"), "version": s.get("version")}
                     for s in result_dict.get("services", [])][:20],
    }
    messages = [Message("system", prompts.AGENT_TOOL_SYSTEM),
                Message("user", prompts.tool_plan_prompt(hyp_view, verify_tools.TOOL_SPECS, context))]
    plan = parse_json(_call(provider, messages, json_mode=True, budget=budget,
                            use_cache=True, audit=audit)) or {}
    plans = plan.get("plans", []) or []
    log(f"ai-prove: planned {len(plans)} tool call(s) for {len(hypotheses)} hypothesis(es)")

    verdicts: list[dict] = []
    used = 0
    for p in plans:
        try:
            idx = int(p.get("hypothesis"))
            hyp = hypotheses[idx]
        except (ValueError, TypeError, IndexError):
            continue
        tool = p.get("tool")
        if tool in (None, "", "none"):
            verdicts.append({"index": idx, "status": "needs-manual", "tool": "none",
                             "reasoning": "no safe read-only tool can settle this"})
            continue
        if used >= max_calls:
            break
        ok, _why = lab.can_send()
        if not ok:
            break
        evidence = verify_tools.run_tool(tool, p.get("args") or {}, lab)
        used += 1
        if evidence is None:
            verdicts.append({"index": idx, "status": "inconclusive", "tool": tool,
                             "reasoning": "invalid tool call"})
            continue
        jmsg = [Message("system", prompts.AGENT_PROVE_JUDGE_SYSTEM),
                Message("user", prompts.prove_judge_prompt(
                    {"title": hyp.get("title"), "detail": hyp.get("description")}, evidence))]
        v = parse_json(_call(provider, jmsg, json_mode=True, budget=budget,
                             use_cache=True, audit=audit)) or {}
        status = str(v.get("status", "inconclusive")).lower()
        if status not in ("confirmed", "refuted", "inconclusive"):
            status = "inconclusive"
        verdicts.append({"index": idx, "status": status, "severity": v.get("severity"),
                         "reasoning": v.get("reasoning", ""), "evidence": v.get("evidence", ""),
                         "tool": tool, "poc": (evidence or {}).get("curl")})
        log(f"ai-prove: {status.upper()} — {hyp.get('title', '')[:60]} (via {tool})")
    return verdicts


def apply_verdicts(findings: list, verdicts: list[dict]) -> tuple[list, dict]:
    """Rewrite the findings list (Finding objects) given prove/refute verdicts,
    matched to the ai-hypothesis findings in order.

    confirmed -> retagged 'ai-active-verify' (now counts toward severity);
    refuted   -> dropped; else kept as an annotated 'ai-hypothesis' lead.
    Returns (new_findings, stats).
    """
    by_idx = {v["index"]: v for v in verdicts}
    out: list = []
    stats = {"confirmed": 0, "refuted": 0, "needs_manual": 0, "untested": 0}
    hyp_pos = 0
    for f in findings:
        if getattr(f, "category", "") != "ai-hypothesis":
            out.append(f)
            continue
        v = by_idx.get(hyp_pos)
        hyp_pos += 1
        if v is None:
            stats["untested"] += 1
            out.append(f)
            continue
        st = v["status"]
        if st == "refuted":
            stats["refuted"] += 1
            continue  # drop the disproven lead
        if st == "confirmed":
            stats["confirmed"] += 1
            f.category = "ai-active-verify"
            f.confidence = "high"
            if v.get("severity"):
                f.severity = _to_sev(v["severity"])
            f.title = "[AI-verified] " + f.title.removeprefix("[AI] ")
            f.description = (f.description
                             + f" — CONFIRMED via {v.get('tool')}: {v.get('evidence', '')}").strip()
            if v.get("poc"):
                f.evidence = (f.evidence + " | " if f.evidence else "") + f"PoC: {v['poc']}"
                f.recommendation = (f.recommendation + "  Reproduce the PoC above to "
                                    "confirm, then remediate.").strip()
            f.exploitability = {"verdict": "confirmed-exploitable", "priority": 90,
                                "signals": {"actively_verified": True, "ai_planned": True,
                                            "has_poc": bool(v.get("poc"))}}
        else:
            stats["needs_manual"] += 1
            f.description = f.description + f" — [unconfirmed: {v.get('tool', 'tool')} {st}]"
        out.append(f)
    return out, stats


# ---- CVE verification: AI plans a benign detection probe per matched CVE -------

_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _poc_refs(cve: dict) -> list:
    return [r.get("url") for r in (cve.get("references") or [])
            if r.get("poc") and r.get("url")][:6]


def cve_candidates(cves: list, max_cves: int = 6) -> list:
    """The CVEs worth an active AI probe: firm (not weak/distro-downgraded) and
    not already verified, highest severity first, those with a public PoC first,
    capped. Weak matches are skipped — they're likely backport-patched FPs."""
    cand = [c for c in cves
            if c.get("confidence", "firm") != "weak" and not c.get("verified")]
    cand.sort(key=lambda c: (_RANK.get(c.get("severity"), 0), len(_poc_refs(c))), reverse=True)
    return cand[:max_cves]


def verify_cves(result_dict: dict, cves: list, provider: LLMProvider, lab, *,
                budget: Optional[cache_mod.Budget] = None, audit=None,
                log=lambda _m: None, max_cves: int = 6, use_poc_content: bool = True) -> list[dict]:
    """For each firm, reachable CVE, have the model plan ONE benign detection probe
    and judge whether the CVE is present. When `use_poc_content`, the model is first
    grounded in EXCERPTS OF THE PUBLIC PoC WRITE-UPS (trickest/cve repo READMEs) so
    the probe targets the real trigger — never the raw destructive exploit. Runs
    host-locked + lab-gated. Returns verdicts:
    {"cve", "status": confirmed|refuted|inconclusive|needs-manual,
     "severity", "reasoning", "evidence", "tool", "curl", "grounded_in_poc"}.
    """
    from . import verify_tools
    from .. import cve as cve_mod
    cand = cve_candidates(cves, max_cves)
    if not cand:
        return []
    context = {"url": result_dict.get("url") or result_dict.get("target"),
               "host": getattr(lab, "host", "")}
    verdicts: list[dict] = []
    for c in cand:
        ok, _why = lab.can_send()
        if not ok:
            break
        techniques = cve_mod.poc_techniques(c) if use_poc_content else []
        if techniques:
            log(f"ai-cve-verify: grounding {c.get('id')} in {len(techniques)} public PoC write-up(s)")
        grounded = bool(techniques)
        plan = parse_json(_call(provider, [
            Message("system", prompts.CVE_VERIFY_SYSTEM),
            Message("user", prompts.cve_verify_prompt(c, context, verify_tools.TOOL_SPECS, techniques))],
            json_mode=True, budget=budget, use_cache=True, audit=audit)) or {}
        tool = plan.get("tool")
        if tool in (None, "", "none"):
            verdicts.append({"cve": c.get("id"), "status": "needs-manual", "tool": "none",
                             "grounded_in_poc": grounded,
                             "reasoning": plan.get("rationale")
                             or "no safe automated probe distinguishes vulnerable from patched"})
            continue
        evidence = verify_tools.run_tool(tool, plan.get("args") or {}, lab)
        if evidence is None:
            verdicts.append({"cve": c.get("id"), "status": "inconclusive", "tool": tool,
                             "grounded_in_poc": grounded, "reasoning": "invalid tool call"})
            continue
        v = parse_json(_call(provider, [
            Message("system", prompts.CVE_JUDGE_SYSTEM),
            Message("user", prompts.cve_judge_prompt(c, evidence))],
            json_mode=True, budget=budget, use_cache=True, audit=audit)) or {}
        status = str(v.get("status", "inconclusive")).lower()
        if status not in ("confirmed", "reachable", "refuted", "inconclusive"):
            status = "inconclusive"
        verdicts.append({"cve": c.get("id"), "status": status, "severity": v.get("severity"),
                         "reasoning": v.get("reasoning", ""), "evidence": v.get("evidence", ""),
                         "tool": tool, "curl": (evidence or {}).get("curl", ""),
                         "grounded_in_poc": grounded})
        log(f"ai-cve-verify: {c.get('id')} -> {status}" + ("  [PoC-grounded]" if grounded else ""))
    return verdicts
