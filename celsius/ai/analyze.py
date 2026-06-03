"""High-level AI analysis: turn scan results / source into hypotheses.

Wraps provider calls with caching, a token budget, optional redaction, and audit
logging, then parses the model's JSON into Finding / CodeFinding objects labeled
as `ai-hypothesis` (never auto-promoted to verified).
"""

from __future__ import annotations

import json
import re
from typing import Optional

from ..codescan import CodeFinding
from ..models import Finding, Severity
from . import cache as cache_mod
from . import prompts
from .provider import AIError, LLMProvider, Message
from .redact import redact

_SEV = {s.value: s for s in Severity}


def _to_sev(v) -> Severity:
    return _SEV.get(str(v).upper(), Severity.INFO)


def parse_json(text: str) -> Optional[dict]:
    """Extract the first JSON object from a model reply (tolerates code fences/prose)."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # find the outermost {...}
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _call(provider: LLMProvider, messages: list[Message], *, json_mode: bool,
          budget: Optional[cache_mod.Budget], use_cache: bool,
          audit=None, redaction=None) -> str:
    payload = json.dumps([(m.role, m.content) for m in messages])
    if use_cache:
        hit = cache_mod.get(provider.name, provider.model, payload)
        if hit is not None:
            return hit
    est = sum(cache_mod.estimate_tokens(m.content) for m in messages)
    if budget and not budget.can_spend(est):
        raise AIError(f"AI token budget exceeded (~{budget.spent()} used)")
    if audit is not None:
        manifest = redaction.manifest if redaction else []
        audit.event(
            "ai_send", provider=provider.name, model=provider.model, est_tokens=est,
            masked=bool(redaction and redaction.enabled),   # was masking applied?
            sensitive_count=sum(m["count"] for m in manifest),
            sensitive=manifest,
        )
    resp = provider.complete(messages, json_mode=json_mode)
    if budget:
        budget.add(est + cache_mod.estimate_tokens(resp))
    if use_cache:
        cache_mod.put(provider.name, provider.model, payload, resp)
    return resp


# ---- host-scan triage ---------------------------------------------------------

def triage_scan(result_dict: dict, provider: LLMProvider, *, redact_secrets: bool = False,
                budget: Optional[cache_mod.Budget] = None, use_cache: bool = True,
                audit=None) -> tuple[list[Finding], str]:
    """Returns (ai_findings, summary_text)."""
    context = {
        "target": result_dict.get("target"),
        "url": result_dict.get("url"),
        "services": result_dict.get("services", []),
        "cves": [{"id": c.get("id"), "severity": c.get("severity"), "affects": c.get("affects")}
                 for c in result_dict.get("cves", [])],
        "findings": [{"title": f.get("title"), "severity": f.get("severity"),
                      "category": f.get("category")} for f in result_dict.get("findings", [])],
    }
    raw = json.dumps(context)
    red = redact(raw, enabled=redact_secrets)
    user = prompts.triage_user_prompt(json.loads(red.text))
    messages = [Message("system", prompts.TRIAGE_SYSTEM), Message("user", user)]
    resp = _call(provider, messages, json_mode=True, budget=budget, use_cache=use_cache,
                 audit=audit, redaction=red)
    data = parse_json(resp) or {}

    findings: list[Finding] = []
    for h in data.get("hypotheses", []) or []:
        findings.append(Finding(
            title=f"[AI] {h.get('title', 'hypothesis')}",
            severity=_to_sev(h.get("severity")),
            category="ai-hypothesis",
            description=h.get("rationale", ""),
            recommendation=f"Verify (non-destructive): {h.get('safe_probe', '')}",
            confidence=str(h.get("confidence", "low")),
        ))
    summary = data.get("summary", "")
    fps = data.get("likely_false_positives", []) or []
    if fps:
        summary += "\nLikely false positives: " + "; ".join(
            f"{x.get('title')} ({x.get('why')})" for x in fps)
    return findings, summary


# ---- code review --------------------------------------------------------------

def review_code_file(path: str, source: str, provider: LLMProvider, *,
                     redact_secrets: bool = False, budget: Optional[cache_mod.Budget] = None,
                     use_cache: bool = True, audit=None) -> list[CodeFinding]:
    red = redact(source, enabled=redact_secrets)
    user = prompts.code_user_prompt(path, red.text)
    messages = [Message("system", prompts.CODE_SYSTEM), Message("user", user)]
    resp = _call(provider, messages, json_mode=True, budget=budget, use_cache=use_cache,
                 audit=audit, redaction=red)
    data = parse_json(resp) or {}
    out: list[CodeFinding] = []
    for f in data.get("findings", []) or []:
        try:
            line = int(f.get("line", 0) or 0)
        except (ValueError, TypeError):
            line = 0
        desc = f.get("description", "")
        flow = f.get("data_flow", "")
        out.append(CodeFinding(
            title=f"[AI] {f.get('title', f.get('type', 'issue'))}",
            severity=str(f.get("severity", "INFO")).upper(),
            category="ai-hypothesis",
            file=f.get("file") or path, line=line,
            rule_id=f"ai/{f.get('type', 'vuln')}",
            evidence=(f"{desc}  | flow: {flow}" if flow else desc)[:300],
            recommendation=f"Verify (non-destructive): {f.get('verification', '')}",
            confidence=str(f.get("confidence", "low")),
        ))
    return out
