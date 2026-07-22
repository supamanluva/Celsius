"""AI hunt planner: model-generated attack hypotheses from the recon picture.

In lab mode, before the proving loops run, the model reads everything recon
learned — tech stack, endpoints, client-side intel, subdomains, services, CVEs
and existing findings — and proposes a small set of specific, testable weakness
hypotheses. Each becomes an `ai-hypothesis` Finding (title prefixed
"[AI hunt] ") that the existing prove_hypotheses loop then proves or refutes
through the guardrailed harness. The planner itself sends nothing to the
target: it only reads scan state and talks to the LLM.
"""

from __future__ import annotations

from typing import Optional

from ..models import Finding, Severity
from . import cache as cache_mod
from . import prompts
from .analyze import _call, _to_sev, parse_json
from .provider import LLMProvider, Message
from .redact import redact_obj


def _hunt_context(result_dict: dict) -> dict:
    """Assemble the model-facing recon picture (redacted later, before send)."""
    recon = result_dict.get("recon") or {}
    return {
        "url": result_dict.get("url") or result_dict.get("target"),
        "tech": (recon.get("tech") or [])[:30],
        "platform": recon.get("platform"),
        "client_libs": (recon.get("client_libs") or [])[:30],
        "subdomains": (recon.get("subdomains") or [])[:30],
        "cohosted": (recon.get("cohosted") or [])[:20],
        "origin_exposure": recon.get("origin_exposure"),
        "api": recon.get("api"),
        "wordpress": recon.get("wordpress"),
        "exposed_paths": (recon.get("exposed_paths") or [])[:30],
        "robots_paths": (recon.get("robots_paths") or [])[:30],
        "sitemap_urls": (recon.get("sitemap_urls") or [])[:40],
        "tls": recon.get("tls"),
        "services": [{"name": s.get("name"), "port": s.get("port"),
                      "version": s.get("version")}
                     for s in result_dict.get("services", [])][:20],
        "cves": [{"id": c.get("id"), "severity": c.get("severity"),
                  "confidence": c.get("confidence", "firm")}
                 for c in result_dict.get("cves", [])][:30],
        "existing_findings": [{"title": f.get("title"), "category": f.get("category")}
                              for f in result_dict.get("findings", [])][:60],
    }


def generate_hunt_hypotheses(result_dict: dict, provider: LLMProvider, *,
                             budget: Optional[cache_mod.Budget] = None, audit=None,
                             log=lambda _m: None, max_hypotheses: int = 10,
                             redact_secrets: bool = True) -> list[Finding]:
    """Propose targeted hypotheses from the recon picture. Never raises on
    model/target weirdness — a bad response just yields zero hypotheses."""
    from . import verify_tools
    context, red = redact_obj(_hunt_context(result_dict), enabled=redact_secrets)
    messages = [Message("system", prompts.AGENT_HUNT_SYSTEM),
                Message("user", prompts.hunt_user_prompt(context, verify_tools.TOOL_SPECS))]
    resp = _call(provider, messages, json_mode=True, budget=budget, use_cache=True,
                 audit=audit, redaction=red)
    data = parse_json(resp) or {}

    out: list[Finding] = []
    for h in (data.get("hypotheses") or []):
        if len(out) >= max_hypotheses:
            break
        if not isinstance(h, dict):
            continue
        title = str(h.get("title") or "").strip()
        if not title:
            continue
        guess = h.get("severity_guess")
        out.append(Finding(
            title=f"[AI hunt] {title}"[:140],
            severity=_to_sev(guess) if guess else Severity.LOW,
            category="ai-hypothesis",
            description=str(h.get("rationale") or ""),
            recommendation="Verify (non-destructive): "
                           f"{h.get('suggested_tool') or 'manual review'}",
            confidence="low",
        ))
    log(f"ai-hunt: model proposed {len(out)} hunt hypothesis(es)")
    return out
