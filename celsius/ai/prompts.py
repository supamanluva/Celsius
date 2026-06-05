"""Prompt templates with strict JSON output contracts.

Discipline: the model PROPOSES; it never declares a vuln verified. Everything it
returns is labeled an `ai-hypothesis` downstream and must be confirmed by a
deterministic probe or a human. Prompts demand evidence (file:line, a concrete
data-flow, a safe probe) and a self-assessed confidence to keep hallucinations
contained.
"""

from __future__ import annotations

import json
from typing import Optional

TRIAGE_SYSTEM = """You are a senior application-security analyst assisting an \
AUTHORIZED penetration test. You receive structured results from an automated \
scanner. Your job: prioritize real risk, flag likely false positives, and \
propose testable attack hypotheses a signature scanner would miss (business \
logic, chained exploits, auth/IDOR, SSRF, misconfig combinations).

Rules:
- Be precise and evidence-driven. Do not invent CVEs or findings.
- A CVE marked confidence="weak" is an UNCONFIRMED upstream version-range guess. \
Linux distros (Debian/Ubuntu/RHEL) routinely backport security fixes WITHOUT \
changing the upstream version, so a weak match may already be patched (e.g. an \
OpenSSH banner like "9.6p1 Ubuntu-3ubuntu13.16" carries fixes 9.6p1 alone does \
not reveal). Treat weak CVEs as low-confidence leads: do NOT build HIGH/CRITICAL \
hypotheses on them or present them as exploitable, and list them under \
likely_false_positives when the banner shows a patched distro build.
- Every hypothesis must include a NON-DESTRUCTIVE way to check it.
- Output ONE valid JSON object, no prose outside it, matching the schema."""

TRIAGE_SCHEMA = {
    "summary": "2-4 sentence risk summary",
    "prioritized": [{"title": "", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", "why": ""}],
    "likely_false_positives": [{"title": "", "why": ""}],
    "hypotheses": [{
        "title": "", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
        "confidence": "high|medium|low",
        "rationale": "why this might exist given the evidence",
        "safe_probe": "a non-destructive check to confirm/deny",
    }],
}

CODE_SYSTEM = """You are a senior secure-code reviewer assisting an AUTHORIZED \
assessment. You receive source files. Find real, exploitable vulnerabilities: \
injection (SQL/cmd/template), insecure deserialization, SSRF, path traversal, \
auth/authz flaws, hardcoded secrets, weak crypto, unsafe redirects, XSS sinks.

Rules:
- Cite the exact file and line. Describe the data-flow from source to sink.
- Do NOT report style issues or speculative bugs without a concrete path.
- Give a NON-DESTRUCTIVE verification step for each.
- Output ONE valid JSON object only, matching the schema."""

CODE_SCHEMA = {
    "findings": [{
        "title": "", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
        "confidence": "high|medium|low",
        "file": "", "line": 0, "type": "e.g. sql-injection",
        "description": "", "data_flow": "source -> ... -> sink",
        "verification": "non-destructive check",
    }],
}


# ---- agentic active verification ---------------------------------------------

AGENT_PLAN_SYSTEM = """You are an offensive-security agent in an AUTHORIZED lab \
penetration test. You are given the live attack surface (injectable request \
points) and scanner findings. Propose a SMALL set (<=8) of high-signal, \
NON-DESTRUCTIVE probes that would PROVE a specific vulnerability.

You only choose the target (point + parameter), a benign DETECTION payload, and \
what to look for. A sandbox sends each probe through strict guardrails and \
returns the response for you to judge later.

HARD RULES:
- Read-only detection payloads ONLY. NEVER modify data: no DROP/DELETE/UPDATE/\
INSERT/TRUNCATE, no OS commands, no time-based/sleep/benchmark payloads.
- Use unique markers so reflection is unambiguous.
- Prefer the few most promising hypotheses over breadth.
- Output ONE valid JSON object only, matching the schema."""

AGENT_PLAN_SCHEMA = {
    "probes": [{
        "point": 0,                     # index into the provided points[]
        "param": "name of the parameter to inject",
        "technique": "reflected-xss|open-redirect|path-traversal|sqli-error|idor|ssrf|other",
        "payload": "a benign, read-only detection payload",
        "hypothesis": "what vuln this would prove and why it's plausible here",
        "look_for": "what in the response confirms it (e.g. unescaped marker)",
    }],
}

AGENT_JUDGE_SYSTEM = """You verify whether a single probe PROVED a vulnerability. \
Given the probe and the server's actual response, decide CONFIRMED or not. Be \
strict and evidence-driven: confirm ONLY when the response contains concrete \
proof (unescaped marker reflected in HTML, an off-host redirect to the canary, a \
file-read/DB-error signature, or another user's data). If uncertain, \
confirmed=false. Output ONE valid JSON object only."""

AGENT_JUDGE_SCHEMA = {
    "confirmed": "true|false",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "evidence": "short quote/markers from the response that prove it",
    "reasoning": "one or two sentences",
}


def plan_user_prompt(context: dict) -> str:
    return ("Authorized lab target. Attack surface and findings:\n\n"
            + json.dumps(context, indent=2)[:12000]
            + "\n\n" + _schema_block(AGENT_PLAN_SCHEMA))


def judge_user_prompt(probe: dict, response: dict) -> str:
    return ("Probe sent:\n" + json.dumps(probe, indent=2)
            + "\n\nServer response:\n" + json.dumps(response, indent=2)[:8000]
            + "\n\n" + _schema_block(AGENT_JUDGE_SCHEMA))


def _schema_block(schema: dict) -> str:
    return "JSON schema (shape, not literal values):\n" + json.dumps(schema, indent=2)


def triage_user_prompt(context: dict) -> str:
    return (
        "Scanner results for an authorized target:\n\n"
        + json.dumps(context, indent=2)[:12000]
        + "\n\n" + _schema_block(TRIAGE_SCHEMA)
    )


def code_user_prompt(path: str, source: str) -> str:
    src = source[:24000]
    return (
        f"SOURCE FILE: {path}\n"
        "```\n" + src + "\n```\n\n"
        + _schema_block(CODE_SCHEMA)
    )


# ---- Tool-using hypothesis proving (lab) -------------------------------------

AGENT_TOOL_SYSTEM = """You are an offensive-security agent in an AUTHORIZED lab \
test. You are given hypotheses about the target and a toolbox. For each \
hypothesis, request ONE tool call that would confirm or refute it — or mark it \
"none" when no safe tool can settle it (needs valid credentials, data mutation, \
or an out-of-band callback you don't have).

Prefer to PROVE feasibility, not just plausibility: when a hypothesis is about an \
exploitable bug (open redirect, reflected XSS, CORS, exposed file/secret, SSRF), \
use the `poc` tool to send ONE crafted request that DEMONSTRATES the impact, and \
a reproducible curl is captured for the report. Choose a benign payload that \
proves it (a redirect to a canary, a unique marker reflected unescaped, an Origin \
that gets reflected, fetching the exposed content).

HARD RULES:
- Non-destructive ONLY: never delete/modify data, never brute-force credentials, \
no time-based/blind payloads. The harness rejects destructive requests.
- Every tool is locked to the scanned host; never target another host.
- Be selective — skip hypotheses no tool can prove rather than guessing.
- Output ONE valid JSON object only, matching the schema."""

AGENT_TOOL_SCHEMA = {
    "plans": [{
        "hypothesis": 0,                # index into the provided hypotheses[]
        "tool": "http_get|tcp_connect|takeover_check|tls_probe|dns_lookup|poc|none",
        "args": {"...": "tool arguments"},
        "expect": "what result would CONFIRM the hypothesis (vs refute it)",
    }],
}

AGENT_PROVE_JUDGE_SYSTEM = """You decide whether a tool's evidence PROVES, \
REFUTES, or is INCONCLUSIVE for one hypothesis. Be strict and evidence-driven:
- confirmed: the evidence concretely proves it (the exposed panel's login page is \
reachable and identified; a CNAME dangles with the takeover fingerprint; the port \
is open and the banner matches).
- refuted: the evidence shows it is NOT the case (404 / connection refused / \
redirect to auth / no dangling fingerprint).
- inconclusive: the tool could not settle it.
Never over-claim. Output ONE valid JSON object only."""

AGENT_PROVE_JUDGE_SCHEMA = {
    "status": "confirmed|refuted|inconclusive",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "evidence": "the concrete fact from the tool result that decides it",
    "reasoning": "one or two sentences",
}


def tool_plan_prompt(hypotheses: list, tools: list, context: dict) -> str:
    return ("Authorized lab target.\n\nTOOLBOX:\n" + json.dumps(tools, indent=2)
            + "\n\nCONTEXT:\n" + json.dumps(context, indent=2)[:4000]
            + "\n\nHYPOTHESES to prove or refute:\n" + json.dumps(hypotheses, indent=2)[:8000]
            + "\n\n" + _schema_block(AGENT_TOOL_SCHEMA))


def prove_judge_prompt(hypothesis: dict, evidence: dict) -> str:
    return ("Hypothesis:\n" + json.dumps(hypothesis, indent=2)
            + "\n\nTool evidence:\n" + json.dumps(evidence, indent=2)[:6000]
            + "\n\n" + _schema_block(AGENT_PROVE_JUDGE_SCHEMA))


# ---- CVE verification (AI plans a benign detection probe per matched CVE) ------

CVE_VERIFY_SYSTEM = """You verify a SPECIFIC CVE on an AUTHORIZED lab target by \
planning ONE benign, detection-grade probe — enough to tell a VULNERABLE host \
from a PATCHED one, never an exploit that does harm.

You get the CVE id, its description, the detected product/version/port, real \
PoC/reference URLs, and (when available) EXCERPTS OF THE PUBLIC PoC WRITE-UPS that \
explain how the exploit actually works. Use the write-ups to understand the precise \
trigger (the path, header, parameter or request shape), then choose the SAFEST \
tool call that observes the vulnerable behaviour or a reliable fingerprint of it \
(a telltale response header/body, an endpoint that only exists when vulnerable, a \
banner/version corroboration, a crafted-but-benign request whose response \
distinguishes patched from unpatched). Distil the write-up into the MINIMUM \
observation that separates vulnerable from patched — never the full destructive \
exploit. If the only way to prove it is destructive (RCE shell, data write, DoS), \
return tool "none" and say it needs manual confirmation.

HARD RULES:
- Non-destructive ONLY: no data deletion/mutation, no DoS, no credential brute \
force, no blind/time-based payloads, no fetching real secrets. The harness \
rejects destructive requests.
- The probe is locked to the scanned host; never target another host or the \
PoC's own example domains.
- Distro-backported packages (e.g. "...ubuntu...", "...deb...") often keep the \
version but ARE patched — a version match alone is NOT proof; require behaviour.
- If no safe probe can distinguish vulnerable from patched, return tool "none" \
with a one-line rationale. Don't guess.
- Output ONE valid JSON object only, matching the schema."""

CVE_VERIFY_SCHEMA = {
    "tool": "http_get|tcp_connect|tls_probe|dns_lookup|poc|none",
    "args": {"...": "tool arguments (host-locked)"},
    "expect": "what result would CONFIRM the CVE is present (vs show it's patched)",
    "rationale": "if tool=none, why no safe probe settles it",
}

CVE_JUDGE_SYSTEM = """You decide whether a probe's evidence shows a SPECIFIC CVE \
is present and reachable. Be strict and behaviour-driven:
- confirmed: the evidence concretely matches the vulnerable behaviour/fingerprint \
the CVE describes (not merely a version string).
- refuted: the evidence shows it is patched / not present / not reachable.
- inconclusive: the probe cannot settle it (e.g. version-only, blocked, ambiguous).
A bare version match WITHOUT corroborating behaviour is inconclusive, never \
confirmed — distros backport fixes silently. Never over-claim. Output ONE valid \
JSON object only."""

CVE_JUDGE_SCHEMA = {
    "status": "confirmed|refuted|inconclusive",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "evidence": "the concrete fact from the probe that decides it",
    "reasoning": "one or two sentences",
}


def cve_verify_prompt(cve: dict, context: dict, tools: list,
                      techniques: Optional[list] = None) -> str:
    view = {
        "id": cve.get("id"), "severity": cve.get("severity"), "cvss": cve.get("cvss"),
        "affects": cve.get("affects"), "product": cve.get("product"),
        "version": cve.get("version"), "port": cve.get("port"),
        "description": (cve.get("description") or "")[:800],
        "poc_references": [r.get("url") for r in (cve.get("references") or [])
                           if r.get("poc") and r.get("url")][:6],
    }
    prompt = ("Authorized lab target.\n\nTOOLBOX:\n" + json.dumps(tools, indent=2)
              + "\n\nTARGET CONTEXT:\n" + json.dumps(context, indent=2)[:2000]
              + "\n\nCVE to verify:\n" + json.dumps(view, indent=2)[:4000])
    if techniques:
        wp = "\n\n".join(f"[PoC: {t.get('url')}]\n{t.get('technique', '')}"
                         for t in techniques if t.get("technique"))
        if wp:
            prompt += ("\n\nPUBLIC PoC WRITE-UPS (how the exploit works — use to craft the "
                       "BENIGN detection probe; do NOT replay any destructive step):\n" + wp[:4000])
    return prompt + "\n\n" + _schema_block(CVE_VERIFY_SCHEMA)


def cve_judge_prompt(cve: dict, evidence: dict) -> str:
    view = {"id": cve.get("id"), "affects": cve.get("affects"),
            "description": (cve.get("description") or "")[:600]}
    return ("CVE:\n" + json.dumps(view, indent=2)
            + "\n\nProbe evidence:\n" + json.dumps(evidence, indent=2)[:6000]
            + "\n\n" + _schema_block(CVE_JUDGE_SCHEMA))


# ---- security advisor (plain-language, prioritized remediation for the owner) --

ADVISOR_SYSTEM = """You are a trusted security advisor writing for the OWNER of \
this website — assume a capable developer, not a security specialist. You are \
given the scan's CONFIRMED findings (firm CVEs, vulnerable client-side libraries, \
and real misconfigurations) plus a computed health grade. Turn them into a calm, \
honest, prioritized action plan.

For every step:
- say plainly WHAT is wrong and WHY it matters to THIS site (concrete impact, not \
generic theory),
- give the EXACT fix: the header to add, the config directive, the command, the \
version to upgrade to — copy-pasteable where possible,
- rate the effort (quick | moderate | involved).

RULES:
- Ground STRICTLY in the findings provided. Never invent a CVE, finding, or \
version. If something is only a lead/low-confidence, do not present it as fact.
- Order steps by real risk to the owner (verified + high impact first).
- Also call out what they're already doing RIGHT — it builds trust and tells them \
not to "fix" things that are fine.
- Be concise and practical. Output ONE valid JSON object only, matching the schema."""

ADVISOR_SCHEMA = {
    "headline": "one honest sentence on overall security posture for the owner",
    "steps": [{
        "title": "short imperative, e.g. 'Add a Content-Security-Policy'",
        "severity": "CRITICAL|HIGH|MEDIUM|LOW",
        "why": "plain-language impact specific to this site",
        "fix": "exact, copy-pasteable remediation (header/config/command/version)",
        "effort": "quick|moderate|involved",
    }],
    "doing_well": ["short notes on controls already in place / done right"],
}


def advisor_prompt(grade: dict, context: dict) -> str:
    return ("Authorized scan of the owner's own site. Write their remediation plan.\n\n"
            "HEALTH GRADE:\n" + json.dumps(grade, indent=2)[:3000]
            + "\n\nCONFIRMED FINDINGS (ground strictly in these):\n"
            + json.dumps(context, indent=2)[:16000]
            + "\n\n" + _schema_block(ADVISOR_SCHEMA))
