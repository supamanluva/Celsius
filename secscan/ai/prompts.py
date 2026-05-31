"""Prompt templates with strict JSON output contracts.

Discipline: the model PROPOSES; it never declares a vuln verified. Everything it
returns is labeled an `ai-hypothesis` downstream and must be confirmed by a
deterministic probe or a human. Prompts demand evidence (file:line, a concrete
data-flow, a safe probe) and a self-assessed confidence to keep hallucinations
contained.
"""

from __future__ import annotations

import json

TRIAGE_SYSTEM = """You are a senior application-security analyst assisting an \
AUTHORIZED penetration test. You receive structured results from an automated \
scanner. Your job: prioritize real risk, flag likely false positives, and \
propose testable attack hypotheses a signature scanner would miss (business \
logic, chained exploits, auth/IDOR, SSRF, misconfig combinations).

Rules:
- Be precise and evidence-driven. Do not invent CVEs or findings.
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
