"""Redaction before sending content to an external LLM.

DEFAULT ON (``ScanConfig.ai_redact``). Any content bound for the model — scan
context, source, and crucially the live *response bodies / tool evidence* the
active loop collects — can contain the very secrets/PII the scan just found, and
the default provider is a third-party API. So secrets are replaced with typed
placeholders (``<AWS_KEY>``): the model can still reason about "a secret is here"
to do its job (judge a reflection, an error signature, a CVE fingerprint) without
the value leaving the host. Opt out with ``--ai-no-redact`` for maximum model
visibility on a target you own. Either way we return a manifest of what was (or
would be) sensitive, which the audit log records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Tuple

from .. import secrets as secret_rules


@dataclass
class RedactionResult:
    text: str
    enabled: bool
    manifest: list[dict] = field(default_factory=list)  # [{rule_id, redacted, count}]

    @property
    def n_sensitive(self) -> int:
        return sum(m["count"] for m in self.manifest)


def redact(text: str, *, enabled: bool = False) -> RedactionResult:
    """Scan for secrets; mask them only if `enabled`. Always builds a manifest."""
    matches = secret_rules.scan_text(text)
    counts: dict[str, dict] = {}
    out = text
    for sm in matches:
        key = sm.rule_id
        counts.setdefault(key, {"rule_id": key, "redacted": sm.redacted, "count": 0})
        counts[key]["count"] += 1
        if enabled:
            placeholder = f"<{sm.rule_id.upper().replace('-', '_')}>"
            out = out.replace(sm.match, placeholder)
    return RedactionResult(text=out, enabled=enabled, manifest=list(counts.values()))


def redact_obj(obj: Any, *, enabled: bool = False) -> Tuple[Any, RedactionResult]:
    """Redact secrets in every string within a nested dict/list/str structure.

    Returns ``(clean_obj, result)`` where ``result`` carries a merged manifest
    across the whole structure (built even when ``enabled`` is False, so the audit
    log always records what sensitive material was present). Used for the active
    loop's response bodies and tool evidence, whose key names aren't known here.
    """
    merged: dict[str, dict] = {}

    def _walk(node: Any) -> Any:
        if isinstance(node, str):
            r = redact(node, enabled=enabled)
            for m in r.manifest:
                agg = merged.setdefault(
                    m["rule_id"],
                    {"rule_id": m["rule_id"], "redacted": m["redacted"], "count": 0},
                )
                agg["count"] += m["count"]
            return r.text
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items()}
        if isinstance(node, (list, tuple)):
            return [_walk(v) for v in node]
        return node

    clean = _walk(obj)
    return clean, RedactionResult(text="", enabled=enabled, manifest=list(merged.values()))
