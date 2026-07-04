"""Redaction before egress to an external LLM.

The active loop feeds live response bodies / tool evidence to the model, which can
carry the very secrets the scan just found — and the default provider is a
third-party API. Redaction is default ON; these tests pin that a secret never
reaches the provider by default, the opt-out still works, and the audit manifest
is always populated.

Offline: a capturing stub provider; no network, no real model.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.ai import agent  # noqa: E402
from celsius.ai import cache as cache_mod  # noqa: E402
from celsius.ai.provider import LLMProvider  # noqa: E402
from celsius.ai.redact import redact_obj  # noqa: E402
from celsius.config import ScanConfig  # noqa: E402


def _bypass_cache():
    """Force provider.complete() to run (the disk cache would otherwise short-
    circuit it on a re-run). conftest restores cache.get after each test."""
    cache_mod.get = lambda *a, **k: None

SECRET = "AKIAIOSFODNN7EXAMPLE"  # AWS access key id — a rule the scanner flags
PAYLOAD = "<xss-probe-42>"


class _Capture(LLMProvider):
    name = "capture"
    default_model = "cap"

    def __init__(self, reply='{"confirmed": false}'):
        super().__init__()
        self.seen = ""
        self._reply = reply

    def complete(self, messages, **kw):
        self.seen = "\n".join(m.content for m in messages)
        return self._reply


class _Resp:
    status = 200
    location = None

    def __init__(self, body):
        self.body = body


def test_config_redaction_defaults_on():
    assert ScanConfig(target="example.com").ai_redact is True


def test_redact_obj_masks_nested_and_builds_manifest():
    clean, res = redact_obj({"h": {"body": f"k={SECRET}"}, "list": [SECRET]}, enabled=True)
    assert SECRET not in str(clean)                       # value gone from every string
    assert res.n_sensitive >= 2                           # both occurrences counted
    assert any(m["rule_id"] == "aws-access-key-id" for m in res.manifest)


def test_manifest_built_even_when_disabled():
    # enabled=False keeps the value but must still record what was sensitive so the
    # audit log is honest about what left the host.
    clean, res = redact_obj({"body": f"k={SECRET}"}, enabled=False)
    assert SECRET in str(clean)
    assert res.n_sensitive == 1


def test_judge_does_not_leak_secret_by_default():
    _bypass_cache()
    prov = _Capture()
    body = f"reflected {PAYLOAD} aws_key={SECRET}"
    agent._judge({"technique": "reflected-xss", "payload": PAYLOAD}, _Resp(body),
                 prov, None, None)                        # redact_secrets defaults True
    assert SECRET not in prov.seen                        # secret never egressed
    assert PAYLOAD in prov.seen                           # payload preserved for the judge


def test_judge_opt_out_sends_raw():
    _bypass_cache()
    prov = _Capture()
    body = f"reflected {PAYLOAD} aws_key={SECRET}"
    agent._judge({"technique": "reflected-xss", "payload": PAYLOAD}, _Resp(body),
                 prov, None, None, redact_secrets=False)
    assert SECRET in prov.seen                            # explicit opt-out still works


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
