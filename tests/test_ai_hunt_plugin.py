"""Integration test: the AiActiveVerify plugin runs the hunt planner before the
proving loop, and ai_hunt=False skips it. Stubbed provider, no network."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import celsius.ai as ai_pkg  # noqa: E402
from celsius.active import harness  # noqa: E402
from celsius.ai import agent, hunt  # noqa: E402
from celsius.audit import AuditLog  # noqa: E402
from celsius.config import ScanConfig  # noqa: E402
from celsius.models import Finding, ScanResult, Severity  # noqa: E402
from celsius.plugins.base import ScanContext  # noqa: E402
from celsius.plugins.builtin import AiActiveVerify  # noqa: E402
from celsius.scope import Scope  # noqa: E402
from celsius.targets import Target  # noqa: E402


class _StubProvider:
    name = "stub"
    model = "stub"

    def available(self):
        return True, ""


def _ctx(ai_hunt=True):
    cfg = ScanConfig(target="127.0.0.1", ai=True, ai_hunt=ai_hunt,
                     allow_exploit=True,
                     lab_attestation="I am authorized to actively test this target",
                     persist=False)
    return ScanContext(
        config=cfg,
        target=Target(raw="127.0.0.1", scheme="http", host="127.0.0.1", port=80, path="/"),
        result=ScanResult(target="127.0.0.1", url="http://127.0.0.1/"),
        scope=Scope.permissive_default(),
        audit=AuditLog(path="/tmp/celsius-hunt-plugin-audit.log"))


def _patch(calls, hunt_findings):
    """Stub every network/model boundary the plugin touches."""
    ai_pkg.get_provider = lambda *a, **k: _StubProvider()
    hunt.generate_hunt_hypotheses = lambda *a, **k: (
        calls.append("hunt"), list(hunt_findings))[1]
    harness.discover_points = lambda *a, **k: []   # skip the injection loop

    def fake_prove(result_dict, hypotheses, provider, lab, **kw):
        calls.append(("prove", [h.get("title") for h in hypotheses]))
        return []

    agent.prove_hypotheses = fake_prove


def _hunt_finding():
    return Finding(title="[AI hunt] git repo exposed", severity=Severity.HIGH,
                   category="ai-hypothesis", description="/.git/HEAD found",
                   confidence="low")


def test_hunt_hypotheses_flow_into_proving_loop():
    calls = []
    _patch(calls, [_hunt_finding()])
    ctx = _ctx(ai_hunt=True)
    AiActiveVerify().run(ctx)
    assert "hunt" in calls
    prove = [c for c in calls if isinstance(c, tuple) and c[0] == "prove"]
    assert prove and "[AI hunt] git repo exposed" in prove[0][1]
    assert ctx.result.recon["ai_active_verify"]["hunt_hypotheses"] == 1
    # no verdicts -> the hypothesis stays as an untested ai-hypothesis lead
    assert any(f.title == "[AI hunt] git repo exposed" for f in ctx.result.findings)


def test_no_ai_hunt_skips_planner():
    calls = []
    _patch(calls, [_hunt_finding()])
    ctx = _ctx(ai_hunt=False)
    AiActiveVerify().run(ctx)
    assert "hunt" not in calls
    assert not [c for c in calls if isinstance(c, tuple) and c[0] == "prove"]
    assert ctx.result.recon["ai_active_verify"]["hunt_hypotheses"] == 0


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
    sys.exit(1 if failed else 0)
