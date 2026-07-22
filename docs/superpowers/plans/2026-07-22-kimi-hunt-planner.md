# Kimi Provider + AI Hunt Planner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Moonshot's Kimi as a first-class AI provider and an AI "hunt planner" that proposes recon-grounded attack hypotheses which the existing guardrailed proving loops then verify.

**Architecture:** `KimiProvider` rides the existing `OpenAICompatProvider` stdlib path. New module `celsius/ai/hunt.py` runs inside the existing `AiActiveVerify` plugin (lab mode only), emits `ai-hypothesis` findings, and the existing `prove_hypotheses` loop proves/refutes them. No new network path, no new dependencies.

**Tech Stack:** Python 3.10+ stdlib only (core), FastAPI web extra, argparse CLI, pytest-style standalone tests.

**Spec:** `docs/superpowers/specs/2026-07-22-kimi-hunt-planner-design.md`

## Global Constraints

- Core stays **stdlib-only**: no new entries in `pyproject.toml` `dependencies`.
- All new model-bound context goes through `ai/redact.py` (`redact_obj`); every send is audit-logged via `_call`.
- Nothing new sends target traffic: the planner only reads scan state; proving stays inside `active/harness.py`.
- Model output is `category="ai-hypothesis"`, `confidence="low"` until deterministically corroborated by the existing loops.
- Every new test file keeps the standalone `if __name__ == "__main__"` runner block (project convention).
- Lint/type gate: `uv run --group dev ruff check celsius/` and `uv run --extra web --extra dynamic --group dev pyright celsius/` must be 0 errors / 0 warnings.
- Do not bump the version (no release); `pyproject.toml` and `celsius/__init__.py` stay in sync untouched.

---

### Task 1: Kimi provider

**Files:**
- Modify: `celsius/ai/provider.py`
- Test: `tests/test_ai_provider_kimi.py`

**Interfaces:**
- Consumes: existing `OpenAICompatProvider`, `LLMProvider._env_var()`, `get_provider()` env resolution.
- Produces: `KimiProvider` (`name="kimi"`, `default_model="kimi-k2-0711-preview"`, `default_base_url="https://api.moonshot.ai/v1"`); `get_provider("kimi")` with env fallback `KIMI_API_KEY` → `MOONSHOT_API_KEY`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_ai_provider_kimi.py`:

```python
"""Tests for the Kimi (Moonshot) AI provider: registration, env-key fallback,
request shape, and base-url safety validation. No network."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.ai import provider as prov  # noqa: E402


def _clean_env():
    for k in ("KIMI_API_KEY", "MOONSHOT_API_KEY"):
        os.environ.pop(k, None)


def test_kimi_registered_with_defaults():
    assert "kimi" in prov.available_providers()
    p = prov.get_provider("kimi", api_key="sk-test")
    assert p.name == "kimi"
    assert p.model == "kimi-k2-0711-preview"
    assert p.base_url == "https://api.moonshot.ai/v1"


def test_kimi_env_key_fallback_order():
    _clean_env()
    try:
        os.environ["MOONSHOT_API_KEY"] = "sk-moon"
        assert prov.get_provider("kimi").api_key == "sk-moon"
        os.environ["KIMI_API_KEY"] = "sk-kimi"
        assert prov.get_provider("kimi").api_key == "sk-kimi"  # primary wins
    finally:
        _clean_env()


def test_kimi_unavailable_without_key():
    _clean_env()
    ok, why = prov.get_provider("kimi").available()
    assert not ok
    assert "KIMI_API_KEY" in why


def test_kimi_openai_compat_request_shape():
    calls = {}

    def fake_post(url, payload, headers, timeout):
        calls.update(url=url, payload=payload, headers=headers)
        return {"choices": [{"message": {"content": "{}"}}]}

    orig = prov._post_json
    prov._post_json = fake_post
    try:
        p = prov.get_provider("kimi", api_key="sk-test")
        out = p.complete([prov.Message("user", "hi")], json_mode=True)
    finally:
        prov._post_json = orig
    assert out == "{}"
    assert calls["url"] == "https://api.moonshot.ai/v1/chat/completions"
    assert calls["headers"]["Authorization"] == "Bearer sk-test"
    assert calls["payload"]["model"] == "kimi-k2-0711-preview"
    assert calls["payload"]["response_format"] == {"type": "json_object"}


def test_kimi_plain_http_base_url_rejected():
    try:
        prov.get_provider("kimi", api_key="sk", base_url="http://evil.example.com/v1")
        raise AssertionError("expected AIError for plain-http non-local base_url")
    except prov.AIError:
        pass


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python tests/test_ai_provider_kimi.py`
Expected: FAIL — `AIError: unknown AI provider 'kimi'`

- [ ] **Step 3: Implement the provider**

In `celsius/ai/provider.py`, after the `LocalProvider` class (ends line 139), add:

```python
class KimiProvider(OpenAICompatProvider):
    """Moonshot AI Kimi — OpenAI-compatible chat API."""
    name = "kimi"
    default_model = "kimi-k2-0711-preview"
    default_base_url = "https://api.moonshot.ai/v1"
```

Update the module docstring provider list (line 4-8) to include a `kimi` line:

```
  kimi       Moonshot AI Kimi (api.moonshot.ai), OpenAI-compatible
```

Update the registries at the bottom:

```python
_PROVIDERS = {
    "deepseek": DeepSeekProvider,
    "openai": OpenAIProvider,
    "local": LocalProvider,
    "anthropic": AnthropicProvider,
    "kimi": KimiProvider,
    "mock": MockProvider,
}

_ENV_KEYS = {
    "deepseek": "DEEPSEEK_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "kimi": "KIMI_API_KEY",
}

# Secondary env vars accepted when the primary one is unset.
_ENV_FALLBACK = {"kimi": "MOONSHOT_API_KEY"}
```

In `get_provider`, after the existing env lookup:

```python
    if api_key is None and name in _ENV_KEYS:
        api_key = os.environ.get(_ENV_KEYS[name])
    if api_key is None and name in _ENV_FALLBACK:
        api_key = os.environ.get(_ENV_FALLBACK[name])
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python tests/test_ai_provider_kimi.py`
Expected: `PASS` for all 5 tests, exit 0.

- [ ] **Step 5: Commit**

```bash
git add celsius/ai/provider.py tests/test_ai_provider_kimi.py
git commit -m "feat(ai): add Kimi (Moonshot) provider with env-key fallback"
```

---

### Task 2: Hunt planner module + prompts

**Files:**
- Modify: `celsius/ai/prompts.py`
- Create: `celsius/ai/hunt.py`
- Test: `tests/test_ai_hunt.py`

**Interfaces:**
- Consumes: `prompts.AGENT_HUNT_SYSTEM`, `prompts.hunt_user_prompt(context, tools)` (created in this task); `analyze._call`, `analyze._to_sev`, `analyze.parse_json`; `redact.redact_obj`; `verify_tools.TOOL_SPECS`; `cache.Budget`.
- Produces: `hunt.generate_hunt_hypotheses(result_dict: dict, provider: LLMProvider, *, budget=None, audit=None, log=lambda _m: None, max_hypotheses: int = 10, redact_secrets: bool = True) -> list[Finding]` — findings shaped `category="ai-hypothesis"`, `confidence="low"`, title prefixed `"[AI hunt] "`. Task 3 calls this from the `AiActiveVerify` plugin.

- [ ] **Step 1: Write the failing test**

Create `tests/test_ai_hunt.py`:

```python
"""Tests for the AI hunt planner (ai/hunt.py): context grounding, hypothesis
parsing/capping, and redaction — all with a stubbed provider, no network."""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.ai import hunt  # noqa: E402
from celsius.models import Severity  # noqa: E402


class _StubProvider:
    name = "stub"
    model = "stub"

    def __init__(self, reply):
        self.reply = reply
        self.messages = None

    def complete(self, messages, *, json_mode=False, **kw):
        self.messages = messages
        return self.reply


def _result():
    return {
        "target": "example.com", "url": "https://example.com",
        "services": [{"name": "http", "port": 443, "version": "nginx 1.18"}],
        "cves": [{"id": "CVE-2021-41773", "severity": "CRITICAL", "confidence": "firm"}],
        "findings": [{"title": "Missing CSP", "category": "headers", "severity": "MEDIUM"}],
        "recon": {"tech": ["nginx", "PHP"], "subdomains": ["dev.example.com"],
                  "exposed_paths": ["/.git/HEAD"]},
    }


def test_valid_json_becomes_hypothesis_findings():
    p = _StubProvider(json.dumps({"hypotheses": [
        {"title": "git repo exposed", "category": "debug-endpoint",
         "rationale": "/.git/HEAD found", "suggested_tool": "http_get",
         "severity_guess": "HIGH"}]}))
    out = hunt.generate_hunt_hypotheses(_result(), p)
    assert len(out) == 1
    f = out[0]
    assert f.category == "ai-hypothesis"
    assert f.confidence == "low"
    assert f.title.startswith("[AI hunt] ")
    assert f.severity == Severity.HIGH


def test_malformed_items_dropped_individually():
    p = _StubProvider(json.dumps({"hypotheses": [
        {"title": ""},                        # empty title -> drop
        {"not_title": 1},                     # garbage -> drop
        {"title": "ok one", "rationale": "r"}]}))
    out = hunt.generate_hunt_hypotheses(_result(), p)
    assert [f.title for f in out] == ["[AI hunt] ok one"]
    assert out[0].severity == Severity.LOW    # no severity_guess -> LOW


def test_cap_enforced():
    p = _StubProvider(json.dumps({"hypotheses": [
        {"title": f"h{i}"} for i in range(20)]}))
    out = hunt.generate_hunt_hypotheses(_result(), p, max_hypotheses=10)
    assert len(out) == 10


def test_garbage_response_yields_nothing():
    p = _StubProvider("not json at all")
    assert hunt.generate_hunt_hypotheses(_result(), p) == []


def test_context_carries_recon_evidence():
    p = _StubProvider(json.dumps({"hypotheses": []}))
    hunt.generate_hunt_hypotheses(_result(), p)
    user = next(m.content for m in p.messages if m.role == "user")
    assert "CVE-2021-41773" in user
    assert "dev.example.com" in user
    assert "nginx" in user


def test_redaction_applied_to_model_context():
    seen = {}
    orig = hunt.redact_obj

    def spy(obj, *, enabled=False):
        seen["enabled"] = enabled
        return orig(obj, enabled=enabled)

    hunt.redact_obj = spy
    try:
        hunt.generate_hunt_hypotheses(_result(), _StubProvider(json.dumps({"hypotheses": []})),
                                      redact_secrets=True)
    finally:
        hunt.redact_obj = orig
    assert seen["enabled"] is True


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python tests/test_ai_hunt.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'celsius.ai.hunt'`

- [ ] **Step 3: Add the hunt prompts**

In `celsius/ai/prompts.py`, after the `AGENT_JUDGE_SCHEMA` block (line ~108), add:

```python
AGENT_HUNT_SYSTEM = """You are a senior offensive-security operator planning an \
AUTHORIZED lab penetration test. You are given the full reconnaissance picture \
of one target: tech stack, endpoints, client-side intel, subdomains, services, \
CVEs and existing scanner findings. Propose a SMALL set (<=10) of specific, \
TESTABLE weakness hypotheses a signature scanner would miss — misconfigurations \
typical for the detected stack, exposed admin/debug surface, takeover-prone \
subdomains, weak auth flows, promising CVE chains.

Rules:
- Ground every hypothesis in the provided evidence; do not invent technology \
that isn't listed.
- Each hypothesis must name one read-only verification tool from the provided \
list (or "none" if no safe automated check exists).
- Prefer the few most promising hypotheses over breadth.
- Output ONE valid JSON object only, matching the schema."""

AGENT_HUNT_SCHEMA = {
    "hypotheses": [{
        "title": "short, specific — e.g. 'Laravel debug mode exposed on /_ignition'",
        "category": "exposed-admin|debug-endpoint|takeover|jwt-weakness|cve-chain|auth-flow|other",
        "rationale": "which recon evidence suggests this",
        "suggested_tool": "one of the provided tool names, or none",
        "severity_guess": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    }],
}
```

And next to `plan_user_prompt` / `judge_user_prompt`, add:

```python
def hunt_user_prompt(context: dict, tools: list) -> str:
    return ("Authorized lab target. Recon picture:\n\n"
            + json.dumps(context, indent=2)[:14000]
            + "\n\nRead-only verification tools available:\n"
            + json.dumps(tools, indent=2)[:4000]
            + "\n\n" + _schema_block(AGENT_HUNT_SCHEMA))
```

- [ ] **Step 4: Implement `celsius/ai/hunt.py`**

Create `celsius/ai/hunt.py`:

```python
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python tests/test_ai_hunt.py`
Expected: `PASS` for all 6 tests, exit 0.

- [ ] **Step 6: Commit**

```bash
git add celsius/ai/prompts.py celsius/ai/hunt.py tests/test_ai_hunt.py
git commit -m "feat(ai): hunt planner — recon-grounded hypotheses for the proving loop"
```

---

### Task 3: CLI / config / plugin wiring

**Files:**
- Modify: `celsius/config.py` (line ~99, AI section)
- Modify: `celsius/cli.py` (AI argument group ~line 208-217; config construction ~line 426)
- Modify: `celsius/plugins/builtin.py` (`AiActiveVerify.run`, lines 1309-1364)
- Test: `tests/test_ai_hunt_plugin.py`

**Interfaces:**
- Consumes: `hunt.generate_hunt_hypotheses(...)` from Task 2; existing `_ready_lab`, `Budget`, `AIError`.
- Produces: `ScanConfig.ai_hunt: bool = True`; CLI flags `--ai-hunt` / `--no-ai-hunt`; `AiActiveVerify` runs the planner before `prove_hypotheses`; `recon["ai_active_verify"]["hunt_hypotheses"]` count.

- [ ] **Step 1: Write the failing test**

Create `tests/test_ai_hunt_plugin.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python tests/test_ai_hunt_plugin.py`
Expected: FAIL — `TypeError: ScanConfig.__init__() got an unexpected keyword argument 'ai_hunt'`

- [ ] **Step 3: Add `ai_hunt` to ScanConfig**

In `celsius/config.py`, in the M2 AI section after `ai_redact` (line 99), add:

```python
    ai_hunt: bool = True                    # lab mode: AI proposes recon-grounded hunt hypotheses
```

- [ ] **Step 4: Add the CLI flags**

In `celsius/cli.py`, in the scan subcommand's AI group after the `--ai-no-redact` mutually-exclusive group (line ~217), add:

```python
    grp_hunt = gai.add_mutually_exclusive_group()
    grp_hunt.add_argument("--ai-hunt", action="store_true", default=True, dest="ai_hunt",
                          help="lab mode: the AI reads recon and proposes targeted hunt "
                               "hypotheses for the proof loop (default ON)")
    grp_hunt.add_argument("--no-ai-hunt", action="store_false", dest="ai_hunt",
                          help="skip the AI hunt planner (triage + proof loop only)")
```

Also update the two `--ai-provider` help strings (lines 210 and 303) from
`"deepseek|openai|anthropic|local|mock"` to `"deepseek|openai|anthropic|kimi|local|mock"`.

In the config construction (line ~426), change:

```python
        ai=args.ai, ai_provider=args.ai_provider, ai_model=args.ai_model,
        ai_base_url=args.ai_base_url, ai_redact=args.ai_redact,
```

to:

```python
        ai=args.ai, ai_provider=args.ai_provider, ai_model=args.ai_model,
        ai_base_url=args.ai_base_url, ai_redact=args.ai_redact, ai_hunt=args.ai_hunt,
```

- [ ] **Step 5: Wire the planner into AiActiveVerify**

In `celsius/plugins/builtin.py`, `AiActiveVerify.run` — replace:

```python
        base = ctx.result.url or ctx.target.web_url()
        ctx.log(f"ai-active-verify: agentic proof loop on {base} ...")
        budget = Budget(max_tokens=2_000_000)   # don't starve the analysis of tokens
        try:
            # 1. Injection proof loop on discovered parameters (XSS/redirect/SQLi/…)
```

with:

```python
        base = ctx.result.url or ctx.target.web_url()
        ctx.log(f"ai-active-verify: agentic proof loop on {base} ...")
        budget = Budget(max_tokens=2_000_000)   # don't starve the analysis of tokens
        hunt_count = 0
        try:
            # 0. Hunt planner: the model reads the recon picture and proposes
            #    targeted hypotheses; the tool loop below proves/refutes them
            #    like any other ai-hypothesis. Additive — a failure here never
            #    blocks the existing loops.
            if cfg.ai_hunt:
                from ..ai import hunt
                try:
                    hyps = hunt.generate_hunt_hypotheses(
                        ctx.result.to_dict(), provider, budget=budget,
                        audit=ctx.audit, log=ctx.log, redact_secrets=cfg.ai_redact)
                    hunt_count = len(hyps)
                    ctx.result.findings.extend(hyps)
                except AIError as e:
                    ctx.result.errors.append(f"ai-hunt: {e}")

            # 1. Injection proof loop on discovered parameters (XSS/redirect/SQLi/…)
```

And update the recon record at the end of `run`:

```python
        ctx.result.recon["ai_active_verify"] = {
            "hunt_hypotheses": hunt_count,
            "injection_points": len(points), "injection_confirmed": len(inj),
            "hypotheses": len(hyps), "verdicts": vstats,
            "requests_sent": lab._count, "halted": lab.stopped_reason or None,
        }
```

(Note: the existing `"hypotheses": len(hyps)` line refers to the variable from
step 2 of the plugin — rename the planner's local to `hunt_hyps` if there's a
shadowing conflict: the plugin's later `hyps = [f for f in ...]` reassigns it
anyway, so `hunt_count` is the correct recorded value and no rename is needed.)

- [ ] **Step 6: Run test to verify it passes**

Run: `python tests/test_ai_hunt_plugin.py`
Expected: `PASS` for both tests, exit 0.

Also run the neighboring suites to catch regressions:
Run: `python tests/test_ai_agent.py && python tests/test_agent.py`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add celsius/config.py celsius/cli.py celsius/plugins/builtin.py tests/test_ai_hunt_plugin.py
git commit -m "feat(ai): wire hunt planner into lab-mode proof loop (--ai-hunt, default on)"
```

---

### Task 4: Web surface

**Files:**
- Modify: `celsius/web/app.py` (ScanRequest ~line 157-161, config construction ~line 284-285, `_AI_ENV` ~line 583)
- Modify: `celsius/web/static/index.html` (AI provider select ~line 179-185, lab-mode disclosure ~line 218)
- Modify: `celsius/web/static/app.js` (provider order ~line 204, request payload ~line 374)

**Interfaces:**
- Consumes: `ScanConfig.ai_hunt` (Task 3), `kimi` provider (Task 1).
- Produces: `ScanRequest.ai_hunt: bool = True` threaded into `ScanConfig`; `/api/ai/status` reports `kimi`; UI provider dropdown + AI-hunt checkbox.

- [ ] **Step 1: Backend wiring**

In `celsius/web/app.py`:

1. In `ScanRequest`, after `ai_redact` (line 161), add:

```python
    ai_hunt: bool = True    # lab mode: AI hunt planner proposes hypotheses from recon
```

2. In the ScanConfig construction (lines 284-285), change:

```python
        ai=req.ai, ai_provider=req.ai_provider, ai_model=req.ai_model,
        ai_base_url=req.ai_base_url, ai_api_key=req.ai_api_key, ai_redact=req.ai_redact,
```

to:

```python
        ai=req.ai, ai_provider=req.ai_provider, ai_model=req.ai_model,
        ai_base_url=req.ai_base_url, ai_api_key=req.ai_api_key, ai_redact=req.ai_redact,
        ai_hunt=req.ai_hunt,
```

3. In `_AI_ENV` (line 583), add the kimi entry:

```python
_AI_ENV = {"deepseek": "DEEPSEEK_API_KEY", "openai": "OPENAI_API_KEY",
           "anthropic": "ANTHROPIC_API_KEY", "kimi": "KIMI_API_KEY"}
```

(Keep any existing additional entries in that dict — add, don't replace.)

- [ ] **Step 2: Provider option + hunt checkbox in the UI**

In `celsius/web/static/index.html`:

1. In the provider `<select id="opt-ai-provider">` (line 179), add after the DeepSeek option:

```html
                  <option value="kimi">Kimi (Moonshot)</option>
```

2. In the lab-mode disclosure, after the `<label class="lab-enable">` line (line 218), add:

```html
        <label class="opt"><input type="checkbox" id="opt-ai-hunt" checked>
          <span class="opt-body"><span class="opt-name">AI hunt planner</span>
          <span class="opt-desc">The AI reads the recon picture, proposes targeted weakness hypotheses, then proves or refutes them through the lab guardrails.</span></span></label>
```

- [ ] **Step 3: app.js**

In `celsius/web/static/app.js`:

1. Line 204, add kimi to the front of the preference order:

```javascript
    const order = ["kimi", "deepseek", "openai", "anthropic", "local"];
```

2. At line 374, extend the payload:

```javascript
    ai: $("opt-ai").checked, ai_provider: $("opt-ai-provider").value,
    ai_hunt: $("opt-ai-hunt") ? $("opt-ai-hunt").checked : true,
```

- [ ] **Step 4: Verify**

Run the web-related tests plus a smoke import:

```bash
uv run --extra web python -c "from celsius.web.app import ScanRequest; print(ScanRequest.model_fields['ai_hunt'].default)"
uv run --group dev pytest -q tests/ -k "web or ai"
```

Expected: prints `True`; tests pass.

- [ ] **Step 5: Commit**

```bash
git add celsius/web/app.py celsius/web/static/index.html celsius/web/static/app.js
git commit -m "feat(web): kimi provider option + AI hunt planner toggle"
```

---

### Task 5: Docs + env plumbing

**Files:**
- Modify: `.env.example` (after line 11 `DEEPSEEK_API_KEY=`)
- Modify: `docker-compose.yml` (after line 35 `DEEPSEEK_API_KEY: ${DEEPSEEK_API_KEY:-}`)
- Modify: `README.md` (AI layer section)
- Modify: `AGENTS.md` (layout line ~99-100, env vars line ~166-167)
- Modify: `TODO.md` (Done section)

**Interfaces:**
- Consumes: everything from Tasks 1-4.
- Produces: user-facing documentation of the kimi provider, `KIMI_API_KEY`/`MOONSHOT_API_KEY` env vars, `--ai-hunt`/`--no-ai-hunt`, and the hunt planner behavior.

- [ ] **Step 1: env files**

`.env.example`, after `DEEPSEEK_API_KEY=`:

```
KIMI_API_KEY=
```

`docker-compose.yml`, after the `DEEPSEEK_API_KEY` line:

```yaml
      KIMI_API_KEY: ${KIMI_API_KEY:-}
```

- [ ] **Step 2: README.md**

In the AI layer section (find where `deepseek|openai|anthropic|local|mock` or the provider list is documented):

1. Update the provider list to include `kimi` (Moonshot; `KIMI_API_KEY`, fallback `MOONSHOT_API_KEY`, default model `kimi-k2-0711-preview`).
2. Add a short subsection:

```markdown
#### AI hunt planner (lab mode)

With `--lab --ai`, a hunt planner (`--ai-hunt`, default on) has the model read
the full recon picture — tech stack, endpoints, JS intel, subdomains, CVEs,
existing findings — and propose up to 10 targeted weakness hypotheses. Each is
labeled `ai-hypothesis` and must survive the same guardrailed proving loop
(tool evidence + deterministic corroboration) as any other hypothesis before it
is promoted to verified. Disable with `--no-ai-hunt`.
```

- [ ] **Step 3: AGENTS.md**

1. Layout section, `ai/` line: change `provider.py (deepseek/openai/anthropic/local=Ollama/mock)` to `provider.py (deepseek/openai/anthropic/kimi/local=Ollama/mock)` and add `hunt.py (recon-grounded hypothesis planner)` to the list.
2. Env vars section: add `` `KIMI_API_KEY` / `MOONSHOT_API_KEY` `` to the list.

- [ ] **Step 4: TODO.md**

In the `## Done (kept for reference)` section, add:

```markdown
- [x] Kimi (Moonshot) AI provider + lab-mode AI hunt planner (`--ai-hunt`)
```

- [ ] **Step 5: Full validation gate**

```bash
for t in tests/test_ai_provider_kimi.py tests/test_ai_hunt.py tests/test_ai_hunt_plugin.py; do python "$t"; done
uv run --group dev pytest -q
uv run --group dev ruff check celsius/
uv run --extra web --extra dynamic --group dev pyright celsius/
```

Expected: all tests pass standalone and under pytest; ruff 0 findings; pyright 0 errors / 0 warnings.

- [ ] **Step 6: Commit**

```bash
git add .env.example docker-compose.yml README.md AGENTS.md TODO.md
git commit -m "docs: kimi provider + AI hunt planner (env, README, AGENTS, TODO)"
```

---

## Self-Review Notes

- Spec coverage: provider (Task 1), hunt planner + prompts (Task 2), CLI/config/plugin + error handling (Task 3), web surface (Task 4), docs (Task 5). Testing strategy from the spec maps to the three new test files + the Task 5 validation gate.
- Type consistency: `generate_hunt_hypotheses` signature is identical in Task 2 (definition), Task 3 (call site), and both test files. `ScanConfig.ai_hunt` naming matches across config/CLI/plugin/web.
