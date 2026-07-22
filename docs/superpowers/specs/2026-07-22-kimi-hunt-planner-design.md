# Kimi provider + AI hunt planner — design

Date: 2026-07-22
Status: approved (design), pending implementation plan
Cycle: 1 of 2 (cycle 2 = web UI redesign, separate spec)

## Goal

Make celsius's agentic active-hunting loop smarter and add Moonshot's Kimi as a
first-class AI provider:

1. **Kimi provider** — `--ai-provider kimi`, default model `kimi-k2-0711-preview`,
   usable by every existing AI surface (scan triage, code review, lab-mode proof
   loop, web UI).
2. **Hunt planner** (`celsius/ai/hunt.py`) — in lab mode, the model reads the full
   recon picture and generates ranked, testable weakness hypotheses that flow into
   the existing `prove_hypotheses` / `agentic_verify` loops for guardrailed
   proving. Nothing unproven ever leaves the `ai-hypothesis` tier.

Non-goals for this cycle: UI redesign, non-AI scanner improvements (rate-limiting,
ASN recon, etc.), any rewrite of the existing agent loops or safety chokepoints.

## Safety invariants (unchanged, explicitly preserved)

- Every target request goes through `celsius/active/harness.py` (scope, attestation,
  request cap, rate limit, kill-switch, audit). The hunt planner sends nothing
  itself — it only *proposes*; the existing loops do the sending.
- Payload validation (`_safe_payload`), destructive-payload filter, and the
  deterministic corroboration backstops (`_corroborated`,
  `_evidence_corroborated`) are untouched.
- Secret redaction (`ai/redact.py`) applies to all new model-bound context; every
  send is audit-logged with `masked`/`sensitive_count`.
- Model output is labeled `ai-hypothesis` until deterministically corroborated;
  only corroborated results reach `ai-active-verify` / priority-90.
- The planner only runs when `ctx.config.ai and ctx.config.allow_exploit` — the
  same gate as the existing `AiActiveVerify` plugin (lab mode + scope exploit
  entry + attestation).

## Section 1 — Kimi provider

`celsius/ai/provider.py`:

- New `KimiProvider(OpenAICompatProvider)`:
  - `name = "kimi"`
  - `default_model = "kimi-k2-0711-preview"`
  - `default_base_url = "https://api.moonshot.ai/v1"`
  - `supports_json_mode = True`
  - `_env_var()` → `"KIMI_API_KEY"`; env fallback also accepts `MOONSHOT_API_KEY`
    when `KIMI_API_KEY` is unset (implemented in `get_provider` env resolution).
- Registered in `_PROVIDERS` and `_ENV_KEYS`.
- Existing `_validate_base_url` https-only rule applies unchanged.
- No new dependencies (rides the stdlib urllib path); core stays stdlib-only.

Wiring:

- `web/app.py` `_AI_ENV` gains the kimi entry so `GET /api/ai/status` reports it.
- Web UI provider dropdown (`celsius/web/static/`) gains `kimi`.
- Docs: `AGENTS.md` (env var list), `README.md` (AI layer section),
  `.env.example` (`KIMI_API_KEY`).

## Section 2 — hunt planner (`celsius/ai/hunt.py`)

One new module, one public function:

```python
def generate_hunt_hypotheses(result_dict, provider, *, budget, audit, log,
                             redact_secrets=True, max_hypotheses=10) -> list[Finding]
```

**Model context** (assembled from `ScanResult.to_dict()`, redacted via
`redact_obj` before sending):

- tech stack + versions, CDN/WAF, TLS posture (recon tech/fingerprint/tls)
- crawled endpoints, parameterized points, JS-intel findings (routes, API calls,
  prototype-pollution sinks), recovered source maps
- subdomains, co-hosted sites, origin-IP leaks, WordPress/API discovery results
- matched CVEs (id + severity only, not full blobs)
- existing deterministic findings (title + category only — build on, don't
  duplicate)

**Output contract** (JSON, parsed with the existing `parse_json` tolerance):
each hypothesis has `title`, `category` (a vuln class such as `exposed-admin`,
`debug-endpoint`, `takeover`, `jwt-weakness`, `cve-chain`), `rationale`,
`suggested_tool` (one of `verify_tools.TOOL_SPECS` names or `none`), and
`severity_guess`. Malformed items are dropped individually; a wholly unusable
response yields zero hypotheses and a log line.

**Conversion:** valid hypotheses become `Finding` objects with
`category="ai-hypothesis"`, `confidence="low"`, title prefixed `[AI hunt] ` —
exactly the shape `prove_hypotheses` already consumes. Severity comes from
`severity_guess` mapped through the existing `_to_sev`, defaulting to LOW —
these are unverified leads until the tool loop proves them.

**Data flow** (inside the existing `AiActiveVerify` plugin,
`plugins/builtin.py:1299`):

```
recon/plugins finish → AiActiveVerify runs (lab mode only)
  ├─ NEW: hunt.generate_hunt_hypotheses(...) → findings += [AI hunt] hypotheses
  ├─ existing: agentic_verify (injection points)         [unchanged]
  └─ existing: prove_hypotheses (proves/refutes all ai-hypothesis findings,
               now including hunt hypotheses)             [unchanged]
```

**Bounds:** `max_hypotheses=10` caps token use and downstream lab requests; the
planner shares the plugin's `Budget`; prompt lives in `ai/prompts.py`
(`AGENT_HUNT_SYSTEM` + `hunt_user_prompt(context)`), matching existing style.

## Section 3 — surface, error handling, testing

**CLI / config**

- No new flag for the provider — `--ai-provider kimi` flows through existing
  `ScanConfig.ai_provider`.
- New flag `--ai-hunt / --no-ai-hunt` → `ScanConfig.ai_hunt: bool = True`.
  Default on means lab+AI scans gain hypotheses; `--no-ai-hunt` restores exact
  prior behavior.
- Web API: `ScanRequest` gains `ai_hunt: bool = True`; web UI AI section gains
  the "Kimi" provider option and an "AI hunt planner" checkbox (shown with the
  lab-mode controls).

**Error handling**

- `AIError` from the planner is caught inside `AiActiveVerify`, appended to
  `result.errors`; the injection/tool loops still run (hunt is additive, never
  blocking).
- Provider unavailable / empty or garbage response → zero hypotheses, log, move
  on. Existing kill-switch / request-cap behavior during proving is unchanged.

**Testing** (project conventions: plain functions, monkeypatched module
boundaries, standalone runner block, no network)

- `tests/test_ai_provider_kimi.py` — registration, env-key fallback order
  (`KIMI_API_KEY` then `MOONSHOT_API_KEY`), default model/base URL, request
  shape, https base-url validation.
- `tests/test_ai_hunt.py` — `generate_hunt_hypotheses` with `MockProvider`
  canned responses: valid JSON → correctly shaped `ai-hypothesis` findings;
  malformed items dropped individually; `max_hypotheses` cap enforced; redaction
  invoked on model-bound context.
- Plugin-level test: hunt hypotheses are generated before `prove_hypotheses`
  runs and flow into it; `--no-ai-hunt` skips the planner.
- Validation gate: `ruff check celsius/`, `pyright celsius/` (0 errors / 0
  warnings), full `pytest -q`, plus standalone `python tests/test_ai_hunt.py` /
  `python tests/test_ai_provider_kimi.py`.

**Docs**

- `README.md`: AI layer section — kimi provider, hunt planner behavior, flag.
- `AGENTS.md`: env vars, `ai/hunt.py` in the layout, flag note.
- `TODO.md`: nothing removed; optionally note hunt planner as done after ship.
