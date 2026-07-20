# Celsius — Agent Guide

Local security scanner for web pages, public IPs, and source code, with a web UI
and an optional agentic AI layer. Python 3.10+, MIT license, flat package layout
(the package lives at the repo root as `celsius/`, not under `src/`).

## Project overview

Celsius is a vulnerability scanner whose **core is stdlib-only** — the CLI and
engine run on a bare Python install with zero third-party packages. Third-party
dependencies exist only behind extras:

- `web` — FastAPI + uvicorn + python-multipart, for `celsius serve` (the web UI).
  Mirrors `requirements.txt`.
- `dynamic` — Playwright, for headless-Chromium SPA analysis (`--dynamic`).

External binaries are optional and auto-discovered at runtime: `nmap` (service/OS
detection), `nuclei` (web vulnerability templates), plus `gitleaks`/`semgrep`/
`trufflehog` for the static code scan. Nothing may be added to the runtime
`dependencies` in `pyproject.toml` — that breaks the stdlib-only guarantee CI
enforces.

Main capabilities: passive recon (DNS-over-HTTPS, subdomain enum via crt.sh, TLS,
tech/CDN/WAF fingerprinting), CVE lookup against NVD + MITRE CNA with client-side
version-range matching, dependency audit (SCA) via OSV.dev, security-header/CSP/
JWT/CORS audits, crawl + JS intel + source-map recovery, front-end secret scan,
static code scan, an optional LLM layer (triage, code review, agentic proof loop),
and reports as terminal/JSON/HTML/SARIF/Markdown. The CLI exit code encodes the
worst severity found (30 CRITICAL / 20 HIGH / 10 MEDIUM / 0 otherwise).

## Build and test commands

Managed with [uv](https://docs.astral.sh/uv/) (build backend: `uv_build`). Plain
Python also works for the core.

```bash
# Run the CLI straight from a checkout (stdlib-only, no install needed)
python3 -m celsius https://example.com
uv run celsius https://example.com

# Web app — always pass BOTH extras; a plain `uv run` drops them
uv run --extra web --extra dynamic celsius serve        # http://127.0.0.1:8000
./run.sh                                                 # detached wrapper (PID + logs)

# Tests — two supported paths, both exercised in CI
for t in tests/test_*.py; do python "$t"; done           # standalone, stdlib-only
uv run --group dev pytest -q                             # shared pytest session

# Lint + type check (both blocking in CI; pyright needs the extras installed)
uv run --group dev ruff check celsius/
uv run --extra web --extra dynamic --group dev pyright celsius/

# Packaging
uv build
```

## Code organization

Entry point: `celsius = celsius.cli:main` (console script); `python -m celsius`
works too. Subcommands: `scan <target>` (default), `code <path>`, `serve`,
`history`, `recheck`, `monitor`, `typosquat`. Scan flags are grouped in argparse
groups, and `--profile quick|standard|deep` bundles common toggles (explicit
flags always win over the profile).

```
celsius/
  cli.py            CLI + subcommands + authorization gate (interactive prompt / --yes)
  engine.py         scan orchestration (run_scan) — plugin pipeline, scope/audit/persist;
                    optional progress=/cancelled= callbacks drive the web UI's
                    progress bar and Cancel button (CLI unaffected)
  config.py         ScanConfig dataclass (all scan toggles/flags)
  models.py         dataclasses: Service, CVE, Finding, ScanResult
  plugins/          plugin framework (base.py: Plugin, ScanContext, Phase, Mode,
                    @register) + all built-in checks (builtin.py, ~39 plugins)
  scope.py          scope.yml authorization gate (mode/exclusion gating)
  audit.py          append-only audit log (every active probe, every AI send)
  store.py          SQLite persistence + scan history
  targets.py        URL/host/IP parsing & resolution
  http_analysis.py  header fetch, service detection, missing-CSP/header audit
  webchecks.py      CSP directive-quality evaluation (single authoritative evaluator)
  portscan.py       nmap -sV / -O wrapper (XML parsing, per-IP cache)
  cve.py            NVD + MITRE CNA lookup, version-range matching, trickest PoCs
  version.py        pragmatic numeric version comparator (not full PEP 440/semver)
  nuclei_scan.py    optional nuclei wrapper
  secrets.py        secret signatures (regex) + Shannon entropy
  codescan.py       static code scan (secrets + SAST-lite + external tools)
  websecrets.py     front-end secret scan (HTML + linked JS)
  poc.py            text-only PoC / reproduction steps per finding
  report.py         terminal / JSON / HTML / SARIF / Markdown rendering
  exploitability.py EPSS + CISA KEV scoring → verdict/priority/how-to
  correlate.py      exploit-chain correlation (findings → attack paths)
  completeness.py   completeness critic + blue-team detection rules
  recon/            attack surface & client-side: dns (DoH), subdomains (crt.sh),
                    tls, fingerprint, crawler, jsintel, sourcemaps, apidisco,
                    wpcheck (WordPress checks, safe-active), content_discovery,
                    dynamic (Playwright), cohost, origin, wayback, robots, …
  active/           lab-mode active verification: harness.py is THE safety
                    chokepoint; verifiers.py has the non-destructive probes
  ai/               LLM layer: provider.py (deepseek/openai/anthropic/local=Ollama/
                    mock), agent.py (proof loop), analyze.py, prompts.py,
                    redact.py (secret masking), cache.py
  web/              app.py (FastAPI backend: scan jobs + progress/cancel, history
                    with export/delete, code upload, AI status) + static/
                    (single-page UI: index.html, app.js, style.css — no build step)
```

### Plugin architecture

Checks are plugins: subclass `Plugin` in `celsius/plugins/base.py`, set `id`,
`title`, `phase` (RECON=1 → DETECT=2 → ENRICH=3, ascending), `mode`
(`passive` / `safe-active` / `exploit` — the least-intrusive mode needed), and
`category`; decorate with `@register`. `run(ctx)` mutates `ctx.result` and must
**not** raise on target errors — append to `ctx.result.errors` instead.
`engine.py` runs all registered plugins in phase order, gated by scope mode and
`enabled(ctx)`. Built-ins live in `plugins/builtin.py`; the `recon/` and `active/`
packages hold the heavier implementations those plugins call.

## Development conventions

- **Stdlib-only core, unconditionally.** No third-party imports outside the
  `web`/`dynamic` code paths (import those lazily/guarded so the CLI never
  requires them). CI byte-compiles everything and runs the full suite on bare
  Python 3.10 and 3.12.
- Type checking is **pyright basic mode, 0 errors / 0 warnings**, run with the
  extras installed so `reportMissingImports` stays on (it catches typo'd
  first-party imports). Lint is **ruff** (target py310, default rules).
- Docstrings/comments are English and explanatory — modules carry a header
  docstring stating intent and non-obvious invariants. Match that density.
- Version lives in two places kept in sync: `pyproject.toml` (`version`) and
  `celsius/__init__.py` (`__version__`) — `tests/test_packaging.py` guards drift.
  Bump both.
- `requirements.txt` mirrors the `web` extra; keep them aligned if it changes.
- Don't add speculative config knobs; CLI flags flow through `ScanConfig` in
  `config.py` and are threaded to plugins via `ScanContext`.
- The web UI is a static single-page app with no JS build tooling — edit
  `celsius/web/static/` directly. Those assets are shipped in the wheel via
  `source-include` in `pyproject.toml`.

## Testing strategy

- Tests are plain pytest-style functions in `tests/test_*.py`, one file per
  module/area (~65 files). They deliberately **monkeypatch module-level callables
  directly** (e.g. `portscan.subprocess.run = fake`) instead of using fixtures,
  so each file also runs **standalone**: `python tests/test_x.py` (the
  `if __name__ == "__main__"` runner at the bottom of each file executes every
  `test_*` function). Keep that runner block in any new test file.
- `tests/conftest.py` holds an autouse fixture that snapshots and restores
  module `__dict__`s so a shared pytest session gets the isolation standalone
  runs get for free. It only activates under pytest.
- CI (`.github/workflows/ci.yml`) has three jobs: `stdlib` (py_compile all files,
  CLI smoke test, standalone test loop on 3.10 + 3.12), `quality` (ruff, pyright,
  pytest — all blocking), and `package` (`uv build`, web-extra resolution).
- No network in unit tests — mock HTTP/subprocess at the module boundary.

## Runtime data & configuration

- Data lives under `$HOME`: scan store + audit + trace log at
  `~/.local/share/celsius/` (`history` SQLite, `audit.log`, `scan.log`), caches at
  `~/.cache/celsius/`. In Docker `$HOME` is `/data`.
- `scope.yml` (see `scope.yml.example`) authorizes targets and modes
  (`passive` / `safe-active` / `exploit`), with glob `exclusions` that always win
  and a `rate_limit_rps` cap. Without a scope file, passive + safe-active are
  allowed after the interactive confirmation; `exploit` always requires an
  explicit scope entry.
- Env vars: `CELSIUS_TOKEN` (web API auth token), `CELSIUS_CODE_ROOT` (restrict
  `/api/code` file reads), `DEEPSEEK_API_KEY` / `OPENAI_API_KEY` /
  `ANTHROPIC_API_KEY`, `NVD_API_KEY`, `SHODAN_API_KEY`, `CENSYS_PAT` /
  `CENSYS_ORG_ID`. `docker-compose.yml` reads them from a gitignored `.env`
  (`.env.example` documents them). Never commit real keys or read `.env` into
  code — the app reads the environment directly.

## Security considerations

This is an offensive-security tool; its safety model is a first-class part of the
architecture. Preserve these invariants when editing:

- **Authorization gate**: every host scan requires interactive confirmation or
  `--yes`; the web API returns 403 without the authorization checkbox. Scope
  exclusions are enforced even for listed targets.
- **Lab mode (`--lab` + friends) is layered**: it requires the flag AND a scope
  entry with `exploit` mode AND a per-run attestation. All active verification
  traffic funnels through `celsius/active/harness.py` — that is the single
  chokepoint enforcing the request cap, rate limit, kill-switch file
  (`~/.celsius-stop`), and audit logging. Do not bypass it.
- **AI privacy**: secret redaction before sending anything to an LLM is default
  ON (`ai/redact.py`); every external send is recorded in the audit log with
  `masked` and `sensitive_count`. AI output is always labeled `ai-hypothesis` —
  never present model output as verified fact.
- **The model never sends requests** in the agentic proof loop: it plans, the
  harness sends (payloads validated read-only), it judges.
- Web API: `/api/code` may only read files under `CELSIUS_CODE_ROOT`;
  `CELSIUS_TOKEN` auth protects all `/api/*` when set (one is auto-generated and
  logged otherwise).

## Deployment

- Docker is the recommended deploy (also the clean way to get working `nmap -O`:
  the process is root *inside* the container — namespaced, with only
  `NET_RAW`/`NET_ADMIN` caps, no `--privileged`).
  `docker compose up -d --build` → http://localhost:8011 (host 8011 → container
  8000). The image (python:3.11-slim) bundles nmap + pinned nuclei, syncs deps
  with `uv sync --frozen --extra web --no-dev`, and stores data in `/data`
  (bind-mounted to the host's `~/.local/share/celsius` + `~/.cache/celsius` in
  `docker-compose.yml`).
- `./run.sh` / `./kill.sh` manage a local detached server (PID file +
  `celsius-serve.log` in the repo root).

## Reference docs

- `README.md` — full user docs: feature list, CLI flags, lab-mode classes, AI
  layer, CVE-matching design. **Update it when you change user-facing behavior.**
- `plan.md` — the shipped M0–M6 roadmap; `TODO.md` — future-work backlog.
