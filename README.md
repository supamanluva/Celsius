<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.png">
  <img src="docs/logo-light.png" alt="Celsius — local security scanner" width="460">
</picture>

### Local security scanner — web, network &amp; source code

<p>
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-3fb96b" alt="MIT License">
  <img src="https://img.shields.io/badge/core-stdlib--only-5b82f7" alt="stdlib-only core">
  <img src="https://img.shields.io/badge/UI-light%20%2F%20dark-7c5cff" alt="light / dark UI">
</p>

Passive recon · OS/platform &amp; EOL fingerprinting · CVE + dependency (SCA) ·
authenticated &amp; headless-browser scanning · CORS/JWT/takeover checks ·
email security · an **agentic AI proof loop** — with a polished web UI and a
stdlib-only core.

</div>

---

## Screenshots

<p align="center">
  <img src="docs/screenshot-home.png" alt="Celsius web UI" width="820">
</p>
<table>
<tr>
  <td width="50%"><img src="docs/screenshot-scan.png" alt="Scan results"><br><em>Host/web scan — services, attack surface, findings, one-click HTML report</em></td>
  <td width="50%"><img src="docs/screenshot-mail.png" alt="Email security scorecard"><br><em>Email security — SPF/DKIM/DMARC/MTA-STS graded A–F with exact fixes</em></td>
</tr>
</table>

---

**Celsius** is a lightweight vulnerability scanner for web pages, public IPs, **and source
code**, with a **web UI**, an **agentic AI proof loop**, and **text-only proof-of-concept**
generation. It:

- **maps the attack surface** — DNS records (via DoH), subdomains (crt.sh CT
  logs), TLS/certificate analysis, and tech/CDN/WAF/CMS fingerprinting, plus a
  **temporal diff** flagging what's new since the last scan;
- **detects running services and versions** — from HTTP `Server`/`X-Powered-By`
  headers, **tech fingerprinting** (with versions), and (optionally) an
  `nmap -sV` port scan;
- **looks up known CVEs** for those versions against the **NVD**, with
  client-side version-range matching that also catches *freshly published* CVEs
  NVD hasn't enriched yet (via the MITRE CNA records);
- **audits web security headers** — CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, cookie flags, version disclosure;
- **deep web checks** — evaluates CSP *content* (unsafe-inline/eval, wildcards,
  missing base-uri/frame-ancestors), analyses JWTs (alg=none, weak HMAC, no
  expiry), probes **CORS** misconfiguration (reflected/`null` origin with
  credentials), checks `security.txt`, and detects dangling-CNAME **subdomain
  takeover**;
- **checks email security** (`--mail`) — SPF, DKIM, DMARC, MTA-STS, TLS-RPT,
  DNSSEC and BIMI for a domain, graded A–F, each gap reported with the exact DNS
  record to add and which mailserver it applies to (passive: DoH lookups only);
- **infers OS/platform passively** — derives OS family + server-side runtime from
  headers/cookies (JSESSIONID→Java/Tomcat, ASP.NET→Windows/IIS, Server-header OS
  hints, F5/CDN/LB edge), and flags **end-of-life** software (PHP, IIS→Windows
  Server, Apache, Tomcat, OpenSSL, CentOS) that no longer gets security patches;
- **crawls & analyzes client-side code** — discovers API endpoints/routes in JS,
  detects DOM-XSS sinks, recovers **hidden original source from exposed source
  maps** (and scans it for secrets), and finds OpenAPI/Swagger + GraphQL APIs;
- **dynamic SPA analysis** (`--dynamic`, needs Playwright) — drives a headless
  browser to render single-page apps, follow client-side routes, capture the
  XHR/fetch endpoints they actually call, and scan the post-JS DOM for sinks the
  static HTML never contains (honours the authenticated session);
- **scans front-end content for exposed secrets** (HTML + linked JS);
- **scans source code** for hardcoded secrets (regex + entropy) and risky
  patterns (SAST-lite), integrating `gitleaks`/`semgrep`/`trufflehog` if present;
- **audits dependencies (SCA)** — parses lockfiles/manifests (npm, PyPI,
  Packagist, RubyGems, Go, crates.io) and flags known-vulnerable versions via
  the OSV.dev database (no API key), with CVE ids and fixed versions;
- **assesses exploitability** — enriches every CVE/finding with EPSS (exploitation
  probability), CISA **KEV** (exploited in the wild), and reachability, into a
  verdict + priority and a *"how to check if exploitable"* decision tree;
- **correlates exploit chains** — composes individual findings into scored attack
  paths (e.g. exposed source map → leaked credential → reachable API), plus a
  completeness critic and blue-team detection-rule generation;
- generates **non-destructive PoC / reproduction steps** for each finding/CVE;
- optionally runs **nuclei** web-vulnerability templates;
- ships a **web app** (FastAPI) and produces **terminal, JSON, HTML, SARIF, and
  Markdown** reports (`--sarif`/`--markdown` for CI/IDE ingestion).

Stdlib-only scanning core — the CLI needs no dependencies. `nmap`/`nuclei` are
optional external binaries (auto-discovered, incl. `~/go/bin`). The **web app**
needs `fastapi`/`uvicorn`, pulled in by the `web` extra.

## Install

Managed with [uv](https://docs.astral.sh/uv/). The CLI is stdlib-only, so for a
quick run you don't even need to install anything:

```bash
# Run straight from a checkout — uv builds + caches it for you
uv run celsius https://example.com

# Or install the CLI as a tool on your PATH
uv tool install .                # then: celsius https://example.com

# Web app needs the `web` extra (fastapi/uvicorn)
uv run --extra web celsius serve            # http://127.0.0.1:8000

# Optional: dynamic SPA analysis (--dynamic) needs the `dynamic` extra + Chromium
uv sync --extra dynamic && uv run playwright install chromium
```

No uv? The stdlib core still runs with plain Python — `python3 -m celsius
<target>` — and the web app works under a classic venv:
`python3 -m venv .venv && .venv/bin/pip install -e '.[web]'`.

## Web app

```bash
uv run --extra web celsius serve            # http://127.0.0.1:8000
# convenience wrapper (detached, PID + logs): ./run.sh   (prefers uv, falls back to venv)
```

The UI has two tabs — **Host/Web scan** (target + options, live log, colour-coded
services/CVEs/findings, a *PoC steps* button on every item) and **Code & secret
scan** (server-side path or pasted snippet). An authorization checkbox gates all
host scanning; the API returns `403` without it.

## ⚠️ Authorized use only

Scanning hosts you do not own or lack **written permission** to test may be
illegal (in Sweden e.g. under brottsbalken / dataintrångs provisions) and can
disrupt services. The tool requires an interactive confirmation; `--yes` asserts
you are authorized. Only point it at your own systems or sanctioned engagements
(pentest scope, bug-bounty in-scope, CTF, lab).

## CLI usage

> Examples below use `python3 -m celsius` (works with zero install). If you ran
> `uv tool install .`, just use `celsius …`; from a checkout, `uv run celsius …`.

```bash
# Host/web scan — headers + CVE lookup + front-end secrets (default)
python3 -m celsius https://example.com           # = `celsius scan https://example.com`

# Add nmap service scan, nuclei, and print PoC/reproduction steps
python3 -m celsius example.com --ports --nuclei --poc

# Specific ports, JSON + HTML output
python3 -m celsius 203.0.113.10 --ports --port-range 80,443,8080 \
    --json report.json --html report.html

# Non-interactive (e.g. CI) — asserts authorization
python3 -m celsius https://mysite.example --yes --json out.json

# Static code / secret scan of a repo (or a single file)
python3 -m celsius code /path/to/repo --json code-report.json

# Launch the web app
python3 -m celsius serve --host 127.0.0.1 --port 8000

# Authorize targets/modes with a scope file; disable active checks
python3 -m celsius scan example.com --scope scope.yml --no-active

# List past scans (stored locally in SQLite)
python3 -m celsius history

# Attack surface: DNS + TLS + fingerprint run by default; add subdomain enum
python3 -m celsius scan https://example.com --subdomains

# Crawl + JS analysis (endpoints, DOM sinks, source-map recovery) + API discovery
python3 -m celsius scan https://example.com --crawl --api-discovery

# AI analysis (DeepSeek by default) — triage + attack-surface hypotheses
export DEEPSEEK_API_KEY=sk-...
python3 -m celsius scan https://example.com --ai

# AI secure-code review (pluggable provider; offline 'mock' needs no key)
python3 -m celsius code /path/to/repo --ai --ai-provider deepseek
```

Subcommands: `scan <target>` (default), `code <path>`, `serve`, `history`.

### AI layer (M2)

`--ai` adds an LLM pass: **triage** (prioritize, flag likely false positives) and
**attack-surface hypotheses** (business-logic/chained issues signatures miss) on a
scan, or a **secure-code review** on `code`. Providers are pluggable —
`--ai-provider deepseek|openai|anthropic|local|mock` (keys via
`DEEPSEEK_API_KEY`/`OPENAI_API_KEY`/`ANTHROPIC_API_KEY`; `local` targets Ollama;
`mock` is offline for testing).

All AI output is labeled **`ai-hypothesis`** with a confidence and a
non-destructive verification step — proposals to confirm, never auto-verified
facts. Responses are cached and bounded by a token budget.

**Privacy:** secret redaction before sending to the model is **optional and
default OFF** (`--ai-redact` to enable) — full context gives the best detection,
and the report carries full secret values for the owner to rotate. Every external
send is recorded in the audit log with `masked` (was masking applied) and
`sensitive_count`. Use `--ai-provider local` to keep everything on-machine.

#### Local / on-prem AI (Ollama) — nothing leaves the machine

celsius speaks the OpenAI-compatible API, so any local server works. With
[Ollama](https://ollama.com):

```bash
ollama pull llama3.1            # or qwen2.5, mistral, … (any model you have)
# Ollama auto-serves an OpenAI-compatible API at http://localhost:11434/v1

# CLI:
python3 -m celsius scan https://example.com --ai --ai-provider local --ai-model llama3.1
# non-default host/port:
python3 -m celsius scan ... --ai --ai-provider local --ai-base-url http://192.168.1.5:11434/v1
```

**In the web UI:** tick **AI analysis**, choose **Local (Ollama)** in the provider
dropdown, leave the API key blank, and (optionally) set the **model** and **base
URL** fields. Blank ⇒ defaults `llama3.1` at `http://localhost:11434/v1`. Then scan.

### Governance (M0)

Scans run as a **phase-ordered plugin pipeline** (recon → detect → enrich), are
**persisted** to a local SQLite store (browse via `history` or the web History
tab), and every active probe is written to an append-only **audit log**
(`~/.local/share/celsius/audit.log`). A `scope.yml` (see `scope.yml.example`)
authorizes which hosts may be scanned and in which **mode**:

- `passive` — ordinary HTTP + third-party lookups (NVD)
- `safe-active` — scanners/probes (nmap, nuclei), benign & non-destructive
- `exploit` — lab-mode active verification (opt-in, guardrailed; see Lab mode below)

Without a scope file, the default permits passive + safe-active for any target
you confirm; `exploit` always requires an explicit scope entry.

### Lab mode (M5) — active verification

`--lab` enables **non-destructive active verification**: it CONFIRMS or refutes
suspected vulnerabilities with benign payloads (a unique reflected-XSS marker, an
open-redirect canary, a read-only traversal canary, a single-quote SQLi probe).
Confirmed issues are marked `confirmed-exploitable`.

It is gated by a layered safety harness — **all** must hold:
1. `--lab` flag set, **and**
2. a `--scope` file listing the target with `exploit` mode, **and**
3. a per-run attestation (`--lab-attest "..."` or the interactive prompt).

Plus: `--dry-run` previews every payload without sending it; a kill-switch file
`~/.celsius-stop` halts immediately; `--exploit-max-requests`/`--exploit-rate-limit`
bound the activity; and **every** active request is written to the audit log.

```bash
python3 -m celsius scan https://lab.local/ --lab --scope scope.yml \
    --lab-attest "I am authorized to actively test lab.local" --dry-run   # preview first
```

Lab mode is **CLI-only by design** — active exploitation is not exposed in the web UI.

#### Agentic AI proof loop (`--lab --ai`)

Add `--ai` to lab mode to run an **AI-driven prove-it loop**: the model reads the
live attack surface and *plans* high-signal, non-destructive probes (which
parameter, which benign payload, what would prove it); the **same lab harness**
sends each request under the guardrails above; then the model *judges* the real
response and only **proven** issues become `[AI-verified]` findings
(`confirmed-exploitable`). The model never sends a request itself, payloads are
validated read-only (no DROP/DELETE/OS-commands/time-based), and the request
cap/rate-limit/kill-switch/audit all still apply. This is celsius's take on
"no exploit, no report".

```bash
python3 -m celsius scan https://lab.local/?q=test --lab --ai --scope scope.yml \
    --lab-attest "I am authorized to actively test lab.local"
```

### Useful flags

| Flag | Meaning |
|------|---------|
| `--no-web` | skip HTTP header/CSP analysis |
| `--no-cve` | skip the NVD CVE lookup |
| `--full` / `--thorough` | enable every safe check at once (ports, nuclei, subdomains, crawl, API discovery, mail, CVE-verify, OS detect) |
| `--cookie` / `--bearer` / `--header` | authenticated scan: attach a session/token to every request |
| `--login-url` (+ `--login-user`/`--login-pass`) | form login: log in first, then scan as that user |
| `--mail` | check email security (SPF/DKIM/DMARC/MTA-STS/TLS-RPT/DNSSEC/BIMI), graded A–F |
| `--ports` | run `nmap -sV` (off by default) |
| `--top-ports N` / `--port-range "80,443"` | port selection for nmap |
| `--nuclei` | run nuclei templates (if installed) |
| `--nvd-api-key KEY` | NVD API key (or `NVD_API_KEY` env) for higher rate limits |
| `--insecure` | skip TLS certificate verification |
| `--json FILE` / `--html FILE` | write reports |
| `-v, --verbose` | show per-step progress on stderr even when piped |
| `--debug` | verbose + debug detail (tool commands, nmap/nuclei stderr) |
| `--quiet` | only show errors on stderr |
| `--log-file PATH` | override the trace file (default `~/.local/share/celsius/scan.log`) |
| `-y, --yes` | skip the authorization prompt |

Exit code encodes the worst severity found (30 CRITICAL / 20 HIGH / 10 MEDIUM /
0 otherwise), handy in CI gates.

### Authenticated scanning

By default celsius scans as an anonymous, logged-out visitor. To reach surfaces
behind a login, attach a session — the crawler, secret scan, API discovery,
nuclei and active checks all run as that user:

```bash
# reuse a session you grabbed from the browser
celsius scan https://app.example.com --full --cookie "session=abc; csrf=xyz" -y
# or a bearer token
celsius scan https://api.example.com --bearer "$TOKEN" --crawl -y
# or let celsius log in via the form (CSRF hidden fields are auto-filled)
celsius scan https://app.example.com --full \
  --login-url https://app.example.com/login --login-user alice --login-pass secret -y
```

⚠️ An authenticated **active** scan sends requests as the logged-in user and can
change state (submit forms, etc.). Use a **test account / staging**. Every scan
that carries a session is recorded in the audit log.

### Logging

Every scan is always traced to a rotating log at
`~/.local/share/celsius/scan.log` (DEBUG level, independent of whether stderr is
a terminal) — so there is a durable record of what ran and what errored, including
the exact `nmap`/`nuclei` command lines and their stderr at `--debug`. The console
shows per-step progress on a TTY by default; `-v` forces it when piped, `--debug`
adds tool detail, `--quiet` limits it to errors. Scans launched from the web app
write to the same file. This is separate from the append-only **audit log**
(`~/.local/share/celsius/audit.log`), which records the accountability trail of
active probes.

## How CVE matching works (and why it's not just one API call)

Freshly published CVEs sit in NVD as *"Awaiting Analysis"* for days/weeks with
**no CPE configuration**, and their descriptions rarely name the exact affected
version. A naive `cpeName=`/keyword query therefore **misses the recent,
high-impact CVEs you care about most**. So celsius:

1. **Discovers** candidate CVEs for a product via one cached NVD keyword search.
2. **Version-matches each candidate client-side**:
   - against NVD's CPE version ranges when the CVE is *enriched*; otherwise
   - against the **MITRE CNA record's** structured `affected[].versions` semver
     ranges, available immediately on publication.
3. Filters CNA candidates by **product** (accept/reject regexes) so unrelated
   products the keyword search drags in (e.g. `ingress-nginx`, WordPress
   plugins) can't cause false positives.

Only authoritative sources (NVD + MITRE) are used — never search-engine results,
which are increasingly polluted with AI-invented "CVEs".

> Worked example: nginx **1.29.6** is affected by **CVE-2026-42945** (range
> `0.6.27`–`<1.30.1`) but **not** CVE-2026-9256, whose real affected ranges
> (`0.1.17`–`0.9.7`, `1.30.0`–`1.30.1`, `1.31.0`) exclude 1.29.6 — even though
> some Google summaries claim otherwise.

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) — `curl -LsSf https://astral.sh/uv/install.sh | sh`
- `nmap` (optional, for `--ports`)
- `nuclei` (optional, for `--nuclei`) — `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

## Layout

```
celsius/
  cli.py            CLI + subcommands (scan/code/serve/history) + auth gate
  engine.py         plugin-pipeline orchestration (run_scan) + scope/audit/persist
  config.py         ScanConfig dataclass
  plugins/          plugin framework (base.py) + built-in checks (builtin.py)
  scope.py          scope.yml authorization gate (mode/exclusion gating)
  audit.py          append-only audit log
  store.py          SQLite persistence + scan history
  ai/               LLM layer: provider.py (DeepSeek/OpenAI/Anthropic/local/mock),
                    analyze.py (triage + code review), prompts.py, redact.py, cache.py
  exploitability.py exploitability assessment (EPSS + CISA KEV + verdict + how-to)
  correlate.py      exploit-chain correlation (composes findings into attack paths)
  completeness.py   completeness critic + blue-team detection-rule generation
  active/           lab-mode active verification: harness.py (safety chokepoint),
                    verifiers.py (XSS/redirect/traversal/SQLi, non-destructive)
  recon/            attack surface + client-side: dns.py (DoH), subdomains.py
                    (crt.sh), tls.py (cert/protocol), fingerprint.py (tech/WAF/CDN),
                    crawler.py, jsintel.py (endpoints/sinks), sourcemaps.py
                    (recover hidden source), apidisco.py (OpenAPI/GraphQL), dynamic.py
  targets.py        URL/host/IP parsing & resolution
  http_analysis.py  header fetch, service detection, security-header audit
  portscan.py       nmap -sV wrapper (XML parsing)
  cve.py            NVD + MITRE CNA CVE lookup with version-range matching
  version.py        version comparison / range checks
  nuclei_scan.py    optional nuclei wrapper
  secrets.py        secret signatures (regex) + Shannon entropy
  codescan.py       static code scan (secrets + SAST-lite + ext. tools)
  websecrets.py     front-end secret scan (HTML + linked JS)
  poc.py            text-only PoC / reproduction generator
  report.py         terminal / JSON / HTML rendering
  models.py         dataclasses (Service, CVE, Finding, ScanResult)
  web/
    app.py          FastAPI backend (scan jobs, code, poc)
    static/         single-page UI (index.html, app.js, style.css)
```

## Limitations

- Banner/header versions can be spoofed or hidden (`server_tokens off`); absence
  of a version means no CVE lookup (kept conservative to avoid noise).
- `version.py` is a pragmatic numeric comparator, not full PEP 440 / semver.
- CVE coverage depends on the built-in product→CPE map; unknown products are
  reported as "verify manually".

## License

MIT — see [LICENSE](LICENSE). For authorized security testing only.
