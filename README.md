# secscan

A lightweight vulnerability scanner for web pages, public IPs, **and source
code**, with a **web UI** and **text-only proof-of-concept** generation. It:

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
- **crawls & analyzes client-side code** — discovers API endpoints/routes in JS,
  detects DOM-XSS sinks, recovers **hidden original source from exposed source
  maps** (and scans it for secrets), and finds OpenAPI/Swagger + GraphQL APIs;
- **scans front-end content for exposed secrets** (HTML + linked JS);
- **scans source code** for hardcoded secrets (regex + entropy) and risky
  patterns (SAST-lite), integrating `gitleaks`/`semgrep`/`trufflehog` if present;
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

Stdlib-only scanning core — the CLI needs no `pip install`. `nmap`/`nuclei` are
optional external binaries (auto-discovered, incl. `~/go/bin`). The **web app**
needs `fastapi`/`uvicorn` (see `requirements.txt`).

## Web app

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m secscan serve            # http://127.0.0.1:8000
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

```bash
# Host/web scan — headers + CVE lookup + front-end secrets (default)
python3 -m secscan https://example.com           # = `secscan scan https://example.com`

# Add nmap service scan, nuclei, and print PoC/reproduction steps
python3 -m secscan example.com --ports --nuclei --poc

# Specific ports, JSON + HTML output
python3 -m secscan 203.0.113.10 --ports --port-range 80,443,8080 \
    --json report.json --html report.html

# Non-interactive (e.g. CI) — asserts authorization
python3 -m secscan https://mysite.example --yes --json out.json

# Static code / secret scan of a repo (or a single file)
python3 -m secscan code /path/to/repo --json code-report.json

# Launch the web app
python3 -m secscan serve --host 127.0.0.1 --port 8000

# Authorize targets/modes with a scope file; disable active checks
python3 -m secscan scan scan.example.com --scope scope.yml --no-active

# List past scans (stored locally in SQLite)
python3 -m secscan history

# Attack surface: DNS + TLS + fingerprint run by default; add subdomain enum
python3 -m secscan scan https://example.com --subdomains

# Crawl + JS analysis (endpoints, DOM sinks, source-map recovery) + API discovery
python3 -m secscan scan https://example.com --crawl --api-discovery

# AI analysis (DeepSeek by default) — triage + attack-surface hypotheses
export DEEPSEEK_API_KEY=sk-...
python3 -m secscan scan https://example.com --ai

# AI secure-code review (pluggable provider; offline 'mock' needs no key)
python3 -m secscan code /path/to/repo --ai --ai-provider deepseek
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

### Governance (M0)

Scans run as a **phase-ordered plugin pipeline** (recon → detect → enrich), are
**persisted** to a local SQLite store (browse via `history` or the web History
tab), and every active probe is written to an append-only **audit log**
(`~/.local/share/secscan/audit.log`). A `scope.yml` (see `scope.yml.example`)
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
`~/.secscan-stop` halts immediately; `--exploit-max-requests`/`--exploit-rate-limit`
bound the activity; and **every** active request is written to the audit log.

```bash
python3 -m secscan scan https://lab.local/ --lab --scope scope.yml \
    --lab-attest "I am authorized to actively test lab.local" --dry-run   # preview first
```

Lab mode is **CLI-only by design** — active exploitation is not exposed in the web UI.

### Useful flags

| Flag | Meaning |
|------|---------|
| `--no-web` | skip HTTP header/CSP analysis |
| `--no-cve` | skip the NVD CVE lookup |
| `--ports` | run `nmap -sV` (off by default) |
| `--top-ports N` / `--port-range "80,443"` | port selection for nmap |
| `--nuclei` | run nuclei templates (if installed) |
| `--nvd-api-key KEY` | NVD API key (or `NVD_API_KEY` env) for higher rate limits |
| `--insecure` | skip TLS certificate verification |
| `--json FILE` / `--html FILE` | write reports |
| `-y, --yes` | skip the authorization prompt |

Exit code encodes the worst severity found (30 CRITICAL / 20 HIGH / 10 MEDIUM /
0 otherwise), handy in CI gates.

## How CVE matching works (and why it's not just one API call)

Freshly published CVEs sit in NVD as *"Awaiting Analysis"* for days/weeks with
**no CPE configuration**, and their descriptions rarely name the exact affected
version. A naive `cpeName=`/keyword query therefore **misses the recent,
high-impact CVEs you care about most**. So secscan:

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
- `nmap` (optional, for `--ports`)
- `nuclei` (optional, for `--nuclei`) — `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

## Layout

```
secscan/
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
