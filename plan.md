# celsius — Development Plan

> From a lightweight scanner to a professional, AI-augmented offensive-security
> platform that finds, prioritizes, and *safely* proves web & code
> vulnerabilities — with an emphasis on doing things signature scanners don't.

**Target operating model:** local single-user power tool (CLI + local web app).
**Active testing posture:** non-destructive by default; **opt-in active
exploitation only in an explicit lab mode** behind hard guardrails.
**AI:** DeepSeek now, behind a pluggable multi-provider abstraction.
**Privacy:** secret redaction before sending to a model is **default ON** —
secrets are masked with typed placeholders (`<AWS_KEY>`) so the value never
leaves the host; `--ai-no-redact` opts out for maximum model visibility on a
target you own. The report always carries full secret values for the target's IT
to rotate; we log what was sent and recommend the provider's no-retention mode.

---

## 0. North star

A tester points celsius at an authorized target (or a repo) and gets back:
1. a complete **attack-surface map** (hosts, ports, tech, endpoints, client code),
2. a prioritized, **deduplicated** list of weaknesses (CVE, config, code, logic),
3. for each: a **non-destructive exploitability verdict** + a generated
   *"how to check if this is exploitable"* decision tree,
4. AI-driven hypotheses for issues **no signature would catch** (business-logic,
   chained exploits, novel misconfigs),
5. a clean **report** with reproduction, remediation, and detection rules.

Everything is explainable (every finding cites evidence and a source), and every
active action is logged and consented.

---

## 1. Principles & Safety / Legal Charter

These are hard constraints, not aspirations. They shape every feature.

1. **Authorized use only.** A scan requires an explicit, recorded authorization
   per target scope. No wildcard "scan the internet" mode.
2. **Non-destructive by default.** The default everywhere is observation and
   benign proof. Destructive or state-changing actions are never automatic.
3. **Lab mode is a deliberate gear.** Active exploitation requires: (a) lab-mode
   enabled, (b) target on an explicit allowlist, (c) a per-run attestation, (d) a
   dry-run payload preview, (e) a kill-switch + rate caps, (f) a full audit log.
4. **No mass-targeting, no evasion-for-malice, no post-exploitation toolkit.**
   We build verification and proof, not weaponized intrusion or stealth.
5. **Explainability.** Every finding carries evidence, a confidence, and a
   citation (advisory, request/response, code location).
6. **Privacy by default, exposure is logged.** Redaction before sending to an
   external model is a per-scan **toggle, default ON** — secrets are masked with
   typed placeholders so the model can still reason about "a secret is here"
   without the value leaving the host; `--ai-no-redact` opts out when full
   context matters on a target you own. The *report* always contains full,
   unmasked values for remediation regardless. We always log what was
   transmitted (`masked` + `sensitive_count`), recommend the provider's
   no-retention/no-training mode, and offer a fully-local model so nothing
   leaves the machine when desired. Trade-off the operator must own: sending a
   *live* credential to a third-party API unmasked widens the leak until
   rotation.
7. **Fail safe.** Unknown/uncertain → lower severity + "verify manually", never a
   silent destructive default.

A machine-readable scope file gates everything:

```yaml
# scope.yml
authorized_by: "stjarngatan19@gmail.com"
authorized_at: 2026-05-31
targets:
  - host: example.com        # owned / written permission
    modes: [passive, safe-active]
  - host: lab.local             # full lab
    modes: [passive, safe-active, exploit]
exclusions: ["*.gov", "*.bank.se"]
rate_limit_rps: 10
```

---

## 2. Where we are today (v1.0.0 — M0–M6 ALL shipped 🎉)

15-stage plugin pipeline: web-analysis → fingerprint → dns → subdomains → tls →
port-scan → crawl → api-discovery → active-verify (lab) → web-secrets → nuclei →
cve-lookup → ai-analysis → exploitability → **correlation**.

**M6 (Correlation & reporting)** ✅ — exploit-chain correlation (composes findings
into scored attack paths), completeness critic, blue-team detection rules, and
SARIF 2.1.0 + Markdown export.

**M5 (Lab-mode active verification)** ✅ — non-destructive verifiers (reflected-XSS,
open-redirect, traversal, error-SQLi) behind a layered safety harness: lab flag +
scope EXPLOIT + per-run attestation + dry-run + kill-switch + caps + full audit.
Available from both the CLI and the web UI lab panel. Confirmed issues are marked
`confirmed-exploitable`.

**M4 (Exploitability)** ✅ — EPSS + CISA KEV enrichment, reachability, a
multi-signal verdict + priority, and a "how to check if exploitable" decision
tree per vuln class (`exploitability.py`). Real-world prioritization beats raw
CVSS (e.g. a CVSS-9.2 CVE with low EPSS and no KEV is honestly rated
"conditions-needed", not "panic").

**M3 (Crawler & client-side)** ✅ — static crawler, JS endpoint/route + DOM-sink
extraction, **source-map archaeology** (recovers hidden original source + scans it
for secrets), OpenAPI/Swagger + GraphQL introspection discovery, optional
Playwright dynamic crawl. CLI `--crawl/--api-discovery/--dynamic`; web panel.

**M1 (Attack surface)** ✅ — DNS recon (DoH), subdomain enum (crt.sh), TLS/cert
analysis, signature tech/WAF/CDN fingerprinting (versioned techs feed the CVE
engine), and temporal diff vs the last scan.

### Earlier milestones

**M0 (Foundation)** ✅ — plugin pipeline (`plugins/`, phase-ordered, mode-gated),
SQLite store (`store.py`, scan history), `scope.yml` authorization gate
(`scope.py`, mode/exclusion gating, stdlib YAML reader), append-only audit log
(`audit.py`), and scoped nuclei templates (fast default). CLI gained `history` +
`--scope`/`--no-active`/`--no-db`/`--nuclei-full`; web app gained a History tab.

**M2 (AI layer)** ✅ — pluggable LLM providers (DeepSeek default; OpenAI,
Anthropic, local/Ollama, mock) in `ai/`, secret redaction (default ON,
`--ai-no-redact` opts out) with
accurate audit, disk cache + token budget, AI triage/attack-surface hypotheses in
the scan pipeline, and `code --ai` secure-code review. All AI output is labeled
`ai-hypothesis` with confidence. CLI `--ai*`; web AI toggle + provider picker.

Already implemented and tested:

| Area | Module | Status |
|------|--------|--------|
| Orchestration | `engine.py` (`ScanConfig`/`run_scan`) | ✅ shared by CLI + web |
| HTTP headers / CSP / cookies | `http_analysis.py` | ✅ |
| Service/version detect | `http_analysis.py`, `portscan.py` (nmap) | ✅ |
| CVE matching (NVD + MITRE CNA, version ranges) | `cve.py`, `version.py` | ✅ catches un-enriched fresh CVEs |
| nuclei integration (+ auto template install) | `nuclei_scan.py` | ✅ |
| Secret signatures + entropy | `secrets.py` | ✅ |
| Static code scan (SAST-lite + ext tools) | `codescan.py` | ✅ gitleaks/semgrep/trufflehog |
| Front-end secret scan | `websecrets.py` | ✅ HTML + linked JS |
| Text-only PoC / repro | `poc.py` | ✅ non-destructive |
| Reporting | `report.py` (terminal/JSON/HTML) | ✅ |
| Web app | `web/` (FastAPI + SPA, scan jobs, PoC modal) | ✅ |

**Gaps to close:** no persistence/DB, no crawler, no real attack-surface
discovery, no DAST/active probing, no AI layer, no exploitability engine, no
plugin system, single-shot (no diff/history), thin TLS analysis.

---

## 3. Target architecture

Evolve the current package into a **plugin-based pipeline** with a persistent
store and a provider-agnostic AI layer.

```
                 ┌──────────────────────────────────────────────┐
                 │                CLI  /  Web UI                  │
                 └───────────────┬───────────────┬───────────────┘
                                 │ REST/WS       │
                 ┌───────────────▼───────────────▼───────────────┐
                 │                 Orchestrator                   │
                 │  scope gate · job queue · scheduling · audit   │
                 └───┬───────┬────────┬────────┬────────┬─────────┘
                     │       │        │        │        │
        ┌────────────▼┐ ┌────▼─────┐ ┌▼───────┐ ┌▼──────┐ ┌▼──────────┐
        │  Recon &    │ │  Detect  │ │ Code   │ │  AI   │ │ Exploit-  │
        │ Attack-Surf │ │ (passive │ │ Intel  │ │ layer │ │ ability   │
        │  plugins    │ │ +active) │ │        │ │       │ │ engine    │
        └─────┬───────┘ └────┬─────┘ └───┬────┘ └───┬───┘ └────┬──────┘
              └──────────────┴───────────┴──────────┴──────────┘
                                 │ normalized Findings
                 ┌───────────────▼───────────────────────────────┐
                 │  Store (SQLite): targets, scans, findings,     │
                 │  evidence, history, knowledge base (RAG)       │
                 └───────────────┬───────────────────────────────┘
                 ┌───────────────▼───────────────┐
                 │  Correlation · Dedup · Triage  │  (graph + AI)
                 └───────────────┬───────────────┘
                 ┌───────────────▼───────────────┐
                 │  Reporting · Detection rules   │
                 └───────────────────────────────┘
```

Key building blocks to add:
- **Plugin interface** — every check is a plugin with metadata
  (`id, category, severity, modes, run(ctx)->Findings`). Enables community/custom
  checks and clean opt-in/opt-out per mode.
- **Persistent store** — SQLite (local-first), schema for targets → scans →
  findings → evidence, plus a vector table for the knowledge base.
- **Job queue** — async workers (start with `asyncio` + a thread pool; the design
  allows swapping in a real queue later).
- **Evidence vault** — raw request/response, screenshots, recovered source, saved
  per finding for reproducibility.
- **Audit log** — append-only record of every active request sent.

---

## 4. AI / LLM layer (DeepSeek-first, pluggable)

```
celsius/ai/
  provider.py      # abstract LLMProvider: complete(), embed(), stream()
  deepseek.py      # default impl (DeepSeek API)
  openai.py        # optional
  anthropic.py     # optional
  local.py         # Ollama / llama.cpp — never leaves the machine
  redact.py        # secret/PII masking, default ON (reuses secrets.py)
  prompts/         # versioned, testable prompt templates
  budget.py        # token/cost guard, caching of identical prompts
```

**Redaction (default ON):** by default `secrets.py` matches are masked with typed
placeholders (`<AWS_KEY_1>`) before anything is sent — the model can still reason
about "a secret is here" without the value leaving the host. A per-scan opt-out
(`--ai-no-redact` / `ai_redact: false`) sends full context for maximum detection
on a target you own; findings exist to be reported to the asset owner for
rotation either way. Regardless of the toggle: (a) the **report always
contains the full unmasked values** needed for remediation, (b) we log a manifest
of exactly what was transmitted, (c) we surface the provider's no-retention /
no-training option, and (d) a local model (`local.py`) keeps data on-box entirely.
The operator owns the trade-off: full context = best detection, but a *live*
secret sent to an external API is exposed to that provider until rotated.

**Where AI adds leverage (each grounded in real evidence, never free-floating):**
1. **Triage & dedup** — collapse N raw findings into ranked, deduplicated issues
   with rationale; cut scanner noise.
2. **Attack-surface reasoning** — given the recon graph + endpoints + tech, the
   model hypothesizes *attack paths* and *business-logic flaws* that signatures
   miss, each emitted as a testable hypothesis with a suggested safe probe.
3. **Code vulnerability hunting** — feed (redacted) recovered/served code; the
   model finds injection, authz, deserialization, SSRF, secrets-in-logic; output
   must cite file:line and a concrete data-flow.
4. **Exploitability assessment** — turn a finding into a precondition checklist +
   a "how to check if exploitable" decision tree (see §5.6).
5. **Remediation & detection** — generate fix diffs, hardened configs, and
   detection rules (Sigma/YARA/CSP).
6. **Report writing** — exec summary + technical narrative from structured data.

**Discipline:** the LLM never *decides* a vuln is real on its own — it proposes;
a deterministic probe or human confirms. Hypotheses are clearly labeled
`ai-hypothesis` with a confidence and required verification step. This keeps
hallucinated "CVEs"/bugs out of the verified set (same principle that already
made `cve.py` reject the Google-sourced false positive).

---

## 5. Capability roadmap (by domain)

### 5.1 Recon & attack-surface discovery
- Subdomain enumeration (passive: crt.sh/CT logs, DNS; active: bruteforce opt-in).
- DNS records, ASN/netblock, reverse DNS, virtual-host discovery.
- Port/service sweep (nmap already wired) + service banners.
- Cloud-asset hints (S3/bucket patterns, storage URLs in code).
- **Attack-surface graph** persisted and diffable over time.

### 5.2 Fingerprinting
- Rich tech detection (Wappalyzer-style signatures: frameworks, CMS, WAF, CDN,
  analytics, JS libs with versions) → feeds CVE engine.
- WAF/CDN detection (so we interpret "no version" correctly, as we saw).
- TLS/certificate analysis: protocols, ciphers, cert chain, expiry, HSTS preload,
  known TLS CVEs (Heartbleed-class), misissued/weak certs.

### 5.3 Crawling & client-side / JS deep analysis  ← high-value, under-served
- Headless-browser crawl (Playwright): render SPAs, capture XHR/fetch, discover
  hidden routes and **undocumented API endpoints**.
- **Source-map recovery**: when `.map` files are exposed, reconstruct original
  source → run full SAST on code the site "thought" was minified/hidden.
- JS endpoint & secret extraction from bundles (extends `websecrets.py`).
- GraphQL introspection; OpenAPI/Swagger discovery; API schema diffing.
- DOM-sink analysis for client-side XSS / prototype pollution.

### 5.4 Vulnerability detection (passive + safe-active)
- Everything today, plus:
- Security headers v2 (CORS misconfig, COOP/COEP, permissions-policy).
- Sensitive-file exposure (`.git/`, `.env`, backups, `.DS_Store`, source leaks).
- Safe-active probes: reflected-marker XSS, open-redirect, SSRF canary
  (collaborator-style OOB), path traversal canaries, default creds (opt-in),
  auth/session checks. All benign markers, no payloads that alter state.
- OWASP Top 10 coverage matrix tracked explicitly.
- nuclei orchestration: scoped template groups (cve/exposure/misconfig/tech) for
  speed, plus full mode.

### 5.5 Code intelligence
- Multi-tool SAST (semgrep rulesets per language) + our patterns + AI pass.
- **Reachability**: link a SAST finding to an actually-exposed endpoint/route to
  cut false positives ("vulnerable code that no request can reach" → downgraded).
- Secret **validation** (opt-in, safe): provider-specific read-only check to tell
  *live* keys from dead ones — rotate-anyway, but prioritize live.
- Dependency/SBOM scanning (lockfiles → known-vuln deps via OSV).
- Git-history secret scanning (not just working tree).

### 5.6 Exploitability engine + "how to check if exploitable"
For each finding we produce an **exploitability record**:
```
preconditions:   [ "feature X reachable", "auth not required", "ASLR off", ... ]
probes:          [ non-destructive checks that confirm each precondition ]
signals:         { epss: 0.82, cisa_kev: true, public_poc: url, reachable: true }
verdict:         likely-exploitable | conditions-needed | not-in-context | unknown
howto:           generated decision tree (text) the tester can follow
lab_action:      (opt-in) controlled, bounded active attempt + expected effect
```
- **Real-world prioritization signals:** EPSS score, CISA **KEV** membership,
  public-PoC/Exploit-DB presence, and *local reachability* — far better than raw
  CVSS for "what to fix first".
- **How-to generator:** per vuln-class templates + AI, producing a yes/no
  decision tree ("Is the rewrite module in use? → curl test → if 500, likely
  affected") with only benign steps.
- **Lab-mode active verification:** behind the §1 guardrails — dry-run preview of
  the exact request, bounded attempt, capture the proof, auto-stop. Non-
  destructive even here unless a destructive action is individually confirmed.

---

## 6. Differentiators — "out of the box"

Things most scanners *don't* do, that we will:

1. **Exploit-chain graph.** Model findings as nodes; let the correlation engine
   (rules + AI) compose **chains** (exposed `.git` → source → leaked DB creds →
   auth bypass) and score the *chain's* impact, not just individual issues.
2. **Reachability-aware SAST.** Fuse static findings with runtime endpoint
   discovery so we report *exploitable* code paths, not theoretical ones.
3. **Source-map archaeology.** Recover and audit original front-end source the
   target believed was hidden — a rich, rarely-mined seam for logic bugs/secrets.
4. **AI business-logic hypotheses.** Reason about the *intended* workflow and test
   for IDOR, price/quantity tampering, broken object-level authz — classes that
   are invisible to signatures.
5. **Temporal/diff security.** Persist every scan; alert on **new** endpoints,
   newly-exposed secrets, regressed headers — continuous drift detection for your
   own assets.
6. **Self-improving knowledge base (RAG).** Index past findings + advisories;
   future scans retrieve "we've seen this pattern; here's what was real."
7. **Blue-team output.** Auto-generate detection rules and remediation diffs from
   each finding — close the loop, not just point fingers.
8. **OOB/canary verification.** Safe SSRF/blind-injection confirmation via a
   collaborator-style out-of-band listener (we control), proving impact without
   touching target data.

---

## 7. Reporting & knowledge base
- Audiences: exec summary (risk, top chains) + technical (evidence, repro, fix).
- Formats: HTML (rich, current), JSON (machine), Markdown, PDF, SARIF (CI/IDE).
- Per finding: severity, confidence, EPSS/KEV, evidence, exploitability verdict,
  how-to, remediation, detection rule.
- **Owner hand-off report:** a dedicated "secrets to rotate" section with the full
  values + exact `file:line`/URL, an "immediate actions" checklist, and a sharable
  artifact the target's IT/security team can act on directly. (This is *why*
  full-context detection matters — the deliverable is actionable remediation.)
- Trend view across scans; export to ticketing later.

---

## 8. Phased milestones

Each milestone is independently shippable and testable.

**M0 — Foundation (refactor & persist)** ✅ DONE (v0.3.0)
- ✅ Plugin interface; existing checks migrated to plugins.
- ✅ SQLite store (scans/findings); scan history in CLI + UI.
- ✅ `scope.yml` gate + audit log. (Global rate-limiting enforcement: TODO M1.)
- ✅ Scoped nuclei template groups (fast default).

**M1 — Attack surface & fingerprinting** ✅ DONE (v0.5.0)
- ✅ DNS recon via DoH (`recon/dns.py`); subdomain enum via crt.sh + optional
  wordlist (`recon/subdomains.py`); TLS/cert analysis (`recon/tls.py`: expiry,
  issuer/SAN, self-signed/hostname/expired, protocol+cipher, legacy-TLS probe).
- ✅ Signature tech/CDN/WAF/CMS/lib fingerprinting (`recon/fingerprint.py`) —
  versioned detections feed the CVE engine; WAF/CDN explains a hidden Server version.
- ✅ Temporal diff vs the last stored scan (new subdomains/services/CVEs).
- TODO (later): ASN/netblock, full attack-surface graph view, active subdomain
  bruteforce wordlist expansion.

**M2 — AI layer (DeepSeek, pluggable) + redaction** ✅ DONE (v0.4.0)
- ✅ Provider abstraction (`ai/provider.py`): DeepSeek (default), OpenAI, Anthropic,
  local/Ollama, mock — all stdlib HTTP.
- ✅ Redaction (`ai/redact.py`, default ON; `--ai-no-redact` opts out) + accurate
  audit (masked flag,
  sensitive_count) on every external send.
- ✅ Disk cache + token budget (`ai/cache.py`). Robust JSON parsing.
- ✅ AI triage + attack-surface hypotheses (scan ENRICH plugin) and secure-code
  review (`code --ai`), all labeled `ai-hypothesis` with a confidence, never
  auto-promoted to verified.
- ✅ CLI `--ai/--ai-provider/--ai-model/--ai-no-redact`; web AI toggle + provider picker.
- TODO (later): RAG knowledge base, multi-file code reasoning, dedup via AI.

**M3 — Crawler & client-side intelligence** ✅ DONE (v0.6.0)
- ✅ Static same-host crawler (`recon/crawler.py`); JS endpoint/route + DOM-sink
  extraction (`recon/jsintel.py`); **source-map archaeology** (`recon/sourcemaps.py`)
  recovers hidden original source and scans it for secrets; OpenAPI/Swagger +
  GraphQL introspection discovery (`recon/apidisco.py`); optional Playwright
  dynamic crawl (`recon/dynamic.py`, used if installed).
- ✅ CLI `--crawl/--api-discovery/--dynamic`; web toggles + crawl/API recon panel.
- TODO (later): API schema diffing, deeper prototype-pollution analysis.

**M4 — Exploitability engine** ✅ DONE (v0.7.0)
- ✅ EPSS (FIRST.org) + CISA KEV (cached) enrichment, reachability, multi-signal
  verdict (likely-exploitable / conditions-needed / not-in-context / unknown) +
  0-100 priority, and a per-vuln-class "how to check if exploitable" decision tree
  (`exploitability.py`). Wired as the final ENRICH plugin.
- ✅ Verdict/signals in terminal report, web cards, and the PoC modal how-to.
- TODO (later): NVD exploit-ref tags for public-PoC signal, AI-augmented how-to.

**M5 — Lab-mode active verification** ✅ DONE (v0.8.0)
- ✅ Non-destructive active verifiers (`active/verifiers.py`): reflected-XSS marker,
  open-redirect canary, path-traversal canary, error-based SQLi — each CONFIRMS or
  refutes with a benign payload.
- ✅ Safety harness (`active/harness.py`, `LabContext`): the single chokepoint for
  every active request, enforcing lab-mode flag + scope.yml EXPLOIT entry + per-run
  attestation + dry-run preview + kill-switch (`~/.celsius-stop`) + request cap +
  rate limit + audit of every request. Verified by tests for each guardrail.
- ✅ CLI (`--lab/--lab-attest/--dry-run/--exploit-max-requests`) + web UI lab
  panel, with interactive attestation. Confirmed findings get verdict `confirmed-exploitable`.
- ✅ (post-M5) OOB canary probes (blind SSRF/RCE/XSS/XXE via `--oob-host` /
  `--oob-domain`) and authenticated-session testing (`--cookie`/`--login-*`,
  `--idor` cross-user).

**M6 — Correlation, differentiators & reporting** ✅ DONE (v1.0.0)
- ✅ Exploit-chain correlation (`correlate.py`): composes findings/CVEs into scored
  attack paths (source-map→secret, secret→API, confirmed-exploitable, CSP+sink,
  KEV→reachable). Rendered as the report headline.
- ✅ Completeness critic (`completeness.py`): reports checks run/skipped + next
  steps, so a clean result isn't mistaken for a complete one.
- ✅ Blue-team detection-rule / remediation generation.
- ✅ SARIF 2.1.0 + Markdown export (`--sarif`/`--markdown`), alongside JSON/HTML.
- TODO (future): vector RAG knowledge base, AI-augmented chains, PDF export.

🎉 **Roadmap M0–M6 complete.** celsius is a full AI-augmented offensive-security
platform: 15-stage plugin pipeline, attack-surface mapping, client-side intel,
CVE + exploitability, lab-mode verification, exploit-chain correlation, and
multi-format reporting — all behind scope/authorization + audit.

---

## 9. Tech stack
- **Language:** Python 3.12 (core), keep stdlib-only for the scanning core where
  feasible; isolate heavy deps behind optional extras.
- **Web:** FastAPI + the existing SPA (consider HTMX or a small framework as the
  UI grows; avoid heavy SPA tooling unless needed).
- **Store:** SQLite (+ a vector extension or a small local embedding index).
- **Crawl:** Playwright (Chromium).
- **External tools (optional, auto-detected):** nmap, nuclei, gitleaks, semgrep,
  trufflehog, testssl/sslyze.
- **AI:** DeepSeek API default; OpenAI/Anthropic/Ollama via the provider layer.
- **Enrichment data:** NVD, MITRE CVE, OSV, EPSS, CISA KEV, Exploit-DB.

---

## 10. Quality, testing & safety engineering
- Unit tests for matchers/parsers (the `cve.py` version-range logic is a model:
  test fixtures of real CNA/NVD records, incl. the nginx 1.29.6 case).
- Golden-file tests for report rendering and prompt outputs.
- A **mock-target lab** (vulnerable apps: DVWA/Juice Shop/WebGoat in Docker) for
  end-to-end and exploit-engine tests — never test active modules on real targets.
- Redaction tests: assert no secret ever reaches a provider mock.
- Audit-log tests: every active request is recorded.
- CI: lint, type-check (mypy), tests; SARIF self-scan (dogfood).

---

## 11. Risks & mitigations
| Risk | Mitigation |
|------|-----------|
| Legal/abuse | Scope gate, lab-mode gating, no mass-targeting, audit log, exclusions |
| AI hallucinated vulns | `ai-hypothesis` labeling + deterministic/human verification before "verified" |
| Data leakage to LLM | Redaction default ON (opt-out for full context); send-manifest logging, provider no-retention mode, local-model option; report carries full values for the owner to rotate |
| False positives | Reachability fusion, multi-signal confirmation, confidence scores |
| Destructive accidents | Non-destructive default, dry-run preview, per-action confirm, kill-switch |
| Scope creep | Milestones are independently shippable; M0–M2 first |

---

## 12. Open questions (decide as we go)
- Embedding/vector store choice for RAG (sqlite-vss vs local FAISS vs simple).
- How much of the UI to rebuild as the feature set grows (HTMX vs SPA).
- OOB collaborator: self-hosted listener design + privacy.
- Packaging/distribution (pipx, Docker, single binary via PyInstaller).

---

> This plan is a living document. We build in vertical slices, keep every active
> capability behind consent + guardrails, and prefer *proving* a vulnerability
> safely over merely asserting it.
