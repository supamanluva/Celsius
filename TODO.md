# celsius — Backlog / future work

Status as of **v1.1.0** — the full M0–M6 roadmap in [plan.md](plan.md) is shipped.
This file tracks the *future* enhancements noted across milestones. None are
blocking; pick by value.

## High value
- [ ] **Vector RAG knowledge base** — index findings across scans + advisories so
      future scans retrieve "seen this before / here's what was real". Needs an
      embedding/vector store choice (sqlite-vss vs local FAISS vs simple cosine).
- [ ] **AI-augmented exploit chains** — let the LLM propose additional correlation
      chains beyond the deterministic rules (labeled `ai-hypothesis`, never
      auto-trusted), feeding `correlate.py`.
- [ ] **Multi-worker job persistence** — web scan jobs currently live in an
      in-memory dict behind one ThreadPoolExecutor (`web/app.py`), so they vanish
      on restart and cap horizontal scaling. Persist jobs to the SQLite store so
      multiple workers/processes can share the queue.

## Medium value
- [ ] **AI multi-file code reasoning** — review across files (call graph / imports)
      instead of file-by-file in `ai/analyze.py`.
- [ ] **AI dedup of findings** — collapse near-duplicate findings via the LLM.
- [ ] **API schema diffing** — track OpenAPI/GraphQL schema changes between scans.
- [ ] **Deeper prototype-pollution analysis** — beyond the current sink presence
      check in `recon/jsintel.py`.
- [ ] **ASN / netblock recon** — expand attack-surface mapping in `recon/`.
- [ ] **Attack-surface graph view** — visualize hosts → services → endpoints →
      findings (the data is already persisted).
- [ ] **PDF export** — render the HTML/Markdown report to PDF (needs a renderer).

## Lower value / polish
- [ ] **Global rate-limiting enforcement** — honor `scope.rate_limit_rps` across
      all active checks (currently only lab mode rate-limits); the portscan and
      service-probe thread pools in particular fire unthrottled.
- [ ] **Subdomain bruteforce wordlist expansion** — larger optional wordlist.
- [ ] **AI key config file** — `~/.config/celsius/config.toml` to store the AI key
      once (web UI field + env var already work; this avoids re-entry).
- [ ] **Packaging/distribution** — pipx / single binary (PyInstaller). Docker
      deploy already ships (`docker-compose.yml`).
- [ ] **Vulnerable-app e2e lab** — DVWA/Juice Shop harness for active-check
      end-to-end tests (unit tests already cover matchers/parsers).

## Done (kept for reference)
- [x] CVE verification via nuclei templates (`--cve-verify`) — v1.1.0
- [x] Public PoC links from NVD exploit-tagged references — v1.1.0
- [x] AI API key field in the web UI (+ browser localStorage) — v1.1.0
- [x] False-positive hardening: secret label words + low-confidence chain weighting
- [x] Web report-download buttons — export JSON / SARIF / Markdown / HTML from the
      result + History views (`/api/scans/{id}/export.{fmt}`, domain ZIP)
- [x] OOB / SSRF collaborator — self-hosted HTTP/DNS canary confirms blind
      SSRF/RCE/XSS/XXE in lab mode (`--ssrf`/`--rce`/`--blind-xss`/`--xxe`,
      `--oob-host`/`--oob-domain`)
- [x] Authenticated-session testing — `--cookie`/`--bearer`/`--header` +
      form login (`--login-*`) cover post-auth surface; `--idor` does cross-user
      BOLA testing with a second identity
- [x] Kimi (Moonshot) AI provider + lab-mode AI hunt planner (`--ai-hunt`)

> Reminder: every new active capability stays behind scope/authorization + audit,
> non-destructive by default. No weaponized/mass-exploitation features.
