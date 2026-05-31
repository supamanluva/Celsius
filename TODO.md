# secscan — Backlog / future work

Status as of **v1.1.0** — the full M0–M6 roadmap in [plan.md](plan.md) is shipped.
This file tracks the *future* enhancements noted across milestones. None are
blocking; pick by value.

## High value
- [ ] **Web report-download buttons** — let the web UI download a scan as
      JSON / SARIF / Markdown / HTML (add `/api/scans/{id}/export?format=` and
      buttons in the result + History views). Reuses existing `report.py` writers.
- [ ] **Vector RAG knowledge base** — index findings across scans + advisories so
      future scans retrieve "seen this before / here's what was real". Needs an
      embedding/vector store choice (sqlite-vss vs local FAISS vs simple cosine).
- [ ] **AI-augmented exploit chains** — let the LLM propose additional correlation
      chains beyond the deterministic rules (labeled `ai-hypothesis`, never
      auto-trusted), feeding `correlate.py`.
- [ ] **OOB / SSRF collaborator** — a self-hosted out-of-band listener to confirm
      blind SSRF / blind injection by observing a callback (lab mode). Design the
      listener + privacy model first.

## Medium value
- [ ] **Authenticated-session testing** — supply cookies/headers/login so active
      verification and crawling cover post-auth surface.
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
      all active checks (currently only lab mode rate-limits).
- [ ] **Subdomain bruteforce wordlist expansion** — larger optional wordlist.
- [ ] **AI key config file** — `~/.config/secscan/config.toml` to store the AI key
      once (web UI field + env var already work; this avoids re-entry).
- [ ] **Packaging/distribution** — pipx / Docker image / single binary (PyInstaller).
- [ ] **Tests** — unit tests for matchers/parsers (cve version ranges, secrets,
      verdicts) + a vulnerable-app lab (DVWA/Juice Shop) for active-check e2e.

## Done (kept for reference)
- [x] CVE verification via nuclei templates (`--cve-verify`) — v1.1.0
- [x] Public PoC links from NVD exploit-tagged references — v1.1.0
- [x] AI API key field in the web UI (+ browser localStorage) — v1.1.0
- [x] False-positive hardening: secret label words + low-confidence chain weighting

> Reminder: every new active capability stays behind scope/authorization + audit,
> non-destructive by default. No weaponized/mass-exploitation features.
