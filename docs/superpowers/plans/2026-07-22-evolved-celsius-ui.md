# Evolved Celsius UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the celsius web UI as "Evolved Celsius" — teal-brand dark-flagship visual system, dashboard home, charts in results, attack-surface graph, jobs queue UI.

**Architecture:** Static SPA, no build step. JS split into ordered plain scripts sharing a `window.CELSIUS` namespace. Hand-rolled SVG for all charts/graphs. One small backend addition (`GET /api/jobs`).

**Tech Stack:** FastAPI backend, vanilla JS/CSS, hand-rolled SVG, Playwright (dev-only verification), pytest.

**Spec:** `docs/superpowers/specs/2026-07-22-evolved-celsius-ui-design.md`

## Global Constraints

- **No build step, no frameworks, no web fonts, no third-party JS/CSS libraries.** Plain `<script>`/`<link>` tags only. Static assets stay under `celsius/web/static/` (shipped in the wheel via `source-include`).
- Core stays stdlib-only; backend changes are confined to `celsius/web/app.py` (the `web` extra).
- The authorization gate (`#authorized` checkbox → 403 without it) and lab-mode attestation flow must keep working exactly as today.
- Theme support: every new component works in dark AND light via CSS custom properties; dark is the flagship default (keep the existing theme toggle + localStorage persistence).
- `prefers-reduced-motion` disables animations.
- Every new fetch path degrades gracefully (empty states, hidden badges) — never a blank page or an unhandled rejection.
- Gate: `uv run --group dev pytest -q` green, `ruff check celsius/` clean, `pyright celsius/` 0/0.
- Do not bump the version.

---

### Task 1: Backend — GET /api/jobs

**Files:**
- Modify: `celsius/web/app.py` (job creation ~line 298-302; add endpoint after `cancel_scan` ~line 327)
- Test: `tests/test_webapp.py`

**Interfaces:**
- Produces: `GET /api/jobs` → `{"jobs": [{"job_id", "target", "status", "progress", "started_at", "error"}]}` newest-first; job dicts gain a `target` field.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_webapp.py` (follow the file's existing style — it uses FastAPI TestClient or direct calls; match it):

```python
def test_jobs_lists_submitted_job_with_target():
    resp = client.post("/api/scan", json={"target": "https://example.com", "authorized": True})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    resp = client.get("/api/jobs")
    assert resp.status_code == 200
    jobs = resp.json()["jobs"]
    mine = [j for j in jobs if j["job_id"] == job_id]
    assert mine and mine[0]["target"] == "https://example.com"
    assert mine[0]["status"] in ("running", "done", "error", "cancelled")
    assert "started_at" in mine[0]
```

(If the existing tests stub `run_scan` or the executor, do the same here — copy the file's established pattern.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --group dev pytest -q tests/test_webapp.py -k jobs_lists`
Expected: FAIL — 404 on `/api/jobs`.

- [ ] **Step 3: Implement**

In `celsius/web/app.py`, in `start_scan`, add `target` to the job dict:

```python
    with _jobs_lock:
        _jobs[job_id] = {"status": "running", "log": [], "result": None, "error": None,
                         "target": req.target.strip(),
                         "started_at": utcnow_iso(), "progress": None,
                         "cancel_requested": False}
```

After `cancel_scan`, add:

```python
@app.get("/api/jobs")
def list_jobs() -> dict:
    """Running + recent in-memory scan jobs, newest first (single-process state)."""
    with _jobs_lock:
        jobs = [{"job_id": jid, "target": j.get("target", ""), "status": j["status"],
                 "progress": j.get("progress"), "started_at": j.get("started_at"),
                 "error": j.get("error")}
                for jid, j in _jobs.items()]
    jobs.sort(key=lambda j: j.get("started_at") or "", reverse=True)
    return {"jobs": jobs}
```

Also update the module docstring endpoint list (add `GET /api/jobs` line).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --group dev pytest -q tests/test_webapp.py`
Expected: all pass, including the new test.

- [ ] **Step 5: Commit**

```bash
git add celsius/web/app.py tests/test_webapp.py
git commit -m "feat(web): GET /api/jobs — list running/recent scan jobs"
```

---

### Task 2: JS split + visual system foundation

**Files:**
- Create: `celsius/web/static/app.js` (rewritten: namespace, utils, tab router, theme, auth/token bar)
- Create: `celsius/web/static/scan.js` (scan form, presets, options, polling, results rendering — moved from old app.js)
- Rewrite: `celsius/web/static/style.css`
- Modify: `celsius/web/static/index.html`
- Rename (git mv): current `app.js` → keep as reference only during the task, then delete

**Interfaces:**
- Produces (everything later tasks rely on):
  - `window.CELSIUS` namespace: `CELSIUS.state` ({token, authorized, currentScan, jobs}), `CELSIUS.$` (getElementById shortcut), `CELSIUS.api(path, opts)` (fetch wrapper injecting `X-Celsius-Token` and throwing on !ok), `CELSIUS.esc(s)` (HTML escape), `CELSIUS.sevRank`, `CELSIUS.fmtElapsed(s)`, `CELSIUS.showTab(name)`, `CELSIUS.loadScan(scanIdOrDict)` (renders a scan dict into the Results tab), `CELSIUS.renderFindings(container, scanDict)`.
  - `index.html` gains `<script src="/static/app.js">`, `scan.js` (defer, in order) and the Dashboard tab skeleton (`<section id="tab-dashboard">`).
  - CSS: the full Evolved Celsius variable set + components (tiles, chips, hero, donut placeholders, drawer) used by Tasks 3-6.

**Behavior:** every existing flow must keep working identically — scan form + presets + advanced/auth/lab disclosures, mailsec tab, code tab, history tab, scan polling + cancel, results rendering, export buttons, AI key localStorage, testsites list. This is a refactor + restyle, not a feature change.

- [ ] **Step 1: Split the JS**

Move the current `app.js` logic into the two files above. Keep all existing element IDs working (Tasks 3-6 may change markup, this task may not break current behavior). Establish the `window.CELSIUS` namespace and route the existing code through it without changing behavior. `scan.js` registers its init on `DOMContentLoaded` via `CELSIUS.onInit(fn)`.

- [ ] **Step 2: Rewrite style.css to the Evolved Celsius system**

Keep the existing variable names (`--bg`, `--surface*`, `--border*`, `--text`, `--muted`, `--faint`, `--accent*`, `--crit/--high/--med/--low/--info/--ok`, `--font-*`, `--r*`, `--shadow*`, `--ring`) so existing markup still renders, but:

- Dark theme values become richer: bg `#080d16`, surface `#0e1626`/`#131e33`/`#1a2740`, borders `#22304d`, accent `#2dd4bf`/`#5eead4`.
- Add: `--accent-glow: rgba(45,212,191,.25)`, severity glow vars (`--crit-glow` etc.), `--grad-hero: radial-gradient(1200px 400px at 20% -10%, rgba(13,148,136,.22), transparent 60%)`.
- Typography scale classes: `.section-title` (22px/700), `.label` (12px uppercase .08em muted), `.metric` (28px/800 tabular-nums), `.mono`.
- Components (used by later tasks, style them now): `.tile` (metric tile), `.chip` + `.chip-crit/high/med/low/info`, `.hero` (gradient panel), `.card-glow-crit` (severity border glow), `.skeleton` (shimmer loader), `.progress` (bar + label row), `.drawer` (right-side jobs drawer) + `.badge` (appbar count), `.donut`, `.bars`, `.spark`, `.graph-wrap`.
- Light theme gets matching polish (same structure, existing light palette refined).
- Add `prefers-reduced-motion` media block zeroing transitions/animations.
- Bump the stylesheet version query in index.html (`style.css?v=3`) and add the new script tags (`app.js`, `scan.js`, both `defer`, in that order).

- [ ] **Step 3: Verify with the dev-only Playwright smoke script**

Create `scripts/ui_smoke.py` (dev-only, NOT in CI, requires the `dynamic` extra):

```python
"""Dev-only UI smoke check: load the app, exercise the main tabs, fail on any
console error. Usage: .venv/bin/python scripts/ui_smoke.py [base_url] [--shot prefix]"""
```

Behavior: start (or reuse) a server on 127.0.0.1:8000, load `/`, collect console errors/pageerrors, click through all tabs, check `#authorized` gating (Scan button disabled until checked), optionally save screenshots with the given prefix (light + dark). Exit 1 on any console error.

Run: `.venv/bin/python scripts/ui_smoke.py --shot shots/after-task2`
Expected: exit 0; screenshots show the restyled app; all existing flows work.

- [ ] **Step 4: Regression gate**

Run: `uv run --group dev pytest -q && uv run --group dev ruff check celsius/`
Expected: green (no Python changes expected beyond Task 1, but the web tests must stay green).

- [ ] **Step 5: Commit**

```bash
git add celsius/web/static/ scripts/ui_smoke.py
git commit -m "refactor(web): JS split + Evolved Celsius visual system foundation"
```

---

### Task 3: Dashboard home

**Files:**
- Create: `celsius/web/static/dashboard.js`
- Modify: `celsius/web/static/index.html` (Dashboard tab nav item + `<section id="tab-dashboard">`)
- Modify: `celsius/web/static/style.css` (dashboard-specific styles, only if Task 2 didn't cover them)
- Modify: `scripts/ui_smoke.py` (assert dashboard renders)

**Interfaces:**
- Consumes: `CELSIUS.api`, `CELSIUS.showTab`, `CELSIUS.loadScan`, `/api/scans`, `/api/scans/{id}`.
- Produces: `CELSIUS.dashboard.refresh()` (re-fetch + render); called on tab show and after any scan completes.

- [ ] **Step 1: Markup + nav**

Add a "Dashboard" tab button (first, `data-tab="dashboard"`, default active) and the section:

```html
<section id="tab-dashboard" class="panel active" role="tabpanel">
  <div id="dashHero"></div>
  <div id="dashTiles" class="tiles"></div>
  <h3 class="section-title">Recent scans</h3>
  <div id="dashRecent"></div>
</section>
```

The previous default tab (host scan) becomes non-active.

- [ ] **Step 2: dashboard.js**

Implement `CELSIUS.dashboard`:
- `refresh()`: `GET /api/scans?limit=8` → if empty, render empty state (icon + "No scans yet" + button that calls `CELSIUS.showTab('host')`); else hero for the newest scan (grade letter from `assessment`, target, relative time, severity counts, "Rescan" → prefill target + showTab('host'), "View results" → `CELSIUS.loadScan(id)`), tiles (crit/high/med/low/CVE/AI-verified counts summed from the newest scan), recent list rows (grade chip, target, date, severity mini-counts; click → loadScan).
- Hero uses `.hero`, tiles use `.tile`, grade chip colored by letter (A→ok, B→low, C→med, D/F→high/crit).
- All HTML built via `CELSIUS.esc` for target strings. Relative time helper ("2h ago").

- [ ] **Step 3: Wire refresh triggers**

Dashboard refreshes when its tab is shown and when a scan job completes (scan.js calls `CELSIUS.dashboard.refresh()` after a done job; guard with `if (CELSIUS.dashboard)`).

- [ ] **Step 4: Verify**

Extend `scripts/ui_smoke.py` to assert `#dashHero` is non-empty (or shows the empty state) with zero console errors.
Run: `.venv/bin/python scripts/ui_smoke.py --shot shots/after-task3`
Expected: exit 0; screenshot shows dashboard.

- [ ] **Step 5: Commit**

```bash
git add celsius/web/static/ scripts/ui_smoke.py
git commit -m "feat(web): dashboard home — hero, severity tiles, recent scans"
```

---

### Task 4: Charts in results

**Files:**
- Create: `celsius/web/static/charts.js`
- Modify: `celsius/web/static/index.html` (charts row in the Results panel)
- Modify: `scripts/ui_smoke.py`

**Interfaces:**
- Consumes: `CELSIUS.api`, current scan dict (via `CELSIUS.state.currentScan`).
- Produces: `CELSIUS.charts.render(scanDict)` — fills `#chartDonut`, `#chartCats`, `#chartTrend`; called from `CELSIUS.loadScan`.

- [ ] **Step 1: charts.js — three hand-rolled SVG charts**

- **Severity donut** (`#chartDonut`): findings grouped by severity; SVG `circle` segments via `stroke-dasharray` on a radius-40 ring, center shows total + "findings"; legend with counts; colors from CSS vars (`var(--crit)` etc. via `getComputedStyle` or hardcoded per theme class). Empty findings → "No findings" placeholder arc in `--ok`.
- **Category bars** (`#chartCats`): top 6 finding categories, horizontal bars, count labels, mono category names.
- **CVE trend sparkline** (`#chartTrend`): `GET /api/scans?target=<host>&limit=10` → CVE count per scan, oldest→newest polyline with area fill and end dot; fetch failure → hide the sparkline container.

All SVG generated as strings with escaped data; theme via `currentColor`/CSS vars; titles via `<title>` for a11y.

- [ ] **Step 2: Results markup**

In the Results panel, above the findings list:

```html
<div class="charts-row">
  <div class="chart-card" id="chartDonut"></div>
  <div class="chart-card" id="chartCats"></div>
  <div class="chart-card" id="chartTrend"></div>
</div>
```

- [ ] **Step 3: Verify**

Run: `.venv/bin/python scripts/ui_smoke.py --shot shots/after-task4`
The smoke script's mock scan path must show the charts row rendered (assert non-empty SVG children), zero console errors.

- [ ] **Step 4: Commit**

```bash
git add celsius/web/static/ scripts/ui_smoke.py
git commit -m "feat(web): results charts — severity donut, category bars, CVE sparkline"
```

---

### Task 5: Jobs queue UI

**Files:**
- Create: `celsius/web/static/jobs.js`
- Modify: `celsius/web/static/index.html` (appbar activity button + drawer)
- Modify: `celsius/web/static/style.css` (drawer polish if needed)
- Modify: `scripts/ui_smoke.py`

**Interfaces:**
- Consumes: `GET /api/jobs` (Task 1), `DELETE /api/scan/{job_id}`, `CELSIUS.loadScan`.
- Produces: `CELSIUS.jobs.start()` (begins polling), `CELSIUS.jobs.refresh()`; scan.js switches its per-job polling to update via the shared jobs state.

- [ ] **Step 1: Markup**

Appbar right side, before the theme toggle:

```html
<button id="jobsBtn" class="jobs-btn" title="Scan jobs" aria-label="Scan jobs">
  <span class="jobs-ico">◔</span><span id="jobsBadge" class="badge hidden">0</span>
</button>
<div id="jobsDrawer" class="drawer hidden" role="dialog" aria-label="Scan jobs">
  <div class="drawer-head"><h3 class="section-title">Scan jobs</h3>
    <button id="jobsClose" class="linklike">Close</button></div>
  <div id="jobsList"></div>
</div>
```

- [ ] **Step 2: jobs.js**

- Poll `GET /api/jobs` every 2s while any job is running OR the drawer is open; every 15s otherwise (and on failure: back off, hide badge, keep silent).
- Badge: count of `status === "running"`; hidden at 0.
- Drawer rows: target (mono, escaped), status chip, progress bar (`progress.index/total` + phase + elapsed via `CELSIUS.fmtElapsed`), cancel button for running jobs (calls DELETE, disables itself, shows "cancelling"), "View" for done jobs with a result → `CELSIUS.loadScan`.
- Toggle drawer on button click; close on outside click / Esc.
- `CELSIUS.jobs.start()` on init; the main scan flow's completion also triggers `CELSIUS.dashboard.refresh()`.

- [ ] **Step 3: Verify**

Extend the smoke script: open the jobs drawer, assert it renders (empty state "No jobs yet" is fine), zero console errors.
Run: `.venv/bin/python scripts/ui_smoke.py --shot shots/after-task5`

- [ ] **Step 4: Commit**

```bash
git add celsius/web/static/ scripts/ui_smoke.py
git commit -m "feat(web): jobs queue UI — appbar badge, drawer, cancel, view result"
```

---

### Task 6: Attack-surface graph

**Files:**
- Create: `celsius/web/static/surface.js`
- Modify: `celsius/web/static/index.html` (Attack surface sub-view in Results)
- Modify: `celsius/web/static/style.css` (graph styles)
- Modify: `scripts/ui_smoke.py`

**Interfaces:**
- Consumes: current scan dict (`CELSIUS.state.currentScan`).
- Produces: `CELSIUS.surface.render(scanDict)` into `#surfaceGraph`; a "Attack surface" button/sub-tab in the Results panel toggles between findings view and graph view.

- [ ] **Step 1: Graph model**

`buildGraph(scanDict)` → `{nodes: [{id, kind, label, sub, sev, data}], edges: [{from, to}]}`:
- `target` node (kind host) from `url`/`target`.
- `host` nodes from `recon.subdomains` (sub: resolved IP + CDN/origin flag when present in recon data).
- `service` nodes from `services[]` (`port/proto · name version`), attached to the target (or matching host when derivable).
- `endpoint` nodes from `recon.crawl`/`recon.api` paths (cap 40, then a single `+N more` aggregate node).
- `finding` pills: attach to the node whose label/host appears in the finding's evidence/description; fallback attach to target. `sev` drives pill color.
- Total node cap ~300 — collapse the largest layer into `+N more` nodes.

- [ ] **Step 2: Layered SVG renderer**

- Columns left→right: target / hosts / services / endpoints / findings; nodes as rounded rects (pills for findings), edges as cubic beziers.
- Deterministic layout: column x = index * columnWidth; nodes stacked vertically with fixed row height; svg height = max column size * row height.
- Pan (drag) + zoom (wheel) via a `viewBox` transform group; double-click resets.
- Click node → detail pane under the graph: kind, label, sub, `data` key-values, and attached findings (severity chip + title + description excerpt, escaped).
- Legend row + empty handling (no recon → target node + "Run a deeper scan (crawl/subdomains) to map the surface" note).

- [ ] **Step 3: Results integration**

Results panel gains a view toggle: "Findings | Attack surface" (segmented control). `CELSIUS.surface.render(scanDict)` runs when the toggle is activated (lazy, re-render on new scan load).

- [ ] **Step 4: Verify**

Extend the smoke script: after a scan, toggle Attack surface, assert `#surfaceGraph svg` exists with ≥1 node, zero console errors.
Run: `.venv/bin/python scripts/ui_smoke.py --shot shots/after-task6`

- [ ] **Step 5: Commit**

```bash
git add celsius/web/static/ scripts/ui_smoke.py
git commit -m "feat(web): attack-surface graph — layered SVG surface map with detail pane"
```

---

### Task 7: Docs, screenshots, final gate

**Files:**
- Modify: `README.md` (web UI section: dashboard, charts, graph, jobs; update screenshots if it embeds any)
- Modify: `AGENTS.md` (`web/` layout line: note the JS split + scripts/ui_smoke.py)
- Modify: `TODO.md` (mark attack-surface graph view as done)
- Create: `shots/final-*.png` (before/after set for the user)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Docs**

README web-UI section: describe Dashboard, charts, attack-surface graph, jobs drawer; AGENTS.md `web/` line lists the new JS files; TODO.md moves "Attack-surface graph view" to Done.

- [ ] **Step 2: Final screenshots**

Restart the server, run the full smoke script capturing: dashboard (light + dark), new-scan form, results with charts, attack-surface graph, jobs drawer — `shots/final-*.png`. Verify each image visually.

- [ ] **Step 3: Full validation gate**

```bash
uv run --group dev pytest -q
uv run --group dev ruff check celsius/
uv run --extra web --extra dynamic --group dev pyright celsius/
.venv/bin/python scripts/ui_smoke.py
```

Expected: all green; smoke exit 0.

- [ ] **Step 4: Commit**

```bash
git add README.md AGENTS.md TODO.md shots/
git commit -m "docs: Evolved Celsius UI — README/AGENTS/TODO + final screenshots"
```

---

## Self-Review Notes

- Spec coverage: /api/jobs (T1) ← spec §3 jobs; JS split + visual system (T2) ← §2/§4; dashboard (T3) ← §3; charts (T4) ← §3; jobs UI (T5) ← §3; graph (T6) ← §3; docs/screenshots/gate (T7) ← §4 + user request.
- Type consistency: `CELSIUS.*` namespace members defined in T2 are the exact names consumed in T3-T6; `/api/jobs` response shape in T1 matches T5's consumption.
- CSS/JS split thresholds follow the spec's conditional (~1500 lines).
