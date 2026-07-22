# Evolved Celsius — web UI redesign — design

Date: 2026-07-22
Status: approved (design), pending implementation plan
Cycle: 2 of 2 (cycle 1 = Kimi provider + AI hunt planner, shipped)

## Goal

Rebuild the celsius web UI (`celsius/web/static/`, FastAPI backend in
`celsius/web/app.py`) as "Evolved Celsius": keep the teal brand identity and
the no-build static SPA constraint, but raise the design ceiling and add four
features — dashboard home, charts in results, attack-surface graph, and a
multi-scan jobs queue UI.

Direction C (Evolved Celsius) was picked from three visual mockups over
A (refined SaaS, indigo) and B (dark terminal sec-ops console).

Non-goals: PDF export, multi-worker job persistence, any scanning-engine
changes, any JS build tooling, any new third-party frontend library.

## Section 1 — information architecture

Tabs become:

- **Dashboard** (new default): latest-scan hero (grade, target, finished time,
  severity counts, Rescan / View results), metric tiles (Critical/High/Medium/
  Low, CVEs, AI-verified), recent-scans list (~8, grade chips, click loads the
  scan), active-jobs strip. Empty state → CTA to New scan. All from existing
  `/api/scans` data.
- **New scan**: current Website & host form, restyled (preset cards, grouped
  disclosures, same fields including lab mode + AI hunt from cycle 1).
- **Results**: restyled; gains a charts row and an Attack surface sub-view.
- **E-mail security**, **Code & secrets**: same features, new visual system.
- **History**: restyled table, keeps filters + export buttons.
- **Jobs**: persistent appbar activity indicator (running-count badge) +
  dropdown drawer of running/recent jobs (progress bar, phase, elapsed, cancel;
  click finished job → load result). Polls every 2s while active.

The authorization + token bar stays (safety feature), restyled.

## Section 2 — visual system

- Dark theme is the flagship; light theme stays fully supported.
- Foundation kept: CSS custom properties, `[data-theme="dark"]`, system font
  stack, teal accent (#0d9488 family dark / #0f766e light).
- Layered cards, subtle gradient borders, teal-glow hero panel, severity-color
  glow accents on critical cards.
- Type scale: 22px section titles / 15px body / 12px labels; `tabular-nums`
  metrics; monospace for targets, IPs, evidence.
- Components: severity donut + bars (hand-rolled SVG), metric tiles with
  count-up, pill severity chips, skeleton loaders, progress bar with phase +
  elapsed, refined focus rings.
- Motion: 150–250ms ease transitions; `prefers-reduced-motion` disables.
- Layout: max-width 1200px card grid; sticky appbar with jobs indicator;
  responsive to 360px.

## Section 3 — features

### Dashboard home
Hero + tiles + recent scans + active jobs strip + empty state. Data: `GET
/api/scans` (list) and `GET /api/scans/{id}` (detail on click). Grade computed
server-side already (`assessment` on stored scans).

### Charts in results
Row above findings: severity donut, top-categories horizontal bars, CVE-count
sparkline across prior scans of the same target (`/api/scans?target=`).
Hand-rolled SVG themed via `currentColor` + CSS vars.

### Attack-surface graph
New sub-view in Results (and for stored scans). Layered left→right: target →
subdomains/IPs → services → endpoints; findings as severity-colored pills
pinned to their node. Hand-rolled SVG with pan/zoom (viewBox transform), click
node → detail pane (node data + its findings + PoC links). Overflow collapses
into "+N more" beyond ~300 nodes. Data derived client-side from the scan JSON
already fetched — no backend change.

### Jobs queue UI
Backend: store `target` on each `_jobs` entry; new `GET /api/jobs` returning
[{job_id, target, status, progress, started_at, error}]. Frontend: appbar badge
+ drawer, 2s polling while running, cancel via existing `DELETE /api/scan/{id}`.

## Section 4 — technical approach + testing

**Files**

- `celsius/web/static/style.css` — extended; if it passes ~1500 lines, split
  feature CSS (`dashboard.css`, `graph.css`) loaded via extra `<link>` tags.
- JS split into plain scripts loaded in order, sharing a `window.CELSIUS`
  namespace: `app.js` (state/utils/tabs), `scan.js` (form + polling),
  `dashboard.js`, `charts.js`, `surface.js`, `jobs.js`. No modules/bundler.
- `celsius/web/app.py` — `GET /api/jobs` + `target` stored on job dicts only.

**Rendering:** hand-rolled SVG everywhere; theme-aware; reduced-motion honored.

**Error handling:** empty history → dashboard empty state; sparse recon →
graph shows target node + note; `/api/jobs` failure hides the badge. `/api/jobs`
sits behind the existing token middleware. No new auth surface.

**Testing**

- `tests/test_webapp.py`: `/api/jobs` lists a submitted job (target + status);
  token gate preserved.
- Dev-only Playwright smoke script (not CI): load app, run a mock scan, assert
  dashboard/charts/graph render with zero console errors; capture before/after
  screenshots.
- Gate: `pytest -q`, `ruff check celsius/`, `pyright celsius/` (0/0).

**Constraints carried from cycle 1 / AGENTS.md:** static SPA with no build
step; assets shipped in the wheel via `source-include`; authorization gate
unchanged; stdlib-only core untouched (backend change is in the `web` extra).
