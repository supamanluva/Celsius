"use strict";

/* ============================================================================
   Celsius web UI — dashboard module: landing view with the latest scan's hero
   (grade, severity counts, rescan/view actions), metric tiles and a list of
   recent scans. Loaded after scan.js; shares window.CELSIUS (see app.js).
   Untrusted scan data is always rendered through esc() — never raw HTML.
   ========================================================================== */

(function () {
  const C = window.CELSIUS;
  const $ = C.$;
  const esc = C.esc;

  const LIST_LIMIT = 8;

  // Grade letter → soft-fill chip class (brief: A→ok, B→low, C→med, D/F→high/crit).
  const GRADE_CHIP = { A: "chip-ok", B: "chip-low", C: "chip-med", D: "chip-high", F: "chip-crit" };

  // ---- helpers ---------------------------------------------------------------

  // "2h ago" style relative time from an ISO timestamp; "" when unparseable.
  function relTime(iso) {
    const t = Date.parse(iso || "");
    if (isNaN(t)) return "";
    const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
    if (s < 60) return "just now";
    const m = Math.floor(s / 60);
    if (m < 60) return m + "m ago";
    const h = Math.floor(m / 60);
    if (h < 24) return h + "h ago";
    const d = Math.floor(h / 24);
    if (d < 30) return d + "d ago";
    return new Date(t).toISOString().slice(0, 10);
  }

  function whenOf(scan) {
    return relTime(scan.finished_at || scan.started_at) || "unknown date";
  }

  // Headline severity counts, same rules as the results view: low-confidence
  // CVEs and AI-hypothesis findings stay out of the totals.
  function sevCounts(res) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    (res.cves || []).forEach((c) => {
      if (c.confidence !== "weak" && counts[c.severity] != null) counts[c.severity]++;
    });
    (res.findings || []).forEach((f) => {
      if (f.category !== "ai-hypothesis" && counts[f.severity] != null) counts[f.severity]++;
    });
    return counts;
  }

  // CVEs / findings confirmed by active verification (nuclei / lab mode).
  function verifiedCount(res) {
    let n = 0;
    (res.cves || []).forEach((c) => { if (c.verified) n++; });
    (res.findings || []).forEach((f) => { if (f.verified) n++; });
    return n;
  }

  function gradeChip(grade) {
    const g = String(grade || "").trim();
    if (!g) return `<span class="chip chip-info">–</span>`;
    const cls = GRADE_CHIP[g[0].toUpperCase()] || "chip-info";
    return `<span class="chip ${cls}">${esc(g)}</span>`;
  }

  // ---- rendering -------------------------------------------------------------

  function renderEmpty(isError) {
    $("dashHero").innerHTML = `
      <div class="dash-empty">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 3l7 3v5c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V6l7-3z"
                stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
          <path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.5"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <h3 class="dash-empty-title">No scans yet</h3>
        <p class="note">${isError
          ? "Scan history could not be loaded right now — you can still start a new scan."
          : "Run your first scan to see the security posture of your targets here."}</p>
        <button type="button" id="dashEmptyCta" class="btn-primary">New scan</button>
      </div>`;
    $("dashTiles").innerHTML = "";
    $("dashRecent").innerHTML = "";
    $("dashEmptyCta").addEventListener("click", () => {
      C.showTab("host");
      const t = $("target");
      if (t) t.focus();
    });
  }

  function renderHero(row, res) {
    const a = res && res.assessment;
    const gradeLetter = (a && a.grade) || row.grade || "?";
    const g0 = String(gradeLetter)[0] || "C";
    const counts = res ? sevCounts(res) : null;
    const chips = counts
      ? ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
          .filter((s) => counts[s] > 0)
          .map((s) => `<span class="chip sev-${s}">${s} ${counts[s]}</span>`).join("")
        || `<span class="chip sev-INFO">no findings</span>`
      : `<span class="chip sev-INFO">${row.n_findings || 0} findings · ${row.n_cves || 0} CVEs</span>`;
    $("dashHero").innerHTML = `
      <div class="hero grade-${esc(g0)}">
        <div class="hero-grade">${esc(gradeLetter)}</div>
        <div class="hero-body">
          <div class="hero-score"><strong>${a ? esc(a.score) : (row.score != null ? esc(row.score) : "–")}</strong>/100</div>
          <div class="hero-verdict">Latest scan · ${esc(row.target)} · ${esc(whenOf(row))}</div>
          <div class="hero-target">${esc(row.url || "-")} · ${esc(row.ip || "-")}</div>
          <div class="hero-counts">${chips}</div>
          <div class="hero-actions">
            <button type="button" id="dashRescan" class="btn-secondary">Rescan</button>
            <button type="button" id="dashView" class="btn-primary">View results</button>
          </div>
        </div>
      </div>`;
    $("dashRescan").addEventListener("click", () => {
      const t = $("target");
      if (t) t.value = row.target || "";
      C.showTab("host");
      if (t) t.focus();
    });
    $("dashView").addEventListener("click", () => C.loadScan(row.id));
  }

  function renderTiles(row, res) {
    const counts = res ? sevCounts(res) : null;
    const nCves = res ? (res.cves || []).length : (row.n_cves || 0);
    // Detail fetch failed: render "–" rather than a misleading 0 for tiles only
    // the full scan can answer — the scan may actually have criticals.
    const sev = (s) => (counts ? counts[s] : "–");
    const nVerified = res ? verifiedCount(res) : "–";
    const tile = (cls, label, n, sub) => `
      <div class="tile ${cls}">
        <span class="label">${label}</span>
        <span class="metric">${n}</span>
        <span class="tile-sub">${sub}</span>
      </div>`;
    $("dashTiles").innerHTML =
      tile("crit", "Critical", sev("CRITICAL"), "fix immediately") +
      tile("high", "High", sev("HIGH"), "fix this week") +
      tile("med", "Medium", sev("MEDIUM"), "plan a fix") +
      tile("low", "Low", sev("LOW"), "when convenient") +
      tile(nCves ? "high" : "ok", "CVEs", nCves, "known vulnerabilities") +
      tile(res && nVerified ? "ok" : "", "AI-verified", nVerified, "confirmed by verification");
  }

  function renderRecent(scans) {
    $("dashRecent").innerHTML = `<div class="dash-recent">` + scans.map((s) => {
      const sev = s.worst && s.worst !== "NONE" ? s.worst : "INFO";
      return `
        <button type="button" class="dash-row" data-scan="${esc(s.id)}">
          ${gradeChip(s.grade)}
          <span class="dash-target">${esc(s.target)}</span>
          <span class="badge sev-${esc(sev)}">${esc(s.worst || "-")}</span>
          <span class="dash-counts">${s.n_findings || 0} findings · ${s.n_cves || 0} CVEs</span>
          <span class="dash-when">${esc(whenOf(s))}</span>
        </button>`;
    }).join("") + `</div>`;
    $("dashRecent").querySelectorAll(".dash-row").forEach((b) =>
      b.addEventListener("click", () => C.loadScan(b.dataset.scan)));
  }

  // ---- refresh -----------------------------------------------------------------

  async function _refresh() {
    const data = await C.api("/api/scans?limit=" + LIST_LIMIT);
    const scans = (data && data.scans) || [];
    if (!scans.length) { renderEmpty(false); return; }
    const newest = scans[0];
    // Full scan for the hero + tiles (severity split, assessment); fall back to
    // the history row alone when the detail fetch fails.
    let full = null;
    try { full = await C.api("/api/scans/" + encodeURIComponent(newest.id)); }
    catch (_) { full = null; }
    renderHero(newest, full);
    renderTiles(newest, full);
    renderRecent(scans);
  }

  function refresh() {
    if (!$("dashHero")) return Promise.resolve();
    return _refresh().catch(() => renderEmpty(true));
  }

  C.dashboard = { refresh };

  // Refresh on first paint (dashboard is the default tab) and whenever its tab
  // is shown again. scan.js also calls refresh() after a scan job completes.
  C.onInit(() => { refresh(); });
  C.onTab((name) => { if (name === "dashboard") refresh(); });
})();
