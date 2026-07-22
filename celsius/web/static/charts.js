"use strict";

/* ============================================================================
   Celsius web UI — results charts: severity donut, top-category bars and a
   CVE-trend sparkline, all hand-rolled inline SVG (no libraries, no build).
   Loaded after scan.js; shares window.CELSIUS (see app.js). CELSIUS.loadScan /
   the scan-completion path call CELSIUS.charts.render(scanDict) to fill
   #chartDonut / #chartCats / #chartTrend above the findings list.
   Untrusted scan data is always rendered through esc() — never raw HTML.
   ========================================================================== */

(function () {
  const C = window.CELSIUS;
  const $ = C.$;
  const esc = C.esc;

  const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const SEV_VAR = {
    CRITICAL: "--crit", HIGH: "--high", MEDIUM: "--med", LOW: "--low", INFO: "--info",
  };
  const SEV_LABEL = {
    CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", INFO: "Info",
  };
  const TREND_LIMIT = 10;
  const TOP_CATS = 6;

  // Headline severity counts — same convention as scan.js / dashboard.js:
  // low-confidence ("weak") CVEs and AI-hypothesis findings stay out.
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

  // Host part of a URL or bare host — mirrors hostOf() in scan.js.
  function hostOf(u) {
    const m = /^(?:[a-z][a-z0-9+.-]*:\/\/)?([^/:?#]+)/i.exec(String(u || "").trim());
    return m ? m[1].toLowerCase() : "";
  }

  // ---- severity donut ----------------------------------------------------------
  // Ring segments via stroke-dasharray on a radius-40 ring; colors come from the
  // theme's CSS severity vars so the chart follows light/dark automatically.
  function donutSVG(counts) {
    const total = SEVS.reduce((n, s) => n + counts[s], 0);
    const R = 40;
    const CIRC = 2 * Math.PI * R;
    let segs = "";
    if (total === 0) {
      segs = `<circle cx="60" cy="60" r="${R}" fill="none" stroke-width="14"
        style="stroke:var(--ok)"><title>No findings</title></circle>`;
    } else {
      let acc = 0;
      SEVS.forEach((s) => {
        const v = counts[s];
        if (!v) return;
        const frac = v / total;
        segs += `<circle cx="60" cy="60" r="${R}" fill="none" stroke-width="14"
          style="stroke:var(${SEV_VAR[s]})"
          stroke-dasharray="${(frac * CIRC).toFixed(2)} ${((1 - frac) * CIRC).toFixed(2)}"
          stroke-dashoffset="${(-acc * CIRC).toFixed(2)}">
          <title>${SEV_LABEL[s]}: ${v}</title></circle>`;
        acc += frac;
      });
    }
    const center = total === 0
      ? `<text x="60" y="58" text-anchor="middle" class="chart-donut-total">0</text>
         <text x="60" y="74" text-anchor="middle" class="chart-donut-label">No findings</text>`
      : `<text x="60" y="58" text-anchor="middle" class="chart-donut-total">${total}</text>
         <text x="60" y="74" text-anchor="middle" class="chart-donut-label">findings</text>`;
    return `<svg width="120" height="120" viewBox="0 0 120 120" role="img"
        aria-label="${total} finding(s) by severity">
      <title>${total} finding(s) by severity</title>
      <g transform="rotate(-90 60 60)">${segs}</g>${center}</svg>`;
  }

  function donutLegend(counts) {
    const items = SEVS.filter((s) => counts[s] > 0).map((s) =>
      `<li><span class="dot" style="background:var(${SEV_VAR[s]})"></span>${SEV_LABEL[s]} <b>${counts[s]}</b></li>`);
    if (!items.length) {
      return `<ul class="chart-legend"><li><span class="dot" style="background:var(--ok)"></span>No findings</li></ul>`;
    }
    return `<ul class="chart-legend">${items.join("")}</ul>`;
  }

  // ---- top-category bars ---------------------------------------------------------
  function barsSVG(res) {
    const byCat = {};
    (res.findings || []).forEach((f) => {
      if (f.category === "ai-hypothesis") return; // leads, not facts — same rule as the counts
      const cat = String(f.category || "other");
      byCat[cat] = (byCat[cat] || 0) + 1;
    });
    const rows = Object.entries(byCat)
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, TOP_CATS);
    if (!rows.length) return `<p class="empty empty-good">✓ No findings to chart.</p>`;

    const ROW_H = 24, LABEL_W = 132, N_W = 34, W = 340;
    const barMax = W - LABEL_W - N_W - 12;
    const max = rows[0][1];
    const H = rows.length * ROW_H + 4;
    let body = "";
    rows.forEach(([cat, n], i) => {
      const y = i * ROW_H + 3;
      const bw = Math.max(2, (n / max) * barMax);
      const label = cat.length > 20 ? cat.slice(0, 19) + "…" : cat;
      body += `<text class="chart-bar-label" x="0" y="${y + 12}">${esc(label)}</text>`
        + `<rect x="${LABEL_W}" y="${y + 3}" width="${bw.toFixed(1)}" height="10" rx="5"
             style="fill:var(--accent)"><title>${esc(cat)}: ${n}</title></rect>`
        + `<text class="chart-bar-n" x="${(LABEL_W + bw + 7).toFixed(1)}" y="${y + 12}">${n}</text>`;
    });
    return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Top finding categories">
      <title>Top ${rows.length} finding categories by count</title>${body}</svg>`;
  }

  // ---- CVE-trend sparkline ---------------------------------------------------------
  function sparkSVG(vals) {
    const W = 220, H = 56, PADX = 6, PADY = 8;
    const max = Math.max(...vals, 1);
    const n = vals.length;
    const X = (i) => (n === 1 ? W - PADX : PADX + (i * (W - 2 * PADX)) / (n - 1));
    const Y = (v) => H - PADY - (v / max) * (H - 2 * PADY);
    const pts = vals.map((v, i) => `${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(" ");
    const area = `M${X(0).toFixed(1)},${H - PADY} L`
      + vals.map((v, i) => `${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(" L")
      + ` L${X(n - 1).toFixed(1)},${H - PADY} Z`;
    return `<svg viewBox="0 0 ${W} ${H}" role="img"
        aria-label="CVEs per scan, oldest to newest: ${vals.join(", ")}">
      <title>CVEs per scan, oldest to newest: ${vals.join(", ")}</title>
      <path d="${area}" style="fill:var(--accent-soft)" stroke="none"></path>
      <polyline points="${pts}"></polyline>
      <circle cx="${X(n - 1).toFixed(1)}" cy="${Y(vals[n - 1]).toFixed(1)}" r="3.2">
        <title>Latest scan: ${vals[n - 1]} CVE(s)</title></circle></svg>`;
  }

  // Fetches prior scans of the same target and draws oldest→newest CVE counts.
  // Any failure (offline API, no matching scans, no host) hides the card.
  async function renderTrend(res, card) {
    const host = hostOf(res.url || res.target);
    if (!host) return;
    let scans;
    try {
      const data = await C.api("/api/scans?target=" + encodeURIComponent(host)
        + "&limit=" + TREND_LIMIT);
      scans = (data && data.scans) || [];
    } catch (_) {
      return; // card stays hidden — graceful degradation
    }
    const vals = scans.slice(0, TREND_LIMIT).reverse()
      .map((s) => Math.max(0, parseInt(s.n_cves, 10) || 0));
    if (!vals.length) return;
    card.innerHTML = `<h3 class="chart-title">CVE trend · ${esc(host)}</h3>
      <div class="spark">${sparkSVG(vals)}</div>
      <div class="chart-trend-meta mono">${vals.length} scan(s) · latest ${vals[vals.length - 1]} CVE(s)</div>`;
    card.classList.remove("hidden");
  }

  // ---- entry point ---------------------------------------------------------------
  // Fills the three chart cards for a scan dict and reveals the charts row.
  // Called by scan.js from the loadScan / scan-completion path.
  function render(scanDict) {
    const row = $("chartsRow");
    const donutCard = $("chartDonut");
    const catsCard = $("chartCats");
    const trendCard = $("chartTrend");
    if (!row || !donutCard || !catsCard || !trendCard) return;
    const res = scanDict || {};
    const counts = sevCounts(res);
    donutCard.innerHTML = `<h3 class="chart-title">Findings by severity</h3>
      <div class="donut">${donutSVG(counts)}${donutLegend(counts)}</div>`;
    catsCard.innerHTML = `<h3 class="chart-title">Top categories</h3>${barsSVG(res)}`;
    trendCard.innerHTML = "";
    trendCard.classList.add("hidden"); // shown only when the history fetch succeeds
    row.classList.remove("hidden");
    renderTrend(res, trendCard);
  }

  C.charts = { render };
})();
