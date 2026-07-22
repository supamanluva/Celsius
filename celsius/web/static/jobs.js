"use strict";

/* ============================================================================
   Celsius web UI — jobs queue module: appbar badge with the running-job count
   and a right-side drawer listing running/recent scan jobs (cancel running,
   open finished results). Loaded after dashboard.js; shares window.CELSIUS
   (see app.js). Additive: scan.js keeps its own per-job polling for the live
   progress card — this module only mirrors GET /api/jobs into CELSIUS.state.jobs.
   Untrusted job data is always rendered through esc() — never raw HTML.
   ========================================================================== */

(function () {
  const C = window.CELSIUS;
  const $ = C.$;
  const esc = C.esc;

  const FAST_MS = 2000;    // any job running OR the drawer is open
  const SLOW_MS = 15000;   // idle
  const BACKOFF_MS = 30000; // after a poll failure

  const STATUS_CHIP = {
    running: "chip-info",
    done: "chip-ok",
    cancelled: "chip-med",
    error: "chip-crit",   // backend marks crashed jobs "error"
  };
  const PHASES = {
    recon: "Mapping the attack surface",
    detect: "Checking for known vulnerabilities",
    enrich: "Scoring and prioritizing",
  };

  let _timer = null;
  let _started = false;
  let _open = false;
  const _prevStatus = {};   // job_id -> last seen status (detect transitions to done)
  const _cancelling = new Set(); // job_ids with a cancel request in flight

  function jobs() { return C.state.jobs || []; }
  function anyRunning() { return jobs().some((j) => j.status === "running"); }

  function schedule(ms) {
    clearTimeout(_timer);
    _timer = setTimeout(tick, ms);
  }

  async function tick() {
    try {
      const data = await C.api("/api/jobs");
      const list = (data && data.jobs) || [];
      // A job we saw running finished — keep the dashboard in sync.
      list.forEach((j) => {
        if (_prevStatus[j.job_id] === "running" && j.status === "done" &&
            C.dashboard && C.dashboard.refresh) {
          C.dashboard.refresh();
        }
        _prevStatus[j.job_id] = j.status;
        if (j.status !== "running") _cancelling.delete(j.job_id);
      });
      C.state.jobs = list;
      renderBadge();
      if (_open) renderList();
      schedule(anyRunning() || _open ? FAST_MS : SLOW_MS);
    } catch (_) {
      // Server unreachable / bad token — stay quiet: hide the badge, back off.
      hideBadge();
      schedule(BACKOFF_MS);
    }
  }

  // ---- badge ---------------------------------------------------------------

  function renderBadge() {
    const badge = $("jobsBadge");
    if (!badge) return;
    const n = jobs().filter((j) => j.status === "running").length;
    badge.textContent = String(n);
    badge.classList.toggle("hidden", n === 0);
  }

  function hideBadge() {
    const badge = $("jobsBadge");
    if (badge) badge.classList.add("hidden");
  }

  // ---- drawer rows ------------------------------------------------------------

  function progressHtml(j) {
    const p = j.progress;
    if (!p) return "";
    const total = p.total || 0;
    const pct = total > 0 ? Math.min(100, Math.round(((p.index || 0) / total) * 100)) : 0;
    const phase = PHASES[p.phase] || p.phase || "Working";
    const step = total > 0 ? `${p.index || 0}/${total}` : "…";
    const elapsed = p.elapsed != null ? C.fmtElapsed(p.elapsed) : "";
    return `<div class="progress">
      <div class="progress-label">
        <span>${esc(phase)}</span>
        <span class="mono">${esc(step)}${elapsed ? " · " + esc(elapsed) : ""}</span>
      </div>
      <div class="progress-track"><div class="progress-value" style="width:${pct}%"></div></div>
    </div>`;
  }

  function rowHtml(j) {
    const st = String(j.status || "");
    const chipCls = STATUS_CHIP[st] || "chip-info";
    let actions = "";
    if (st === "running") {
      actions = _cancelling.has(j.job_id)
        ? `<button type="button" class="btn-ghost-danger jobs-cancel" disabled>cancelling…</button>`
        : `<button type="button" class="btn-ghost-danger jobs-cancel" data-job="${esc(j.job_id)}">Cancel</button>`;
    } else if (st === "done") {
      actions = `<button type="button" class="btn-secondary jobs-view" data-job="${esc(j.job_id)}">View</button>`;
    }
    return `<div class="jobs-row" data-job="${esc(j.job_id)}">
      <div class="jobs-row-top">
        <span class="mono jobs-target">${esc(j.target || "(unknown target)")}</span>
        <span class="chip ${chipCls}">${esc(st || "?")}</span>
      </div>
      ${st === "running" ? progressHtml(j) : ""}
      ${st === "error" && j.error ? `<div class="jobs-err">${esc(j.error)}</div>` : ""}
      ${actions ? `<div class="jobs-actions">${actions}</div>` : ""}
    </div>`;
  }

  function renderList() {
    const box = $("jobsList");
    if (!box) return;
    const list = jobs();
    box.innerHTML = list.length
      ? list.map(rowHtml).join("")
      : `<p class="jobs-empty">No jobs yet</p>`;
    box.querySelectorAll(".jobs-cancel").forEach((b) =>
      b.addEventListener("click", () => cancelJob(b.dataset.job)));
    box.querySelectorAll(".jobs-view").forEach((b) =>
      b.addEventListener("click", () => viewJob(b.dataset.job)));
  }

  // ---- actions ----------------------------------------------------------------

  async function cancelJob(jobId) {
    _cancelling.add(jobId);
    if (_open) renderList(); // disable the button, show "cancelling…"
    try {
      await C.api("/api/scan/" + encodeURIComponent(jobId), { method: "DELETE" });
      refresh(); // pick up the new status right away
    } catch (err) {
      _cancelling.delete(jobId);
      if (_open) renderList();
      C.toast("Could not cancel: " + err.message, "error");
    }
  }

  async function viewJob(jobId) {
    try {
      const job = await C.api("/api/scan/" + encodeURIComponent(jobId));
      if (job && job.result) {
        closeDrawer();
        // ScanResult.to_dict() drops scan_id; it lives on the job dict (set by
        // the backend, app.py) — hand it through so loadScan can render the
        // export links and the "scan {id}" meta line like the History path does.
        C.loadScan(Object.assign({}, job.result, { scan_id: job.scan_id }));
      } else {
        C.toast("That job has no stored result — check the History tab.", "info");
      }
    } catch (err) {
      C.toast("Could not open result: " + err.message, "error");
    }
  }

  // ---- drawer open/close ------------------------------------------------------------

  function openDrawer() {
    const drawer = $("jobsDrawer");
    if (!drawer || _open) return;
    _open = true;
    drawer.classList.remove("hidden");
    void drawer.offsetWidth; // restart the slide-in transition
    drawer.classList.add("open");
    renderList();
    schedule(FAST_MS);
  }

  function closeDrawer() {
    const drawer = $("jobsDrawer");
    if (!drawer || !_open) return;
    _open = false;
    drawer.classList.remove("open");
    setTimeout(() => { if (!_open) drawer.classList.add("hidden"); }, 260);
    schedule(anyRunning() ? FAST_MS : SLOW_MS);
  }

  function refresh() { schedule(0); }

  C.jobs = {
    start() {
      if (_started) return;
      _started = true;
      tick();
    },
    refresh,
  };

  C.onInit(() => {
    const btn = $("jobsBtn");
    const drawer = $("jobsDrawer");
    if (!btn || !drawer) return;
    btn.addEventListener("click", () => (_open ? closeDrawer() : openDrawer()));
    $("jobsClose").addEventListener("click", closeDrawer);
    document.addEventListener("click", (e) => {
      if (_open && !drawer.contains(e.target) && !btn.contains(e.target)) closeDrawer();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && _open) closeDrawer();
    });
    C.jobs.start();
  });
})();
