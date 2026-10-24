"use strict";

/* ============================================================================
   Celsius web UI — jobs queue module: appbar badge with the running-job count
   and a right-side drawer listing running/recent scan jobs (cancel running,
   open live progress or finished results). Loaded after dashboard.js; shares window.CELSIUS
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
    const target = j.target || "(unknown target)";
    let actions = "";
    if (st === "running") {
      const cancel = _cancelling.has(j.job_id)
        ? `<button type="button" class="btn-ghost-danger jobs-cancel" data-action="cancel" disabled>cancelling…</button>`
        : `<button type="button" class="btn-ghost-danger jobs-cancel" data-action="cancel"
            data-job="${esc(j.job_id)}" aria-label="Cancel scan of ${esc(target)}">Cancel</button>`;
      actions = `<button type="button" class="btn-secondary jobs-open" data-action="open"
          data-job="${esc(j.job_id)}" aria-label="Open progress for ${esc(target)}">Open progress</button>`
        + cancel;
    } else if (st === "done") {
      actions = `<button type="button" class="btn-secondary jobs-view" data-action="view"
        data-job="${esc(j.job_id)}" aria-label="View results for ${esc(target)}">View</button>`;
    }
    return `<div class="jobs-row" data-job="${esc(j.job_id)}" aria-label="Scan job for ${esc(target)}">
      <div class="jobs-row-top">
        <span class="mono jobs-target">${esc(target)}</span>
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
    const active = document.activeElement;
    const focusedRow = active && box.contains(active) ? active.closest(".jobs-row") : null;
    const focusIdentity = focusedRow ? {
      job: focusedRow.dataset.job,
      action: active.dataset ? active.dataset.action : null,
    } : null;
    const scrollTop = $("jobsDrawer").scrollTop;
    const list = jobs();
    box.innerHTML = list.length
      ? list.map(rowHtml).join("")
      : `<p class="jobs-empty">No jobs yet</p>`;
    box.querySelectorAll(".jobs-cancel").forEach((b) =>
      b.addEventListener("click", () => cancelJob(b.dataset.job)));
    box.querySelectorAll(".jobs-open").forEach((b) =>
      b.addEventListener("click", () => openJobProgress(b.dataset.job)));
    box.querySelectorAll(".jobs-view").forEach((b) =>
      b.addEventListener("click", () => viewJob(b.dataset.job)));
    $("jobsDrawer").scrollTop = scrollTop;
    if (focusIdentity) {
      const row = [...box.querySelectorAll(".jobs-row")]
        .find((el) => el.dataset.job === focusIdentity.job);
      const same = row && focusIdentity.action
        ? row.querySelector(`[data-action="${focusIdentity.action}"]:not(:disabled)`) : null;
      const fallback = row && row.querySelector("button:not(:disabled)");
      (same || fallback || $("jobsClose")).focus({ preventScroll: true });
    }
  }

  // ---- actions ----------------------------------------------------------------

  function openJobProgress(jobId) {
    const job = jobs().find((j) => j.job_id === jobId);
    closeDrawer(false);
    C.showTab("host");
    C.watchJob(jobId, { target: job && job.target, startedAt: job && job.started_at });
    C.scrollIntoView($("scanProgress"), { block: "center" });
    $("scanProgress").tabIndex = -1;
    $("scanProgress").focus({ preventScroll: true });
  }

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
        closeDrawer(false);
        // ScanResult.to_dict() drops scan_id; it lives on the job dict (set by
        // the backend, app.py) — hand it through so loadScan can render the
        // export links and the "scan {id}" meta line like the History path does.
        await C.loadScan(Object.assign({}, job.result, { scan_id: job.scan_id }));
        $("results").focus({ preventScroll: true });
      } else {
        C.toast("That job has no stored result — check the History tab.", "info");
      }
    } catch (err) {
      C.toast("Could not open result: " + err.message, "error");
    }
  }

  // ---- drawer open/close ------------------------------------------------------------

  let _drawerReturnFocus = null;
  let _drawerHideTimer = null;
  let _drawerMobile = false;
  const _drawerBackground = new Map();
  const _drawerMedia = window.matchMedia("(max-width: 720px)");

  function setDrawerBackgroundInert(inert) {
    if (inert) {
      if (_drawerBackground.size) return;
      [...document.body.children].forEach((el) => {
        if (el.id === "jobsDrawer" || el.tagName === "SCRIPT") return;
        _drawerBackground.set(el, el.inert);
        el.inert = true;
      });
    } else {
      _drawerBackground.forEach((wasInert, el) => { el.inert = wasInert; });
      _drawerBackground.clear();
    }
  }

  function syncDrawerModality() {
    const drawer = $("jobsDrawer");
    const mobile = _open && _drawerMedia.matches;
    drawer.setAttribute("aria-modal", mobile ? "true" : "false");
    if (mobile === _drawerMobile) return;
    _drawerMobile = mobile;
    setDrawerBackgroundInert(mobile);
  }

  function openDrawer() {
    const drawer = $("jobsDrawer");
    if (!drawer || _open) return;
    if (_drawerHideTimer) {
      clearTimeout(_drawerHideTimer);
      _drawerHideTimer = null;
    }
    _drawerReturnFocus = document.activeElement;
    _open = true;
    $("jobsBtn").setAttribute("aria-expanded", "true");
    drawer.setAttribute("aria-hidden", "false");
    drawer.classList.remove("hidden");
    syncDrawerModality();
    void drawer.offsetWidth; // restart the slide-in transition
    drawer.classList.add("open");
    renderList();
    $("jobsClose").focus({ preventScroll: true });
    schedule(FAST_MS);
  }

  function closeDrawer(restoreFocus) {
    const drawer = $("jobsDrawer");
    if (!drawer || !_open) return;
    _open = false;
    syncDrawerModality();
    const returnFocus = _drawerReturnFocus;
    _drawerReturnFocus = null;
    const restore = restoreFocus !== false && returnFocus && returnFocus.isConnected;
    const destination = (restore ? returnFocus : $("jobsBtn")) || $("main-content");
    if (restoreFocus !== false || drawer.contains(document.activeElement)) {
      destination.focus({ preventScroll: true });
    }
    $("jobsBtn").setAttribute("aria-expanded", "false");
    drawer.setAttribute("aria-hidden", "true");
    drawer.classList.remove("open");
    if (_drawerHideTimer) clearTimeout(_drawerHideTimer);
    _drawerHideTimer = setTimeout(() => {
      _drawerHideTimer = null;
      if (!_open) drawer.classList.add("hidden");
    }, 260);
    schedule(anyRunning() ? FAST_MS : SLOW_MS);
  }

  function trapDrawerTab(e) {
    if (e.key !== "Tab" || !_open || !_drawerMedia.matches) return;
    const drawer = $("jobsDrawer");
    const focusable = [...drawer.querySelectorAll(
      'button, a[href], input, textarea, select, [tabindex]:not([tabindex="-1"])')]
      .filter((el) => !el.disabled && el.getClientRects().length);
    if (!focusable.length) {
      e.preventDefault();
      return;
    }
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (e.shiftKey && (document.activeElement === first || !drawer.contains(document.activeElement))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (document.activeElement === last || !drawer.contains(document.activeElement))) {
      e.preventDefault();
      first.focus();
    }
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
    syncDrawerModality();
    _drawerMedia.addEventListener("change", syncDrawerModality);
    drawer.addEventListener("keydown", trapDrawerTab);
    btn.addEventListener("click", () => (_open ? closeDrawer() : openDrawer()));
    $("jobsClose").addEventListener("click", () => closeDrawer());
    document.addEventListener("click", (e) => {
      if (_open && !drawer.contains(e.target) && !btn.contains(e.target)) closeDrawer(false);
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && _open) closeDrawer();
    });
    C.jobs.start();
  });
})();
