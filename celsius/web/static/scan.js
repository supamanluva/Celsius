"use strict";

/* ============================================================================
   Celsius web UI — scan module: scan form, presets, advanced/auth/lab options,
   AI config, test sites, scan queue + polling + progress, results rendering,
   PoC modal, history, code scan, mail security.
   Loaded after app.js; shares window.CELSIUS (see app.js for the namespace).
   Untrusted scan data is always rendered through esc() — never raw HTML.
   ========================================================================== */

(function () {
  const C = window.CELSIUS;
  const $ = C.$;
  const esc = C.esc;
  const toast = C.toast;
  const setStatus = C.setStatus;
  const fmtElapsed = C.fmtElapsed;
  const withToken = C.withToken;
  const SEV_ORDER = C.SEV_ORDER;

  C.onInit(function () {
    let lastUrl = null; // url of last scan, for PoC context

    // Refresh the dashboard (Task 3+) after a scan completes — optional hook.
    function notifyScanDone() {
      if (C.dashboard && C.dashboard.refresh) C.dashboard.refresh();
    }

    // ---- history is loaded when its tab is shown -------------------------------
    C.onTab((name) => { if (name === "history") loadHistory(true); });

    // ---- scan presets ---------------------------------------------------------------
    // Each preset maps the advanced-option checkbox ids to on/off. Only depth
    // edits select Custom; AI and authenticated-session settings stay independent.
    const PRESETS = {
      quick: {
        "opt-web": true, "opt-cve": true, "opt-secrets": true, "opt-dns": true,
        "opt-tls": true, "opt-fingerprint": true, "opt-mailsec": false,
        "opt-subdomains": false, "opt-crawl": false, "opt-content": false,
        "opt-apidisco": false, "opt-wayback": false, "opt-topology": false,
        "opt-dynamic": false, "opt-ports": false, "opt-udp": false,
        "opt-osdetect": false, "opt-subbrute": false, "opt-nuclei": false,
        "opt-nucleifull": false, "opt-cveverify": false, "opt-defaultcreds": false,
      },
      standard: {
        "opt-web": true, "opt-cve": true, "opt-secrets": true, "opt-dns": true,
        "opt-tls": true, "opt-fingerprint": true, "opt-mailsec": true,
        "opt-subdomains": true, "opt-crawl": true, "opt-content": true,
        "opt-apidisco": true, "opt-wayback": false, "opt-topology": false,
        "opt-dynamic": false, "opt-ports": false, "opt-udp": false,
        "opt-osdetect": false, "opt-subbrute": false, "opt-nuclei": false,
        "opt-nucleifull": false, "opt-cveverify": false, "opt-defaultcreds": false,
      },
      deep: {
        "opt-web": true, "opt-cve": true, "opt-secrets": true, "opt-dns": true,
        "opt-tls": true, "opt-fingerprint": true, "opt-mailsec": true,
        "opt-subdomains": true, "opt-crawl": true, "opt-content": true,
        "opt-apidisco": true, "opt-wayback": true, "opt-topology": true,
        "opt-dynamic": false, "opt-ports": true, "opt-udp": false,
        "opt-osdetect": false, "opt-subbrute": true, "opt-nuclei": true,
        "opt-nucleifull": false, "opt-cveverify": false, "opt-defaultcreds": false,
      },
    };

    const PRESET_LABELS = { quick: "Quick", standard: "Standard", deep: "Deep", custom: "Custom" };
    const DEPTH_CONTROLS = new Set([
      ...Object.keys(PRESETS.standard), "opt-portrange", "opt-nucleitags",
    ]);
    const DEPENDENCIES = [
      ["opt-udp", "opt-ports"], ["opt-osdetect", "opt-ports"],
      ["opt-portrange", "opt-ports"], ["opt-subbrute", "opt-subdomains"],
      ["opt-dynamic", "opt-crawl"], ["opt-nucleifull", "opt-nuclei"],
      ["opt-nucleitags", "opt-nuclei"], ["opt-cveverify", "opt-cve"],
    ];
    let _activePreset = "standard";
    function presetLabel() { return PRESET_LABELS[_activePreset] || "Custom"; }

    function syncDependencies() {
      DEPENDENCIES.forEach(([childId, parentId]) => {
        const child = $(childId), enabled = $(parentId).checked;
        child.disabled = !enabled;
        if (!enabled && child.type === "checkbox") child.checked = false;
        const note = $(childId + "-dependency");
        if (note) note.classList.toggle("hidden", enabled);
        const row = child.closest(".opt");
        if (row) row.classList.toggle("dependency-disabled", !enabled);
      });
    }

    function selectPreset(name, applyValues) {
      _activePreset = name;
      document.querySelectorAll(".preset").forEach((p) => {
        const on = p.dataset.preset === name;
        p.classList.toggle("active", on);
        p.setAttribute("aria-checked", on ? "true" : "false");
        p.tabIndex = on ? 0 : -1;
      });
      if (applyValues && PRESETS[name]) {
        Object.entries(PRESETS[name]).forEach(([id, on]) => { $(id).checked = on; });
        $("opt-portrange").value = "";
        $("opt-nucleitags").value = "";
      }
      syncDependencies();
      if (name === "custom") $("advancedOpts").open = true;
    }

    const presetButtons = [...document.querySelectorAll(".preset")];
    presetButtons.forEach((p) => {
      p.addEventListener("click", () => selectPreset(p.dataset.preset, true));
    });
    document.querySelector(".presets").addEventListener("keydown", (e) => {
      C.rovingKey(e, presetButtons, (preset) => {
        selectPreset(preset.dataset.preset, true);
        preset.focus();
      });
    });
    // AI and authenticated-session configuration do not define scan depth.
    $("advancedOpts").addEventListener("change", (e) => {
      if (e.target && DEPTH_CONTROLS.has(e.target.id)) selectPreset("custom", false);
      syncDependencies();
    });
    $("advancedOpts").addEventListener("input", (e) => {
      if (e.target && DEPTH_CONTROLS.has(e.target.id)) selectPreset("custom", false);
    });

    // Default state: Standard.
    selectPreset("standard", true);

    // ---- AI provider status -----------------------------------------------------------
    // Ask the server which providers are configured. If none: friendly hint with the
    // form hidden behind a "Configure AI" toggle. If some: preselect the first one.
    (async function initAI() {
      try {
        const r = await fetch("/api/ai/status");
        if (!r.ok) return;
        const { providers } = await r.json();
        const order = ["kimi", "deepseek", "openai", "anthropic", "local"];
        const configured = order.filter((p) => providers && providers[p]);
        if (configured.length) {
          $("aiReady").classList.remove("hidden");
          $("opt-ai-provider").value = configured[0];
        } else {
          $("aiHint").classList.remove("hidden");
          $("aiForm").classList.add("hidden");
        }
      } catch (e) { /* status probe is best-effort */ }
    })();
    $("aiConfigureBtn").addEventListener("click", () => {
      $("aiForm").classList.remove("hidden");
      $("aiHint").classList.add("hidden");
    });

    // Existing saved keys remain available and are shown as opted in; new keys are
    // stored only after explicit consent, and opting out removes the legacy value too.
    const aiKeyInput = $("opt-ai-key"), rememberAiKey = $("opt-ai-remember");
    try {
      const savedKey = localStorage.getItem("celsius_ai_key");
      if (savedKey) {
        aiKeyInput.value = savedKey;
        rememberAiKey.checked = true;
      }
    } catch (e) { /* localStorage may be unavailable */ }
    function persistAiKeyIfOptedIn() {
      if (!rememberAiKey.checked) return;
      try {
        if (aiKeyInput.value) localStorage.setItem("celsius_ai_key", aiKeyInput.value);
        else localStorage.removeItem("celsius_ai_key");
      } catch (_) {}
    }
    aiKeyInput.addEventListener("input", persistAiKeyIfOptedIn);
    rememberAiKey.addEventListener("change", () => {
      if (rememberAiKey.checked) persistAiKeyIfOptedIn();
      else {
        try { localStorage.removeItem("celsius_ai_key"); } catch (_) {}
      }
    });

    // ---- legal test targets -------------------------------------------------------------
    (async function loadTestSites() {
      try {
        const r = await fetch("/api/testsites");
        if (!r.ok) return;
        const data = await r.json();
        $("testsitesNote").textContent = data.note || "";
        $("testsitesList").innerHTML = (data.groups || []).map((g) => `
          <div class="ts-group">
            <h4>${esc(g.name)}</h4>
            ${(g.sites || []).map((s) => `
              <div class="ts-site">
                <button type="button" class="ts-use" data-url="${esc(s.url)}"
                  title="Use ${esc(s.url)} as the scan target">${esc(s.name)}</button>
                <span class="ts-stack">${esc(s.stack)}</span>
                <div class="ts-focus">${esc(s.focus)}</div>
              </div>`).join("")}
          </div>`).join("");

        $("testsitesList").addEventListener("click", (e) => {
          const btn = e.target.closest(".ts-use");
          if (!btn) return;
          $("target").value = btn.dataset.url;
          $("testsites").open = false;
          $("target").focus();
          $("target").scrollIntoView({ block: "center", behavior: C.scrollBehavior() });
        });
      } catch (e) { /* offline — panel just stays empty */ }
    })();

    // ---- shared render helpers -------------------------------------------------------------
    const VERDICT_CLASS = {
      "confirmed-exploitable": "v-high", "confirmed-exposed": "v-high",
      "likely-exploitable": "v-high", "conditions-needed": "v-med",
      "needs-manual": "v-med", "not-in-context": "v-low",
      "unknown": "v-unk", "informational": "v-info",
    };
    function verdictBadge(ex) {
      if (!ex || !ex.verdict || ex.verdict === "informational") return "";
      const cls = VERDICT_CLASS[ex.verdict] || "v-unk";
      return ` <span class="verdict ${cls}" title="exploitability verdict">${esc(ex.verdict)}</span>`;
    }
    // Remediation playbook (steps + copyable snippet) from exploitability.remediation.
    function fixContent(ex) {
      const pb = ex && ex.remediation;
      if (!pb) return "";
      const steps = (pb.steps || []).map((s) => `<li>${esc(s)}</li>`).join("");
      const stepsHtml = steps ? `<ol class="fixsteps">${steps}</ol>` : "";
      const snipHtml = pb.snippet
        ? `<div class="snipwrap"><button class="copyBtn" type="button">copy</button>`
          + `<pre class="fixsnippet"><code>${esc(pb.snippet)}</code></pre></div>`
        : "";
      const sumHtml = pb.summary ? `<p>${esc(pb.summary)}</p>` : "";
      return sumHtml + stepsHtml + snipHtml;
    }
    // Delegated copy button for remediation snippets.
    document.addEventListener("click", (e) => {
      if (e.target && e.target.classList && e.target.classList.contains("copyBtn")) {
        const pre = e.target.parentElement.querySelector("pre");
        if (pre) {
          navigator.clipboard && navigator.clipboard.writeText(pre.innerText);
          const old = e.target.textContent;
          e.target.textContent = "copied!";
          setTimeout(() => { e.target.textContent = old; }, 1500);
        }
      }
    });
    function shortUrl(u) {
      try { const x = new URL(u); return x.hostname.replace(/^www\./, "") + (x.pathname.length > 1 ? x.pathname.slice(0, 24) : ""); }
      catch (e) { return String(u || "").slice(0, 40); }
    }
    function exploitMeta(ex) {
      if (!ex || !ex.signals) return "";
      const s = ex.signals, bits = [];
      const epss = numberValue(s.epss, null);
      if (epss != null) bits.push("EPSS " + epss.toFixed(3));
      if (s.kev) bits.push("CISA-KEV");
      if (ex.priority != null) bits.push("priority " + String(ex.priority));
      return bits.length ? " · " + esc(bits.join(" · ")) : "";
    }

    // Plain-language "why it matters" fallback per severity.
    const WHY = {
      CRITICAL: "Attackers can likely exploit this with little effort — treat it as urgent.",
      HIGH: "This could meaningfully compromise the site, its data or its users.",
      MEDIUM: "Not directly exploitable on its own, but it weakens your defenses.",
      LOW: "A minor issue — worth fixing when convenient.",
      INFO: "Informational — no direct risk on its own.",
    };

    // Inline-SVG severity donut (no libraries). Circumference-100 circle trick.
    function donutSVG(counts) {
      const sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      const colors = { CRITICAL: "#dc2626", HIGH: "#ea580c", MEDIUM: "#d97706", LOW: "#2563eb", INFO: "#94a3b8" };
      const total = sevs.reduce((n, s) => n + (counts[s] || 0), 0);
      let segs = "";
      if (total === 0) {
        segs = `<circle r="15.9155" cx="21" cy="21" fill="transparent" stroke="#cbd5e1" stroke-width="5"/>`;
      } else {
        let offset = 25;
        sevs.forEach((s) => {
          const v = counts[s] || 0;
          if (!v) return;
          const pct = (v / total) * 100;
          segs += `<circle r="15.9155" cx="21" cy="21" fill="transparent" stroke="${colors[s]}" stroke-width="5"
            stroke-dasharray="${pct.toFixed(2)} ${(100 - pct).toFixed(2)}" stroke-dashoffset="${offset.toFixed(2)}"/>`;
          offset -= pct;
        });
      }
      return `<svg class="hero-donut" width="104" height="104" viewBox="0 0 42 42"
          role="img" aria-label="${total} issue(s) by severity">${segs}
        <text x="21" y="20.5" text-anchor="middle" class="donut-total">${total}</text>
        <text x="21" y="27.5" text-anchor="middle" class="donut-label">issues</text></svg>`;
    }

    // ---- host/web scan ----------------------------------------------------------------------
    let _scanQueue = [];
    let _scanning = false;
    let _postPending = false;
    const _jobRegistry = new Map();
    let _activeJob = null;
    let _viewedJobId = null;
    let _viewGeneration = 0;
    let _resultLoadGeneration = 0;
    let _elapsedTimer = null;
    let _elapsedBase = null;
    let _lastElapsed = null;

    function showFieldError(inputId, message) {
      const input = $(inputId), error = $(inputId + "Error");
      if (!input || !error) return;
      input.setAttribute("aria-invalid", message ? "true" : "false");
      error.textContent = message || "";
      error.classList.toggle("hidden", !message);
    }

    ["target", "mailDomain", "codePath", "codeText"].forEach((id) => {
      $(id).addEventListener("input", () => showFieldError(id, ""));
    });

    function targetProblem(raw) {
      const value = raw.trim(), invalid = "Enter a valid hostname, IP address, or URL (including a valid port).";
      if (!value) return "Enter a website, hostname, or IP address to scan.";
      try {
        if (value.includes("://")) {
          if (!new URL(value).hostname) return invalid;
          return "";
        }
        let host = value;
        if (value.startsWith("[")) {
          const end = value.indexOf("]");
          if (end < 0) return invalid;
          host = value.slice(1, end);
          const rest = value.slice(end + 1);
          if (rest && (!rest.startsWith(":") || !validPort(rest.slice(1)))) return invalid;
          new URL("http://[" + host + "]");
        } else if (value.includes(":") && value.indexOf(":") === value.lastIndexOf(":")) {
          const parts = value.split(":");
          host = parts[0];
          if (!validPort(parts[1])) return invalid;
        }
        if (!host || /\s/.test(host) || host.startsWith("/")) return invalid;
      } catch (_) { return invalid; }
      return "";
    }

    function validPort(value) {
      if (!/^\d+$/.test(value)) return false;
      const port = Number(value);
      return port >= 1 && port <= 65535;
    }

    function normalizeOptions(options) {
      const o = { ...options };
      o.udp = !!(o.ports && o.udp);
      o.os_detect = !!(o.ports && o.os_detect);
      o.port_range = o.ports ? (o.port_range || null) : null;
      o.subdomain_bruteforce = !!(o.subdomains && o.subdomain_bruteforce);
      o.dynamic = !!(o.crawl && o.dynamic);
      o.nuclei_full = !!(o.nuclei && o.nuclei_full);
      o.nuclei_tags = o.nuclei ? (o.nuclei_tags || null) : null;
      o.cve_verify = !!(o.cve && o.cve_verify);
      return o;
    }

    function currentScanOptions() {
      return normalizeOptions({
        web: $("opt-web").checked, cve: $("opt-cve").checked,
        web_secrets: $("opt-secrets").checked, ports: $("opt-ports").checked,
        default_creds: $("opt-defaultcreds").checked,
        nuclei: $("opt-nuclei").checked,
        dns: $("opt-dns").checked, tls: $("opt-tls").checked,
        mailsec: $("opt-mailsec").checked,
        fingerprint: $("opt-fingerprint").checked, subdomains: $("opt-subdomains").checked,
        topology: $("opt-topology").checked,
        crawl: $("opt-crawl").checked, api_discovery: $("opt-apidisco").checked,
        cve_verify: $("opt-cveverify").checked,
        dynamic: $("opt-dynamic").checked, wayback: $("opt-wayback").checked,
        content_discovery: $("opt-content").checked, os_detect: $("opt-osdetect").checked,
        udp: $("opt-udp").checked, port_range: $("opt-portrange").value.trim() || null,
        subdomain_bruteforce: $("opt-subbrute").checked, nuclei_full: $("opt-nucleifull").checked,
        nuclei_tags: $("opt-nucleitags").value.trim() || null,
        allow_exploit: $("opt-exploit").checked,
        lab_attestation: $("opt-attest").value.trim() || null,
        dry_run: $("opt-dryrun").checked,
        ai: $("opt-ai").checked, ai_provider: $("opt-ai-provider").value,
        ai_hunt: $("opt-ai-hunt") ? $("opt-ai-hunt").checked : true,
        ai_redact: true,
        ai_api_key: $("opt-ai-key").value.trim() || null,
        ai_model: $("opt-ai-model").value.trim() || null,
        ai_base_url: $("opt-ai-base").value.trim() || null,
        auth_cookie: $("opt-cookie").value.trim() || null,
        auth_bearer: $("opt-bearer").value.trim() || null,
        auth_headers: ($("opt-headers").value || "").split("\n").map((s) => s.trim()).filter(Boolean),
        login_url: $("opt-login-url").value.trim() || null,
        login_user: $("opt-login-user").value.trim() || null,
        login_pass: $("opt-login-pass").value || null,
        login_field_user: $("opt-login-fuser").value.trim() || "username",
        login_field_pass: $("opt-login-fpass").value.trim() || "password",
      });
    }

    function scrubOptions(options) {
      if (!options) return;
      ["ai_api_key", "auth_cookie", "auth_bearer", "login_user", "login_pass"]
        .forEach((key) => { options[key] = null; });
      options.auth_headers = [];
    }

    function queueNote() { return _scanQueue.length ? ` · ${_scanQueue.length} queued` : ""; }
    function updateScanButton() {
      $("scanBtn").disabled = _postPending;
      $("scanBtn").textContent = _scanning ? "Queue scan" : "Scan";
    }

    function clearResultViews() {
      _resultLoadGeneration++;
      _viewedJobId = null;
      C.state.currentScan = null;
      $("results").innerHTML = "";
      $("chartsRow").classList.add("hidden");
      ["chartDonut", "chartCats", "chartTrend"].forEach((id) => {
        const card = $(id);
        card.replaceWith(card.cloneNode(false)); // detach any in-flight trend render
      });
      $("chartTrend").classList.add("hidden");
      $("resultsToggle").classList.add("hidden");
      if (C.surface && C.surface.setView) C.surface.setView("findings");
      $("surfaceView").classList.add("hidden");
      $("surfaceGraph").innerHTML = "";
      $("surfaceDetail").innerHTML = "";
      $("surfaceDetail").classList.add("hidden");
    }

    const PHASES = {
      recon: "Mapping the attack surface…",
      detect: "Checking for known vulnerabilities…",
      enrich: "Scoring and prioritizing…",
    };

    function announceProgress(message) {
      const status = $("scanProgressStatus");
      if (status.textContent !== message) status.textContent = message;
    }

    function setProgressPhase(job, phase) {
      const changed = $("progPhase").textContent !== phase;
      const restored = ["interrupted", "auth-required", "reconnecting"].includes(job.connectionState);
      $("progPhase").textContent = phase;
      job.connectionState = "connected";
      if (changed || restored) {
        announceProgress((restored ? "Connection restored. " : "") + phase);
      }
    }

    function startElapsed(job) {
      stopElapsed();
      const parsed = job.startedAt ? Date.parse(job.startedAt) : NaN;
      _elapsedBase = Number.isFinite(parsed) ? parsed : Date.now();
      _lastElapsed = job.elapsed != null ? job.elapsed : null;
      const tick = () => {
        if (!isVisibleJob(job)) return;
        const sec = _lastElapsed != null ? _lastElapsed : (Date.now() - _elapsedBase) / 1000;
        $("progElapsed").textContent = fmtElapsed(sec);
      };
      tick();
      _elapsedTimer = setInterval(tick, 1000);
    }
    function stopElapsed() {
      if (_elapsedTimer) { clearInterval(_elapsedTimer); _elapsedTimer = null; }
    }

    function isVisibleJob(job) {
      return !!job && _activeJob === job;
    }

    function shouldPollJob(job) {
      return !!job && _jobRegistry.get(job.id) === job && !job.terminal
        && (job.queueOwned || isVisibleJob(job));
    }

    function updateCancelButton(job) {
      if (!isVisibleJob(job)) return;
      const button = $("cancelBtn");
      button.classList.remove("hidden");
      button.disabled = !!job.cancelPending;
      button.textContent = job.cancelPending ? "Cancelling…" : "Cancel scan";
    }

    function resetProgress(job) {
      const card = $("scanProgress");
      card.classList.remove("hidden", "done", "cancelled", "error");
      $("progTitle").textContent = `${job.preset} scan of ${job.target} — running…`;
      $("progPhase").textContent = "Starting…";
      $("progPlugin").textContent = "";
      $("progFill").style.width = "0%";
      $("progBar").setAttribute("aria-valuenow", "0");
      $("scanLog").textContent = "";
      $("reconnectJobBtn").classList.add("hidden");
      job.cancelPending = false;
      job.connectionState = "starting";
      announceProgress(`Starting ${job.preset} scan of ${job.target}.`);
      updateCancelButton(job);
      startElapsed(job);
    }

    function showProgress(job, data) {
      $("scanProgress").classList.remove("hidden");
      $("progTitle").textContent = `${job.preset} scan of ${job.target} — running…`;
      const p = data.progress;
      if (p) {
        setProgressPhase(job, PHASES[p.phase] || "Working…");
        const pct = p.total ? Math.min(100, Math.round((p.index / p.total) * 100)) : 0;
        $("progFill").style.width = pct + "%";
        $("progBar").setAttribute("aria-valuenow", String(pct));
        $("progPlugin").textContent = p.plugin ? `${p.plugin} · step ${p.index}/${p.total}` : "";
        if (p.elapsed != null) {
          job.elapsed = p.elapsed;
          _lastElapsed = p.elapsed;
          $("progElapsed").textContent = fmtElapsed(p.elapsed);
        }
      } else {
        setProgressPhase(job, "Starting…");
        $("progPlugin").textContent = (data.log || []).slice(-1)[0] || "";
      }
      updateCancelButton(job);
    }

    function completeProgress(job, state, gradeLetter) {
      stopElapsed();
      const card = $("scanProgress");
      card.classList.remove("done", "cancelled", "error");
      const elapsed = fmtElapsed(_lastElapsed != null ? _lastElapsed : (Date.now() - _elapsedBase) / 1000);
      $("cancelBtn").classList.add("hidden");
      $("reconnectJobBtn").classList.add("hidden");
      $("progPlugin").textContent = "";
      $("progElapsed").textContent = elapsed;
      job.connectionState = state;
      if (state === "done") {
        card.classList.add("done");
        $("progTitle").textContent = `${job.preset} scan of ${job.target} — finished in ${elapsed}`
          + `${gradeLetter ? " · grade " + gradeLetter : ""}`;
        $("progPhase").textContent = "Complete";
        $("progFill").style.width = "100%";
        $("progBar").setAttribute("aria-valuenow", "100");
        announceProgress(`Scan of ${job.target} complete${gradeLetter ? ", grade " + gradeLetter : ""}.`);
      } else if (state === "cancelled") {
        card.classList.add("cancelled");
        $("progTitle").textContent = `${job.preset} scan of ${job.target} — cancelled after ${elapsed}`;
        $("progPhase").textContent = "Cancelled";
        announceProgress(`Scan of ${job.target} cancelled.`);
      } else {
        card.classList.add("error");
        $("progTitle").textContent = state === "missing"
          ? `Scan job ${job.id} is no longer available`
          : `${job.preset} scan of ${job.target} — failed after ${elapsed}`;
        $("progPhase").textContent = state === "missing" ? "Not found" : "Failed";
        announceProgress(state === "missing"
          ? `Scan job ${job.id} is no longer available.`
          : `Scan of ${job.target} failed.`);
      }
    }

    function ensureJob(jobId, meta) {
      const existing = _jobRegistry.get(jobId);
      if (existing) {
        existing.target = meta.target || existing.target;
        existing.preset = meta.preset || existing.preset;
        existing.startedAt = meta.startedAt || existing.startedAt;
        existing.queueOwned = existing.queueOwned || !!meta.queueOwned;
        return existing;
      }
      const job = {
        id: jobId, job_id: jobId, target: meta.target || jobId,
        preset: meta.preset || "Scan", queueOwned: !!meta.queueOwned,
        startedAt: meta.startedAt || null, timer: null, polling: false,
        failures: 0, cancelPending: false, terminal: false, initialized: false,
        connectionState: "starting", lastData: null, elapsed: null,
      };
      _jobRegistry.set(jobId, job);
      return job;
    }

    function pauseWatcher(job) {
      if (job && job.timer) {
        clearTimeout(job.timer);
        job.timer = null;
      }
    }

    function selectJob(job) {
      if (!isVisibleJob(job)) {
        if (_activeJob && !_activeJob.queueOwned) pauseWatcher(_activeJob);
        stopElapsed();
        _activeJob = job;
        C.state.activeJob = job;
        if (!job.initialized) {
          resetProgress(job);
          job.initialized = true;
        } else {
          $("scanProgress").classList.remove("hidden", "done", "cancelled", "error");
          if (job.lastData) showProgress(job, job.lastData);
          else updateCancelButton(job);
          renderJobLog(job.lastData || { log: [] });
          startElapsed(job);
        }
      }
      _viewedJobId = job.id;
      $("scanProgress").classList.remove("hidden");
    }

    function schedulePoll(job, delay) {
      if (!shouldPollJob(job)) return;
      pauseWatcher(job);
      job.timer = setTimeout(() => {
        job.timer = null;
        if (shouldPollJob(job)) pollJob(job);
      }, delay);
    }

    function renderJobLog(data) {
      if (!Array.isArray(data.log)) return;
      $("scanLog").textContent = data.log.join("\n");
      $("scanLog").scrollTop = $("scanLog").scrollHeight;
    }

    function noteSuffix(result) {
      const n = ((result && result.errors) || []).length;
      return n ? ` ${n} scan note${n === 1 ? "" : "s"}.` : "";
    }

    function finishJob(job, state, data) {
      if (job.terminal) return;
      job.terminal = true;
      job.connectionState = state;
      pauseWatcher(job);
      const visible = isVisibleJob(job);
      const shouldRender = visible && _viewedJobId === job.id && state === "done" && !!data.result;
      const revealNext = job.queueOwned && visible && _viewedJobId === job.id;
      if (visible) {
        renderJobLog(data);
        _activeJob = null;
        C.state.activeJob = null;
        stopElapsed();
      }
      if (state === "done") {
        const result = data.result || {};
        const grade = (result.assessment || {}).grade;
        if (visible) completeProgress(job, "done", grade);
        if (shouldRender) {
          _resultLoadGeneration++;
          renderResult(result, data.scan_id, job.id);
          setStatus("scanStatus", "Scan complete." + noteSuffix(result) + queueNote(), false);
          finishTitle(result);
        } else if (visible) {
          const kept = C.state.currentScan ? " The result below was left unchanged." : "";
          setStatus("scanStatus", "Scan complete — open the result from Scan jobs."
            + kept + noteSuffix(result) + queueNote(), false);
        }
        toast("Scan of " + (result.target || job.target) + " finished.", "success");
        notifyScanDone();
      } else if (state === "cancelled") {
        if (visible) {
          completeProgress(job, "cancelled");
          setStatus("scanStatus", "Scan cancelled." + queueNote(), false);
        }
        toast("Scan cancelled.", "info");
      } else if (state === "missing") {
        if (visible) {
          completeProgress(job, "missing");
          setStatus("scanStatus", `Scan job ${job.id} was not found (404). It may have expired `
            + "or the server may have restarted. Polling has stopped.", true);
        }
      } else {
        const message = data.error || "unknown error";
        if (visible) {
          completeProgress(job, "error");
          setStatus("scanStatus", "Scan failed: " + message, true);
        }
        toast("Scan failed: " + message, "error");
      }
      if (job.queueOwned) nextScan(revealNext);
    }

    function transientPollError(err) {
      return !err.status || err.status === 429 || err.status >= 500;
    }

    async function pollJob(job) {
      if (!shouldPollJob(job) || job.polling) return;
      job.polling = true;
      pauseWatcher(job);
      try {
        const data = await C.api("/api/scan/" + encodeURIComponent(job.id));
        if (!shouldPollJob(job)) return;
        job.failures = 0;
        job.lastData = data;
        job.target = data.target || (data.result || {}).target || job.target;
        const visible = isVisibleJob(job);
        if (!job.startedAt && data.started_at) {
          job.startedAt = data.started_at;
          if (visible) {
            const parsed = Date.parse(data.started_at);
            if (Number.isFinite(parsed)) _elapsedBase = parsed;
          }
        }
        if (visible) {
          $("reconnectJobBtn").classList.add("hidden");
          renderJobLog(data);
        }
        if (data.status === "running") {
          if (visible) showProgress(job, data);
          schedulePoll(job, 800);
        } else if (data.status === "done") {
          finishJob(job, "done", data);
        } else if (data.status === "cancelled") {
          finishJob(job, "cancelled", data);
        } else {
          finishJob(job, "error", data);
        }
      } catch (err) {
        if (!shouldPollJob(job)) return;
        if (err.status === 404) {
          finishJob(job, "missing", { log: (job.lastData || {}).log || [] });
        } else if (err.status === 401) {
          job.connectionState = "auth-required";
          if (isVisibleJob(job)) {
            announceProgress("Connection paused — access token required.");
            $("progPhase").textContent = "Access token required";
            $("reconnectJobBtn").textContent = "Reconnect";
            $("reconnectJobBtn").classList.remove("hidden");
            setStatus("scanStatus", "HTTP 401: the access token is missing or invalid. Paste the token "
              + "printed by `celsius serve` into Access token above, then choose Reconnect. "
              + "The active job is still being tracked.", true);
          }
        } else if (transientPollError(err)) {
          job.failures++;
          const delay = Math.min(15000, 800 * Math.pow(2, job.failures - 1));
          job.connectionState = "interrupted";
          if (isVisibleJob(job)) {
            announceProgress("Connection interrupted — retrying.");
            $("progPhase").textContent = "Connection interrupted — retrying";
            $("reconnectJobBtn").textContent = "Retry now";
            $("reconnectJobBtn").classList.remove("hidden");
            setStatus("scanStatus", `Temporary problem reading job progress${err.status ? " (HTTP "
              + err.status + ")" : ""}: ${err.message}. Retrying in ${(delay / 1000).toFixed(1)}s; `
              + "the active job and queue are retained.", true);
          }
          schedulePoll(job, delay);
        } else {
          finishJob(job, "error", { error: `HTTP ${err.status || "error"}: ${err.message}` });
        }
      } finally {
        job.polling = false;
      }
    }

    function watchJob(jobId, meta) {
      if (!jobId) return null;
      _resultLoadGeneration++;
      _viewGeneration++;
      const job = ensureJob(jobId, meta || {});
      selectJob(job);
      if (!job.polling && !job.timer) pollJob(job);
      return jobId;
    }

    $("reconnectJobBtn").addEventListener("click", () => {
      const job = _activeJob;
      if (!job || job.polling) return;
      pauseWatcher(job);
      job.failures = 0;
      job.connectionState = "reconnecting";
      announceProgress("Reconnecting to scan job " + job.id + ".");
      setStatus("scanStatus", "Reconnecting to scan job " + job.id + "…", false);
      pollJob(job);
    });

    async function runQueueItem(item, reveal) {
      const viewGeneration = _viewGeneration;
      _postPending = true;
      updateScanButton();
      if (reveal) {
        document.title = "Celsius";
        setStatus("scanStatus", `Starting scan of ${item.target}…${queueNote()}`, false);
      }
      let jobId = null;
      try {
        const response = await C.api("/api/scan", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target: item.target, authorized: true, ...item.options }),
        });
        jobId = response.job_id;
        if (!jobId) throw new Error("The server did not return a scan job id.");
      } catch (err) {
        if (reveal && viewGeneration === _viewGeneration) {
          setStatus("scanStatus", "Could not start scan: " + err.message, true);
        }
        toast("Could not start the scan: " + err.message, "error");
      } finally {
        scrubOptions(item.options);
        _postPending = false;
        updateScanButton();
      }
      if (!jobId) {
        nextScan(reveal && viewGeneration === _viewGeneration);
        return;
      }

      const job = ensureJob(jobId, {
        target: item.target, preset: item.preset, queueOwned: true,
      });
      if (reveal && viewGeneration === _viewGeneration) {
        _viewGeneration++;
        $("target").value = item.target;
        clearResultViews();
        selectJob(job);
        setStatus("scanStatus", `Scanning ${item.target}…${queueNote()}`, false);
      }
      pollJob(job);
    }

    // Follow-up scans skip repeated apex-level recon but otherwise retain the
    // complete option snapshot taken when the hosts are queued.
    const FOLLOWUP_OVERRIDE = { subdomains: false, subdomain_bruteforce: false, topology: false };

    function nextScan(reveal) {
      if (_scanQueue.length) {
        runQueueItem(_scanQueue.shift(), !!reveal);
      } else {
        _scanning = false;
        updateScanButton();
      }
    }

    function queueItems(items) {
      const wasBusy = _scanning;
      _scanQueue.push(...items);
      if (!wasBusy) {
        _scanning = true;
        updateScanButton();
        nextScan(true);
      }
      return wasBusy;
    }

    function enqueueScans(targets) {
      const snapshot = currentScanOptions(), preset = presetLabel();
      const items = targets.map((target) => ({
        target, preset,
        options: normalizeOptions({
          ...snapshot, ...FOLLOWUP_OVERRIDE,
          auth_headers: [...(snapshot.auth_headers || [])],
        }),
      }));
      queueItems(items);
    }

    $("scanForm").addEventListener("submit", (e) => {
      e.preventDefault();
      if (!C.demandAuth()) return;
      const target = $("target").value.trim();
      const problem = targetProblem(target);
      if (problem) {
        showFieldError("target", problem);
        $("target").focus();
        return;
      }
      if ($("opt-exploit").checked && $("opt-attest").value.trim().length < 10) {
        toast("Lab mode needs an authorization attestation (≥10 characters) before active exploitation.", "error");
        $("labmode").open = true;
        $("opt-attest").focus();
        return;
      }
      const queued = queueItems([{ target, options: currentScanOptions(), preset: presetLabel() }]);
      if (queued) {
        setStatus("scanStatus", `Queued ${target}…${queueNote()}`, false);
        toast(`Queued ${target} — it will run next.`, "info");
      }
    });

    $("cancelBtn").addEventListener("click", async () => {
      const job = _activeJob;
      if (!job || job.cancelPending) return;
      job.cancelPending = true;
      updateCancelButton(job);
      try {
        await C.api("/api/scan/" + encodeURIComponent(job.id), { method: "DELETE" });
        if (!isVisibleJob(job)) return;
        toast("Cancelling scan…", "info");
        setStatus("scanStatus", "Cancellation requested; waiting for the current check to stop…", false);
      } catch (err) {
        if (!isVisibleJob(job)) return;
        job.cancelPending = false;
        updateCancelButton(job);
        if (err.status === 409) {
          toast("That scan already finished; refreshing its status.", "info");
          schedulePoll(job, 0);
        } else {
          toast("Could not cancel: " + err.message, "error");
        }
      }
    });

    function finishTitle(result) {
      const g = result && result.assessment && result.assessment.grade;
      document.title = "✓ Celsius — scan finished" + (g ? " · grade " + g : "");
    }
    window.addEventListener("focus", () => {
      if (document.title.startsWith("✓")) document.title = "Celsius";
    });

    C.watchJob = watchJob;
    C.scan = Object.assign(C.scan || {}, { watchJob });

    function hostOf(u) {
      try {
        if (!/^https?:\/\//.test(u)) {
          if (!u || u.startsWith("/")) return null;  // path or empty, not a host
          u = "http://" + u;
        }
        return new URL(u).hostname.toLowerCase();
      } catch (e) { return null; }
    }
    function originOf(u) {
      try { return /^https?:\/\//.test(u) ? new URL(u).origin : null; } catch (e) { return null; }
    }

    // Distinct discovered hosts (≠ the scanned host) referenced by this scan.
    // Discovery alone does not establish authorization or scope for follow-ups.
    function followupHosts(res) {
      const scanned = hostOf(res.url || res.target);
      const apex = scanned ? scanned.split(".").slice(-2).join(".") : null;
      const byHost = new Map();   // host -> target string (origin if known, else host)
      const recon = res.recon || {};
      ((recon.crawl || {}).endpoints || []).forEach((e) => {
        const h = hostOf(e);
        if (h && h !== scanned && !byHost.has(h)) byHost.set(h, originOf(e) || h);
      });
      (recon.subdomains || []).forEach((s) => {
        const h = (s || "").toLowerCase();
        if (h && h !== scanned && !byHost.has(h)) byHost.set(h, h);
      });
      // co-hosted siblings on the same IP (cert SANs + reverse-IP)
      ((recon.cohosted || {}).siblings || []).forEach((s) => {
        const h = (s || "").toLowerCase();
        if (h && h !== scanned && !byHost.has(h)) byHost.set(h, h);
      });
      // The target's OWN subdomains (same apex) are the most relevant follow-ups —
      // list them first so they're always visible, then unrelated co-hosted siblings.
      const sameSite = (h) => !!apex && (h === apex || h.endsWith("." + apex));
      return [...byHost.entries()]
        .sort((a, b) => (sameSite(b[0]) - sameSite(a[0])) || a[0].localeCompare(b[0]))
        .map((e) => e[1]);
    }

    const GRADE_VERDICT = {
      A: "Good overall posture — review the hardening opportunities below.",
      B: "Mostly fine, with a few things worth fixing.",
      C: "Several issues need your attention.",
      D: "Your site has serious issues that need attention.",
      F: "Critical issues found — act on these first.",
    };

    // Render a full scan result into a container. `scanDict._scanId` (set by
    // loadScan / renderResult) enables the export/report links.
    C.renderFindings = function (container, scanDict) {
      renderResultInto(container, scanDict, scanDict._scanId || null);
    };

    // Backwards-compatible wrapper: render into the Results view of the host tab.
    function renderResult(res, scanId, jobId) {
      if (scanId) res._scanId = scanId;
      _viewedJobId = jobId || null;
      C.state.currentScan = { id: scanId || null, jobId: jobId || null, result: res };
      C.renderFindings($("results"), res);
      if (C.charts && C.charts.render) C.charts.render(res); // charts row above the findings
      if (C.surface && C.surface.onScan) C.surface.onScan(res); // attack-surface toggle (Task 6)
    }

    // Loading a result never detaches an active job. Its later completion may
    // render only if the user has not switched to this stored/different result.
    C.loadScan = async function (scanIdOrDict) {
      const generation = ++_resultLoadGeneration;
      _viewGeneration++;
      _viewedJobId = null;
      try {
        let result, scanId = null;
        if (typeof scanIdOrDict === "string") {
          scanId = scanIdOrDict;
          result = await C.api("/api/scans/" + encodeURIComponent(scanId));
          if (generation !== _resultLoadGeneration) return false;
        } else {
          result = scanIdOrDict || {};
          scanId = result._scanId || result.scan_id || null;
        }
        if (generation !== _resultLoadGeneration) return false;
        C.showTab("host");
        setStatus("scanStatus", scanId ? "Loaded stored scan " + scanId : "Scan loaded.", false);
        renderResult(result, scanId);
        window.scrollTo({ top: 0, behavior: C.scrollBehavior() });
        return true;
      } catch (err) {
        if (generation !== _resultLoadGeneration) return false;
        toast("Could not open scan: " + err.message, "error");
        return false;
      }
    };

    const CONFIRMED_VERDICTS = new Set(["confirmed-exploitable", "confirmed-exposed"]);

    function confirmedByExploitability(item) {
      if (!item || item.category === "ai-hypothesis") return false;
      const ex = item.exploitability || {};
      const signals = ex.signals || {};
      return CONFIRMED_VERDICTS.has(ex.verdict) || signals.verified === true
        || (signals.actively_verified === true && signals.corroborated === true);
    }

    function targetVerified(item, kind) {
      return !!item && ((kind === "cve" && item.verified === true)
        || confirmedByExploitability(item));
    }

    function severityName(value) {
      const sev = String(value || "INFO").toUpperCase();
      return SEV_ORDER[sev] != null ? sev : "INFO";
    }

    function numberValue(value, fallback) {
      if (value == null || value === "") return fallback;
      const n = Number(value);
      return Number.isFinite(n) ? n : fallback;
    }

    function publishedTime(value) {
      if (!value) return -Infinity;
      const time = Date.parse(value);
      return isNaN(time) ? -Infinity : time;
    }

    // Interaction keys name source records; sorted/filter positions never identify items.
    function triageRecord(kind, item, sourceIndex) {
      const key = kind === "cve"
        ? String(item.id || `cve:${sourceIndex}`)
        : `finding:${sourceIndex}:${String(item.title || "")}`;
      return { kind, item, sourceIndex, key };
    }

    function triageRecordMap(records) {
      return new Map(records.map((r) => [r.key, r]));
    }

    function unconfirmedCve(item) {
      return !!item && item.confidence === "weak" && !targetVerified(item, "cve");
    }

    function cveRiskCompare(a, b) {
      const x = a.item, y = b.item;
      return Number(unconfirmedCve(x)) - Number(unconfirmedCve(y))
        || Number(targetVerified(y, "cve")) - Number(targetVerified(x, "cve"))
        || numberValue((y.exploitability || {}).priority, -1)
          - numberValue((x.exploitability || {}).priority, -1)
        || SEV_ORDER[severityName(y.severity)] - SEV_ORDER[severityName(x.severity)]
        || numberValue(y.cvss, -1) - numberValue(x.cvss, -1)
        || publishedTime(y.published) - publishedTime(x.published);
    }

    function compareCveRecords(a, b, sort) {
      let compared = 0;
      if (sort === "cvss") {
        compared = numberValue(b.item.cvss, -1) - numberValue(a.item.cvss, -1);
      } else if (sort === "newest") {
        compared = publishedTime(b.item.published) - publishedTime(a.item.published);
      }
      return compared || cveRiskCompare(a, b) || a.sourceIndex - b.sourceIndex;
    }

    function findingSeverityCompare(a, b) {
      return SEV_ORDER[severityName(b.item.severity)] - SEV_ORDER[severityName(a.item.severity)];
    }

    function findingPriorityCompare(a, b) {
      return numberValue((b.item.exploitability || {}).priority, -1)
        - numberValue((a.item.exploitability || {}).priority, -1);
    }

    function findingVerifiedCompare(a, b) {
      return Number(targetVerified(b.item, "finding")) - Number(targetVerified(a.item, "finding"));
    }

    function compareFindingRecords(a, b, sort) {
      let compared;
      if (sort === "severity") {
        compared = findingSeverityCompare(a, b) || findingPriorityCompare(a, b)
          || findingVerifiedCompare(a, b);
      } else if (sort === "priority") {
        compared = findingPriorityCompare(a, b) || findingVerifiedCompare(a, b)
          || findingSeverityCompare(a, b);
      } else {
        compared = findingVerifiedCompare(a, b) || findingPriorityCompare(a, b)
          || findingSeverityCompare(a, b);
      }
      return compared || String(a.item.title || "").localeCompare(String(b.item.title || ""))
        || a.sourceIndex - b.sourceIndex;
    }

    function matchesQuery(item, fields, query) {
      const q = query.trim().toLowerCase();
      return !q || fields.some((field) => String(item[field] || "").toLowerCase().includes(q));
    }

    function hasKev(item) {
      return !!((item.exploitability || {}).signals || {}).kev;
    }

    function hasPublicPoc(item) {
      const signals = (item.exploitability || {}).signals || {};
      return (item.references || []).some((r) => r && r.poc)
        || signals.public_poc === true || (signals.poc_urls || []).length > 0;
    }

    function cveMatches(record, state) {
      const c = record.item;
      if (!matchesQuery(c, ["id", "product", "affects", "description"], state.q)) return false;
      if (state.severity !== "all" && severityName(c.severity) !== state.severity) return false;
      const confidence = unconfirmedCve(c) ? "weak" : "firm";
      if (state.confidence !== "all" && confidence !== state.confidence) return false;
      if (state.evidence === "verified" && !targetVerified(c, "cve")) return false;
      if (state.evidence === "kev" && !hasKev(c)) return false;
      if (state.evidence === "poc" && !hasPublicPoc(c)) return false;
      return true;
    }

    function findingMatches(record, state) {
      const f = record.item;
      if (!matchesQuery(f, ["title", "category", "description", "evidence"], state.q)) return false;
      if (state.severity !== "all" && severityName(f.severity) !== state.severity) return false;
      if (state.category !== "all" && String(f.category || "") !== state.category) return false;
      if (state.verdict !== "all") {
        const verdict = (f.exploitability || {}).verdict || "__none__";
        if (verdict !== state.verdict) return false;
      }
      return true;
    }

    function triageOptions(options) {
      return options.map(([value, label]) =>
        `<option value="${esc(value)}">${esc(label)}</option>`).join("");
    }

    function triageField(id, label, control, extraClass) {
      return `<div class="triage-field${extraClass ? " " + extraClass : ""}">
        <label class="triage-label" for="${id}">${esc(label)}</label>${control}</div>`;
    }

    function severityOptions() {
      return [["all", "All"], ...["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        .map((s) => [s, s])];
    }

    function cveTriageHtml(records, firmN, weakN) {
      return `<h2 class="section">Known vulnerabilities — CVEs (${firmN}${weakN ? ` + ${weakN} unconfirmed` : ""})</h2>
        <div class="triage" data-triage-root="cve">
          <div class="triage-toolbar" role="group" aria-label="CVE triage filters">
            ${triageField("cveTriageSearch", "Search CVEs", `<input id="cveTriageSearch" type="search" data-filter="q" autocomplete="off" placeholder="ID, product, affects, description">`, "triage-search")}
            ${triageField("cveTriageSeverity", "Severity", `<select id="cveTriageSeverity" data-filter="severity">${triageOptions(severityOptions())}</select>`)}
            ${triageField("cveTriageConfidence", "Confidence", `<select id="cveTriageConfidence" data-filter="confidence">${triageOptions([["all", "All"], ["firm", "Firm"], ["weak", "Unconfirmed"]])}</select>`)}
            ${triageField("cveTriageEvidence", "Evidence", `<select id="cveTriageEvidence" data-filter="evidence">${triageOptions([["all", "All"], ["verified", "Verified"], ["kev", "CISA KEV"], ["poc", "Public PoC"]])}</select>`)}
            ${triageField("cveTriageSort", "Sort", `<select id="cveTriageSort" data-filter="sort">${triageOptions([["risk", "Risk"], ["cvss", "CVSS"], ["newest", "Newest publication"]])}</select>`)}
          </div>
          <div class="triage-list-meta">
            <output class="triage-count" data-triage-count aria-live="polite" aria-atomic="true">${records.length} of ${records.length}</output>
            <button type="button" class="triage-reset" data-triage-reset>Reset filters</button>
          </div>
          <div class="triage-list" data-triage-list></div>
        </div>`;
    }

    function findingTriageHtml(records) {
      const categories = [...new Set(records.map((r) => String(r.item.category || "")).filter(Boolean))]
        .sort((a, b) => a.localeCompare(b));
      const verdictOrder = ["confirmed-exploitable", "confirmed-exposed", "likely-exploitable",
        "conditions-needed", "needs-manual", "not-in-context", "unknown", "informational"];
      const presentVerdicts = new Set(records.map((r) => (r.item.exploitability || {}).verdict).filter(Boolean));
      const verdicts = verdictOrder.filter((v) => presentVerdicts.has(v));
      [...presentVerdicts].filter((v) => !verdictOrder.includes(v)).sort().forEach((v) => verdicts.push(v));
      const verdictOptions = [["all", "All"], ...verdicts.map((v) => [v, v.replace(/-/g, " ")])];
      if (records.some((r) => !(r.item.exploitability || {}).verdict)) {
        verdictOptions.push(["__none__", "No verdict"]);
      }
      return `<h2 class="section">Findings (${records.length})</h2>
        <div class="triage" data-triage-root="finding">
          <div class="triage-toolbar" role="group" aria-label="Finding triage filters">
            ${triageField("findingTriageSearch", "Search findings", `<input id="findingTriageSearch" type="search" data-filter="q" autocomplete="off" placeholder="Title, category, description, evidence">`, "triage-search")}
            ${triageField("findingTriageSeverity", "Severity", `<select id="findingTriageSeverity" data-filter="severity">${triageOptions(severityOptions())}</select>`)}
            ${triageField("findingTriageCategory", "Category", `<select id="findingTriageCategory" data-filter="category">${triageOptions([["all", "All"], ...categories.map((c) => [c, c])])}</select>`)}
            ${triageField("findingTriageVerdict", "Verdict", `<select id="findingTriageVerdict" data-filter="verdict">${triageOptions(verdictOptions)}</select>`)}
            ${triageField("findingTriageSort", "Sort", `<select id="findingTriageSort" data-filter="sort">${triageOptions([["risk", "Risk"], ["priority", "Priority"], ["severity", "Severity"]])}</select>`)}
          </div>
          <div class="triage-list-meta">
            <output class="triage-count" data-triage-count aria-live="polite" aria-atomic="true">${records.length} of ${records.length}</output>
            <button type="button" class="triage-reset" data-triage-reset>Reset filters</button>
          </div>
          <div class="triage-list" data-triage-list></div>
        </div>`;
    }

    function cveDescriptionHtml(description) {
      const desc = String(description || "");
      if (desc.length <= 240) return `<div class="desc">${esc(desc)}</div>`;
      return `<details class="cve-description">
        <summary><span class="cve-desc-preview">${esc(desc.slice(0, 240))}… </span>
          <span class="cve-desc-expand">Read full description</span>
          <span class="cve-desc-collapse">Show less</span></summary>
        <div class="desc cve-desc-full">${esc(desc)}</div>
      </details>`;
    }

    function publicationHtml(value) {
      if (!value) return "";
      const time = publishedTime(value);
      const label = time === -Infinity ? String(value) : new Date(time).toISOString().slice(0, 10);
      return ` · published <time datetime="${esc(value)}">${esc(label)}</time>`;
    }

    function cveCard(record) {
      const c = record.item;
      const sev = severityName(c.severity);
      const isVerified = targetVerified(c, "cve");
      const verified = isVerified ? ` <span class="verdict v-high">✔ VERIFIED</span>` : "";
      const weak = unconfirmedCve(c);
      const unconfirmed = weak
        ? ` <span class="verdict v-low" title="${esc(c.caveat || "")}">⚠ UNCONFIRMED</span>` : "";
      const caveatHtml = weak && c.caveat ? `<div class="meta">⚠ ${esc(c.caveat)}</div>` : "";
      const pocs = (c.references || []).filter((r) => r && r.poc).slice(0, 4);
      const pocHtml = pocs.length
        ? `<div class="meta">PoC: ${pocs.map((r) => `<a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(shortUrl(r.url))}</a>`).join(" · ")}</div>`
        : "";
      return `<article class="card triage-card ${weak ? "INFO weak" : sev}" data-kind="cve"
          data-triage-key="${esc(record.key)}" tabindex="-1" aria-label="CVE ${esc(c.id || "unknown")}">
        <div class="row">
          <span class="title"><span class="badge sev-${sev}">${sev}</span>
            <a href="${esc(c.url)}" target="_blank" rel="noopener">${esc(c.id)}</a>
            &nbsp;CVSS ${esc(c.cvss == null ? "-" : c.cvss)}${verdictBadge(c.exploitability)}${verified}${unconfirmed}</span>
          <button type="button" class="pocBtn" data-poc="${record.kind}" data-item-key="${esc(record.key)}">How to check</button>
        </div>
        <div class="meta">affects: ${esc(c.affects)}${publicationHtml(c.published)}${exploitMeta(c.exploitability)}</div>
        ${caveatHtml}${pocHtml}${cveDescriptionHtml(c.description)}
      </article>`;
    }

    function findingCard(record) {
      const f = record.item;
      const sev = severityName(f.severity);
      const category = String(f.category || "");
      const conf = f.confidence ? ` <span class="conf">confidence: ${esc(f.confidence)}</span>` : "";
      const aiTag = category.startsWith("ai") ? ' <span class="ai-tag">AI</span>' : "";
      const ex = f.exploitability || {};
      const signals = ex.signals || {};
      const whyBits = [];
      if (ex.verdict && ex.verdict !== "informational") {
        whyBits.push(`Exploitability: ${String(ex.verdict).replace(/-/g, " ")}.`);
      }
      const epss = numberValue(signals.epss, null);
      if (epss != null) whyBits.push(`EPSS score ${epss.toFixed(3)} (exploit probability).`);
      if (signals.kev) whyBits.push("Listed in CISA's Known Exploited Vulnerabilities catalog.");
      whyBits.push(WHY[sev] || WHY.INFO);
      const fixInner = (f.recommendation ? `<p>${esc(f.recommendation)}</p>` : "") + fixContent(ex);
      return `<article class="card triage-card ${sev}" data-kind="finding"
          data-triage-key="${esc(record.key)}" tabindex="-1" aria-label="Finding: ${esc(f.title || "untitled")}">
        <div class="row">
          <span class="title"><span class="badge sev-${sev}">${sev}</span> ${esc(f.title)}${aiTag}${verdictBadge(ex)}</span>
          <button type="button" class="pocBtn" data-poc="${record.kind}" data-item-key="${esc(record.key)}">How to check</button>
        </div>
        <div class="meta">[${esc(category)}]${conf}</div>
        <div class="f-secs">
          <details class="f-sec"><summary>What is this?</summary>
            <div class="desc">${esc(f.description)}</div>
            ${f.evidence ? `<div class="meta">evidence: ${esc(f.evidence)}</div>` : ""}
          </details>
          <details class="f-sec"><summary>Why it matters</summary><p>${esc(whyBits.join(" "))}</p></details>
          ${fixInner ? `<details class="f-sec"><summary>How to fix</summary>${fixInner}</details>` : ""}
        </div>
      </article>`;
    }

    function wirePocButtons(container, kind, recordsByKey) {
      container.addEventListener("click", (e) => {
        const button = e.target.closest(".pocBtn");
        if (!button || !container.contains(button)) return;
        const record = recordsByKey.get(button.dataset.itemKey);
        if (record) showPoc(kind, record.item, record.item.exploitability, button);
      });
    }

    function createTriage(resultsEl, kind, records, defaults, matches, compare, card, emptyHtml) {
      const root = resultsEl.querySelector(`[data-triage-root="${kind}"]`);
      const list = root.querySelector("[data-triage-list]");
      const count = root.querySelector("[data-triage-count]");
      const controls = [...root.querySelectorAll("[data-filter]")];
      const state = { ...defaults };

      function render() {
        const visible = records.filter((r) => matches(r, state))
          .sort((a, b) => compare(a, b, state.sort));
        count.textContent = `${visible.length} of ${records.length}`;
        if (visible.length) {
          list.innerHTML = visible.map((r) => card(r)).join("");
        } else if (records.length) {
          const noun = kind === "cve" ? "CVEs" : "findings";
          list.innerHTML = `<div class="empty triage-empty">
            <div><strong>No ${noun} match these filters.</strong>
              <div class="triage-empty-hint">Try a broader search or change the filter combination.</div></div>
            <button type="button" class="triage-empty-reset" data-triage-reset>Reset filters</button>
          </div>`;
        } else {
          list.innerHTML = emptyHtml;
        }
      }

      function reset() {
        Object.assign(state, defaults);
        controls.forEach((control) => { control.value = state[control.dataset.filter]; });
        render();
      }

      root.addEventListener("input", (e) => {
        if (!e.target.matches('input[type="search"][data-filter]')) return;
        state[e.target.dataset.filter] = e.target.value;
        render();
      });
      root.addEventListener("change", (e) => {
        if (!e.target.matches("select[data-filter]")) return;
        state[e.target.dataset.filter] = e.target.value;
        render();
      });
      root.addEventListener("click", (e) => {
        const button = e.target.closest("[data-triage-reset]");
        if (button && root.contains(button)) reset();
      });
      wirePocButtons(root, kind, triageRecordMap(records));
      render();

      return {
        reset,
        reveal(key) {
          reset();
          const cardEl = [...list.querySelectorAll(".triage-card")]
            .find((el) => el.dataset.triageKey === key);
          if (!cardEl) return;
          cardEl.focus({ preventScroll: true });
          cardEl.scrollIntoView({ block: "center", behavior: C.scrollBehavior() });
          cardEl.classList.add("triage-jump");
          setTimeout(() => cardEl.classList.remove("triage-jump"), 1800);
        },
      };
    }

    function coverageSummaryHtml(res) {
      const cov = res.coverage || {};
      const run = Array.isArray(cov.checks_run) ? cov.checks_run : [];
      const skipped = Array.isArray(cov.checks_skipped) ? cov.checks_skipped : [];
      const errors = (res.errors || []).map((e) => String(e));
      const authWarning = errors.find((e) => e.startsWith("AUTH_FALLBACK:"));
      const disabledNotes = errors.filter((e) => /: skipped \(/i.test(e));
      const infoNotes = errors.filter((e) => /^note:/i.test(e));
      const failures = errors.filter((e) => e !== authWarning
        && !disabledNotes.includes(e) && !infoNotes.includes(e));
      const unverified = numberValue(cov.unverified_findings,
        (res.findings || []).filter((f) => ["unknown", "conditions-needed"]
          .includes((f.exploitability || {}).verdict)).length);
      const aiUnconfirmed = numberValue(cov.ai_unconfirmed,
        (res.findings || []).filter((f) => f.category === "ai-hypothesis").length);
      const hasCoverage = Object.prototype.hasOwnProperty.call(cov, "checks_run")
        || Object.prototype.hasOwnProperty.call(cov, "checks_skipped");
      const chips = [];
      if (hasCoverage) {
        chips.push(`<span><strong>${run.length}</strong> checks ran</span>`);
        chips.push(`<span><strong>${skipped.length}</strong> intentionally disabled</span>`);
      } else {
        chips.push("<span>Coverage details not recorded</span>");
      }
      if (unverified) chips.push(`<span><strong>${unverified}</strong> unverified findings</span>`);
      if (aiUnconfirmed) chips.push(`<span><strong>${aiUnconfirmed}</strong> unconfirmed AI leads</span>`);
      if (errors.length) chips.push(`<span><strong>${errors.length}</strong> scan notes</span>`);
      if (failures.length) chips.push(`<span class="coverage-error-count"><strong>${failures.length}</strong> check errors</span>`);

      const groups = [];
      if (run.length) {
        groups.push(`<div class="coverage-group"><strong>Checks that ran (${run.length})</strong>
          <p>${esc(run.join(" · "))}</p></div>`);
      }
      if (skipped.length) {
        groups.push(`<div class="coverage-group"><strong>Intentionally disabled by scan options (${skipped.length})</strong>
          <p>${esc(skipped.join(" · "))}</p><p>These checks were not enabled; this is not a tool failure.</p></div>`);
      }
      if (disabledNotes.length) {
        groups.push(`<div class="coverage-group"><strong>Skipped by scan mode or scope</strong>
          <ul>${disabledNotes.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>
          <p>These are coverage limits, separate from check errors.</p></div>`);
      }
      if (failures.length) {
        groups.push(`<div class="coverage-group coverage-errors"><strong>Check errors (${failures.length})</strong>
          <ul>${failures.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></div>`);
      }
      if (infoNotes.length) {
        groups.push(`<div class="coverage-group"><strong>Informational notes</strong>
          <ul>${infoNotes.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></div>`);
      }
      if (unverified || aiUnconfirmed) {
        groups.push(`<div class="coverage-group"><strong>Confidence limits</strong><p>
          ${unverified ? `${unverified} finding(s) still need verification. ` : ""}
          ${aiUnconfirmed ? `${aiUnconfirmed} AI hypothesis(es) are leads, not confirmed issues.` : ""}
          </p></div>`);
      }
      const nextSteps = Array.isArray(cov.next_steps) ? cov.next_steps : [];
      if (nextSteps.length) {
        groups.push(`<div class="coverage-group"><strong>Want deeper coverage?</strong>
          <ul class="coverage-list">${nextSteps.map((s) => `<li>${esc(s)}</li>`).join("")}</ul></div>`);
      }
      const authHtml = authWarning
        ? `<div class="auth-fallback-banner" role="alert"><strong>Unauthenticated scan.</strong>
            ${esc(authWarning.slice("AUTH_FALLBACK:".length).trim())}</div>` : "";
      return `<section class="coverage-summary${authWarning ? " has-auth-warning" : ""}${failures.length ? " has-errors" : ""}"
          aria-label="Scan coverage and confidence">
        <div class="coverage-head"><strong>Coverage &amp; confidence</strong>
          <div class="coverage-chips">${chips.join("")}</div></div>
        ${authHtml}
        <details class="coverage-details"><summary>Review checks, skipped coverage, notes and next steps</summary>
          ${groups.length ? groups.join("") : "<p>No additional coverage notes.</p>"}
        </details>
      </section>`;
    }

    function renderResultInto(resultsEl, res, scanId) {
      lastUrl = res.url || res.target;
      const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
      // Unconfirmed CVEs stay out of headline counts; legacy verified weak records
      // count normally because target confirmation supersedes their old confidence label.
      let weakCount = 0;
      (res.cves || []).forEach((c) => {
        if (unconfirmedCve(c)) weakCount++;
        else counts[severityName(c.severity)]++;
      });
      // AI hypotheses are leads, not facts — kept out of the headline severity too.
      let aiCount = 0;
      (res.findings || []).forEach((f) => {
        if (f.category === "ai-hypothesis") aiCount++;
        else counts[severityName(f.severity)]++;
      });

      const scannedHost = hostOf(res.url || res.target) || "";
      const apex = scannedHost.split(".").slice(-2).join(".");
      const a = res.assessment;
      const gradeLetter = a && a.grade ? a.grade : "C";
      const g0 = gradeLetter[0];

      const cveRecords = (res.cves || []).map((c, i) => triageRecord("cve", c, i));
      const findingRecords = (res.findings || []).map((f, i) => triageRecord("finding", f, i));
      const realFindingRecords = findingRecords.filter((r) => r.item.category !== "ai-hypothesis");
      const aiFindingRecords = findingRecords.filter((r) => r.item.category === "ai-hypothesis");

      let html = "";

      // ---- hero: grade + score + verdict + donut ----
      const chips = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        .filter((s) => counts[s] > 0)
        .map((s) => `<span class="chip sev-${s}">${s} ${counts[s]}</span>`).join("")
        + (weakCount ? `<span class="chip sev-UNCONFIRMED" title="Reported but not confirmed — verify before acting">Unconfirmed ${weakCount}</span>` : "")
        + (aiCount ? `<span class="chip sev-AILEADS" title="AI hypotheses — unverified leads, not counted in severity">AI leads ${aiCount}</span>` : "");
      const verdict = a && a.clean
        ? "No confident issues found in the checks that ran."
        : (GRADE_VERDICT[g0] || "Review the issues below.");
      html += `<div class="hero grade-${esc(g0)}">
        <div class="hero-grade">${esc(gradeLetter)}</div>
        <div class="hero-body">
          <div class="hero-score"><strong>${a ? esc(a.score) : "–"}</strong>/100</div>
          <div class="hero-verdict">${esc(verdict)}</div>
          <div class="hero-target">${esc(res.target)} · ${esc(res.url || "-")} · ${esc(res.ip || "-")}</div>
          <div class="hero-counts">${chips}</div>
        </div>
        ${donutSVG(counts)}
      </div>`;
      html += coverageSummaryHtml(res);

      // ---- "fix these first" action list ----
      if (a && !a.clean && (a.fix_first || []).length) {
        const items = a.fix_first.map((it) => {
          const kind = it.kind === "finding" ? "finding" : "cve";
          const title = String(it.title || "");
          const records = kind === "cve" ? cveRecords : realFindingRecords;
          const candidates = records
            .filter((r) => String(kind === "cve" ? r.item.id : r.item.title) === title);
          const sev = severityName(it.severity);
          const record = Number.isInteger(it.source_index)
            ? records.find((r) => r.sourceIndex === it.source_index)
            : candidates.find((r) => severityName(r.item.severity) === sev) || candidates[0];
          const content = `<span class="badge sev-${sev}">${sev}</span>${it.verified ? ' <span class="verdict v-high">✔ verified</span>' : ""}
            <strong>${esc(it.title)}</strong>${it.why ? `<span class="hc-why"> — ${esc(it.why)}</span>` : ""}${it.fix ? `<span class="hc-fix">Fix: ${esc(it.fix)}</span>` : ""}`;
          if (!record) return `<li><span class="fix-jump-static">${content}</span></li>`;
          return `<li><button type="button" class="fix-jump" data-fix-kind="${record.kind}"
            data-fix-key="${esc(record.key)}">${content}</button></li>`;
        }).join("");
        const more = a.total_actionable > a.fix_first.length
          ? `<div class="hc-more">+${esc(a.total_actionable - a.fix_first.length)} more below</div>` : "";
        html += `<div class="fixfirst"><h3>Fix these first</h3><ol class="fixfirst-list">${items}</ol>${more}</div>`;
      }

      // ---- AI security advisor — grounded, plain-language action plan ----
      const adv = (res.recon || {}).advisor;
      if (adv && (adv.headline || (adv.steps || []).length)) {
        const steps = (adv.steps || []).map((s) => {
          const sev = severityName(s.severity);
          return `<li>
            <span class="badge sev-${sev}">${sev}</span>
            <strong>${esc(s.title || "")}</strong>${s.effort ? ` <span class="adv-effort">${esc(s.effort)}</span>` : ""}
            ${s.why ? `<div class="adv-why">${esc(s.why)}</div>` : ""}
            ${s.fix ? `<div class="adv-fix"><code>${esc(s.fix)}</code></div>` : ""}</li>`;
        }).join("");
        const well = (adv.doing_well || []).length
          ? `<div class="adv-well"><strong>Already doing well:</strong> ${(adv.doing_well).map(esc).join(" · ")}</div>` : "";
        html += `<div class="advisor">
            <div class="adv-head">Your action plan <span class="adv-tag">AI advisor</span></div>
            ${adv.headline ? `<p class="adv-headline">${esc(adv.headline)}</p>` : ""}
            ${steps ? `<ol class="adv-list">${steps}</ol>` : ""}
            ${well}</div>`;
      }

      // ---- exploit chains ----
      const chains = res.chains || [];
      if (chains.length) {
        html += `<h2 class="section">Exploit chains (${chains.length})
          <span class="section-sub">How separate issues combine into real attack paths</span></h2>`;
        chains.forEach((ch) => {
          const sev = severityName(ch.severity);
          html += `<div class="card ${sev}">
            <div class="row"><span class="title"><span class="badge sev-${sev}">${sev}</span> ${esc(ch.title)}</span>
              <span class="meta">priority ${esc(ch.priority)}</span></div>
            <div class="meta">path: ${(ch.nodes || []).map(esc).join(" → ")}</div>
            <div class="desc">${esc(ch.narrative)}</div>
            <div class="fix">↳ ${esc(ch.recommendation)}</div>
          </div>`;
        });
      }

      // ---- attack surface: clean grid of summary cards ----
      const recon = res.recon || {};
      const minis = [];
      if (recon.tech && recon.tech.length) {
        minis.push(`<div class="mini"><h5>Technologies</h5><p>${recon.tech.map((t) =>
          esc(t.name + (t.version ? " " + t.version : ""))).join(" · ")}</p>
          <p class="mono">${esc([...new Set(recon.tech.map((t) => t.category))].join(" · "))}</p></div>`);
      }
      if (recon.tls && recon.tls.protocol) {
        const t = recon.tls;
        minis.push(`<div class="mini"><h5>HTTPS / TLS</h5><p>${esc(t.protocol)} · ${esc(t.cipher || "")}</p>
          <p class="mono">issuer: ${esc(t.issuer || "?")} · expires in ${t.days_to_expiry != null ? t.days_to_expiry + " days" : "?"}</p></div>`);
      }
      if (recon.dns && recon.dns.records) {
        const r = recon.dns.records;
        const line = ["A", "AAAA", "MX", "NS"].filter((k) => r[k]).map((k) => `${k}: ${r[k].slice(0, 3).join(", ")}`).join(" · ");
        minis.push(`<div class="mini"><h5>DNS</h5><p class="mono">${esc(line)}</p></div>`);
      }
      if (recon.subdomains && recon.subdomains.length) {
        minis.push(`<div class="mini"><h5>Subdomains (${recon.subdomains.length})</h5>
          <p class="mono">${recon.subdomains.slice(0, 12).map(esc).join(", ")}${recon.subdomains.length > 12 ? " …" : ""}</p></div>`);
      }
      if (recon.crawl) {
        const c = recon.crawl;
        minis.push(`<div class="mini"><h5>Crawl</h5><p>${c.pages} page(s) · ${c.js_files} JS file(s) ·
          ${(c.endpoints || []).length} endpoint(s) · ${(c.routes || []).length} route(s)${c.recovered_sources ? " · " + c.recovered_sources + " recovered source(s)" : ""}</p></div>`);
      }
      if (recon.api && (recon.api.openapi || recon.api.graphql)) {
        const ap = recon.api, bits = [];
        if (ap.openapi) bits.push(`OpenAPI: ${esc(ap.openapi.url)} (${(ap.openapi.paths || []).length} paths)`);
        if (ap.graphql) bits.push(`GraphQL introspection: ${esc(ap.graphql.url)} (${ap.graphql.types} types)`);
        minis.push(`<div class="mini"><h5>API</h5><p class="mono">${bits.join("<br>")}</p></div>`);
      }
      if (recon.origin_exposure) {
        const oe = recon.origin_exposure;
        const lines = [`behind <strong>${esc(oe.cdn || "a CDN")}</strong>`];
        (oe.exposed || []).forEach((e) =>
          lines.push(`possible origin: <strong>${esc(e.host)}</strong> → ${esc((e.origin_ips || []).join(", "))}`));
        (oe.verified || []).forEach((v) =>
          lines.push(`origin IP <strong>${esc(v.ip)}</strong>${v.matched ? " ✓ confirmed" : ""}${v.server ? " · Server: " + esc(v.server) : ""}`));
        const pivots = (oe.pivots || []).map((p) =>
          `<a href="${esc(p.url)}" target="_blank" rel="noopener">${esc(p.engine)}: ${esc(p.label || p.query)}</a>`).join(" · ");
        minis.push(`<div class="mini"><h5>Origin / exposure</h5><p>${lines.join(" · ")}</p>
          ${pivots ? `<p class="mono">Origin hunt: ${pivots}</p>` : ""}</div>`);
      }
      if (recon.os && recon.os.best_match) {
        const o = recon.os;
        const alt = (o.matches || []).slice(1, 4).map((m) => `${esc(m.name)} (${m.accuracy}%)`).join(" · ");
        minis.push(`<div class="mini"><h5>OS / device</h5><p>${esc(o.best_match)} · ${o.best_accuracy}% match</p>
          <p class="mono">type: ${esc((o.device_types || []).join(", ") || "?")} · vendor: ${esc((o.vendors || []).join(", ") || "?")}${alt ? "<br>other guesses: " + alt : ""}</p></div>`);
      }
      if (recon.topology && recon.topology.hosts && recon.topology.hosts.length) {
        const ICON = { home: "🏠", vps: "☁️", saas: "📦", cdn: "🌐", unknown: "❔" };
        const KIND = { home: "home self-host", vps: "VPS/datacenter", saas: "managed SaaS", cdn: "CDN/edge", unknown: "unknown" };
        const rows = recon.topology.hosts.map((h) => {
          const subs = (h.hostnames || []).map((n) => (n.indexOf(":") >= 0 || /^[\d.]+$/.test(n)) ? n : n.split(".")[0]);
          const loc = h.org || h.isp || "?";
          const ports = (h.ports || []).length ? " · ports " + h.ports.join(", ") : "";
          const ptr = h.ptr ? " · PTR " + esc(h.ptr) : "";
          return `<p class="mono">${ICON[h.kind] || "❔"} <strong>${esc(h.ip)}</strong> [${esc(KIND[h.kind] || h.kind)}] ${esc(loc)}${h.asn ? " " + esc(h.asn) : ""}${ptr}${ports}`
            + `<br>${esc(subs.slice(0, 12).join(", "))}${subs.length > 12 ? " …" : ""}</p>`;
        }).join("");
        minis.push(`<div class="mini"><h5>Infrastructure (${recon.topology.n_hosts} host(s))</h5>${rows}</div>`);
      }
      if (minis.length) {
        html += `<h2 class="section">Attack surface</h2><div class="grid">${minis.join("")}</div>`;
      }

      // ---- services table ----
      html += `<h2 class="section">Detected services (${(res.services || []).length})</h2>`;
      if ((res.services || []).length) {
        html += `<div class="tablewrap"><table class="svc">
          <caption class="visually-hidden">Detected services for ${esc(res.target || "this scan")}</caption>
          <thead><tr><th scope="col">Product</th><th scope="col">Version</th>
            <th scope="col">Port</th><th scope="col">Source</th></tr></thead><tbody>`;
        res.services.forEach((s) => {
          html += `<tr><td>${esc(s.name)}</td><td>${esc(s.version || "?")}</td>
            <td class="mono">${esc(s.port || "")}</td><td>${esc(s.source)}</td></tr>`;
        });
        html += `</tbody></table></div>`;
      } else html += `<p class="empty">None detected.</p>`;

      // ---- independently filterable CVE and finding lists ----
      const firmN = cveRecords.filter((r) => !unconfirmedCve(r.item)).length;
      const weakN = cveRecords.length - firmN;
      html += cveTriageHtml(cveRecords, firmN, weakN);
      html += findingTriageHtml(realFindingRecords);

      // AI hypotheses stay outside the finding filters and headline totals.
      if (aiFindingRecords.length) {
        const aiSorted = aiFindingRecords.slice().sort((a, b) =>
          findingSeverityCompare(a, b) || a.sourceIndex - b.sourceIndex);
        html += `<div class="ai-section" data-ai-hypotheses>
          <h2 class="section">AI hypotheses (${aiSorted.length})</h2>
          <p class="ai-disclaimer">Unverified leads generated by an AI model — not counted in the severity
            totals. Verify each one before trusting or acting on it.</p>
          ${aiSorted.map((r) => findingCard(r)).join("")}</div>`;
      }

      // ---- follow-up: discovered hosts whose authorization/scope is unverified ----
      const followup = followupHosts(res);
      if (followup.length) {
        html += `<h2 class="section">Discovered hosts — scan them too? (${followup.length})</h2>`;
        html += `<div class="card INFO followup">
          <p class="note">Hosts discovered by this scan; their authorization and scope are not verified.
            Select only hosts you are authorized to test. Each queued scan uses a snapshot of the current options.</p>
          <div class="fu-list">${followup.slice(0, 50).map((t) =>
            `<label class="fu-item"><input type="checkbox" class="fu-chk" value="${esc(t)}"> ${esc(t)}</label>`).join("")}
          </div>${followup.length > 50 ? `<p class="note">… and ${followup.length - 50} more (not shown)</p>` : ""}
          <div class="fu-actions">
            <button type="button" id="fuAll" class="btn-secondary">Select all</button>
            <button type="button" id="fuScan" class="btn-primary">Scan selected</button>
          </div>
        </div>`;
      }

      // ---- meta footer: duration and exports ----
      let dur = "";
      if (res.started_at && res.finished_at) {
        const s = Date.parse(res.started_at), f = Date.parse(res.finished_at);
        if (!isNaN(s) && !isNaN(f) && f >= s) dur = fmtElapsed((f - s) / 1000);
      }
      const exp = [];
      if (scanId) {
        exp.push(`<a class="reportlink" href="${withToken(`/api/scans/${encodeURIComponent(scanId)}/report.html`)}" target="_blank">HTML report</a>`);
        ["json", "md", "sarif", "html"].forEach((fmt) => {
          exp.push(`<a class="reportlink" href="${withToken(`/api/scans/${encodeURIComponent(scanId)}/export.${fmt}`)}" download>Download .${fmt}</a>`);
        });
      }
      if (apex) {
        exp.push(`<a class="reportlink" href="${withToken(`/api/domain/${encodeURIComponent(apex)}/report.html`)}" target="_blank" title="Aggregated report across ${esc(apex)} and its scanned subdomains">Domain report (${esc(apex)})</a>`);
        exp.push(`<a class="reportlink" href="${withToken(`/api/domain/${encodeURIComponent(apex)}/report.zip`)}" download title="Domain overview + a report for every scanned subdomain">Domain bundle (.zip)</a>`);
      }
      html += `<div class="metafoot">
        <div class="metafoot-line">Scanned ${esc(res.finished_at || "")}${dur ? ` · took ${dur}` : ""}${scanId ? ` · scan ${esc(scanId)}` : ""}</div>
        ${exp.length ? `<h5>Export</h5><div class="exports">${exp.join("")}</div>` : ""}
      </div>`;

      resultsEl.innerHTML = html;
      const cveTriage = createTriage(
        resultsEl, "cve", cveRecords,
        { q: "", severity: "all", confidence: "all", evidence: "all", sort: "risk" },
        cveMatches, compareCveRecords, cveCard,
        `<p class="empty empty-good">✓ No known CVEs for the detected versions.</p>`);
      const findingTriage = createTriage(
        resultsEl, "finding", realFindingRecords,
        { q: "", severity: "all", category: "all", verdict: "all", sort: "risk" },
        findingMatches, compareFindingRecords, findingCard,
        `<p class="empty empty-good">✓ No findings — nice work.</p>`);

      const aiRoot = resultsEl.querySelector("[data-ai-hypotheses]");
      if (aiRoot) wirePocButtons(aiRoot, "finding", triageRecordMap(aiFindingRecords));

      resultsEl.querySelectorAll(".fix-jump").forEach((button) => {
        button.addEventListener("click", () => {
          const triage = button.dataset.fixKind === "cve" ? cveTriage : findingTriage;
          triage.reveal(button.dataset.fixKey);
        });
      });

      // wire follow-up scan controls
      const fuScan = $("fuScan");
      if (fuScan) {
        $("fuAll").addEventListener("click", () => {
          const boxes = [...resultsEl.querySelectorAll(".fu-chk")];
          const turnOn = boxes.some((b) => !b.checked);
          boxes.forEach((b) => (b.checked = turnOn));
        });
        fuScan.addEventListener("click", () => {
          if (!C.demandAuth()) return;
          const sel = [...resultsEl.querySelectorAll(".fu-chk:checked")].map((b) => b.value);
          if (!sel.length) { toast("Select at least one host first.", "info"); return; }
          enqueueScans(sel);
          setStatus("scanStatus", `Queued ${sel.length} follow-up scan(s)…${queueNote()}`, false);
          toast(`Queued ${sel.length} follow-up scan(s).`, "info");
        });
      }
    }

    // ---- PoC modal -----------------------------------------------------------------
    let _pocReturnFocus = null;
    let _pocGeneration = 0;
    let _pocController = null;
    const _pocBackground = new Map();
    const _pocTriggers = new WeakMap();

    function setPocBackgroundInert(inert) {
      if (inert) {
        if (_pocBackground.size) return;
        [...document.body.children].forEach((el) => {
          if (el.id === "pocModal" || el.tagName === "SCRIPT") return;
          _pocBackground.set(el, el.inert);
          el.inert = true;
        });
      } else {
        _pocBackground.forEach((wasInert, el) => { el.inert = wasInert; });
        _pocBackground.clear();
      }
    }

    // Modal open/close with focus management: trap Tab inside the dialog, close on
    // Escape or backdrop click, and restore focus to whatever opened it.
    function openModal() {
      const modal = $("pocModal");
      if (modal.classList.contains("hidden")) {
        _pocReturnFocus = document.activeElement;
        setPocBackgroundInert(true);
      }
      modal.classList.remove("hidden");
      modal.setAttribute("aria-hidden", "false");
      $("pocClose").focus();
    }
    function closeModal() {
      const modal = $("pocModal");
      if (modal.classList.contains("hidden")) return;
      _pocGeneration++;
      if (_pocController) {
        _pocController.abort();
        _pocController = null;
      }
      $("pocContent").setAttribute("aria-busy", "false");
      modal.classList.add("hidden");
      modal.setAttribute("aria-hidden", "true");
      setPocBackgroundInert(false);
      const returnFocus = _pocReturnFocus;
      _pocReturnFocus = null;
      if (returnFocus && returnFocus.isConnected) {
        const target = returnFocus.disabled ? returnFocus.closest(".triage-card") : returnFocus;
        if (target && target.focus) target.focus({ preventScroll: true });
      }
    }
    $("pocClose").addEventListener("click", closeModal);
    $("pocModal").addEventListener("click", (e) => {
      if (e.target.id === "pocModal") closeModal();
    });
    // Escape closes from anywhere while the modal is open — clicking non-interactive
    // PoC text moves focus to <body>, so a modal-scoped listener would miss it.
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !$("pocModal").classList.contains("hidden")) closeModal();
    });
    // Tab focus-trap stays scoped to the modal.
    $("pocModal").addEventListener("keydown", (e) => {
      if (e.key !== "Tab") return;
      const focusable = [...$("pocModal").querySelectorAll(
        'button, a[href], input, textarea, select, [tabindex]:not([tabindex="-1"])')]
        .filter((el) => !el.disabled && el.getClientRects().length);
      if (!focusable.length) return;
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });

    async function showPoc(kind, data, exploit, trigger) {
      const generation = ++_pocGeneration;
      if (_pocController) _pocController.abort();
      const controller = new AbortController();
      _pocController = controller;
      const content = $("pocContent");
      content.setAttribute("aria-busy", "true");
      content.innerHTML = `<h2 id="pocTitle">Loading reproduction steps…</h2>
        <p class="poc-loading" role="status">Loading reproduction steps…</p>`;
      openModal();
      const oldLabel = trigger ? trigger.textContent : "";
      if (trigger) {
        _pocTriggers.set(trigger, generation);
        trigger.disabled = true;
        trigger.setAttribute("aria-busy", "true");
        trigger.textContent = "Loading…";
      }
      try {
        const box = await C.api("/api/poc", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ kind, data, url: lastUrl }), signal: controller.signal,
        });
        if (generation !== _pocGeneration) return;
        if (!box || !Array.isArray(box.steps)) {
          throw new Error("The server returned invalid reproduction steps.");
        }
        let html = `<h2 id="pocTitle">${esc(box.title || "Proof of concept")}</h2>`;
        if (exploit && exploit.verdict) {
          html += `<div class="poc-verdict">Exploitability: ${verdictBadge(exploit)}${exploitMeta(exploit)}</div>`;
          if (exploit.howto && exploit.howto.length) {
            html += `<h3>How to check if exploitable</h3><ol class="poc-steps">`;
            exploit.howto.forEach((s) => { html += `<li>${esc(s)}</li>`; });
            html += `</ol>`;
          }
        }
        html += `<h3>Reproduction</h3><ol class="poc-steps">`;
        box.steps.forEach((s) => { html += `<li>${esc(s)}</li>`; });
        html += `</ol>`;
        if (box.note) html += `<div class="poc-note">⚠ ${esc(box.note)}</div>`;
        if (Array.isArray(box.references) && box.references.length) {
          html += `<div class="poc-refs"><strong>References</strong>`;
          box.references.forEach((u) => {
            html += `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a>`;
          });
          html += `</div>`;
        }
        if (generation !== _pocGeneration) return;
        content.innerHTML = html;
      } catch (err) {
        if (generation !== _pocGeneration) return;
        content.innerHTML = `<h2 id="pocTitle">Reproduction steps unavailable</h2>
          <p class="poc-error" role="alert">Could not load the reproduction steps: ${esc(err.message)}</p>`;
        toast("Could not load the reproduction steps: " + err.message, "error");
      } finally {
        if (generation === _pocGeneration) {
          content.setAttribute("aria-busy", "false");
          if (_pocController === controller) _pocController = null;
        }
        if (trigger && trigger.isConnected && _pocTriggers.get(trigger) === generation) {
          trigger.disabled = false;
          trigger.removeAttribute("aria-busy");
          trigger.textContent = oldLabel;
          _pocTriggers.delete(trigger);
        }
      }
    }

    // ---- history ---------------------------------------------------------------------
    const HIST_LIMIT = 20;
    let histOffset = 0;

    async function loadHistory(reset) {
      if (reset) histOffset = 0;
      const filter = $("historyFilter").value.trim();
      const params = new URLSearchParams({ limit: String(HIST_LIMIT), offset: String(histOffset) });
      if (filter) params.set("target", filter);
      try {
        const r = await fetch("/api/scans?" + params.toString());
        const { scans } = await r.json();
        if (!scans.length) {
          $("historyList").innerHTML = histOffset > 0
            ? `<p class="empty">No more scans.</p>`
            : `<p class="empty">${filter ? "No scans match “" + esc(filter) + "”." : "No scans recorded yet — run your first scan."}</p>`;
          $("historyPager").classList.toggle("hidden", histOffset === 0);
          $("histPrev").disabled = histOffset === 0;
          $("histNext").disabled = true;
          $("histPageInfo").textContent = "";
          return;
        }
        let html = `<div class="tablewrap"><table class="svc" id="historyTable" aria-label="Scan history">
          <caption class="visually-hidden">Stored scan history, with actions for each scan</caption>
          <thead><tr><th scope="col">When</th><th scope="col">Target</th><th scope="col">Grade</th>
            <th scope="col">Worst</th><th scope="col">CVEs</th><th scope="col">Findings</th>
            <th scope="col">Actions</th></tr></thead><tbody>`;
        scans.forEach((s) => {
          const sev = s.worst && s.worst !== "NONE" ? s.worst : "INFO";
          const grade = s.grade ? `<span class="grade-badge grade-${esc(s.grade[0])}">${esc(s.grade)}</span>` : "—";
          const id = esc(s.id);
          html += `<tr data-history-row="${id}">
            <td class="mono history-when" data-label="When">${esc((s.finished_at || s.started_at || "-").replace("T", " ").slice(0, 19))}</td>
            <td class="history-target" data-label="Target">${esc(s.target)}</td>
            <td data-label="Grade">${grade}</td>
            <td data-label="Worst"><span class="badge sev-${esc(sev)}">${esc(s.worst || "-")}</span></td>
            <td data-label="CVEs">${esc(s.n_cves)}</td><td data-label="Findings">${esc(s.n_findings)}</td>
            <td class="history-actions" data-label="Actions"><div class="rowactions">
              <button type="button" class="actbtn" data-view="${id}"
                aria-label="View scan of ${esc(s.target)}">View</button>
              <button type="button" class="actbtn" data-rescan="${esc(s.target)}"
                aria-label="Review and rescan ${esc(s.target)}">Review &amp; rescan</button>
              <details class="exportmenu">
                <summary class="actbtn" aria-label="Export scan of ${esc(s.target)}">Export ▾</summary>
                <div class="exportmenu-list">
                  <a href="${withToken(`/api/scans/${id}/export.json`)}" download>JSON</a>
                  <a href="${withToken(`/api/scans/${id}/export.md`)}" download>Markdown</a>
                  <a href="${withToken(`/api/scans/${id}/export.sarif`)}" download>SARIF</a>
                  <a href="${withToken(`/api/scans/${id}/export.html`)}" download>HTML</a>
                </div>
              </details>
              <button type="button" class="actbtn danger" data-del="${id}"
                aria-label="Delete scan of ${esc(s.target)}">Delete</button>
            </div></td>
          </tr>`;
        });
        html += `</tbody></table></div>`;
        $("historyList").innerHTML = html;

        $("historyList").querySelectorAll("button[data-view]").forEach((b) =>
          b.addEventListener("click", () => C.loadScan(b.dataset.view)));
        $("historyList").querySelectorAll("button[data-rescan]").forEach((b) =>
          b.addEventListener("click", () => rescan(b.dataset.rescan)));
        $("historyList").querySelectorAll("button[data-del]").forEach((b) =>
          b.addEventListener("click", () => deleteScan(b.dataset.del)));

        $("historyPager").classList.remove("hidden");
        $("histPrev").disabled = histOffset === 0;
        $("histNext").disabled = scans.length < HIST_LIMIT;
        $("histPageInfo").textContent = `Showing ${histOffset + 1}–${histOffset + scans.length}`;
      } catch (err) {
        $("historyList").innerHTML = `<p class="empty">Error loading history: ${esc(err.message)}</p>`;
        $("historyPager").classList.add("hidden");
      }
    }

    $("historyForm").addEventListener("submit", (e) => { e.preventDefault(); loadHistory(true); });
    $("histPrev").addEventListener("click", () => {
      histOffset = Math.max(0, histOffset - HIST_LIMIT);
      loadHistory(false);
    });
    $("histNext").addEventListener("click", () => {
      histOffset += HIST_LIMIT;
      loadHistory(false);
    });

    function rescan(target) {
      C.showTab("host");
      showFieldError("target", "");
      $("target").value = target;
      $("target").focus();
      $("target").scrollIntoView({ block: "center", behavior: C.scrollBehavior() });
    }

    async function deleteScan(scanId) {
      if (!window.confirm("Delete this stored scan? This cannot be undone.")) return;
      try {
        const r = await fetch("/api/scans/" + encodeURIComponent(scanId), { method: "DELETE" });
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          throw new Error(err.detail || r.statusText);
        }
        toast("Scan deleted.", "success");
        loadHistory(false);
      } catch (err) {
        toast("Could not delete: " + err.message, "error");
      }
    }

    // ---- code scan ----------------------------------------------------------------------
    let _codePending = false;
    function setCodePending(pending) {
      _codePending = pending;
      ["codeBtn", "codeTextBtn"].forEach((id) => { $(id).disabled = pending; });
      $("codeFile").disabled = pending;
      $("dropzone").setAttribute("aria-disabled", pending ? "true" : "false");
      $("dropzone").classList.toggle("disabled", pending);
    }

    function resultProblemsHtml(errors) {
      return errors.length ? `<div class="result-problems" role="alert">
        <strong>Check errors — results may be incomplete.</strong>
        <ul>${errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></div>` : "";
    }

    $("codeForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      if (_codePending) return;
      const path = $("codePath").value.trim();
      if (!path) {
        showFieldError("codePath", "Enter a server path to scan.");
        $("codePath").focus();
        return;
      }
      await runCode({ path, use_external: true });
    });
    $("codeTextBtn").addEventListener("click", async () => {
      if (_codePending) return;
      const text = $("codeText").value;
      if (!text.trim()) {
        showFieldError("codeText", "Paste code or configuration text to scan.");
        $("codeText").focus();
        return;
      }
      await runCode({ text });
    });

    // File-upload dropzone (multipart, 2 MB cap — scanned in memory, never stored).
    const MAX_UPLOAD = 2 * 1024 * 1024;
    const dz = $("dropzone");
    dz.addEventListener("click", () => { if (!_codePending) $("codeFile").click(); });
    dz.addEventListener("keydown", (e) => {
      if ((e.key === "Enter" || e.key === " ") && !_codePending) {
        e.preventDefault();
        $("codeFile").click();
      }
    });
    $("codeFile").addEventListener("change", (e) => {
      if (!_codePending && e.target.files && e.target.files[0]) uploadCodeFile(e.target.files[0]);
      e.target.value = "";
    });
    ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => {
      e.preventDefault();
      if (!_codePending) dz.classList.add("dragover");
    }));
    ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => {
      e.preventDefault();
      dz.classList.remove("dragover");
    }));
    dz.addEventListener("drop", (e) => {
      if (_codePending) return;
      const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) uploadCodeFile(f);
    });

    async function uploadCodeFile(file) {
      if (_codePending) return;
      if (file.size > MAX_UPLOAD) {
        toast(`“${file.name}” is too large — the limit is 2 MB.`, "error");
        return;
      }
      setCodePending(true);
      setStatus("codeStatus", `Scanning ${file.name}…`, false);
      try {
        const fd = new FormData();
        fd.append("file", file);
        renderCode(await C.api("/api/code", { method: "POST", body: fd }));
      } catch (err) {
        setStatus("codeStatus", "Error: " + err.message, true);
        toast("Code scan failed: " + err.message, "error");
      } finally {
        setCodePending(false);
      }
    }

    async function runCode(body) {
      if (_codePending) return;
      setCodePending(true);
      setStatus("codeStatus", "Scanning…", false);
      try {
        renderCode(await C.api("/api/code", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }));
      } catch (err) {
        setStatus("codeStatus", "Error: " + err.message, true);
        toast("Code scan failed: " + err.message, "error");
      } finally {
        setCodePending(false);
      }
    }

    function renderCode(res) {
      const errors = (res.errors || []).map((e) => String(e));
      const finds = (res.findings || []).slice().sort((a, b) =>
        SEV_ORDER[b.severity] - SEV_ORDER[a.severity]);
      setStatus("codeStatus",
        `Scanned ${res.files_scanned || 0} file(s) · tools: ${(res.tools_used || []).join(", ") || "built-in"}`
          + ` · ${finds.length} finding(s)${errors.length ? ` · ${errors.length} check error(s)` : ""}`,
        errors.length > 0);
      let html = resultProblemsHtml(errors);
      if (!finds.length) {
        html += errors.length
          ? `<p class="empty">No findings were returned. Review the errors above; coverage is incomplete.</p>`
          : `<p class="empty empty-good">✓ No secrets or risky patterns found.</p>`;
        $("codeResults").innerHTML = html;
        return;
      }
      finds.forEach((f) => {
        const sev = severityName(f.severity);
        html += `<div class="card ${sev}">
          <div class="row"><span class="title"><span class="badge sev-${sev}">${sev}</span> ${esc(f.title)}</span></div>
          <div class="meta">${esc(f.file)}:${esc(f.line)} &middot; ${esc(f.category)}/${esc(f.rule_id)}</div>
          ${f.evidence ? `<div class="desc">evidence: ${esc(f.evidence)}</div>` : ""}
          ${f.recommendation ? `<div class="fix">↳ ${esc(f.recommendation)}</div>` : ""}
        </div>`;
      });
      $("codeResults").innerHTML = html;
    }

    // ---- mail security ---------------------------------------------------------------------
    let _mailPending = false;
    function setMailPending(pending) {
      _mailPending = pending;
      $("mailBtn").disabled = pending;
    }

    $("mailForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      if (_mailPending) return;
      const domain = $("mailDomain").value.trim();
      if (!domain) {
        showFieldError("mailDomain", "Enter a domain, URL, or e-mail address to check.");
        $("mailDomain").focus();
        return;
      }
      setMailPending(true);
      setStatus("mailStatus", "Checking e-mail security…", false);
      try {
        renderMail(await C.api("/api/mailsec", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain }),
        }));
      } catch (err) {
        setStatus("mailStatus", "Error: " + err.message, true);
        toast("Mail check failed: " + err.message, "error");
      } finally {
        setMailPending(false);
      }
    });

    const MAIL_STATUS = {
      ok:   { icon: "✓", cls: "ms-ok",   label: "OK" },
      warn: { icon: "⚠", cls: "ms-warn", label: "Fix" },
      bad:  { icon: "✗", cls: "ms-bad",  label: "Issue" },
      info: { icon: "ℹ", cls: "ms-info", label: "Info" },
    };

    function renderMail(info) {
      const errors = (info.errors || []).map((e) => String(e));
      if (!info.checks || !info.checks.length) {
        setStatus("mailStatus", `No DNS answers for ${info.domain || ""}.`
          + `${errors.length ? ` ${errors.length} check error(s).` : ""}`, true);
        $("mailResults").innerHTML = resultProblemsHtml(errors);
        return;
      }
      const todo = info.checks.filter((c) => c.status === "warn" || c.status === "bad").length;
      setStatus("mailStatus",
        `${info.domain} · grade ${info.grade} (${info.score}/100) · ${todo} to fix`
          + `${errors.length ? ` · ${errors.length} check error(s)` : ""}`, errors.length > 0);

      const mx = (info.mx || []).join(", ") || "no MX";
      const reportUrl = withToken("/api/mailsec/report.html?domain=" + encodeURIComponent(info.domain || ""));
      let html = resultProblemsHtml(errors) + `<div class="mail-score grade-${esc((info.grade || "F")[0])}">
          <div class="grade">${esc(info.grade)}</div>
          <div class="score"><strong>${esc(info.score)}</strong>/100</div>
          <div class="mx">Mail server: ${esc(mx)}${info.provider ? " · " + esc(info.provider) : ""}
            <br><a class="reportlink" href="${reportUrl}" target="_blank">HTML report</a>
            <a class="reportlink" href="${reportUrl}&download=1" download title="Download the mail report (.html)">Download</a></div>
        </div>`;

      info.checks.forEach((c) => {
        const s = MAIL_STATUS[c.status] || MAIL_STATUS.info;
        html += `<div class="card mailcheck ${s.cls}">
          <div class="row"><span class="title">${s.icon} ${esc(c.label)}
            <span class="badge ${s.cls}">${s.label}</span></span></div>
          <div class="desc">${esc(c.detail)}</div>
          ${c.value ? `<div class="meta">${esc(c.value)}</div>` : ""}
          ${c.fix ? `<div class="fix">↳ ${esc(c.fix)}</div>` : ""}
        </div>`;
      });
      $("mailResults").innerHTML = html;
    }
  });
})();
