"use strict";

/* ============================================================================
   Celsius web UI — vanilla JS, no build step.
   Sections: helpers · token · theme · tabs · presets · AI · scan queue ·
   progress · results · PoC modal · history · code scan · mail security.
   Untrusted scan data is always rendered through esc() — never raw HTML.
   ========================================================================== */

const $ = (id) => document.getElementById(id);
const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
let lastUrl = null; // url of last scan, for PoC context

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

// ---- toast notifications (non-blocking replacement for alert()) --------------
function toast(msg, kind) {
  const box = $("toasts");
  if (!box) return;
  const el = document.createElement("div");
  el.className = "toast toast-" + (kind || "info");
  el.setAttribute("role", "status");
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => {
    el.classList.add("out");
    setTimeout(() => el.remove(), 320);
  }, 4600);
}

// ---- access token ------------------------------------------------------------
// When the server runs with CELSIUS_TOKEN (LAN/Docker exposure), every /api/*
// request must carry it. We inject it as a header on fetch() and as a ?token=
// query param on report links opened directly in a browser tab.
const ACCESS_TOKEN = (function () {
  let tok = "";
  try { tok = localStorage.getItem("celsius_token") || ""; } catch (_) {}
  document.addEventListener("DOMContentLoaded", () => {
    const el = $("accessToken");
    if (!el) return;
    el.value = tok;
    el.addEventListener("input", (e) => {
      tok = e.target.value.trim();
      try { localStorage.setItem("celsius_token", tok); } catch (_) {}
    });
  });
  return { get: () => tok };
})();

// Wrap fetch: add the token header for same-origin /api/ calls.
(function patchFetch() {
  const orig = window.fetch.bind(window);
  window.fetch = function (input, init) {
    const url = typeof input === "string" ? input : (input && input.url) || "";
    const isApi = url.startsWith("/api/") || url.startsWith(location.origin + "/api/");
    const tok = ACCESS_TOKEN.get();
    if (isApi && tok) {
      init = init || {};
      const h = new Headers(init.headers || (typeof input !== "string" && input.headers) || {});
      h.set("X-Celsius-Token", tok);
      init.headers = h;
    }
    return orig(input, init);
  };
})();

// Append ?token= to an /api/ report link so a plain browser navigation authenticates.
function withToken(url) {
  const tok = ACCESS_TOKEN.get();
  if (!tok || !url.startsWith("/api/")) return url;
  return url + (url.includes("?") ? "&" : "?") + "token=" + encodeURIComponent(tok);
}

// ---- theme (light default, dark opt-in) ----------------------------------------
(function initTheme() {
  const KEY = "celsius_theme";
  const root = document.documentElement;
  function apply(theme) {
    root.setAttribute("data-theme", theme);
    const btn = $("themeToggle");
    if (btn) btn.textContent = theme === "light" ? "☾" : "☀";
  }
  let saved = null;
  try { saved = localStorage.getItem(KEY); } catch (e) { /* private mode */ }
  apply(saved === "dark" ? "dark" : "light"); // light by default; dark is the toggle
  document.addEventListener("click", (e) => {
    if (e.target && e.target.id === "themeToggle") {
      const next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      apply(next);
      try { localStorage.setItem(KEY, next); } catch (_) { /* ignore */ }
    }
  });
})();

// ---- tabs ----------------------------------------------------------------------
function activateTab(name) {
  document.querySelectorAll(".tab").forEach((x) => {
    const on = x.dataset.tab === name;
    x.classList.toggle("active", on);
    x.setAttribute("aria-selected", on ? "true" : "false");
  });
  document.querySelectorAll(".panel").forEach((x) =>
    x.classList.toggle("active", x.id === "tab-" + name));
}
document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    activateTab(t.dataset.tab);
    if (t.dataset.tab === "history") loadHistory(true);
  });
});

// ---- scan presets ---------------------------------------------------------------
// Each preset maps the advanced-option checkbox ids to on/off. Custom means
// "whatever the user has set" — any manual edit switches the preset to Custom.
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

function selectPreset(name, applyValues) {
  document.querySelectorAll(".preset").forEach((p) => {
    const on = p.dataset.preset === name;
    p.classList.toggle("active", on);
    p.setAttribute("aria-checked", on ? "true" : "false");
  });
  if (applyValues && PRESETS[name]) {
    Object.entries(PRESETS[name]).forEach(([id, on]) => { $(id).checked = on; });
  }
  if (name === "custom") $("advancedOpts").open = true;
}

document.querySelectorAll(".preset").forEach((p) => {
  p.addEventListener("click", () => selectPreset(p.dataset.preset, true));
});
// Any manual edit inside the advanced panel flips the preset to Custom.
$("advancedOpts").addEventListener("change", (e) => {
  if (e.target && e.target.id === "opt-ai") return; // AI toggle isn't part of presets
  selectPreset("custom", false);
});

// Default state: Standard.
selectPreset("standard", true);

// ---- authorization gate ----------------------------------------------------------
$("authorized").addEventListener("change", (e) => {
  $("authbar").classList.toggle("ok", e.target.checked);
  if (e.target.checked) $("authbar").classList.remove("attention");
});

// Returns true when the authorization checkbox is ticked; otherwise highlights
// and scrolls to it with a clear message.
function demandAuth() {
  if ($("authorized").checked) return true;
  toast("Please confirm you own or have permission to scan this target.", "error");
  const bar = $("authbar");
  bar.classList.add("attention");
  bar.scrollIntoView({ block: "center", behavior: "smooth" });
  $("authorized").focus();
  setTimeout(() => bar.classList.remove("attention"), 3500);
  return false;
}

// ---- AI provider status -----------------------------------------------------------
// Ask the server which providers are configured. If none: friendly hint with the
// form hidden behind a "Configure AI" toggle. If some: preselect the first one.
(async function initAI() {
  try {
    const r = await fetch("/api/ai/status");
    if (!r.ok) return;
    const { providers } = await r.json();
    const order = ["deepseek", "openai", "anthropic", "local"];
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

// ---- AI key: remember in the browser (localStorage) --------------------------------
try {
  const savedKey = localStorage.getItem("celsius_ai_key");
  if (savedKey) $("opt-ai-key").value = savedKey;
} catch (e) { /* localStorage may be unavailable */ }
$("opt-ai-key").addEventListener("change", (e) => {
  try { localStorage.setItem("celsius_ai_key", e.target.value); } catch (_) {}
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
      $("target").scrollIntoView({ block: "center", behavior: "smooth" });
    });
  } catch (e) { /* offline — panel just stays empty */ }
})();

// ---- shared render helpers -------------------------------------------------------------
const VERDICT_CLASS = {
  "likely-exploitable": "v-high", "conditions-needed": "v-med",
  "not-in-context": "v-low", "unknown": "v-unk", "informational": "v-info",
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
  catch (e) { return u.slice(0, 40); }
}
function exploitMeta(ex) {
  if (!ex || !ex.signals) return "";
  const s = ex.signals, bits = [];
  if (s.epss != null) bits.push("EPSS " + s.epss.toFixed(3));
  if (s.kev) bits.push("CISA-KEV");
  if (ex.priority != null) bits.push("priority " + ex.priority);
  return bits.length ? " · " + bits.join(" · ") : "";
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

function fmtElapsed(sec) {
  sec = Math.max(0, Math.round(sec));
  return Math.floor(sec / 60) + ":" + String(sec % 60).padStart(2, "0");
}

// ---- host/web scan ----------------------------------------------------------------------
let _scanQueue = [];     // follow-up targets waiting to be scanned
let _scanning = false;
let _currentJobId = null;
let _elapsedTimer = null;
let _elapsedBase = null;   // ms epoch of scan start
let _lastElapsed = null;   // server-stamped elapsed seconds (preferred)

function currentScanOptions() {
  return {
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
  };
}

function queueNote() { return _scanQueue.length ? ` · ${_scanQueue.length} queued` : ""; }

const PHASES = {
  recon: "Mapping the attack surface…",
  detect: "Checking for known vulnerabilities…",
  enrich: "Scoring and prioritizing…",
};

function startElapsed(startedAtIso) {
  stopElapsed();
  _elapsedBase = startedAtIso ? Date.parse(startedAtIso) : Date.now();
  _lastElapsed = null;
  const tick = () => {
    const sec = _lastElapsed != null ? _lastElapsed : (Date.now() - _elapsedBase) / 1000;
    $("progElapsed").textContent = fmtElapsed(sec);
  };
  tick();
  _elapsedTimer = setInterval(tick, 1000);
}
function stopElapsed() {
  if (_elapsedTimer) { clearInterval(_elapsedTimer); _elapsedTimer = null; }
}

function showProgress(job) {
  $("scanProgress").classList.remove("hidden");
  const p = job.progress;
  if (p) {
    $("progPhase").textContent = PHASES[p.phase] || "Working…";
    const pct = p.total ? Math.min(100, Math.round((p.index / p.total) * 100)) : 0;
    $("progFill").style.width = pct + "%";
    $("progBar").setAttribute("aria-valuenow", String(pct));
    $("progPlugin").textContent = p.plugin ? `${p.plugin} · step ${p.index}/${p.total}` : "";
    if (p.elapsed != null) {
      _lastElapsed = p.elapsed;
      $("progElapsed").textContent = fmtElapsed(p.elapsed);
    }
  } else {
    $("progPhase").textContent = "Starting…";
    $("progPlugin").textContent = (job.log || []).slice(-1)[0] || "";
  }
}
function hideProgress() {
  stopElapsed();
  $("scanProgress").classList.add("hidden");
  _currentJobId = null;
}

async function runScan(target) {
  _scanning = true;
  document.title = "Celsius";
  $("scanBtn").disabled = true;
  $("target").value = target;
  $("results").innerHTML = "";
  $("scanLog").textContent = "";
  setStatus("scanStatus", `Starting scan of ${target}…${queueNote()}`, false);
  $("scanProgress").classList.remove("hidden");
  $("progFill").style.width = "0%";
  startElapsed(null);
  try {
    const resp = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, authorized: true, ...currentScanOptions() }),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || resp.statusText);
    }
    const { job_id } = await resp.json();
    _currentJobId = job_id;
    pollJob(job_id);
  } catch (err) {
    hideProgress();
    setStatus("scanStatus", "Error: " + err.message, true);
    toast("Could not start the scan: " + err.message, "error");
    nextScan();
  }
}

// Advance the queue: run the next target, or go idle.
function nextScan() {
  if (_scanQueue.length) {
    runScan(_scanQueue.shift());
  } else {
    _scanning = false;
    $("scanBtn").disabled = false;
  }
}

function enqueueScans(targets) {
  _scanQueue.push(...targets);
  if (!_scanning) nextScan();
}

$("scanForm").addEventListener("submit", (e) => {
  e.preventDefault();
  if (!demandAuth()) return;
  const target = $("target").value.trim();
  if (!target) return;
  if ($("opt-exploit").checked && $("opt-attest").value.trim().length < 10) {
    toast("Lab mode needs an authorization attestation (≥10 characters) before active exploitation.", "error");
    $("labmode").open = true;
    $("opt-attest").focus();
    return;
  }
  if (_scanning) {
    _scanQueue.push(target);
    setStatus("scanStatus", `Queued ${target}…${queueNote()}`, false);
    toast(`Queued ${target} — it will run next.`, "info");
    return;
  }
  runScan(target);
});

// Cancel the running job (no confirmation — immediate, with a toast).
$("cancelBtn").addEventListener("click", async () => {
  if (!_currentJobId) return;
  try {
    const r = await fetch("/api/scan/" + _currentJobId, { method: "DELETE" });
    if (r.status === 409) { toast("That scan already finished.", "info"); return; }
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error(err.detail || r.statusText);
    }
    toast("Cancelling scan…", "info");
  } catch (err) {
    toast("Could not cancel: " + err.message, "error");
  }
});

function finishTitle(result) {
  const g = result && result.assessment && result.assessment.grade;
  document.title = "✓ Celsius — scan finished" + (g ? " · grade " + g : "");
}
window.addEventListener("focus", () => {
  if (document.title.startsWith("✓")) document.title = "Celsius";
});

async function pollJob(jobId) {
  try {
    const r = await fetch("/api/scan/" + jobId);
    const job = await r.json();
    $("scanLog").textContent = (job.log || []).join("\n");
    $("scanLog").scrollTop = $("scanLog").scrollHeight;

    if (job.status === "running") {
      showProgress(job);
      setTimeout(() => pollJob(jobId), 800);
    } else if (job.status === "done") {
      hideProgress();
      setStatus("scanStatus", "Scan complete." + queueNote(), false);
      renderResult(job.result, job.scan_id);
      finishTitle(job.result);
      toast("Scan of " + esc((job.result || {}).target || "target") + " finished.", "success");
      nextScan();
    } else if (job.status === "cancelled") {
      hideProgress();
      setStatus("scanStatus", "Scan cancelled." + queueNote(), false);
      toast("Scan cancelled.", "info");
      nextScan();
    } else {
      hideProgress();
      setStatus("scanStatus", "Scan failed: " + (job.error || "unknown"), true);
      toast("Scan failed: " + (job.error || "unknown"), "error");
      nextScan();
    }
  } catch (err) {
    hideProgress();
    setStatus("scanStatus", "Error polling job: " + err.message, true);
    nextScan();
  }
}

function setStatus(id, msg, isErr) {
  const el = $(id);
  el.classList.remove("hidden");
  el.classList.toggle("err", !!isErr);
  el.textContent = msg;
}

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

// Distinct in-scope hosts (≠ the scanned host) referenced by this scan — derived
// from same-site crawl endpoints and any enumerated subdomains. These are full
// targets you can queue follow-up scans against.
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
  A: "Looking good — no confident security issues found.",
  B: "Mostly fine, with a few things worth fixing.",
  C: "Several issues need your attention.",
  D: "Your site has serious issues that need attention.",
  F: "Critical issues found — act on these first.",
};

function renderResult(res, scanId) {
  lastUrl = res.url || res.target;
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  // Low-confidence CVEs (over-broad NVD match / distro-backported) are reported
  // but kept out of the headline severity counts so they don't cry wolf.
  let weakCount = 0;
  (res.cves || []).forEach((c) => { if (c.confidence === "weak") weakCount++; else counts[c.severity]++; });
  // AI hypotheses are leads, not facts — kept out of the headline severity too.
  let aiCount = 0;
  (res.findings || []).forEach((f) => { if (f.category === "ai-hypothesis") aiCount++; else counts[f.severity]++; });

  const scannedHost = hostOf(res.url || res.target) || "";
  const apex = scannedHost.split(".").slice(-2).join(".");
  const a = res.assessment;
  const gradeLetter = a && a.grade ? a.grade : "C";
  const g0 = gradeLetter[0];

  let html = "";

  // ---- hero: grade + score + verdict + donut ----
  const chips = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    .filter((s) => counts[s] > 0)
    .map((s) => `<span class="chip sev-${s}">${s} ${counts[s]}</span>`).join("")
    + (weakCount ? `<span class="chip sev-UNCONFIRMED" title="Reported but not confirmed — verify before acting">Unconfirmed ${weakCount}</span>` : "")
    + (aiCount ? `<span class="chip sev-AILEADS" title="AI hypotheses — unverified leads, not counted in severity">AI leads ${aiCount}</span>` : "");
  const verdict = a && a.clean
    ? "No findings — nice work. Anything listed below is a low-confidence lead, not a confirmed issue."
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

  // ---- "fix these first" action list ----
  if (a && !a.clean && (a.fix_first || []).length) {
    const items = a.fix_first.map((it) =>
      `<li><span class="badge sev-${it.severity}">${it.severity}</span>${it.verified ? ' <span class="verdict v-high">✔ verified</span>' : ""}
        <strong>${esc(it.title)}</strong>${it.why ? `<span class="hc-why"> — ${esc(it.why)}</span>` : ""}${it.fix ? `<div class="hc-fix">Fix: ${esc(it.fix)}</div>` : ""}</li>`).join("");
    const more = a.total_actionable > a.fix_first.length
      ? `<div class="hc-more">+${a.total_actionable - a.fix_first.length} more below</div>` : "";
    html += `<div class="fixfirst"><h3>Fix these first</h3><ol class="fixfirst-list">${items}</ol>${more}</div>`;
  }

  // ---- AI security advisor — grounded, plain-language action plan ----
  const adv = (res.recon || {}).advisor;
  if (adv && (adv.headline || (adv.steps || []).length)) {
    const steps = (adv.steps || []).map((s) => `<li>
        <span class="badge sev-${s.severity || "LOW"}">${esc(s.severity || "")}</span>
        <strong>${esc(s.title || "")}</strong>${s.effort ? ` <span class="adv-effort">${esc(s.effort)}</span>` : ""}
        ${s.why ? `<div class="adv-why">${esc(s.why)}</div>` : ""}
        ${s.fix ? `<div class="adv-fix"><code>${esc(s.fix)}</code></div>` : ""}</li>`).join("");
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
      html += `<div class="card ${ch.severity}">
        <div class="row"><span class="title"><span class="badge sev-${ch.severity}">${ch.severity}</span> ${esc(ch.title)}</span>
          <span class="meta">priority ${ch.priority}</span></div>
        <div class="meta">path: ${ch.nodes.map(esc).join(" → ")}</div>
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
    html += `<div class="tablewrap"><table class="svc"><tr><th>Product</th><th>Version</th><th>Port</th><th>Source</th></tr>`;
    res.services.forEach((s) => {
      html += `<tr><td>${esc(s.name)}</td><td>${esc(s.version || "?")}</td><td class="mono">${s.port || ""}</td><td>${esc(s.source)}</td></tr>`;
    });
    html += `</table></div>`;
  } else html += `<p class="empty">None detected.</p>`;

  // ---- CVEs — firm (confident) first, low-confidence ("weak") to the bottom ----
  const cves = (res.cves || []).slice().sort((x, y) =>
    ((x.confidence === "weak") - (y.confidence === "weak"))
    || (SEV_ORDER[y.severity] - SEV_ORDER[x.severity]) || ((y.cvss || 0) - (x.cvss || 0)));
  const firmN = cves.filter((c) => c.confidence !== "weak").length;
  const weakN = cves.length - firmN;
  html += `<h2 class="section">Known vulnerabilities — CVEs (${firmN}${weakN ? ` + ${weakN} unconfirmed` : ""})</h2>`;
  if (cves.length) {
    cves.forEach((c, i) => {
      const verified = c.verified ? ` <span class="verdict v-high">✔ VERIFIED</span>` : "";
      const weak = c.confidence === "weak";
      const unconfirmed = weak ? ` <span class="verdict v-low" title="${esc(c.caveat || "")}">⚠ UNCONFIRMED</span>` : "";
      const caveatHtml = weak && c.caveat ? `<div class="meta">⚠ ${esc(c.caveat)}</div>` : "";
      const pocs = (c.references || []).filter((r) => r.poc).slice(0, 4);
      const pocHtml = pocs.length
        ? `<div class="meta">PoC: ${pocs.map((r) => `<a href="${esc(r.url)}" target="_blank">${esc(shortUrl(r.url))}</a>`).join(" · ")}</div>`
        : "";
      html += `<div class="card ${weak ? "INFO" : c.severity}${weak ? " weak" : ""}">
        <div class="row">
          <span class="title"><span class="badge sev-${c.severity}">${c.severity}</span>
            <a href="${esc(c.url)}" target="_blank">${esc(c.id)}</a>
            &nbsp;CVSS ${c.cvss == null ? "-" : c.cvss}${verdictBadge(c.exploitability)}${verified}${unconfirmed}</span>
          <button class="pocBtn" data-poc="cve" data-i="${i}">How to check</button>
        </div>
        <div class="meta">affects: ${esc(c.affects)}${exploitMeta(c.exploitability)}</div>
        ${caveatHtml}
        ${pocHtml}
        <div class="desc">${esc((c.description || "").slice(0, 240))}</div>
      </div>`;
    });
  } else html += `<p class="empty empty-good">✓ No known CVEs for the detected versions.</p>`;

  // ---- findings — confirmed first; AI hypotheses in a distinct block below ----
  const bySev = (x, y) => SEV_ORDER[y.severity] - SEV_ORDER[x.severity];
  const realFinds = (res.findings || []).filter((f) => f.category !== "ai-hypothesis").sort(bySev);
  const aiFinds = (res.findings || []).filter((f) => f.category === "ai-hypothesis").sort(bySev);
  const finds = [...realFinds, ...aiFinds];   // single array so pocBtn data-i still maps

  function findingCard(f, i) {
    const conf = f.confidence ? ` <span class="conf">confidence: ${esc(f.confidence)}</span>` : "";
    const aiTag = f.category && f.category.startsWith("ai") ? ' <span class="ai-tag">AI</span>' : "";
    const ex = f.exploitability;
    const whyBits = [];
    if (ex && ex.verdict && ex.verdict !== "informational") whyBits.push(`Exploitability: ${ex.verdict.replace(/-/g, " ")}.`);
    if (ex && ex.signals && ex.signals.epss != null) whyBits.push(`EPSS score ${ex.signals.epss.toFixed(3)} (exploit probability).`);
    if (ex && ex.signals && ex.signals.kev) whyBits.push(`Listed in CISA's Known Exploited Vulnerabilities catalog.`);
    whyBits.push(WHY[f.severity] || WHY.INFO);
    const fixInner = (f.recommendation ? `<p>${esc(f.recommendation)}</p>` : "") + fixContent(ex);
    return `<div class="card ${f.severity}">
      <div class="row">
        <span class="title"><span class="badge sev-${f.severity}">${f.severity}</span> ${esc(f.title)}${aiTag}${verdictBadge(ex)}</span>
        <button class="pocBtn" data-poc="finding" data-i="${i}">How to check</button>
      </div>
      <div class="meta">[${esc(f.category)}]${conf}</div>
      <div class="f-secs">
        <details class="f-sec"><summary>What is this?</summary>
          <div class="desc">${esc(f.description)}</div>
          ${f.evidence ? `<div class="meta">evidence: ${esc(f.evidence)}</div>` : ""}
        </details>
        <details class="f-sec"><summary>Why it matters</summary><p>${esc(whyBits.join(" "))}</p></details>
        ${fixInner ? `<details class="f-sec"><summary>How to fix</summary>${fixInner}</details>` : ""}
      </div>
    </div>`;
  }

  html += `<h2 class="section">Findings (${realFinds.length})</h2>`;
  if (realFinds.length) {
    realFinds.forEach((f, i) => { html += findingCard(f, i); });
  } else {
    html += `<p class="empty empty-good">✓ No findings — nice work.</p>`;
  }
  if (aiFinds.length) {
    html += `<div class="ai-section">
      <h2 class="section">AI hypotheses (${aiFinds.length})</h2>
      <p class="ai-disclaimer">Unverified leads generated by an AI model — not counted in the severity
        totals. Verify each one before trusting or acting on it.</p>`;
    aiFinds.forEach((f, j) => { html += findingCard(f, realFinds.length + j); });
    html += `</div>`;
  }

  // ---- follow-up: in-scope hosts discovered during this scan ----
  const followup = followupHosts(res);
  if (followup.length) {
    html += `<h2 class="section">Discovered hosts — scan them too? (${followup.length})</h2>`;
    html += `<div class="card INFO followup">
      <p class="note">In-scope hosts referenced by ${esc(res.target)}. Select any to queue a full
        scan of each (uses the current scan options). Authorized targets only.</p>
      <div class="fu-list">${followup.slice(0, 50).map((t) =>
        `<label class="fu-item"><input type="checkbox" class="fu-chk" value="${esc(t)}"> ${esc(t)}</label>`).join("")}
      </div>${followup.length > 50 ? `<p class="note">… and ${followup.length - 50} more (not shown)</p>` : ""}
      <div class="fu-actions">
        <button type="button" id="fuAll" class="btn-secondary">Select all</button>
        <button type="button" id="fuScan" class="btn-primary">Scan selected</button>
      </div>
    </div>`;
  }

  if ((res.errors || []).length) {
    html += `<h2 class="section">Notes</h2>`;
    res.errors.forEach((e) => { html += `<div class="meta">! ${esc(e)}</div>`; });
  }

  // ---- meta footer: duration, coverage, exports ----
  let dur = "";
  if (res.started_at && res.finished_at) {
    const s = Date.parse(res.started_at), f = Date.parse(res.finished_at);
    if (!isNaN(s) && !isNaN(f) && f >= s) dur = fmtElapsed((f - s) / 1000);
  }
  const cov = res.coverage || {};
  const covHtml = (cov.next_steps || []).length
    ? `<h5>Want deeper coverage?</h5><ul class="coverage-list">${cov.next_steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>` : "";
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
    ${covHtml}
    ${exp.length ? `<h5>Export</h5><div class="exports">${exp.join("")}</div>` : ""}
  </div>`;

  $("results").innerHTML = html;
  // wire PoC buttons
  $("results").querySelectorAll(".pocBtn").forEach((b) => {
    b.addEventListener("click", () => {
      const kind = b.dataset.poc;
      const item = kind === "cve" ? cves[+b.dataset.i] : finds[+b.dataset.i];
      showPoc(kind, item, item.exploitability);
    });
  });

  // wire follow-up scan controls
  const fuScan = $("fuScan");
  if (fuScan) {
    $("fuAll").addEventListener("click", () => {
      const boxes = [...$("results").querySelectorAll(".fu-chk")];
      const turnOn = boxes.some((b) => !b.checked);
      boxes.forEach((b) => (b.checked = turnOn));
    });
    fuScan.addEventListener("click", () => {
      if (!demandAuth()) return;
      const sel = [...$("results").querySelectorAll(".fu-chk:checked")].map((b) => b.value);
      if (!sel.length) { toast("Select at least one host first.", "info"); return; }
      enqueueScans(sel);
      setStatus("scanStatus", `Queued ${sel.length} follow-up scan(s)…${queueNote()}`, false);
      toast(`Queued ${sel.length} follow-up scan(s).`, "info");
    });
  }
}

// ---- PoC modal -----------------------------------------------------------------
async function showPoc(kind, data, exploit) {
  try {
    const r = await fetch("/api/poc", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind, data, url: lastUrl }),
    });
    const box = await r.json();
    let html = `<h2>${esc(box.title)}</h2>`;
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
    if (box.references && box.references.length) {
      html += `<div class="poc-refs"><strong>References</strong>`;
      box.references.forEach((u) => { html += `<a href="${esc(u)}" target="_blank">${esc(u)}</a>`; });
      html += `</div>`;
    }
    $("pocContent").innerHTML = html;
    openModal();
  } catch (err) {
    toast("Could not load the reproduction steps: " + err.message, "error");
  }
}

// Modal open/close with focus management: trap Tab inside the dialog, close on
// Escape or backdrop click, and restore focus to whatever opened it.
let _pocReturnFocus = null;
function openModal() {
  const modal = $("pocModal");
  _pocReturnFocus = document.activeElement;
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
  $("pocClose").focus();
}
function closeModal() {
  const modal = $("pocModal");
  if (modal.classList.contains("hidden")) return;
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
  if (_pocReturnFocus && _pocReturnFocus.focus) _pocReturnFocus.focus();
  _pocReturnFocus = null;
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
  const focusable = $("pocModal").querySelectorAll(
    'button, a[href], input, textarea, select, [tabindex]:not([tabindex="-1"])');
  if (!focusable.length) return;
  const first = focusable[0], last = focusable[focusable.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
});

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
    let html = `<div class="tablewrap"><table class="svc"><tr>
      <th>When</th><th>Target</th><th>Grade</th><th>Worst</th><th>CVEs</th><th>Findings</th><th></th></tr>`;
    scans.forEach((s) => {
      const sev = s.worst && s.worst !== "NONE" ? s.worst : "INFO";
      const grade = s.grade ? `<span class="grade-badge grade-${esc(s.grade[0])}">${esc(s.grade)}</span>` : "—";
      const id = esc(s.id);
      html += `<tr>
        <td class="mono">${esc((s.finished_at || s.started_at || "-").replace("T", " ").slice(0, 19))}</td>
        <td>${esc(s.target)}</td>
        <td>${grade}</td>
        <td><span class="badge sev-${sev}">${esc(s.worst || "-")}</span></td>
        <td>${s.n_cves}</td><td>${s.n_findings}</td>
        <td><div class="rowactions">
          <button class="actbtn" data-view="${id}">View</button>
          <button class="actbtn" data-rescan="${esc(s.target)}">Re-scan</button>
          <details class="exportmenu">
            <summary class="actbtn">Export ▾</summary>
            <div class="exportmenu-list">
              <a href="${withToken(`/api/scans/${id}/export.json`)}" download>JSON</a>
              <a href="${withToken(`/api/scans/${id}/export.md`)}" download>Markdown</a>
              <a href="${withToken(`/api/scans/${id}/export.sarif`)}" download>SARIF</a>
              <a href="${withToken(`/api/scans/${id}/export.html`)}" download>HTML</a>
            </div>
          </details>
          <button class="actbtn danger" data-del="${id}">Delete</button>
        </div></td>
      </tr>`;
    });
    html += `</table></div>`;
    $("historyList").innerHTML = html;

    $("historyList").querySelectorAll("button[data-view]").forEach((b) =>
      b.addEventListener("click", () => openScan(b.dataset.view)));
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
  activateTab("host");
  $("target").value = target;
  if (!demandAuth()) return;
  if (_scanning) {
    _scanQueue.push(target);
    toast(`Queued ${target} — it will run next.`, "info");
    return;
  }
  runScan(target);
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

async function openScan(scanId) {
  try {
    const r = await fetch("/api/scans/" + scanId);
    if (!r.ok) throw new Error("not found");
    const result = await r.json();
    activateTab("host");
    setStatus("scanStatus", "Loaded stored scan " + scanId, false);
    hideProgress();
    renderResult(result, scanId);
    window.scrollTo({ top: 0, behavior: "smooth" });
  } catch (err) {
    toast("Could not open scan: " + err.message, "error");
  }
}

// ---- code scan ----------------------------------------------------------------------
$("codeForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const path = $("codePath").value.trim();
  if (!path) return;
  await runCode({ path, use_external: true });
});
$("codeTextBtn").addEventListener("click", async () => {
  const text = $("codeText").value;
  if (!text.trim()) return;
  await runCode({ text });
});

// File-upload dropzone (multipart, 2 MB cap — scanned in memory, never stored).
const MAX_UPLOAD = 2 * 1024 * 1024;
const dz = $("dropzone");
dz.addEventListener("click", () => $("codeFile").click());
dz.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("codeFile").click(); }
});
$("codeFile").addEventListener("change", (e) => {
  if (e.target.files && e.target.files[0]) uploadCodeFile(e.target.files[0]);
  e.target.value = "";
});
["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => {
  e.preventDefault();
  dz.classList.add("dragover");
}));
["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => {
  e.preventDefault();
  dz.classList.remove("dragover");
}));
dz.addEventListener("drop", (e) => {
  const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  if (f) uploadCodeFile(f);
});

async function uploadCodeFile(file) {
  if (file.size > MAX_UPLOAD) {
    toast(`“${file.name}” is too large — the limit is 2 MB.`, "error");
    return;
  }
  setStatus("codeStatus", `Scanning ${file.name}…`, false);
  $("codeResults").innerHTML = "";
  try {
    const fd = new FormData();
    fd.append("file", file);
    const r = await fetch("/api/code", { method: "POST", body: fd });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error(err.detail || r.statusText);
    }
    renderCode(await r.json());
  } catch (err) {
    setStatus("codeStatus", "Error: " + err.message, true);
    toast("Code scan failed: " + err.message, "error");
  }
}

async function runCode(body) {
  setStatus("codeStatus", "Scanning…", false);
  $("codeResults").innerHTML = "";
  try {
    const r = await fetch("/api/code", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error(err.detail || r.statusText);
    }
    renderCode(await r.json());
  } catch (err) {
    setStatus("codeStatus", "Error: " + err.message, true);
    toast("Code scan failed: " + err.message, "error");
  }
}

function renderCode(res) {
  setStatus("codeStatus",
    `Scanned ${res.files_scanned} file(s) · tools: ${(res.tools_used || []).join(", ")} · ${res.findings.length} finding(s)`,
    false);
  const finds = (res.findings || []).slice().sort((a, b) =>
    SEV_ORDER[b.severity] - SEV_ORDER[a.severity]);
  if (!finds.length) {
    $("codeResults").innerHTML = `<p class="empty empty-good">✓ No secrets or risky patterns found.</p>`;
    return;
  }
  let html = "";
  finds.forEach((f) => {
    html += `<div class="card ${f.severity}">
      <div class="row"><span class="title"><span class="badge sev-${f.severity}">${f.severity}</span> ${esc(f.title)}</span></div>
      <div class="meta">${esc(f.file)}:${f.line} &middot; ${esc(f.category)}/${esc(f.rule_id)}</div>
      ${f.evidence ? `<div class="desc">evidence: ${esc(f.evidence)}</div>` : ""}
      ${f.recommendation ? `<div class="fix">↳ ${esc(f.recommendation)}</div>` : ""}
    </div>`;
  });
  $("codeResults").innerHTML = html;
}

// ---- mail security ---------------------------------------------------------------------
$("mailForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const domain = $("mailDomain").value.trim();
  if (!domain) return;
  setStatus("mailStatus", "Checking e-mail security…", false);
  $("mailResults").innerHTML = "";
  try {
    const r = await fetch("/api/mailsec", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error(err.detail || r.statusText);
    }
    renderMail(await r.json());
  } catch (err) {
    setStatus("mailStatus", "Error: " + err.message, true);
    toast("Mail check failed: " + err.message, "error");
  }
});

const MAIL_STATUS = {
  ok:   { icon: "✓", cls: "ms-ok",   label: "OK" },
  warn: { icon: "⚠", cls: "ms-warn", label: "Fix" },
  bad:  { icon: "✗", cls: "ms-bad",  label: "Issue" },
  info: { icon: "ℹ", cls: "ms-info", label: "Info" },
};

function renderMail(info) {
  if (!info.checks || !info.checks.length) {
    setStatus("mailStatus", "No DNS answers for " + (info.domain || "") + ".", true);
    return;
  }
  const todo = info.checks.filter((c) => c.status === "warn" || c.status === "bad").length;
  setStatus("mailStatus",
    `${info.domain} · grade ${info.grade} (${info.score}/100) · ${todo} to fix`, false);

  const mx = (info.mx || []).join(", ") || "no MX";
  const reportUrl = withToken("/api/mailsec/report.html?domain=" + encodeURIComponent(info.domain || ""));
  let html = `<div class="mail-score grade-${esc((info.grade || "F")[0])}">
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
