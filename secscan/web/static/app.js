"use strict";

const $ = (id) => document.getElementById(id);
const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
let lastUrl = null; // url of last scan, for PoC context

// ---- theme (light / dark) ----------------------------------------------------
(function initTheme() {
  const KEY = "celsius_theme";
  const root = document.documentElement;
  function apply(theme) {
    root.setAttribute("data-theme", theme);
    const btn = $("themeToggle");
    if (btn) btn.textContent = theme === "light" ? "☾" : "☀"; // ☾ / ☀
  }
  let saved = null;
  try { saved = localStorage.getItem(KEY); } catch (e) { /* private mode */ }
  apply(saved === "light" ? "light" : "dark"); // dark by default; light is opt-in
  document.addEventListener("click", (e) => {
    if (e.target && e.target.id === "themeToggle") {
      const next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      apply(next);
      try { localStorage.setItem(KEY, next); } catch (_) { /* ignore */ }
    }
  });
})();

// ---- tabs --------------------------------------------------------------------
document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    $("tab-" + t.dataset.tab).classList.add("active");
    if (t.dataset.tab === "history") loadHistory();
  });
});

// ---- mail security -----------------------------------------------------------
$("mailForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const domain = $("mailDomain").value.trim();
  if (!domain) return;
  setStatus("mailStatus", "Kontrollerar e-postsäkerhet…", false);
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
    setStatus("mailStatus", "Fel: " + err.message, true);
  }
});

const MAIL_STATUS = {
  ok:   { icon: "✅", cls: "ms-ok",   label: "OK" },
  warn: { icon: "⚠️", cls: "ms-warn", label: "Åtgärda" },
  bad:  { icon: "❌", cls: "ms-bad",  label: "Brist" },
  info: { icon: "ℹ️", cls: "ms-info", label: "Info" },
};

function renderMail(info) {
  if (!info.checks || !info.checks.length) {
    setStatus("mailStatus", "Inga DNS-svar för " + esc(info.domain || "") + ".", true);
    return;
  }
  const todo = info.checks.filter((c) => c.status === "warn" || c.status === "bad").length;
  setStatus("mailStatus",
    `${info.domain} · betyg ${info.grade} (${info.score}/100) · ${todo} att åtgärda`, false);

  const mx = (info.mx || []).join(", ") || "ingen MX";
  const reportUrl = "/api/mailsec/report.html?domain=" + encodeURIComponent(info.domain || "");
  let html = `<div class="mail-score grade-${(info.grade || "F")[0]}">
      <div class="grade">${esc(info.grade)}</div>
      <div class="score"><strong>${info.score}</strong>/100</div>
      <div class="mx">Mailserver: ${esc(mx)}${info.provider ? " · " + esc(info.provider) : ""}
        <br><a class="reportlink" href="${reportUrl}" target="_blank">📄 HTML-rapport</a></div>
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

// ---- authorization gate ------------------------------------------------------
$("authorized").addEventListener("change", (e) => {
  $("authbar").classList.toggle("ok", e.target.checked);
});

// ---- AI key: remember in the browser (localStorage) --------------------------
try {
  const savedKey = localStorage.getItem("secscan_ai_key");
  if (savedKey) $("opt-ai-key").value = savedKey;
} catch (e) { /* localStorage may be unavailable */ }
$("opt-ai-key").addEventListener("change", (e) => {
  try { localStorage.setItem("secscan_ai_key", e.target.value); } catch (_) {}
});

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

const VERDICT_CLASS = {
  "likely-exploitable": "v-high", "conditions-needed": "v-med",
  "not-in-context": "v-low", "unknown": "v-unk", "informational": "v-info",
};
function verdictBadge(ex) {
  if (!ex || !ex.verdict || ex.verdict === "informational") return "";
  const cls = VERDICT_CLASS[ex.verdict] || "v-unk";
  return ` <span class="verdict ${cls}" title="exploitability verdict">${esc(ex.verdict)}</span>`;
}
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

// ---- host/web scan -----------------------------------------------------------
$("scanForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!$("authorized").checked) {
    alert("Please confirm you are authorized to scan this target.");
    return;
  }
  const target = $("target").value.trim();
  if (!target) return;

  $("scanBtn").disabled = true;
  $("results").innerHTML = "";
  $("summary").classList.add("hidden");
  setStatus("scanStatus", "Starting scan…", false);
  $("scanLog").classList.remove("hidden");
  $("scanLog").textContent = "";

  try {
    const resp = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target, authorized: true,
        web: $("opt-web").checked, cve: $("opt-cve").checked,
        web_secrets: $("opt-secrets").checked, ports: $("opt-ports").checked,
        nuclei: $("opt-nuclei").checked,
        dns: $("opt-dns").checked, tls: $("opt-tls").checked,
        fingerprint: $("opt-fingerprint").checked, subdomains: $("opt-subdomains").checked,
        crawl: $("opt-crawl").checked, api_discovery: $("opt-apidisco").checked,
        cve_verify: $("opt-cveverify").checked,
        ai: $("opt-ai").checked, ai_provider: $("opt-ai-provider").value,
        ai_api_key: $("opt-ai-key").value.trim() || null,
      }),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || resp.statusText);
    }
    const { job_id } = await resp.json();
    pollJob(job_id);
  } catch (err) {
    setStatus("scanStatus", "Error: " + err.message, true);
    $("scanBtn").disabled = false;
  }
});

async function pollJob(jobId) {
  try {
    const r = await fetch("/api/scan/" + jobId);
    const job = await r.json();
    $("scanLog").textContent = (job.log || []).join("\n");
    $("scanLog").scrollTop = $("scanLog").scrollHeight;

    if (job.status === "running") {
      setStatus("scanStatus", "Scanning… " + ((job.log || []).slice(-1)[0] || ""), false);
      setTimeout(() => pollJob(jobId), 800);
    } else if (job.status === "done") {
      setStatus("scanStatus", "Scan complete.", false);
      $("scanBtn").disabled = false;
      renderResult(job.result, job.scan_id);
    } else {
      setStatus("scanStatus", "Scan failed: " + (job.error || "unknown"), true);
      $("scanBtn").disabled = false;
    }
  } catch (err) {
    setStatus("scanStatus", "Error polling job: " + err.message, true);
    $("scanBtn").disabled = false;
  }
}

function setStatus(id, msg, isErr) {
  const el = $(id);
  el.classList.remove("hidden");
  el.classList.toggle("err", !!isErr);
  el.textContent = msg;
}

function renderResult(res, scanId) {
  lastUrl = res.url || res.target;
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  (res.cves || []).forEach((c) => counts[c.severity]++);
  (res.findings || []).forEach((f) => counts[f.severity]++);

  const sum = $("summary");
  sum.classList.remove("hidden");
  sum.innerHTML = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    .map((s) => `<span class="chip sev-${s}">${s} ${counts[s]}</span>`).join("")
    + (scanId ? `<a class="reportlink" href="/api/scans/${encodeURIComponent(scanId)}/report.html" target="_blank">📄 HTML-rapport</a>` : "");

  let html = "";

  // Exploit chains — headline correlated attack paths
  const chains = res.chains || [];
  if (chains.length) {
    html += `<h2 class="section">⛓️ Exploit chains (${chains.length})</h2>`;
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

  html += `<h2 class="section">Target</h2>
    <div class="card INFO"><div class="meta">target: ${esc(res.target)} &middot; url: ${esc(res.url || "-")} &middot; ip: ${esc(res.ip || "-")}</div></div>`;

  // services
  html += `<h2 class="section">Detected services (${(res.services || []).length})</h2>`;
  if ((res.services || []).length) {
    html += `<table class="svc"><tr><th>Product</th><th>Version</th><th>Port</th><th>Source</th></tr>`;
    res.services.forEach((s) => {
      html += `<tr><td>${esc(s.name)}</td><td>${esc(s.version || "?")}</td><td>${s.port || ""}</td><td>${esc(s.source)}</td></tr>`;
    });
    html += `</table>`;
  } else html += `<p class="empty">none</p>`;

  // Recon (attack surface)
  const recon = res.recon || {};
  const hasRecon = recon.tls || recon.dns || (recon.subdomains && recon.subdomains.length) || (recon.tech && recon.tech.length);
  if (hasRecon) {
    html += `<h2 class="section">Attack surface</h2>`;
    if (recon.tls && recon.tls.protocol) {
      const t = recon.tls;
      html += `<div class="card INFO"><div class="title">TLS</div>
        <div class="meta">${esc(t.protocol)} · ${esc(t.cipher || "")} · issuer: ${esc(t.issuer || "?")} · expires in ${t.days_to_expiry != null ? t.days_to_expiry + "d" : "?"}</div></div>`;
    }
    if (recon.dns && recon.dns.records) {
      const r = recon.dns.records;
      const line = ["A", "AAAA", "MX", "NS"].filter((k) => r[k]).map((k) => `${k}: ${r[k].slice(0, 3).join(", ")}`).join(" · ");
      html += `<div class="card INFO"><div class="title">DNS</div><div class="meta">${esc(line)}</div></div>`;
    }
    if (recon.tech && recon.tech.length) {
      html += `<div class="card INFO"><div class="title">Technologies</div><div class="meta">${recon.tech.map((t) => esc(t.name + (t.version ? " " + t.version : "") + " [" + t.category + "]")).join(" · ")}</div></div>`;
    }
    if (recon.subdomains && recon.subdomains.length) {
      html += `<div class="card INFO"><div class="title">Subdomains (${recon.subdomains.length})</div><div class="meta">${recon.subdomains.slice(0, 40).map(esc).join(", ")}${recon.subdomains.length > 40 ? " …" : ""}</div></div>`;
    }
    if (recon.crawl) {
      const c = recon.crawl;
      html += `<div class="card INFO"><div class="title">Crawl</div>
        <div class="meta">${c.pages} page(s) · ${c.js_files} JS file(s) · ${(c.endpoints||[]).length} endpoint(s) · ${(c.routes||[]).length} route(s)${c.recovered_sources ? " · " + c.recovered_sources + " recovered source(s)" : ""}</div>
        ${(c.endpoints||[]).length ? `<div class="meta">endpoints: ${c.endpoints.slice(0,25).map(esc).join(", ")}</div>` : ""}</div>`;
    }
    if (recon.api && (recon.api.openapi || recon.api.graphql)) {
      const a = recon.api;
      const bits = [];
      if (a.openapi) bits.push(`OpenAPI: ${esc(a.openapi.url)} (${(a.openapi.paths||[]).length} paths)`);
      if (a.graphql) bits.push(`GraphQL introspection: ${esc(a.graphql.url)} (${a.graphql.types} types)`);
      html += `<div class="card INFO"><div class="title">API</div><div class="meta">${bits.join(" · ")}</div></div>`;
    }
  }

  // CVEs
  const cves = (res.cves || []).slice().sort((a, b) =>
    (SEV_ORDER[b.severity] - SEV_ORDER[a.severity]) || ((b.cvss || 0) - (a.cvss || 0)));
  html += `<h2 class="section">Known CVEs (${cves.length})</h2>`;
  if (cves.length) {
    cves.forEach((c, i) => {
      const verified = c.verified ? ` <span class="verdict v-high">✔ VERIFIED</span>` : "";
      const pocs = (c.references || []).filter((r) => r.poc).slice(0, 4);
      const pocHtml = pocs.length
        ? `<div class="meta">PoC: ${pocs.map((r) => `<a href="${esc(r.url)}" target="_blank">${esc(shortUrl(r.url))}</a>`).join(" · ")}</div>`
        : "";
      html += `<div class="card ${c.severity}">
        <div class="row">
          <span class="title"><span class="badge sev-${c.severity}">${c.severity}</span>
            <a href="${esc(c.url)}" target="_blank">${esc(c.id)}</a>
            &nbsp;CVSS ${c.cvss == null ? "-" : c.cvss}${verdictBadge(c.exploitability)}${verified}</span>
          <button class="pocBtn" data-poc="cve" data-i="${i}">how-to</button>
        </div>
        <div class="meta">affects: ${esc(c.affects)}${exploitMeta(c.exploitability)}</div>
        ${pocHtml}
        <div class="desc">${esc((c.description || "").slice(0, 240))}</div>
      </div>`;
    });
  } else html += `<p class="empty">none found for detected versions</p>`;

  // findings
  const finds = (res.findings || []).slice().sort((a, b) =>
    SEV_ORDER[b.severity] - SEV_ORDER[a.severity]);
  html += `<h2 class="section">Web / config findings (${finds.length})</h2>`;
  if (finds.length) {
    finds.forEach((f, i) => {
      const conf = f.confidence ? ` <span class="conf">confidence: ${esc(f.confidence)}</span>` : "";
      const aiTag = f.category && f.category.startsWith("ai") ? ' <span class="ai-tag">AI</span>' : "";
      html += `<div class="card ${f.severity}">
        <div class="row">
          <span class="title"><span class="badge sev-${f.severity}">${f.severity}</span> ${esc(f.title)}${aiTag}${verdictBadge(f.exploitability)}</span>
          <button class="pocBtn" data-poc="finding" data-i="${i}">how-to</button>
        </div>
        <div class="meta">[${esc(f.category)}]${conf}</div>
        <div class="desc">${esc(f.description)}</div>
        ${f.recommendation ? `<div class="fix">↳ ${esc(f.recommendation)}</div>` : ""}
        ${f.evidence ? `<div class="meta">evidence: ${esc(f.evidence)}</div>` : ""}
      </div>`;
    });
  } else html += `<p class="empty">none</p>`;

  if ((res.errors || []).length) {
    html += `<h2 class="section">Notes</h2>`;
    res.errors.forEach((e) => { html += `<div class="meta">! ${esc(e)}</div>`; });
  }

  $("results").innerHTML = html;
  // wire PoC buttons
  $("results").querySelectorAll(".pocBtn").forEach((b) => {
    b.addEventListener("click", () => {
      const kind = b.dataset.poc;
      const item = kind === "cve" ? cves[+b.dataset.i] : finds[+b.dataset.i];
      showPoc(kind, item, item.exploitability);
    });
  });
}

// ---- PoC modal ---------------------------------------------------------------
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
    $("pocModal").classList.remove("hidden");
  } catch (err) {
    alert("Could not load PoC: " + err.message);
  }
}
$("pocClose").addEventListener("click", () => $("pocModal").classList.add("hidden"));
$("pocModal").addEventListener("click", (e) => {
  if (e.target.id === "pocModal") $("pocModal").classList.add("hidden");
});

// ---- history -----------------------------------------------------------------
const SEV_RANK_NAME = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

async function loadHistory() {
  const filter = $("historyFilter").value.trim();
  const q = filter ? "?target=" + encodeURIComponent(filter) : "";
  try {
    const r = await fetch("/api/scans" + q);
    const { scans } = await r.json();
    if (!scans.length) {
      $("historyList").innerHTML = `<p class="empty">No scans recorded yet.</p>`;
      return;
    }
    let html = `<table class="svc"><tr><th>When</th><th>Target</th><th>Worst</th><th>CVE</th><th>Findings</th><th></th></tr>`;
    scans.forEach((s) => {
      const sev = s.worst && s.worst !== "NONE" ? s.worst : "INFO";
      html += `<tr>
        <td>${esc(s.finished_at || "-")}</td>
        <td>${esc(s.target)}</td>
        <td><span class="badge sev-${sev}">${esc(s.worst || "-")}</span></td>
        <td>${s.n_cves}</td><td>${s.n_findings}</td>
        <td><button class="pocBtn" data-scan="${esc(s.id)}">open</button></td>
      </tr>`;
    });
    html += `</table>`;
    $("historyList").innerHTML = html;
    $("historyList").querySelectorAll("button[data-scan]").forEach((b) => {
      b.addEventListener("click", () => openScan(b.dataset.scan));
    });
  } catch (err) {
    $("historyList").innerHTML = `<p class="empty">Error loading history: ${esc(err.message)}</p>`;
  }
}

async function openScan(scanId) {
  try {
    const r = await fetch("/api/scans/" + scanId);
    if (!r.ok) throw new Error("not found");
    const result = await r.json();
    // switch to host tab and render the stored result
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((x) => x.classList.remove("active"));
    document.querySelector('.tab[data-tab="host"]').classList.add("active");
    $("tab-host").classList.add("active");
    setStatus("scanStatus", "Loaded stored scan " + scanId, false);
    $("scanLog").classList.add("hidden");
    renderResult(result, scanId);
  } catch (err) {
    alert("Could not open scan: " + err.message);
  }
}

$("refreshHistory").addEventListener("click", loadHistory);

// ---- code scan ---------------------------------------------------------------
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
    const res = await r.json();
    renderCode(res);
  } catch (err) {
    setStatus("codeStatus", "Error: " + err.message, true);
  }
}

function renderCode(res) {
  setStatus("codeStatus",
    `Scanned ${res.files_scanned} file(s) · tools: ${(res.tools_used || []).join(", ")} · ${res.findings.length} finding(s)`,
    false);
  const finds = (res.findings || []).slice().sort((a, b) =>
    SEV_ORDER[b.severity] - SEV_ORDER[a.severity]);
  if (!finds.length) {
    $("codeResults").innerHTML = `<p class="empty">No secrets or risky patterns found.</p>`;
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
