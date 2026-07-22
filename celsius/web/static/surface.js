"use strict";

/* ============================================================================
   Celsius web UI — attack-surface graph: layered SVG map of what a scan saw
   (target → hosts → services → endpoints → findings), hand-rolled, no
   libraries, no build step. Loaded after scan.js; shares window.CELSIUS
   (see app.js). scan.js calls CELSIUS.surface.onScan(scanDict) from the
   loadScan / scan-completion path; the graph itself renders lazily when the
   "Attack surface" results-view toggle is activated.
   Untrusted scan data is always rendered through esc() — never raw HTML.
   ========================================================================== */

(function () {
  const C = window.CELSIUS;
  const $ = C.$;
  const esc = C.esc;

  // ---- layout constants (deterministic layered layout) ----------------------
  const COLS = ["target", "host", "service", "endpoint", "finding"];
  const COL_TITLE = {
    target: "Target", host: "Hosts", service: "Services",
    endpoint: "Endpoints", finding: "Findings",
  };
  const COL_W = 220;          // column x = index * COL_W
  const NODE_W = 180, NODE_H = 46, ROW_H = 58;
  const PILL_H = 30, PILL_ROW = 38;
  const PAD = 26, TOP = 46;   // TOP leaves room for the column titles

  // ---- graph caps ------------------------------------------------------------
  const EP_CAP = 40;          // per the brief: 40 endpoints, then "+N more"
  const HOST_CAP = 60, SVC_CAP = 40, FIND_CAP = 140;
  const TOTAL_CAP = 300;      // collapse the largest layer beyond this

  // Host part of a URL or bare host — mirrors hostOf() in scan.js / charts.js.
  function hostOf(u) {
    const m = /^(?:[a-z][a-z0-9+.-]*:\/\/)?([^/:?#]+)/i.exec(String(u || "").trim());
    return m ? m[1].toLowerCase() : "";
  }

  function cut(s, n) {
    s = String(s == null ? "" : s);
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }

  // Strip scheme+host off an endpoint that was stored as a full URL.
  function pathOf(ep) {
    ep = String(ep || "").trim();
    const m = /^[a-z][a-z0-9+.-]*:\/\/[^/]+(\/[^?#]*)?/i.exec(ep);
    return m ? (m[1] || "/") : ep;
  }

  /* ==========================================================================
     Step 1 — graph model: buildGraph(scanDict) → {nodes, edges}
     node: {id, kind, label, sub, sev, data, attach}  edge: {from, to}
     `attach` is the parent node's id; edges are derived from it.
     ======================================================================== */
  function buildGraph(scanDict) {
    const res = scanDict || {};
    const recon = res.recon || {};
    const nodes = [];
    const byId = {};

    function addNode(n) {
      n.id = n.kind[0] + nodes.length;
      nodes.push(n);
      byId[n.id] = n;
      return n;
    }

    // ---- target ---------------------------------------------------------------
    const targetHost = hostOf(res.url || res.target) || String(res.target || "target");
    const target = addNode({
      kind: "target", label: targetHost, sub: res.url || "",
      sev: null, attach: null,
      data: { target: res.target || "", url: res.url || "", ip: res.ip || "" },
      keys: [targetHost],
    });

    // topology: hostname → {ip, kind, org, …} — grounds host subs in real recon data.
    const topoByName = {};
    (((recon.topology) || {}).hosts || []).forEach((h) => {
      (h.hostnames || []).forEach((n) => { topoByName[String(n).toLowerCase()] = h; });
    });
    const oe = recon.origin_exposure || {};
    const exposedByHost = {};
    (oe.exposed || []).forEach((e) => {
      if (e && e.host) exposedByHost[String(e.host).toLowerCase()] = (e.origin_ips || []).join(", ");
    });

    // ---- hosts: subdomains + co-hosted siblings + exposed origins ----------------
    const hostSeen = new Set([targetHost]);
    const hostItems = [];
    function addHostItem(name, src) {
      const host = String(name || "").trim().toLowerCase();
      if (!host || hostSeen.has(host)) return;
      hostSeen.add(host);
      const t = topoByName[host];
      const originIps = exposedByHost[host] || "";
      const ip = (t && t.ip) || originIps || "";
      const flags = [];
      if (t && t.kind === "cdn") flags.push("CDN");
      if (originIps || (t && (t.kind === "home" || t.kind === "vps"))) flags.push("origin");
      hostItems.push({
        kind: "host", label: host, sub: [ip, flags.join("/")].filter(Boolean).join(" · "),
        sev: null, attach: target.id, keys: [host],
        data: { source: src, ip: ip, kind: (t && t.kind) || "", org: (t && (t.org || t.isp)) || "" },
      });
    }
    (recon.subdomains || []).forEach((s) => addHostItem(s, "subdomain"));
    (((recon.cohosted) || {}).siblings || []).forEach((s) => addHostItem(s, "co-hosted"));
    Object.keys(exposedByHost).forEach((h) => addHostItem(h, "exposed origin"));
    hostItems.sort((a, b) => a.label.localeCompare(b.label));

    // ---- services ----------------------------------------------------------------
    const svcItems = (res.services || []).map((s) => {
      const name = String(s.name || "service");
      const label = name + (s.version ? " " + s.version : "");
      const port = s.port ? `${s.port}/${s.protocol || "tcp"}` : "";
      return {
        kind: "service", label, sub: [port, s.source || ""].filter(Boolean).join(" · "),
        sev: null, attach: target.id, keys: [name.toLowerCase(), label.toLowerCase()],
        data: {
          name, version: s.version || "", port: s.port != null ? s.port : "",
          protocol: s.protocol || "", source: s.source || "", product: s.product || "",
        },
      };
    }).sort((a, b) => a.label.localeCompare(b.label));

    // ---- endpoints: crawl + routes + API discovery -------------------------------
    const epSeen = new Set();
    const epItems = [];
    function addEndpoint(raw, src) {
      const path = pathOf(raw);
      if (!path || epSeen.has(path)) return;
      epSeen.add(path);
      const full = String(raw || "");
      epItems.push({
        kind: "endpoint", label: path, sub: src, sev: null, attach: target.id,
        keys: [path, full.toLowerCase()].filter((k) => k && k.length >= 3),
        data: { source: src, url: full },
      });
    }
    const crawl = recon.crawl || {};
    (crawl.endpoints || []).forEach((e) => addEndpoint(e, "crawl"));
    (crawl.routes || []).forEach((e) => addEndpoint(e, "route"));
    const api = recon.api || {};
    (api.endpoints || []).forEach((e) => addEndpoint(e, "api"));
    if (api.openapi) (api.openapi.paths || []).forEach((p) => addEndpoint(p, "openapi"));
    if (api.graphql && api.graphql.url) addEndpoint(api.graphql.url, "graphql");
    epItems.sort((a, b) => a.label.localeCompare(b.label));

    // ---- findings: severity-colored pills pinned to the node they mention --------
    const findItems = (res.findings || [])
      .filter((f) => f.category !== "ai-hypothesis") // leads, not surface — same rule as the counts
      .map((f) => ({
        kind: "finding", label: String(f.title || "finding"), sub: f.category || "",
        sev: f.severity || "INFO", attach: null, keys: [],
        data: {
          severity: f.severity || "INFO", category: f.category || "",
          title: f.title || "", description: f.description || "",
          evidence: f.evidence || "", recommendation: f.recommendation || "",
        },
        _hay: (String(f.evidence || "") + " " + String(f.description || "")).toLowerCase(),
      }))
      .sort((a, b) => (C.sevRank(b.sev) - C.sevRank(a.sev)) || a.label.localeCompare(b.label));

    // ---- per-layer caps with a single "+N more" aggregate node --------------------
    const aggregates = [];
    function capLayer(items, cap, plural) {
      if (items.length <= cap) return items;
      const kept = items.slice(0, cap);
      const hidden = items.slice(cap);
      aggregates.push({
        kind: items[0].kind, label: `+${hidden.length} more ${plural}`, sub: "collapsed",
        sev: null, attach: target.id, aggregate: true, keys: [],
        data: { hidden: hidden.length, examples: hidden.slice(0, 10).map((i) => i.label).join(", ") },
      });
      return kept;
    }
    const hosts = capLayer(hostItems, HOST_CAP, "hosts");
    const services = capLayer(svcItems, SVC_CAP, "services");
    const endpoints = capLayer(epItems, EP_CAP, "endpoints");
    const finds = capLayer(findItems, FIND_CAP, "findings");

    // Endpoints stored as full URLs pin to their host node when we have one.
    endpoints.forEach((ep) => {
      const h = hostOf(ep.data.url);
      if (!h || h === targetHost) return;
      const hn = hosts.find((n) => !n.aggregate && n.label === h);
      if (hn) ep._pin = hn; // resolved to an id once nodes are registered below
    });

    // Register everything (ids are assigned here), then wire attachments.
    [hosts, services, endpoints, finds].forEach((layer) => layer.forEach(addNode));
    aggregates.forEach((n) => addNode(n));
    endpoints.forEach((ep) => { if (ep._pin) ep.attach = ep._pin.id; });

    // Attach findings to the node whose label/host appears in their
    // evidence/description — most specific layer first, longest key wins.
    const matchPools = [endpoints, services, hosts].map((pool) =>
      pool.filter((n) => !n.aggregate)
        .map((n) => ({ node: n, keys: (n.keys || []).filter((k) => k.length >= 3) })));
    finds.forEach((f) => {
      let hit = null;
      for (const pool of matchPools) {
        if (hit) break;
        let bestLen = 0;
        pool.forEach(({ node, keys }) => {
          keys.forEach((k) => {
            if (k.length > bestLen && f._hay.includes(k)) { hit = node; bestLen = k.length; }
          });
        });
      }
      f.attach = (hit || target).id;
    });

    // ---- total cap ~300: collapse the largest layer into its "+N more" node -------
    function layerNodes(kind) { return nodes.filter((n) => n.kind === kind && !n.aggregate); }
    ["host", "service", "endpoint", "finding"].forEach((kind) => {
      while (nodes.length > TOTAL_CAP && layerNodes(kind).length > 4) {
        const pool = layerNodes(kind);
        const drop = pool.slice(Math.ceil(pool.length / 2));
        const dropIds = new Set(drop.map((n) => n.id));
        drop.forEach((n) => {
          nodes.splice(nodes.indexOf(n), 1);
          delete byId[n.id];
        });
        // survivors pinned to a dropped node fall back to the target
        nodes.forEach((n) => { if (dropIds.has(n.attach)) n.attach = target.id; });
        let agg = nodes.find((n) => n.kind === kind && n.aggregate);
        if (!agg) {
          agg = addNode({
            kind, label: "", sub: "collapsed", sev: null, attach: target.id,
            aggregate: true, keys: [], data: { hidden: 0, examples: "" },
          });
        }
        agg.data.hidden += drop.length;
        agg.data.examples = drop.slice(0, 10).map((i) => i.label).join(", ");
        agg.label = `+${agg.data.hidden} more ${COL_TITLE[kind].toLowerCase()}`;
      }
    });

    const edges = [];
    nodes.forEach((n) => {
      if (n.attach && byId[n.attach]) edges.push({ from: n.attach, to: n.id });
    });
    return { nodes, edges };
  }

  /* ==========================================================================
     Step 2 — layered SVG renderer
     ======================================================================== */
  const SEV_CLASS = { CRITICAL: "sev-CRITICAL", HIGH: "sev-HIGH", MEDIUM: "sev-MEDIUM", LOW: "sev-LOW", INFO: "sev-INFO" };
  // CSS var / chip suffix per severity (--crit, .chip-crit, …)
  const SEV_SHORT = { CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low", INFO: "info" };

  function layout(graph) {
    const byCol = {};
    COLS.forEach((k) => { byCol[k] = []; });
    graph.nodes.forEach((n) => byCol[n.kind].push(n));
    let height = TOP + NODE_H + PAD;
    COLS.forEach((kind, ci) => {
      const rh = kind === "finding" ? PILL_ROW : ROW_H;
      byCol[kind].forEach((n, i) => {
        n.x = PAD + ci * COL_W;
        n.y = TOP + i * rh;
        n.w = NODE_W;
        n.h = kind === "finding" ? PILL_H : NODE_H;
      });
      height = Math.max(height, TOP + byCol[kind].length * rh + PAD);
    });
    return { byCol, width: PAD * 2 + COLS.length * COL_W, height };
  }

  function render(scanDict) {
    const wrap = $("surfaceGraph");
    const detail = $("surfaceDetail");
    if (!wrap) return;
    const graph = buildGraph(scanDict);
    const { byCol, width, height } = layout(graph);
    const byId = {};
    graph.nodes.forEach((n) => { byId[n.id] = n; });
    // node → attached findings, for the detail pane
    const findsByNode = {};
    graph.nodes.forEach((n) => {
      if (n.kind === "finding" && !n.aggregate) {
        (findsByNode[n.attach] = findsByNode[n.attach] || []).push(n);
      }
    });

    // ---- edges (cubic beziers, right edge of parent → left edge of child) ----
    let edgeSvg = "";
    graph.edges.forEach((e) => {
      const p = byId[e.from], c = byId[e.to];
      if (!p || !c) return;
      const x1 = p.x + p.w, y1 = p.y + p.h / 2;
      const x2 = c.x, y2 = c.y + c.h / 2;
      const mx = (x1 + x2) / 2;
      edgeSvg += `<path class="sg-edge" d="M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}"/>`;
    });

    // ---- column titles ---------------------------------------------------------
    let titleSvg = "";
    COLS.forEach((kind, ci) => {
      const n = byCol[kind].length;
      if (!n && kind !== "target") return;
      titleSvg += `<text class="sg-col-title" x="${PAD + ci * COL_W}" y="${TOP - 16}">${COL_TITLE[kind]} (${n})</text>`;
    });

    // ---- nodes -------------------------------------------------------------------
    let nodeSvg = "";
    graph.nodes.forEach((n) => {
      const isPill = n.kind === "finding";
      const cls = ["sg-node", "k-" + n.kind, isPill ? "sg-pill" : "",
        n.aggregate ? "sg-agg" : "", isPill ? (SEV_CLASS[n.sev] || "sev-INFO") : ""]
        .filter(Boolean).join(" ");
      const rx = isPill ? n.h / 2 : 10;
      const cx = n.x + n.w / 2;
      if (isPill) {
        nodeSvg += `<g class="${cls}" data-id="${n.id}" data-kind="${n.kind}" tabindex="0"
            role="button" aria-label="${esc(n.sev)}: ${esc(n.label)}">
          <rect x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" rx="${rx}"/>
          <text x="${cx}" y="${n.y + n.h / 2 + 3.5}" text-anchor="middle">${esc(cut(n.label, 30))}</text>
        </g>`;
      } else {
        nodeSvg += `<g class="${cls}" data-id="${n.id}" data-kind="${n.kind}" tabindex="0"
            role="button" aria-label="${esc(n.kind)}: ${esc(n.label)}">
          <rect x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" rx="${rx}"/>
          <text x="${cx}" y="${n.y + 19}" text-anchor="middle">${esc(cut(n.label, 26))}</text>
          <text class="sg-sub" x="${cx}" y="${n.y + 34}" text-anchor="middle">${esc(cut(n.sub, 30))}</text>
        </g>`;
      }
    });

    // ---- legend + hint -------------------------------------------------------------
    const counts = COLS.map((k) => `${byCol[k].length} ${COL_TITLE[k].toLowerCase()}`).join(" · ");
    const sevDots = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
      .filter((s) => graph.nodes.some((n) => n.kind === "finding" && n.sev === s))
      .map((s) => `<span class="dot" style="background:var(--${SEV_SHORT[s]})"></span>${s.charAt(0) + s.slice(1).toLowerCase()}`)
      .join("");
    const sparse = !byCol.host.length && !byCol.service.length && !byCol.endpoint.length;
    const legend = `<div class="sg-toolbar">
      <span class="sg-legend">
        <span class="sg-lg"><i class="sg-sw k-target"></i>Target</span>
        <span class="sg-lg"><i class="sg-sw k-host"></i>Host</span>
        <span class="sg-lg"><i class="sg-sw k-service"></i>Service</span>
        <span class="sg-lg"><i class="sg-sw k-endpoint"></i>Endpoint</span>
        ${sevDots ? `<span class="sg-sep">·</span>${sevDots}` : ""}
      </span>
      <span class="sg-hint">${esc(counts)} · drag to pan · wheel to zoom · double-click to reset</span>
    </div>`;

    wrap.innerHTML = legend
      + `<svg viewBox="0 0 ${width} ${height}" role="img"
          aria-label="Attack surface graph — ${esc(counts)}">
        <title>Attack surface graph</title>
        <g class="sg-edges">${edgeSvg}</g>
        <g class="sg-titles">${titleSvg}</g>
        <g class="sg-nodes">${nodeSvg}</g>
      </svg>`;

    const svg = wrap.querySelector("svg");

    // ---- pan (drag) + zoom (wheel) via the viewBox; double-click resets ----------
    // Fit the scene to the element with the viewBox aspect matched to the element
    // aspect — no letterboxing, so mouse → viewBox mapping stays exact.
    const cw = svg.clientWidth || width, ch = svg.clientHeight || height;
    const fit = Math.max(width / cw, height / ch);
    const vb0 = {
      x: (width - fit * cw) / 2, y: (height - fit * ch) / 2,
      w: fit * cw, h: fit * ch,
    };
    const vb = { ...vb0 };
    function applyVb() { svg.setAttribute("viewBox", `${vb.x} ${vb.y} ${vb.w} ${vb.h}`); }
    applyVb();
    let dragging = false, sx = 0, sy = 0, moved = 0;
    svg.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      dragging = true; moved = 0; sx = e.clientX; sy = e.clientY;
      svg.setPointerCapture(e.pointerId);
    });
    svg.addEventListener("pointermove", (e) => {
      if (!dragging) return;
      const scale = vb.w / (svg.clientWidth || 1);
      const dx = (e.clientX - sx) * scale, dy = (e.clientY - sy) * scale;
      moved += Math.abs(dx) + Math.abs(dy);
      vb.x -= dx; vb.y -= dy;
      sx = e.clientX; sy = e.clientY;
      applyVb();
    });
    ["pointerup", "pointercancel"].forEach((ev) =>
      svg.addEventListener(ev, () => { dragging = false; }));
    svg.addEventListener("wheel", (e) => {
      e.preventDefault();
      const rect = svg.getBoundingClientRect();
      const fx = (e.clientX - rect.left) / (rect.width || 1);
      const fy = (e.clientY - rect.top) / (rect.height || 1);
      const k = e.deltaY > 0 ? 1.15 : 1 / 1.15;
      const nw = Math.min(vb0.w * 3, Math.max(vb0.w * 0.12, vb.w * k));
      const nh = nw * (vb0.h / vb0.w);
      vb.x = vb.x + fx * (vb.w - nw);
      vb.y = vb.y + fy * (vb.h - nh);
      vb.w = nw; vb.h = nh;
      applyVb();
    }, { passive: false });
    svg.addEventListener("dblclick", () => { Object.assign(vb, vb0); applyVb(); });

    // ---- click / keyboard → detail pane ------------------------------------------
    function select(id) {
      const n = byId[id];
      if (!n) return;
      svg.querySelectorAll(".sg-node.sel").forEach((g) => g.classList.remove("sel"));
      const g = svg.querySelector(`.sg-node[data-id="${id}"]`);
      if (g) g.classList.add("sel");
      showDetail(n);
    }
    svg.addEventListener("click", (e) => {
      if (moved > 6) { moved = 0; return; } // was a pan drag, not a click
      // pointer capture (for panning) retargets the click to the svg root —
      // hit-test the click point instead of trusting e.target.
      const el = document.elementFromPoint(e.clientX, e.clientY) || e.target;
      const g = el && el.closest ? el.closest(".sg-node") : null;
      if (g) select(g.dataset.id);
    });
    svg.addEventListener("keydown", (e) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      const g = e.target.closest ? e.target.closest(".sg-node") : null;
      if (g) { e.preventDefault(); select(g.dataset.id); }
    });

    function showDetail(n) {
      if (!detail) return;
      const rows = Object.entries(n.data || {})
        .filter(([, v]) => v !== "" && v != null)
        .map(([k, v]) => `<div class="sd-kv"><span class="sd-k">${esc(k)}</span><span class="sd-v">${esc(v)}</span></div>`)
        .join("");
      let findsHtml = "";
      const attached = findsByNode[n.id] || [];
      if (attached.length) {
        findsHtml = `<h4 class="sd-sub">Attached findings (${attached.length})</h4><ul class="sd-finds">`
          + attached.map((f) => `<li><span class="chip chip-${SEV_SHORT[f.sev] || "info"}">${esc(f.sev)}</span>
              <strong>${esc(f.data.title)}</strong>
              ${f.data.description ? `<div class="sd-desc">${esc(cut(f.data.description, 180))}</div>` : ""}</li>`).join("")
          + `</ul>`;
      }
      detail.innerHTML = `<div class="sd-head">
          <span class="sd-kind k-${esc(n.kind)}">${esc(n.kind)}</span>
          <strong class="sd-label">${esc(n.label)}</strong>
          ${n.sub ? `<span class="sd-subline">${esc(n.sub)}</span>` : ""}
        </div>
        ${rows ? `<div class="sd-data">${rows}</div>` : ""}
        ${findsHtml}`;
      detail.classList.remove("hidden");
    }

    // ---- initial detail content: note / hint --------------------------------------
    if (detail) {
      detail.classList.remove("hidden");
      detail.innerHTML = sparse
        ? `<p class="surface-note">Only the target is visible — run a deeper scan
           (subdomains / crawl / API discovery) to map the attack surface.</p>`
        : `<p class="surface-note">Click a node for details — findings are pinned to the
           host, service or endpoint they mention.</p>`;
    }
    if (sparse) {
      svg.insertAdjacentHTML("beforeend",
        `<text class="sg-col-title" x="${PAD}" y="${height - 8}">No recon data — target only.</text>`);
    }
  }

  /* ==========================================================================
     Step 3 — results integration: Findings | Attack surface segmented toggle.
     ======================================================================== */
  let _scan = null;   // last scan dict seen via onScan
  let _dirty = true;  // graph stale → re-render on next activation
  let _view = "findings";

  function setView(name) {
    _view = name;
    const results = $("results"), surfaceView = $("surfaceView");
    const fb = $("viewFindings"), sb = $("viewSurface");
    if (!results || !surfaceView || !fb || !sb) return;
    const isSurface = name === "surface";
    results.classList.toggle("hidden", isSurface);
    surfaceView.classList.toggle("hidden", !isSurface);
    fb.classList.toggle("active", !isSurface);
    sb.classList.toggle("active", isSurface);
    fb.setAttribute("aria-selected", isSurface ? "false" : "true");
    sb.setAttribute("aria-selected", isSurface ? "true" : "false");
    if (isSurface && _dirty && _scan) {
      render(_scan);
      _dirty = false;
    }
  }

  // Called by scan.js from the loadScan / scan-completion path (mirror of
  // CELSIUS.charts.render). Reveals the toggle; re-renders at once when the
  // surface view is active, otherwise lazily on the next activation.
  function onScan(scanDict) {
    _scan = scanDict;
    _dirty = true;
    const toggle = $("resultsToggle");
    if (toggle) toggle.classList.remove("hidden");
    if (_view === "surface") {
      render(_scan);
      _dirty = false;
    }
  }

  C.onInit(function () {
    const fb = $("viewFindings"), sb = $("viewSurface");
    if (fb) fb.addEventListener("click", () => setView("findings"));
    if (sb) sb.addEventListener("click", () => setView("surface"));
  });

  C.surface = { render, onScan, buildGraph, setView };
})();
