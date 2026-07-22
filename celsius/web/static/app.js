"use strict";

/* ============================================================================
   Celsius web UI — shell: namespace, utils, tab router, theme, auth/token bar.
   Vanilla JS, no build step. Feature modules (scan.js, …) load after this file,
   share window.CELSIUS and register their init via CELSIUS.onInit(fn).
   Untrusted scan data is always rendered through esc() — never raw HTML.
   ========================================================================== */

window.CELSIUS = (function () {
  const C = {};

  // ---- shared state -----------------------------------------------------------
  // token: access token for CELSIUS_TOKEN-protected servers (mirrors the
  // #accessToken input). authorized: mirrors the #authorized checkbox.
  // currentScan: {id, result} of the scan shown in the Results view.
  // jobs: running/recent scan jobs (populated by the jobs drawer, Task 4+).
  C.state = { token: "", authorized: false, currentScan: null, jobs: [] };

  // ---- small utils --------------------------------------------------------------
  C.$ = (id) => document.getElementById(id);
  const $ = C.$;

  C.esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  };

  const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  C.SEV_ORDER = SEV_ORDER;
  C.sevRank = (sev) => (SEV_ORDER[sev] != null ? SEV_ORDER[sev] : -1);

  C.fmtElapsed = function (sec) {
    sec = Math.max(0, Math.round(sec));
    return Math.floor(sec / 60) + ":" + String(sec % 60).padStart(2, "0");
  };

  C.setStatus = function (id, msg, isErr) {
    const el = $(id);
    el.classList.remove("hidden");
    el.classList.toggle("err", !!isErr);
    el.textContent = msg;
  };

  // ---- toast notifications (non-blocking replacement for alert()) -----------------
  C.toast = function (msg, kind) {
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
  };
  const toast = C.toast;

  // ---- init callback registry -------------------------------------------------------
  // Modules register CELSIUS.onInit(fn); callbacks run once the DOM is ready.
  const _initFns = [];
  let _initRan = false;
  function _runInit() {
    if (_initRan) return;
    _initRan = true;
    _initFns.forEach((fn) => fn());
  }
  C.onInit = function (fn) {
    if (_initRan) fn();
    else _initFns.push(fn);
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", _runInit);
  } else {
    _runInit(); // defer scripts run after parsing; later onInit() calls run at once
  }

  // ---- access token ------------------------------------------------------------------
  // When the server runs with CELSIUS_TOKEN (LAN/Docker exposure), every /api/*
  // request must carry it. We inject it as a header on fetch() and as a ?token=
  // query param on report links opened directly in a browser tab.
  try { C.state.token = localStorage.getItem("celsius_token") || ""; } catch (_) {}
  C.onInit(() => {
    const el = $("accessToken");
    if (!el) return;
    el.value = C.state.token;
    el.addEventListener("input", (e) => {
      C.state.token = e.target.value.trim();
      try { localStorage.setItem("celsius_token", C.state.token); } catch (_) {}
    });
  });

  // Wrap fetch: add the token header for same-origin /api/ calls.
  (function patchFetch() {
    const orig = window.fetch.bind(window);
    window.fetch = function (input, init) {
      const url = typeof input === "string" ? input : (input && input.url) || "";
      const isApi = url.startsWith("/api/") || url.startsWith(location.origin + "/api/");
      const tok = C.state.token;
      if (isApi && tok) {
        init = init || {};
        const h = new Headers(init.headers || (typeof input !== "string" && input.headers) || {});
        h.set("X-Celsius-Token", tok);
        init.headers = h;
      }
      return orig(input, init);
    };
  })();

  // Fetch wrapper for JSON API calls: injects the token header (via the patch
  // above) and throws Error(detail) on !ok. Returns the parsed JSON body.
  C.api = async function (path, opts) {
    const r = await fetch(path, opts);
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error((err && err.detail) || r.statusText || ("HTTP " + r.status));
    }
    return r.json();
  };

  // Append ?token= to an /api/ report link so a plain browser navigation authenticates.
  C.withToken = function (url) {
    const tok = C.state.token;
    if (!tok || !url.startsWith("/api/")) return url;
    return url + (url.includes("?") ? "&" : "?") + "token=" + encodeURIComponent(tok);
  };

  // ---- theme (light default, dark opt-in) ----------------------------------------------
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

  // ---- tab router ------------------------------------------------------------------------
  const _tabFns = [];
  C.onTab = (fn) => _tabFns.push(fn); // modules subscribe to tab switches
  C.showTab = function (name) {
    document.querySelectorAll(".tab").forEach((x) => {
      const on = x.dataset.tab === name;
      x.classList.toggle("active", on);
      x.setAttribute("aria-selected", on ? "true" : "false");
    });
    document.querySelectorAll(".panel").forEach((x) =>
      x.classList.toggle("active", x.id === "tab-" + name));
    _tabFns.forEach((fn) => fn(name));
  };
  C.onInit(() => {
    document.querySelectorAll(".tab").forEach((t) => {
      t.addEventListener("click", () => C.showTab(t.dataset.tab));
    });
  });

  // ---- authorization gate -------------------------------------------------------------------
  C.onInit(() => {
    $("authorized").addEventListener("change", (e) => {
      C.state.authorized = !!e.target.checked;
      $("authbar").classList.toggle("ok", e.target.checked);
      if (e.target.checked) $("authbar").classList.remove("attention");
    });
  });

  // Returns true when the authorization checkbox is ticked; otherwise highlights
  // and scrolls to it with a clear message.
  C.demandAuth = function () {
    if ($("authorized").checked) return true;
    toast("Please confirm you own or have permission to scan this target.", "error");
    const bar = $("authbar");
    bar.classList.add("attention");
    bar.scrollIntoView({ block: "center", behavior: "smooth" });
    $("authorized").focus();
    setTimeout(() => bar.classList.remove("attention"), 3500);
    return false;
  };

  return C;
})();
