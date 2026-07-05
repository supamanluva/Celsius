"""Command-line interface.

Subcommands:
  scan   <target>   host/web scan (services, CVEs, headers, secrets) [default]
  code   <path>     static code/secret scan of a directory or file
  serve             launch the web app (FastAPI)

`celsius <target>` with no subcommand is treated as `celsius scan <target>`.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from . import codescan, poc, report
from .engine import ScanConfig, run_scan
from .logsetup import setup_logging
from .models import severity_rank

BANNER = f"Celsius {__version__} — service/version + CVE + web + code scanner"

CONSENT_TEXT = """\
╭───────────────────────────────────────────────────────────────────────────╮
│  AUTHORIZED USE ONLY                                                       │
│  Scanning hosts you do not own or lack written permission to test may be   │
│  illegal and can disrupt services. By continuing you confirm you are       │
│  authorized to test the target below.                                      │
╰───────────────────────────────────────────────────────────────────────────╯"""

_SUBCOMMANDS = {"scan", "code", "serve", "history", "recheck", "monitor", "typosquat"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="celsius", description=BANNER)
    p.add_argument("--version", action="version", version=f"Celsius {__version__}")
    sub = p.add_subparsers(dest="command")

    # scan
    s = sub.add_parser("scan", help="host/web scan")
    s.add_argument("target", help="URL, hostname, or IP")
    s.add_argument("--full", "--thorough", action="store_true", dest="full",
                   help="turn on every safe check at once (ports, nuclei, subdomains, "
                        "crawl, API discovery, mail, CVE-verify, OS detect)")
    s.add_argument("--no-web", action="store_true", help="skip HTTP header/CSP analysis")
    s.add_argument("--no-cve", action="store_true", help="skip NVD CVE lookup")
    s.add_argument("--no-cve-pocs", action="store_true", help="skip public-exploit/PoC links (trickest/cve)")
    s.add_argument("--no-secrets", action="store_true", help="skip front-end secret scan")
    s.add_argument("--no-dns", action="store_true", help="skip DNS recon")
    s.add_argument("--no-tls", action="store_true", help="skip TLS/certificate analysis")
    s.add_argument("--no-robots", action="store_true", help="skip robots.txt/sitemap.xml harvesting")
    s.add_argument("--no-favicon", action="store_true", help="skip favicon hash fingerprinting")
    s.add_argument("--mail", action="store_true",
                   help="e-mail security: SPF/DKIM/DMARC/MTA-STS/TLS-RPT/DNSSEC/BIMI (passive)")
    s.add_argument("--no-fingerprint", action="store_true", help="skip tech fingerprinting")
    s.add_argument("--subdomains", action="store_true", help="enumerate subdomains (crt.sh)")
    s.add_argument("--subdomain-bruteforce", action="store_true", help="also resolve a wordlist")
    s.add_argument("--topology", action="store_true",
                   help="map IP topology of target+subdomains (Shodan/RDAP, passive): VPS vs home vs SaaS")
    s.add_argument("--wayback", action="store_true", help="harvest historical URLs/params from archive.org (passive)")
    s.add_argument("--no-diff", action="store_true", help="skip temporal diff vs last scan")
    s.add_argument("--no-exploitability", action="store_true", help="skip EPSS/KEV exploitability assessment")
    s.add_argument("--cve-verify", action="store_true", help="confirm detected CVEs with matching nuclei templates (safe-active)")
    s.add_argument("--crawl", action="store_true", help="crawl + JS endpoint/route + source-map recovery")
    s.add_argument("--crawl-max-pages", type=int, default=40)
    s.add_argument("--api-discovery", action="store_true", help="probe OpenAPI/Swagger + GraphQL introspection")
    s.add_argument("--content-discovery", action="store_true", help="probe for exposed sensitive files (.git/.env/backups)")
    s.add_argument("--dynamic", action="store_true", help="use Playwright dynamic crawl if installed")
    s.add_argument("--ports", action="store_true", help="run nmap port/service scan")
    s.add_argument("--default-creds", action="store_true",
                   help="safe-active: try curated vendor default logins (admin/admin, "
                        "tomcat/tomcat, anonymous FTP, …) on identified panels/services")
    s.add_argument("--nuclei", action="store_true", help="run nuclei templates")
    s.add_argument("--nuclei-full", action="store_true", help="run the ENTIRE nuclei set (slow)")
    s.add_argument("--top-ports", type=int, default=100)
    s.add_argument("--port-range", help="explicit nmap ports, e.g. '1-65535' (full) or '22,80,443'")
    s.add_argument("--udp", action="store_true", help="also run a UDP service scan (needs root; slow)")
    s.add_argument("--os-detect", action="store_true",
                   help="nmap OS/device fingerprint (-O); identifies router/firewall/vendor (needs sudo/root)")
    s.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"))
    s.add_argument("--scope", metavar="FILE", help="scope.yml authorizing targets/modes")
    s.add_argument("--no-active", action="store_true", help="disable safe-active checks (nmap/nuclei)")
    s.add_argument("--lab", action="store_true",
                   help="LAB MODE: non-destructive active verification (needs scope EXPLOIT + attestation)")
    s.add_argument("--lab-attest", metavar="TEXT", help="attestation statement for lab mode")
    s.add_argument("--dry-run", action="store_true", help="lab mode: preview payloads without sending")
    s.add_argument("--ssrf", action="store_true",
                   help="lab mode: blind-SSRF probe via an out-of-band callback canary (needs --lab)")
    s.add_argument("--rce", action="store_true",
                   help="lab mode: OS command-injection probe via an out-of-band callback (needs --lab)")
    s.add_argument("--blind-xss", action="store_true",
                   help="lab mode: blind/stored-XSS beacon via an out-of-band callback (needs --lab)")
    s.add_argument("--xxe", action="store_true",
                   help="lab mode: blind-XXE probe via an out-of-band callback (needs --lab)")
    s.add_argument("--oob-host", metavar="ADDR",
                   help="address the target should call back to for OOB probes (default: auto-detect LAN IP)")
    s.add_argument("--time-sqli", action="store_true",
                   help="lab mode: time-based blind SQLi — DELIBERATELY delays the DB (load-adjacent; "
                        "opt-in exception to the non-destructive default; needs --lab)")
    s.add_argument("--time-sqli-delay", type=float, default=3.0, metavar="SECS",
                   help="seconds the injected SQL sleep should pause for (default 3)")
    s.add_argument("--idor", action="store_true",
                   help="lab mode: IDOR/BOLA authorization probe (needs --lab and an auth session; "
                        "add --auth2-* for cross-user testing)")
    s.add_argument("--auth2-cookie", metavar="COOKIE",
                   help="second identity's Cookie header for --idor cross-user (BOLA) testing")
    s.add_argument("--auth2-bearer", metavar="TOKEN",
                   help="second identity's bearer token for --idor cross-user (BOLA) testing")
    s.add_argument("--exploit-max-requests", type=int, default=200)
    s.add_argument("--exploit-rate-limit", type=float, default=5.0)
    s.add_argument("--no-db", action="store_true", help="do not persist the scan to the local store")
    s.add_argument("--ai", action="store_true", help="AI triage + attack-surface hypotheses")
    s.add_argument("--ai-provider", default="deepseek", help="deepseek|openai|anthropic|local|mock")
    s.add_argument("--ai-model", help="override the provider's default model (e.g. a local Ollama model)")
    s.add_argument("--ai-base-url", help="AI API base URL (local Ollama: http://localhost:11434/v1)")
    grp = s.add_mutually_exclusive_group()
    grp.add_argument("--ai-redact", action="store_true", default=True, dest="ai_redact",
                     help="mask secrets before sending to the AI (default ON)")
    grp.add_argument("--ai-no-redact", action="store_false", dest="ai_redact",
                     help="send unmasked content to the AI (only on a target you own)")
    s.add_argument("--json", metavar="FILE")
    s.add_argument("--html", metavar="FILE")
    s.add_argument("--sarif", metavar="FILE", help="write a SARIF 2.1.0 report (CI/IDE)")
    s.add_argument("--markdown", metavar="FILE", help="write a Markdown report")
    s.add_argument("--poc", action="store_true", help="print reproduction steps for findings/CVEs")
    s.add_argument("--insecure", action="store_true")
    # authenticated scan: attach a logged-in session to crawl/checks/nuclei/active
    s.add_argument("--cookie", help="Cookie header to send (e.g. \"session=abc; csrf=xyz\")")
    s.add_argument("--header", action="append", metavar="\"K: V\"",
                   help="extra request header (repeatable), e.g. --header \"Authorization: Bearer ...\"")
    s.add_argument("--bearer", help="shortcut for an Authorization: Bearer <token> header")
    s.add_argument("--login-url", help="form login: URL to POST credentials to (captures the session)")
    s.add_argument("--login-data", help="form login: raw body, e.g. \"user=alice&pass=secret\"")
    s.add_argument("--login-user", help="form login: username value")
    s.add_argument("--login-pass", help="form login: password value")
    s.add_argument("--login-field-user", default="username", help="form login: username field name")
    s.add_argument("--login-field-pass", default="password", help="form login: password field name")
    s.add_argument("-y", "--yes", action="store_true", help="skip authorization prompt")
    s.add_argument("-v", "--verbose", action="store_true",
                   help="show per-step progress on stderr even when piped")
    s.add_argument("--debug", action="store_true",
                   help="verbose + debug detail (commands, subprocess stderr)")
    s.add_argument("--quiet", action="store_true", help="only show errors on stderr")
    s.add_argument("--log-file", metavar="PATH",
                   help="write the full debug trace here (default ~/.local/share/celsius/scan.log)")

    # history
    h = sub.add_parser("history", help="list past scans from the local store")
    h.add_argument("--target", help="filter by target")
    h.add_argument("--limit", type=int, default=30)

    # recheck — re-evaluate stored fingerprints against the latest CVE feed
    rc = sub.add_parser("recheck",
                        help="re-match stored scans against the latest CVEs (no new target traffic)")
    rc.add_argument("--target", help="only re-check this target (default: latest scan per host)")
    rc.add_argument("--limit", type=int, default=100, help="how many recent scans to consider")
    rc.add_argument("--firm-only", action="store_true",
                    help="show only firm (range-confirmed) new CVEs, hiding weak leads")
    rc.add_argument("--no-refresh", action="store_true",
                    help="use the CVE cache instead of forcing a fresh NVD fetch")
    rc.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"),
                    help="NVD API key (faster lookups; env NVD_API_KEY)")
    rc.add_argument("--json", metavar="FILE", help="write the full result as JSON")

    # monitor — watch known hosts for new exposure and alert
    mon = sub.add_parser("monitor",
                         help="watch hosts for NEW exposure (CVEs/subdomains/ports) and alert")
    mon.add_argument("--target", action="append", dest="targets",
                     help="host to watch (repeatable; default: all stored hosts)")
    mon.add_argument("--watchlist", help="file with one host per line (# comments allowed)")
    mon.add_argument("--rescan", action="store_true",
                     help="run a fresh scan per host (sends traffic) and diff vs last scan; "
                          "default is a no-traffic CVE re-check only")
    mon.add_argument("--firm-only", action="store_true", help="ignore weak CVE leads")
    mon.add_argument("--email", help="send an alert to this address (SMTP_* env)")
    mon.add_argument("--webhook", help="POST a JSON alert to this URL")
    mon.add_argument("--always", action="store_true",
                     help="send the alert even when nothing new (heartbeat)")
    mon.add_argument("--typosquat", action="store_true",
                     help="also watch for newly-registered look-alike/phishing domains")
    mon.add_argument("--limit", type=int, default=200, help="how many stored hosts to consider")
    mon.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"))

    # typosquat — find registered look-alike / phishing domains
    ts = sub.add_parser("typosquat", help="find registered look-alike / phishing domains")
    ts.add_argument("domain", help="your domain, e.g. example.com")
    ts.add_argument("--max", type=int, default=1000, help="max lookalike candidates to check")
    ts.add_argument("--no-mail", action="store_true", help="skip the MX (mail-capable) check")
    ts.add_argument("--json", metavar="FILE", help="write results as JSON")

    # code
    c = sub.add_parser("code", help="static code/secret scan")
    c.add_argument("path", help="directory or file to scan")
    c.add_argument("--json", metavar="FILE")
    c.add_argument("--no-external", action="store_true", help="don't call gitleaks/semgrep/trufflehog")
    c.add_argument("--no-sca", action="store_true",
                   help="skip dependency vulnerability scan (OSV.dev; needs network)")
    c.add_argument("--ai", action="store_true", help="add an AI secure-code review pass")
    c.add_argument("--ai-provider", default="deepseek", help="deepseek|openai|anthropic|local|mock")
    c.add_argument("--ai-model", help="override the provider's default model")
    cgrp = c.add_mutually_exclusive_group()
    cgrp.add_argument("--ai-redact", action="store_true", default=True, dest="ai_redact",
                      help="mask secrets before sending to the AI (default ON)")
    cgrp.add_argument("--ai-no-redact", action="store_false", dest="ai_redact",
                      help="send unmasked source to the AI (only for code you own)")

    # serve
    sv = sub.add_parser("serve", help="launch the web app")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--reload", action="store_true",
                    help="auto-reload on code changes (development only)")
    return p


def _confirm_authorization(target: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("Refusing to scan without confirmation in non-interactive mode. "
              "Pass --yes if you are authorized.", file=sys.stderr)
        return False
    print(CONSENT_TEXT)
    print(f"\n  Target: {target}")
    try:
        return input("  Type 'yes' to confirm you are authorized: ").strip().lower() in ("yes", "y")
    except (EOFError, KeyboardInterrupt):
        return False


def _build_auth(args, logger):
    """Assemble an AuthSession from --cookie/--bearer/--header and optional form
    login. Returns an AuthSession or None."""
    from . import auth as auth_mod
    return auth_mod.build_session(
        cookie=args.cookie or "", bearer=args.bearer or "", headers=args.header or [],
        login_url=args.login_url or "", login_data=args.login_data or "",
        login_user=args.login_user or "", login_pass=args.login_pass or "",
        login_field_user=args.login_field_user, login_field_pass=args.login_field_pass,
        insecure=args.insecure, log=logger.info)


def _cmd_scan(args) -> int:
    if not _confirm_authorization(args.target, args.yes):
        print("Aborted: authorization not confirmed.", file=sys.stderr)
        return 2

    # --full / --thorough: enable the whole safe (passive + safe-active) battery.
    # Lab/exploit and AI stay opt-in (they need attestation / an API key).
    if args.full:
        for attr in ("ports", "nuclei", "subdomains", "wayback", "crawl", "api_discovery",
                     "content_discovery", "mail", "cve_verify", "os_detect"):
            setattr(args, attr, True)

    # Lab-mode attestation gate (in addition to scope EXPLOIT + the auth prompt).
    lab_attest = None
    if args.lab:
        if not args.scope:
            print("Lab mode requires --scope <scope.yml> authorizing EXPLOIT for the target.",
                  file=sys.stderr)
            return 2
        lab_attest = args.lab_attest
        if not lab_attest:
            if not sys.stdin.isatty():
                print("Lab mode needs --lab-attest \"<statement>\" in non-interactive mode.",
                      file=sys.stderr)
                return 2
            print("\n⚠️  LAB MODE — active, non-destructive verification will send real "
                  "probes to the target.")
            print(f"   Target: {args.target}")
            try:
                lab_attest = input("   Type an attestation that you are authorized to ACTIVELY "
                                   "test this target:\n   > ").strip()
            except (EOFError, KeyboardInterrupt):
                lab_attest = ""
        if len(lab_attest or "") < 10:
            print("Aborted: a meaningful lab attestation is required.", file=sys.stderr)
            return 2

    logger = setup_logging(
        verbose=args.verbose, debug=args.debug, quiet=args.quiet, log_file=args.log_file,
    )
    logger.info("scan starting: target=%s", args.target)

    auth_session = _build_auth(args, logger)
    if auth_session and not args.no_active:
        print("[!] Authenticated + active scan: requests are sent as the logged-in user and "
              "may change state. Prefer a test account / staging.", file=sys.stderr)
    auth2_session = None
    if getattr(args, "auth2_cookie", None) or getattr(args, "auth2_bearer", None):
        from . import auth as auth_mod
        auth2_session = auth_mod.from_options(cookie=args.auth2_cookie or "",
                                              bearer=args.auth2_bearer or "")
    log = lambda m: logger.info("%s", m)  # noqa: E731  (engine progress callback)
    config = ScanConfig(
        target=args.target, web=not args.no_web, cve=not args.no_cve,
        cve_pocs=not args.no_cve_pocs,
        web_secrets=not args.no_secrets, ports=args.ports, default_creds=args.default_creds,
        nuclei=args.nuclei,
        nuclei_full=args.nuclei_full, top_ports=args.top_ports, port_range=args.port_range,
        udp=args.udp, os_detect=args.os_detect,
        nvd_api_key=args.nvd_api_key, insecure=args.insecure,
        exploitability=not args.no_exploitability, cve_verify=args.cve_verify,
        dns=not args.no_dns, tls=not args.no_tls, robots=not args.no_robots,
        favicon=not args.no_favicon, mailsec=args.mail,
        fingerprint=not args.no_fingerprint,
        subdomains=args.subdomains, subdomain_bruteforce=args.subdomain_bruteforce,
        topology=args.topology,
        wayback=args.wayback,
        diff=not args.no_diff,
        crawl=args.crawl, crawl_max_pages=args.crawl_max_pages,
        api_discovery=args.api_discovery, content_discovery=args.content_discovery,
        dynamic=args.dynamic,
        auth=auth_session,
        scope_file=args.scope, allow_active=not args.no_active, persist=not args.no_db,
        allow_exploit=args.lab, lab_attestation=lab_attest, dry_run=args.dry_run,
        ssrf_oob=args.ssrf, rce_oob=args.rce, blind_xss_oob=args.blind_xss,
        xxe_oob=args.xxe, oob_callback_host=args.oob_host,
        idor=args.idor, auth2=auth2_session,
        time_sqli=args.time_sqli, time_sqli_delay=args.time_sqli_delay,
        exploit_max_requests=args.exploit_max_requests, exploit_rate_limit=args.exploit_rate_limit,
        ai=args.ai, ai_provider=args.ai_provider, ai_model=args.ai_model,
        ai_base_url=args.ai_base_url, ai_redact=args.ai_redact,
    )
    store = None
    if config.persist:
        try:
            from .store import Store
            store = Store()
        except Exception as e:
            print(f"[!] store unavailable ({e}); continuing without persistence", file=sys.stderr)
    result = run_scan(config, log=log, store=store)
    for e in result.errors:
        logger.warning("note/error: %s", e)
    logger.info("scan finished: %d finding(s), %d CVE(s)",
                len(result.findings), len(result.cves))

    report.render_terminal(result)
    if store is not None and getattr(result, "scan_id", None):
        print(f"[+] saved as scan {result.scan_id} (see `celsius history`)", file=sys.stderr)
    if args.poc:
        _print_poc(result)
    if args.json:
        report.write_json(result, args.json)
        print(f"[+] JSON written to {args.json}", file=sys.stderr)
    if args.html:
        report.write_html(result, args.html)
        print(f"[+] HTML written to {args.html}", file=sys.stderr)
    if args.sarif:
        report.write_sarif(result, args.sarif)
        print(f"[+] SARIF written to {args.sarif}", file=sys.stderr)
    if args.markdown:
        report.write_markdown(result, args.markdown)
        print(f"[+] Markdown written to {args.markdown}", file=sys.stderr)

    worst = result.all_severities_sorted()
    if worst:
        return {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10}.get(worst[0].value, 0)
    return 0


def _print_poc(result) -> None:
    print("\n" + "═" * 70)
    print(" PROOF-OF-CONCEPT / REPRODUCTION STEPS (text only, non-destructive)")
    print("═" * 70)
    for c in result.cves[:10]:
        box = poc.poc_for_cve(c)
        print(f"\n▶ {box['title']}")
        for step in box["steps"]:
            print(f"   {step}")
        if box["note"]:
            print(f"   ⚠ {box['note']}")
    for f in result.findings[:15]:
        box = poc.poc_for_finding(f, result.url or result.target)
        print(f"\n▶ {box['title']}")
        for step in box["steps"]:
            print(f"   {step}")
        if box["note"]:
            print(f"   ⚠ {box['note']}")




def _cmd_code(args) -> int:
    print(f"[*] scanning {args.path} ...", file=sys.stderr)
    res = codescan.scan_path(args.path, use_external=not args.no_external, sca=not args.no_sca)
    if getattr(args, "ai", False):
        _ai_code_review(args, res)
    print(f"\n celsius code scan — {res.root}")
    print(f" files scanned: {res.files_scanned} | tools: {', '.join(res.tools_used)}")
    print("─" * 70)
    if not res.findings:
        print(" No secrets or risky patterns found.")
    for f in sorted(res.findings, key=lambda x: severity_rank(x.severity), reverse=True):
        conf = f"  conf={f.confidence}" if getattr(f, "confidence", "") else ""
        print(f" [{f.severity:^8}] {f.title}{conf}")
        print(f"            {f.file}:{f.line}  ({f.category}/{f.rule_id})")
        if f.evidence:
            print(f"            evidence: {f.evidence}")
        if f.recommendation:
            print(f"            ↳ {f.recommendation}")
    for e in res.errors:
        print(f" ! {e}", file=sys.stderr)
    if args.json:
        import json
        with open(args.json, "w") as fh:
            json.dump(res.to_dict(), fh, indent=2)
        print(f"[+] JSON written to {args.json}", file=sys.stderr)
    worst = max((severity_rank(f.severity) for f in res.findings), default=0)
    return {4: 30, 3: 20, 2: 10}.get(worst, 0)


def _ai_code_review(args, res) -> None:
    """Run an AI secure-code review over the scanned files and merge findings."""
    import os
    from .ai import get_provider
    from .ai.analyze import review_code_file
    from .ai.cache import Budget
    from .ai.provider import AIError
    from .audit import AuditLog

    audit = AuditLog(scan_id="code-review")
    try:
        provider = get_provider(args.ai_provider, model=args.ai_model)
    except AIError as e:
        print(f"[!] AI review: {e}", file=sys.stderr)
        return
    ok, why = provider.available()
    if not ok:
        print(f"[!] AI review skipped: provider '{args.ai_provider}' unavailable ({why})", file=sys.stderr)
        return

    root = os.path.abspath(args.path)
    files = [root] if os.path.isfile(root) else _gather_source_files(root)
    budget = Budget()
    print(f"[*] AI code review via {provider.name}/{provider.model} on {len(files)} file(s) ...",
          file=sys.stderr)
    for path in files[:40]:  # cap files per run
        try:
            with open(path, "r", errors="replace") as fh:
                source = fh.read()
        except OSError:
            continue
        if not source.strip():
            continue
        try:
            rel = os.path.relpath(path, root if os.path.isdir(root) else os.path.dirname(root))
            findings = review_code_file(rel, source, provider,
                                        redact_secrets=args.ai_redact, budget=budget, audit=audit)
            res.findings.extend(findings)
        except AIError as e:
            print(f"[!] AI review error on {path}: {e}", file=sys.stderr)
            break
    if "ai:" + provider.name not in res.tools_used:
        res.tools_used.append("ai:" + provider.name)
    res.findings = codescan._dedupe(res.findings)


def _gather_source_files(root: str) -> list:
    import os
    exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go", ".java",
            ".cs", ".sh", ".sql", ".html", ".vue"}
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in codescan._SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in exts:
                out.append(os.path.join(dirpath, name))
    return out


def _cmd_history(args) -> int:
    from .store import Store
    store = Store()
    scans = store.list_scans(target=args.target, limit=args.limit)
    if not scans:
        print("No scans recorded yet.")
        return 0
    print(f"{'SCAN ID':<14}{'WORST':<10}{'CVE':>4}{'FIND':>5}  {'WHEN':<22}TARGET")
    print("─" * 80)
    for s in scans:
        print(f"{s['id']:<14}{(s['worst'] or '-'):<10}{s['n_cves']:>4}{s['n_findings']:>5}  "
              f"{(s['finished_at'] or '-'):<22}{s['target']}")
    return 0


def _cmd_recheck(args) -> int:
    from .store import Store
    from . import reeval

    store = Store()
    print("[*] Re-evaluating stored fingerprints against the latest CVE feed "
          "(no new requests to targets)…", file=sys.stderr)
    results = reeval.reevaluate(
        store, target=args.target, limit=args.limit,
        api_key=args.nvd_api_key, force_refresh=not args.no_refresh,
        log=lambda m: print(f"    {m}", file=sys.stderr),
    )

    total_new = 0
    affected = []
    for r in results:
        new = r.firm_new() if args.firm_only else r.new_cves
        if not new:
            continue
        affected.append((r, new))
        total_new += len(new)

    if not results:
        print("No stored scans with fingerprinted software to re-check.")
    elif not affected:
        print(f"✓ Re-checked {len(results)} host(s) — no new CVEs since their last scan.")
    else:
        for r, new in affected:
            new = sorted(new, key=lambda c: (c.severity.rank, c.cvss or 0), reverse=True)
            print(f"\n⚠  {r.host}  ({len(new)} new CVE(s) since {r.last_scanned or 'last scan'})")
            for c in new:
                tag = "" if getattr(c, "confidence", "firm") != "weak" else "  [weak]"
                cvss = f" CVSS {c.cvss}" if c.cvss else ""
                print(f"     {c.severity.value:<8} {c.id:<18} {c.affects or ''}{cvss}{tag}")
                print(f"              {c.url}")
        print(f"\n{total_new} new CVE(s) across {len(affected)} host(s). "
              f"Re-scan affected hosts to confirm and remediate.")

    if args.json:
        import json
        payload = [{
            "scan_id": r.scan_id, "target": r.target, "host": r.host,
            "last_scanned": r.last_scanned, "checked_services": r.checked_services,
            "new_cves": [c.to_dict() for c in r.new_cves], "notes": r.notes,
        } for r in results]
        with open(args.json, "w") as fh:
            json.dump(payload, fh, indent=2, default=str)
        print(f"\n[*] Wrote {args.json}", file=sys.stderr)
    return 0


def _cmd_monitor(args) -> int:
    from .store import Store
    from . import monitor as monitor_mod
    from .config import ScanConfig

    store = Store()

    # In --rescan mode, each host gets a fresh exposure-focused scan that the
    # engine diffs against the previous stored scan.
    def cfg_factory(target: str) -> ScanConfig:
        return ScanConfig(
            target=target, web=True, cve=True, dns=True, tls=True, fingerprint=True,
            subdomains=True, ports=True, service_probe=True,
            nvd_api_key=args.nvd_api_key, diff=True, persist=True,
        )

    mode = "rescan (fresh scans + diff)" if args.rescan else "recheck (no target traffic)"
    print(f"[*] Celsius monitor — {mode}", file=sys.stderr)
    report = monitor_mod.run_monitor(
        store, targets=args.targets, watchlist_file=args.watchlist, rescan=args.rescan,
        scan_config_factory=cfg_factory if args.rescan else None,
        api_key=args.nvd_api_key, firm_only=args.firm_only, typosquat=args.typosquat,
        limit=args.limit, log=lambda m: print(f"    {m}", file=sys.stderr),
    )

    _subject, body = monitor_mod.format_report(report)
    print(body)

    if args.email or args.webhook:
        monitor_mod.dispatch_alerts(
            report, email=args.email, webhook=args.webhook, always=args.always,
            log=lambda m: print(f"[*] {m}", file=sys.stderr))
    elif report.any_changes():
        print("\n[*] New exposure found — pass --email / --webhook to get alerted.",
              file=sys.stderr)

    return 0


def _cmd_typosquat(args) -> int:
    from . import typosquat

    print(f"[*] Hunting look-alike domains for {args.domain} …", file=sys.stderr)
    live = typosquat.scan(args.domain, max_candidates=args.max, mail=not args.no_mail,
                          log=lambda m: print(f"    {m}", file=sys.stderr))
    if not live:
        print("No live look-alike domains found.")
    else:
        print(f"\n{len(live)} live look-alike domain(s):")
        for r in live:
            mail = "  ✉ MAIL-CAPABLE" if r.get("mail") else ""
            print(f"  {r['domain']:<40} {r.get('ip',''):<16}{mail}")
        print("\nLook-alikes that resolve can be used for phishing; mail-capable ones can "
              "send mail impersonating you. Consider defensive registration or takedown.")
    if args.json:
        import json
        with open(args.json, "w") as fh:
            json.dump(live, fh, indent=2)
        print(f"\n[*] Wrote {args.json}", file=sys.stderr)
    return 0


def _cmd_serve(args) -> int:
    try:
        import uvicorn
    except ImportError:
        print("The web app needs FastAPI/uvicorn. Install with:\n"
              "  python3 -m venv .venv && .venv/bin/pip install 'fastapi' 'uvicorn[standard]' python-multipart\n"
              "then run:  .venv/bin/python -m celsius serve", file=sys.stderr)
        return 1
    # When exposed beyond loopback, require a token. If the operator didn't set
    # CELSIUS_TOKEN, generate one and print it so LAN/Docker exposure is never
    # silently unauthenticated. The env var is inherited by the uvicorn worker
    # (including the reload subprocess) and read by celsius.web.app.
    import os
    import secrets
    loopback = args.host in ("127.0.0.1", "localhost", "::1", "")
    token = os.environ.get("CELSIUS_TOKEN", "").strip()
    if not loopback:
        if not token:
            token = secrets.token_urlsafe(24)
            os.environ["CELSIUS_TOKEN"] = token
            print("[*] No CELSIUS_TOKEN set and binding beyond localhost — "
                  "generated an access token:", file=sys.stderr)
            print(f"\n      {token}\n", file=sys.stderr)
            print("    Paste it into the web UI's \"Access token\" field "
                  "(or send header  X-Celsius-Token: <token>).", file=sys.stderr)
        else:
            print("[*] Access-token auth enabled (CELSIUS_TOKEN).", file=sys.stderr)

    mode = " (auto-reload)" if args.reload else ""
    print(f"[*] Celsius web app on http://{args.host}:{args.port}{mode}", file=sys.stderr)
    uvicorn.run("celsius.web.app:app", host=args.host, port=args.port,
                log_level="info", reload=args.reload)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Backward-compat: `celsius <target>` -> `celsius scan <target>`.
    if argv and argv[0] not in _SUBCOMMANDS and not argv[0].startswith("-"):
        argv = ["scan"] + argv

    args = build_parser().parse_args(argv)
    if args.command == "code":
        return _cmd_code(args)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "history":
        return _cmd_history(args)
    if args.command == "recheck":
        return _cmd_recheck(args)
    if args.command == "monitor":
        return _cmd_monitor(args)
    if args.command == "typosquat":
        return _cmd_typosquat(args)
    if args.command == "scan":
        return _cmd_scan(args)
    build_parser().print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
