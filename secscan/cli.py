"""Command-line interface.

Subcommands:
  scan   <target>   host/web scan (services, CVEs, headers, secrets) [default]
  code   <path>     static code/secret scan of a directory or file
  serve             launch the web app (FastAPI)

`secscan <target>` with no subcommand is treated as `secscan scan <target>`.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from . import codescan, poc, report
from .engine import ScanConfig, run_scan
from .logsetup import setup_logging
from .models import Severity

BANNER = f"secscan {__version__} — service/version + CVE + web + code scanner"

CONSENT_TEXT = """\
╭───────────────────────────────────────────────────────────────────────────╮
│  AUTHORIZED USE ONLY                                                       │
│  Scanning hosts you do not own or lack written permission to test may be   │
│  illegal and can disrupt services. By continuing you confirm you are       │
│  authorized to test the target below.                                      │
╰───────────────────────────────────────────────────────────────────────────╯"""

_SUBCOMMANDS = {"scan", "code", "serve", "history"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secscan", description=BANNER)
    p.add_argument("--version", action="version", version=f"secscan {__version__}")
    sub = p.add_subparsers(dest="command")

    # scan
    s = sub.add_parser("scan", help="host/web scan")
    s.add_argument("target", help="URL, hostname, or IP")
    s.add_argument("--full", "--thorough", action="store_true", dest="full",
                   help="turn on every safe check at once (ports, nuclei, subdomains, "
                        "crawl, API discovery, mail, CVE-verify, OS detect)")
    s.add_argument("--no-web", action="store_true", help="skip HTTP header/CSP analysis")
    s.add_argument("--no-cve", action="store_true", help="skip NVD CVE lookup")
    s.add_argument("--no-secrets", action="store_true", help="skip front-end secret scan")
    s.add_argument("--no-dns", action="store_true", help="skip DNS recon")
    s.add_argument("--no-tls", action="store_true", help="skip TLS/certificate analysis")
    s.add_argument("--mail", action="store_true",
                   help="e-postsäkerhet: SPF/DKIM/DMARC/MTA-STS/TLS-RPT/DNSSEC/BIMI (passivt)")
    s.add_argument("--no-fingerprint", action="store_true", help="skip tech fingerprinting")
    s.add_argument("--subdomains", action="store_true", help="enumerate subdomains (crt.sh)")
    s.add_argument("--subdomain-bruteforce", action="store_true", help="also resolve a wordlist")
    s.add_argument("--no-diff", action="store_true", help="skip temporal diff vs last scan")
    s.add_argument("--no-exploitability", action="store_true", help="skip EPSS/KEV exploitability assessment")
    s.add_argument("--cve-verify", action="store_true", help="confirm detected CVEs with matching nuclei templates (safe-active)")
    s.add_argument("--crawl", action="store_true", help="crawl + JS endpoint/route + source-map recovery")
    s.add_argument("--crawl-max-pages", type=int, default=40)
    s.add_argument("--api-discovery", action="store_true", help="probe OpenAPI/Swagger + GraphQL introspection")
    s.add_argument("--dynamic", action="store_true", help="use Playwright dynamic crawl if installed")
    s.add_argument("--ports", action="store_true", help="run nmap port/service scan")
    s.add_argument("--nuclei", action="store_true", help="run nuclei templates")
    s.add_argument("--nuclei-full", action="store_true", help="run the ENTIRE nuclei set (slow)")
    s.add_argument("--top-ports", type=int, default=100)
    s.add_argument("--port-range")
    s.add_argument("--os-detect", action="store_true",
                   help="nmap OS/device fingerprint (-O); identifies router/firewall/vendor (needs sudo/root)")
    s.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"))
    s.add_argument("--scope", metavar="FILE", help="scope.yml authorizing targets/modes")
    s.add_argument("--no-active", action="store_true", help="disable safe-active checks (nmap/nuclei)")
    s.add_argument("--lab", action="store_true",
                   help="LAB MODE: non-destructive active verification (needs scope EXPLOIT + attestation)")
    s.add_argument("--lab-attest", metavar="TEXT", help="attestation statement for lab mode")
    s.add_argument("--dry-run", action="store_true", help="lab mode: preview payloads without sending")
    s.add_argument("--exploit-max-requests", type=int, default=200)
    s.add_argument("--exploit-rate-limit", type=float, default=5.0)
    s.add_argument("--no-db", action="store_true", help="do not persist the scan to the local store")
    s.add_argument("--ai", action="store_true", help="AI triage + attack-surface hypotheses")
    s.add_argument("--ai-provider", default="deepseek", help="deepseek|openai|anthropic|local|mock")
    s.add_argument("--ai-model", help="override the provider's default model")
    s.add_argument("--ai-redact", action="store_true", help="mask secrets before sending to the AI (default off)")
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
                   help="write the full debug trace here (default ~/.local/share/secscan/scan.log)")

    # history
    h = sub.add_parser("history", help="list past scans from the local store")
    h.add_argument("--target", help="filter by target")
    h.add_argument("--limit", type=int, default=30)

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
    c.add_argument("--ai-redact", action="store_true", help="mask secrets before sending to the AI")

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
    import urllib.parse
    from . import auth as auth_mod

    base = auth_mod.from_options(cookie=args.cookie or "", bearer=args.bearer or "",
                                 headers=args.header or [])
    if args.login_url:
        data: dict = {}
        if args.login_data:
            data.update(dict(urllib.parse.parse_qsl(args.login_data)))
        if args.login_user:
            data[args.login_field_user] = args.login_user
        if args.login_pass:
            data[args.login_field_pass] = args.login_pass
        session, msg = auth_mod.form_login(args.login_url, data, insecure=args.insecure,
                                           extra_headers=base.headers)
        logger.info("auth: %s", msg)
        if not session:
            logger.warning("auth: form login failed — continuing UNauthenticated")
            return base if base else None
        return session
    if base:
        logger.info("auth: attaching session (%s)", base.source)
        return base
    return None


def _cmd_scan(args) -> int:
    if not _confirm_authorization(args.target, args.yes):
        print("Aborted: authorization not confirmed.", file=sys.stderr)
        return 2

    # --full / --thorough: enable the whole safe (passive + safe-active) battery.
    # Lab/exploit and AI stay opt-in (they need attestation / an API key).
    if args.full:
        for attr in ("ports", "nuclei", "subdomains", "crawl", "api_discovery",
                     "mail", "cve_verify", "os_detect"):
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
    log = lambda m: logger.info("%s", m)  # noqa: E731  (engine progress callback)
    config = ScanConfig(
        target=args.target, web=not args.no_web, cve=not args.no_cve,
        web_secrets=not args.no_secrets, ports=args.ports, nuclei=args.nuclei,
        nuclei_full=args.nuclei_full, top_ports=args.top_ports, port_range=args.port_range,
        os_detect=args.os_detect,
        nvd_api_key=args.nvd_api_key, insecure=args.insecure,
        exploitability=not args.no_exploitability, cve_verify=args.cve_verify,
        dns=not args.no_dns, tls=not args.no_tls, mailsec=args.mail,
        fingerprint=not args.no_fingerprint,
        subdomains=args.subdomains, subdomain_bruteforce=args.subdomain_bruteforce,
        diff=not args.no_diff,
        crawl=args.crawl, crawl_max_pages=args.crawl_max_pages,
        api_discovery=args.api_discovery, dynamic=args.dynamic,
        auth=auth_session,
        scope_file=args.scope, allow_active=not args.no_active, persist=not args.no_db,
        allow_exploit=args.lab, lab_attestation=lab_attest, dry_run=args.dry_run,
        exploit_max_requests=args.exploit_max_requests, exploit_rate_limit=args.exploit_rate_limit,
        ai=args.ai, ai_provider=args.ai_provider, ai_model=args.ai_model,
        ai_redact=args.ai_redact,
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
        print(f"[+] saved as scan {result.scan_id} (see `secscan history`)", file=sys.stderr)
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


_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _cmd_code(args) -> int:
    print(f"[*] scanning {args.path} ...", file=sys.stderr)
    res = codescan.scan_path(args.path, use_external=not args.no_external, sca=not args.no_sca)
    if getattr(args, "ai", False):
        _ai_code_review(args, res)
    print(f"\n secscan code scan — {res.root}")
    print(f" files scanned: {res.files_scanned} | tools: {', '.join(res.tools_used)}")
    print("─" * 70)
    if not res.findings:
        print(" No secrets or risky patterns found.")
    for f in sorted(res.findings, key=lambda x: _SEV_RANK.get(x.severity, 0), reverse=True):
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
    worst = max((_SEV_RANK.get(f.severity, 0) for f in res.findings), default=0)
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


def _cmd_serve(args) -> int:
    try:
        import uvicorn
    except ImportError:
        print("The web app needs FastAPI/uvicorn. Install with:\n"
              "  python3 -m venv .venv && .venv/bin/pip install 'fastapi' 'uvicorn[standard]' python-multipart\n"
              "then run:  .venv/bin/python -m secscan serve", file=sys.stderr)
        return 1
    mode = " (auto-reload)" if args.reload else ""
    print(f"[*] secscan web app on http://{args.host}:{args.port}{mode}", file=sys.stderr)
    uvicorn.run("secscan.web.app:app", host=args.host, port=args.port,
                log_level="info", reload=args.reload)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Backward-compat: `secscan <target>` -> `secscan scan <target>`.
    if argv and argv[0] not in _SUBCOMMANDS and not argv[0].startswith("-"):
        argv = ["scan"] + argv

    args = build_parser().parse_args(argv)
    if args.command == "code":
        return _cmd_code(args)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "history":
        return _cmd_history(args)
    if args.command == "scan":
        return _cmd_scan(args)
    build_parser().print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
