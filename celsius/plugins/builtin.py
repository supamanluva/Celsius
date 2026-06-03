"""Built-in checks, migrated to the plugin interface.

Each plugin wraps an existing analysis module. Logic stays in those modules; the
plugins handle orchestration, phase ordering, and mode classification.
"""

from __future__ import annotations

from .. import cve as cve_mod
from .. import http_analysis, nuclei_scan, portscan, webchecks, websecrets
from ..models import Finding, Service, Severity
from ..recon import apidisco as api_mod
from ..recon import crawler as crawler_mod
from ..recon import dns as dns_mod
from ..recon import dynamic as dynamic_mod
from ..recon import fingerprint as fp_mod
from ..recon import jsintel as jsintel_mod
from ..recon import mailsec as mailsec_mod
from ..recon import sourcemaps as sm_mod
from ..recon import subdomains as subs_mod
from ..recon import tls as tls_mod
from ..targets import is_private_or_local
from .base import Mode, Phase, Plugin, ScanContext, register


@register
class WebAnalysis(Plugin):
    id = "web-analysis"
    title = "HTTP headers, service detection & security-header audit"
    phase = Phase.RECON
    mode = Mode.PASSIVE
    category = "web"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.web

    def run(self, ctx: ScanContext) -> None:
        http_res, services, findings, errs = http_analysis.analyze(
            ctx.target, insecure=ctx.config.insecure, auth=ctx.config.auth
        )
        ctx.result.services.extend(services)
        ctx.result.findings.extend(findings)
        ctx.result.errors.extend(errs)
        if http_res is not None:
            ctx.result.url = http_res.final_url
            ctx.http_result = http_res


@register
class Fingerprint(Plugin):
    id = "fingerprint"
    title = "technology / CDN / WAF / CMS fingerprinting"
    phase = Phase.RECON          # registered after WebAnalysis -> runs after it
    mode = Mode.PASSIVE
    category = "fingerprint"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.fingerprint

    def run(self, ctx: ScanContext) -> None:
        http = ctx.http_result
        if http is None:
            return
        techs, services, findings, platform = fp_mod.fingerprint(
            http.headers, getattr(http, "body", ""))
        ctx.result.services.extend(services)
        ctx.result.findings.extend(findings)
        ctx.result.recon["tech"] = [
            {"name": t.name, "category": t.category, "version": t.version} for t in techs
        ]
        ctx.result.recon["platform"] = platform


@register
class DnsRecon(Plugin):
    id = "dns"
    title = "DNS records (A/AAAA/MX/NS/TXT/CNAME) + reverse DNS"
    phase = Phase.RECON
    mode = Mode.PASSIVE
    category = "dns"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.dns and not ctx.target.is_ip

    def run(self, ctx: ScanContext) -> None:
        dns = dns_mod.lookup(ctx.target.host)
        ctx.result.recon["dns"] = dns
        summary = dns_mod.summarize(dns)
        if summary:
            ctx.result.findings.append(Finding(
                title="DNS records", severity=Severity.INFO, category="dns",
                description=summary, evidence=", ".join(dns.get("reverse", {}).values())[:160],
            ))


@register
class MailSecurity(Plugin):
    id = "mailsec"
    title = "e-mail security (SPF/DKIM/DMARC/MTA-STS/TLS-RPT/DNSSEC/BIMI)"
    phase = Phase.RECON
    mode = Mode.PASSIVE       # DoH lookups + the domain's own MTA-STS policy URL
    category = "mailsec"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.mailsec and not ctx.target.is_ip

    def run(self, ctx: ScanContext) -> None:
        ctx.log("assessing e-mail security (SPF/DKIM/DMARC/MTA-STS) ...")
        info, findings, errs = mailsec_mod.analyze(ctx.target.host)
        ctx.result.recon["mailsec"] = info
        ctx.result.findings.extend(findings)
        ctx.result.errors.extend(errs)
        if info.get("checks"):
            ctx.result.findings.append(Finding(
                title=f"E-mail security: grade {info['grade']} ({info['score']}/100)",
                severity=Severity.INFO, category="mailsec",
                description=mailsec_mod.summarize(info),
                evidence="MX: " + (", ".join(info.get("mx", [])) or "none")
                         + (f" ({info['provider']})" if info.get("provider") else ""),
            ))


@register
class SubdomainEnum(Plugin):
    id = "subdomains"
    title = "subdomain enumeration (crt.sh CT logs)"
    phase = Phase.RECON
    mode = Mode.PASSIVE       # crt.sh is passive; optional DNS bruteforce is benign
    category = "subdomains"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.subdomains and not ctx.target.is_ip

    def run(self, ctx: ScanContext) -> None:
        ctx.log("enumerating subdomains (crt.sh) ...")
        subs, errs = subs_mod.enumerate_subdomains(
            ctx.target.host, bruteforce=ctx.config.subdomain_bruteforce)
        ctx.result.recon["subdomains"] = subs
        ctx.result.errors.extend(errs)
        if subs:
            preview = ", ".join(subs[:15]) + (" ..." if len(subs) > 15 else "")
            ctx.result.findings.append(Finding(
                title=f"Subdomains discovered ({len(subs)})",
                severity=Severity.INFO, category="subdomains",
                description=preview,
                recommendation="Each subdomain is additional attack surface; scan the "
                               "ones in scope.",
            ))


@register
class TlsAnalysis(Plugin):
    id = "tls"
    title = "TLS/certificate analysis"
    phase = Phase.RECON
    mode = Mode.PASSIVE
    category = "tls"

    def enabled(self, ctx: ScanContext) -> bool:
        if not ctx.config.tls:
            return False
        # only for https-capable targets
        return ctx.target.scheme in (None, "https")

    def run(self, ctx: ScanContext) -> None:
        port = ctx.target.port or 443
        info, findings, errs = tls_mod.analyze(ctx.target.host, port)
        ctx.result.recon["tls"] = info
        ctx.result.findings.extend(findings)
        ctx.result.errors.extend(errs)


@register
class PortScan(Plugin):
    id = "port-scan"
    title = "nmap service/version scan"
    phase = Phase.RECON
    mode = Mode.SAFE_ACTIVE
    category = "network"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.ports

    def run(self, ctx: ScanContext) -> None:
        if not portscan.is_available():
            ctx.result.errors.append("nmap not installed — skipped port scan")
            return
        ctx.audit.active_probe(self.id, ctx.target.host, self.mode.value,
                               detail=f"top_ports={ctx.config.top_ports} range={ctx.config.port_range} "
                                      f"os_detect={ctx.config.os_detect}")
        try:
            svcs, os_info, errs = portscan.scan(
                ctx.target.host, top_ports=ctx.config.top_ports,
                ports=ctx.config.port_range, os_detect=ctx.config.os_detect,
            )
            ctx.result.services.extend(svcs)
            ctx.result.errors.extend(errs)
            if os_info:
                ctx.result.recon["os"] = os_info
                vendors = ", ".join(os_info.get("vendors") or []) or "?"
                types = ", ".join(os_info.get("device_types") or []) or "?"
                ctx.log(f"OS/device: {os_info.get('best_match')} "
                        f"({os_info.get('best_accuracy')}%) — type={types} vendor={vendors}")
        except portscan.NmapNotInstalled as e:
            ctx.result.errors.append(str(e))


@register
class Crawler(Plugin):
    id = "crawl"
    title = "crawl + JS endpoint/route extraction + source-map recovery"
    phase = Phase.DETECT
    mode = Mode.PASSIVE       # same-host GETs like a browser
    category = "crawl"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.crawl

    def run(self, ctx: ScanContext) -> None:
        base = ctx.result.url or ctx.target.web_url()
        ctx.log(f"crawling {base} (<= {ctx.config.crawl_max_pages} pages) ...")
        cr = crawler_mod.crawl(base, max_pages=ctx.config.crawl_max_pages,
                               insecure=ctx.config.insecure, auth=ctx.config.auth)
        ctx.result.errors.extend(cr.errors[:10])

        # fetch JS bodies
        js_sources: dict[str, str] = {}
        for js in list(cr.js_urls)[:30]:
            try:
                _s, body, _f = crawler_mod._fetch(js, ctx.config.insecure, ctx.config.auth)
                if body:
                    js_sources[js] = body
            except Exception:
                continue

        # JS intelligence (endpoints / routes / DOM sinks) over pages + JS
        blob = dict(cr.pages)
        blob.update(js_sources)
        endpoints, routes, sink_findings = jsintel_mod.analyze_js(blob)
        ctx.result.findings.extend(sink_findings)

        # source-map archaeology
        sm_findings: list = []
        recovered_total = 0
        if ctx.config.sourcemaps:
            for js_url, body in js_sources.items():
                recovered, fnds, _ = sm_mod.recover(js_url, body, insecure=ctx.config.insecure)
                sm_findings.extend(fnds)
                if recovered:
                    recovered_total += len(recovered)
                    sm_findings.extend(sm_mod.scan_recovered(recovered))
        ctx.result.findings.extend(sm_findings)

        # optional dynamic SPA analysis (headless browser)
        if ctx.config.dynamic and dynamic_mod.is_available():
            ctx.log("dynamic SPA render (Playwright) ...")
            dyn, derrs = dynamic_mod.crawl(
                base, max_pages=min(ctx.config.crawl_max_pages, 12),
                auth=ctx.config.auth, insecure=ctx.config.insecure)
            ctx.result.errors.extend(derrs[:10])
            for e in dyn.get("endpoints", []):
                endpoints.add(e)
            for r in dyn.get("routes", []):
                routes.add(r)
            # Re-run JS intel over the POST-JS rendered DOM — catches DOM-XSS sinks,
            # endpoints and routes that never appear in the static HTML.
            dyn_pages = dyn.get("pages", {})
            if dyn_pages:
                d_eps, d_routes, d_sinks = jsintel_mod.analyze_js(dyn_pages)
                endpoints |= d_eps
                routes |= d_routes
                ctx.result.findings.extend(d_sinks)
            if dyn.get("console_errors"):
                ctx.result.recon["dynamic_console_errors"] = dyn["console_errors"][:30]
            ctx.result.recon["dynamic"] = {
                "rendered_pages": len(dyn_pages),
                "network_endpoints": len(dyn.get("endpoints", [])),
                "routes": dyn.get("routes", [])[:50],
            }
        elif ctx.config.dynamic:
            ctx.result.errors.append(
                "dynamic: Playwright not installed (pip install playwright && "
                "playwright install chromium) — used static crawl only")

        ctx.result.recon["crawl"] = {
            "pages": len(cr.pages),
            "js_files": len(js_sources),
            "endpoints": sorted(endpoints)[:200],
            "routes": sorted(routes)[:100],
            "recovered_sources": recovered_total,
        }
        if endpoints:
            ctx.result.findings.append(Finding(
                title=f"API endpoints discovered in client code ({len(endpoints)})",
                severity=Severity.INFO, category="crawl",
                description="; ".join(sorted(endpoints)[:25]),
                recommendation="Review for undocumented/internal endpoints; test those in scope.",
            ))


@register
class ApiDiscovery(Plugin):
    id = "api-discovery"
    title = "OpenAPI/Swagger + GraphQL introspection discovery"
    phase = Phase.DETECT
    mode = Mode.SAFE_ACTIVE   # probes well-known paths + a benign GraphQL query
    category = "api-discovery"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.api_discovery

    def run(self, ctx: ScanContext) -> None:
        base = ctx.result.url or ctx.target.web_url()
        ctx.audit.active_probe(self.id, ctx.target.host, self.mode.value,
                               detail="openapi/swagger/graphql probe")
        info, findings, errs = api_mod.discover(base, insecure=ctx.config.insecure, auth=ctx.config.auth)
        ctx.result.findings.extend(findings)
        ctx.result.errors.extend(errs)
        if info.get("openapi") or info.get("graphql"):
            ctx.result.recon["api"] = info


@register
class ActiveVerification(Plugin):
    id = "active-verify"
    title = "lab-mode active verification (reflected-XSS / open-redirect / traversal / SQLi)"
    phase = Phase.DETECT
    mode = Mode.EXPLOIT       # engine gates on allow_exploit + scope EXPLOIT
    category = "active-verify"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.allow_exploit

    def run(self, ctx: ScanContext) -> None:
        from ..active.harness import LabContext, discover_points
        from ..active.verifiers import run_all

        cfg = ctx.config
        lab = LabContext(
            host=ctx.target.host, enabled=cfg.allow_exploit,
            attested=bool(cfg.lab_attestation), audit=ctx.audit, dry_run=cfg.dry_run,
            rate_limit_rps=cfg.exploit_rate_limit, max_requests=cfg.exploit_max_requests,
            insecure=cfg.insecure, log=ctx.log, auth=cfg.auth,
        )
        ready, why = lab.ready()
        if not ready:
            ctx.result.errors.append(f"active-verify: skipped ({why})")
            ctx.audit.skipped(self.id, ctx.target.host, why)
            return

        # record the attestation in the audit trail
        ctx.audit.event("lab_attestation", host=ctx.target.host,
                        statement=str(cfg.lab_attestation)[:300], dry_run=cfg.dry_run)
        base = ctx.result.url or ctx.target.web_url()
        ctx.log(f"lab-mode active verification on {base} "
                f"(dry-run={cfg.dry_run}, cap={cfg.exploit_max_requests}) ...")

        points = discover_points(base, lab)
        if not points:
            ctx.result.errors.append("active-verify: no injectable parameters found")
            return
        findings, ran = run_all(points, lab)
        ctx.result.findings.extend(findings)

        ctx.result.recon["active_verify"] = {
            "points": len(points), "checks_run": ran,
            "requests_sent": lab._count, "dry_run": cfg.dry_run,
            "halted": lab.stopped_reason or None,
            "preview": lab.preview[:50] if cfg.dry_run else [],
        }
        if cfg.dry_run:
            ctx.result.findings.append(Finding(
                title=f"[DRY-RUN] {len(lab.preview)} active probe(s) previewed (none sent)",
                severity=Severity.INFO, category="active-verify",
                description="Lab-mode dry-run: payloads were previewed and audited but "
                            "NOT sent. Re-run without --dry-run to execute.",
                recommendation="Review the previewed payloads before executing.",
            ))


@register
class AiActiveVerify(Plugin):
    id = "ai-active-verify"
    title = "agentic AI proof loop (plan -> guardrailed probe -> judge)"
    phase = Phase.DETECT
    mode = Mode.EXPLOIT       # sends real probes; engine gates on allow_exploit + scope EXPLOIT
    category = "ai-active-verify"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.ai and ctx.config.allow_exploit

    def run(self, ctx: ScanContext) -> None:
        from ..active.harness import LabContext, discover_points
        from ..ai import agent, get_provider
        from ..ai.cache import Budget
        from ..ai.provider import AIError

        cfg = ctx.config
        try:
            provider = get_provider(cfg.ai_provider, model=cfg.ai_model,
                                    api_key=cfg.ai_api_key, base_url=cfg.ai_base_url)
        except AIError as e:
            ctx.result.errors.append(f"ai-active-verify: {e}")
            return
        ok, why = provider.available()
        if not ok:
            ctx.result.errors.append(f"ai-active-verify: provider unavailable ({why})")
            return

        lab = LabContext(
            host=ctx.target.host, enabled=cfg.allow_exploit,
            attested=bool(cfg.lab_attestation), audit=ctx.audit, dry_run=cfg.dry_run,
            rate_limit_rps=cfg.exploit_rate_limit, max_requests=cfg.exploit_max_requests,
            insecure=cfg.insecure, log=ctx.log, auth=cfg.auth,
        )
        ready, why = lab.ready()
        if not ready:
            ctx.result.errors.append(f"ai-active-verify: skipped ({why})")
            ctx.audit.skipped(self.id, ctx.target.host, why)
            return

        base = ctx.result.url or ctx.target.web_url()
        ctx.log(f"ai-active-verify: agentic proof loop on {base} ...")
        points = discover_points(base, lab)
        if not points:
            ctx.result.errors.append("ai-active-verify: no injectable parameters found")
            return
        try:
            findings = agent.agentic_verify(
                ctx.result.to_dict(), points, provider, lab,
                budget=Budget(), audit=ctx.audit, log=ctx.log)
        except AIError as e:
            ctx.result.errors.append(f"ai-active-verify failed: {e}")
            return
        ctx.result.findings.extend(findings)
        ctx.result.recon["ai_active_verify"] = {
            "points": len(points), "confirmed": len(findings),
            "requests_sent": lab._count, "halted": lab.stopped_reason or None,
        }


@register
class WebHardening(Plugin):
    id = "web-hardening"
    title = "CSP deep-eval, JWT analysis, security.txt"
    phase = Phase.DETECT
    mode = Mode.PASSIVE
    category = "hardening"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.web

    def run(self, ctx: ScanContext) -> None:
        http = ctx.http_result
        if http is not None:
            ctx.result.findings.extend(webchecks.analyze_csp(http.headers))
            ctx.result.findings.extend(webchecks.analyze_jwt(http.headers, getattr(http, "body", "")))
        base = ctx.result.url or ctx.target.web_url()
        ctx.result.findings.extend(
            webchecks.check_security_txt(base, insecure=ctx.config.insecure, auth=ctx.config.auth))


@register
class Cors(Plugin):
    id = "cors"
    title = "CORS misconfiguration probe"
    phase = Phase.DETECT
    mode = Mode.SAFE_ACTIVE       # sends a few requests with crafted Origin headers
    category = "cors"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.web

    def run(self, ctx: ScanContext) -> None:
        base = ctx.result.url or ctx.target.web_url()
        ctx.audit.active_probe(self.id, ctx.target.host, self.mode.value, detail="CORS Origin probe")
        ctx.result.findings.extend(
            webchecks.check_cors(base, insecure=ctx.config.insecure, auth=ctx.config.auth))


@register
class SubdomainTakeover(Plugin):
    id = "subdomain-takeover"
    title = "dangling-CNAME subdomain takeover"
    phase = Phase.DETECT          # runs after subdomain enumeration (RECON)
    mode = Mode.SAFE_ACTIVE
    category = "takeover"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.subdomains and not ctx.target.is_ip

    def run(self, ctx: ScanContext) -> None:
        subs = ctx.result.recon.get("subdomains") or []
        if not subs:
            return
        ctx.audit.active_probe(self.id, ctx.target.host, self.mode.value,
                               detail=f"{len(subs)} subdomains")
        ctx.log(f"checking {min(len(subs), 40)} subdomain(s) for takeover ...")
        ctx.result.findings.extend(webchecks.check_takeover(subs, insecure=ctx.config.insecure))


@register
class WebSecrets(Plugin):
    id = "web-secrets"
    title = "front-end secret scan (HTML + linked JS)"
    phase = Phase.DETECT
    mode = Mode.PASSIVE
    category = "exposed-secret"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.web_secrets

    def run(self, ctx: ScanContext) -> None:
        if ctx.http_result is None and not ctx.result.url:
            return
        url = ctx.result.url or ctx.target.web_url()
        findings, errs = websecrets.scan_page(url, insecure=ctx.config.insecure, auth=ctx.config.auth)
        ctx.result.findings.extend(findings)
        ctx.result.errors.extend(errs)


@register
class Nuclei(Plugin):
    id = "nuclei"
    title = "nuclei web-vulnerability templates"
    phase = Phase.DETECT
    mode = Mode.SAFE_ACTIVE
    category = "nuclei"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.nuclei

    def run(self, ctx: ScanContext) -> None:
        if not nuclei_scan.is_available():
            ctx.result.errors.append("nuclei not found — skipped (install nuclei to enable)")
            return
        url = ctx.result.url or ctx.target.web_url()
        tags = None if ctx.config.nuclei_full else (ctx.config.nuclei_tags or nuclei_scan.DEFAULT_TAGS)
        ctx.audit.active_probe(self.id, ctx.target.host, self.mode.value,
                               detail=f"tags={tags or 'ALL'}")
        hdrs = ([f"{k}: {v}" for k, v in ctx.config.auth.headers.items()]
                if ctx.config.auth else None)
        nf, errs = nuclei_scan.scan(url, tags=tags, headers=hdrs)
        ctx.result.findings.extend(nf)
        ctx.result.errors.extend(errs)


@register
class CveLookup(Plugin):
    id = "cve-lookup"
    title = "NVD + MITRE CVE lookup for detected versions"
    phase = Phase.ENRICH
    mode = Mode.PASSIVE
    category = "cve"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.cve

    def run(self, ctx: ScanContext) -> None:
        versioned = [s for s in ctx.result.services if s.version]
        if not versioned:
            ctx.result.errors.append("no versioned services detected — nothing to look up in NVD")
            return
        ctx.log(f"NVD CVE lookup for {len(versioned)} versioned service(s) ...")
        cves, notes = cve_mod.lookup_all(
            ctx.result.services, api_key=ctx.config.nvd_api_key, progress=ctx.log
        )
        ctx.result.cves.extend(cves)
        ctx.result.errors.extend(notes)


@register
class CveVerification(Plugin):
    id = "cve-verify"
    title = "confirm detected CVEs with matching nuclei templates (non-destructive)"
    phase = Phase.ENRICH      # registered after cve-lookup -> runs after it
    mode = Mode.SAFE_ACTIVE   # sends real probes; engine gates on scope/allow_active
    category = "cve-verify"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.cve_verify and bool(ctx.result.cves)

    def run(self, ctx: ScanContext) -> None:
        from .. import cveverify
        url = ctx.result.url or ctx.target.web_url()
        cve_ids = sorted({c.id for c in ctx.result.cves})
        ctx.audit.active_probe(self.id, ctx.target.host, self.mode.value,
                               detail=f"nuclei -id for {len(cve_ids)} CVE(s)")
        ctx.log(f"verifying {len(cve_ids)} CVE(s) with nuclei templates ...")
        confirmed, hits, errs = cveverify.verify_cves(url, cve_ids)
        ctx.result.errors.extend(errs)
        if confirmed:
            for c in ctx.result.cves:
                if c.id in confirmed:
                    c.verified = True
            ctx.result.findings.append(Finding(
                title=f"CVE(s) CONFIRMED on live target: {', '.join(sorted(confirmed))}",
                severity=Severity.CRITICAL, category="cve-verify",
                description="A matching nuclei template fired against the target, "
                            "confirming the vulnerability is present and reachable "
                            "(non-destructively).",
                recommendation="Patch urgently — this is verified, not just version-inferred.",
                evidence="; ".join(f"{h['cve']} @ {h['matched_at']}" for h in hits)[:300],
                confidence="high",
            ))
            ctx.result.recon["cve_verified"] = sorted(confirmed)


@register
class AIAnalysis(Plugin):
    id = "ai-analysis"
    title = "AI triage + attack-surface hypotheses (DeepSeek by default)"
    phase = Phase.ENRICH      # runs last, after CVEs are gathered
    mode = Mode.PASSIVE       # sends data to an LLM; doesn't probe the target
    category = "ai-hypothesis"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.ai

    def run(self, ctx: ScanContext) -> None:
        from ..ai import analyze, get_provider
        from ..ai.cache import Budget
        from ..ai.provider import AIError

        cfg = ctx.config
        try:
            provider = get_provider(cfg.ai_provider, model=cfg.ai_model,
                                    api_key=cfg.ai_api_key, base_url=cfg.ai_base_url)
        except AIError as e:
            ctx.result.errors.append(f"ai-analysis: {e}")
            return
        ok, why = provider.available()
        if not ok:
            ctx.result.errors.append(f"ai-analysis: provider '{cfg.ai_provider}' unavailable ({why})")
            return

        ctx.log(f"AI triage via {provider.name}/{provider.model} ...")
        try:
            findings, summary = analyze.triage_scan(
                ctx.result.to_dict(), provider,
                redact_secrets=cfg.ai_redact, budget=Budget(), audit=ctx.audit,
            )
        except AIError as e:
            ctx.result.errors.append(f"ai-analysis failed: {e}")
            return

        if summary:
            ctx.result.findings.append(Finding(
                title="[AI] Analysis summary",
                severity=Severity.INFO, category="ai-summary",
                description=summary,
                recommendation="AI-generated; treat hypotheses as leads to verify, not facts.",
            ))
        ctx.result.findings.extend(findings)


@register
class ExploitabilityAssessment(Plugin):
    id = "exploitability"
    title = "exploitability assessment (EPSS + CISA KEV + reachability + how-to)"
    phase = Phase.ENRICH      # registered last -> runs after CVE + AI findings exist
    mode = Mode.PASSIVE       # third-party enrichment; no target interaction
    category = "exploitability"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.exploitability

    def run(self, ctx: ScanContext) -> None:
        from .. import exploitability as exploit_mod
        if not ctx.result.cves and not ctx.result.findings:
            return
        exploit_mod.assess(ctx.result, log=ctx.log)


@register
class Correlation(Plugin):
    id = "correlation"
    title = "exploit-chain correlation + completeness critic"
    phase = Phase.ENRICH      # registered last -> runs after exploitability
    mode = Mode.PASSIVE
    category = "correlation"

    def enabled(self, ctx: ScanContext) -> bool:
        return True

    def run(self, ctx: ScanContext) -> None:
        from .. import correlate, completeness
        ctx.result.chains = correlate.correlate(ctx.result)
        ctx.result.coverage = completeness.assess_coverage(ctx.result, ctx.config)
        if ctx.result.chains:
            ctx.log(f"correlated {len(ctx.result.chains)} exploit chain(s)")
