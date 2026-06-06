"""Built-in checks, migrated to the plugin interface.

Each plugin wraps an existing analysis module. Logic stays in those modules; the
plugins handle orchestration, phase ordering, and mode classification.
"""

from __future__ import annotations

from .. import cve as cve_mod
from .. import http_analysis, nuclei_scan, portscan, webchecks, websecrets
from ..models import Finding, Service, Severity
from ..recon import apidisco as api_mod
from ..recon import apphint as apphint_mod
from ..recon import cohost as cohost_mod
from ..recon import appversion as appversion_mod
from ..recon import content_discovery as cd_mod
from ..recon import origin as origin_mod
from ..recon import crawler as crawler_mod
from ..recon import dns as dns_mod
from ..recon import dynamic as dynamic_mod
from ..recon import favicon as favicon_mod
from ..recon import fingerprint as fp_mod
from ..recon import jsintel as jsintel_mod
from ..recon import mailsec as mailsec_mod
from ..recon import robots as robots_mod
from ..recon import sourcemaps as sm_mod
from ..recon import subdomains as subs_mod
from ..recon import wayback as wayback_mod
from ..recon import tls as tls_mod
from .base import Mode, Phase, Plugin, ScanContext, register

_SEV_BY_NAME = {s.name: s for s in Severity}   # "HIGH" -> Severity.HIGH


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
class AppHint(Plugin):
    id = "app-hint"
    title = "likely service from hostname naming convention"
    phase = Phase.RECON          # registered after Fingerprint -> runs after it
    mode = Mode.PASSIVE
    category = "fingerprint"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.fingerprint

    def run(self, ctx: ScanContext) -> None:
        hint = apphint_mod.hint_from_hostname(ctx.target.host)
        if not hint:
            return
        ctx.result.recon["app_hint"] = hint
        # Only surface a finding when direct fingerprinting found no app — the
        # service is auth-gated, down (502), or returns a bare 404. If the app was
        # already identified from the response, the hostname hint is redundant.
        tech = ctx.result.recon.get("tech") or []
        if any(t.get("category") in ("app", "cms", "auth") for t in tech):
            return
        ctx.result.findings.append(Finding(
            title=f"Likely service (hostname convention): {hint}",
            severity=Severity.INFO, category="fingerprint", confidence="low",
            description=(
                f"The hostname '{ctx.target.host}' follows the common self-hosted naming "
                f"convention for {hint}, but direct fingerprinting was inconclusive — the "
                "service is likely behind an auth gate, down, or on another port. A naming "
                "hint, not confirmation."),
        ))


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
                resolved_ip=ctx.result.ip,
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
        endpoints, routes, sink_findings = jsintel_mod.analyze_js(blob, ctx.target.host)
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
            endpoints |= jsintel_mod.scope_endpoints(set(dyn.get("endpoints", [])), ctx.target.host)
            for r in dyn.get("routes", []):
                routes.add(r)
            # Re-run JS intel over the POST-JS rendered DOM — catches DOM-XSS sinks,
            # endpoints and routes that never appear in the static HTML.
            dyn_pages = dyn.get("pages", {})
            if dyn_pages:
                d_eps, d_routes, d_sinks = jsintel_mod.analyze_js(dyn_pages, ctx.target.host)
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
                "dynamic: Playwright not installed (uv sync --extra dynamic && "
                "uv run playwright install chromium) — used static crawl only")

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

        # client-side SCA: known JS libraries + versions -> OSV.dev (no source needed)
        try:
            from .. import sca as sca_mod
            from ..recon import clientsca
            libs = clientsca.detect_libraries(cr.js_urls, js_sources, pages=cr.pages)
            if libs:
                ctx.result.recon["client_libs"] = sorted(f"{d.name}@{d.version}" for d in libs)
                cfindings, cerrs = sca_mod.audit_deps(libs)
                ctx.result.errors.extend(cerrs)
                for f in cfindings:
                    ctx.result.findings.append(Finding(
                        title=f["title"].replace("Vulnerable dependency:",
                                                 "Outdated client-side library:"),
                        severity=_SEV_BY_NAME.get(f.get("severity", "MEDIUM"), Severity.MEDIUM),
                        category="client-sca",
                        description=f.get("evidence", ""),
                        recommendation=f.get("recommendation", ""),
                        evidence=f.get("rule_id", ""), confidence="firm",
                    ))
        except Exception as e:                       # never let recon crash the scan
            ctx.result.errors.append(f"client-sca: {e}")


@register
class Wayback(Plugin):
    id = "wayback"
    title = "archive.org historical URL + parameter harvesting"
    phase = Phase.RECON
    mode = Mode.PASSIVE       # queries archive.org, never the target
    category = "recon"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.wayback and not ctx.target.is_ip

    def run(self, ctx: ScanContext) -> None:
        ctx.log(f"harvesting archive.org URLs for {ctx.target.host} ...")
        findings, urls, params, errs = wayback_mod.harvest(ctx.target.host)
        ctx.result.findings.extend(findings)
        ctx.result.errors.extend(errs[:5])
        if urls:
            ctx.result.recon["wayback_urls"] = urls[:200]
        if params:
            ctx.result.recon["wayback_params"] = params


@register
class FaviconFingerprint(Plugin):
    id = "favicon"
    title = "favicon hash fingerprint (app identification + Shodan pivot)"
    phase = Phase.RECON          # after WebAnalysis -> reuse the fetched HTML/body
    mode = Mode.PASSIVE
    category = "fingerprint"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.favicon

    def run(self, ctx: ScanContext) -> None:
        base = ctx.result.url or ctx.target.web_url()
        html = getattr(ctx.http_result, "body", "") if ctx.http_result else ""
        services, findings, h, errs = favicon_mod.analyze(
            base, html=html, insecure=ctx.config.insecure, auth=ctx.config.auth)
        ctx.result.services.extend(services)
        ctx.result.findings.extend(findings)
        ctx.result.errors.extend(errs[:3])
        if h is not None:
            ctx.result.recon["favicon_hash"] = h


@register
class RobotsSitemap(Plugin):
    id = "robots"
    title = "robots.txt + sitemap.xml path harvesting"
    phase = Phase.RECON          # registered after WebAnalysis -> ctx.result.url set
    mode = Mode.PASSIVE
    category = "recon"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.robots and not ctx.target.is_ip

    def run(self, ctx: ScanContext) -> None:
        base = ctx.result.url or ctx.target.web_url()
        findings, paths, sitemap_urls, errs = robots_mod.harvest(
            base, insecure=ctx.config.insecure, auth=ctx.config.auth)
        ctx.result.findings.extend(findings)
        ctx.result.errors.extend(errs[:5])
        if paths:
            ctx.result.recon["robots_paths"] = paths
        if sitemap_urls:
            ctx.result.recon["sitemap_urls"] = sitemap_urls[:200]


@register
class ContentDiscovery(Plugin):
    id = "content-discovery"
    title = "exposed sensitive files (.git/.env/backups/server-status)"
    phase = Phase.DETECT
    mode = Mode.SAFE_ACTIVE   # GETs paths a browser wouldn't request
    category = "exposure"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.content_discovery and not ctx.target.is_ip

    def run(self, ctx: ScanContext) -> None:
        base = ctx.result.url or ctx.target.web_url()
        ctx.log(f"probing {base} for exposed sensitive files ...")
        findings, paths, errs = cd_mod.discover(
            base, insecure=ctx.config.insecure, auth=ctx.config.auth)
        ctx.result.findings.extend(findings)
        ctx.result.errors.extend(errs[:10])
        if paths:
            ctx.result.recon["exposed_paths"] = paths


# Shared CDN/WAF edges: a reverse-IP lookup here returns OTHER tenants of the CDN,
# not co-located infrastructure — pure noise. Detected via the fingerprint pass.
_SHARED_CDNS = ("cloudflare", "fastly", "cloudfront", "akamai", "bunny cdn", "keycdn",
                "stackpath", "sucuri", "imperva", "incapsula", "google cloud cdn")


def _fronting_cdn(recon: dict) -> Optional[str]:
    """Name of a shared CDN/WAF fronting the target (from the fingerprint), or None."""
    for t in (recon.get("tech") or []):
        if t.get("category") in ("cdn", "waf"):
            name = (t.get("name") or "")
            if any(c in name.lower() for c in _SHARED_CDNS):
                return name
    return None


@register
class AppVersionProbe(Plugin):
    id = "app-version"
    title = "self-hosted app version disclosure (status/health endpoints)"
    phase = Phase.DETECT      # before ENRICH cve-lookup, so the version feeds CVE matching
    mode = Mode.SAFE_ACTIVE   # a handful of GETs to well-known unauthenticated API paths

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.web and not ctx.target.is_ip

    def run(self, ctx: ScanContext) -> None:
        base = ctx.result.url or ctx.target.web_url()
        ctx.audit.active_probe(self.id, ctx.target.host, self.mode.value,
                               detail="self-hosted app version endpoints")
        hits = appversion_mod.probe(base, insecure=ctx.config.insecure, auth=ctx.config.auth)
        if not hits:
            return
        for h in hits:
            # add as a versioned service so cve-lookup (ENRICH) can match it
            ctx.result.services.append(Service(
                name=h["app"], version=h["version"], source=f"app-api:{h['path']}"))
            ctx.result.findings.append(Finding(
                title=f"App version disclosed: {h['app']} {h['version']}",
                severity=Severity.LOW, category="app-version",
                description=(f"{h['app']} reveals its exact version ({h['version']}) on the "
                             f"unauthenticated endpoint {h['path']} — readable even behind a CDN that "
                             "hides the Server header, and enough to target version-specific exploits."),
                recommendation=(f"Restrict or authenticate {h['path']}, and keep {h['app']} updated; "
                                "the disclosed version feeds the CVE lookup."),
                evidence=f"GET {h['path']} → version {h['version']}"))
        ctx.log("app-version: disclosed " + ", ".join(f"{h['app']} {h['version']}" for h in hits))


@register
class CoHostDiscovery(Plugin):
    id = "cohost"
    title = "co-hosted hosts on the same IP (cert SANs + reverse-IP)"
    phase = Phase.DETECT      # after TLS (SANs) + IP resolution
    mode = Mode.PASSIVE       # cert already fetched; reverse-IP is a passive 3rd-party lookup
    category = "cohost"

    def run(self, ctx: ScanContext) -> None:
        sans = (ctx.result.recon.get("tls") or {}).get("san", [])
        # reverse-IP is an external lookup — tie it to the "enumerate more hosts"
        # intent (subdomains opt-in); cert-SAN harvest is free and always runs. Skip
        # it behind a shared CDN, where the resolved IP is an edge serving thousands
        # of unrelated tenants (e.g. Cloudflare) — the "siblings" would be noise.
        cdn = _fronting_cdn(ctx.result.recon)
        do_rip = ctx.config.subdomains and not cdn
        if ctx.config.subdomains and cdn:
            ctx.result.errors.append(
                f"cohost: target is behind {cdn} (shared CDN) — reverse-IP cohosting "
                "skipped; co-tenants on a CDN edge are unrelated to this host. Cert-SAN "
                "siblings still reported.")
        info = cohost_mod.discover(ctx.target.host, ctx.result.ip, sans,
                                   do_reverse_ip=do_rip)
        if info.get("error"):
            ctx.result.errors.append(f"cohost: {info['error']}")
        sibs = info.get("siblings", [])
        if sibs:
            ctx.result.recon["cohosted"] = info
            shown = ", ".join(sibs[:25]) + (" …" if len(sibs) > 25 else "")
            srcs = []
            if info.get("from_san"):
                srcs.append("cert SAN")
            if info.get("from_reverse_ip"):
                srcs.append("reverse-IP")
            ctx.result.findings.append(Finding(
                title=f"Co-hosted hostnames on {ctx.result.ip or 'this IP'} ({len(sibs)})",
                severity=Severity.INFO, category="cohost",
                description=f"Other hostnames served from the same IP (via {', '.join(srcs)}): {shown}. "
                            "Each is a separate service on the same box — scan the ones in scope.",
                recommendation="Queue scans of these hosts too; one reverse proxy often fronts many apps.",
                evidence=", ".join(sibs[:40]),
            ))


@register
class OriginExposure(Plugin):
    id = "origin-exposure"
    title = "origin / CDN-bypass exposure (hostnames that skip the CDN)"
    phase = Phase.ENRICH      # after subdomains + dns + cohost (SANs) + fingerprint
    mode = Mode.PASSIVE       # DoH resolutions only

    def enabled(self, ctx: ScanContext) -> bool:
        # Only meaningful when the target itself is fronted by a CDN.
        return bool(_fronting_cdn(ctx.result.recon)
                    or origin_mod.cdn_for_ip(ctx.result.ip or ""))

    def run(self, ctx: ScanContext) -> None:
        recon = ctx.result.recon
        cdn = (_fronting_cdn(recon) or origin_mod.cdn_for_ip(ctx.result.ip or "")
               or "a CDN")
        apex = ".".join(ctx.target.host.split(".")[-2:])
        # mail hosts are EXPECTED off-CDN (intel, not a leak); web hosts that bypass
        # the CDN are the real finding.
        mailish = set(origin_mod.mx_hosts((recon.get("dns") or {}).get("records", {})))
        mailish.update(f"{p}.{apex}" for p in ("mail", "webmail", "smtp", "imap", "pop", "mx"))
        web = set(recon.get("subdomains") or [])
        web.update((recon.get("cohosted") or {}).get("from_san") or [])
        web.update(f"{p}.{apex}" for p in ("direct", "origin", "direct-connect", "cpanel",
                                           "dev", "staging", "server", "ssh", "vpn", "ftp", "www"))
        candidates = {h for h in (web | mailish) if h and h != ctx.target.host}
        if not candidates:
            return
        exposed = origin_mod.find_exposed_origins(sorted(candidates))
        recon["origin_exposure"] = {"cdn": cdn, "checked": len(candidates), "exposed": exposed}
        for e in exposed:
            is_mail = e["host"] in mailish and e["host"] not in web
            ips = ", ".join(e["origin_ips"])
            if is_mail:
                ctx.result.findings.append(Finding(
                    title=f"Mail/non-CDN host reveals hosting network: {e['host']} → {ips}",
                    severity=Severity.INFO, category="origin-exposure",
                    description=(f"{e['host']} resolves to {ips} (not behind {cdn}). Mail hosts are "
                                 "normally un-proxied, but the IP/ASN narrows down where the origin "
                                 "is hosted — a pivot point for finding the web origin."),
                    recommendation=f"Check whether the web origin shares this network ({ips}).",
                    evidence=f"{e['host']} A/AAAA: {', '.join(e['ips'])}"))
                continue
            ctx.result.findings.append(Finding(
                title=f"Possible origin behind {cdn}: {e['host']} → {ips}",
                severity=Severity.MEDIUM, category="origin-exposure",
                description=(f"{e['host']} resolves to {ips}, which is not in {cdn}'s ranges — likely "
                             f"an un-proxied origin/service. The site is fronted by {cdn}, but this "
                             "hostname bypasses it, exposing a real IP to direct scanning "
                             "(version/CVE fingerprinting and attacks that skip the WAF/DDoS edge)."),
                recommendation=(f"Scan {e['origin_ips'][0]} directly with a 'Host: {ctx.target.host}' "
                                f"header to fingerprint the real service. Defensively: firewall the "
                                f"origin to accept only {cdn}'s published IP ranges."),
                evidence=f"{e['host']} A/AAAA: {', '.join(e['ips'])}"))
        n_web = sum(1 for e in exposed if not (e["host"] in mailish and e["host"] not in web))
        if exposed:
            ctx.log(f"origin-exposure: {len(exposed)} host(s) bypass {cdn} "
                    f"({n_web} possible web origin(s)) → candidate IP(s)")
        else:
            ctx.log(f"origin-exposure: behind {cdn}; no hostname bypasses it via DNS")

        self._origin_hunt(ctx, recon, cdn, apex)

    def _origin_hunt(self, ctx: ScanContext, recon: dict, cdn: str, apex: str) -> None:
        """Beyond DNS: generate Shodan/Censys pivots from the favicon hash + cert, and
        (with SHODAN_API_KEY) look up candidate IPs and confirm each by connecting with
        a Host: header — getting the origin's REAL Server header the CDN hides."""
        import os
        fav = recon.get("favicon_hash")
        sans = (recon.get("tls") or {}).get("san") or []
        pivots = origin_mod.pivot_queries(ctx.target.host, favicon_hash=fav, sans=sans)
        recon["origin_exposure"]["pivots"] = pivots
        ctx.result.findings.append(Finding(
            title=f"Hunt the origin behind {cdn} — {len(pivots)} ready search(es)",
            severity=Severity.INFO, category="origin-exposure",
            description=("The origin IP isn't in any HTTP response, but an IP serving the same "
                         "TLS cert / favicon directly is indexed by Shodan/Censys. Run these to "
                         "find it: " + " · ".join(f"{p['engine']}: {p['query']}" for p in pivots)),
            recommendation="Open the queries (Shodan/Censys) and scan any non-CDN IP that serves the "
                           "same site; set SHODAN_API_KEY or CENSYS_PAT/CENSYS_ORG_ID to let "
                           "celsius look them up and Host-verify automatically.",
            evidence="  ".join(p["url"] for p in pivots)))

        shodan_key = os.environ.get("SHODAN_API_KEY", "")
        censys_pat = os.environ.get("CENSYS_PAT", "")
        censys_org = os.environ.get("CENSYS_ORG_ID", "")
        if not (shodan_key or (censys_pat and censys_org)):
            return
        candidates: list = []
        for p in pivots:
            if p["engine"] == "Shodan" and shodan_key:
                ips, err = origin_mod.shodan_search(p["query"], shodan_key)
            elif p["engine"] == "Censys" and censys_pat and censys_org:
                ips, err = origin_mod.censys_search(p["query"], censys_pat, censys_org)
            else:
                continue
            if err:
                ctx.result.errors.append(f"origin-exposure: {err}")
                continue   # one engine/query failing shouldn't stop the others
            for ip in ips:
                if ip not in candidates and not origin_mod.cdn_for_ip(ip):
                    candidates.append(ip)
        candidates = candidates[:20]
        recon["origin_exposure"]["candidates"] = candidates
        if not candidates or not ctx.config.allow_active:
            if candidates:
                ctx.log(f"origin-exposure: {len(candidates)} candidate IP(s) from Shodan/Censys; "
                        "skipping live Host-verification (safe-active not allowed)")
            return
        confirmed = []
        for ip in candidates:
            ctx.audit.active_probe(self.id, ctx.target.host, "safe-active",
                                   detail=f"origin Host-verify {ip}")
            v = origin_mod.verify_origin(ip, ctx.target.host, expected_favicon=fav)
            if v.get("reachable"):
                confirmed.append(v)
        recon["origin_exposure"]["verified"] = confirmed
        for v in confirmed:
            proven = v.get("matched")
            sev = Severity.HIGH if proven else Severity.MEDIUM
            srv = f" Real Server header: {v['server']}." if v.get("server") else ""
            ctx.result.findings.append(Finding(
                title=(f"Origin server found behind {cdn}: {v['ip']}"
                       + (" (confirmed)" if proven else " (candidate)")),
                severity=sev, category="origin-exposure",
                description=(f"{v['ip']} answers for {ctx.target.host} directly (HTTP {v.get('status')}), "
                             f"bypassing {cdn}. {v.get('how','')}." + srv +
                             " The CDN's WAF/DDoS protection can be skipped by hitting this IP."),
                recommendation=(f"Scan {v['ip']} directly to fingerprint versions/CVEs. Defensively: "
                                f"firewall the origin to accept only {cdn}'s published IP ranges."),
                evidence=f"{v['ip']}:{v.get('port')} title={v.get('title','')!r} server={v.get('server','')!r}"))
        if confirmed:
            ctx.log(f"origin-exposure: Shodan→ {len(confirmed)} candidate origin(s) answered directly "
                    f"({sum(1 for v in confirmed if v.get('matched'))} confirmed by favicon)")


@register
class InternalExposure(Plugin):
    id = "internal-exposure"
    title = "internal/VPN address leaked in public DNS (RFC1918, Tailscale, *.ts.net)"
    phase = Phase.ENRICH      # after subdomains + dns + cohost (SANs)
    mode = Mode.PASSIVE       # DoH resolutions only

    def enabled(self, ctx: ScanContext) -> bool:
        return not ctx.target.is_ip

    def run(self, ctx: ScanContext) -> None:
        recon = ctx.result.recon
        hosts = {ctx.target.host}
        hosts.update(recon.get("subdomains") or [])
        hosts.update((recon.get("cohosted") or {}).get("from_san") or [])
        hosts.update(origin_mod.mx_hosts((recon.get("dns") or {}).get("records", {})))
        leaks = origin_mod.find_internal_leaks(sorted(h for h in hosts if h))
        if not leaks:
            return
        recon["internal_exposure"] = leaks
        for e in leaks:
            where = ", ".join(e["ts_net"]) if e["ts_net"] else ", ".join(e["ips"])
            detail = ("a Tailscale tailnet address — revealing that Tailscale is in use and the "
                      "internal/VPN topology." if e["kind"] == "Tailscale" else
                      f"an internal/{e['kind']} address that should not be in public DNS.")
            ctx.result.findings.append(Finding(
                title=f"Internal address in public DNS: {e['host']} → {where} ({e['kind']})",
                severity=Severity.LOW, category="internal-exposure",
                description=(f"{e['host']} resolves in PUBLIC DNS to {where} — {detail} It leaks "
                             "internal infrastructure and aids network mapping / SSRF targeting."),
                recommendation=("Serve internal names only over split-horizon DNS / Tailscale MagicDNS; "
                                "remove the internal record from public DNS."),
                evidence=f"{e['host']} -> {', '.join(e['ips'])}"
                         + (f" CNAME {', '.join(e['ts_net'])}" if e["ts_net"] else "")))
        ctx.log("internal-exposure: " + ", ".join(f"{e['host']} ({e['kind']})" for e in leaks))


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
        # fold any endpoints the crawler surfaced into the BOLA/IDOR analysis
        crawl = ctx.result.recon.get("crawl") or {}
        extra = list(crawl.get("endpoints") or []) + list(crawl.get("routes") or [])
        info, findings, errs = api_mod.discover(
            base, insecure=ctx.config.insecure, auth=ctx.config.auth, extra_endpoints=extra)
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
        budget = Budget(max_tokens=2_000_000)   # don't starve the analysis of tokens
        try:
            # 1. Injection proof loop on discovered parameters (XSS/redirect/SQLi/…)
            points = discover_points(base, lab)
            if points:
                inj = agent.agentic_verify(ctx.result.to_dict(), points, provider, lab,
                                           budget=budget, audit=ctx.audit, log=ctx.log)
                ctx.result.findings.extend(inj)
            else:
                inj = []

            # 2. Tool loop: prove/refute the AI hypotheses, drop the refuted ones.
            hyps = [f for f in ctx.result.findings if f.category == "ai-hypothesis"]
            vstats = {}
            if hyps:
                verdicts = agent.prove_hypotheses(
                    ctx.result.to_dict(), [f.to_dict() for f in hyps], provider, lab,
                    budget=budget, audit=ctx.audit, log=ctx.log, max_calls=30)
                ctx.result.findings, vstats = agent.apply_verdicts(ctx.result.findings, verdicts)
                ctx.log(f"ai-prove: {vstats.get('confirmed', 0)} confirmed, "
                        f"{vstats.get('refuted', 0)} refuted, "
                        f"{vstats.get('needs_manual', 0)} need manual")
        except AIError as e:
            ctx.result.errors.append(f"ai-active-verify failed: {e}")
            return
        ctx.result.recon["ai_active_verify"] = {
            "injection_points": len(points), "injection_confirmed": len(inj),
            "hypotheses": len(hyps), "verdicts": vstats,
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
        if ctx.config.cve_pocs and cves:
            n = cve_mod.enrich_pocs(ctx.result.cves)
            if n:
                ctx.log(f"exploit-PoC enrichment: linked {n} CVE(s) to public PoCs (trickest/cve)")


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


def _cve_pocs(c) -> list:
    return c.poc_refs()[:4] if c is not None else []


def _verification_record(c, v: dict, target_url: str) -> dict:
    """What the AI verification settled for a CVE, plus a manual-repro package — so
    every firm CVE carries its outcome and (for unproven ones) everything needed to
    confirm it by hand."""
    rec = {"status": v.get("status"), "reasoning": v.get("reasoning", ""),
           "evidence": v.get("evidence", ""), "poc_grounded": bool(v.get("grounded_in_poc"))}
    if v.get("curl"):
        rec["probe"] = v["curl"]                       # the benign probe actually sent
    rec["manual_repro"] = {                            # B: verify-it-yourself package
        "target": target_url,
        "matched": (c.affects or f"{c.product} {c.version}".strip()) if c is not None else "",
        "public_poc": _cve_pocs(c),
    }
    return rec


def _cve_verify_finding(c, v: dict, target_url: str):
    """A Finding for a noteworthy verdict: confirmed (proven), reachable (vulnerable
    code path active — the oracle tier), or a manual-verification to-do for a firm
    HIGH+/PoC-backed CVE an automated benign probe couldn't settle. None otherwise."""
    status = v.get("status")
    cve = v.get("cve")
    sev = c.severity if c is not None else Severity.HIGH
    grounded = (" The probe was grounded in the public PoC technique (trickest/cve write-up)."
                if v.get("grounded_in_poc") else "")
    pocs = _cve_pocs(c)
    if status == "confirmed":
        return Finding(
            title=f"CVE CONFIRMED by AI probe: {cve}",
            severity=sev, category="ai-cve-verify",
            description=(v.get("reasoning", "") + " Confirmed by an AI-planned, non-destructive "
                         "probe on an authorized lab target." + grounded).strip(),
            recommendation="Verified present & reachable — patch urgently. "
                           "Reproduce with the captured request.",
            evidence=(f"{v.get('evidence', '')}  {v.get('curl', '')}").strip()[:300],
            confidence="high",
            exploitability={"verdict": "confirmed-exploitable", "priority": 92,
                            "signals": {"reachable": True, "actively_verified": True,
                                        "ai_planned": True,
                                        "poc_grounded": bool(v.get("grounded_in_poc"))}})
    if status == "reachable":
        return Finding(
            title=f"CVE reachable — vulnerable code path active: {cve}",
            severity=(sev if sev.rank <= Severity.HIGH.rank else Severity.HIGH),
            category="ai-cve-verify",
            description=(v.get("reasoning", "") + " A non-destructive probe shows the vulnerable "
                         "code path is present and reachable on this host — strong corroboration, "
                         "not full exploitation." + grounded).strip(),
            recommendation=("Treat the host as affected and patch. To fully prove exploitability, "
                            "reproduce the public PoC in an isolated copy"
                            + (": " + ", ".join(pocs) if pocs else ".")),
            evidence=(f"{v.get('evidence', '')}  {v.get('curl', '')}").strip()[:300],
            confidence="medium",
            exploitability={"verdict": "likely-exploitable", "priority": 75,
                            "signals": {"reachable": True, "actively_verified": True,
                                        "ai_planned": True,
                                        "poc_grounded": bool(v.get("grounded_in_poc"))}})
    # B: a firm, high-impact / PoC-backed CVE a benign probe couldn't settle -> to-do.
    if status in ("needs-manual", "inconclusive") and c is not None and (
            sev.rank >= Severity.HIGH.rank or pocs):
        why = v.get("reasoning") or "no safe automated probe distinguishes vulnerable from patched"
        steps = [f"Target: {target_url}", f"Matched: {c.affects or (c.product + ' ' + c.version)}"]
        if pocs:
            steps.append("Public PoC: " + ", ".join(pocs))
        if v.get("curl"):
            steps.append("Benign probe already sent: " + v["curl"])
        return Finding(
            title=f"CVE needs manual verification: {cve}",
            severity=(Severity.MEDIUM if sev.rank > Severity.MEDIUM.rank else sev),
            category="ai-cve-manual",
            description=(f"Firm version match for {cve} that an automated benign probe could not "
                         f"settle ({status}): {why}." + grounded).strip(),
            recommendation="Verify by hand — everything you need:\n  • " + "\n  • ".join(steps),
            evidence=(v.get("evidence", "") or "")[:300],
            confidence="medium",
            exploitability={"verdict": "needs-manual", "priority": 50,
                            "signals": {"reachable": False, "ai_planned": True,
                                        "has_poc": bool(pocs),
                                        "poc_grounded": bool(v.get("grounded_in_poc"))}})
    return None


@register
class AiCveVerify(Plugin):
    id = "ai-cve-verify"
    title = "AI-planned benign verification of detected CVEs (lab mode)"
    phase = Phase.ENRICH      # after cve-lookup + nuclei cve-verify
    mode = Mode.EXPLOIT       # sends crafted probes; engine gates on allow_exploit + scope
    category = "ai-cve-verify"

    def enabled(self, ctx: ScanContext) -> bool:
        return ctx.config.ai and ctx.config.allow_exploit and bool(ctx.result.cves)

    def run(self, ctx: ScanContext) -> None:
        from ..active.harness import LabContext
        from ..ai import agent, get_provider
        from ..ai.cache import Budget
        from ..ai.provider import AIError

        cfg = ctx.config
        # Only firm, not-yet-verified CVEs are worth a probe; nuclei (cve-verify)
        # may have already confirmed some, and weak matches are likely FPs.
        todo = [c for c in ctx.result.cves if c.confidence != "weak" and not c.verified]
        if not todo:
            return
        try:
            provider = get_provider(cfg.ai_provider, model=cfg.ai_model,
                                    api_key=cfg.ai_api_key, base_url=cfg.ai_base_url)
        except AIError as e:
            ctx.result.errors.append(f"ai-cve-verify: {e}")
            return
        ok, why = provider.available()
        if not ok:
            ctx.result.errors.append(f"ai-cve-verify: provider unavailable ({why})")
            return

        lab = LabContext(
            host=ctx.target.host, enabled=cfg.allow_exploit,
            attested=bool(cfg.lab_attestation), audit=ctx.audit, dry_run=cfg.dry_run,
            rate_limit_rps=cfg.exploit_rate_limit, max_requests=cfg.exploit_max_requests,
            insecure=cfg.insecure, log=ctx.log, auth=cfg.auth,
        )
        ready, why = lab.ready()
        if not ready:
            ctx.result.errors.append(f"ai-cve-verify: skipped ({why})")
            ctx.audit.skipped(self.id, ctx.target.host, why)
            return

        ctx.log(f"ai-cve-verify: planning benign probes for {len(todo)} firm CVE(s) ...")
        try:
            verdicts = agent.verify_cves(
                ctx.result.to_dict(), [c.to_dict() for c in ctx.result.cves],
                provider, lab, budget=Budget(max_tokens=2_000_000), audit=ctx.audit,
                log=ctx.log, max_cves=20)
        except AIError as e:
            ctx.result.errors.append(f"ai-cve-verify failed: {e}")
            return

        by_id = {c.id: c for c in ctx.result.cves}
        target_url = ctx.result.url or ctx.result.target
        for v in verdicts:
            c = by_id.get(v.get("cve"))
            if c is not None:
                # B: every CVE carries its verification outcome + manual-repro package
                c.exploitability = {**(c.exploitability or {}),
                                    "verification": _verification_record(c, v, target_url)}
                if v.get("status") == "confirmed":
                    c.verified = True
            f = _cve_verify_finding(c, v, target_url)
            if f is not None:
                ctx.result.findings.append(f)
        counts = {s: sum(1 for v in verdicts if v.get("status") == s)
                  for s in ("confirmed", "reachable", "refuted", "inconclusive", "needs-manual")}
        ctx.log(f"ai-cve-verify: {counts['confirmed']} confirmed, {counts['reachable']} reachable, "
                f"{counts['refuted']} refuted, {counts['inconclusive']} inconclusive, "
                f"{counts['needs-manual']} need manual")
        ctx.result.recon["ai_cve_verify"] = {
            "candidates": len(todo), "verdicts": counts,
            "requests_sent": lab._count, "halted": lab.stopped_reason or None,
        }


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

        # Generous budget — we don't hold the analysis back (active-exploit safety
        # rails are enforced separately by the lab harness, not by token budget).
        budget = Budget(max_tokens=2_000_000)
        ctx.log(f"AI triage via {provider.name}/{provider.model} ...")
        try:
            findings, summary = analyze.triage_scan(
                ctx.result.to_dict(), provider,
                redact_secrets=cfg.ai_redact, budget=budget, audit=ctx.audit,
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

        # Security advisor — a grounded, plain-language, prioritized fix plan for
        # the site owner (built from the confirmed findings + the health grade).
        ctx.log("AI security advisor: drafting the owner's remediation plan ...")
        try:
            advisory = analyze.security_advisor(
                ctx.result.to_dict(), provider,
                redact_secrets=cfg.ai_redact, budget=budget, audit=ctx.audit,
            )
            if advisory:
                ctx.result.recon["advisor"] = advisory
        except AIError as e:
            ctx.result.errors.append(f"ai-advisor failed: {e}")


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
