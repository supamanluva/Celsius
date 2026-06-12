"""Copy-paste remediation playbooks.

Findings say *what* is wrong; this maps each to *exactly how to fix it* — the
concrete config snippet, command, or DNS record an operator can paste. Matching is
on the finding category + title keywords; the first matching rule wins.

A playbook is {summary, steps[], snippet, lang}. `lang` hints syntax highlighting
(nginx / bash / dns / apache / text). Returns None when there's no curated fix
(the finding's own recommendation still stands).
"""

from __future__ import annotations

from typing import Optional

# ---- rules --------------------------------------------------------------------
# Each rule: a list of keyword sets — the rule fires when ANY set fully matches
# the lowercased "title + category" haystack. Keep summaries short and snippets
# paste-ready (placeholders in <ANGLE_BRACKETS>).

_RULES: list[dict] = [
    {
        "any": [["redis", "without authentication"]],
        "summary": "Require a Redis password and firewall the port.",
        "steps": [
            "Set a strong password in redis.conf and restart Redis.",
            "Bind Redis to localhost / a private interface, not 0.0.0.0.",
            "Block the port at the firewall so only trusted hosts reach it.",
        ],
        "snippet": "# /etc/redis/redis.conf\nrequirepass <LONG_RANDOM_SECRET>\nbind 127.0.0.1 ::1\nprotected-mode yes\n# then:  sudo systemctl restart redis",
        "lang": "bash",
    },
    {
        "any": [["docker engine api"]],
        "summary": "Stop exposing the Docker daemon; bind it to localhost (or require mTLS).",
        "steps": [
            "Remove the -H tcp://0.0.0.0:2375 daemon option.",
            "Use the local socket, or if remote access is required, enable TLS client-cert auth.",
            "Firewall 2375/2376 to trusted management hosts only.",
        ],
        "snippet": "# /etc/docker/daemon.json — do NOT expose tcp without TLS\n{\n  \"hosts\": [\"unix:///var/run/docker.sock\"]\n}\n# remote access instead: dockerd --tlsverify --tlscacert=ca.pem \\\n#   --tlscert=server-cert.pem --tlskey=server-key.pem -H=0.0.0.0:2376",
        "lang": "bash",
    },
    {
        "any": [["mongodb", "exposed"], ["mongodb", "without authentication"], ["mongodb reachable"]],
        "summary": "Enable MongoDB authorization and bind to a private network.",
        "steps": [
            "Create an admin user, then enable authorization.",
            "Bind mongod to localhost / a private IP.",
            "Firewall 27017 to trusted hosts.",
        ],
        "snippet": "# /etc/mongod.conf\nsecurity:\n  authorization: enabled\nnet:\n  bindIp: 127.0.0.1,<PRIVATE_IP>\n# then:  sudo systemctl restart mongod",
        "lang": "text",
    },
    {
        "any": [["elasticsearch", "without authentication"]],
        "summary": "Turn on Elasticsearch security and restrict the HTTP port.",
        "steps": [
            "Enable the security features and set built-in user passwords.",
            "Bind to a private interface; never expose 9200 to the internet.",
        ],
        "snippet": "# elasticsearch.yml\nxpack.security.enabled: true\nnetwork.host: 127.0.0.1\n# then set passwords:\nbin/elasticsearch-setup-passwords auto",
        "lang": "text",
    },
    {
        "any": [["memcached"]],
        "summary": "Bind Memcached to localhost and disable UDP (amplification).",
        "steps": [
            "Listen only on 127.0.0.1 and disable the UDP port.",
            "Firewall 11211 to trusted hosts.",
        ],
        "snippet": "# /etc/memcached.conf\n-l 127.0.0.1\n-U 0          # disable UDP (reflection/amplification)\n# then:  sudo systemctl restart memcached",
        "lang": "bash",
    },
    {
        "any": [["couchdb"]],
        "summary": "Set a CouchDB admin and require authentication.",
        "steps": [
            "Create a server admin (ends 'admin party' open access).",
            "Bind to a private interface and firewall 5984.",
        ],
        "snippet": "# local.ini\n[admins]\nadmin = <STRONG_PASSWORD>\n[chttpd]\nbind_address = 127.0.0.1",
        "lang": "text",
    },
    {
        "any": [["anonymous ftp"]],
        "summary": "Disable anonymous FTP (or move to SFTP).",
        "steps": [
            "Turn off anonymous access in the FTP server config.",
            "Prefer SFTP (over SSH) so credentials and data are encrypted.",
        ],
        "snippet": "# vsftpd.conf\nanonymous_enable=NO\nlocal_enable=YES\n# then:  sudo systemctl restart vsftpd",
        "lang": "bash",
    },
    {
        "any": [["default credentials"]],
        "summary": "Change the default credentials now and restrict the panel.",
        "steps": [
            "Log in and set a unique, strong password (rotate any shared admin account).",
            "Restrict the management interface to a VPN / trusted IPs.",
            "Enable MFA if the device/app supports it.",
        ],
        "snippet": "",
        "lang": "text",
    },
    {
        "any": [["weak tls protocol"], ["tls", "deprecated"], ["sslv3"], ["tlsv1.0"], ["tlsv1.1"]],
        "summary": "Disable legacy TLS; serve only TLS 1.2+.",
        "steps": [
            "Drop SSLv3 / TLS 1.0 / 1.1 and keep a modern cipher suite.",
            "Reload the web server.",
        ],
        "snippet": "# nginx\nssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\nssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384';\n# then:  sudo nginx -t && sudo systemctl reload nginx",
        "lang": "nginx",
    },
    {
        "any": [["strict-transport"], ["hsts"]],
        "summary": "Add an HSTS header so browsers force HTTPS.",
        "steps": ["Send Strict-Transport-Security on HTTPS responses (start with a short max-age, then raise)."],
        "snippet": "# nginx (inside the HTTPS server block)\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
        "lang": "nginx",
    },
    {
        "any": [["x-frame-options"], ["clickjack"]],
        "summary": "Prevent framing (clickjacking) with a frame-ancestors policy.",
        "steps": ["Prefer CSP frame-ancestors; X-Frame-Options for older browsers."],
        "snippet": "# nginx\nadd_header Content-Security-Policy \"frame-ancestors 'self'\" always;\nadd_header X-Frame-Options \"SAMEORIGIN\" always;",
        "lang": "nginx",
    },
    {
        "any": [["x-content-type-options"], ["nosniff"], ["mime"]],
        "summary": "Stop MIME-sniffing with X-Content-Type-Options.",
        "steps": ["Send the nosniff header on all responses."],
        "snippet": "# nginx\nadd_header X-Content-Type-Options \"nosniff\" always;",
        "lang": "nginx",
    },
    {
        "any": [["content security policy"], ["missing csp"], ["no csp"]],
        "summary": "Add a Content-Security-Policy (start strict, then relax as needed).",
        "steps": [
            "Begin with a restrictive default and allow only what the app needs.",
            "Test in Report-Only mode first to catch breakage.",
        ],
        "snippet": "# nginx — a safe starting point; widen per real needs\nadd_header Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'\" always;",
        "lang": "nginx",
    },
    {
        "any": [["cors"]],
        "summary": "Restrict CORS to known origins; never reflect arbitrary Origins.",
        "steps": [
            "Allow only an explicit allowlist of origins.",
            "Don't combine Access-Control-Allow-Credentials: true with a wildcard or reflected origin.",
        ],
        "snippet": "# Express example\nconst allowed = new Set(['https://app.example.com']);\napp.use((req, res, next) => {\n  const o = req.headers.origin;\n  if (allowed.has(o)) res.set('Access-Control-Allow-Origin', o);\n  next();\n});",
        "lang": "text",
    },
    {
        "any": [["spf"]],
        "summary": "Publish a strict SPF record.",
        "steps": ["Add a TXT record listing your senders and ending in -all (hard fail)."],
        "snippet": "; DNS TXT on the apex\n@   IN   TXT   \"v=spf1 include:<your-mail-provider> -all\"",
        "lang": "dns",
    },
    {
        "any": [["dmarc"]],
        "summary": "Publish a DMARC policy (start at none, move to reject).",
        "steps": ["Add _dmarc TXT; begin with p=none + rua to collect reports, then tighten to p=reject."],
        "snippet": "; DNS TXT\n_dmarc   IN   TXT   \"v=DMARC1; p=reject; rua=mailto:dmarc@<your-domain>; fo=1\"",
        "lang": "dns",
    },
    {
        "any": [["subdomain takeover"], ["dangling"]],
        "summary": "Remove the dangling DNS record pointing at an unclaimed resource.",
        "steps": [
            "Delete the CNAME/A record, or re-claim the resource at the provider.",
            "Audit DNS for other records pointing to deprovisioned services.",
        ],
        "snippet": "",
        "lang": "text",
    },
    {
        "any": [[".git"], [".env"], ["source code repo"], ["exposed git"]],
        "summary": "Block access to the sensitive path and ROTATE any exposed secrets.",
        "steps": [
            "Deny the path at the web server (or remove it from the web root).",
            "Assume any credentials in the exposed files are compromised — rotate them.",
        ],
        "snippet": "# nginx\nlocation ~ /\\.(git|env|svn|hg) { deny all; return 404; }",
        "lang": "nginx",
    },
    {
        "any": [["alg=none"], ["jwt", "none"], ["algorithm confusion"]],
        "summary": "Reject unsigned/None-alg JWTs and pin the expected algorithm.",
        "steps": [
            "Never accept alg=none; verify with a fixed allowlist of algorithms.",
            "Don't let the token header choose the verification algorithm.",
        ],
        "snippet": "# pyjwt\njwt.decode(token, key, algorithms=[\"RS256\"])  # explicit; never trust header alg",
        "lang": "text",
    },
    {
        "any": [["directory listing"], ["autoindex"]],
        "summary": "Disable directory listing.",
        "steps": ["Turn off autoindex so directory contents aren't enumerable."],
        "snippet": "# nginx\nautoindex off;",
        "lang": "nginx",
    },
]


def _haystack(finding: dict) -> str:
    return f"{finding.get('title', '')} {finding.get('category', '')}".lower()


def playbook_for(finding: dict) -> Optional[dict]:
    """Return a {summary, steps, snippet, lang} playbook for a finding, or None."""
    hay = _haystack(finding)
    for rule in _RULES:
        for needset in rule["any"]:
            if all(n in hay for n in needset):
                return {"summary": rule["summary"], "steps": list(rule["steps"]),
                        "snippet": rule["snippet"], "lang": rule["lang"]}
    return None
