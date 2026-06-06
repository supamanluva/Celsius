"""Secret detection: regex signatures for common credential formats plus a
Shannon-entropy fallback for high-entropy strings (generic keys/tokens).

Used both for code scanning (codescan.py) and web-page scanning (websecrets.py).
Returns lightweight dicts so callers can wrap them into Findings with location
context appropriate to their source (file:line vs URL).
"""

from __future__ import annotations

import math
import re

# Each rule: (id, human title, compiled regex, severity hint).
# Patterns favour precision; the entropy pass catches the long tail.
_RULES: list[tuple[str, str, re.Pattern, str]] = [
    ("aws-access-key-id", "AWS Access Key ID",
     re.compile(r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"), "CRITICAL"),
    ("aws-secret-key", "AWS Secret Access Key",
     re.compile(r"(?i)aws.{0,20}?(secret|sk).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]"), "CRITICAL"),
    ("github-pat", "GitHub Personal Access Token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "CRITICAL"),
    ("github-fine-grained", "GitHub fine-grained PAT",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), "CRITICAL"),
    ("gitlab-pat", "GitLab Personal Access Token",
     re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"), "CRITICAL"),
    ("slack-token", "Slack token",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "HIGH"),
    ("slack-webhook", "Slack webhook URL",
     re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"), "HIGH"),
    ("google-api-key", "Google API key",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "HIGH"),
    ("google-oauth", "Google OAuth client secret",
     re.compile(r"\bGOCSPX-[A-Za-z0-9\-_]{20,}\b"), "HIGH"),
    ("stripe-secret", "Stripe secret key",
     re.compile(r"\b[rs]k_(live|test)_[A-Za-z0-9]{20,}\b"), "CRITICAL"),
    ("sendgrid", "SendGrid API key",
     re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "HIGH"),
    ("twilio", "Twilio API key",
     re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "HIGH"),
    ("openai", "OpenAI API key",
     re.compile(r"\bsk-(proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b"), "CRITICAL"),
    ("anthropic", "Anthropic API key",
     re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"), "CRITICAL"),
    # Require real key material after the header — the bare "-----BEGIN PRIVATE
    # KEY-----" string ships inside many minified bundles (cert-handling code,
    # regexes, labels) and is NOT a leaked key. Demand >=40 base64 chars of body,
    # tolerating escaped (\n) or literal newlines between header and body.
    ("private-key", "Private key block",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
                r"(?:\s|\\[rnt])*[A-Za-z0-9+/]{40,}"), "CRITICAL"),
    ("jwt", "JSON Web Token",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "MEDIUM"),
    ("npm-token", "npm access token",
     re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "HIGH"),
    ("heroku", "Heroku API key (UUID near 'heroku')",
     re.compile(r"(?i)heroku.{0,20}?\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), "HIGH"),
    ("generic-assignment", "Hardcoded credential assignment",
     re.compile(r"""(?i)\b(api[_-]?key|secret|passwd|password|token|access[_-]?key)\b\s*[:=]\s*['"]([^'"\s]{8,})['"]"""), "MEDIUM"),
    ("basic-auth-url", "Credentials in URL",
     re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@[^\s/]+"), "HIGH"),
]

# Strings that look like secrets but are placeholders — suppress these.
_PLACEHOLDER = re.compile(
    r"(?i)(example|placeholder|your[_-]?|xxx+|<.+?>|change[_-]?me|dummy|sample|test[_-]?key|"
    r"redacted|\bnull\b|\bnone\b|00000000|123456|aaaa+|"
    # connection-string credential placeholders (e.g. "mysql://username:password@host")
    # — only the user/pass words, NOT host/port/db (those match real hostnames like db.internal)
    r"\buser(name)?\b|\bpass(word|wd)?\b)"
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_HIGH_ENTROPY_TOKEN = re.compile(r"['\"]([A-Za-z0-9+/_\-]{24,})['\"]")

# A high-entropy *token* that is really a URL/asset path, not a credential.
# Real keys don't start with "/" and don't carry file extensions; URL slugs,
# webpack public paths and asset URLs do.
_PATHISH_TOKEN = re.compile(
    r"^(?:/|https?://)"
    r"|\.(?:js|mjs|css|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|"
    r"json|html?|php|aspx?|xml|txt|pdf)(?:[?#]|$)",
    re.I,
)

# The text immediately *before* a quoted token, when it's an HTML/CSS attribute
# or CSS url(): values here (hrefs, SRI hashes, asset URLs) are never secrets.
_BENIGN_BEFORE = re.compile(
    r"""(?:href|src|srcset|action|integrity|xlink:href|data-[\w-]+|cite|poster|"""
    r"""type|nonce|class|rel|as)"""
    r"""\s*=\s*["']?\s*$"""
    r"""|url\(\s*["']?\s*$""",
    re.I,
)

# A public verification token (e.g. <meta name="…-verification" content="TOKEN">):
# these are public by design and must not be reported as exposed secrets.
_VERIFICATION_BEFORE = re.compile(
    r"""verification["'][^"'<>]*content\s*=\s*["']?\s*$""",
    re.I,
)

# JSON keys whose values are PUBLIC by design (a Web Push VAPID *public* key, an
# OAuth/crypto public key) or build artifacts (Next.js buildId, CSP nonce, webpack
# content hashes) — high-entropy but never credentials.
_BENIGN_KEY_BEFORE = re.compile(
    r"""(?:^|[.,{;\[\s"'])"""                              # key boundary (also unquoted JS keys)
    r"""(?:vapidpublic(?:key)?|publicvapidkey|public_?key|vapidkey|"""
    r"""buildid|buildhash|nonce|chunk(?:id|hash)|contenthash|revision|csrf(?:token)?)"""
    r"""["']?\s*[:=]\s*["']?\s*$""",                       # : or = , key/value quotes optional
    re.I,
)


def _is_pathish_token(tok: str) -> bool:
    return bool(_PATHISH_TOKEN.search(tok))


def _benign_token_context(before: str) -> bool:
    """True if the ~90 chars preceding the token mark it as a URL/asset/verification
    value rather than a credential."""
    tail = before[-90:]
    return bool(_BENIGN_BEFORE.search(tail) or _VERIFICATION_BEFORE.search(tail)
                or _BENIGN_KEY_BEFORE.search(tail))


class SecretMatch:
    __slots__ = ("rule_id", "title", "severity", "match", "redacted", "entropy")

    def __init__(self, rule_id, title, severity, match, entropy=0.0):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.match = match
        self.redacted = redact(match)
        self.entropy = entropy


def redact(s: str) -> str:
    s = s.strip()
    if len(s) <= 12:
        return s[:2] + "…"
    return f"{s[:4]}…{s[-4:]} ({len(s)} chars)"


# UI labels / i18n strings / form-field words that the generic-assignment rule
# (`password:"..."`) matches but which are NOT secrets. Lower-cased.
_LABEL_WORDS = {
    "password", "lösenord", "losenord", "passwort", "contraseña", "mot de passe",
    "username", "user name", "användarnamn", "email", "e-mail", "e-post",
    "secret", "token", "apikey", "api key", "api-key", "accesskey", "access key",
    "current-password", "new-password", "confirm password", "passwordconfirm",
    "enter password", "your password", "old password",
}


def _looks_like_secret(value: str) -> bool:
    """Heuristic gate for the broad generic-assignment rule: reject obvious labels
    and short pure-alphabetic dictionary words; keep entropy-bearing values."""
    v = value.strip()
    if v.lower() in _LABEL_WORDS:
        return False
    # a short, purely alphabetic value is almost always a label/word, not a secret
    if v.replace(" ", "").isalpha() and len(v) <= 12:
        return False
    return True


def scan_text(text: str, *, entropy_threshold: float = 4.3) -> list[SecretMatch]:
    """Find secrets in a blob of text. Deduplicates by (rule_id, match)."""
    found: dict[tuple[str, str], SecretMatch] = {}

    for rule_id, title, pat, sev in _RULES:
        for m in pat.finditer(text):
            raw = m.group(0)
            # For assignment-style rules, the secret value is in the last group.
            value = m.groups()[-1] if m.groups() else raw
            if _PLACEHOLDER.search(value or ""):
                continue
            # The broad credential-assignment rule needs a value sanity check to
            # avoid matching UI labels like password:"Password".
            if rule_id == "generic-assignment" and not _looks_like_secret(value):
                continue
            key = (rule_id, raw)
            if key not in found:
                found[key] = SecretMatch(rule_id, title, sev, raw)

    # Entropy pass for quoted long tokens not already caught.
    already = {sm.match for sm in found.values()}
    for m in _HIGH_ENTROPY_TOKEN.finditer(text):
        tok = m.group(1)
        if tok in already or _PLACEHOLDER.search(tok):
            continue
        # Suppress URL/asset paths and HTML-attribute/verification values: these
        # are high-entropy but never credentials (common false positives).
        if _is_pathish_token(tok) or _benign_token_context(text[:m.start()]):
            continue
        ent = shannon_entropy(tok)
        if ent >= entropy_threshold and _looks_random(tok):
            key = ("high-entropy", tok)
            if key not in found:
                found[key] = SecretMatch(
                    "high-entropy", "High-entropy string (possible secret)",
                    "LOW", tok, entropy=ent,
                )
    return list(found.values())


def _looks_random(tok: str) -> bool:
    # require a mix of character classes to cut down on hashes of words etc.
    has_upper = any(c.isupper() for c in tok)
    has_lower = any(c.islower() for c in tok)
    has_digit = any(c.isdigit() for c in tok)
    return (has_upper + has_lower + has_digit) >= 2
