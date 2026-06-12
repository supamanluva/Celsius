"""Notification channels for monitoring alerts — SMTP email and webhook.

Stdlib-only (smtplib / email / urllib). SMTP is configured via environment:

    SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASS,
    SMTP_FROM (defaults to SMTP_USER)

Port 465 uses implicit TLS; any other port uses STARTTLS.
"""

from __future__ import annotations

import json
import os
import smtplib
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage
from typing import Optional


def smtp_configured() -> bool:
    return all(os.environ.get(k) for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASS"))


def send_email(to: str, subject: str, body: str, *,
               html: Optional[str] = None) -> tuple[bool, str]:
    """Send a plain-text (optionally multipart with HTML) email via env SMTP.
    Returns (ok, detail)."""
    host = os.environ.get("SMTP_HOST")
    if not host:
        return False, "SMTP_HOST not set"
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    pw = os.environ.get("SMTP_PASS", "")
    sender = os.environ.get("SMTP_FROM") or user

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")

    ctx = ssl.create_default_context()
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=30, context=ctx) as s:
                if user:
                    s.login(user, pw)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=30) as s:
                s.starttls(context=ctx)
                if user:
                    s.login(user, pw)
                s.send_message(msg)
        return True, "sent"
    except (smtplib.SMTPException, OSError) as e:
        return False, str(e)


def send_webhook(url: str, payload: dict) -> tuple[bool, str]:
    """POST a JSON payload to a webhook URL. Returns (ok, detail)."""
    data = json.dumps(payload, default=str).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "celsius-monitor"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return (200 <= resp.status < 300), f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except (urllib.error.URLError, OSError) as e:
        return False, str(e)
