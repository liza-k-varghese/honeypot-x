"""
Response & Alerting — Group 10.

Notification channels degrade the same way threat_intel's external
lookups do: no SMTP/Telegram configured means send_*() returns False and
logs why, rather than raising — a misconfigured alert channel should
never crash the detection pipeline that's trying to use it.
"""

import logging
import operator
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText

try:
    import requests
except ImportError:
    requests = None

from app.core.config import settings

logger = logging.getLogger("alerting")


# ---------------------------------------------------------------------------
# Features 92-93: Email / Telegram alerts
# ---------------------------------------------------------------------------

def send_email_alert(subject: str, body: str, to_override: str | None = None) -> bool:
    recipient = to_override or settings.ALERT_EMAIL_TO
    if not settings.SMTP_HOST or not recipient:
        logger.info("Email alert skipped (SMTP not configured): %s", subject)
        return False

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = settings.ALERT_EMAIL_FROM
    msg["To"] = recipient

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            server.starttls()
            if settings.SMTP_USER:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.ALERT_EMAIL_FROM, [recipient], msg.as_string())
        return True
    except (smtplib.SMTPException, OSError) as exc:
        logger.error("Failed to send email alert: %s", exc)
        return False


def send_telegram_alert(message: str) -> bool:
    if requests is None or not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        logger.info("Telegram alert skipped (bot or requests library not configured)")
        return False

    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        resp = requests.post(
            url, json={"chat_id": settings.TELEGRAM_CHAT_ID, "text": message}, timeout=10,
        )
        resp.raise_for_status()
        return True
    except Exception as exc:
        logger.error("Failed to send Telegram alert: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Feature 95: Severity-Based Alerts — which channels a given severity uses
# ---------------------------------------------------------------------------

SEVERITY_CHANNEL_MAP = {
    "critical": ["dashboard", "email", "telegram"],
    "high": ["dashboard", "email"],
    "medium": ["dashboard"],
    "low": ["dashboard"],
    "info": ["dashboard"],
}


def determine_notification_channels(severity: str) -> list[str]:
    return SEVERITY_CHANNEL_MAP.get(severity, ["dashboard"])


# ---------------------------------------------------------------------------
# Feature 94: Custom Alert Rules — generic condition evaluator
# ---------------------------------------------------------------------------

_OPERATORS = {
    ">=": operator.ge, "<=": operator.le, ">": operator.gt, "<": operator.lt,
    "==": operator.eq, "!=": operator.ne,
    "contains": lambda field_value, threshold: threshold in (field_value or ""),
}


def evaluate_custom_rule(rule: dict, data: dict) -> bool:
    """rule: {"condition_field": str, "operator": str, "threshold": Any}
    data: the session/event dict to check the rule against.
    Unknown fields or operators fail closed (return False) rather than
    raising, so one bad admin-authored rule can't take down the whole
    alert pipeline."""
    field = rule.get("condition_field")
    op_name = rule.get("operator")
    threshold = rule.get("threshold")

    if field not in data or op_name not in _OPERATORS:
        return False

    try:
        return _OPERATORS[op_name](data[field], threshold)
    except TypeError:
        return False


def evaluate_all_rules(rules: list[dict], data: dict) -> list[dict]:
    """Returns the subset of rules that matched — each becomes one alert."""
    return [rule for rule in rules if evaluate_custom_rule(rule, data)]


# ---------------------------------------------------------------------------
# Features 96-97: Repeated-Attack / Critical Event alerts — these are just
# severity="critical" or a repeated-attack flag routed through the same
# channel logic above; no separate code path needed. See
# app.services.detection.classify_severity() for how severity is decided.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Feature 99: Alert Escalation
# ---------------------------------------------------------------------------

# How long an alert can sit unacknowledged before it escalates, per severity.
ESCALATION_THRESHOLDS = {
    "critical": timedelta(minutes=15),
    "high": timedelta(hours=1),
    "medium": timedelta(hours=4),
    "low": timedelta(hours=24),
    "info": None,  # info-level alerts never escalate
}


def should_escalate(created_at: datetime, severity: str, status: str, now: datetime | None = None) -> bool:
    if status != "open":
        return False  # already acknowledged/escalated/resolved
    threshold = ESCALATION_THRESHOLDS.get(severity)
    if threshold is None:
        return False
    now = now or datetime.now(timezone.utc)
    return (now - created_at) >= threshold


# ---------------------------------------------------------------------------
# Feature 100: Controlled Automated Response
# ---------------------------------------------------------------------------

def recommend_response_action(severity: str, had_successful_login: bool, high_risk_command_count: int) -> dict:
    """Decides what automated response (if any) a session's severity
    warrants. Deliberately returns a *recommendation*, not a direct
    firewall call — the actual IP-blocking implementation (pfSense REST
    API / SSH / iptables backends) already exists in the companion
    smart-firewall-honeypot project's automation/firewall_manager.py;
    wire this recommendation into that module's block_ip() rather than
    duplicating firewall logic here, so there's exactly one place that
    talks to the firewall.
    """
    if severity == "critical" or (had_successful_login and high_risk_command_count > 0):
        return {"action": "block_ip", "reason": "critical severity or confirmed compromise + malicious activity"}
    if severity == "high":
        return {"action": "flag_for_review", "reason": "high severity — recommend analyst review before blocking"}
    return {"action": "log_only", "reason": f"severity={severity} — logging only, no response action"}


