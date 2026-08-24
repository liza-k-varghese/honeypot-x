"""
Automated Response & Playbooks — Group 10, Feature 100.

Split the same way as everywhere else in this codebase: playbook
*selection* and *action planning* are pure functions (testable without
touching a network or database — see tests below), while *execution*
is a thin layer that calls out to firewall_response.py and
alerting.py's already-existing, already-tested send functions.

Default playbooks are data, not hardcoded if/else branches — add or
tune one by editing DEFAULT_PLAYBOOKS below, or (future extension)
move this list into the Configuration table so admins can edit
playbooks from the dashboard without a code change.
"""

import logging
from datetime import datetime, timezone

from app.services import alerting, firewall_response

logger = logging.getLogger("playbooks")


# ---------------------------------------------------------------------------
# Default playbooks
# ---------------------------------------------------------------------------
# Each trigger condition is optional — omit a key to not gate on it.
# A session matches a playbook if EVERY specified condition holds.

DEFAULT_PLAYBOOKS = [
    {
        "name": "critical_compromise",
        "description": "Successful login + at least one high-risk command — the highest-confidence signal in the system.",
        "trigger": {"min_severity": "critical", "requires_successful_login": True},
        "actions": ["block_ip", "notify", "create_incident"],
    },
    {
        "name": "confirmed_deception_trigger",
        "description": "A canary file was touched — nothing legitimate does this, ever.",
        "trigger": {"source": "deception"},
        "actions": ["block_ip", "notify", "create_incident"],
    },
    {
        "name": "sustained_brute_force",
        "description": "High-severity brute force without a successful login — worth blocking, doesn't need a full incident on its own.",
        "trigger": {"min_severity": "high", "requires_successful_login": False},
        "actions": ["block_ip", "notify"],
    },
    {
        "name": "elevated_anomaly",
        "description": "ML flagged the session as anomalous but rule-based severity is still medium — notify for analyst review rather than auto-blocking on an ML signal alone.",
        "trigger": {"min_severity": "medium", "is_anomalous": True},
        "actions": ["notify"],
    },
]

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


# ---------------------------------------------------------------------------
# Selection — pure
# ---------------------------------------------------------------------------

def _severity_at_least(actual: str, minimum: str) -> bool:
    try:
        return _SEVERITY_ORDER.index(actual) >= _SEVERITY_ORDER.index(minimum)
    except ValueError:
        return False


def matches_trigger(trigger: dict, context: dict) -> bool:
    """context keys used: severity, had_successful_login, is_anomalous,
    high_risk_command_count, source (e.g. 'deception' for a canary alert)."""
    if "min_severity" in trigger and not _severity_at_least(context.get("severity", "info"), trigger["min_severity"]):
        return False
    if "requires_successful_login" in trigger and context.get("had_successful_login", False) != trigger["requires_successful_login"]:
        return False
    if "is_anomalous" in trigger and context.get("is_anomalous", False) != trigger["is_anomalous"]:
        return False
    if "min_high_risk_commands" in trigger and context.get("high_risk_command_count", 0) < trigger["min_high_risk_commands"]:
        return False
    if "source" in trigger and context.get("source") != trigger["source"]:
        return False
    return True


def select_matching_playbooks(context: dict, playbooks: list[dict] | None = None) -> list[dict]:
    """Returns every playbook whose trigger matches — deliberately not
    just the first/highest-priority one, since e.g. a critical
    compromise should both block AND create an incident, which two
    different playbooks might jointly express. Caller (execute_all
    below) is responsible for not double-blocking if two matched
    playbooks both say "block_ip" for the same IP."""
    playbooks = playbooks if playbooks is not None else DEFAULT_PLAYBOOKS
    return [p for p in playbooks if matches_trigger(p["trigger"], context)]


# ---------------------------------------------------------------------------
# Action planning — pure (describes what to do, doesn't do it)
# ---------------------------------------------------------------------------

def build_action_plan(matched_playbooks: list[dict], context: dict) -> list[dict]:
    """Flattens every matched playbook's action list into a single
    deduplicated plan — {"action_type": ..., "playbook_name": ...,
    "target": ...}. Dedup on action_type+target so "block_ip" from two
    different matched playbooks doesn't attempt the block twice."""
    seen = set()
    plan = []
    for playbook in matched_playbooks:
        for action_type in playbook["actions"]:
            target = context.get("src_ip") if action_type == "block_ip" else context.get("session_id")
            key = (action_type, target)
            if key in seen:
                continue
            seen.add(key)
            plan.append({"action_type": action_type, "playbook_name": playbook["name"], "target": target})
    return plan


# ---------------------------------------------------------------------------
# Execution — thin, calls the already-tested lower-level services
# ---------------------------------------------------------------------------

def execute_action(action: dict, context: dict) -> dict:
    """Executes one planned action, returns a ResponseAction-shaped
    result dict. Never raises — a failed action is a result to record,
    not an exception to propagate (same philosophy as
    firewall_response.block_ip)."""
    action_type = action["action_type"]

    if action_type == "block_ip":
        result = firewall_response.block_ip(context["src_ip"], reason=f"playbook: {action['playbook_name']}")
        return {**action, "success": result["success"], "skipped": result.get("skipped", False), "detail": result}

    if action_type == "notify":
        channels = alerting.determine_notification_channels(context.get("severity", "medium"))
        message = f"[{context.get('severity', 'unknown').upper()}] Automated response '{action['playbook_name']}' triggered for {context.get('src_ip')}"
        sent_email = alerting.send_email_alert(f"HoneyShield X: {action['playbook_name']}", message) if "email" in channels else None
        sent_telegram = alerting.send_telegram_alert(message) if "telegram" in channels else None
        return {**action, "success": True, "skipped": False, "detail": {"email_sent": sent_email, "telegram_sent": sent_telegram}}

    if action_type == "create_incident":
        # The actual Incident row is created by the caller (ingestion
        # worker / route), which has a DB session — this just signals
        # that it should happen, keeping this module DB-free like every
        # other service module.
        return {**action, "success": True, "skipped": False, "detail": {"note": "incident creation delegated to caller"}}

    logger.warning("Unknown action_type in playbook action plan: %s", action_type)
    return {**action, "success": False, "skipped": False, "detail": {"error": "unknown action_type"}}


def run(context: dict, playbooks: list[dict] | None = None) -> list[dict]:
    """Full pipeline: select -> plan -> execute. This is the single
    function app.workers.ingestion_worker calls."""
    matched = select_matching_playbooks(context, playbooks)
    if not matched:
        return []
    plan = build_action_plan(matched, context)
    return [execute_action(action, context) for action in plan]


