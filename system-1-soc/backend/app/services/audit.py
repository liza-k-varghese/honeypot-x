"""
Audit Logging — Group 14 (Feature 140).

Every route that changes state (acknowledging an alert, overriding an AI
classification, editing a Configuration row, creating/deleting a user)
calls record() so there's always an answer to "who did what, when" —
see app/models.AuditLog for the destination table.
"""

from datetime import datetime, timezone

# Actions worth auditing — used as a reference/checklist when wiring new
# routes, not enforced in code (any action string is accepted; this list
# just documents what's expected to call record()).
SENSITIVE_ACTIONS = [
    "user.create", "user.deactivate", "user.role_change",
    "alert.acknowledge", "alert.escalate",
    "session.classification_override",
    "configuration.update",
    "evidence.export",
    "report.generate",
]


def build_audit_entry(
    user_id: str | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> dict:
    """Pure builder — the route handler passes the result straight to a
    models.AuditLog(**entry) call with its own DB session, keeping this
    module free of any DB dependency."""
    return {
        "user_id": user_id,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "details": details or {},
        "ip_address": ip_address,
        "created_at": datetime.now(timezone.utc),
    }


