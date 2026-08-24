"""
Unit tests for automated response playbooks.
"""

from app.services import playbooks


def test_playbook_matching_critical_compromise():
    context = {
        "src_ip": "198.51.100.45",
        "severity": "critical",
        "had_successful_login": True,
        "high_risk_command_count": 1,
        "is_anomalous": True,
    }
    matched = playbooks.select_matching_playbooks(context)
    names = [p["name"] for p in matched]
    assert "critical_compromise" in names


def test_playbook_matching_deception_canary():
    context = {
        "src_ip": "198.51.100.45",
        "severity": "critical",
        "source": "deception",
    }
    matched = playbooks.select_matching_playbooks(context)
    names = [p["name"] for p in matched]
    assert "confirmed_deception_trigger" in names


def test_action_plan_deduplication():
    matched = [
        {"name": "p1", "actions": ["block_ip", "notify"]},
        {"name": "p2", "actions": ["block_ip", "create_incident"]},
    ]
    context = {"src_ip": "198.51.100.55", "session_id": "sess-123"}
    plan = playbooks.build_action_plan(matched, context)
    action_types = [a["action_type"] for a in plan]
    # block_ip should only appear once
    assert action_types.count("block_ip") == 1
    assert "notify" in action_types
    assert "create_incident" in action_types
