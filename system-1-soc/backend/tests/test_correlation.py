"""
Unit tests for attack correlation and campaign clustering.
"""

from datetime import datetime, timedelta, timezone
from app.services import correlation


def test_identify_campaigns():
    base_time = datetime(2026, 8, 24, 10, 0, 0, tzinfo=timezone.utc)
    sessions = [
        {"session_id": "s1", "src_ip": "198.51.100.10", "started_at": base_time, "target_service": "SSH"},
        {"session_id": "s2", "src_ip": "198.51.100.20", "started_at": base_time + timedelta(minutes=5), "target_service": "SSH"},
        {"session_id": "s3", "src_ip": "198.51.100.30", "started_at": base_time + timedelta(minutes=15), "target_service": "SSH"},
        # Distinct service
        {"session_id": "s4", "src_ip": "198.51.100.40", "started_at": base_time + timedelta(minutes=2), "target_service": "HTTP"},
    ]

    campaigns = correlation.identify_campaigns(sessions, time_window_minutes=30, min_sessions=3, min_distinct_ips=2)
    assert len(campaigns) == 1
    c = campaigns[0]
    assert c["target_service"] == "SSH"
    assert c["session_count"] == 3
    assert c["source_ip_count"] == 3
    assert len(c["session_ids"]) == 3


def test_build_cypher_queries():
    q, p = correlation.build_link_ip_attacked_honeypot_query("198.51.100.1", "cowrie")
    assert "MERGE (i:IP {address: $ip})" in q
    assert p["ip"] == "198.51.100.1"
    assert p["honeypot"] == "cowrie"

    q2, p2 = correlation.build_link_session_executed_command_query("sess-1", "whoami")
    assert "MERGE (c:Command {text: $command})" in q2
    assert p2["command"] == "whoami"
