"""
Unit tests for deception lures and canary access detection.
"""

from app.services import deception


def test_canary_access_trigger():
    cmd = "cat /opt/app/config/api_keys.json"
    hit = deception.check_canary_access(cmd)
    assert hit is not None
    assert hit["canary_path"] == "/opt/app/config/api_keys.json"
    assert hit["severity"] == "critical"


def test_canary_access_ignores_ls():
    # Listing directory is not reading the canary file
    cmd = "ls -la /opt/app/config/"
    hit = deception.check_canary_access(cmd)
    assert hit is None


def test_canary_access_customer_csv():
    cmd = "head -n 20 /var/backups/customer_export.csv.bak"
    hit = deception.check_canary_access(cmd)
    assert hit is not None
    assert hit["canary_path"] == "/var/backups/customer_export.csv.bak"


def test_generate_fake_user_accounts():
    accounts = deception.generate_fake_user_accounts(count=3)
    assert len(accounts) == 3
    for acc in accounts:
        assert "username" in acc
        assert "password" in acc
