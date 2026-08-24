"""
Deception & Honeypot Enhancement — Group 9.

Two halves:
  1. Provisioning — generates the fake accounts/files/directories that
     get placed onto Cowrie's simulated filesystem (honeyfs) so an
     attacker who gets a "successful" login has something plausible-
     looking to explore. Run once during System 2 setup.
  2. Detection — watches commands captured by Cowrie for any touch of a
     canary path, and raises a deception event when one fires. Canary
     files exist purely to be bait: nothing on the real system reads
     them, so any access is unambiguous evidence of exploration.
"""

import hashlib
import secrets
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Features 81-86: fake accounts, credentials, files, directories, configs, API keys
# ---------------------------------------------------------------------------

FAKE_DIRECTORY_STRUCTURE = [
    "/home/admin", "/home/backup", "/home/deploy",
    "/var/www/html", "/var/backups", "/opt/app/config",
    "/etc/app", "/root/.ssh",
]


def generate_fake_files() -> list[dict]:
    """Feature 83/85/86 — attractive-looking files that are harmless to
    serve up (no real data, no real credentials) but designed to look
    worth stealing. Returns (path, content) pairs to write into Cowrie's
    honeyfs during provisioning."""
    return [
        {
            "path": "/home/admin/.bash_history",
            "content": "ssh backup@10.0.0.5\nmysql -u root -p\ncat /etc/app/config/database.yml\n",
        },
        {
            "path": "/etc/app/config/database.yml",
            "content": _fake_config_yaml(),
        },
        {
            "path": "/root/.ssh/id_rsa",
            "content": _fake_ssh_key_placeholder(),
        },
        {
            "path": "/opt/app/config/api_keys.json",
            "content": _fake_api_keys_json(),
        },
        {
            "path": "/var/backups/customer_export.csv.bak",
            "content": "id,name,email\n# (canary file — access to this path triggers an alert)\n",
        },
    ]


def _fake_config_yaml() -> str:
    return (
        "production:\n"
        "  host: db-internal.local\n"
        "  username: app_service\n"
        f"  password: {secrets.token_urlsafe(12)}\n"
        "  database: app_production\n"
    )


def _fake_ssh_key_placeholder() -> str:
    # Deliberately NOT a real key format/structure an attacker could
    # attempt to use anywhere — just plausible-looking bait text.
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "(honeypot decoy — not a functional key)\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )


def _fake_api_keys_json() -> str:
    import json
    return json.dumps({
        "stripe_key": f"sk_test_decoy_{secrets.token_hex(8)}",
        "aws_access_key": f"AKIADECOY{secrets.token_hex(6).upper()}",
        "internal_service_token": secrets.token_urlsafe(24),
    }, indent=2)


def generate_fake_user_accounts(count: int = 5) -> list[dict]:
    """Feature 81/82 — returns username/password pairs suitable for
    Cowrie's userdb.txt (see system-2-honeypot/cowrie/userdb.txt for the
    checked-in defaults; this function is for generating additional/
    rotating ones programmatically)."""
    common_usernames = ["admin", "backup", "deploy", "support", "oracle", "postgres", "svc_monitor"]
    weak_passwords = ["admin123", "password", "changeme", "backup123", "welcome1"]
    accounts = []
    for i in range(min(count, len(common_usernames))):
        accounts.append({"username": common_usernames[i], "password": weak_passwords[i % len(weak_passwords)]})
    return accounts


# ---------------------------------------------------------------------------
# Feature 87: Canary Files + Feature 89/90: Interaction Recording & Alerts
# ---------------------------------------------------------------------------

CANARY_PATHS = {
    "/var/backups/customer_export.csv.bak",
    "/opt/app/config/api_keys.json",
    "/root/.ssh/id_rsa",
    "/etc/app/config/database.yml",
}

# Commands that mean "the attacker actually looked at the file", not just
# listed a directory that happens to contain it.
_ACCESS_COMMAND_PREFIXES = ("cat ", "less ", "more ", "vim ", "vi ", "nano ", "head ", "tail ", "cp ", "scp ")


def check_canary_access(command_text: str) -> dict | None:
    """Feature 90 (Deception Event Alerts) — call this for every command a
    session executes. Returns a deception-event dict if the command
    touches a canary path, else None. This is the honeypot-side detection
    signal that's independent of (and complements) threat_detector's
    keyword-based high-risk-command check."""
    if not command_text:
        return None
    lowered = command_text.strip().lower()
    if not lowered.startswith(_ACCESS_COMMAND_PREFIXES):
        return None

    for canary_path in CANARY_PATHS:
        if canary_path.lower() in lowered:
            return {
                "canary_path": canary_path,
                "command": command_text,
                "detected_at": datetime.now(timezone.utc),
                "severity": "critical",  # touching a canary is unambiguous — nothing legitimate does this
            }
    return None


def hash_canary_content(content: str) -> str:
    """Lets provisioning verify a canary file hasn't been tampered with
    between deploys (Feature 40-adjacent integrity tracking, applied to
    deception assets specifically)."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


