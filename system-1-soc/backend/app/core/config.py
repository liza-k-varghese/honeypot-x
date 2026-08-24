"""
Central configuration for the HoneyShield X SOC backend (System 1).

All values are overridable via environment variables (or a .env file —
see .env.example) so the same code runs in dev, testing, and the real
deployment without edits.
"""

import os
from functools import lru_cache


class Settings:
    # --- App ---
    APP_NAME: str = "HoneyShield X SOC Backend"
    ENVIRONMENT: str = os.environ.get("ENVIRONMENT", "development")
    DEBUG: bool = os.environ.get("DEBUG", "true").lower() == "true"

    # --- PostgreSQL ---
    POSTGRES_HOST: str = os.environ.get("POSTGRES_HOST", "localhost")
    POSTGRES_PORT: int = int(os.environ.get("POSTGRES_PORT", 5432))
    POSTGRES_DB: str = os.environ.get("POSTGRES_DB", "honeyshield")
    POSTGRES_USER: str = os.environ.get("POSTGRES_USER", "honeyshield")
    POSTGRES_PASSWORD: str = os.environ.get("POSTGRES_PASSWORD", "changeme")

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # --- Redis ---
    REDIS_HOST: str = os.environ.get("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.environ.get("REDIS_PORT", 6379))
    REDIS_DB: int = int(os.environ.get("REDIS_DB", 0))

    # --- Neo4j ---
    NEO4J_URI: str = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.environ.get("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.environ.get("NEO4J_PASSWORD", "changeme")

    # --- OpenSearch ---
    OPENSEARCH_HOST: str = os.environ.get("OPENSEARCH_HOST", "localhost")
    OPENSEARCH_PORT: int = int(os.environ.get("OPENSEARCH_PORT", 9200))
    OPENSEARCH_USER: str = os.environ.get("OPENSEARCH_USER", "admin")
    OPENSEARCH_PASSWORD: str = os.environ.get("OPENSEARCH_PASSWORD", "changeme")
    OPENSEARCH_USE_SSL: bool = os.environ.get("OPENSEARCH_USE_SSL", "true").lower() == "true"
    OPENSEARCH_VERIFY_CERTS: bool = os.environ.get("OPENSEARCH_VERIFY_CERTS", "false").lower() == "true"
    OPENSEARCH_INDICES = [
        "cowrie-logs", "opencanary-logs", "dionaea-logs",
        "zeek-logs", "suricata-alerts",
    ]

    # --- Auth (Group 14) ---
    JWT_SECRET_KEY: str = os.environ.get("JWT_SECRET_KEY", "CHANGE-THIS-IN-PRODUCTION")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", 60))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", 7))

    # Shared secret for ESP32 + System 2 health-check callers (not full user auth)
    DEVICE_API_KEY: str = os.environ.get("HONEYSHIELD_API_KEY", "CHANGE-THIS-DEVICE-KEY")

    # --- Detection thresholds (Group 6) ---
    LOGIN_ATTEMPT_THRESHOLD: int = int(os.environ.get("LOGIN_ATTEMPT_THRESHOLD", 5))
    LOGIN_ATTEMPT_WINDOW_SECONDS: int = int(os.environ.get("LOGIN_ATTEMPT_WINDOW_SECONDS", 60))
    PORT_SCAN_THRESHOLD: int = int(os.environ.get("PORT_SCAN_THRESHOLD", 10))
    PORT_SCAN_WINDOW_SECONDS: int = int(os.environ.get("PORT_SCAN_WINDOW_SECONDS", 30))
    HIGH_RISK_COMMAND_KEYWORDS = [
        "wget", "curl", "chmod +x", "nc -e", "netcat", "base64 -d",
        "rm -rf", "/etc/passwd", "scp ", "python -c", "perl -e", "masscan", "nmap",
    ]

    # --- Dashboard login rate limiting (Group 14 security hardening) ---
    # This protects the SOC platform's OWN login endpoint from brute
    # force — a different concern from LOGIN_ATTEMPT_THRESHOLD above,
    # which detects brute force against the *honeypot's* fake SSH.
    LOGIN_RATE_LIMIT_MAX_ATTEMPTS: int = int(os.environ.get("LOGIN_RATE_LIMIT_MAX_ATTEMPTS", 10))
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = int(os.environ.get("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 300))

    # --- AI (Group 7) ---
    ANOMALY_MODEL_PATH: str = os.environ.get(
        "ANOMALY_MODEL_PATH", os.path.join(os.path.dirname(__file__), "..", "..", "data", "anomaly_model.joblib")
    )
    CLASSIFIER_MODEL_PATH: str = os.environ.get(
        "CLASSIFIER_MODEL_PATH", os.path.join(os.path.dirname(__file__), "..", "..", "data", "classifier_model.joblib")
    )
    ANOMALY_SCORE_THRESHOLD: float = float(os.environ.get("ANOMALY_SCORE_THRESHOLD", 0.05))

    # --- Threat intel (Group 5) ---
    GEOIP_DB_PATH: str = os.environ.get("GEOIP_DB_PATH", "/opt/honeyshield/data/GeoLite2-City.mmdb")
    ABUSEIPDB_API_KEY: str = os.environ.get("ABUSEIPDB_API_KEY", "")
    TOR_EXIT_LIST_PATH: str = os.environ.get("TOR_EXIT_LIST_PATH", "/opt/honeyshield/data/tor_exit_nodes.txt")

    # --- Alerting (Group 10) ---
    SMTP_HOST: str = os.environ.get("SMTP_HOST", "")
    SMTP_PORT: int = int(os.environ.get("SMTP_PORT", 587))
    SMTP_USER: str = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD: str = os.environ.get("SMTP_PASSWORD", "")
    ALERT_EMAIL_FROM: str = os.environ.get("ALERT_EMAIL_FROM", "honeyshield@example.com")
    ALERT_EMAIL_TO: str = os.environ.get("ALERT_EMAIL_TO", "")
    TELEGRAM_BOT_TOKEN: str = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID: str = os.environ.get("TELEGRAM_CHAT_ID", "")

    # --- Automated Response / Playbooks (Group 10, Feature 100) ---
    # Same backend design as the companion smart-firewall-honeypot
    # project's firewall_manager.py — pfSense REST API, pfSense over SSH,
    # local iptables, or a mock that just logs. AUTOMATED_RESPONSE_ENABLED
    # is a separate master switch from the backend choice: leave it False
    # to run everything in "would have blocked X" logging-only mode
    # (recommended until you've validated detection accuracy against real
    # traffic — see backend/TESTING.md) even with a real backend configured.
    AUTOMATED_RESPONSE_ENABLED: bool = os.environ.get("AUTOMATED_RESPONSE_ENABLED", "false").lower() == "true"
    FIREWALL_BACKEND: str = os.environ.get("FIREWALL_BACKEND", "mock")  # "pfsense" | "pfsense_ssh" | "iptables" | "mock"

    PFSENSE_HOST: str = os.environ.get("PFSENSE_HOST", "https://192.168.1.1")
    PFSENSE_API_KEY: str = os.environ.get("PFSENSE_API_KEY", "")
    PFSENSE_BLOCKLIST_ALIAS: str = os.environ.get("PFSENSE_BLOCKLIST_ALIAS", "honeyshield_blacklist")
    PFSENSE_VERIFY_TLS: bool = os.environ.get("PFSENSE_VERIFY_TLS", "false").lower() == "true"

    PFSENSE_SSH_HOST: str = os.environ.get("PFSENSE_SSH_HOST", "192.168.1.1")
    PFSENSE_SSH_PORT: int = int(os.environ.get("PFSENSE_SSH_PORT", 22))
    PFSENSE_SSH_USER: str = os.environ.get("PFSENSE_SSH_USER", "admin")
    PFSENSE_SSH_KEY_PATH: str = os.environ.get("PFSENSE_SSH_KEY_PATH", "")
    PFSENSE_SSH_PASSWORD: str = os.environ.get("PFSENSE_SSH_PASSWORD", "")
    PFSENSE_PF_TABLE: str = os.environ.get("PFSENSE_PF_TABLE", "honeyshield_blacklist")

    # How long an automated IP block lasts before it's eligible for
    # review/expiry (Feature 100 calls this "controlled" automated
    # response — permanent blocks without a review step are how you
    # eventually lock out a legitimate re-assigned IP forever).
    AUTO_BLOCK_REVIEW_AFTER_HOURS: int = int(os.environ.get("AUTO_BLOCK_REVIEW_AFTER_HOURS", 72))

    # --- Reporting (Group 13) ---
    REPORTS_DIR: str = os.environ.get("REPORTS_DIR", "/opt/honeyshield/reports")    # --- Forensics (Group 12) ---
    # Where System 2's rotating tcpdump captures land — mount this as a
    # shared volume/NFS export from System 2, or rsync it over on a
    # schedule; either way this path must be readable from System 1 for
    # app.services.pcap_linker to find anything.
    PCAP_CAPTURE_DIR: str = os.environ.get("PCAP_CAPTURE_DIR", "/mnt/honeyshield-pcap")
    PCAP_EVIDENCE_DIR: str = os.environ.get("PCAP_EVIDENCE_DIR", "/opt/honeyshield/pcap-evidence")

    # --- System health (Group 15) ---
    DISK_USAGE_WARNING_PERCENT: int = int(os.environ.get("DISK_USAGE_WARNING_PERCENT", 80))
    DISK_USAGE_CRITICAL_PERCENT: int = int(os.environ.get("DISK_USAGE_CRITICAL_PERCENT", 90))

    # --- CORS ---
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(",")


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()


