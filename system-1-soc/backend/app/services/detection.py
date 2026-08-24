"""
Attack Detection & Analytics — Group 6.

Every function here is a pure function operating on plain dicts/lists, not
ORM objects — deliberately, so the detection logic can be unit tested
without a live Postgres connection (see tests/test_detection.py), and so
app/workers/ingestion_worker.py can call these the same way whether the
data came from a fresh SQLAlchemy row or a Suricata alert straight off
OpenSearch.
"""

import statistics
from datetime import datetime

from app.core.config import settings

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Common ports for the honeypot services in the master plan's stack —
# used by analyze_target_service() to turn a raw port number into a
# human-readable service name for the dashboard's "Most Targeted Services"
# panel (Group 11, feature 108).
SERVICE_PORT_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 69: "TFTP", 80: "HTTP",
    445: "SMB", 2222: "SSH (honeypot)", 2223: "Telnet (honeypot)",
    3306: "MySQL", 8080: "HTTP (honeypot)",
}


# ---------------------------------------------------------------------------
# Features 51-55: core rule-based detections
# ---------------------------------------------------------------------------

def is_brute_force(recent_attempt_count: int) -> bool:
    """recent_attempt_count = login attempts from one IP within
    LOGIN_ATTEMPT_WINDOW_SECONDS, as computed by the caller's DB query."""
    return recent_attempt_count >= settings.LOGIN_ATTEMPT_THRESHOLD


def is_port_scan(distinct_ports_hit: int) -> bool:
    return distinct_ports_hit >= settings.PORT_SCAN_THRESHOLD


def find_high_risk_commands(commands: list[str]) -> list[str]:
    """Returns the subset of `commands` that match a keyword on the
    high-risk list — e.g. download/execute/recon/exfil tooling typed into
    Cowrie's fake shell."""
    matched = []
    for cmd in commands:
        lowered = (cmd or "").lower()
        if any(kw.lower() in lowered for kw in settings.HIGH_RISK_COMMAND_KEYWORDS):
            matched.append(cmd)
    return matched


def is_repeated_attack(prior_session_count_for_ip: int, threshold: int = 3) -> bool:
    """An IP that has hit the honeypot in `threshold`-or-more separate
    sessions is treated as a repeat offender rather than a one-off scan."""
    return prior_session_count_for_ip >= threshold


def is_abnormal_session(
    duration_seconds: float,
    command_count: int,
    historical_mean_duration: float,
    historical_stdev_duration: float,
    z_threshold: float = 2.5,
) -> bool:
    """Flags a session whose duration is a statistical outlier relative to
    the honeypot's own historical traffic — catches sessions that are
    unusually long/short even when no single rule above fires. Falls back
    to "not abnormal" when there isn't enough history yet (stdev of 0)
    rather than dividing by zero."""
    if historical_stdev_duration <= 0:
        return False
    z_score = abs(duration_seconds - historical_mean_duration) / historical_stdev_duration
    return z_score >= z_threshold


# ---------------------------------------------------------------------------
# Features 56-59: frequency / duration / source / target analysis
# ---------------------------------------------------------------------------

def analyze_frequency(event_timestamps: list[datetime]) -> dict:
    """Events-per-hour rate for a set of timestamps (typically: every event
    from one source IP). Used for the dashboard's Attack Frequency Analysis
    panel and as an input to severity classification."""
    if len(event_timestamps) < 2:
        return {"count": len(event_timestamps), "events_per_hour": 0.0, "span_seconds": 0.0}
    sorted_ts = sorted(event_timestamps)
    span_seconds = (sorted_ts[-1] - sorted_ts[0]).total_seconds()
    if span_seconds <= 0:
        return {"count": len(event_timestamps), "events_per_hour": float("inf"), "span_seconds": 0.0}
    events_per_hour = len(event_timestamps) / (span_seconds / 3600)
    return {"count": len(event_timestamps), "events_per_hour": round(events_per_hour, 2), "span_seconds": span_seconds}


def analyze_duration(started_at: datetime, ended_at: datetime | None) -> float | None:
    if ended_at is None:
        return None
    return (ended_at - started_at).total_seconds()


def analyze_target_service(dst_port: int | None) -> str:
    if dst_port is None:
        return "unknown"
    return SERVICE_PORT_MAP.get(dst_port, f"port-{dst_port}")


def compute_historical_stats(durations: list[float]) -> dict:
    """Mean/stdev helper for is_abnormal_session() — computed by the
    caller from however much session history it wants to consider (e.g.
    the last 500 sessions), then passed in rather than queried here, to
    keep this module free of any direct DB dependency."""
    if len(durations) < 2:
        return {"mean": 0.0, "stdev": 0.0}
    return {"mean": statistics.mean(durations), "stdev": statistics.stdev(durations)}


# ---------------------------------------------------------------------------
# Feature 60: severity classification
# ---------------------------------------------------------------------------

def classify_severity(
    had_successful_login: bool,
    high_risk_command_count: int,
    is_brute_force_flag: bool,
    is_port_scan_flag: bool,
    is_repeated_attack_flag: bool,
    is_abnormal_flag: bool,
    threat_intel_reputation_score: int | None = None,
) -> str:
    """Combines every signal into one severity level for the session.
    Ordered so the single worst signal decides the floor, then repeat/
    abnormal-behavior signals can push it up by one level — mirrors how a
    human analyst would triage: "did they get in and do something bad?"
    outweighs "did they scan a lot of ports?".
    """
    if had_successful_login and high_risk_command_count > 0:
        severity = "critical"
    elif had_successful_login:
        severity = "high"
    elif high_risk_command_count > 0:
        severity = "high"
    elif is_brute_force_flag:
        severity = "medium"
    elif is_port_scan_flag:
        severity = "low"
    else:
        severity = "info"

    # Escalate by one level for corroborating signals, capped at critical.
    escalate = is_repeated_attack_flag or is_abnormal_flag or (
        threat_intel_reputation_score is not None and threat_intel_reputation_score >= 75
    )
    if escalate and severity != "critical":
        idx = SEVERITY_ORDER.index(severity)
        severity = SEVERITY_ORDER[min(idx + 1, len(SEVERITY_ORDER) - 1)]

    return severity


