"""
SQLAlchemy models for every PostgreSQL entity in the master plan's
"Suggested entities" list (Section 13): Users, Roles, Permissions,
AttackEvents, Sessions, Alerts, Honeypots, ThreatIntelligence, Reports,
Notifications, SystemHealth, SensorReadings, Incidents, Evidence,
Configurations, AuditLogs.

Kept in one file deliberately (rather than one file per table) — at this
table count, one file with clear section headers is easier to navigate
than jumping across 16 tiny files, and avoids circular-import headaches
between related tables (e.g. AttackEvent <-> AttackSession <-> Alert).
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, JSON,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.postgres import Base


def _uuid_col():
    return Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


# ---------------------------------------------------------------------------
# Group 14 — User Management & Access Control
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id = _uuid_col()
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default="readonly")  # admin | analyst | readonly
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)

    audit_logs = relationship("AuditLog", back_populates="user")
    investigation_notes = relationship("Evidence", back_populates="analyst")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = _uuid_col()
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action = Column(String(128), nullable=False)          # e.g. "alert.acknowledge"
    target_type = Column(String(64), nullable=True)        # e.g. "alert"
    target_id = Column(String(64), nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    user = relationship("User", back_populates="audit_logs")


# ---------------------------------------------------------------------------
# Group 2 — Honeypots
# ---------------------------------------------------------------------------

class Honeypot(Base):
    __tablename__ = "honeypots"

    id = _uuid_col()
    name = Column(String(64), unique=True, nullable=False)   # cowrie | opencanary | dionaea
    service_type = Column(String(64), nullable=False)        # ssh | telnet | http | ftp | smb | ...
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False)
    is_healthy = Column(Boolean, default=True)
    last_health_check = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    sessions = relationship("AttackSession", back_populates="honeypot")


# ---------------------------------------------------------------------------
# Groups 3/4/6 — Network Monitoring, Logging, Attack Detection
# ---------------------------------------------------------------------------

class AttackSession(Base):
    """One honeypot interaction (Cowrie session, OpenCanary connection,
    etc.) — the unit correlation and AI scoring both operate on."""
    __tablename__ = "attack_sessions"

    id = _uuid_col()
    external_session_id = Column(String(128), nullable=True, index=True)  # e.g. Cowrie's own session id
    honeypot_id = Column(UUID(as_uuid=True), ForeignKey("honeypots.id"), nullable=True)
    src_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    ended_at = Column(DateTime, nullable=True)
    login_attempt_count = Column(Integer, default=0)
    had_successful_login = Column(Boolean, default=False)
    command_count = Column(Integer, default=0)
    high_risk_command_count = Column(Integer, default=0)
    severity = Column(String(16), default="info")  # info | low | medium | high | critical
    risk_score = Column(Float, nullable=True)
    ai_confidence = Column(Float, nullable=True)
    ai_classification = Column(String(64), nullable=True)  # e.g. "brute_force", "recon", "exploitation"
    analyst_reviewed = Column(Boolean, default=False)
    analyst_override_classification = Column(String(64), nullable=True)

    honeypot = relationship("Honeypot", back_populates="sessions")
    events = relationship("AttackEvent", back_populates="session")
    alerts = relationship("Alert", back_populates="session")


class AttackEvent(Base):
    """One normalized log line from any of the 5 sources (Cowrie,
    OpenCanary, Dionaea, Zeek, Suricata) — see
    app/services/log_normalization.py for how raw OpenSearch documents
    become rows here."""
    __tablename__ = "attack_events"

    id = _uuid_col()
    session_id = Column(UUID(as_uuid=True), ForeignKey("attack_sessions.id"), nullable=True)
    source = Column(String(32), nullable=False, index=True)   # cowrie | opencanary | dionaea | zeek | suricata
    event_type = Column(String(64), nullable=False, index=True)  # login_attempt | login_success | command | connection | ids_alert | ...
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)
    username = Column(String(128), nullable=True)
    password = Column(String(128), nullable=True)
    command = Column(Text, nullable=True)
    ids_signature = Column(String(255), nullable=True)   # Suricata rule msg, when source=suricata
    raw_json = Column(JSON, nullable=True)
    occurred_at = Column(DateTime, nullable=False, index=True)
    ingested_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("AttackSession", back_populates="events")


# ---------------------------------------------------------------------------
# Group 5 — Threat Intelligence
# ---------------------------------------------------------------------------

class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"

    id = _uuid_col()
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    country = Column(String(64), nullable=True)
    city = Column(String(128), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    asn = Column(Integer, nullable=True)
    isp = Column(String(255), nullable=True)
    organization = Column(String(255), nullable=True)
    is_tor_exit_node = Column(Boolean, default=False)
    is_vpn_indicator = Column(Boolean, default=False)
    is_proxy_indicator = Column(Boolean, default=False)
    reputation_score = Column(Integer, nullable=True)   # 0-100, higher = worse, from AbuseIPDB-style source
    reputation_source = Column(String(64), nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    last_enriched_at = Column(DateTime, nullable=True)
    total_attack_count = Column(Integer, default=0)


# ---------------------------------------------------------------------------
# Group 8 — Attack Correlation & Campaign Analysis (Postgres side; the
# graph itself lives in Neo4j — this table just tracks campaign metadata
# for reporting/dashboard listing)
# ---------------------------------------------------------------------------

class Campaign(Base):
    __tablename__ = "campaigns"

    id = _uuid_col()
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)
    source_ip_count = Column(Integer, default=0)
    session_count = Column(Integer, default=0)
    severity = Column(String(16), default="medium")
    created_at = Column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# Group 10 — Response & Alerting
# ---------------------------------------------------------------------------

class Alert(Base):
    __tablename__ = "alerts"

    id = _uuid_col()
    session_id = Column(UUID(as_uuid=True), ForeignKey("attack_sessions.id"), nullable=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), nullable=False, default="medium")  # low | medium | high | critical
    source = Column(String(64), nullable=True)   # which detection rule / engine raised it
    status = Column(String(16), default="open")  # open | acknowledged | escalated | resolved
    acknowledged_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    escalated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    session = relationship("AttackSession", back_populates="alerts")


class Notification(Base):
    __tablename__ = "notifications"

    id = _uuid_col()
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=True)
    channel = Column(String(32), nullable=False)   # email | telegram | dashboard
    recipient = Column(String(255), nullable=True)
    status = Column(String(16), default="pending")  # pending | sent | failed
    error_message = Column(Text, nullable=True)
    sent_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ResponseAction(Base):
    """Feature 100: Controlled Automated Response — one row per playbook
    action actually attempted (not just recommended). Distinct from
    AuditLog, which tracks human analyst actions; this tracks what the
    *system* did on its own, which needs its own review trail since an
    automated block is exactly the kind of thing that needs to be easy
    to find and reverse if it turns out to be a false positive."""
    __tablename__ = "response_actions"

    id = _uuid_col()
    session_id = Column(UUID(as_uuid=True), ForeignKey("attack_sessions.id"), nullable=True)
    playbook_name = Column(String(64), nullable=False)
    action_type = Column(String(32), nullable=False)  # block_ip | notify | create_incident
    target = Column(String(255), nullable=True)         # e.g. the IP that was blocked
    success = Column(Boolean, nullable=False)
    skipped = Column(Boolean, default=False)              # e.g. AUTOMATED_RESPONSE_ENABLED was false
    detail = Column(JSON, nullable=True)
    reviewed = Column(Boolean, default=False)
    reviewed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


# ---------------------------------------------------------------------------
# Group 12 — Digital Forensics
# ---------------------------------------------------------------------------

class Evidence(Base):
    __tablename__ = "evidence"

    id = _uuid_col()
    session_id = Column(UUID(as_uuid=True), ForeignKey("attack_sessions.id"), nullable=True)
    evidence_type = Column(String(32), nullable=False)  # pcap | command_history | malware_sample | note
    file_path = Column(String(512), nullable=True)
    file_hash_sha256 = Column(String(64), nullable=True)
    note_text = Column(Text, nullable=True)
    analyst_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    analyst = relationship("User", back_populates="investigation_notes")


class Incident(Base):
    __tablename__ = "incidents"

    id = _uuid_col()
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), default="medium")
    status = Column(String(16), default="open")  # open | investigating | contained | closed
    campaign_id = Column(UUID(as_uuid=True), ForeignKey("campaigns.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    closed_at = Column(DateTime, nullable=True)


# ---------------------------------------------------------------------------
# Group 13 — Reporting
# ---------------------------------------------------------------------------

class Report(Base):
    __tablename__ = "reports"

    id = _uuid_col()
    report_type = Column(String(32), nullable=False)  # daily | weekly | monthly | incident | custom
    title = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=True)
    format = Column(String(8), default="pdf")   # pdf | csv
    period_start = Column(DateTime, nullable=True)
    period_end = Column(DateTime, nullable=True)
    generated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# Group 15 — System Health & Infrastructure Monitoring
# ---------------------------------------------------------------------------

class SystemHealth(Base):
    __tablename__ = "system_health"

    id = _uuid_col()
    node = Column(String(64), nullable=False)   # system-1-soc | system-2-honeypot
    cpu_percent = Column(Float, nullable=True)
    memory_percent = Column(Float, nullable=True)
    disk_percent = Column(Float, nullable=True)
    services_status = Column(JSON, nullable=True)  # {"cowrie": true, "suricata": false, ...}
    is_healthy = Column(Boolean, default=True)
    recorded_at = Column(DateTime, default=datetime.utcnow, index=True)


# ---------------------------------------------------------------------------
# Group 16 — ESP32 Hardware Security Monitoring
# ---------------------------------------------------------------------------

class SensorReading(Base):
    __tablename__ = "sensor_readings"

    id = _uuid_col()
    device_id = Column(String(64), nullable=False, default="esp32-01")
    temperature_c = Column(Float, nullable=True)
    humidity_percent = Column(Float, nullable=True)
    smoke_level = Column(Integer, nullable=True)     # raw MQ-2 analog reading
    tamper_detected = Column(Boolean, default=False)  # reed switch state
    alert_triggered = Column(Boolean, default=False)
    recorded_at = Column(DateTime, default=datetime.utcnow, index=True)


# ---------------------------------------------------------------------------
# Group 1 — Core Platform (Configurations)
# ---------------------------------------------------------------------------

class Configuration(Base):
    __tablename__ = "configurations"

    id = _uuid_col()
    key = Column(String(128), unique=True, nullable=False)
    value = Column(JSON, nullable=False)
    description = Column(Text, nullable=True)
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)


