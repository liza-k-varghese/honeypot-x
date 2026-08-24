"""
Pydantic v2 schemas — request/response shapes for every route in
app/api/routes/. Mirrors app/models.py table-for-table so the mapping
between ORM model and API shape stays obvious.
"""

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class _ORMBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Auth / Users
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: Optional[EmailStr] = None
    password: str = Field(min_length=8)
    role: str = "readonly"


class UserOut(_ORMBase):
    id: UUID
    username: str
    email: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


# ---------------------------------------------------------------------------
# Honeypots
# ---------------------------------------------------------------------------

class HoneypotOut(_ORMBase):
    id: UUID
    name: str
    service_type: str
    host: str
    port: int
    is_healthy: bool
    last_health_check: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Attack sessions / events
# ---------------------------------------------------------------------------

class AttackEventOut(_ORMBase):
    id: UUID
    source: str
    event_type: str
    src_ip: str
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    ids_signature: Optional[str] = None
    occurred_at: datetime


class AttackSessionOut(_ORMBase):
    id: UUID
    external_session_id: Optional[str] = None
    src_ip: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    login_attempt_count: int
    had_successful_login: bool
    command_count: int
    high_risk_command_count: int
    severity: str
    risk_score: Optional[float] = None
    ai_confidence: Optional[float] = None
    ai_classification: Optional[str] = None
    analyst_reviewed: bool
    analyst_override_classification: Optional[str] = None


class AttackSessionDetail(AttackSessionOut):
    events: list[AttackEventOut] = []


class ClassificationOverride(BaseModel):
    classification: str
    note: Optional[str] = None


# ---------------------------------------------------------------------------
# Threat intelligence
# ---------------------------------------------------------------------------

class ThreatIntelligenceOut(_ORMBase):
    ip_address: str
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    is_tor_exit_node: bool
    is_vpn_indicator: bool
    is_proxy_indicator: bool
    reputation_score: Optional[int] = None
    total_attack_count: int


# ---------------------------------------------------------------------------
# Alerts / notifications
# ---------------------------------------------------------------------------

class AlertOut(_ORMBase):
    id: UUID
    session_id: Optional[UUID] = None
    title: str
    description: Optional[str] = None
    severity: str
    source: Optional[str] = None
    status: str
    acknowledged_by: Optional[UUID] = None
    acknowledged_at: Optional[datetime] = None
    escalated_at: Optional[datetime] = None
    created_at: datetime


class AlertAcknowledge(BaseModel):
    note: Optional[str] = None


class CustomAlertRule(BaseModel):
    name: str
    condition_field: str          # e.g. "login_attempt_count"
    operator: str                 # ">=" | "==" | "contains"
    threshold: Any
    severity: str = "medium"


# ---------------------------------------------------------------------------
# Campaigns / correlation
# ---------------------------------------------------------------------------

class CampaignOut(_ORMBase):
    id: UUID
    name: str
    description: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    source_ip_count: int
    session_count: int
    severity: str


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # IP | Session | Command | Service | Campaign | Honeypot


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


# ---------------------------------------------------------------------------
# Forensics
# ---------------------------------------------------------------------------

class EvidenceCreate(BaseModel):
    session_id: Optional[UUID] = None
    evidence_type: str
    file_path: Optional[str] = None
    note_text: Optional[str] = None


class EvidenceOut(_ORMBase):
    id: UUID
    session_id: Optional[UUID] = None
    evidence_type: str
    file_path: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    note_text: Optional[str] = None
    analyst_id: Optional[UUID] = None
    created_at: datetime


class IncidentOut(_ORMBase):
    id: UUID
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    created_at: datetime
    closed_at: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

class ReportRequest(BaseModel):
    report_type: str  # daily | weekly | monthly | incident | custom
    format: str = "pdf"
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    incident_id: Optional[UUID] = None


class ReportOut(_ORMBase):
    id: UUID
    report_type: str
    title: str
    file_path: Optional[str] = None
    format: str
    created_at: datetime


# ---------------------------------------------------------------------------
# ESP32 / hardware
# ---------------------------------------------------------------------------

class SensorReadingIn(BaseModel):
    device_id: str = "esp32-01"
    temperature_c: Optional[float] = None
    humidity_percent: Optional[float] = None
    smoke_level: Optional[int] = None
    tamper_detected: bool = False


class SensorReadingOut(_ORMBase):
    id: UUID
    device_id: str
    temperature_c: Optional[float] = None
    humidity_percent: Optional[float] = None
    smoke_level: Optional[int] = None
    tamper_detected: bool
    alert_triggered: bool
    recorded_at: datetime


# ---------------------------------------------------------------------------
# System health
# ---------------------------------------------------------------------------

class SystemHealthIn(BaseModel):
    node: str
    healthy: bool
    services: dict[str, bool] = {}
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    disk_percent: Optional[float] = None


class SystemHealthOut(_ORMBase):
    node: str
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    disk_percent: Optional[float] = None
    services_status: Optional[dict] = None
    is_healthy: bool
    recorded_at: datetime


# ---------------------------------------------------------------------------
# Stats / dashboard
# ---------------------------------------------------------------------------

class DashboardStats(BaseModel):
    total_events: int
    total_sessions: int
    unique_attackers: int
    open_alerts: int
    blocked_or_high_risk_count: int
    active_campaigns: int


class ConfigurationOut(_ORMBase):
    key: str
    value: Any
    description: Optional[str] = None
    updated_at: datetime


class ConfigurationUpdate(BaseModel):
    value: Any
    description: Optional[str] = None


# ---------------------------------------------------------------------------
# Automated response / playbooks
# ---------------------------------------------------------------------------

class ResponseActionOut(_ORMBase):
    id: UUID
    session_id: Optional[UUID] = None
    playbook_name: str
    action_type: str
    target: Optional[str] = None
    success: bool
    skipped: bool
    detail: Optional[dict] = None
    reviewed: bool
    reviewed_by: Optional[UUID] = None
    reviewed_at: Optional[datetime] = None
    created_at: datetime


class PlaybookDefinition(BaseModel):
    name: str
    description: str
    trigger: dict
    actions: list[str]


