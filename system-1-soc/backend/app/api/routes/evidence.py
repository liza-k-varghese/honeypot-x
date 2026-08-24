"""
Digital Forensics & Incident Management API routes — Group 12 (Features 111-120).
"""

import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app import models, schemas
from app.api.deps import get_client_ip, get_current_user, require_role
from app.core import security
from app.core.config import settings
from app.db.postgres import get_db
from app.services import audit, pcap_linker

router = APIRouter(prefix="/api/evidence", tags=["evidence"])
incidents_router = APIRouter(prefix="/api/incidents", tags=["incidents"])


# ---------------------------------------------------------------------------
# Evidence Endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=list[schemas.EvidenceOut])
def list_evidence(
    session_id: str | None = None,
    evidence_type: str | None = None,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Features 111-120: List forensic evidence items."""
    query = db.query(models.Evidence)
    if session_id:
        query = query.filter(models.Evidence.session_id == session_id)
    if evidence_type:
        query = query.filter(models.Evidence.evidence_type == evidence_type)
    return query.order_by(models.Evidence.created_at.desc()).limit(limit).all()


@router.post(
    "",
    response_model=schemas.EvidenceOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role(security.ROLE_ANALYST))],
)
def add_evidence(
    payload: schemas.EvidenceCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Add an analyst note or external artifact to the evidence store."""
    file_hash = None
    if payload.file_path and os.path.exists(payload.file_path):
        file_hash = pcap_linker.sha256_file(payload.file_path)

    evidence = models.Evidence(
        session_id=payload.session_id,
        evidence_type=payload.evidence_type,
        file_path=payload.file_path,
        file_hash_sha256=file_hash,
        note_text=payload.note_text,
        analyst_id=current_user.id,
    )
    db.add(evidence)
    db.flush()

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id),
        action="evidence.create",
        target_type="evidence",
        target_id=str(evidence.id),
        ip_address=get_client_ip(request),
    )))
    db.commit()
    db.refresh(evidence)
    return evidence


@router.post(
    "/extract-pcap/{session_id}",
    response_model=schemas.EvidenceOut,
    dependencies=[Depends(require_role(security.ROLE_ANALYST))],
)
def extract_pcap_for_session(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Feature 111: Extract session-scoped PCAP from raw hourly captures."""
    session = db.query(models.AttackSession).filter(models.AttackSession.id == session_id).first()
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Attack session not found")

    end_time = session.ended_at or session.started_at
    result = pcap_linker.extract_session_pcap(
        capture_dir=settings.PCAP_CAPTURE_DIR,
        output_dir=settings.PCAP_EVIDENCE_DIR,
        session_id=str(session.id),
        src_ip=session.src_ip,
        session_start=session.started_at,
        session_end=end_time,
        port=session.dst_port,
    )

    if not result:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "No matching PCAP packets found covering this session's time window",
        )

    evidence = models.Evidence(
        session_id=session.id,
        evidence_type="pcap",
        file_path=result["file_path"],
        file_hash_sha256=result["file_hash_sha256"],
        note_text=result["note_text"],
        analyst_id=current_user.id,
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


@router.get("/{evidence_id}/download")
def download_evidence_file(
    evidence_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Download evidence file (PCAP, malware sample, or export)."""
    evidence = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if evidence is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Evidence record not found")
    if not evidence.file_path or not os.path.exists(evidence.file_path):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Evidence file not found on disk")

    filename = os.path.basename(evidence.file_path)
    return FileResponse(path=evidence.file_path, filename=filename)


# ---------------------------------------------------------------------------
# Incident Endpoints
# ---------------------------------------------------------------------------

@incidents_router.get("", response_model=list[schemas.IncidentOut])
def list_incidents(
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = None,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List security incidents."""
    query = db.query(models.Incident)
    if status_filter:
        query = query.filter(models.Incident.status == status_filter)
    if severity:
        query = query.filter(models.Incident.severity == severity)
    return query.order_by(models.Incident.created_at.desc()).limit(limit).all()


@incidents_router.post(
    "",
    response_model=schemas.IncidentOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role(security.ROLE_ANALYST))],
)
def create_incident(
    title: str,
    description: str | None = None,
    severity: str = "medium",
    campaign_id: str | None = None,
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Create a new formal security incident."""
    incident = models.Incident(
        title=title,
        description=description,
        severity=severity,
        status="open",
        campaign_id=campaign_id,
    )
    db.add(incident)
    db.flush()

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id),
        action="incident.create",
        target_type="incident",
        target_id=str(incident.id),
        ip_address=get_client_ip(request) if request else "unknown",
    )))
    db.commit()
    db.refresh(incident)
    return incident


@incidents_router.patch(
    "/{incident_id}",
    response_model=schemas.IncidentOut,
    dependencies=[Depends(require_role(security.ROLE_ANALYST))],
)
def update_incident(
    incident_id: str,
    new_status: str = Query(..., regex="^(open|investigating|contained|closed)$"),
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Update incident status."""
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")

    incident.status = new_status
    if new_status == "closed":
        incident.closed_at = datetime.now(timezone.utc)

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id),
        action="incident.update_status",
        target_type="incident",
        target_id=incident_id,
        details={"status": new_status},
        ip_address=get_client_ip(request) if request else "unknown",
    )))
    db.commit()
    db.refresh(incident)
    return incident
