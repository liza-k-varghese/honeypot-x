"""
Threat Intelligence API routes — Group 5 (Features 41-50).
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.api.deps import get_client_ip, get_current_user, require_role
from app.core import security
from app.db.postgres import get_db
from app.services import audit, threat_intel

router = APIRouter(prefix="/api/threat-intel", tags=["threat-intel"])


@router.get("", response_model=list[schemas.ThreatIntelligenceOut])
def list_threat_intel(
    limit: int = Query(50, le=500),
    offset: int = 0,
    is_tor: bool | None = None,
    is_vpn: bool | None = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List threat intelligence records stored in the database."""
    query = db.query(models.ThreatIntelligence)
    if is_tor is not None:
        query = query.filter(models.ThreatIntelligence.is_tor_exit_node == is_tor)
    if is_vpn is not None:
        query = query.filter(models.ThreatIntelligence.is_vpn_indicator == is_vpn)
    return (
        query.order_by(models.ThreatIntelligence.last_seen.desc())
        .offset(offset).limit(limit).all()
    )


@router.get("/{ip_address}", response_model=schemas.ThreatIntelligenceOut)
def get_threat_intel_by_ip(
    ip_address: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Lookup threat intelligence for an IP address. If not present in DB,
    runs on-demand enrichment and persists the result."""
    record = db.query(models.ThreatIntelligence).filter(
        models.ThreatIntelligence.ip_address == ip_address
    ).first()

    if record is not None:
        return record

    # Perform on-demand enrichment
    data = threat_intel.enrich(ip_address)
    record = models.ThreatIntelligence(**data)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.post(
    "/{ip_address}/re-enrich",
    response_model=schemas.ThreatIntelligenceOut,
    dependencies=[Depends(require_role(security.ROLE_ANALYST))],
)
def re_enrich_ip(
    ip_address: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Force re-enrichment of threat intelligence for a given IP."""
    data = threat_intel.enrich(ip_address)
    record = db.query(models.ThreatIntelligence).filter(
        models.ThreatIntelligence.ip_address == ip_address
    ).first()

    if record is None:
        record = models.ThreatIntelligence(**data)
        db.add(record)
    else:
        for k, v in data.items():
            setattr(record, k, v)
        record.last_enriched_at = datetime.now(timezone.utc)

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id),
        action="threat_intel.re_enrich",
        target_type="threat_intelligence",
        target_id=ip_address,
        ip_address=get_client_ip(request),
    )))
    db.commit()
    db.refresh(record)
    return record
