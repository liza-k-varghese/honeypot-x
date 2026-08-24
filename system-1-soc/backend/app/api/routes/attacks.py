"""Attack Events / Sessions — Groups 3, 6, 11 (live feed, search, filtering)."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models, schemas
from app.api.deps import get_client_ip, get_current_user, require_role
from app.core import security
from app.db import opensearch_client
from app.db.postgres import get_db
from app.services import audit

router = APIRouter(prefix="/api/attacks", tags=["attacks"])


@router.get("/stats", response_model=schemas.DashboardStats)
def dashboard_stats(db: Session = Depends(get_db), _=Depends(get_current_user)):
    total_events = db.query(func.count(models.AttackEvent.id)).scalar() or 0
    total_sessions = db.query(func.count(models.AttackSession.id)).scalar() or 0
    unique_attackers = db.query(func.count(func.distinct(models.AttackSession.src_ip))).scalar() or 0
    open_alerts = db.query(func.count(models.Alert.id)).filter(models.Alert.status == "open").scalar() or 0
    high_risk = db.query(func.count(models.AttackSession.id)).filter(
        models.AttackSession.severity.in_(["high", "critical"])
    ).scalar() or 0
    active_campaigns = db.query(func.count(models.Campaign.id)).filter(
        models.Campaign.last_seen >= datetime.now(timezone.utc) - timedelta(days=1)
    ).scalar() or 0

    return schemas.DashboardStats(
        total_events=total_events,
        total_sessions=total_sessions,
        unique_attackers=unique_attackers,
        open_alerts=open_alerts,
        blocked_or_high_risk_count=high_risk,
        active_campaigns=active_campaigns,
    )


@router.get("/sessions", response_model=list[schemas.AttackSessionOut])
def list_sessions(
    limit: int = Query(50, le=500),
    offset: int = 0,
    severity: str | None = None,
    src_ip: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    query = db.query(models.AttackSession)
    if severity:
        query = query.filter(models.AttackSession.severity == severity)
    if src_ip:
        query = query.filter(models.AttackSession.src_ip == src_ip)
    return (
        query.order_by(models.AttackSession.started_at.desc())
        .offset(offset).limit(limit).all()
    )


@router.get("/sessions/{session_id}", response_model=schemas.AttackSessionDetail)
def get_session(session_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    session = db.query(models.AttackSession).filter(models.AttackSession.id == session_id).first()
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    return session


@router.patch(
    "/sessions/{session_id}/classification",
    response_model=schemas.AttackSessionOut,
    dependencies=[Depends(require_role(security.ROLE_ANALYST))],
)
def override_classification(
    session_id: str,
    payload: schemas.ClassificationOverride,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Feature 70: Human Review Support."""
    session = db.query(models.AttackSession).filter(models.AttackSession.id == session_id).first()
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")

    session.analyst_override_classification = payload.classification
    session.analyst_reviewed = True

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id), action="session.classification_override",
        target_type="attack_session", target_id=session_id,
        details={"new_classification": payload.classification, "note": payload.note},
        ip_address=get_client_ip(request),
    )))
    db.commit()
    db.refresh(session)
    return session


@router.get("/events", response_model=list[schemas.AttackEventOut])
def list_events(
    limit: int = Query(50, le=500),
    source: str | None = None,
    src_ip: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    query = db.query(models.AttackEvent)
    if source:
        query = query.filter(models.AttackEvent.source == source)
    if src_ip:
        query = query.filter(models.AttackEvent.src_ip == src_ip)
    return query.order_by(models.AttackEvent.occurred_at.desc()).limit(limit).all()


@router.get("/search")
def search_raw_events(
    q: str = Query(..., min_length=2),
    source: str = Query("*", description="cowrie | opencanary | dionaea | zeek | suricata | *"),
    limit: int = Query(50, le=200),
    _=Depends(get_current_user),
):
    """Feature 119: Evidence Search — free-text search across raw
    OpenSearch documents (not just the normalized Postgres rows)."""
    index_pattern = f"{source}-logs-*" if source != "*" else ",".join(
        f"{s}-logs-*" for s in ["cowrie", "opencanary", "dionaea", "zeek", "suricata"]
    )
    return opensearch_client.search(index_pattern, q, size=limit)


@router.get("/top-sources")
def top_attacking_sources(limit: int = 10, db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Feature 107: Top Attacking Sources."""
    rows = (
        db.query(models.AttackSession.src_ip, func.count(models.AttackSession.id).label("session_count"))
        .group_by(models.AttackSession.src_ip)
        .order_by(func.count(models.AttackSession.id).desc())
        .limit(limit)
        .all()
    )
    return [{"src_ip": r.src_ip, "session_count": r.session_count} for r in rows]


@router.get("/top-services")
def most_targeted_services(limit: int = 10, db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Feature 108: Most Targeted Services."""
    rows = (
        db.query(models.AttackEvent.dst_port, func.count(models.AttackEvent.id).label("hit_count"))
        .filter(models.AttackEvent.dst_port.isnot(None))
        .group_by(models.AttackEvent.dst_port)
        .order_by(func.count(models.AttackEvent.id).desc())
        .limit(limit)
        .all()
    )
    from app.services.detection import analyze_target_service
    return [{"service": analyze_target_service(r.dst_port), "port": r.dst_port, "hit_count": r.hit_count} for r in rows]


