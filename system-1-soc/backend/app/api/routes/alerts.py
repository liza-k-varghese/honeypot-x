"""Alerts — Group 10 (Features 91, 94, 98-99)."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.api.deps import get_client_ip, get_current_user, require_role
from app.core import security
from app.db.postgres import get_db
from app.services import alerting, audit

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[schemas.AlertOut])
def list_alerts(
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = None,
    limit: int = Query(50, le=500),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    query = db.query(models.Alert)
    if status_filter:
        query = query.filter(models.Alert.status == status_filter)
    if severity:
        query = query.filter(models.Alert.severity == severity)
    return query.order_by(models.Alert.created_at.desc()).limit(limit).all()


@router.post(
    "/{alert_id}/acknowledge",
    response_model=schemas.AlertOut,
    dependencies=[Depends(require_role(security.ROLE_ANALYST))],
)
def acknowledge_alert(
    alert_id: str,
    payload: schemas.AlertAcknowledge,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")

    alert.status = "acknowledged"
    alert.acknowledged_by = current_user.id
    alert.acknowledged_at = datetime.now(timezone.utc)

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id), action="alert.acknowledge",
        target_type="alert", target_id=alert_id,
        details={"note": payload.note}, ip_address=get_client_ip(request),
    )))
    db.commit()
    db.refresh(alert)
    return alert


@router.post(
    "/{alert_id}/escalate",
    response_model=schemas.AlertOut,
    dependencies=[Depends(require_role(security.ROLE_ANALYST))],
)
def escalate_alert(
    alert_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")

    alert.status = "escalated"
    alert.escalated_at = datetime.now(timezone.utc)

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id), action="alert.escalate",
        target_type="alert", target_id=alert_id, ip_address=get_client_ip(request),
    )))
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/check-escalations", dependencies=[Depends(require_role(security.ROLE_ANALYST))])
def run_escalation_check(db: Session = Depends(get_db)):
    """Feature 99: Alert Escalation — run on a schedule (cron/APScheduler)
    against every open alert; escalates any that have sat unacknowledged
    past their severity's threshold. Exposed as an endpoint too so it can
    be triggered manually from the dashboard during a demo."""
    open_alerts = db.query(models.Alert).filter(models.Alert.status == "open").all()
    escalated_ids = []
    now = datetime.now(timezone.utc)

    for alert in open_alerts:
        created_at = alert.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if alerting.should_escalate(created_at, alert.severity, alert.status, now=now):
            alert.status = "escalated"
            alert.escalated_at = now
            escalated_ids.append(str(alert.id))

    db.commit()
    return {"escalated_count": len(escalated_ids), "escalated_alert_ids": escalated_ids}


@router.get("/rules", response_model=list[schemas.CustomAlertRule])
def list_custom_rules(db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Feature 94: Custom Alert Rules — stored in Configuration under a
    reserved key, rather than a dedicated table, since a project of this
    scope doesn't need full rule-versioning; see app.models.Configuration."""
    config = db.query(models.Configuration).filter(models.Configuration.key == "custom_alert_rules").first()
    return config.value if config else []


@router.put(
    "/rules",
    response_model=list[schemas.CustomAlertRule],
    dependencies=[Depends(require_role(security.ROLE_ADMIN))],
)
def update_custom_rules(
    rules: list[schemas.CustomAlertRule],
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    config = db.query(models.Configuration).filter(models.Configuration.key == "custom_alert_rules").first()
    value = [r.model_dump() for r in rules]
    if config is None:
        config = models.Configuration(key="custom_alert_rules", value=value, description="Admin-defined alert conditions")
        db.add(config)
    else:
        config.value = value
        config.updated_by = current_user.id

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id), action="configuration.update",
        target_type="configuration", target_id="custom_alert_rules",
        ip_address=get_client_ip(request),
    )))
    db.commit()
    return rules


######################################################
