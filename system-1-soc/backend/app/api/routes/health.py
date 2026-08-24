"""
System Health & Infrastructure Monitoring API routes — Group 15 (Features 141-150).
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.api.deps import get_current_user, require_device_api_key
from app.db.postgres import get_db
from app.services import system_health

router = APIRouter(prefix="/api/health", tags=["health"])


@router.post("/system2", dependencies=[Depends(require_device_api_key)])
def receive_system2_health(
    payload: schemas.SystemHealthIn,
    db: Session = Depends(get_db),
):
    """Group 2/15: Receive health and container status payload from
    System 2's periodic cron script."""
    record = models.SystemHealth(
        node=payload.node,
        cpu_percent=payload.cpu_percent,
        memory_percent=payload.memory_percent,
        disk_percent=payload.disk_percent,
        services_status=payload.services,
        is_healthy=payload.healthy,
    )
    db.add(record)

    # Check for disk space threshold alert
    if payload.disk_percent is not None:
        alert_level = system_health.classify_disk_alert(payload.disk_percent)
        if alert_level:
            db.add(models.Alert(
                title=f"System 2 Disk Storage Alert [{payload.disk_percent}%]",
                description=f"Storage threshold alert on node {payload.node}: disk is at {payload.disk_percent}%.",
                severity="critical" if alert_level == "critical" else "high",
                source="system2_health_monitor",
                status="open",
            ))

    db.commit()
    return {"status": "recorded", "healthy": payload.healthy}


@router.get("/status")
def get_overall_health_status(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Returns combined real-time health for System 1 and latest reported
    health for System 2."""
    local_metrics = system_health.get_local_metrics()
    postgres_up = system_health.check_postgres_health()
    redis_up = system_health.check_redis_health()
    opensearch_up = system_health.check_opensearch_health()

    system1_services = {
        "postgres": postgres_up,
        "redis": redis_up,
        "opensearch": opensearch_up,
    }
    system1_healthy = all(system1_services.values())

    # Get latest System 2 record
    s2_latest = (
        db.query(models.SystemHealth)
        .filter(models.SystemHealth.node == "system-2-honeypot")
        .order_by(models.SystemHealth.recorded_at.desc())
        .first()
    )

    return {
        "system1": {
            "node": "system-1-soc",
            "healthy": system1_healthy,
            "metrics": local_metrics,
            "services": system1_services,
        },
        "system2": {
            "node": "system-2-honeypot",
            "healthy": s2_latest.is_healthy if s2_latest else False,
            "cpu_percent": s2_latest.cpu_percent if s2_latest else None,
            "memory_percent": s2_latest.memory_percent if s2_latest else None,
            "disk_percent": s2_latest.disk_percent if s2_latest else None,
            "services": s2_latest.services_status if s2_latest else {},
            "last_seen": s2_latest.recorded_at if s2_latest else None,
        },
    }


@router.get("/history", response_model=list[schemas.SystemHealthOut])
def get_health_history(
    node: str | None = None,
    limit: int = Query(50, le=500),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List historical health logs."""
    query = db.query(models.SystemHealth)
    if node:
        query = query.filter(models.SystemHealth.node == node)
    return query.order_by(models.SystemHealth.recorded_at.desc()).limit(limit).all()
