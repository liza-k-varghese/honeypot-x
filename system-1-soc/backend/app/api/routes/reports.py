"""
Reporting & Documentation API routes — Group 13 (Features 121-130).
"""

import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models, schemas
from app.api.deps import get_client_ip, get_current_user, require_role
from app.core import security
from app.core.config import settings
from app.db.postgres import get_db
from app.services import audit, reporting

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("", response_model=list[schemas.ReportOut])
def list_reports(
    limit: int = Query(50, le=200),
    report_type: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List previously generated reports."""
    query = db.query(models.Report)
    if report_type:
        query = query.filter(models.Report.report_type == report_type)
    return query.order_by(models.Report.created_at.desc()).limit(limit).all()


@router.post(
    "/generate",
    response_model=schemas.ReportOut,
    dependencies=[Depends(require_role(security.ROLE_ANALYST))],
)
def generate_report(
    payload: schemas.ReportRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Features 121-129: Generate PDF or CSV security report."""
    now = datetime.now(timezone.utc)
    period_end = payload.period_end or now

    # Determine default time range based on report_type
    if payload.period_start:
        period_start = payload.period_start
    elif payload.report_type == "daily":
        period_start = period_end - timedelta(days=1)
    elif payload.report_type == "weekly":
        period_start = period_end - timedelta(days=7)
    elif payload.report_type == "monthly":
        period_start = period_end - timedelta(days=30)
    else:
        period_start = period_end - timedelta(days=7)

    # Compute statistics for report
    total_events = db.query(func.count(models.AttackEvent.id)).filter(
        models.AttackEvent.occurred_at >= period_start,
        models.AttackEvent.occurred_at <= period_end,
    ).scalar() or 0

    total_sessions = db.query(func.count(models.AttackSession.id)).filter(
        models.AttackSession.started_at >= period_start,
        models.AttackSession.started_at <= period_end,
    ).scalar() or 0

    critical_alerts = db.query(func.count(models.Alert.id)).filter(
        models.Alert.severity == "critical",
        models.Alert.created_at >= period_start,
        models.Alert.created_at <= period_end,
    ).scalar() or 0

    stats = {
        "Total Attack Events": total_events,
        "Total Sessions": total_sessions,
        "Critical Alerts": critical_alerts,
        "Period Start": period_start.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Period End": period_end.strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    # Top attackers
    top_attackers_rows = (
        db.query(models.AttackSession.src_ip, func.count(models.AttackSession.id).label("session_count"))
        .filter(models.AttackSession.started_at >= period_start, models.AttackSession.started_at <= period_end)
        .group_by(models.AttackSession.src_ip)
        .order_by(func.count(models.AttackSession.id).desc())
        .limit(10)
        .all()
    )
    top_attackers = [{"IP Address": r.src_ip, "Sessions": r.session_count} for r in top_attackers_rows]

    # Alerts list
    alerts_rows = (
        db.query(models.Alert)
        .filter(models.Alert.created_at >= period_start, models.Alert.created_at <= period_end)
        .order_by(models.Alert.created_at.desc())
        .limit(25)
        .all()
    )
    alerts_list = [
        {"Title": a.title, "Severity": a.severity, "Status": a.status, "Time": a.created_at.strftime("%Y-%m-%d %H:%M")}
        for a in alerts_rows
    ]

    meta = reporting.build_report_metadata(payload.report_type, period_start, period_end)
    file_path = meta["file_path"]

    if payload.format.lower() == "csv":
        file_path = file_path.replace(".pdf", ".csv")
        csv_content = reporting.generate_csv(alerts_list, fieldnames=["Title", "Severity", "Status", "Time"])
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(csv_content)
    else:
        reporting.generate_pdf(
            title=meta["title"],
            period_label=meta["period_label"],
            stats=stats,
            top_attackers=top_attackers,
            alerts=alerts_list,
            output_path=file_path,
        )

    report_record = models.Report(
        report_type=payload.report_type,
        title=meta["title"],
        file_path=file_path,
        format=payload.format.lower(),
        period_start=period_start,
        period_end=period_end,
        generated_by=current_user.id,
    )
    db.add(report_record)

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id),
        action="report.generate",
        target_type="report",
        details={"type": payload.report_type, "format": payload.format},
        ip_address=get_client_ip(request),
    )))
    db.commit()
    db.refresh(report_record)
    return report_record


@router.get("/{report_id}/download")
def download_report(
    report_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Download a generated PDF or CSV report file."""
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    if not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report file not found on disk")

    media_type = "application/pdf" if report.format == "pdf" else "text/csv"
    filename = os.path.basename(report.file_path)
    return FileResponse(path=report.file_path, filename=filename, media_type=media_type)
