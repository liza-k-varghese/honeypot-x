"""
Deception & Honeypot Enhancement API routes — Group 9 (Features 81-90).
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models
from app.api.deps import get_current_user, require_role
from app.core import security
from app.db.postgres import get_db
from app.services import deception

router = APIRouter(prefix="/api/deception", tags=["deception"])


@router.get("/canaries")
def list_canary_assets(_=Depends(get_current_user)):
    """Features 83-87: List configured canary files, bait paths, and directories."""
    return {
        "canary_paths": sorted(list(deception.CANARY_PATHS)),
        "directories": deception.FAKE_DIRECTORY_STRUCTURE,
        "sample_files": [f["path"] for f in deception.generate_fake_files()],
    }


@router.post(
    "/generate-credentials",
    dependencies=[Depends(require_role(security.ROLE_ADMIN))],
)
def generate_decoy_credentials(
    count: int = Query(5, ge=1, le=20),
    _=Depends(get_current_user),
):
    """Features 81-82: Generate additional weak deception credentials for Cowrie."""
    accounts = deception.generate_fake_user_accounts(count=count)
    return {
        "generated_count": len(accounts),
        "accounts": accounts,
        "format_userdb": "\n".join(f"{a['username']}:0:{a['password']}" for a in accounts),
    }


@router.get("/triggers")
def list_deception_triggers(
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Features 89-90: List alerts and events triggered by interaction
    with canary deception assets."""
    alerts = (
        db.query(models.Alert)
        .filter(models.Alert.source == "deception")
        .order_by(models.Alert.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": str(a.id),
            "session_id": str(a.session_id) if a.session_id else None,
            "title": a.title,
            "description": a.description,
            "severity": a.severity,
            "status": a.status,
            "created_at": a.created_at,
        }
        for a in alerts
    ]


@router.get("/stats")
def deception_stats(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Summary statistics for deception lure engagements."""
    total_deception_alerts = (
        db.query(func.count(models.Alert.id))
        .filter(models.Alert.source == "deception")
        .scalar()
        or 0
    )
    canary_paths_count = len(deception.CANARY_PATHS)

    return {
        "total_triggers": total_deception_alerts,
        "active_canary_paths": canary_paths_count,
        "active_fake_directories": len(deception.FAKE_DIRECTORY_STRUCTURE),
    }
