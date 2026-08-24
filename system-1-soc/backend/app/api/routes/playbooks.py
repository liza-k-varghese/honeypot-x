"""
Automated Response & Playbooks API routes — Group 10, Feature 100.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.api.deps import get_client_ip, get_current_user, require_role
from app.core import security
from app.db.postgres import get_db
from app.services import audit, firewall_response, playbooks

router = APIRouter(prefix="/api/playbooks", tags=["playbooks"])


@router.get("", response_model=list[schemas.PlaybookDefinition])
def list_playbooks(_=Depends(get_current_user)):
    """List available automated response playbook definitions."""
    return [
        schemas.PlaybookDefinition(
            name=p["name"],
            description=p["description"],
            trigger=p["trigger"],
            actions=p["actions"],
        )
        for p in playbooks.DEFAULT_PLAYBOOKS
    ]


@router.get("/actions", response_model=list[schemas.ResponseActionOut])
def list_response_actions(
    limit: int = Query(50, le=200),
    reviewed: bool | None = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Feature 100: Review log of automated response actions taken by the system."""
    query = db.query(models.ResponseAction)
    if reviewed is not None:
        query = query.filter(models.ResponseAction.reviewed == reviewed)
    return query.order_by(models.ResponseAction.created_at.desc()).limit(limit).all()


@router.post(
    "/actions/{action_id}/review",
    response_model=schemas.ResponseActionOut,
    dependencies=[Depends(require_role(security.ROLE_ANALYST))],
)
def review_response_action(
    action_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Mark an automated action as reviewed by a security analyst."""
    action = db.query(models.ResponseAction).filter(models.ResponseAction.id == action_id).first()
    if action is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Response action not found")

    action.reviewed = True
    action.reviewed_by = current_user.id
    action.reviewed_at = datetime.now(timezone.utc)

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id),
        action="playbook_action.review",
        target_type="response_action",
        target_id=action_id,
        ip_address=get_client_ip(request),
    )))
    db.commit()
    db.refresh(action)
    return action


@router.post(
    "/block-ip",
    dependencies=[Depends(require_role(security.ROLE_ADMIN))],
)
def manually_block_ip(
    ip_address: str,
    reason: str = "Manual analyst block",
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Manually invoke firewall block against an IP."""
    result = firewall_response.block_ip(ip_address, reason=reason)

    resp_action = models.ResponseAction(
        playbook_name="manual_analyst_block",
        action_type="block_ip",
        target=ip_address,
        success=result.get("success", False),
        skipped=result.get("skipped", False),
        detail=result,
        reviewed=True,
        reviewed_by=current_user.id,
        reviewed_at=datetime.now(timezone.utc),
    )
    db.add(resp_action)

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id),
        action="firewall.manual_block",
        target_type="ip_address",
        target_id=ip_address,
        details={"reason": reason, "result": result},
        ip_address=get_client_ip(request) if request else "unknown",
    )))
    db.commit()
    return result
