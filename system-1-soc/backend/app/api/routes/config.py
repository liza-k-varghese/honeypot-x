"""
System Configurations API routes — Group 1 (Core Platform).
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.api.deps import get_client_ip, get_current_user, require_role
from app.core import security
from app.db.postgres import get_db
from app.services import audit

router = APIRouter(prefix="/api/config", tags=["config"])


@router.get("", response_model=list[schemas.ConfigurationOut])
def list_configurations(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List system configurations."""
    return db.query(models.Configuration).order_by(models.Configuration.key.asc()).all()


@router.get("/{key}", response_model=schemas.ConfigurationOut)
def get_configuration(
    key: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Get single system configuration value."""
    config = db.query(models.Configuration).filter(models.Configuration.key == key).first()
    if config is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Configuration '{key}' not found")
    return config


@router.put(
    "/{key}",
    response_model=schemas.ConfigurationOut,
    dependencies=[Depends(require_role(security.ROLE_ADMIN))],
)
def update_configuration(
    key: str,
    payload: schemas.ConfigurationUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Create or update system configuration."""
    config = db.query(models.Configuration).filter(models.Configuration.key == key).first()
    if config is None:
        config = models.Configuration(
            key=key,
            value=payload.value,
            description=payload.description,
            updated_by=current_user.id,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(config)
    else:
        config.value = payload.value
        if payload.description is not None:
            config.description = payload.description
        config.updated_by = current_user.id
        config.updated_at = datetime.now(timezone.utc)

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id),
        action="configuration.update",
        target_type="configuration",
        target_id=key,
        details={"value": payload.value},
        ip_address=get_client_ip(request),
    )))
    db.commit()
    db.refresh(config)
    return config
