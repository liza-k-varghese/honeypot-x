"""User Management — Group 14 (Features 131-140)."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.api.deps import get_client_ip, get_current_user, require_role
from app.core import security
from app.db.postgres import get_db
from app.services import audit

router = APIRouter(prefix="/api/users", tags=["users"])


@router.patch("/me/password", response_model=schemas.UserOut)
def change_own_password(
    payload: schemas.PasswordChange,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Self-service password change — critically, this is how the
    default admin account (seeded with a printed, one-time password by
    app/init_db.py) gets a real password on first login. There is
    deliberately no admin-reset-another-user's-password endpoint yet:
    that needs its own audit/notification story (the affected user
    should know their password changed) that's worth building
    thoughtfully rather than bolting on here — for now, an admin who
    needs to reset someone locked out deactivates and recreates the
    account."""
    if not security.verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")

    current_user.hashed_password = security.hash_password(payload.new_password)

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id), action="user.password_change",
        target_type="user", target_id=str(current_user.id),
        ip_address=get_client_ip(request),
    )))
    db.commit()
    db.refresh(current_user)
    return current_user


@router.get("", response_model=list[schemas.UserOut], dependencies=[Depends(require_role(security.ROLE_ADMIN))])
def list_users(db: Session = Depends(get_db)):
    return db.query(models.User).order_by(models.User.created_at.desc()).all()


@router.post("", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: schemas.UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_role(security.ROLE_ADMIN)),
):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already exists")

    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=security.hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.flush()

    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id), action="user.create",
        target_type="user", target_id=str(user.id),
        details={"created_username": user.username, "role": user.role},
        ip_address=get_client_ip(request),
    )))
    db.commit()
    db.refresh(user)
    return user


@router.patch("/{user_id}/deactivate", response_model=schemas.UserOut)
def deactivate_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_role(security.ROLE_ADMIN)),
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if str(user.id) == str(current_user.id):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot deactivate your own account")

    user.is_active = False
    db.add(models.AuditLog(**audit.build_audit_entry(
        user_id=str(current_user.id), action="user.deactivate",
        target_type="user", target_id=str(user.id),
        ip_address=get_client_ip(request),
    )))
    db.commit()
    db.refresh(user)
    return user


