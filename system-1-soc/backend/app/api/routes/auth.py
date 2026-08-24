"""Auth routes — Group 14 (User Authentication, JWT-Based Sessions)."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.api.deps import get_client_ip, get_current_user
from app.core import security
from app.core.config import settings
from app.db import redis_client
from app.db.postgres import get_db

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=schemas.TokenResponse)
def login(payload: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    allowed = redis_client.check_rate_limit(
        f"login:{client_ip}",
        settings.LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
        settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    )
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many login attempts from this address. Try again in a few minutes.",
        )

    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if user is None or not security.verify_password(payload.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is deactivated")

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    return schemas.TokenResponse(
        access_token=security.create_access_token(str(user.id), user.username, user.role),
        refresh_token=security.create_refresh_token(str(user.id)),
    )


@router.post("/refresh", response_model=schemas.TokenResponse)
def refresh(payload: schemas.RefreshRequest, db: Session = Depends(get_db)):
    try:
        claims = security.decode_token(payload.refresh_token)
    except security.TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc))
    if claims.get("type") != "refresh":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not a refresh token")

    user = db.query(models.User).filter(models.User.id == claims["sub"]).first()
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")

    return schemas.TokenResponse(
        access_token=security.create_access_token(str(user.id), user.username, user.role),
        refresh_token=security.create_refresh_token(str(user.id)),
    )


@router.get("/me", response_model=schemas.UserOut)
def get_me(user: models.User = Depends(get_current_user)):
    return user


