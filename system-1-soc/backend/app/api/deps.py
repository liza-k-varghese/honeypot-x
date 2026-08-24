"""
Shared FastAPI dependencies: current-user resolution from a JWT, and a
require_role() factory for endpoint-level RBAC (Group 14).
"""

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import settings
from app.db.postgres import get_db
from app import models

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")

    try:
        payload = security.decode_token(credentials.credentials)
    except security.TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc))

    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not an access token")

    user = db.query(models.User).filter(models.User.id == payload["sub"]).first()
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")

    return user


def require_role(required_role: str):
    """Usage: @router.post(..., dependencies=[Depends(require_role(security.ROLE_ANALYST))])
    Admin satisfies any analyst/readonly requirement; analyst satisfies
    readonly; readonly satisfies only readonly — see
    app.core.security.ROLE_HIERARCHY."""

    def dependency(user: models.User = Depends(get_current_user)) -> models.User:
        if not security.role_satisfies(user.role, required_role):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Requires {required_role} role or higher (you have {user.role})",
            )
        return user

    return dependency


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def require_device_api_key(request: Request):
    """For ESP32 / System 2 callers — a shared secret rather than full
    user auth, since these are unattended devices, not human analysts."""
    api_key = request.headers.get("x-api-key")
    if api_key != settings.DEVICE_API_KEY:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing device API key")


