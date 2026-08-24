"""
Authentication primitives — Group 14 (User Authentication, JWT-Based
Sessions, Password Security).

Deliberately implemented with only the Python standard library (hashlib,
hmac, base64, json) rather than python-jose/passlib. Two reasons:
  1. It keeps the security-critical code path dependency-free — one less
     thing that can silently pull in an incompatible version.
  2. PBKDF2-HMAC-SHA256 (password hashing) and HMAC-SHA256 JWTs are both
     well-established, secure primitives on their own — this isn't a
     "toy" implementation, it's what libraries like passlib/python-jose
     do internally, just without the extra abstraction layers.

If you'd rather standardize on python-jose + passlib[bcrypt] for
consistency with other FastAPI tutorials, swapping this module out is a
clean, isolated change — everything else only calls the four functions
below.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone

from app.core.config import settings

PBKDF2_ITERATIONS = 260_000


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Returns a self-describing hash string: algorithm$iterations$salt$hash
    (all base64url, no padding) — same pattern Django's PBKDF2 hasher uses,
    so the iteration count can be bumped later without breaking old hashes."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        base64.urlsafe_b64encode(salt).decode().rstrip("="),
        base64.urlsafe_b64encode(dk).decode().rstrip("="),
    )


def verify_password(password: str, hashed: str) -> bool:
    try:
        algo, iterations_str, salt_b64, hash_b64 = hashed.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iterations_str)
        salt = base64.urlsafe_b64decode(salt_b64 + "=" * (-len(salt_b64) % 4))
        expected = base64.urlsafe_b64decode(hash_b64 + "=" * (-len(hash_b64) % 4))
    except (ValueError, TypeError):
        return False

    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(dk, expected)


# ---------------------------------------------------------------------------
# JWT (compact HS256), stdlib only
# ---------------------------------------------------------------------------

class TokenError(Exception):
    pass


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _sign(message: bytes) -> bytes:
    return hmac.new(settings.JWT_SECRET_KEY.encode("utf-8"), message, hashlib.sha256).digest()


def create_token(claims: dict, expires_delta: timedelta) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = datetime.now(timezone.utc)
    payload = {
        **claims,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
    }

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature_b64 = _b64url_encode(_sign(signing_input))

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def create_access_token(user_id: str, username: str, role: str) -> str:
    return create_token(
        {"sub": user_id, "username": username, "role": role, "type": "access"},
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def create_refresh_token(user_id: str) -> str:
    return create_token(
        {"sub": user_id, "type": "refresh"},
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )


def decode_token(token: str) -> dict:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError:
        raise TokenError("Malformed token")

    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = _sign(signing_input)
    actual_sig = _b64url_decode(signature_b64)

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise TokenError("Invalid signature")

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except (ValueError, json.JSONDecodeError):
        raise TokenError("Invalid payload")

    if payload.get("exp", 0) < time.time():
        raise TokenError("Token expired")

    return payload


# ---------------------------------------------------------------------------
# Role-based access control (Group 14: Administrator / Security Analyst /
# Read-Only roles)
# ---------------------------------------------------------------------------

ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_READONLY = "readonly"

ROLE_HIERARCHY = {ROLE_READONLY: 0, ROLE_ANALYST: 1, ROLE_ADMIN: 2}


def role_satisfies(user_role: str, required_role: str) -> bool:
    """True if user_role has at least the privilege level of required_role."""
    return ROLE_HIERARCHY.get(user_role, -1) >= ROLE_HIERARCHY.get(required_role, 99)


