"""Password hashing, session tokens, CSRF tokens and credential encryption."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import get_settings

log = logging.getLogger("cloudaegis.security")

_hasher = PasswordHasher()  # argon2id with library defaults (OWASP-aligned)
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "cloudaegis"

# A valid hash used to equalise timing when the user does not exist.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


# --- Passwords -------------------------------------------------------------
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def password_policy_violations(password: str, email: str | None = None) -> list[str]:
    problems: list[str] = []
    if len(password) < 12:
        problems.append("must be at least 12 characters")
    if len(password) > 128:
        problems.append("must be at most 128 characters")
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3:
        problems.append("must contain at least three of: lowercase, uppercase, digits, symbols")
    if email and email.split("@")[0].lower() in password.lower():
        problems.append("must not contain your email name")
    return problems


# --- Session tokens --------------------------------------------------------
def create_session_token(user_id: int, role: str, expires_at: datetime) -> tuple[str, str]:
    jti = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user_id), "role": role, "jti": jti, "iat": now, "nbf": now, "exp": expires_at,
               "iss": JWT_ISSUER}
    token = jwt.encode(payload, get_settings().secret_key, algorithm=JWT_ALGORITHM)
    return token, jti


def decode_session_token(token: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(token, get_settings().secret_key, algorithms=[JWT_ALGORITHM], issuer=JWT_ISSUER,
                          options={"require": ["exp", "iat", "sub", "jti"]})
    except jwt.PyJWTError:
        return None


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_equals(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())


def session_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=get_settings().session_absolute_minutes)


# --- Credential encryption -------------------------------------------------
def _fernet() -> Fernet:
    settings = get_settings()
    if settings.credential_encryption_key:
        return Fernet(settings.credential_encryption_key.encode())
    # Development fallback: derive a stable key from SECRET_KEY. Production
    # configuration refuses to start without an explicit key.
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"cloudaegis-credentials",
                   info=b"fernet").derive(settings.secret_key.encode())
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_secret_payload(payload: dict[str, Any]) -> str:
    return _fernet().encrypt(json.dumps(payload).encode()).decode()


def decrypt_secret_payload(token: str | None) -> dict[str, Any]:
    if not token:
        return {}
    try:
        return json.loads(_fernet().decrypt(token.encode()))
    except (InvalidToken, ValueError):
        log.error("credential_decryption_failed")
        return {}
