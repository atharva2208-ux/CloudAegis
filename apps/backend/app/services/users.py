"""User management."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import AppError, ConflictError, NotFoundError
from app.core.permissions import Role
from app.core.security import hash_password, password_policy_violations, verify_password
from app.models import RoleModel, User
from app.schemas.auth import UserCreate, UserUpdate
from app.services import audit
from app.services.auth import revoke_all_sessions
from app.services.context import Actor


def to_out(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role_name,
        "permissions": sorted(user.role.permission_codes),
        "is_active": user.is_active,
        "last_login_at": user.last_login_at,
        "created_at": user.created_at,
        "locked": is_locked(user),
        "failed_login_attempts": user.failed_login_attempts,
    }


def is_locked(user: User) -> bool:
    if user.locked_until is None:
        return False
    locked_until = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc)
    return locked_until > datetime.now(timezone.utc)


def _role(db: Session, role: Role) -> RoleModel:
    model = db.scalar(select(RoleModel).where(RoleModel.name == role.value))
    if model is None:
        raise AppError("Role catalog not initialised", status_code=500)
    return model


def _check_password(password: str, email: str) -> None:
    problems = password_policy_violations(password, email)
    if problems:
        raise AppError("Password " + "; ".join(problems), code="weak_password", status_code=422,
                       details=[{"field": "password", "message": p} for p in problems])


def create_user(db: Session, data: UserCreate, actor: Actor) -> User:
    email = data.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise ConflictError("A user with this email already exists")
    _check_password(data.password, email)
    user = User(email=email, full_name=data.full_name, password_hash=hash_password(data.password),
                role_id=_role(db, data.role).id)
    db.add(user)
    db.flush()
    audit.record(db, actor, "user.created", resource_type="user", resource_id=user.id,
                 details={"email": email, "role": data.role.value})
    db.commit()
    db.refresh(user)
    return user


def _active_admins(db: Session) -> int:
    return db.scalar(select(func.count(User.id)).join(RoleModel).where(
        RoleModel.name == Role.ADMIN.value, User.is_active.is_(True))) or 0


def update_user(db: Session, user_id: int, data: UserUpdate, actor: Actor) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise NotFoundError("User not found")
    changes: dict = {}
    demoting = data.role is not None and data.role.value != user.role_name and user.role_name == Role.ADMIN.value
    deactivating = data.is_active is False and user.is_active and user.role_name == Role.ADMIN.value
    if (demoting or deactivating) and _active_admins(db) <= 1:
        raise AppError("At least one active administrator is required", code="last_admin", status_code=409)
    if actor.user_id == user.id and (data.is_active is False or demoting):
        raise AppError("You cannot deactivate or demote your own account", code="self_modification",
                       status_code=409)
    if data.full_name is not None and data.full_name != user.full_name:
        changes["full_name"] = {"from": user.full_name, "to": data.full_name}
        user.full_name = data.full_name.strip()
    if data.role is not None and data.role.value != user.role_name:
        changes["role"] = {"from": user.role_name, "to": data.role.value}
        user.role = _role(db, data.role)
    if data.is_active is not None and data.is_active != user.is_active:
        changes["is_active"] = {"from": user.is_active, "to": data.is_active}
        user.is_active = data.is_active
        if not data.is_active:
            revoke_all_sessions(db, user.id)
    if changes:
        action = "user.role_changed" if "role" in changes else "user.updated"
        audit.record(db, actor, action, resource_type="user", resource_id=user.id, details=changes)
        if "role" in changes:
            revoke_all_sessions(db, user.id)  # force re-login with new permissions
    db.commit()
    db.refresh(user)
    return user


def unlock_user(db: Session, user_id: int, actor: Actor) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise NotFoundError("User not found")
    user.locked_until = None
    user.failed_login_attempts = 0
    audit.record(db, actor, "user.unlocked", resource_type="user", resource_id=user.id)
    db.commit()
    return user


def change_password(db: Session, user: User, current: str, new: str, actor: Actor, current_jti: str) -> None:
    if not verify_password(current, user.password_hash):
        audit.record_now(actor, "user.password_change", result="failure", resource_type="user", resource_id=user.id)
        raise AppError("Current password is incorrect", code="invalid_password", status_code=400)
    if current == new:
        raise AppError("New password must differ from the current password", code="weak_password", status_code=422)
    _check_password(new, user.email)
    user.password_hash = hash_password(new)
    user.password_changed_at = datetime.now(timezone.utc)
    revoke_all_sessions(db, user.id, except_jti=current_jti)
    audit.record(db, actor, "user.password_changed", resource_type="user", resource_id=user.id)
    db.commit()


def list_users(db: Session) -> list[User]:
    return list(db.scalars(select(User).order_by(User.created_at)).all())
