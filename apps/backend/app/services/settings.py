"""Platform settings stored as JSON documents keyed by name."""

from __future__ import annotations

from typing import Any

from cloudaegis_engine.resource_types import SERVICE_ORDER
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.models import AppSetting

DEFAULTS: dict[str, dict[str, Any]] = {
    "thresholds": {"stale_credential_days": 90, "unused_user_days": 90, "secret_rotation_days": 90},
    "scanning": {"services": list(SERVICE_ORDER)},
    "notifications": {"notify_on_critical": True},
}

THRESHOLD_BOUNDS = {
    "stale_credential_days": (30, 365),
    "unused_user_days": (30, 365),
    "secret_rotation_days": (7, 365),
}


def get(db: Session, key: str) -> dict[str, Any]:
    row = db.get(AppSetting, key)
    value = dict(DEFAULTS.get(key, {}))
    if row and isinstance(row.value, dict):
        value.update(row.value)
    return value


def put(db: Session, key: str, value: dict[str, Any], user_id: int | None) -> dict[str, Any]:
    row = db.get(AppSetting, key)
    if row is None:
        row = AppSetting(key=key, value=value, updated_by_id=user_id)
        db.add(row)
    else:
        row.value = value
        row.updated_by_id = user_id
    return value


def validate_thresholds(values: dict[str, int]) -> dict[str, int]:
    clean = {}
    for key, value in values.items():
        if key not in THRESHOLD_BOUNDS:
            raise AppError(f"Unknown threshold '{key}'", code="validation_error", status_code=422)
        low, high = THRESHOLD_BOUNDS[key]
        if not isinstance(value, int) or not low <= value <= high:
            raise AppError(f"{key} must be between {low} and {high}", code="validation_error", status_code=422)
        clean[key] = value
    return clean


def validate_services(services: list[str]) -> list[str]:
    unknown = [s for s in services if s not in SERVICE_ORDER]
    if unknown:
        raise AppError(f"Unknown services: {', '.join(unknown)}", code="validation_error", status_code=422)
    if not services:
        raise AppError("Select at least one service", code="validation_error", status_code=422)
    return [s for s in SERVICE_ORDER if s in services]
