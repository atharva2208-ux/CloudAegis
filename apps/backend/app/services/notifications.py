"""In-app notifications."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models import Finding, Notification, Scan, User
from app.services import settings as app_settings


def _recipients(db: Session) -> list[int]:
    return list(db.scalars(select(User.id).where(User.is_active.is_(True))).all())


def broadcast(db: Session, kind: str, title: str, message: str, severity: str = "INFO", link: str | None = None) -> None:
    for user_id in _recipients(db):
        db.add(Notification(user_id=user_id, kind=kind, severity=severity, title=title, message=message, link=link))


def notify_scan(db: Session, scan: Scan, failed: bool = False, new_critical: list[Finding] | None = None) -> None:
    if scan.trigger == "seed":
        return
    name = scan.account.name if scan.account else "account"
    if failed:
        broadcast(db, "scan_failed", f"Scan {scan.display_id} failed", f"{name}: {scan.error_message or 'unknown error'}",
                  severity="HIGH", link=f"/scans/{scan.id}")
        return
    broadcast(db, "scan_completed", f"Scan {scan.display_id} completed",
              f"{name}: score {scan.security_score}, {scan.findings_total} open findings "
              f"({scan.findings_new} new, {scan.findings_resolved} resolved)",
              severity="INFO", link=f"/scans/{scan.id}")
    if new_critical and app_settings.get(db, "notifications").get("notify_on_critical", True):
        first = new_critical[0]
        extra = f" and {len(new_critical) - 1} more" if len(new_critical) > 1 else ""
        broadcast(db, "critical_finding", f"{len(new_critical)} new critical finding(s)",
                  f"{first.title}{extra}", severity="CRITICAL",
                  link=f"/findings/{first.id}" if len(new_critical) == 1 else "/findings?severity=CRITICAL&status=OPEN")


def list_for_user(db: Session, user_id: int, limit: int = 30) -> dict[str, Any]:
    items = db.scalars(select(Notification).where(Notification.user_id == user_id)
                       .order_by(Notification.created_at.desc()).limit(limit)).all()
    unread = db.scalar(select(func.count(Notification.id)).where(Notification.user_id == user_id,
                                                                 Notification.read_at.is_(None))) or 0
    return {"items": list(items), "unread": unread}


def mark_read(db: Session, user_id: int, ids: list[int] | None = None) -> None:
    stmt = update(Notification).where(Notification.user_id == user_id, Notification.read_at.is_(None))
    if ids:
        stmt = stmt.where(Notification.id.in_(ids))
    db.execute(stmt.values(read_at=datetime.now(timezone.utc)))
    db.commit()
