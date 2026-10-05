"""Bootstrap users and the simulated demo environment.

The demo history is produced by running the real scan pipeline against the
simulated provider at increasing "maturity" levels with back-dated clocks,
so trends, comparisons and finding lifecycles are genuine engine output.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.permissions import Role
from app.core.security import hash_password
from app.models import CloudAccount, Finding, FindingStatus, RoleModel, Scan, User
from app.schemas.account import DemoAccountCreate
from app.services import accounts, findings
from app.services.context import SYSTEM, Actor
from app.services.scans import create_scan, execute_scan

log = logging.getLogger("cloudaegis.demo")

DEMO_PASSWORD = "CloudAegis!Demo2026"
DEMO_USERS = (
    ("analyst@cloudaegis.local", "Sam Rivera", Role.SECURITY_ANALYST),
    ("viewer@cloudaegis.local", "Jordan Lee", Role.VIEWER),
)
# (days ago, maturity) — posture improves over six weeks of remediation.
HISTORY = ((42, 0.28), (35, 0.34), (28, 0.40), (21, 0.46), (14, 0.52), (7, 0.57), (0, 0.62))


def _role(db: Session, role: Role) -> RoleModel:
    return db.scalar(select(RoleModel).where(RoleModel.name == role.value))


def ensure_admin(db: Session) -> tuple[User, str | None]:
    settings = get_settings()
    existing = db.scalar(select(User).join(RoleModel).where(RoleModel.name == Role.ADMIN.value))
    if existing:
        return existing, None
    password = settings.seed_admin_password or (DEMO_PASSWORD if settings.demo_mode else secrets.token_urlsafe(18))
    admin = User(email=settings.seed_admin_email.lower(), full_name="Platform Administrator",
                 password_hash=hash_password(password), role_id=_role(db, Role.ADMIN).id)
    db.add(admin)
    db.commit()
    generated = None if settings.seed_admin_password or settings.demo_mode else password
    return admin, generated


def ensure_demo_users(db: Session) -> None:
    for email, name, role in DEMO_USERS:
        if not db.scalar(select(User).where(User.email == email)):
            db.add(User(email=email, full_name=name, password_hash=hash_password(DEMO_PASSWORD),
                        role_id=_role(db, role).id))
    db.commit()


def seed_demo_environment(db: Session, admin: User) -> CloudAccount | None:
    if db.scalar(select(CloudAccount).where(CloudAccount.is_demo.is_(True))):
        return None
    actor = Actor(user=admin, user_agent="cloudaegis-bootstrap")
    account = accounts.create_demo_account(db, DemoAccountCreate(name="Production AWS (Demo)", start_scan=False), actor)
    now = datetime.now(timezone.utc)
    for index, (days_ago, maturity) in enumerate(HISTORY):
        clock = now - timedelta(days=days_ago, hours=2 if days_ago else 0, minutes=7 * index)
        scan = create_scan(db, account.id, SYSTEM if days_ago else actor, trigger="seed" if days_ago else "manual")
        scan.queued_at = clock
        db.commit()
        execute_scan(scan.id, provider_overrides={"maturity": maturity, "now": clock, "pace_seconds": 0}, clock=clock)
        log.info("demo_scan_seeded", extra={"scan_id": scan.id, "maturity": maturity})
    _simulate_triage(db, admin)
    return account


def _simulate_triage(db: Session, admin: User) -> None:
    """Record realistic analyst activity on a handful of findings."""
    actor = Actor(user=admin, user_agent="cloudaegis-bootstrap")
    open_findings = db.scalars(select(Finding).where(Finding.status == FindingStatus.OPEN.value)
                               .order_by(Finding.id)).unique().all()
    by_rule: dict[str, list[Finding]] = {}
    for f in open_findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    for f in by_rule.get("S3-005", [])[:3]:
        findings.update_status(db, f.id, FindingStatus.ACKNOWLEDGED.value, "Owner team notified", actor)
    for f in by_rule.get("EC2-005", [])[:2]:
        findings.link_ticket(db, f.id, f"SEC-{1200 + f.id}", "IMDSv2 rollout tracked in platform backlog", actor)
    for f in by_rule.get("S3-006", [])[:2]:
        findings.update_status(db, f.id, FindingStatus.SUPPRESSED.value,
                               "Accepted risk: short-lived scratch bucket, data classification 'public'", actor)
    for f in by_rule.get("VPC-003", [])[:1]:
        findings.add_comment(db, f.id, "Egress proxy migration planned for next quarter.", actor)


def bootstrap(db: Session, with_demo: bool | None = None) -> dict:
    from app.services.catalog import sync_catalog

    sync_catalog(db)
    admin, generated = ensure_admin(db)
    settings = get_settings()
    seeded = None
    if (with_demo if with_demo is not None else settings.demo_mode):
        ensure_demo_users(db)
        seeded = seed_demo_environment(db, admin)
    return {"admin": admin.email, "generated_password": generated, "demo_seeded": bool(seeded),
            "scans": db.scalar(select(Scan.id).order_by(Scan.id.desc()).limit(1))}
