"""Synchronise static catalogs (RBAC, rules, compliance) into the database.

Runs at startup and is idempotent. The security engine remains the source
of truth for rule metadata; the database copy enables joins, filtering and
per-rule enablement.
"""

from __future__ import annotations

import logging

from cloudaegis_engine.compliance import FRAMEWORKS
from cloudaegis_engine.rules import default_registry
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.permissions import PERMISSION_DESCRIPTIONS, ROLE_DESCRIPTIONS, ROLE_PERMISSIONS
from app.models import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceMapping,
    Permission,
    RoleModel,
    SecurityRule,
)

log = logging.getLogger("cloudaegis.catalog")


def sync_rbac(db: Session) -> None:
    perms = {p.code: p for p in db.scalars(select(Permission)).all()}
    for perm, description in PERMISSION_DESCRIPTIONS.items():
        if perm.value not in perms:
            perms[perm.value] = Permission(code=perm.value, description=description)
            db.add(perms[perm.value])
        else:
            perms[perm.value].description = description
    db.flush()
    roles = {r.name: r for r in db.scalars(select(RoleModel)).all()}
    for role, granted in ROLE_PERMISSIONS.items():
        model = roles.get(role.value) or RoleModel(name=role.value)
        model.description = ROLE_DESCRIPTIONS[role]
        model.permissions = [perms[p.value] for p in sorted(granted, key=lambda p: p.value)]
        db.add(model)
    db.flush()


def sync_rules(db: Session) -> dict[str, SecurityRule]:
    existing = {r.rule_id: r for r in db.scalars(select(SecurityRule)).all()}
    for rule in default_registry().all():
        meta = rule.metadata.as_dict()
        model = existing.get(meta["rule_id"])
        if model is None:
            model = SecurityRule(rule_id=meta["rule_id"], enabled=True)
            existing[meta["rule_id"]] = model
            db.add(model)
        for field in ("title", "severity", "service", "category", "resource_type", "description", "impact",
                      "remediation", "remediation_steps", "remediation_cli", "references"):
            setattr(model, field, meta[field])
    db.flush()
    return existing


def sync_frameworks(db: Session, rules: dict[str, SecurityRule]) -> None:
    existing = {f.key: f for f in db.scalars(select(ComplianceFramework)).all()}
    for framework in FRAMEWORKS:
        model = existing.get(framework.key)
        if model is None:
            model = ComplianceFramework(key=framework.key)
            db.add(model)
        model.name = framework.name
        model.short_name = framework.short_name
        model.version = framework.version
        model.description = framework.description
        db.flush()
        controls = {c.control_id: c for c in model.controls}
        wanted = set()
        for position, control in enumerate(framework.controls):
            wanted.add(control.control_id)
            cm = controls.get(control.control_id)
            if cm is None:
                cm = ComplianceControl(framework_id=model.id, control_id=control.control_id)
                model.controls.append(cm)
            cm.section = control.section
            cm.title = control.title
            cm.description = control.description
            cm.position = position
            db.flush()
            have = {m.rule_id for m in cm.mappings}
            for rule_id in control.rule_ids:
                if rule_id not in have and rule_id in rules:
                    cm.mappings.append(ComplianceMapping(control_id=cm.id, security_rule_id=rules[rule_id].id,
                                                         rule_id=rule_id))
            cm.mappings[:] = [m for m in cm.mappings if m.rule_id in control.rule_ids]
        for control_id, cm in controls.items():
            if control_id not in wanted:
                db.delete(cm)
    db.flush()


def sync_catalog(db: Session) -> None:
    sync_rbac(db)
    rules = sync_rules(db)
    sync_frameworks(db, rules)
    db.commit()
    log.info("catalog_synced", extra={"rules": len(rules), "frameworks": len(FRAMEWORKS)})
