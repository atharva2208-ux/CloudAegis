"""Global search across assets, findings, rules, accounts, regions and IPs."""

from __future__ import annotations

import ipaddress
import re

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.permissions import Perm
from app.models import Asset, CloudAccount, Finding, SecurityRule, User

PER_GROUP = 6


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def search(db: Session, user: User, q: str) -> dict:
    q = q.strip()
    like = f"%{q}%"
    groups: dict[str, list[dict]] = {}

    if user.has(Perm.ASSETS_READ.value):
        if _is_ip(q):
            hits = db.scalars(select(Asset).where(Asset.is_active.is_(True), or_(
                Asset.properties["public_ip"].as_string() == q, Asset.properties["private_ip"].as_string() == q))
                .limit(PER_GROUP)).all()
            groups["ip"] = [{"category": "ip", "id": str(a.id), "title": q,
                             "subtitle": f"{a.name} · {a.service} · {a.region}", "link": f"/assets/{a.id}"} for a in hits]
        assets = db.scalars(select(Asset).where(Asset.is_active.is_(True), or_(
            Asset.name.ilike(like), Asset.resource_uid.ilike(like))).order_by(Asset.risk_score.desc()).limit(PER_GROUP)).all()
        groups["asset"] = [{"category": "asset", "id": str(a.id), "title": a.name,
                            "subtitle": f"{a.service} · {a.region} · {a.resource_uid}", "link": f"/assets/{a.id}"}
                           for a in assets]

    if user.has(Perm.FINDINGS_READ.value):
        conditions = [Finding.title.ilike(like)]
        m = re.fullmatch(r"(?i)(?:fnd-)?0*(\d{1,9})", q)
        if m:
            conditions.append(Finding.id == int(m.group(1)))
        findings = db.scalars(select(Finding).where(or_(*conditions)).order_by(Finding.last_detected_at.desc())
                              .limit(PER_GROUP)).unique().all()
        groups["finding"] = [{"category": "finding", "id": str(f.id), "title": f"{f.display_id} · {f.title}",
                              "subtitle": f"{f.severity} · {f.status} · {f.asset.name if f.asset else ''}",
                              "link": f"/findings/{f.id}"} for f in findings]

    if user.has(Perm.RULES_READ.value):
        rules = db.scalars(select(SecurityRule).where(or_(SecurityRule.rule_id.ilike(like), SecurityRule.title.ilike(like)))
                           .order_by(SecurityRule.rule_id).limit(PER_GROUP)).all()
        groups["rule"] = [{"category": "rule", "id": r.rule_id, "title": f"{r.rule_id} · {r.title}",
                           "subtitle": f"{r.severity} · {r.service}", "link": f"/findings?rule_id={r.rule_id}"}
                          for r in rules]

    if user.has(Perm.ACCOUNTS_READ.value):
        accounts = db.scalars(select(CloudAccount).where(or_(CloudAccount.name.ilike(like),
                                                             CloudAccount.account_identifier.ilike(like)))
                              .limit(PER_GROUP)).all()
        groups["account"] = [{"category": "account", "id": str(a.id), "title": a.name,
                              "subtitle": f"AWS {a.account_identifier}" + (" · simulated" if a.is_demo else ""),
                              "link": f"/accounts/{a.id}"} for a in accounts]
        if user.has(Perm.ASSETS_READ.value) and re.fullmatch(r"[a-z]{2}(-[a-z]+)*(-\d)?", q.lower()):
            regions = db.scalars(select(Asset.region).where(Asset.region.ilike(f"{q.lower()}%")).distinct()
                                 .limit(PER_GROUP)).all()
            groups["region"] = [{"category": "region", "id": r, "title": r, "subtitle": "Region",
                                 "link": f"/assets?region={r}"} for r in regions]

    groups = {k: v for k, v in groups.items() if v}
    return {"query": q, "groups": groups, "total": sum(len(v) for v in groups.values())}
