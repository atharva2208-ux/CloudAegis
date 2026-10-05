"""Role-based access control definitions.

Roles map to a fixed set of permission codes. The mapping is seeded into
the ``roles`` / ``permissions`` tables and enforced on every endpoint via
the ``require(...)`` dependency.
"""

from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    VIEWER = "VIEWER"


class Perm(str, Enum):
    ACCOUNTS_READ = "accounts:read"
    ACCOUNTS_MANAGE = "accounts:manage"
    ASSETS_READ = "assets:read"
    FINDINGS_READ = "findings:read"
    FINDINGS_UPDATE = "findings:update"
    SCANS_READ = "scans:read"
    SCANS_RUN = "scans:run"
    COMPLIANCE_READ = "compliance:read"
    RULES_READ = "rules:read"
    REPORTS_READ = "reports:read"
    REPORTS_GENERATE = "reports:generate"
    AUDIT_READ = "audit:read"
    USERS_MANAGE = "users:manage"
    SETTINGS_MANAGE = "settings:manage"


PERMISSION_DESCRIPTIONS = {
    Perm.ACCOUNTS_READ: "View connected cloud accounts",
    Perm.ACCOUNTS_MANAGE: "Add, edit and remove cloud accounts",
    Perm.ASSETS_READ: "View the asset inventory",
    Perm.FINDINGS_READ: "View security findings",
    Perm.FINDINGS_UPDATE: "Acknowledge, resolve, suppress and ticket findings",
    Perm.SCANS_READ: "View scan history and progress",
    Perm.SCANS_RUN: "Start and cancel scans",
    Perm.COMPLIANCE_READ: "View compliance posture",
    Perm.RULES_READ: "View detection rules",
    Perm.REPORTS_READ: "View and download reports",
    Perm.REPORTS_GENERATE: "Generate reports",
    Perm.AUDIT_READ: "View the audit trail",
    Perm.USERS_MANAGE: "Manage users and roles",
    Perm.SETTINGS_MANAGE: "Change platform settings and rule configuration",
}

_READ = {
    Perm.ACCOUNTS_READ, Perm.ASSETS_READ, Perm.FINDINGS_READ, Perm.SCANS_READ, Perm.COMPLIANCE_READ,
    Perm.RULES_READ, Perm.REPORTS_READ,
}

ROLE_PERMISSIONS: dict[Role, set[Perm]] = {
    Role.ADMIN: set(Perm),
    Role.SECURITY_ANALYST: _READ | {Perm.FINDINGS_UPDATE, Perm.SCANS_RUN, Perm.REPORTS_GENERATE},
    Role.VIEWER: set(_READ),
}

ROLE_DESCRIPTIONS = {
    Role.ADMIN: "Full control including users, accounts and settings",
    Role.SECURITY_ANALYST: "Runs scans, triages findings and generates reports",
    Role.VIEWER: "Read-only access to posture, findings and reports",
}
