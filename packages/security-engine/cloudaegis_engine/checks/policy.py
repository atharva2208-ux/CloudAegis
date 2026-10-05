"""IAM / resource-policy analysis helpers.

These functions work on parsed JSON policy documents (dicts) and never call
a cloud API, which keeps every rule that uses them unit-testable.
"""

from __future__ import annotations

import fnmatch
import json
from typing import Any, Iterable, Iterator

# Condition keys that meaningfully narrow a "Principal: *" grant. A policy
# statement that uses one of these is treated as *restricted*, not public.
RESTRICTING_CONDITION_KEYS = {
    "aws:sourceaccount",
    "aws:sourcearn",
    "aws:sourceowner",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:sourceip",
    "aws:principalaccount",
    "aws:principalarn",
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:userid",
    "aws:username",
    "kms:callerAccount".lower(),
    "kms:viaservice",
    "lambda:functionurlauthtype",
    "s3:dataaccesspointaccount",
}

# Actions that let a principal grant itself more privilege. Sourced from
# well-documented IAM privilege-escalation paths.
PRIVILEGE_ESCALATION_ACTIONS = (
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:UpdateAssumeRolePolicy",
    "iam:AddUserToGroup",
    "iam:PassRole",
)


def load_document(document: Any) -> dict[str, Any] | None:
    """Accept a dict, a JSON string, or None and return a dict or None."""
    if document is None or document == "":
        return None
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        try:
            parsed = json.loads(document)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def statements(document: Any) -> Iterator[dict[str, Any]]:
    doc = load_document(document)
    if not doc:
        return
    for statement in _as_list(doc.get("Statement")):
        if isinstance(statement, dict):
            yield statement


def allow_statements(document: Any) -> Iterator[dict[str, Any]]:
    for statement in statements(document):
        if statement.get("Effect") == "Allow":
            yield statement


def statement_actions(statement: dict[str, Any]) -> list[str]:
    return [str(a) for a in _as_list(statement.get("Action"))]


def statement_resources(statement: dict[str, Any]) -> list[str]:
    return [str(r) for r in _as_list(statement.get("Resource"))]


def action_matches(pattern: str, action: str) -> bool:
    """IAM action matching is case-insensitive and supports * and ? wildcards."""
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def statement_allows_action(statement: dict[str, Any], action: str) -> bool:
    if "NotAction" in statement:
        # NotAction with Allow grants everything except the listed actions.
        excluded = [str(a) for a in _as_list(statement.get("NotAction"))]
        return not any(action_matches(p, action) for p in excluded)
    return any(action_matches(p, action) for p in statement_actions(statement))


def is_full_admin_statement(statement: dict[str, Any]) -> bool:
    """True for an Allow statement granting ``*`` actions on ``*`` resources."""
    if statement.get("Effect") != "Allow":
        return False
    if "Condition" in statement:
        return False
    actions = statement_actions(statement)
    resources = statement_resources(statement) if "Resource" in statement else []
    allows_all_actions = "*" in actions or (
        "NotAction" in statement and not _as_list(statement.get("NotAction"))
    )
    return allows_all_actions and "*" in resources


def grants_full_admin(document: Any) -> bool:
    return any(is_full_admin_statement(s) for s in statements(document))


def wildcard_service_grants(document: Any) -> list[str]:
    """Return service-wide wildcard actions such as ``iam:*`` or ``s3:*``
    granted on ``*`` resources."""
    found: list[str] = []
    for statement in allow_statements(document):
        if "*" not in statement_resources(statement):
            continue
        for action in statement_actions(statement):
            if action.endswith(":*") and action not in found:
                found.append(action)
    return found


def escalation_actions(document: Any) -> list[str]:
    """Privilege-escalation actions allowed on any resource (``*``)."""
    hits: list[str] = []
    for statement in allow_statements(document):
        if "*" not in statement_resources(statement):
            continue
        for action in PRIVILEGE_ESCALATION_ACTIONS:
            if statement_allows_action(statement, action) and action not in hits:
                hits.append(action)
    return hits


def _principal_values(principal: Any) -> list[str]:
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        values: list[str] = []
        for key in ("AWS", "CanonicalUser", "Federated", "Service"):
            values.extend(str(v) for v in _as_list(principal.get(key)))
        return values
    return [str(p) for p in _as_list(principal)]


def principal_is_wildcard(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return "*" in [str(v) for v in _as_list(principal.get("AWS"))]
    return False


def has_restricting_condition(statement: dict[str, Any]) -> bool:
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return False
    for operator_block in condition.values():
        if not isinstance(operator_block, dict):
            continue
        for key, value in operator_block.items():
            if key.lower() in RESTRICTING_CONDITION_KEYS and not _unrestricted_value(key, value):
                return True
    return False


def _unrestricted_value(key: str, value: Any) -> bool:
    """A restricting key whose value still matches everyone (e.g. SourceIp 0.0.0.0/0, or ``*``)."""
    values = [str(v).strip() for v in _as_list(value)]
    if not values or any(v in ("*", "") for v in values):
        return True
    if key.lower() == "aws:sourceip":
        return any(v in ("0.0.0.0/0", "::/0") for v in values)
    return False


def public_statements(document: Any) -> list[dict[str, Any]]:
    """Allow statements that grant access to anyone (Principal ``*``)
    without a condition that scopes the caller."""
    public: list[dict[str, Any]] = []
    for statement in allow_statements(document):
        if principal_is_wildcard(statement.get("Principal")) and not has_restricting_condition(
            statement
        ):
            public.append(statement)
    return public


def is_public_policy(document: Any) -> bool:
    return bool(public_statements(document))


def external_principals(document: Any, own_account_id: str) -> list[str]:
    """AWS principals in Allow statements that belong to another account."""
    externals: list[str] = []
    for statement in allow_statements(document):
        principal = statement.get("Principal")
        if not isinstance(principal, dict):
            continue
        for value in _as_list(principal.get("AWS")):
            value = str(value)
            if value == "*":
                continue
            account = _account_from_principal(value)
            if account and account != own_account_id and value not in externals:
                externals.append(value)
    return externals


def _account_from_principal(value: str) -> str | None:
    if value.isdigit() and len(value) == 12:
        return value
    if value.startswith("arn:"):
        parts = value.split(":")
        if len(parts) > 4 and parts[4].isdigit():
            return parts[4]
    return None


def statement_has_condition_key(statement: dict[str, Any], key: str) -> bool:
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return False
    key = key.lower()
    return any(
        isinstance(block, dict) and any(k.lower() == key for k in block)
        for block in condition.values()
    )


def denies_insecure_transport(document: Any) -> bool:
    """True if the policy contains a Deny for requests where
    ``aws:SecureTransport`` is false."""
    for statement in statements(document):
        if statement.get("Effect") != "Deny":
            continue
        condition = statement.get("Condition") or {}
        for operator, block in condition.items():
            if not isinstance(block, dict) or not operator.lower().startswith("bool"):
                continue
            for key, value in block.items():
                if key.lower() == "aws:securetransport" and str(
                    value[0] if isinstance(value, list) else value
                ).lower() == "false":
                    return True
    return False


def summarize_statement(statement: dict[str, Any]) -> dict[str, Any]:
    """Compact, evidence-friendly view of a statement."""
    summary: dict[str, Any] = {"Effect": statement.get("Effect")}
    for key in ("Sid", "Principal", "Action", "NotAction", "Resource", "Condition"):
        if key in statement:
            summary[key] = statement[key]
    return summary


def iter_documents(entries: Iterable[dict[str, Any]]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Iterate ``[{"name": ..., "document": ...}]`` lists produced by providers."""
    for entry in entries or ():
        doc = load_document(entry.get("document"))
        if doc:
            yield str(entry.get("name", "inline")), doc
